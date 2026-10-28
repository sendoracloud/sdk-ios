import Foundation
import XCTest
@testable import SendoraCloud

// ADR-033 rev 3 — the step-2 review fixes (docs/audit/sdk-auth-s58.415/TRIAGE-step2.md), one behavioural test per
// fix that applies to iOS, each reproducing the reviewer's scenario against the real machine (recording Keychain +
// scripted transport). Lockstep with RN `test/durability-review.test.ts` (cebf4bf4). Not applicable on iOS: T3 / T11 /
// T13 (RN-only), T16 (Android-only).

final class DurabilityReviewTests: XCTestCase {
    private static let guest = AuthHarness.anonymousUser()
    private static let account = AuthHarness.identifiedUser()
    private static let refreshKey = "sendora_auth_refresh_token"
    private static let sessionKeys = AuthHarness.frozenAuthKeys + [SendoraStorage.authSessionKey]

    private static func guestToken(_ user: SendoraCloudAuthUser = guest, sid: String = "sid-anon") -> String {
        TestJWT.make(sub: user.id, sid: sid, isAnonymous: true)
    }
    private static func accountToken(sid: String = "sid-b") -> String {
        TestJWT.make(sub: account.id, sid: sid, isAnonymous: false)
    }
    private static func session(_ user: SendoraCloudAuthUser, refresh: String, sid: String = "sid-anon") -> StubResponse {
        Stub.session(user: Stub.user(from: user),
                     tokens: Stub.tokens(access: TestJWT.make(sub: user.id, sid: sid, isAnonymous: user.isAnonymous), refresh: refresh))
    }

    private func guestHarness(configure: (AuthHarness) -> Void = { _ in }) -> AuthHarness {
        let h = AuthHarness()
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        configure(h)
        h.boot()
        return h
    }

    private func result<T>(_ h: AuthHarness, _ body: (@escaping (Result<T, SendoraCloudAuthError>) -> Void) -> Void) -> Result<T, SendoraCloudAuthError> {
        h.wait { done in body(done) }
    }

    // MARK: Decision C — a guest's plain signOut() drops its token like an account's

    /// Review H1 (probe P1): five "sign out, ensureSession" rounds bricked ensureSession() with HELD_GUEST_LIMIT.
    func test_C_guestSignOutNeverHolds_soRepeatedSignOutsNeverHitTheCap() {
        let h = AuthHarness()
        h.boot()
        let lock = NSLock()
        var n = 0
        h.transport.stub("POST", "/auth-service/anonymous") { _ in
            lock.lock(); n += 1; let i = n; lock.unlock()
            let u = AuthHarness.anonymousUser(String(format: "c0000000-0000-4000-8000-%012d", i))
            return Stub.session(user: Stub.user(from: u), tokens: Stub.tokens(access: TestJWT.make(sub: u.id, sid: "sid-\(i)"), refresh: "rt-\(i)"), status: 201)
        }
        for round in 1...7 {
            guard case .success = h.mint() else { return XCTFail("round \(round): ensureSession() must keep working") }
            h.waitVoid { done in h.auth.signOut(completion: done) }
            XCTAssertEqual(h.auth.status(), .signedOut, "round \(round)")
            XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-\(round)",
                           "round \(round): the guest's token is revoked like an account's")
        }
        XCTAssertEqual(h.auth.heldGuests().count, 0, "a sign-out never holds")
        XCTAssertEqual(h.auth.getQuarantinedGuests().count, 0, "…nor quarantines (the J.1 fallback is gone)")
        XCTAssertFalse(h.eventNames.contains("guest_held"), "no guest_held on a sign-out — the README's 'restore on guestHeld' pattern is never triggered by it")
    }

    // MARK: T1 — grace retries per attempt

    func test_T1_aLaterLostAnswerGetsItsOwnGraceSchedule() {
        let h = AuthHarness()
        h.graceRetryScale = 0.01
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-t1")
        h.boot()
        let lock = NSLock()
        var n = 0
        h.transport.stub("POST", "/auth-service/token/refresh") { req in
            lock.lock(); n += 1; let call = n; lock.unlock()
            return call == 1 ? .offline : Self.session(Self.guest, refresh: "\(req.body?["refreshToken"] as? String ?? "")-rot")
        }
        // An earlier outage left a schedule for this token that started two minutes ago (past its 50 s deadline).
        h.auth.lock.lock(); h.auth.graceRetry = ("rt-t1", Date().addingTimeInterval(-120), false, 0); h.auth.lock.unlock()
        XCTAssertNil(h.getAccessToken(forceRefresh: true), "the answer is lost")
        XCTAssertTrue(h.eventually { h.storedRefresh == "rt-t1-rot" }, "the lost answer is retried on a NEW schedule and recovered")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").compactMap { $0.body?["refreshToken"] as? String }, ["rt-t1", "rt-t1"])
    }

    // MARK: T2 — a read that keeps failing while the device is unlocked is permanent

    func test_T2_permanentReadFailureWhileUnlocked_proceedsAsAbsent_neverDeletes() {
        let h = AuthHarness()
        h.storageUnavailableQueueMs = 300
        h.deviceUnlocked = true // e.g. −34018 / errSecDecode on a fresh install, app in the foreground
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-perm")
        h.secure.readErrors = [Self.refreshKey]
        h.boot()
        XCTAssertEqual(h.auth.status(), .unknown, "precondition: unknown{storageUnavailable}")
        h.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "after-permanent", isAnonymous: true),
                                                                       tokens: Stub.tokens(access: TestJWT.make(sub: "after-permanent", sid: "sid-p"), refresh: "rt-new"), status: 201))
        let mark = h.secure.writeCount
        let t0 = Date()
        // ⚠ Pin converted (s58.415, C2 + C3 — Codex #3): a key given up as unreadable is NEVER written over while it
        // still fails to read (its bytes may still be the guest), and a minted guest is handed to the app only once its
        // session is on disk. So the mint after the window no longer "proceeds as if absent": nothing is installed,
        // nothing is written over the unreadable item, the mint key is kept (a retry replays the same guest), and the
        // verb fails STORAGE_UNAVAILABLE (retryable). It used to install `after-permanent` and overwrite `rt-perm`.
        let e = h.mint().failureError
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(t0), 0.25, "only after the whole window")
        XCTAssertEqual(e?.code, "STORAGE_UNAVAILABLE"); XCTAssertEqual(e?.retryable, true)
        XCTAssertNil(h.auth.currentUser, "the minted guest is never handed to the app")
        XCTAssertFalse(h.auth.storageUnavailable, "the window ended: the keys are accepted (they read as absent)")
        let sessionWrites = h.secure.writesSince(mark).filter { Self.sessionKeys.contains($0.key) }
        XCTAssertEqual(sessionWrites, [], "nothing deleted AND nothing written over the session keys")
        XCTAssertEqual(h.secure.snapshot()[Self.refreshKey], "rt-perm", "the unreadable bytes are untouched")
        XCTAssertNotNil(h.storage.pendingMintKey, "the mint key is kept for the retry")
        // The storage half: a key given up as unreadable is never removed by a clear (only a write replaces it).
        let secure = RecordingSecureStore()
        secure.seed(Self.refreshKey, "rt-bytes"); secure.seed("sendora_auth_user", "{}")
        secure.readErrors = [Self.refreshKey]
        let storage = SendoraStorage(secure: secure, plain: RecordingPlainStore())
        XCTAssertEqual(storage.acceptUnreadableSessionKeys(), [Self.refreshKey])
        XCTAssertEqual(storage.read(.refreshToken), .absent, "reads as absent from now on")
        storage.clearAuthTokens()
        XCTAssertEqual(secure.snapshot()[Self.refreshKey], "rt-bytes", "clearAuthTokens never deletes an accepted-unreadable key")
        XCTAssertNil(secure.snapshot()["sendora_auth_user"], "…the readable keys are cleared as usual")
        // A window in which the device was locked AT ANY POINT (unlocked, then locked mid-window) still refuses.
        let mixed = AuthHarness()
        mixed.storageUnavailableQueueMs = 300
        mixed.deviceUnlocked = true
        mixed.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-mixed")
        mixed.secure.readErrors = [Self.refreshKey]
        mixed.boot()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { mixed.deviceUnlocked = false }
        XCTAssertEqual(mixed.mint().failureError?.code, "STORAGE_UNAVAILABLE", "one 'locked' sample in the window → not permanent")
        // A window in which the device was LOCKED (or no signal at all) still refuses — never a mint over the account.
        for unlocked in [false, nil] as [Bool?] {
            let l = AuthHarness()
            l.storageUnavailableQueueMs = 300
            l.deviceUnlocked = unlocked
            l.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-locked")
            l.secure.readErrors = [Self.refreshKey]
            l.boot()
            XCTAssertEqual(l.mint().failureError?.code, "STORAGE_UNAVAILABLE", "deviceUnlocked=\(String(describing: unlocked))")
            XCTAssertEqual(l.transport.requests(to: "/auth-service/anonymous").count, 0)
        }
    }

    // MARK: T4 — a hold on sign-in is confirmed before the current token is replaced

    func test_T4_aSignInOverAGuestWhoseHoldDoesNotLandChangesNothing() {
        let h = guestHarness()
        h.transport.stub("POST", "/auth-service/login", Self.session(Self.account, refresh: "rt-acct", sid: "sid-b"))
        h.secure.failWrites = { $0.hasPrefix("sendora_auth_held_") }
        let e = h.signIn().failureError
        XCTAssertEqual(e?.code, "STORAGE_UNAVAILABLE"); XCTAssertEqual(e?.retryable, true)
        XCTAssertEqual(h.auth.status(), .anonymous); XCTAssertEqual(h.auth.currentUser?.id, Self.guest.id)
        XCTAssertEqual(h.storedRefresh, "rt-anon", "the guest's token untouched")
        XCTAssertEqual(h.auth.heldGuests().count, 0)
        XCTAssertTrue(h.eventually { h.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String == "rt-acct" },
                      "the new account session is revoked (not left live)")
        XCTAssertFalse(h.transport.requests(to: "/auth-service/token/revoke").contains { $0.body?["refreshToken"] as? String == "rt-anon" },
                       "the guest's own token is never revoked")
    }

    // MARK: T5 — settle an uncertain refresh before a hold

    func test_T5_aHoldSettlesAnUncertainRefreshFirst_soTheSlotCarriesTheRotatedSuccessor() {
        let h = guestHarness()
        h.transport.stub("POST", "/auth-service/token/refresh") { req in Self.session(Self.guest, refresh: "\(req.body?["refreshToken"] as? String ?? "")-live") }
        h.transport.stub("POST", "/auth-service/login", Self.session(Self.account, refresh: "rt-acct", sid: "sid-b"))
        // The last refresh of rt-anon lost its answer: its grace schedule is open (the server may have rotated it).
        h.auth.lock.lock(); h.auth.graceRetry = ("rt-anon", Date(), false, 0); h.auth.lock.unlock()
        guard case .success = h.signIn() else { return XCTFail("sign-in") }
        XCTAssertEqual(h.heldSlot(0)?.userId, Self.guest.id)
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "rt-anon-live", "the held guest got the LIVE successor, not the possibly-spent token")
        XCTAssertEqual(h.transitionEventNames, ["guest_held", "signed_in"])
        // forceNew holds the same way.
        let m = guestHarness()
        m.transport.stub("POST", "/auth-service/token/refresh") { req in Self.session(Self.guest, refresh: "\(req.body?["refreshToken"] as? String ?? "")-live") }
        m.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true),
                                                                       tokens: Stub.tokens(access: TestJWT.make(sub: "fresh", sid: "sid-f"), refresh: "rt-fresh"), status: 201))
        m.auth.lock.lock(); m.auth.graceRetry = ("rt-anon", Date(), false, 0); m.auth.lock.unlock()
        guard case .success = m.mint(forceNew: true) else { return XCTFail("forceNew") }
        XCTAssertEqual(m.heldSlot(0)?.refreshToken, "rt-anon-live")
    }

    // MARK: T6 — reuse with no readable quarantine slot keeps the session

    func test_T6_reuseWithNoReadableQuarantineSlot_keepsTheSessionAndBacksOff() {
        let h = AuthHarness()
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        for k in SendoraStorage.quarantineSlotKeys { h.secure.seed(k, "{ torn") }
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "reuse"))
        XCTAssertNil(h.getAccessToken(forceRefresh: true))
        XCTAssertEqual(h.auth.status(), .anonymous, "the session is KEPT — clearing would leave no handle at all")
        XCTAssertEqual(h.storedRefresh, "rt-anon")
        XCTAssertEqual(h.transitionEventNames, [], "no signed_out")
        XCTAssertTrue(SendoraStorage.quarantineSlotKeys.allSatisfy { h.secure.get($0) == "{ torn" }, "no reserved slot overwritten")
        XCTAssertNil(h.getAccessToken(forceRefresh: true))
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 1, "backed off: the spent token is not presented again at once (no reuse-alarm storm)")
    }

    // MARK: T7 — restore / recover / claim release the slot only after the installed session is on disk

    func test_T7_restoreKeepsTheSlotUntilTheSessionIsOnDisk() {
        let h = AuthHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "hg", refresh: "held-rt", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", Self.session(AuthHarness.anonymousUser("hg"), refresh: "held-rt-rot", sid: "sid-held"))
        h.secure.failWrites = { $0 == "sendora_auth_access_token" } // the session write fails; the slot write lands
        guard case .success(let u) = (result(h) { h.auth.restoreHeldGuest(completion: $0) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("restore") }
        XCTAssertEqual(u.id, "hg"); XCTAssertEqual(h.auth.status(), .anonymous, "installed in memory")
        XCTAssertTrue(h.auth.pendingCommit, "a pending commit (the write is retried)")
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "held-rt-rot", "the slot (with the rotated token) is KEPT — the guest's only durable copy")
        XCTAssertEqual(h.transitionEventNames, ["signed_in"], "no guest_released before the slot really goes")
        // The store recovers: the pending commit lands, THEN the slot is released and announced.
        h.secure.failWrites = nil
        XCTAssertNotNil(h.getAccessToken())
        XCTAssertFalse(h.auth.pendingCommit)
        XCTAssertNil(h.heldSlot(0), "released once the session is confirmed")
        XCTAssertEqual(h.transitionEventNames, ["signed_in", "guest_released"])
        if case .guestReleased(let id, let reason, _)? = h.events.last { XCTAssertEqual(id, "hg"); XCTAssertEqual(reason, .restored) }
    }

    func test_T7_recoverKeepsTheQuarantineSlotUntilTheSessionIsOnDisk() {
        let h = AuthHarness()
        h.seedQuarantine(0, userId: "g-q", refresh: "q-rt")
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", Self.session(AuthHarness.anonymousUser("g-q"), refresh: "q-rt-2", sid: "sid-q"))
        h.secure.failWrites = { $0 == "sendora_auth_access_token" }
        guard case .success = (result(h) { h.auth.recoverQuarantinedGuest("g-q", completion: $0) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("recover") }
        XCTAssertEqual(h.quarantineSlot(0)?.refreshToken, "q-rt-2", "the quarantine slot (rotated) is KEPT while the session is unconfirmed")
        // A relaunch NOW (the process dies before the retry) still finds the guest.
        let before = h.secureSnapshot
        XCTAssertNil(before[Self.refreshKey]); XCTAssertNotNil(before[SendoraStorage.quarantineSlotKeys[0]])
        h.secure.failWrites = nil
        XCTAssertNotNil(h.getAccessToken())
        XCTAssertNil(h.quarantineSlot(0), "released once the session is confirmed")
        XCTAssertEqual(h.transitionEventNames.last, "guest_released")
    }

    func test_T7_claimKeepsTheSlotUntilTheAccountSessionIsOnDisk() {
        let h = AuthHarness()
        h.seedSession(user: Self.account, access: Self.accountToken(sid: "sid-ident"), refresh: "rt-ident")
        h.seedSlot(0, AuthHarness.slot(userId: "hg", refresh: "held-rt", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", Self.session(AuthHarness.anonymousUser("hg"), refresh: "held-rt-2", sid: "sid-held"))
        h.transport.stub("POST", "/auth-service/merge", .ok(["tokens": Stub.tokens(access: Self.accountToken(sid: "sid-ident"), refresh: "rt-ident-2"),
                                                             "mergedUserId": Self.account.id, "deletedAnonymousId": "hg"]))
        h.secure.failWrites = { $0 == "sendora_auth_access_token" }
        guard case .success = (result(h) { h.auth.claimHeldGuest(completion: $0) } as Result<SendoraCloudClaimResult, SendoraCloudAuthError>) else { return XCTFail("claim") }
        XCTAssertNotNil(h.heldSlot(0), "kept while the account's rotated pair is not on disk")
        h.secure.failWrites = nil
        XCTAssertNotNil(h.getAccessToken())
        XCTAssertNil(h.heldSlot(0))
        XCTAssertEqual(h.transitionEventNames, ["user_updated", "guest_released"])
    }

    /// The hydrate half: a recover whose session landed but whose release did not → the duplicate quarantine slot goes.
    func test_T7_hydrateDropsAQuarantineSlotThatDuplicatesTheCurrentSession() {
        let h = AuthHarness()
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        h.seedQuarantine(0, userId: Self.guest.id, refresh: "rt-anon")
        h.seedQuarantine(1, userId: Self.guest.id, refresh: "rt-older")
        h.boot()
        XCTAssertNil(h.quarantineSlot(0), "exact duplicate (same token) dropped")
        XCTAssertNotNil(h.quarantineSlot(1), "a different token of the same guest is NOT a duplicate")
    }

    // MARK: T8 — a slot rotation that does not reach disk is a pending value

    func test_T8_aHeldSlotRotationThatDoesNotLandStopsTheRestore_retryableAndKeptInMemory() {
        let h = AuthHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "hg", refresh: "held-rt", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh") { req in Self.session(AuthHarness.anonymousUser("hg"), refresh: "\(req.body?["refreshToken"] as? String ?? "")-rot", sid: "sid-held") }
        h.secure.failWrites = { $0.hasPrefix("sendora_auth_held_") }
        let e = (result(h) { h.auth.restoreHeldGuest(completion: $0) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError
        XCTAssertEqual(e?.code, "RESTORE_FAILED"); XCTAssertEqual(e?.retryable, true)
        XCTAssertEqual(h.auth.status(), .signedOut, "nothing installed on an unconfirmed rotation")
        XCTAssertEqual(h.auth.heldGuests().map { $0.userId }, ["hg"], "still held")
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "held-rt", "harness: the disk still holds the spent token")
        // The store recovers: the in-memory successor is re-written (next retry point) and the retry presents IT.
        h.secure.failWrites = nil
        _ = h.getAccessToken()
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "held-rt-rot", "the dirty slot is re-written on the next pending-commit retry")
        guard case .success = (result(h) { h.auth.restoreHeldGuest(completion: $0) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("retry") }
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").compactMap { $0.body?["refreshToken"] as? String }, ["held-rt", "held-rt-rot"])
    }

    func test_T8_aQuarantineRotationThatDoesNotLandIsKept_notDropped() {
        let h = AuthHarness()
        h.seedQuarantine(0, userId: "g-q", refresh: "q-rt")
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh") { req in Self.session(AuthHarness.anonymousUser("g-q"), refresh: "\(req.body?["refreshToken"] as? String ?? "")-2", sid: "sid-q") }
        h.secure.failWrites = { $0.hasPrefix("sendora_auth_quarantine_") }
        let e = (result(h) { h.auth.recoverQuarantinedGuest("g-q", completion: $0) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError
        XCTAssertEqual(e?.code, "STORAGE_UNAVAILABLE"); XCTAssertEqual(e?.retryable, true)
        XCTAssertEqual(h.auth.status(), .signedOut)
        h.secure.failWrites = nil
        guard case .success = (result(h) { h.auth.recoverQuarantinedGuest("g-q", completion: $0) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("retry") }
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").compactMap { $0.body?["refreshToken"] as? String }, ["q-rt", "q-rt-2"],
                       "the retry presents the in-memory successor (it used to be dropped — only the spent token was left)")
    }

    // MARK: T9 — signOut() while unreadable defers (a verb's re-read runs it first)

    func test_T9_aDeferredSignOutRunsBeforeTheVerbThatRecoveredTheStore() {
        let h = AuthHarness()
        h.storageUnavailableQueueMs = 2_000
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        h.secure.readErrors = [Self.refreshKey]
        h.boot()
        h.waitVoid { done in h.auth.signOut(completion: done) }
        XCTAssertEqual(h.storedRefresh, "rt-anon", "nothing deleted while unreadable")
        h.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true),
                                                                       tokens: Stub.tokens(access: TestJWT.make(sub: "fresh", sid: "sid-f"), refresh: "rt-fresh"), status: 201))
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { h.secure.readErrors = [] }
        guard case .success(let u) = h.mint() else { return XCTFail("mint after the unlock") }
        XCTAssertEqual(u.id, "fresh", "the requested sign-out ran first — the mint did not return the signed-out guest")
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-anon")
        XCTAssertEqual(h.transitionEventNames, ["signed_out", "signed_in"])
    }

    // MARK: T10 — quarantine from `unknown` with no access token: the disk user says it is a guest

    func test_T10_reuseInUnknownUsesTheDiskUserWhenThereIsNoAccessToken() {
        let h = AuthHarness()
        h.secure.seed(Self.refreshKey, "rt-limbo")
        h.secure.seed("sendora_auth_user", SendoraCloudAuth.encodeUser(Self.guest)!)
        h.boot()
        XCTAssertEqual(h.auth.status(), .unknown, "precondition: LIMBO_A (no access token)")
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "reuse"))
        XCTAssertNil(h.getAccessToken())
        XCTAssertEqual(h.quarantineSlot(0)?.userId, Self.guest.id, "a guest by its disk record → QUARANTINED, never cleared")
        XCTAssertEqual(h.quarantineSlot(0)?.refreshToken, "rt-limbo")
    }

    // MARK: T12 — a pending commit blocks the next rotation

    func test_T12_aRotationStillUnconfirmedOnDiskBlocksTheNextRotation() {
        let h = guestHarness()
        h.transport.stub("POST", "/auth-service/token/refresh") { req in Self.session(Self.guest, refresh: "\(req.body?["refreshToken"] as? String ?? "")-rot") }
        h.secure.failWrites = { $0 == Self.refreshKey }
        XCTAssertNotNil(h.getAccessToken(forceRefresh: true))
        XCTAssertTrue(h.auth.pendingCommit, "precondition: the first rotation is a pending commit")
        XCTAssertNil(h.getAccessToken(forceRefresh: true))
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 1, "no second /token/refresh while the first pair is not on disk")
        XCTAssertEqual(h.storedRefresh, "rt-anon"); XCTAssertEqual(h.auth.getRefreshToken(), "rt-anon-rot")
    }

    // MARK: T14 — release by occupant checks the timestamp

    func test_T14_aReleaseNamesTheOccupantsTimestampToo() {
        let h = AuthHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "hg", refresh: "rt-h", heldAt: 1_000))
        h.seedQuarantine(0, userId: "qg", refresh: "q-rt", at: 5)
        h.boot()
        XCTAssertNil(h.auth.commitRelease(index: 0, userId: "hg", heldAt: 999), "same userId, different heldAt → dropped")
        XCTAssertNil(h.auth.commitQuarantineRelease(index: 0, userId: "qg", quarantinedAt: 4), "same userId, different quarantinedAt → dropped")
        XCTAssertNotNil(h.heldSlot(0)); XCTAssertNotNil(h.quarantineSlot(0))
        XCTAssertNotNil(h.auth.commitRelease(index: 0, userId: "hg", heldAt: 1_000))
        XCTAssertNotNil(h.auth.commitQuarantineRelease(index: 0, userId: "qg", quarantinedAt: 5))
    }

    // MARK: T15 — a confirmed-durable marker; re-check storage on didBecomeActive

    func test_T15_theMarkerIsAConfirmedKeychainWrite_andAFailedOneAbortsTheRefresh() {
        let h = guestHarness()
        var markerAtSend: String?
        h.transport.onRequest = { req in if req.path == "/auth-service/token/refresh" { markerAtSend = h.secure.get(SendoraStorage.refreshInflightKey) } }
        h.transport.stub("POST", "/auth-service/token/refresh", .offline)
        XCTAssertNil(h.getAccessToken(forceRefresh: true))
        XCTAssertNotNil(markerAtSend, "the marker was a Keychain item, on disk, before the request went out")
        XCTAssertNil(h.plain.string(forKey: SendoraStorage.refreshInflightKey), "not a UserDefaults read-back")
        let f = guestHarness()
        f.secure.failWrites = { $0 == SendoraStorage.refreshInflightKey }
        XCTAssertNil(f.getAccessToken(forceRefresh: true))
        XCTAssertEqual(f.transport.requests(to: "/auth-service/token/refresh").count, 0, "a marker that does not confirm aborts the refresh")
    }

    func test_T15_aResumeReChecksAnUnreadableStore() {
        let h = AuthHarness()
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        h.secure.readErrors = [Self.refreshKey]
        h.boot()
        XCTAssertEqual(h.auth.status(), .unknown)
        // The unlock happened while the app was suspended (protectedDataDidBecomeAvailable is not replayed).
        h.secure.readErrors = []
        NotificationCenter.default.post(name: SendoraCloudAuth.appDidBecomeActiveNotification, object: nil)
        XCTAssertTrue(h.eventually { h.auth.status() == .anonymous }, "didBecomeActive re-reads the store")
        XCTAssertEqual(h.transitionEventNames.last, "signed_in")
    }

    // MARK: T17 — guest_held.count includes reserved slots; the double's failWrites covers set / delete

    func test_T17_guestHeldCountIncludesReservedSlots() {
        let h = AuthHarness()
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        h.seedRawSlot(0, "{ torn")
        h.boot()
        h.transport.stub("POST", "/auth-service/login", Self.session(Self.account, refresh: "rt-acct", sid: "sid-b"))
        guard case .success = h.signIn() else { return XCTFail("sign-in") }
        guard case .guestHeld(_, let count)? = h.events.first(where: { $0.eventName == "guest_held" }) else { return XCTFail("guest_held") }
        XCTAssertEqual(count, 2, "the new hold + the reserved (unreadable) slot — RN / web / Android count it too")
    }

    func test_T17_harnessFailWritesAppliesToTheLegacySetAndDelete() {
        let s = RecordingSecureStore()
        s.seed("k", "old")
        s.failWrites = { _ in true }
        s.set("k", "new"); s.delete("k")
        XCTAssertEqual(s.get("k"), "old", "a faulted legacy set / delete changes nothing, like the real store")
        XCTAssertEqual(s.writeCount, 0)
    }

    // MARK: iOS H2 — a sign-in whose new tokens landed but whose user / record did not

    func test_H2_aPartialSignInWriteNeverDropsTheHeldGuest() {
        // Disk after the partial write: account A's access + refresh, guest G's user blob and record, G held in slot 0.
        let h = AuthHarness()
        let accountAccess = Self.accountToken(sid: "sid-b")
        h.secure.seed("sendora_auth_access_token", accountAccess)
        h.secure.seed(Self.refreshKey, "rt-acct")
        h.secure.seed("sendora_auth_access_expires", String(Int64(Date().timeIntervalSince1970 * 1000) + 900_000))
        h.secure.seed("sendora_auth_user", SendoraCloudAuth.encodeUser(Self.guest)!)
        let gRecord = AuthSessionRecord(user: Self.guest, accessToken: Self.guestToken(), refreshToken: "rt-g", accessExpiresAt: 1, sid: "sid-anon", heldReportPending: [])
        h.secure.seed(SendoraStorage.authSessionKey, SendoraCloudAuth.encodeSessionRecord(gRecord)!)
        h.seedSlot(0, AuthHarness.slot(userId: Self.guest.id, refresh: "rt-g", heldAt: 1))
        h.boot()
        XCTAssertEqual(h.auth.status(), .unknown, "identity-uncertain (the user blob is not the token's sub) → unknown, never G-with-A's-tokens")
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "rt-g", "the held guest's only token is NOT dropped")
        h.transport.stub("POST", "/auth-service/token/refresh", Self.session(Self.account, refresh: "rt-acct-2", sid: "sid-b"))
        XCTAssertNotNil(h.getAccessToken(), "the gap-fill refresh names the user")
        XCTAssertEqual(h.auth.status(), .identified); XCTAssertEqual(h.auth.currentUser?.id, Self.account.id)
        XCTAssertEqual(h.auth.heldGuests().map { $0.userId }, [Self.guest.id], "G is still held")
    }

    func test_H2_aFailedAccessWriteNeverLeavesANewRefreshBesideAnOldAccessToken() {
        let h = guestHarness()
        h.transport.stub("POST", "/auth-service/login", Self.session(Self.account, refresh: "rt-acct", sid: "sid-b"))
        h.secure.failWrites = { $0 == "sendora_auth_access_token" }
        guard case .success = h.signIn() else { return XCTFail("sign-in (installed in memory)") }
        XCTAssertEqual(h.storedRefresh, "rt-anon", "the refresh key is not written when its access token did not land")
        // Relaunch over that disk (the old process's later retries keep failing the same way — its B15 report
        // acknowledgement re-writes the record): the guest is coherent (its own access + refresh + user) — and held
        // too: the duplicate slot goes, the guest is the session again, nothing is lost.
        XCTAssertTrue(h.eventually { h.transport.requests(to: "/auth-service/guest/held").count == 1 })
        usleep(50_000)
        XCTAssertEqual(h.storedRefresh, "rt-anon")
        h.boot()
        XCTAssertEqual(h.auth.status(), .anonymous); XCTAssertEqual(h.auth.currentUser?.id, Self.guest.id)
        XCTAssertEqual(h.storedRefresh, "rt-anon")
    }
}
