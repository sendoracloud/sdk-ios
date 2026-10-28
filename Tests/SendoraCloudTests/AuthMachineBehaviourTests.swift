import XCTest
@testable import SendoraCloud

// ADR-033 wave 1 — behavioural tests BESIDE the row replay: the §5 integrator
// conformance test 10, the B15 hold-report retry, the native-sheet CAS for the
// passkey / OIDC paths, and the 5.3.0 declarations kept verbatim. Same recording
// doubles as the row scenarios; nothing here reads source text.

final class AuthMachineBehaviourTests: XCTestCase {
    private static let guestA = AuthHarness.anonymousUser("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    private static let ident = AuthHarness.identifiedUser()

    private func identifiedLogin(refresh: String) -> StubResponse {
        Stub.session(user: Stub.user(id: Self.ident.id, isAnonymous: false, email: "p@example.com"),
                     tokens: Stub.tokens(access: TestJWT.make(sub: Self.ident.id, sid: "sid-\(refresh)", isAnonymous: false), refresh: refresh))
    }

    private func waitUntil(_ timeout: TimeInterval = 3, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            usleep(10_000)
        }
        return condition()
    }

    // MARK: §5 conformance test 10 (integrator)

    /// Two sign-ins in a row from two different guests → both held (two slots),
    /// `guestHeld` carries count 1 then 2, nothing displaced, `heldGuests()` is
    /// ordered `heldAt` desc.
    func test_twoSignInsFromTwoGuestsHoldBothNewestFirst() {
        let h = AuthHarness(autoRestoreHeldGuest: false)
        h.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, sid: "sid-a"), refresh: "rt-a")
        h.boot()
        XCTAssertEqual(h.auth.status(), .anonymous)
        h.transport.stub("POST", "/auth-service/login", identifiedLogin(refresh: "rt-b1"))
        guard case .success = h.signIn() else { return XCTFail("first sign-in") }

        // Back to a (different) guest: sign out, mint (autoRestore off → fresh guest C).
        h.waitVoid { done in h.auth.signOut(completion: done) }
        h.transport.stub("POST", "/auth-service/anonymous",
                         Stub.session(user: Stub.user(id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", isAnonymous: true),
                                      tokens: Stub.tokens(access: TestJWT.make(sub: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", sid: "sid-c"), refresh: "rt-c"), status: 201))
        guard case .success(let guestC) = h.mint() else { return XCTFail("mint guest C") }
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 0, "autoRestore off: the held guest A is not restored")
        usleep(5_000) // distinct heldAt
        h.transport.stub("POST", "/auth-service/login", identifiedLogin(refresh: "rt-b2"))
        guard case .success = h.signIn() else { return XCTFail("second sign-in") }

        let held: [(String, Int)] = h.events.compactMap {
            if case .guestHeld(let id, let count) = $0 { return (id, count) }
            return nil
        }
        XCTAssertEqual(held.map { $0.0 }, [Self.guestA.id, guestC.id])
        XCTAssertEqual(held.map { $0.1 }, [1, 2], "count 1 then 2")
        XCTAssertEqual(h.auth.heldGuests().map { $0.userId }, [guestC.id, Self.guestA.id], "heldAt desc")
        XCTAssertNotNil(h.heldSlot(0)); XCTAssertNotNil(h.heldSlot(1), "nothing displaced")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/guest/discard").count, 0)
    }

    /// Two holds at a FROZEN clock: the second `heldAt` is strictly greater than
    /// the first (`max(now, newest + 1)`), so "newest" is defined — and a slot
    /// already stamped in the future (clock stepped back) is still outranked.
    func test_twoHoldsAtAFrozenClockNeverTie() {
        let frozen: Int64 = 1_760_000_000_000
        let h = AuthHarness(autoRestoreHeldGuest: false)
        h.clock = { frozen }
        h.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, sid: "sid-a"), refresh: "rt-a")
        h.boot()
        h.transport.stub("POST", "/auth-service/login", identifiedLogin(refresh: "rt-b1"))
        guard case .success = h.signIn() else { return XCTFail("first hold") }
        h.waitVoid { done in h.auth.signOut(completion: done) }
        let c = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        h.transport.stub("POST", "/auth-service/anonymous",
                         Stub.session(user: Stub.user(id: c, isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: c, sid: "sid-c"), refresh: "rt-c"), status: 201))
        guard case .success = h.mint() else { return XCTFail("mint C") }
        h.transport.stub("POST", "/auth-service/login", identifiedLogin(refresh: "rt-b2"))
        guard case .success = h.signIn() else { return XCTFail("second hold") }
        let held = h.auth.heldGuests()
        XCTAssertEqual(held.map { $0.userId }, [c, Self.guestA.id], "newest first, deterministically")
        XCTAssertEqual(held.map { $0.heldAt }, [frozen + 1, frozen], "strictly increasing at a frozen clock")

        // A slot stamped AHEAD of the clock (it stepped backwards) is still outranked.
        let skew = AuthHarness()
        skew.clock = { frozen }
        skew.seedSlot(0, AuthHarness.slot(userId: "g-future", refresh: "rt-f", heldAt: frozen + 60_000))
        skew.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, sid: "sid-a"), refresh: "rt-a")
        skew.boot()
        skew.transport.stub("POST", "/auth-service/login", identifiedLogin(refresh: "rt-b3"))
        guard case .success = skew.signIn() else { return XCTFail("hold after skew") }
        XCTAssertEqual(skew.auth.heldGuest()?.userId, Self.guestA.id, "the new hold is the newest")
        XCTAssertEqual(skew.auth.heldGuest()?.heldAt, frozen + 60_001)
    }

    // MARK: B15 — the hold report survives a lost acknowledgement

    func test_aPendingHoldReportIsRetriedOnTheNextHydrate() {
        let h = AuthHarness()
        h.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, sid: "sid-a"), refresh: "rt-a")
        h.boot()
        h.transport.stub("POST", "/auth-service/guest/held", Stub.serverError)
        h.transport.stub("POST", "/auth-service/login", identifiedLogin(refresh: "rt-b"))
        guard case .success = h.signIn() else { return XCTFail("sign-in") }
        XCTAssertTrue(waitUntil { h.transport.requests(to: "/auth-service/guest/held").count == 1 })
        usleep(50_000)
        XCTAssertEqual(h.storedSessionRecord?.heldReportPending, [Self.guestA.id], "an unacknowledged report stays pending ON DISK")

        // Next process: the report is retried with the held guest's own token.
        h.transport.stub("POST", "/auth-service/guest/held", .ok(["reported": true]))
        h.boot()
        XCTAssertTrue(waitUntil { h.transport.requests(to: "/auth-service/guest/held").count == 2 }, "retried on hydrate")
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/guest/held")?.body?["refreshToken"] as? String, "rt-a")
        XCTAssertTrue(waitUntil { h.storedSessionRecord?.heldReportPending == [] }, "the acknowledgement clears the pending entry")

        // And a third process does not report again.
        h.boot()
        usleep(100_000)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/guest/held").count, 2)
    }

    func test_aWithheldHydrateMakesNoNetworkCallEvenWithAPendingReport() {
        let h = AuthHarness(expectedProjectId: TestJWT.projectA)
        let access = TestJWT.make(sub: Self.guestA.id, sid: "sid-a", project: .some(TestJWT.projectB))
        h.seedSession(user: Self.guestA, access: access, refresh: "rt-w")
        let record = AuthSessionRecord(user: Self.guestA, accessToken: access, refreshToken: "rt-w",
                                       accessExpiresAt: Int64(Date().timeIntervalSince1970 * 1000) + 900_000,
                                       sid: "sid-a", heldReportPending: ["g-held"])
        h.secure.seed(SendoraStorage.authSessionKey, SendoraCloudAuth.encodeSessionRecord(record)!)
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        let before = h.secure.snapshot()
        h.boot()
        XCTAssertEqual(h.auth.status(), .withheld)
        usleep(100_000)
        XCTAssertEqual(h.transport.requestCount, 0, "withheld: no network of any kind")
        XCTAssertEqual(h.secure.snapshot(), before, "and zero writes")
    }

    // MARK: native-sheet CAS (passkey / OIDC): taken when the ceremony STARTS

    private func externalEnvelope(refresh: String) -> [String: Any] {
        return ["success": true, "data": [
            "user": Stub.user(id: Self.ident.id, isAnonymous: false, email: "p@example.com"),
            "tokens": Stub.tokens(access: TestJWT.make(sub: Self.ident.id, sid: "sid-ext", isAnonymous: false), refresh: refresh),
        ] as [String: Any]]
    }

    func test_anExternalSignInThatLandsAfterSignOutIsDroppedAndRevoked() {
        let h = AuthHarness()
        h.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, sid: "sid-a"), refresh: "rt-a")
        h.boot()
        let startedFrom = h.auth.externalAttemptStart()        // the sheet opens
        h.waitVoid { done in h.auth.signOut(completion: done) } // the player signs out meanwhile
        h.clearEvents()
        let result: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in
            h.auth.completeExternalSignIn(response: externalEnvelope(refresh: "rt-ext"), startedFrom: startedFrom, completion: done)
        }
        XCTAssertNotNil(result.failureError, "a result derived from a session that is gone is DROPPED")
        XCTAssertEqual(h.auth.status(), .signedOut)
        XCTAssertNil(h.storedRefresh)
        // ⚠ Pin converted TWICE: J.1 (first rev-3 cut) held the signed-out guest here; decision C (2026-10-26) put the
        // pre-rev-3 behaviour back — a guest's signOut() drops its token like an account's. Nothing is held, and
        // nothing by the dropped result.
        XCTAssertEqual(h.auth.heldGuests().count, 0, "nothing held: neither the signed-out guest nor the dropped result")
        XCTAssertEqual(h.events.map { $0.eventName }, [])
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-ext",
                       "server session B is not left live")
    }

    func test_anExternalSignInFromTheSameSessionHoldsTheGuest() {
        let h = AuthHarness()
        h.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, sid: "sid-a"), refresh: "rt-a")
        h.boot()
        let startedFrom = h.auth.externalAttemptStart()
        let result: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in
            h.auth.completeExternalSignIn(response: externalEnvelope(refresh: "rt-ext"), startedFrom: startedFrom, completion: done)
        }
        XCTAssertEqual(try? result.get().id, Self.ident.id)
        XCTAssertEqual(h.auth.status(), .identified)
        XCTAssertEqual(h.heldSlot(0)?.userId, Self.guestA.id)
        XCTAssertEqual(h.transitionEventNames, ["guest_held", "signed_in"])
    }

    // MARK: MINOR — the subscribe-time replay keeps the 5.3.0 `.signedIn` (lockstep ruling 1)

    /// `onAuthStateChanged` replays `.initial(status:user:withheld:)` AND THEN —
    /// when a session exists — the legacy `.signedIn(user:)` exactly as 5.3.0 did.
    /// Removing the legacy replay is an event removal a MINOR cannot ship.
    func test_subscribeReplaysInitialThenTheLegacySignedInWhenASessionExists() {
        let anon = AuthHarness()
        anon.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, sid: "sid-a"), refresh: "rt-a")
        let ident = AuthHarness()
        ident.seedSession(user: Self.ident, access: TestJWT.make(sub: Self.ident.id, sid: "sid-i", isAnonymous: false), refresh: "rt-i")
        for (h, user, status) in [(anon, Self.guestA, SendoraCloudAuthStatus.anonymous), (ident, Self.ident, .identified)] {
            h.boot()
            XCTAssertEqual(h.eventNames, ["initial", "signed_in"], "\(status): initial, then the 5.3.0 signedIn replay")
            if case .initial(let s, let u, let w)? = h.events.first {
                XCTAssertEqual(s, status); XCTAssertEqual(u?.id, user.id); XCTAssertNil(w)
            } else { XCTFail("initial first") }
            if case .signedIn(let u)? = h.events.last { XCTAssertEqual(u.id, user.id) } else { XCTFail("signedIn second") }
            // Every subscriber gets its own replay; an existing one gets nothing new.
            var second: [String] = []
            let off = h.auth.onAuthStateChanged { second.append($0.eventName) }
            XCTAssertEqual(second, ["initial", "signed_in"])
            XCTAssertEqual(h.eventNames, ["initial", "signed_in"], "the first subscriber is not replayed twice")
            off()
        }
    }

    /// No session → no legacy `.signedIn` (5.3.0 emitted nothing for a signed-out
    /// cold start); the new `.initial` carries the settled status.
    func test_subscribeReplaysOnlyInitialWithoutASession() {
        let out = AuthHarness()
        let limbo = AuthHarness(); limbo.seedLimbo(refresh: "rt-l")
        let withheld = AuthHarness(expectedProjectId: TestJWT.projectA)
        withheld.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, project: .some(TestJWT.projectB)), refresh: "rt-w")
        for (h, status) in [(out, SendoraCloudAuthStatus.signedOut), (limbo, .unknown), (withheld, .withheld)] {
            h.boot()
            XCTAssertEqual(h.eventNames, ["initial"], "\(status)")
            if case .initial(let s, let u, _)? = h.events.first { XCTAssertEqual(s, status); XCTAssertNil(u) }
        }
    }

    // MARK: downgrade cycle — a record with no matching frozen key is a LEFTOVER

    /// 5.4 session → downgrade to 5.3.0 → 5.3.0 `signOut()` / `deleteAccount()`
    /// (clears ONLY the four frozen keys) → upgrade to 5.4 again. The surviving
    /// `sendora_auth_session` record must NOT reinstall the signed-out / deleted
    /// account: it is cleared silently (no event beyond the boot `initial`, no
    /// network) and the state is `signedOut`.
    func test_aRecordWhoseFrozenKeysAreGoneIsALeftoverNeverReinstalled() {
        for user in [Self.guestA, Self.ident] {
            let h = AuthHarness()
            h.seedSession(user: user, access: TestJWT.make(sub: user.id, sid: "sid-x", isAnonymous: user.isAnonymous), refresh: "rt-x")
            h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
            // what a 5.3.0 signOut()/deleteAccount() leaves behind
            for key in AuthHarness.frozenAuthKeys { h.secure.delete(key) }
            let mark = h.secure.writeCount
            h.boot()
            XCTAssertEqual(h.auth.status(), .signedOut, "\(user.id): never reinstalled from the leftover record")
            XCTAssertNil(h.auth.currentUser)
            XCTAssertNil(h.storedSessionRecord, "the leftover record is cleared")
            XCTAssertEqual(h.eventNames, ["initial"], "silently — no signed_in, no signed_out")
            XCTAssertEqual(h.identityChanges, [])
            usleep(50_000)
            XCTAssertEqual(h.transport.requestCount, 0, "no network")
            XCTAssertNotNil(h.heldSlot(0), "held guests are not the record's to clear")
            // ⚠ Pin converted (s58.415, G7): a hydrate never deletes a record holding a refresh token the frozen keys
            // lack unless nothing in it can be a guest's last handle. A GUEST's leftover is RESCUED into a quarantine slot
            // first (the one write; never auto-restored, never presented); an account's is just cleared.
            let sets = h.secure.writesSince(mark).filter { $0.op == "set" }.map { $0.key }
            if user.isAnonymous {
                XCTAssertEqual(sets, [SendoraStorage.quarantineSlotKeys[0]], "the guest's leftover token is rescued, then the record cleared")
                XCTAssertEqual(h.quarantineSlot(0)?.refreshToken, "rt-x")
                XCTAssertEqual(h.auth.getQuarantinedGuests().map { $0.userId }, [user.id])
            } else {
                XCTAssertEqual(sets, [], "an account's leftover: nothing written, only the leftover deleted")
            }
        }
        // …and with the quarantine FULL the guest's leftover record is NOT deleted (signed out over the bytes).
        let full = AuthHarness()
        full.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, sid: "sid-x"), refresh: "rt-x")
        for key in AuthHarness.frozenAuthKeys { full.secure.delete(key) }
        for i in 0..<3 { full.seedQuarantine(i, userId: "q\(i)", refresh: "rq\(i)") }
        full.boot()
        XCTAssertEqual(full.auth.status(), .signedOut)
        XCTAssertEqual(full.storedSessionRecord?.refreshToken, "rt-x", "kept — it may be the guest's only token")
    }

    /// 5.3.0 signed into ANOTHER account after the downgrade, and its user blob is
    /// unreadable (LIMBO_A): the record (account A) does not match the frozen
    /// refresh token (account C), so it is dropped at hydrate — a later rotation
    /// can never graft C's tokens onto A's user and have the next boot trust it.
    func test_aMismatchedRecordInLimboIsDroppedNotRotated() {
        let h = AuthHarness()
        h.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, sid: "sid-a"), refresh: "rt-a")
        h.secure.seed("sendora_auth_refresh_token", "rt-c")     // 5.3.0 signed into C…
        h.secure.seed("sendora_auth_user", "{not json")          // …and C's blob is unreadable
        h.boot()
        XCTAssertEqual(h.auth.status(), .unknown)
        XCTAssertNil(h.storedSessionRecord, "A's record is not C's — dropped")
        h.transport.stub("POST", "/auth-service/token/refresh",
                         Stub.session(user: Stub.user(id: Self.ident.id, isAnonymous: false, email: "p@example.com"),
                                      tokens: Stub.tokens(access: TestJWT.make(sub: Self.ident.id, sid: "sid-c", isAnonymous: false), refresh: "rt-c2")))
        XCTAssertNotNil(h.getAccessToken())
        XCTAssertEqual(h.auth.currentUser?.id, Self.ident.id)
        XCTAssertEqual(h.storedSessionRecord?.user.id, Self.ident.id)
        h.boot()
        XCTAssertEqual(h.auth.currentUser?.id, Self.ident.id, "the next boot trusts the record only because it is C's")
    }

    /// The withhold-on-refresh rotation (writeRotationOnly) must not rotate a record
    /// that belongs to another session: under the guard, an absent claim keeps a
    /// rebuilt session `unknown` with no writes, the refresh lands on project B
    /// (withheld), and the stale record of account A must be DROPPED — rotating it
    /// would make the next boot install A's user with C's tokens.
    func test_aWithholdRotationNeverGraftsTokensOntoALeftoverRecord() {
        let h = AuthHarness(expectedProjectId: TestJWT.projectA)
        // record = account A (rt-a); frozen keys = account C (rt-c) with an ABSENT project claim
        h.seedSession(user: Self.guestA, access: TestJWT.make(sub: Self.guestA.id, sid: "sid-a"), refresh: "rt-a")
        let cUser = AuthHarness.anonymousUser("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        h.secure.seed("sendora_auth_refresh_token", "rt-c")
        h.secure.seed("sendora_auth_access_token", TestJWT.make(sub: cUser.id, sid: "sid-c", project: nil))
        h.secure.seed("sendora_auth_user", SendoraCloudAuth.encodeUser(cUser)!)
        h.boot()
        XCTAssertEqual(h.auth.status(), .unknown, "absent claim under the guard")
        h.transport.stub("POST", "/auth-service/token/refresh",
                         Stub.session(user: Stub.user(id: cUser.id, isAnonymous: true, project: TestJWT.projectB),
                                      tokens: Stub.tokens(access: TestJWT.make(sub: cUser.id, sid: "sid-c", project: .some(TestJWT.projectB)), refresh: "rt-c2")))
        _ = h.getAccessToken()
        XCTAssertEqual(h.auth.status(), .withheld)
        XCTAssertEqual(h.storedRefresh, "rt-c2", "the server-performed rotation is persisted to the frozen keys")
        XCTAssertNotEqual(h.storedSessionRecord?.user.id, Self.guestA.id, "A's leftover record never carries C's tokens")
        // Re-init without the guard: whatever installs must be C, never A.
        h.expectedProjectId = nil
        h.boot()
        XCTAssertNotEqual(h.auth.currentUser?.id, Self.guestA.id)
        XCTAssertEqual(h.auth.getRefreshToken(), "rt-c2")
    }

    /// Every install writes the four frozen keys BEFORE the record, so a crash
    /// between the two can leave a frozen-only disk (re-forwarded on the next
    /// hydrate) but never a record-only one.
    func test_installWritesTheFrozenKeysBeforeTheRecord() {
        let h = AuthHarness()
        h.boot()
        h.transport.stub("POST", "/auth-service/anonymous",
                         Stub.session(user: Stub.user(id: Self.guestA.id, isAnonymous: true),
                                      tokens: Stub.tokens(access: TestJWT.make(sub: Self.guestA.id, sid: "sid-a"), refresh: "rt-a"), status: 201))
        let mark = h.secure.writeCount
        guard case .success = h.mint() else { return XCTFail("mint") }
        let writes = h.secure.writesSince(mark).map { $0.key }
        guard let record = writes.firstIndex(of: SendoraStorage.authSessionKey) else { return XCTFail("record written") }
        for key in AuthHarness.frozenAuthKeys {
            guard let i = writes.firstIndex(of: key) else { XCTFail("\(key) written"); continue }
            XCTAssertLessThan(i, record, "\(key) before the record")
        }
    }

    // MARK: MINOR — the 5.3.0 declarations survive verbatim

    func test_preWaveDeclarationsAreStillThere() {
        let h = AuthHarness()
        h.boot()
        // Unapplied references with the 5.3.0 types: a defaulted parameter in
        // their place would fail to compile here.
        let reset: () -> Void = SendoraCloud.reset
        let delete: (@escaping (Result<SendoraCloudAuth.AccountDeletionResult, Error>) -> Void) -> Void = h.auth.deleteAccount(completion:)
        _ = reset; _ = delete
    }
}
