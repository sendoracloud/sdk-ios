import XCTest
@testable import SendoraCloud

// s58.415 — zero guest-account loss (`docs/audit/sdk-auth-s58.415/SPEC-guest-loss-sdk.md` G1–G8 + the iOS items
// D2 / #4 / #8 / #9 / #10 / #11). Behavioural, on the real auth machine through `AuthHarness` (recording Keychain with
// its fault switches, scripted transport). The changed shared rows are driven in `AuthMachineRowScenarios*.swift`;
// this file covers what the rows do not show on their own. ⚠ No test name here may contain the substring that
// `swift test --skip` filters the staging suites with (it is a regex — such a test would be skipped silently).

final class GuestLossTests: XCTestCase {
    static let guest = AuthHarness.anonymousUser()
    static let account = AuthHarness.identifiedUser()
    static func guestToken(_ id: String = guest.id, sid: String = "sid-anon") -> String { TestJWT.make(sub: id, sid: sid, isAnonymous: true) }
    static let accountToken = TestJWT.make(sub: account.id, sid: "sid-ident", isAnonymous: false)

    private func guestHarness(configure: (AuthHarness) -> Void = { _ in }) -> AuthHarness {
        let h = AuthHarness()
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        configure(h)
        h.boot()
        return h
    }

    private func refreshOk(_ id: String, refresh: String, anonymous: Bool = true, sid: String = "sid-anon") -> StubResponse {
        Stub.session(user: Stub.user(id: id, isAnonymous: anonymous), tokens: Stub.tokens(access: TestJWT.make(sub: id, sid: sid, isAnonymous: anonymous), refresh: refresh))
    }

    private func mintResponse(_ id: String = "fresh") -> StubResponse {
        Stub.session(user: Stub.user(id: id, isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: id, sid: "sid-\(id)"), refresh: "rt-\(id)"), status: 201)
    }

    // MARK: - G1 — never throw a guest's token away on a verdict the server could not confirm

    /// The env-switch incident shape (X1): the SAME guest + its held guests are presented to a backend that never issued
    /// them. With the hint the server answers `unknown` — and NOTHING is lost: the current guest is quarantined, and
    /// ensureSession()'s auto-restore moves every held guest to quarantine instead of releasing it, then mints.
    func test_G1_aBackendThatNeverIssuedTheTokensAnswersUnknown_noGuestIsDropped() {
        let h = guestHarness { h in
            h.seedSlot(0, AuthHarness.slot(userId: "g0", refresh: "rt-g0", heldAt: 1, access: "at-g0"))
            h.seedSlot(1, AuthHarness.slot(userId: "g1", refresh: "rt-g1", heldAt: 2, access: "at-g1"))
        }
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "unknown"))
        h.transport.stub("POST", "/auth-service/anonymous", mintResponse())
        XCTAssertNil(h.getAccessToken(forceRefresh: true))
        XCTAssertEqual(h.auth.status(), .signedOut)
        guard case .success(let fresh) = h.mint() else { return XCTFail("ensureSession() must not fail RESTORE_FAILED on a slot it moved") }
        XCTAssertEqual(fresh.id, "fresh")
        let quarantined = Set((0..<3).compactMap { h.quarantineSlot($0)?.refreshToken })
        XCTAssertEqual(quarantined, ["rt-anon", "rt-g0", "rt-g1"], "every token survives on the device")
        XCTAssertNil(h.heldSlot(0)); XCTAssertNil(h.heldSlot(1))
        let hints = h.transport.requests(to: "/auth-service/token/refresh").compactMap { $0.body?["accessTokenHint"] as? String }
        XCTAssertEqual(hints, [Self.guestToken(), "at-g1", "at-g0"], "every presentation carried its hint (newest held first)")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/guest/discard").count, 0)
    }

    /// A CLAIM whose held guest comes back with anything but `deleted` moves it to quarantine (RESTORE_FAILED, retryable).
    func test_G1_aClaimOnANonDeletedVerdictQuarantinesTheHeldGuest() {
        let h = AuthHarness()
        h.seedSession(user: Self.account, access: Self.accountToken, refresh: "rt-ident")
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "revoked"))
        let r: Result<SendoraCloudClaimResult, SendoraCloudAuthError> = h.wait { done in h.auth.claimHeldGuest(id: "g-held", completion: done) }
        XCTAssertEqual(r.failureError?.code, "RESTORE_FAILED"); XCTAssertEqual(r.failureError?.retryable, true)
        XCTAssertEqual(h.quarantineSlot(0)?.refreshToken, "rt-held")
        XCTAssertNil(h.heldSlot(0))
        XCTAssertEqual(h.transport.requests(to: "/auth-service/merge").count, 0)
        XCTAssertEqual(h.auth.status(), .identified, "the account is untouched")
    }

    /// The held-slot move is CONFIRMED before the held slot goes: a quarantine write that does not land parks the slot
    /// (autoRestore:false) — the token is never in zero places.
    func test_G1_aQuarantineWriteThatDoesNotLandParksTheHeldSlotInstead() {
        let h = AuthHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        h.secure.failWrites = { $0.hasPrefix("sendora_auth_quarantine_") }
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "expired"))
        let r: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.restoreHeldGuest(id: "g-held", completion: done) }
        XCTAssertEqual(r.failureError?.code, "RESTORE_FAILED")
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "rt-held", "kept")
        XCTAssertEqual(h.heldSlot(0)?.autoRestore, false, "parked")
        XCTAssertNil(h.quarantineSlot(0))
        XCTAssertEqual(h.transitionEventNames, [], "nothing released")
    }

    // MARK: - G2 — accessTokenHint

    func test_G2_everyRefreshCarriesTheLastAccessTokenAndEverySlotKeepsItsOwn() {
        // A HOLD stores the held session's access token; a slot rotation stores the rotated one.
        let h = guestHarness()
        h.transport.stub("POST", "/auth-service/login", Stub.session(user: Stub.user(id: Self.account.id, isAnonymous: false, email: "p@example.com"),
                                                                   tokens: Stub.tokens(access: Self.accountToken, refresh: "rt-b")))
        guard case .success = h.signIn() else { return XCTFail("sign-in") }
        XCTAssertEqual(h.heldSlot(0)?.accessToken, Self.guestToken(), "held with its last access token")
        XCTAssertEqual(h.heldSlot(0)?.origin, AuthHarness.origin, "held with its origin")
        XCTAssertEqual(h.storedSessionRecord?.origin, AuthHarness.origin, "the installed session is bound to the configured origin")
        // restore rotates the slot first: the rotated access token lands in the slot (CAS per slot) before the install.
        let rotatedAccess = TestJWT.make(sub: Self.guest.id, sid: "sid-anon-2")
        var slotAfterRotation: HeldSlotRecord?
        h.transport.stub("POST", "/auth-service/token/refresh") { req in
            XCTAssertEqual(req.body?["accessTokenHint"] as? String, Self.guestToken(), "the held slot's hint")
            return Stub.session(user: Stub.user(id: Self.guest.id, isAnonymous: true), tokens: Stub.tokens(access: rotatedAccess, refresh: "rt-anon-2"))
        }
        h.secure.failWrites = { $0 == "sendora_auth_access_token" } // keep the install pending → the slot stays, readable
        let r: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.restoreHeldGuest(id: Self.guest.id, completion: done) }
        guard case .success = r else { return XCTFail("restore") }
        slotAfterRotation = h.heldSlot(0)
        XCTAssertEqual(slotAfterRotation?.refreshToken, "rt-anon-2"); XCTAssertEqual(slotAfterRotation?.accessToken, rotatedAccess)
        h.secure.failWrites = nil
        // A limbo with no access token sends no hint (checked in the quarantine scenario); a current session sends its own.
        let c = guestHarness()
        c.transport.stub("POST", "/auth-service/token/refresh", refreshOk(Self.guest.id, refresh: "rt-anon-2"))
        XCTAssertNotNil(c.getAccessToken(forceRefresh: true))
        XCTAssertEqual(c.transport.lastRequest(to: "/auth-service/token/refresh")?.body?["accessTokenHint"] as? String, Self.guestToken())
        // recoverQuarantinedGuest sends the slot's stored hint.
        let q = AuthHarness()
        q.seedQuarantine(0, userId: "g-q", refresh: "q-rt", access: "at-q")
        q.boot()
        q.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "unknown"))
        _ = q.wait { done in q.auth.recoverQuarantinedGuest("g-q", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>
        XCTAssertEqual(q.transport.lastRequest(to: "/auth-service/token/refresh")?.body?["accessTokenHint"] as? String, "at-q")
        XCTAssertNotNil(q.quarantineSlot(0), "unknown → kept")
    }

    // MARK: - G3 — origin binding of slots

    func test_G3_aSlotOfAnotherOriginIsNeverPresentedNeverReleasedAndCountsAsReserved() {
        let other = "https://api.sendoracloud.com"
        let h = AuthHarness()
        for i in 0..<4 { h.seedSlot(i, AuthHarness.slot(userId: "foreign\(i)", refresh: "rt-f\(i)", heldAt: Int64(i + 1), origin: other)) }
        h.seedSlot(4, AuthHarness.slot(userId: "mine", refresh: "rt-mine", heldAt: 9, autoRestore: false, origin: AuthHarness.origin))
        h.seedQuarantine(0, userId: "fq", refresh: "rt-fq", origin: other)
        h.boot()
        XCTAssertEqual(h.auth.heldGuests().map { $0.userId }, ["mine"], "another origin's held guests are not listed")
        XCTAssertEqual(h.auth.getQuarantinedGuests().count, 0, "nor its quarantined ones")
        // counted in T (4 foreign + 1 ineligible = 5 = K): no eligible slot → the cap refuses the mint.
        XCTAssertEqual(h.mint().failureError?.code, "HELD_GUEST_LIMIT")
        // never presented, never sent anywhere
        XCTAssertEqual(h.wait { done in h.auth.restoreHeldGuest(id: "foreign0", completion: done) }.failureError?.code, "HELD_GUEST_GONE")
        XCTAssertEqual((h.wait { done in h.auth.discardHeldGuest(id: "foreign0", completion: done) } as Result<Void, SendoraCloudAuthError>).failureError?.code, "HELD_GUEST_GONE")
        let rq: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.recoverQuarantinedGuest("fq", completion: done) }
        XCTAssertEqual(rq.failureError?.code, "QUARANTINE_UNRECOVERABLE"); XCTAssertEqual(rq.failureError?.retryable, true)
        XCTAssertEqual((h.wait { done in h.auth.discardQuarantinedGuest("fq", completion: done) } as Result<Void, SendoraCloudAuthError>).failureError?.code, "QUARANTINE_UNRECOVERABLE")
        // never released, even by the RESET row with includeHeldGuests
        h.waitVoid { done in h.auth.resetFromParent(includeHeldGuests: true, completion: done) }
        for i in 0..<4 { XCTAssertEqual(h.heldSlot(i)?.userId, "foreign\(i)") }
        XCTAssertEqual(h.quarantineSlot(0)?.userId, "fq")
        XCTAssertNil(h.heldSlot(4), "this origin's slot IS released by the reset")
        usleep(50_000)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 0)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/guest/discard").count, 0)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/guest/held").count, 0)
    }

    // MARK: - G5 — slots vs the current session

    func test_G5_hydrateDropsADuplicateOnlyByTokenNeverByUserIdAlone() {
        // Same user, DIFFERENT token (a passkey guest held, then signed back in: a new family) → KEPT.
        let h = guestHarness { h in
            h.seedSlot(0, AuthHarness.slot(userId: Self.guest.id, refresh: "rt-old-family", heldAt: 1))
            h.seedSlot(1, AuthHarness.slot(userId: Self.guest.id, refresh: "rt-anon", heldAt: 2)) // exact duplicate
            h.seedQuarantine(0, userId: Self.guest.id, refresh: "rt-q-old")
        }
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "rt-old-family", "a different token of the same user is a separate handle")
        XCTAssertNil(h.heldSlot(1), "the exact duplicate is dropped")
        XCTAssertEqual(h.quarantineSlot(0)?.refreshToken, "rt-q-old")
        // …and is not offered to the app while that user is current.
        XCTAssertEqual(h.auth.heldGuests().count, 0)
        XCTAssertEqual(h.auth.getQuarantinedGuests().count, 0)
    }

    func test_G5_everyVerbRefusesTheCurrentUsersOwnSlotWithNothingSent() {
        let h = guestHarness { h in
            h.seedSlot(0, AuthHarness.slot(userId: Self.guest.id, refresh: "rt-old-family", heldAt: 1))
            h.seedQuarantine(0, userId: Self.guest.id, refresh: "rt-q-old")
        }
        let before = h.transport.requestCount
        let discard: Result<Void, SendoraCloudAuthError> = h.wait { done in h.auth.discardHeldGuest(id: Self.guest.id, completion: done) }
        let restore: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.restoreHeldGuest(id: Self.guest.id, completion: done) }
        let recover: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.recoverQuarantinedGuest(Self.guest.id, completion: done) }
        let discardQ: Result<Void, SendoraCloudAuthError> = h.wait { done in h.auth.discardQuarantinedGuest(Self.guest.id, completion: done) }
        for (label, e) in [("discard", discard.failureError), ("restore", restore.failureError), ("recover", recover.failureError), ("discardQ", discardQ.failureError)] {
            XCTAssertEqual(e?.code, "SLOT_IS_CURRENT", label)
            XCTAssertEqual(e?.kind, .config, label)
        }
        XCTAssertEqual(h.transport.requestCount, before, "nothing sent")
        XCTAssertNotNil(h.heldSlot(0)); XCTAssertNotNil(h.quarantineSlot(0))
        XCTAssertEqual(h.auth.status(), .anonymous)
        // claim: an identified current user whose own guest-era slot is held
        let a = AuthHarness()
        a.seedSession(user: Self.account, access: Self.accountToken, refresh: "rt-ident")
        a.seedSlot(0, AuthHarness.slot(userId: Self.account.id, refresh: "rt-pre-upgrade", heldAt: 1))
        a.boot()
        let claim: Result<SendoraCloudClaimResult, SendoraCloudAuthError> = a.wait { done in a.auth.claimHeldGuest(id: Self.account.id, completion: done) }
        XCTAssertEqual(claim.failureError?.code, "SLOT_IS_CURRENT")
        XCTAssertEqual(a.transport.requests(to: "/auth-service/merge").count + a.transport.requests(to: "/auth-service/token/refresh").count, 0)
    }

    /// A PENDING restore (its session write did not land) keeps the slot as the guest's only durable copy, and the
    /// verbs refuse it while it is the current user (SLOT_IS_CURRENT) — the audit's scenario A: `discardHeldGuest` used
    /// to send the CURRENT session's live token to `/guest/discard`. When the write lands, the slot is released.
    func test_G5_aPendingRestoresSlotCannotBeDiscardedWhileItIsTheCurrentSession() {
        let h = AuthHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", refreshOk("g-held", refresh: "rt-held-2", sid: "sid-held"))
        h.transport.stub("POST", "/auth-service/guest/discard", .ok([:]))
        h.secure.failWrites = { $0 == "sendora_auth_access_token" }
        guard case .success = (h.wait { done in h.auth.restoreHeldGuest(id: "g-held", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("restore") }
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "rt-held-2", "pending: the slot is the only durable copy")
        XCTAssertEqual(h.auth.heldGuests().count, 0, "not offered while it is the current user")
        let d: Result<Void, SendoraCloudAuthError> = h.wait { done in h.auth.discardHeldGuest(id: "g-held", completion: done) }
        XCTAssertEqual(d.failureError?.code, "SLOT_IS_CURRENT")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/guest/discard").count, 0, "the live account is never erased")
        h.secure.failWrites = nil
        _ = h.getAccessToken() // the pending commit lands → its deferred release runs
        XCTAssertEqual(h.storedRefresh, "rt-held-2")
        XCTAssertNil(h.heldSlot(0))
    }

    // MARK: - G6 / C3 — the mint key (Keychain since batch C) and a minted guest that is never exposed before it is on disk

    func test_G6_aMintKeyThatCannotBeStoredMintsNothing() {
        let h = AuthHarness()
        h.boot()
        // ⚠ converted (C3 / Codex #7): the key is a Keychain item now — a UserDefaults read-back proved nothing durable.
        h.secure.failWrites = { $0 == SendoraStorage.mintKeyKey }
        h.transport.stub("POST", "/auth-service/anonymous", mintResponse())
        let e = h.mint().failureError
        XCTAssertEqual(e?.code, "STORAGE_UNAVAILABLE"); XCTAssertEqual(e?.retryable, true)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/anonymous").count, 0, "no mint without a stored key")
        XCTAssertEqual(h.auth.status(), .signedOut)
        // A mint key we cannot READ is not "none": no new key, no mint.
        let r = AuthHarness()
        r.secure.seed(SendoraStorage.mintKeyKey, "k-existing")
        r.secure.readErrors = [SendoraStorage.mintKeyKey]
        r.boot()
        r.transport.stub("POST", "/auth-service/anonymous", mintResponse())
        XCTAssertEqual(r.mint().failureError?.code, "STORAGE_UNAVAILABLE")
        XCTAssertEqual(r.transport.requests(to: "/auth-service/anonymous").count, 0)
        // A legacy UserDefaults key (≤ batch A) is still honoured, moved into the Keychain, then cleared on MINT_OK.
        let l = AuthHarness()
        l.plain.seedString("sendora_auth_mint_key", "k-legacy")
        l.boot()
        l.transport.stub("POST", "/auth-service/anonymous", mintResponse())
        guard case .success = l.mint() else { return XCTFail("mint") }
        XCTAssertEqual(l.transport.lastRequest(to: "/auth-service/anonymous")?.body?["mintKey"] as? String, "k-legacy")
        XCTAssertNil(l.secure.get(SendoraStorage.mintKeyKey)); XCTAssertNil(l.plain.string(forKey: "sendora_auth_mint_key"))
    }

    /// C3 (Codex #4 + #7): a mint whose session does not reach disk hands NOTHING to the app — the in-memory guest is
    /// dropped, the mint key KEPT, the call fails STORAGE_UNAVAILABLE. The retry with the same key replays the SAME guest
    /// (server B10), so a guest that never existed for the app cannot be lost — even past 24 h (the server then mints fresh).
    func test_C3_aMintWhoseSessionIsNotOnDiskIsNeverHandedToTheApp_theRetryReplaysTheSameGuest() {
        let h = AuthHarness()
        h.boot()
        var keys: [String] = []
        h.transport.stub("POST", "/auth-service/anonymous") { req in
            keys.append(req.body?["mintKey"] as? String ?? "")
            return self.mintResponse("n")
        }
        h.secure.failWrites = { $0 == "sendora_auth_refresh_token" }
        let e = h.mint().failureError
        XCTAssertEqual(e?.code, "STORAGE_UNAVAILABLE"); XCTAssertEqual(e?.retryable, true)
        XCTAssertNil(h.auth.currentUser, "never installed"); XCTAssertEqual(h.auth.status(), .signedOut)
        XCTAssertEqual(h.transitionEventNames, [], "no signed_in for a guest that is not on disk")
        XCTAssertEqual(h.identityChanges, [], "the parent never saw it")
        XCTAssertNil(h.storedSessionRecord); XCTAssertNil(h.storedRefresh)
        XCTAssertEqual(h.secure.get(SendoraStorage.mintKeyKey), keys.first, "the mint key is KEPT")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/revoke").count, 0, "the guest is NOT revoked — the retry replays it")
        // Killed now: the relaunch is signed out and the retried mint carries the SAME key (B10 → the same guest).
        h.secure.failWrites = nil
        h.boot()
        XCTAssertEqual(h.auth.status(), .signedOut)
        guard case .success(let n) = h.mint() else { return XCTFail("retry") }
        XCTAssertEqual(n.id, "n")
        XCTAssertEqual(keys.count, 2); XCTAssertEqual(keys[0], keys[1], "same key → same guest")
        XCTAssertEqual(h.storedRefresh, "rt-n")
        XCTAssertNil(h.secure.get(SendoraStorage.mintKeyKey), "durable now → cleared")
        XCTAssertEqual(h.transitionEventNames, ["signed_in"])
        // forceNew over a guest: the guest is held first; a non-durable mint rolls the hold back — the guest stays current.
        let f = AuthHarness()
        f.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        f.boot()
        f.transport.stub("POST", "/auth-service/anonymous", mintResponse("m"))
        f.secure.failWrites = { $0 == "sendora_auth_refresh_token" }
        XCTAssertEqual(f.mint(forceNew: true).failureError?.code, "STORAGE_UNAVAILABLE")
        f.secure.failWrites = nil
        XCTAssertEqual(f.auth.currentUser?.id, Self.guest.id, "the current guest is untouched")
        XCTAssertEqual(f.storedRefresh, "rt-anon")
        XCTAssertNil(f.heldSlot(0), "the hold is rolled back (no duplicate handle)")
    }

    // MARK: - G7 — every install confirms durability; a leftover record is never deleted by hydrate

    func test_G7_aSignInWhoseSessionWriteFailsIsAPendingCommitThatBlocksTheNextRotation() {
        let h = guestHarness()
        h.transport.stub("POST", "/auth-service/login", Stub.session(user: Stub.user(id: Self.account.id, isAnonymous: false, email: "p@example.com"),
                                                                   tokens: Stub.tokens(access: Self.accountToken, refresh: "rt-b")))
        h.secure.failWrites = { $0 == "sendora_auth_refresh_token" }
        guard case .success = h.signIn() else { return XCTFail("sign-in") }
        XCTAssertEqual(h.auth.status(), .identified)
        XCTAssertEqual(h.storedRefresh, "rt-anon", "not on disk yet")
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "rt-anon", "the guest is held (confirmed) regardless")
        h.transport.stub("POST", "/auth-service/token/refresh", refreshOk(Self.account.id, refresh: "rt-b2", anonymous: false, sid: "sid-ident"))
        XCTAssertNil(h.getAccessToken(forceRefresh: true), "T12: an unconfirmed install blocks the next rotation")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 0)
        h.secure.failWrites = nil
        XCTAssertNotNil(h.getAccessToken())
        XCTAssertEqual(h.storedRefresh, "rt-b", "the retry lands the SAME pair (never re-rotated)")
    }

    /// A rebuild from the frozen keys over a record of ANOTHER guest (contradicting token) rescues that guest's token.
    func test_G7_aContradictingRecordOfAnotherGuestIsRescuedBeforeTheWriteForward() {
        let other = AuthHarness.anonymousUser("99999999-9999-4999-8999-999999999999")
        let h = AuthHarness()
        h.seedSession(user: other, access: Self.guestToken(other.id), refresh: "rt-other")  // the record
        h.secure.seed("sendora_auth_refresh_token", "rt-anon")                              // frozen = this guest
        h.secure.seed("sendora_auth_access_token", Self.guestToken())
        h.secure.seed("sendora_auth_user", SendoraCloudAuth.encodeUser(Self.guest)!)
        h.boot()
        XCTAssertEqual(h.auth.currentUser?.id, Self.guest.id)
        XCTAssertEqual(h.quarantineSlot(0)?.refreshToken, "rt-other", "rescued into quarantine")
        XCTAssertEqual(h.storedSessionRecord?.refreshToken, "rt-anon", "then the record is written forward")
    }

    // MARK: - G8 — restore awaits an in-flight refresh of the current session before its commit

    func test_G8_aRestoreCommitsOnlyAfterTheCurrentRefreshLanded_andTheHeldSlotGetsItsSuccessor() {
        let h = guestHarness { h in h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1)) }
        var started = false
        let refreshDone = DispatchSemaphore(value: 0)
        var currentRefreshFinished = false
        h.transport.stub("POST", "/auth-service/token/refresh") { req in
            let sent = req.body?["refreshToken"] as? String
            if sent == "rt-held" { return self.refreshOk("g-held", refresh: "rt-held-2", sid: "sid-held") }
            return self.refreshOk(Self.guest.id, refresh: "rt-anon-2")
        }
        h.transport.onRequest = { req in
            guard req.body?["refreshToken"] as? String == "rt-held", !started else { return }
            started = true
            // A refresh of the CURRENT guest starts while the held slot is being presented (off the auth queue).
            let gate = h.transport.gate("/auth-service/token/refresh")
            DispatchQueue.global().async {
                h.auth.performRefresh(force: true) { _ in currentRefreshFinished = true; refreshDone.signal() }
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { gate.signal() }
        }
        let r: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.restoreHeldGuest(id: "g-held", completion: done) }
        XCTAssertTrue(currentRefreshFinished, "the restore committed only after the current refresh landed")
        _ = refreshDone.wait(timeout: .now() + 2)
        guard case .success(let u) = r else { return XCTFail("restore") }
        XCTAssertEqual(u.id, "g-held")
        let held = (0..<5).compactMap { h.heldSlot($0) }.first { $0.userId == Self.guest.id }
        XCTAssertEqual(held?.refreshToken, "rt-anon-2", "the guest held by the restore keeps its SUCCESSOR, not the spent token")
    }

    // MARK: - iOS #4 — background activity from the marker write to the confirmed commit

    func test_4_aRefreshIsCoveredByABackgroundActivityFromItsMarkerToItsCommit() {
        let h = guestHarness()
        var activityAtRequest: [String] = []
        var markerAtRequest: String?
        h.transport.onRequest = { req in
            if req.path == "/auth-service/token/refresh" { activityAtRequest = h.activityEvents; markerAtRequest = h.refreshMarker }
        }
        h.transport.stub("POST", "/auth-service/token/refresh", refreshOk(Self.guest.id, refresh: "rt-anon-2"))
        XCTAssertNotNil(h.getAccessToken(forceRefresh: true))
        XCTAssertEqual(activityAtRequest, ["begin"], "begun before the request (and the marker)")
        XCTAssertNotNil(markerAtRequest)
        XCTAssertEqual(h.activityEvents, ["begin", "end"], "ended once the rotated pair is committed")
        XCTAssertNil(h.refreshMarker)
        // Outcome unknown: held across the grace schedule, released when it ends.
        let g = AuthHarness()
        g.graceRetryScale = 0.01
        g.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        g.boot()
        var calls = 0
        g.transport.stub("POST", "/auth-service/token/refresh") { _ in
            calls += 1
            return calls == 1 ? .offline : self.refreshOk(Self.guest.id, refresh: "rt-anon-2")
        }
        XCTAssertNil(g.getAccessToken(forceRefresh: true))
        XCTAssertEqual(g.activityEvents, ["begin"], "still held while the grace retry is scheduled")
        XCTAssertTrue(g.eventually { g.storedRefresh == "rt-anon-2" })
        XCTAssertTrue(g.eventually { g.activityEvents == ["begin", "end"] }, "ended after the retry committed")
    }

    // MARK: - iOS #8 — a failed rotation-only write is retried and blocks the next rotation

    func test_8_aLimboRotationWhoseWriteFailsIsRetriedAndBlocksTheNextRotation() {
        let h = AuthHarness()
        h.seedLimbo(refresh: "rt-limbo")
        h.boot()
        // the gap-fill answers WITHOUT a user (the route tolerates it): rotation-only write — which fails
        h.transport.stub("POST", "/auth-service/token/refresh", .ok(["tokens": Stub.tokens(access: Self.guestToken(), refresh: "rt-limbo-2")]))
        h.secure.failWrites = { $0 == "sendora_auth_refresh_token" }
        XCTAssertNotNil(h.getAccessToken())
        XCTAssertEqual(h.storedRefresh, "rt-limbo", "not on disk")
        XCTAssertNotNil(h.refreshMarker, "the marker stays")
        _ = h.getAccessToken(forceRefresh: true) // (in `unknown` the stashed access token may still be served)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 1, "T12: no second rotation while the disk is a token behind")
        h.secure.failWrites = nil
        _ = h.getAccessToken() // retried
        XCTAssertEqual(h.storedRefresh, "rt-limbo-2")
        XCTAssertNil(h.refreshMarker)
    }

    // MARK: - a queued verb in `unknown` really asks the server (backport of the ADR-037 kill-test finding)

    /// LIMBO_A (a refresh token, no readable user) whose stashed access token is still servable: the verb's settle
    /// used to short-circuit on that token — no request, still `unknown` — so every queued verb failed `.network` until
    /// the token expired. It must FORCE the gap-fill refresh.
    func test_aQueuedVerbInUnknownForcesTheGapFillRefresh_evenWithAServableStashedToken() {
        let h = AuthHarness()
        h.seedLimbo(refresh: "rt-limbo", access: Self.guestToken())
        h.secure.seed("sendora_auth_access_expires", String(Int64(Date().timeIntervalSince1970 * 1000) + 900_000))
        h.transport.stub("POST", "/auth-service/token/refresh", refreshOk(Self.guest.id, refresh: "rt-limbo-2"))
        h.boot()
        XCTAssertEqual(h.auth.status(), .unknown, "precondition: limbo")
        h.transport.stub("POST", "/auth-service/login", .failure(status: 401, code: "INVALID_CREDENTIALS"))
        _ = h.signIn()
        XCTAssertGreaterThanOrEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 1, "the settle never asked the server")
        XCTAssertNotEqual(h.auth.status(), .unknown, "still unknown after the settle")
    }

    // MARK: - iOS #9 — a limbo hydrate with a marker refreshes at once

    func test_9_aLimboHydrateWithAMarkerRefreshesAtOnce() {
        let h = AuthHarness()
        h.seedLimbo(refresh: "rt-limbo", access: Self.guestToken())
        h.seedRefreshMarker()
        h.transport.stub("POST", "/auth-service/token/refresh", refreshOk(Self.guest.id, refresh: "rt-limbo-2"))
        h.boot()
        XCTAssertTrue(h.eventually { h.transport.requests(to: "/auth-service/token/refresh").count == 1 }, "refreshed at once, inside the grace")
        XCTAssertTrue(h.eventually { h.auth.status() == .anonymous })
        XCTAssertEqual(h.storedRefresh, "rt-limbo-2")
    }

    // MARK: - iOS #10 / C2 — a key given up as unreadable is never written over

    /// C2 — Codex #3's probe: a 10 s read outage while unlocked (T2 gives up on the keys), then the store heals DURING
    /// `/anonymous`. The old guest A is the session afterwards and its token was never overwritten; the minted pair is
    /// revoked (it was never handed to the app).
    func test_C2_storageHealsDuringTheMint_theOldGuestIsKept_theMintedPairRevoked() {
        let h = AuthHarness()
        h.storageUnavailableQueueMs = 200
        h.deviceUnlocked = true
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        let sessionKeys = AuthHarness.frozenAuthKeys + [SendoraStorage.authSessionKey]
        h.secure.readErrors = Set(sessionKeys)
        h.boot()
        XCTAssertTrue(h.auth.storageUnavailable)
        h.transport.onRequest = { req in if req.path == "/auth-service/anonymous" { h.secure.readErrors = [] } }
        h.transport.stub("POST", "/auth-service/anonymous", mintResponse("b"))
        let r = h.mint()
        XCTAssertEqual(h.transport.requests(to: "/auth-service/anonymous").count, 1)
        XCTAssertEqual(r.failureError?.code, "STORAGE_UNAVAILABLE", "the in-flight result is dropped (retryable)")
        XCTAssertTrue(h.eventually { h.auth.currentUser?.id == Self.guest.id }, "re-hydrated: A is the session")
        XCTAssertEqual(h.storedRefresh, "rt-anon", "A's token was never overwritten")
        XCTAssertEqual(h.storedSessionRecord?.user.id, Self.guest.id)
        XCTAssertTrue(h.eventually { h.transport.requests(to: "/auth-service/token/revoke").contains { $0.body?["refreshToken"] as? String == "rt-b" } }, "the minted pair is revoked")
        XCTAssertNil(h.heldSlot(0), "nothing to hold — B was never exposed")
        guard case .success(let again) = h.mint() else { return XCTFail("the retry returns A") }
        XCTAssertEqual(again.id, Self.guest.id)
        // The store heals BETWEEN two mints: the next mint re-checks the given-up keys BEFORE /anonymous — A comes back
        // and no second guest is created server-side.
        let b = AuthHarness()
        b.storageUnavailableQueueMs = 200
        b.deviceUnlocked = true
        b.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        b.secure.readErrors = ["sendora_auth_refresh_token"]
        b.boot()
        b.transport.stub("POST", "/auth-service/anonymous", mintResponse("b"))
        XCTAssertEqual(b.mint().failureError?.code, "STORAGE_UNAVAILABLE", "still unreadable: the mint is never installed")
        XCTAssertEqual(b.transport.requests(to: "/auth-service/anonymous").count, 1)
        b.secure.readErrors = []
        XCTAssertEqual(b.mint().failureError?.code, "STORAGE_UNAVAILABLE", "re-hydrated instead (retryable)")
        XCTAssertEqual(b.transport.requests(to: "/auth-service/anonymous").count, 1, "no second /anonymous")
        XCTAssertEqual(b.auth.currentUser?.id, Self.guest.id)
        XCTAssertEqual(b.storedRefresh, "rt-anon")
    }

    /// C2 — still unreadable: a write over the given-up key is REFUSED (not only when a value re-appears). An account
    /// signed in meanwhile lives in memory (pending); when the store heals the guest on disk comes back, the account's
    /// pair is revoked, and A's token was never touched.
    func test_10_C2_aStillUnreadableKeyIsNeverOverwritten_theDiskGuestComesBackWhenItReads() {
        let h = AuthHarness()
        h.storageUnavailableQueueMs = 200
        h.deviceUnlocked = true
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-anon")
        h.secure.readErrors = ["sendora_auth_refresh_token"]
        h.boot()
        h.transport.stub("POST", "/auth-service/login", Stub.session(user: Stub.user(id: Self.account.id, isAnonymous: false, email: "p@example.com"),
                                                                   tokens: Stub.tokens(access: Self.accountToken, refresh: "rt-b")))
        guard case .success = h.signIn() else { return XCTFail("sign-in proceeds in memory (G7 pending)") }
        XCTAssertEqual(h.secure.get("sendora_auth_refresh_token"), "rt-anon", "the still-unreadable key is NOT written over")
        XCTAssertEqual(h.auth.status(), .identified)
        h.secure.readErrors = []
        _ = h.getAccessToken() // the pending commit retries → finds A's value → re-hydrate
        XCTAssertTrue(h.eventually { h.auth.currentUser?.id == Self.guest.id }, "re-hydrated onto the guest that was on disk")
        XCTAssertEqual(h.storedRefresh, "rt-anon", "never overwritten")
        XCTAssertTrue(h.eventually { h.transport.requests(to: "/auth-service/token/revoke").contains { $0.body?["refreshToken"] as? String == "rt-b" } }, "the in-memory account is revoked")
    }

    // MARK: - C1 — a slot's pending value is durable before the slot is refreshed again

    /// Codex #1: restore under a refused slot write (the server rotated R1 → R2, R2 lives in memory only), then retry
    /// the restore under the SAME fault → exactly ONE /token/refresh: the retry fails STORAGE_UNAVAILABLE with no network.
    /// Re-rotating the undurable R2 → R3 would strand R1 (ADR-036 recovers only a direct successor never presented).
    func test_C1_aRetryUnderTheSameSlotFaultSendsNothing_R2IsNeverRotatedAgainUntilDurable() {
        let h = AuthHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "R1", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh") { req in
            let sent = req.body?["refreshToken"] as? String ?? ""
            return self.refreshOk("g-held", refresh: sent == "R1" ? "R2" : "R3", sid: "sid-held")
        }
        h.secure.failWrites = { $0 == SendoraStorage.heldSlotKeys[0] }
        let first: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.restoreHeldGuest(id: "g-held", completion: done) }
        XCTAssertEqual(first.failureError?.code, "RESTORE_FAILED", "T8: R2 is not on disk")
        let second: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.restoreHeldGuest(id: "g-held", completion: done) }
        XCTAssertEqual(second.failureError?.code, "STORAGE_UNAVAILABLE"); XCTAssertEqual(second.failureError?.retryable, true)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 1, "exactly ONE /token/refresh")
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "R1", "disk still R1 — and R1's direct successor R2 was never presented")
        // auto-restore under the same fault: no network either, and no mint over the guest.
        h.transport.stub("POST", "/auth-service/anonymous", mintResponse())
        XCTAssertEqual(h.mint().failureError?.code, "STORAGE_UNAVAILABLE")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 1)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/anonymous").count, 0)
        // The fault clears: R2 is written FIRST, then presented (R2 → R3), never R1 again.
        h.secure.failWrites = nil
        guard case .success = (h.wait { done in h.auth.restoreHeldGuest(id: "g-held", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("restore") }
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").compactMap { $0.body?["refreshToken"] as? String }, ["R1", "R2"])
        XCTAssertEqual(h.storedRefresh, "R3")
        // Same rule for a quarantine slot (recover).
        let q = AuthHarness()
        q.seedQuarantine(0, userId: "g-q", refresh: "Q1")
        q.boot()
        q.transport.stub("POST", "/auth-service/token/refresh", refreshOk("g-q", refresh: "Q2", sid: "sid-q"))
        q.secure.failWrites = { $0 == SendoraStorage.quarantineSlotKeys[0] }
        XCTAssertEqual((q.wait { done in q.auth.recoverQuarantinedGuest("g-q", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError?.code, "STORAGE_UNAVAILABLE")
        XCTAssertEqual((q.wait { done in q.auth.recoverQuarantinedGuest("g-q", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError?.code, "STORAGE_UNAVAILABLE")
        XCTAssertEqual(q.transport.requests(to: "/auth-service/token/refresh").count, 1, "the second recover sends nothing")
    }

    // MARK: - C5 — the released-reason vocabulary equals the shared one (quarantined is additive)

    func test_C5_guestReleasedReasonsEqualTheSharedUnion() {
        let packages = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        guard let src = try? String(contentsOf: packages.appendingPathComponent("shared/src/auth-machine/types.ts"), encoding: .utf8),
              let line = src.split(separator: "\n").first(where: { $0.contains("export type GuestReleasedReason =") }) else {
            return XCTFail("shared GuestReleasedReason not found")
        }
        let shared = line.split(separator: "\"").enumerated().filter { $0.offset % 2 == 1 }.map { String($0.element) }
        XCTAssertEqual(Set(shared), ["claimed", "restored", "discarded", "dead", "reset", "quarantined"])
        for raw in shared { XCTAssertNotNil(SendoraCloudGuestReleasedReason(rawValue: raw), "\(raw) has a Swift case with the same raw value") }
    }

    // MARK: - iOS #11 — the 5.9.0 delete-then-add leftover is rebuilt, not cleared

    func test_11_aRecordWhoseFrozenAccessMatchesIsRebuiltNotClearedAsStale() {
        let h = AuthHarness()
        h.seedSession(user: Self.guest, access: Self.guestToken(), refresh: "rt-r2")
        h.secure.delete("sendora_auth_refresh_token") // 5.9.0: the delete landed, the add did not
        h.boot()
        XCTAssertEqual(h.auth.status(), .anonymous)
        XCTAssertEqual(h.auth.getRefreshToken(), "rt-r2")
        XCTAssertEqual(h.storedRefresh, "rt-r2", "the write-forward restores the frozen refresh key")
        XCTAssertEqual(h.storedSessionRecord?.refreshToken, "rt-r2")
        XCTAssertEqual(h.transitionEventNames, [])
    }
}
