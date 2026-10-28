import XCTest
@testable import SendoraCloud

// ADR-033 rev 3 §3.8 (s58.415) — one behavioural scenario per DURABILITY row (part 3): INV-16 (the refresh marker,
// confirmed writes, grace retries), INV-17 (a read error is not absence), quarantine (decision D), the deferred
// sign-out while unreadable (T9 — replaced the J.1 guest-signOut hold, decision C) and release-by-occupant (N4). Same harness, same rules as parts 1–2: drive the machine through
// its verbs, assert state, events (names + order) and writes. Faults come from the recording Keychain's switches
// (`readErrors`, `failWrites`) — off, it is the perfect map it always was.

extension AuthMachineConformanceTests {
    func rowScenariosPart3() -> [String: () -> Void] {
        return [
            "hydrate.read_error": scenario_hydrate_read_error,
            "hydrate.refresh_inflight": scenario_hydrate_refresh_inflight,
            "refresh_ok.write_failed": scenario_refresh_ok_write_failed,
            "refresh_outcome_unknown.retry": scenario_refresh_outcome_unknown_retry,
            "refresh_dead.current_guest_quarantine": scenario_refresh_dead_current_guest_quarantine,
            "sign_out.deferred_unreadable": scenario_sign_out_deferred_unreadable,
            "sign_out.discard_guest": scenario_sign_out_discard_guest,
            "recover_quarantined.as_restore": scenario_recover_quarantined_as_restore,
            "discard_quarantined.slot": scenario_discard_quarantined_slot,
        ]
    }

    private static let refreshKey = "sendora_auth_refresh_token"

    func freshMintResponse(_ id: String = "fresh") -> StubResponse {
        Stub.session(user: Stub.user(id: id, isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: id, sid: "sid-\(id)"), refresh: "rt-\(id)"), status: 201)
    }

    // MARK: HYDRATE (INV-17 / INV-16)

    func scenario_hydrate_read_error() {
        let h = AuthHarness()
        h.storageUnavailableQueueMs = 300
        h.seedSession(user: Self.anon, access: Self.anonToken(), refresh: "rt-anon")
        h.secure.readErrors = [Self.refreshKey] // a locked Keychain: the value IS on disk
        let secureBefore = h.secure.snapshot(), plainBefore = h.plain.snapshot()
        h.transport.stub("POST", "/auth-service/anonymous", freshMintResponse())
        h.transport.stub("POST", "/auth-service/login", identifiedSignInResponse())
        h.boot()
        XCTAssertEqual(h.auth.status(), .unknown, "a session read error → unknown, never signed_out")
        XCTAssertTrue(h.auth.storageUnavailable)
        var unavailableInsideInitial: Bool?
        let unsubscribe = h.auth.onAuthStateChanged { change in
            if case .initial(let status, _, _) = change, status == .unknown { unavailableInsideInitial = h.auth.storageUnavailable }
        }
        unsubscribe()
        XCTAssertEqual(unavailableInsideInitial, true, "initial{status: unknown} with storageUnavailable readable inside the listener")
        XCTAssertEqual(h.eventNames, ["initial"])
        XCTAssertEqual(h.secure.writeCount, 0, "NOTHING written or removed (no stale-blob clear of the readable user)")
        XCTAssertEqual(h.plain.writeCount, 0)
        XCTAssertEqual(h.secure.snapshot(), secureBefore); XCTAssertEqual(h.plain.snapshot(), plainBefore)
        XCTAssertFalse(h.auth.cronArmed, "no cron while unreadable")
        // MINT / SIGN_IN queue, then give up STORAGE_UNAVAILABLE — never a mint over the unreadable session.
        let t0 = Date()
        let mint = h.mint().failureError
        XCTAssertEqual(mint?.code, "STORAGE_UNAVAILABLE"); XCTAssertEqual(mint?.kind, .network); XCTAssertEqual(mint?.retryable, true)
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(t0), 0.25, "the verb waited the queue window")
        XCTAssertEqual(h.signIn().failureError?.code, "STORAGE_UNAVAILABLE")
        XCTAssertEqual(h.transport.requestCount, 0, "no /anonymous, no /login")
        XCTAssertEqual(h.secure.snapshot(), secureBefore, "the stored token untouched")
        // The device unlocks: the platform signal re-reads; the ORIGINAL guest is the session, announced.
        h.secure.readErrors = []
        NotificationCenter.default.post(name: SendoraCloudAuth.protectedDataAvailableNotification, object: nil)
        XCTAssertTrue(h.eventually { h.auth.status() == .anonymous }, "protectedDataDidBecomeAvailable re-hydrates")
        XCTAssertFalse(h.auth.storageUnavailable)
        XCTAssertEqual(h.auth.currentUser?.id, Self.anon.id)
        XCTAssertEqual(h.transitionEventNames.last, "signed_in", "the recovered session is announced")
        guard case .success(let u) = h.mint() else { return XCTFail("mint after recovery") }
        XCTAssertEqual(u.id, Self.anon.id, "the next verb sees the original guest — nothing minted")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/anonymous").count, 0)
        // A verb alone (no signal) re-reads too.
        let v = AuthHarness()
        v.storageUnavailableQueueMs = 2_000
        v.seedSession(user: Self.anon, access: Self.anonToken(), refresh: "rt-anon")
        v.secure.readErrors = [SendoraStorage.authSessionKey]
        v.boot()
        XCTAssertEqual(v.auth.status(), .unknown)
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { v.secure.readErrors = [] }
        guard case .success(let u2) = v.mint() else { return XCTFail("a queued verb re-reads and proceeds") }
        XCTAssertEqual(u2.id, Self.anon.id)
        // A held slot whose READ errors is RESERVED: counts toward T, never free, never released.
        let r = anonymousHarness()
        r.seedSlot(0, AuthHarness.slot(userId: "g-x", refresh: "rt-x", heldAt: 1))
        r.secure.readErrors = [SendoraStorage.heldSlotKeys[0]]
        r.boot()
        XCTAssertEqual(r.auth.status(), .anonymous, "a slot read error does not block the session")
        XCTAssertEqual(r.auth.heldGuests().count, 0, "an unreadable slot is not listed")
        r.transport.stub("POST", "/auth-service/anonymous", freshMintResponse("g2"))
        guard case .success = r.mint(forceNew: true) else { return XCTFail("forceNew holds into the next free slot") }
        XCTAssertEqual(r.heldSlot(1)?.userId, Self.anon.id, "the hold skipped the unreadable slot 0")
        XCTAssertEqual(r.secure.writes.filter { $0.key == SendoraStorage.heldSlotKeys[0] }, [], "slot 0 never written")
    }

    func scenario_hydrate_refresh_inflight() {
        let h = AuthHarness()
        h.seedSession(user: Self.anon, access: Self.anonToken(), refresh: "rt-anon")
        h.seedRefreshMarker()
        h.transport.stub("POST", "/auth-service/token/refresh") { req in
            Stub.session(user: Stub.user(from: Self.anon), tokens: Stub.tokens(access: Self.anonToken(), refresh: "\(req.body?["refreshToken"] as? String ?? "")-rot"))
        }
        h.boot()
        XCTAssertEqual(h.auth.status(), .anonymous, "installed like hydrate.coherent_match")
        XCTAssertTrue(h.eventually { h.storedRefresh == "rt-anon-rot" }, "an IMMEDIATE refresh with the token on disk — no waiting for the cron")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").map { $0.body?["refreshToken"] as? String }, ["rt-anon"])
        XCTAssertTrue(h.eventually { h.refreshMarker == nil }, "the marker goes once the rotated pair's write confirmed")
        XCTAssertEqual(h.transitionEventNames, [], "a rotation is not a transition")
        // No marker → no hydrate-time refresh.
        let quiet = anonymousHarness()
        usleep(100_000)
        XCTAssertEqual(quiet.transport.requestCount, 0)
        // A marker with no session behind it is stale → removed.
        let stale = AuthHarness()
        stale.seedRefreshMarker()
        stale.boot()
        XCTAssertNil(stale.refreshMarker)
        XCTAssertEqual(stale.transport.requestCount, 0)
    }

    // MARK: REFRESH (INV-16)

    func scenario_refresh_ok_write_failed() {
        let h = anonymousHarness()
        var markerAtSend: String?
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.session(user: Stub.user(from: Self.anon), tokens: Stub.tokens(access: Self.anonToken(), refresh: "rt-anon-2")))
        // The Keychain refuses the rotation's writes (a locked device mid-refresh) — AFTER the marker landed (T15: the
        // marker is a Keychain item now, written before the request).
        h.transport.onRequest = { req in
            if req.path == "/auth-service/token/refresh" {
                markerAtSend = h.refreshMarker
                h.secure.failWrites = { $0.hasPrefix("sendora_auth_") }
            }
        }
        XCTAssertNotNil(h.getAccessToken(forceRefresh: true), "the session keeps working on the in-memory pending commit")
        XCTAssertNotNil(markerAtSend, "the marker was on disk BEFORE the request went out")
        XCTAssertEqual(h.auth.status(), .anonymous)
        XCTAssertEqual(h.auth.getRefreshToken(), "rt-anon-2", "R2 installed in memory")
        XCTAssertEqual(h.storedRefresh, "rt-anon", "the disk still holds R1 (an in-place update that failed leaves the old value)")
        XCTAssertNotNil(h.refreshMarker, "the marker is KEPT while the write is unconfirmed")
        XCTAssertTrue(h.auth.pendingCommit)
        // The store recovers: the next token request re-writes the PENDING pair — never a second rotation.
        h.transport.onRequest = nil
        h.secure.failWrites = nil
        XCTAssertNotNil(h.getAccessToken())
        XCTAssertEqual(h.storedRefresh, "rt-anon-2"); XCTAssertEqual(h.storedSessionRecord?.refreshToken, "rt-anon-2")
        XCTAssertNil(h.refreshMarker, "confirmed → marker removed")
        XCTAssertFalse(h.auth.pendingCommit)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 1, "exactly ONE /token/refresh — a failed write is never repaired by re-rotating")
        // A marker that cannot be written ABORTS the refresh (the old token is still good): nothing sent.
        let m = anonymousHarness()
        m.secure.failWrites = { $0 == SendoraStorage.refreshInflightKey }
        XCTAssertNil(m.getAccessToken(forceRefresh: true))
        XCTAssertEqual(m.transport.requests(to: "/auth-service/token/refresh").count, 0, "never send without the marker")
        XCTAssertEqual(m.auth.status(), .anonymous)
    }

    func scenario_refresh_outcome_unknown_retry() {
        let h = AuthHarness()
        h.graceRetryScale = 0.01 // 2 s → 20 ms; the SCHEDULE is the shared one
        h.seedSession(user: Self.anon, access: Self.anonToken(), refresh: "rt-anon")
        h.boot()
        let lock = NSLock()
        var n = 0
        h.transport.stub("POST", "/auth-service/token/refresh") { _ in
            lock.lock(); n += 1; let call = n; lock.unlock()
            // The server rotated; the answer never arrives (the first time).
            return call == 1 ? .offline : Stub.session(user: Stub.user(from: Self.anon), tokens: Stub.tokens(access: Self.anonToken(), refresh: "rt-anon-2"))
        }
        XCTAssertNil(h.getAccessToken(forceRefresh: true))
        XCTAssertEqual(h.auth.status(), .anonymous, "a lost response is not a failure of the session")
        XCTAssertTrue(h.eventually { h.storedRefresh == "rt-anon-2" }, "the grace retry fires on its own with the SAME token")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").compactMap { $0.body?["refreshToken"] as? String }, ["rt-anon", "rt-anon"])
        XCTAssertTrue(h.eventually { h.refreshMarker == nil })
        // Exempt from the client-wide breaker: a 503 Retry-After on another route holds it for an hour.
        let b = anonymousHarness()
        b.transport.stub("POST", "/events", Stub.serverError.with(headers: ["Retry-After": "3600"]))
        b.waitVoid { done in b.client.requestWithDetails(method: "POST", path: "/events", body: [:]) { _ in done() } }
        XCTAssertGreaterThan(b.client.breakerOpenUntil, Date().addingTimeInterval(60), "harness: the breaker is open")
        b.transport.stub("POST", "/auth-service/token/refresh", Stub.session(user: Stub.user(from: Self.anon), tokens: Stub.tokens(access: Self.anonToken(), refresh: "rt-b2")))
        XCTAssertNotNil(b.getAccessToken(forceRefresh: true), "the refresh is not held by the breaker")
        XCTAssertEqual(b.storedRefresh, "rt-b2")
        // Past the deadline the self-retries stop (the cron takes over): every attempt fails → at most 1 + 4 sends.
        let d = AuthHarness()
        d.graceRetryScale = 0.002
        d.seedSession(user: Self.anon, access: Self.anonToken(), refresh: "rt-anon")
        d.boot()
        d.transport.stub("POST", "/auth-service/token/refresh", .offline)
        XCTAssertNil(d.getAccessToken(forceRefresh: true))
        usleep(400_000)
        XCTAssertEqual(d.transport.requests(to: "/auth-service/token/refresh").count, 1 + SendoraCloudAuth.refreshRetryOffsetsMs.count,
                       "one attempt per offset (2/5/15/35 s), none past the 50 s deadline")
        XCTAssertNotNil(d.refreshMarker, "outcome unknown keeps the marker")
        XCTAssertEqual(d.auth.status(), .anonymous)
    }

    func scenario_refresh_dead_current_guest_quarantine() {
        let h = anonymousHarness()
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "reuse"))
        var endReasonInListener: SendoraCloudRefreshEndReason?
        let unsubscribe = h.auth.onAuthStateChanged { change in
            if case .signedOut = change { endReasonInListener = h.auth.lastSignedOutEndReason() }
        }
        defer { unsubscribe() }
        XCTAssertNil(h.getAccessToken(forceRefresh: true))
        XCTAssertEqual(h.auth.status(), .signedOut, "the current session cleared")
        XCTAssertEqual(h.transitionEventNames, ["guest_quarantined", "signed_out"], "guest_quarantined THEN signed_out")
        if case .guestQuarantined(let id, let end)? = h.event(at: 2) { XCTAssertEqual(id, Self.anon.id); XCTAssertEqual(end, .reuse) } else { XCTFail("guestQuarantined") }
        if case .signedOut(let reason)? = h.events.last { XCTAssertEqual(reason, .sessionExpired) }
        XCTAssertEqual(endReasonInListener, .reuse)
        let q = h.quarantineSlot(0)
        XCTAssertEqual(q?.userId, Self.anon.id); XCTAssertEqual(q?.refreshToken, "rt-anon"); XCTAssertEqual(q?.v, 1)
        XCTAssertEqual(q?.project, TestJWT.projectA)
        XCTAssertNil(h.storedRefresh)
        XCTAssertEqual(h.auth.getQuarantinedGuests().map { $0.userId }, [Self.anon.id])
        XCTAssertEqual(h.auth.heldGuests().count, 0, "quarantined, NOT held")
        XCTAssertEqual(h.clearEffects.last?.rotateDeviceId, false, "no anon-id rotation")
        XCTAssertFalse(h.auth.cronArmed)
        h.transport.stub("POST", "/auth-service/anonymous", freshMintResponse())
        guard case .success(let fresh) = h.mint() else { return XCTFail("ensureSession mints fresh") }
        XCTAssertEqual(fresh.id, "fresh", "a quarantined guest is NEVER auto-restored")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 1, "its token is never presented in the background")
        XCTAssertNotNil(h.quarantineSlot(0), "the slot survives")
        // NOT counted in T: four ineligible held guests + one quarantined → a mint still runs (T = 4 < 5).
        let t = signedOutHarness()
        for i in 0..<4 { t.seedSlot(i, AuthHarness.slot(userId: "g\(i)", refresh: "rt\(i)", heldAt: Int64(i + 1), autoRestore: false)) }
        t.seedQuarantine(0, userId: "g-q", refresh: "rt-q")
        t.boot()
        t.transport.stub("POST", "/auth-service/anonymous", freshMintResponse())
        guard case .success = t.mint() else { return XCTFail("a quarantine slot is not counted in T") }
        // From unknown (LIMBO_A) whose access token says guest: quarantined too.
        let l = AuthHarness()
        l.seedLimbo(refresh: "rt-limbo", access: Self.anonToken())
        l.boot()
        l.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "reuse"))
        XCTAssertNil(l.getAccessToken())
        XCTAssertEqual(l.quarantineSlot(0)?.refreshToken, "rt-limbo")
        XCTAssertEqual(l.auth.status(), .signedOut)
        // An unparseable quarantine slot is RESERVED: the new one goes to slot 1, slot 0 byte-identical.
        let torn = anonymousHarness()
        torn.secure.seed(SendoraStorage.quarantineSlotKeys[0], "{ torn")
        torn.boot()
        torn.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "reuse"))
        XCTAssertNil(torn.getAccessToken(forceRefresh: true))
        XCTAssertEqual(torn.secure.get(SendoraStorage.quarantineSlotKeys[0]), "{ torn")
        XCTAssertEqual(torn.quarantineSlot(1)?.userId, Self.anon.id)
        // ⚠ Pin converted (s58.415): all Q full → NOTHING is overwritten (the oldest may still be recoverable, ADR-036);
        // "no free slot" is T6 — the current session is KEPT and backed off. (Was: the oldest overwritten.)
        let full = anonymousHarness()
        for (i, at) in [(0, Int64(30)), (1, Int64(10)), (2, Int64(20))] { full.seedQuarantine(i, userId: "q\(i)", refresh: "rq\(i)", at: at) }
        full.boot()
        full.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "reuse"))
        XCTAssertNil(full.getAccessToken(forceRefresh: true))
        for i in 0..<3 { XCTAssertEqual(full.quarantineSlot(i)?.userId, "q\(i)", "slot \(i) never overwritten") }
        XCTAssertEqual(full.auth.status(), .anonymous, "T6: the session is kept"); XCTAssertEqual(full.storedRefresh, "rt-anon")
        XCTAssertEqual(full.transitionEventNames, [])
        XCTAssertNil(full.getAccessToken(forceRefresh: true))
        XCTAssertEqual(full.transport.requests(to: "/auth-service/token/refresh").count, 1, "backed off — not presented again at once")
        // (s58.415, G1) EVERY non-`deleted` verdict quarantines a guest — not only `reuse`; the event carries the verdict.
        for (raw, expected) in [("revoked", SendoraCloudRefreshEndReason.revoked), ("expired", .expired), ("unknown", .unknown), ("evicted", .evicted), (nil, .unknown)] as [(String?, SendoraCloudRefreshEndReason)] {
            let g = anonymousHarness()
            g.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: raw))
            XCTAssertNil(g.getAccessToken(forceRefresh: true))
            let label = raw ?? "absent"
            XCTAssertEqual(g.quarantineSlot(0)?.refreshToken, "rt-anon", label)
            XCTAssertEqual(g.quarantineSlot(0)?.accessToken, Self.anonToken(), "\(label): the last access token kept as the slot's hint")
            XCTAssertEqual(g.quarantineSlot(0)?.origin, AuthHarness.origin, label)
            XCTAssertEqual(g.transitionEventNames, ["guest_quarantined", "signed_out"], label)
            if case .guestQuarantined(_, let end)? = g.event(at: 2) { XCTAssertEqual(end, expected, label) } else { XCTFail(label) }
            XCTAssertEqual(g.auth.lastSignedOutEndReason(), raw.flatMap(SendoraCloudRefreshEndReason.init(rawValue:)), label)
            XCTAssertEqual(g.transport.lastRequest(to: "/auth-service/token/refresh")?.body?["accessTokenHint"] as? String, Self.anonToken(),
                           "\(label): the refresh carried accessTokenHint (G2)")
        }
        // `deleted` (server-confirmed through the hint) → the guest's token is dropped: refresh_dead.current.
        let gone = anonymousHarness()
        gone.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "deleted"))
        XCTAssertNil(gone.getAccessToken(forceRefresh: true))
        XCTAssertNil(gone.quarantineSlot(0)); XCTAssertEqual(gone.transitionEventNames, ["signed_out"])
        // A limbo whose owner cannot be determined (no access token, unreadable user) is a GUEST: quarantined as
        // `unknown:<first 16 hex of sha256(token)>`.
        let u = AuthHarness()
        u.seedLimbo(refresh: "rt-who")
        u.boot()
        u.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "revoked"))
        XCTAssertNil(u.getAccessToken())
        XCTAssertNil(u.transport.lastRequest(to: "/auth-service/token/refresh")?.body?["accessTokenHint"], "no access token known → no hint")
        XCTAssertEqual(u.quarantineSlot(0)?.refreshToken, "rt-who")
        XCTAssertEqual(u.quarantineSlot(0)?.userId, SendoraCloudAuth.unknownOccupantId("rt-who"))
        XCTAssertTrue(u.quarantineSlot(0)?.userId.hasPrefix("unknown:") == true)
        XCTAssertEqual(u.quarantineSlot(0)?.userId.count, "unknown:".count + 16)
        XCTAssertEqual(u.auth.status(), .signedOut)
        // The quarantine write does not confirm → the session is NOT cleared (clearing would leave no handle).
        let w = anonymousHarness()
        w.secure.failWrites = { $0.hasPrefix("sendora_auth_quarantine_") }
        w.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "reuse"))
        XCTAssertNil(w.getAccessToken(forceRefresh: true))
        XCTAssertEqual(w.auth.status(), .anonymous); XCTAssertEqual(w.storedRefresh, "rt-anon")
        XCTAssertEqual(w.transitionEventNames, [])
    }

    // MARK: SIGN_OUT (T9 — the deferred sign-out; decision C replaced J.1's `sign_out.guest_holds`)

    func scenario_sign_out_deferred_unreadable() {
        // unknown{storageUnavailable}: DELETE NOTHING, never fail, DEFER until the store reads again.
        let h = AuthHarness()
        h.seedSession(user: Self.anon, access: Self.anonToken(), refresh: "rt-anon")
        h.seedSlot(0, AuthHarness.slot(userId: "g0", refresh: "rt0", heldAt: 1))
        h.secure.readErrors = [Self.refreshKey]
        h.boot()
        XCTAssertEqual(h.auth.status(), .unknown); XCTAssertTrue(h.auth.storageUnavailable, "precondition")
        let before = h.secure.snapshot()
        let mark = h.secure.writeCount
        // An ERASE while unreadable is refused (retryable) and NOT deferred — lockstep with RN / web / Android.
        let e: Result<Void, SendoraCloudAuthError> = h.wait { done in h.auth.signOut(discardGuest: true, completion: done) }
        if case .rejected(let code, _, _, _)? = e.failureError { XCTAssertEqual(code, "STORAGE_UNAVAILABLE") } else { XCTFail("discardGuest while unreadable must fail STORAGE_UNAVAILABLE") }
        XCTAssertEqual(e.failureError?.retryable, true)
        XCTAssertEqual(h.secure.writeCount, mark, "the refused erase wrote nothing")
        let r: Result<Void, SendoraCloudAuthError> = h.wait { done in h.auth.signOut(discardGuest: false, completion: done) }
        XCTAssertNil(r.failureError, "a plain signOut() never fails")
        h.waitVoid { done in h.auth.signOut(completion: done) }
        XCTAssertEqual(h.secure.writeCount, mark, "NOTHING written or removed while unreadable")
        XCTAssertEqual(h.secure.snapshot(), before)
        XCTAssertEqual(h.transport.requestCount, 0, "no revoke sent while unreadable")
        XCTAssertEqual(h.transitionEventNames, [], "nothing emitted yet")
        XCTAssertEqual(h.auth.status(), .unknown)
        // The device unlocks: the re-read runs the DEFERRED sign-out — cleared, revoked, ONE signed_out{user}, and the
        // recovered session is NOT announced as signed in first.
        h.secure.readErrors = []
        NotificationCenter.default.post(name: SendoraCloudAuth.protectedDataAvailableNotification, object: nil)
        XCTAssertTrue(h.eventually { h.auth.status() == .signedOut }, "on recovery the deferred sign-out runs")
        XCTAssertNil(h.storedRefresh); XCTAssertNil(h.storedSessionRecord)
        XCTAssertTrue(h.eventually { h.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String == "rt-anon" }, "…and revokes")
        XCTAssertEqual(h.transitionEventNames, ["signed_out"], "ONE signed_out — no signed_in for the recovered session")
        if case .signedOut(let reason)? = h.events.last { XCTAssertEqual(reason, .user) }
        XCTAssertNotNil(h.heldSlot(0), "held slots kept")
        // LIMBO_A (a readable token, no readable user): cleared + revoked at once.
        let l = AuthHarness()
        l.seedLimbo(refresh: "rt-limbo")
        l.boot()
        XCTAssertEqual(l.auth.status(), .unknown); XCTAssertFalse(l.auth.storageUnavailable)
        l.waitVoid { done in l.auth.signOut(completion: done) }
        XCTAssertEqual(l.auth.status(), .signedOut); XCTAssertNil(l.storedRefresh)
        XCTAssertEqual(l.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-limbo")
        XCTAssertEqual(l.transitionEventNames, ["signed_out"])
    }

    func scenario_sign_out_discard_guest() {
        let h = anonymousHarness()
        h.transport.stub("POST", "/auth-service/guest/discard", .ok(["userId": Self.anon.id, "status": "purged"]))
        let r: Result<Void, SendoraCloudAuthError> = h.wait { done in h.auth.signOut(discardGuest: true, completion: done) }
        XCTAssertNil(r.failureError)
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/guest/discard")?.body?["refreshToken"] as? String, "rt-anon")
        XCTAssertEqual(h.auth.status(), .signedOut); XCTAssertNil(h.heldSlot(0)); XCTAssertEqual(h.auth.heldGuests().count, 0)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/revoke").count, 0, "erased — nothing to revoke")
        XCTAssertEqual(h.transitionEventNames, ["signed_out"])
        if case .signedOut(let reason)? = h.events.last { XCTAssertEqual(reason, .user) }
        // A refused discard still clears locally, revokes, and reports the failure.
        let f = anonymousHarness()
        // (a 500, not the 503 stub: a 503 opens the client breaker, which then holds the fire-and-forget revoke)
        f.transport.stub("POST", "/auth-service/guest/discard", .failure(status: 500, code: "BOOM"))
        let fr: Result<Void, SendoraCloudAuthError> = f.wait { done in f.auth.signOut(discardGuest: true, completion: done) }
        XCTAssertNotNil(fr.failureError)
        XCTAssertEqual(f.auth.status(), .signedOut)
        XCTAssertEqual(f.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-anon")
        // On an identified session the flag changes nothing: the local-first row.
        let i = identifiedHarness()
        XCTAssertNil((i.wait { done in i.auth.signOut(discardGuest: true, completion: done) } as Result<Void, SendoraCloudAuthError>).failureError)
        XCTAssertEqual(i.transport.requests(to: "/auth-service/guest/discard").count, 0)
        XCTAssertEqual(i.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-ident")
    }

    // MARK: QUARANTINE verbs

    func scenario_recover_quarantined_as_restore() {
        let ok = signedOutHarness(expected: TestJWT.projectA)
        ok.seedQuarantine(0, userId: "g-q", refresh: "q-rt")
        ok.boot()
        ok.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse(userId: "g-q", refresh: "q-rt-2"))
        let mark = ok.secure.writeCount
        guard case .success(let u) = (ok.wait { done in ok.auth.recoverQuarantinedGuest("g-q", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("recover") }
        XCTAssertEqual(u.id, "g-q"); XCTAssertEqual(ok.auth.status(), .anonymous); XCTAssertEqual(ok.storedRefresh, "q-rt-2")
        XCTAssertNil(ok.quarantineSlot(0))
        let writes = ok.secure.writesSince(mark)
        guard let installIdx = writes.firstIndex(where: { $0.key == Self.refreshKey && $0.value == "q-rt-2" }),
              let releaseIdx = writes.lastIndex(where: { $0.key == SendoraStorage.quarantineSlotKeys[0] && $0.op == "delete" }) else { return XCTFail("install + release") }
        XCTAssertLessThan(installIdx, releaseIdx, "install BEFORE the slot is released")
        XCTAssertEqual(ok.transitionEventNames, ["signed_in", "guest_released"])
        XCTAssertEqual(ok.auth.lastSignedInCause(), .restore)
        if case .guestReleased(let id, let reason, _)? = ok.events.last { XCTAssertEqual(id, "g-q"); XCTAssertEqual(reason, .restored) }
        // reuse → KEPT, QUARANTINE_UNRECOVERABLE (retryable, kind server), no event.
        let reuse = signedOutHarness()
        reuse.seedQuarantine(0, userId: "g-q", refresh: "q-rt")
        reuse.boot()
        reuse.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "reuse"))
        let e = (reuse.wait { done in reuse.auth.recoverQuarantinedGuest("g-q", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError
        XCTAssertEqual(e?.code, "QUARANTINE_UNRECOVERABLE"); XCTAssertEqual(e?.kind, .server); XCTAssertEqual(e?.retryable, true)
        XCTAssertNotNil(reuse.quarantineSlot(0)); XCTAssertEqual(reuse.transitionEventNames, [])
        // ⚠ Pin converted (s58.415): `revoked` / `expired` / `unknown` now KEEP the slot too (was released with
        // HELD_GUEST_GONE for revoked|expired) — only a confirmed `deleted` releases it.
        for verdict in ["revoked", "expired", "unknown"] {
            let k = signedOutHarness()
            k.seedQuarantine(0, userId: "g-q", refresh: "q-rt")
            k.boot()
            k.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: verdict))
            let ke = (k.wait { done in k.auth.recoverQuarantinedGuest("g-q", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError
            XCTAssertEqual(ke?.code, "QUARANTINE_UNRECOVERABLE", verdict); XCTAssertNotNil(k.quarantineSlot(0), verdict)
            XCTAssertEqual(k.transitionEventNames, [], verdict)
        }
        // An `unknown:<hash>` occupant is named by the server's answer (no identity tripwire against a placeholder).
        let anonOcc = signedOutHarness()
        let placeholder = SendoraCloudAuth.unknownOccupantId("q-rt")
        anonOcc.seedQuarantine(0, userId: placeholder, refresh: "q-rt")
        anonOcc.boot()
        anonOcc.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse(userId: "g-real", refresh: "q-rt-2"))
        guard case .success(let named) = (anonOcc.wait { done in anonOcc.auth.recoverQuarantinedGuest(placeholder, completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("recover an unknown occupant") }
        XCTAssertEqual(named.id, "g-real"); XCTAssertNil(anonOcc.quarantineSlot(0))
        // deleted → released (guest_released{dead}), HELD_GUEST_GONE.
        let gone = signedOutHarness()
        gone.seedQuarantine(0, userId: "g-q", refresh: "q-rt")
        gone.boot()
        gone.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "deleted"))
        let ge = (gone.wait { done in gone.auth.recoverQuarantinedGuest("g-q", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError
        XCTAssertEqual(ge?.code, "HELD_GUEST_GONE"); XCTAssertNil(gone.quarantineSlot(0))
        if case .guestReleased(_, let reason, let end)? = gone.events.last { XCTAssertEqual(reason, .dead); XCTAssertEqual(end, .deleted) } else { XCTFail("released dead") }
        // Over a guest: the current guest is HELD first (slot written before the token goes out).
        let over = anonymousHarness()
        over.seedQuarantine(0, userId: "g-q", refresh: "q-rt")
        over.boot()
        var heldAtSend: HeldSlotRecord?
        over.transport.onRequest = { req in if req.path == "/auth-service/token/refresh" { heldAtSend = over.heldSlot(0) } }
        over.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse(userId: "g-q", refresh: "q-rt-2"))
        guard case .success = (over.wait { done in over.auth.recoverQuarantinedGuest("g-q", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("recover over a guest") }
        XCTAssertEqual(heldAtSend?.userId, Self.anon.id)
        XCTAssertEqual(over.transitionEventNames, ["guest_held", "signed_in", "guest_released"])
        XCTAssertEqual(over.transport.requests(to: "/auth-service/token/revoke").count, 0)
        // Unknown id → no network.
        let none = signedOutHarness()
        XCTAssertEqual((none.wait { done in none.auth.recoverQuarantinedGuest("nobody", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError?.code, "QUARANTINED_GUEST_NOT_FOUND")
        XCTAssertEqual(none.transport.requestCount, 0)
    }

    func scenario_discard_quarantined_slot() {
        for (response, released) in [(StubResponse.ok(["userId": "g-q", "status": "purged"]), true), (.failure(status: 404, code: "NOT_FOUND", message: "Guest"), true), (Stub.serverError, false), (.offline, false)] {
            let h = signedOutHarness()
            h.seedQuarantine(0, userId: "g-q", refresh: "q-rt")
            h.boot()
            h.transport.stub("POST", "/auth-service/guest/discard", response)
            let r: Result<Void, SendoraCloudAuthError> = h.wait { done in h.auth.discardQuarantinedGuest("g-q", completion: done) }
            XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/guest/discard")?.body?["refreshToken"] as? String, "q-rt")
            if released {
                XCTAssertNil(r.failureError); XCTAssertNil(h.quarantineSlot(0), "status \(response.status): released")
                XCTAssertEqual(h.transitionEventNames, ["guest_released"])
                if case .guestReleased(_, let reason, _)? = h.events.last { XCTAssertEqual(reason, .discarded) }
            } else {
                XCTAssertNotNil(r.failureError); XCTAssertNotNil(h.quarantineSlot(0), "status \(response.status): KEPT")
                XCTAssertEqual(h.transitionEventNames, [])
            }
        }
        // N4 — release BY OCCUPANT: a commit naming a guest the slot no longer holds is DROPPED (held + quarantine).
        let n = signedOutHarness()
        n.seedSlot(0, AuthHarness.slot(userId: "now-here", refresh: "rt-n", heldAt: 1))
        n.seedQuarantine(0, userId: "now-here", refresh: "q-n")
        n.boot()
        let mark = n.secure.writeCount
        XCTAssertNil(n.auth.commitRelease(index: 0, userId: "was-here"), "held: a mismatching occupant is not released")
        XCTAssertNil(n.auth.commitQuarantineRelease(index: 0, userId: "was-here"), "quarantine: same")
        XCTAssertEqual(n.secure.writeCount, mark, "nothing written")
        XCTAssertEqual(n.heldSlot(0)?.userId, "now-here"); XCTAssertEqual(n.quarantineSlot(0)?.userId, "now-here")
        XCTAssertEqual(n.auth.commitRelease(index: 0, userId: "now-here")?.userId, "now-here", "the named occupant is released")
        XCTAssertEqual(n.auth.commitQuarantineRelease(index: 0, userId: "now-here")?.userId, "now-here")
        // A delayed discard whose slot was refilled meanwhile leaves the new occupant alone.
        let d = signedOutHarness()
        d.seedQuarantine(0, userId: "g-q", refresh: "q-rt")
        d.boot()
        d.transport.onRequest = { req in
            if req.path == "/auth-service/guest/discard" {
                d.secure.seed(SendoraStorage.quarantineSlotKeys[0], QuarantineSlotRecord(userId: "other", sid: "", refreshToken: "q-o", quarantinedAt: 9, project: nil).encodeJson()!)
                d.auth.lock.lock(); d.auth.quarantine[0] = QuarantineSlotRecord(userId: "other", sid: "", refreshToken: "q-o", quarantinedAt: 9, project: nil); d.auth.lock.unlock()
            }
        }
        d.transport.stub("POST", "/auth-service/guest/discard", .ok([:]))
        _ = d.wait { done in d.auth.discardQuarantinedGuest("g-q", completion: done) } as Result<Void, SendoraCloudAuthError>
        XCTAssertEqual(d.quarantineSlot(0)?.userId, "other", "the refilled slot is not emptied by the late discard")
        XCTAssertEqual(d.transitionEventNames, [])
    }
}
