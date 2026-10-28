import XCTest
@testable import SendoraCloud

// ADR-033 INV-11 — row scenarios, part 2: CAS, REFRESH_*, SIGN_OUT, DELETE,
// CLAIM, RESTORE, DISCARD, RESET and the three §3.5-sourced rows.

extension AuthMachineConformanceTests {
    func rowScenariosPart2() -> [String: () -> Void] {
        return [
            "sign_in.cas_mismatch": scenario_sign_in_cas_mismatch,
            "refresh_ok.current_match": scenario_refresh_ok_current_match,
            "refresh_ok.current_mismatch_withhold": scenario_refresh_ok_current_mismatch_withhold,
            "refresh_ok.held_slot": scenario_refresh_ok_held_slot,
            "refresh_ok.unrouted_drop": scenario_refresh_ok_unrouted_drop,
            "refresh_dead.current": scenario_refresh_dead_current,
            "refresh_dead.held_slot": scenario_refresh_dead_held_slot,
            "refresh_transient.backoff": scenario_refresh_transient_backoff,
            "sign_out.local_first": scenario_sign_out_local_first,
            "delete.account": scenario_delete_account,
            "claim.held_guest": scenario_claim_held_guest,
            "restore.held_guest": scenario_restore_held_guest,
            "restore.over_anonymous_holds_current": scenario_restore_over_anonymous_holds_current,
            "discard.held_guest": scenario_discard_held_guest,
            "reset.keeps_held": scenario_reset_keeps_held,
            "discard_withheld.precondition_false": scenario_discard_withheld_precondition_false,
            "claim.identified_only": scenario_claim_identified_only,
            "session_verb.pass_through": scenario_session_verb_pass_through,
        ]
    }

    func heldRefreshResponse(userId: String = "g-held", refresh: String = "rt-held-2", project: String?? = .some(TestJWT.projectA)) -> StubResponse {
        Stub.session(user: Stub.user(id: userId, isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: userId, sid: "sid-held", isAnonymous: true, project: project), refresh: refresh))
    }

    func scenario_sign_in_cas_mismatch() {
        let h = anonymousHarness()
        let gate = h.transport.gate("/auth-service/login")
        h.transport.stub("POST", "/auth-service/login", identifiedSignInResponse(refresh: "rt-b-dropped"))
        let sem = DispatchSemaphore(value: 0)
        var result: Result<SendoraCloudAuthUser, SendoraCloudAuthError>?
        h.auth.signIn(email: "p@example.com", password: "pw") { r in result = r; sem.signal() }
        usleep(150_000)
        // The session the attempt was derived from changes while the request is in flight.
        XCTAssertTrue(h.auth.commitClear(reason: .user))
        gate.signal()
        XCTAssertEqual(sem.wait(timeout: .now() + 5), .success)
        XCTAssertNotNil(result?.failureError, "the result is DROPPED")
        XCTAssertEqual(h.auth.status(), .signedOut, "not installed")
        XCTAssertNil(h.heldSlot(0), "nothing held either")
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-b-dropped", "server session B is not left live")
        XCTAssertEqual(h.transitionEventNames, ["signed_out"], "only the clear's event; no signed_in for the dropped result")
    }

    func scenario_refresh_ok_current_match() {
        let h = anonymousHarness(expected: TestJWT.projectA)
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.session(user: Stub.user(from: Self.anon), tokens: Stub.tokens(access: Self.anonToken(), refresh: "rt-anon-2")))
        XCTAssertNotNil(h.getAccessToken(forceRefresh: true))
        XCTAssertEqual(h.storedRefresh, "rt-anon-2"); XCTAssertEqual(h.storedSessionRecord?.refreshToken, "rt-anon-2")
        XCTAssertEqual(h.transitionEventNames, [], "a rotation is not a transition")
        XCTAssertEqual(h.auth.status(), .anonymous)
        // the user object differs → user_updated{refresh}
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.session(user: Stub.user(id: Self.anon.id, isAnonymous: true, name: "renamed"), tokens: Stub.tokens(access: Self.anonToken(), refresh: "rt-anon-3")))
        _ = h.getAccessToken(forceRefresh: true)
        XCTAssertEqual(h.transitionEventNames, ["user_updated"])
        if case .userUpdated(let user, let cause)? = h.events.last { XCTAssertEqual(user.name, "renamed"); XCTAssertEqual(cause, .refresh) }
    }

    func scenario_refresh_ok_current_mismatch_withhold() {
        let h = anonymousHarness(expected: TestJWT.projectA)
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.session(user: Stub.user(id: Self.anon.id, isAnonymous: true, project: TestJWT.projectB), tokens: Stub.tokens(access: Self.anonToken(project: .some(TestJWT.projectB)), refresh: "rt-rotated")))
        XCTAssertNil(h.getAccessToken(forceRefresh: true))
        XCTAssertEqual(h.auth.status(), .withheld)
        XCTAssertEqual(h.storedRefresh, "rt-rotated", "persist the rotated pair by sent-token CAS (the server already performed it)")
        XCTAssertNotNil(h.storedUserJson, "and NOTHING else is touched")
        XCTAssertNil(h.auth.currentUser, "in-memory user uninstalled")
        XCTAssertFalse(h.auth.cronArmed, "stop the cron")
        XCTAssertEqual(h.withheldHookCalls, 1)
        XCTAssertEqual(h.transitionEventNames, ["session_withheld"])
        if case .sessionWithheld(let expected, let actual, let userId)? = h.events.last {
            XCTAssertEqual(expected, TestJWT.projectA); XCTAssertEqual(actual, TestJWT.projectB); XCTAssertEqual(userId, Self.anon.id)
        }
        XCTAssertNil(h.getAccessToken(), "no refresh in withheld")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 1)
    }

    func scenario_refresh_ok_held_slot() {
        // CLAIM presents the held token: the slot carries the ROTATED token BEFORE /merge goes out.
        let h = identifiedHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse())
        var slotAtMerge: HeldSlotRecord?
        h.transport.onRequest = { req in if req.path == "/auth-service/merge" { slotAtMerge = h.heldSlot(0) } }
        h.transport.stub("POST", "/auth-service/merge", Stub.serverError)
        let result: Result<SendoraCloudClaimResult, SendoraCloudAuthError> = h.wait { done in h.auth.claimHeldGuest(completion: done) }
        XCTAssertNotNil(result.failureError)
        XCTAssertEqual(slotAtMerge?.refreshToken, "rt-held-2", "CAS per slot: the rotation is persisted into the slot before the next step")
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/merge")?.body?["anonymousRefreshToken"] as? String, "rt-held-2")
        XCTAssertEqual(h.heldSlot(0)?.tokenAtHold, "rt-held", "tokenAtHold is kept for the merge() alias")
        XCTAssertEqual(h.storedRefresh, "rt-ident", "the CURRENT session is untouched by a held-slot rotation")
        // a stale per-slot CAS drops
        XCTAssertEqual(h.auth.commitSlotRotation(index: 0, expectRefresh: "rt-held", newRefresh: "x"), .casMismatch)
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "rt-held-2")
    }

    func scenario_refresh_ok_unrouted_drop() {
        // An IDENTIFIED account (rev 3 narrowed this to identified while J.1 held a signed-out guest; since decision C
        // a guest's sign-out drops its token too, so a late guest rotation is dropped the same way — the identified
        // drive is kept as the pin).
        let h = identifiedHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "g", refresh: "rt-g", heldAt: 1))
        h.boot()
        let before = h.secure.snapshot()
        let tokens = SendoraCloudAuthTokens(accessToken: Self.anonToken(), refreshToken: "rt-new", expiresIn: 900, tokenType: "Bearer")
        XCTAssertNil(h.auth.commitRefreshOk(sent: "rt-that-nothing-holds", tokens: tokens, user: Self.anon))
        XCTAssertEqual(h.secure.snapshot(), before, "DROP — a rotation whose sent token matches nothing installs nothing (P16)")
        XCTAssertEqual(h.transitionEventNames, [])
        // The real interleaving: signOut() lands while the refresh is in flight → the late answer is DROPPED.
        let late = identifiedHarness()
        let gate = late.transport.gate("/auth-service/token/refresh")
        late.transport.stub("POST", "/auth-service/token/refresh", Stub.session(user: Stub.user(from: Self.ident), tokens: Stub.tokens(access: Self.identToken(), refresh: "rt-late")))
        let sem = DispatchSemaphore(value: 0)
        late.auth.getAccessToken(forceRefresh: true) { _ in sem.signal() }
        XCTAssertTrue(late.eventually { late.transport.requests(to: "/auth-service/token/refresh").count == 1 })
        late.waitVoid { done in late.auth.signOut(completion: done) }
        gate.signal()
        XCTAssertEqual(sem.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(late.auth.status(), .signedOut, "the late rotation installs nothing")
        XCTAssertNil(late.storedRefresh)
        XCTAssertNil(late.refreshMarker, "the marker of a session that is gone is not left behind")
        XCTAssertEqual(late.transitionEventNames, ["signed_out"])
    }

    func scenario_refresh_dead_current() {
        // 5.4.1: `reason` is sessionExpired for EVERY dead verdict (5.3.0's value — a listener
        // matching it must still see "deleted elsewhere" / "revoked"); the server's detail is
        // `lastSignedOutEndReason()`, set before delivery, nil iff the server sent none.
        // ⚠ Pin converted (s58.415, G1 — zero guest-account loss): a GUEST is cleared here ONLY on a server-confirmed
        // `deleted`; every other verdict (revoked / evicted / expired / reuse / unknown / absent) is
        // refresh_dead.current_guest_quarantine. So the non-`deleted` cases drive an IDENTIFIED account (cleared as before)
        // and `deleted` drives BOTH. (rev 3 converted only `reuse` this way.)
        for (endReason, expected, guest): (String?, SendoraCloudAuthSignedOutReason, Bool) in [("revoked", .sessionExpired, false), ("deleted", .sessionExpired, true), ("deleted", .sessionExpired, false), ("evicted", .sessionExpired, false), ("expired", .sessionExpired, false), ("reuse", .sessionExpired, false), ("unknown", .sessionExpired, false), (nil, .sessionExpired, false)] {
            let h = guest ? anonymousHarness() : identifiedHarness()
            h.seedSlot(0, AuthHarness.slot(userId: "g", refresh: "rt-g", heldAt: 1))
            h.boot()
            var seenInListener: SendoraCloudRefreshEndReason?? = .none
            let unsubscribe = h.auth.onAuthStateChanged { change in
                if case .signedOut = change { seenInListener = .some(h.auth.lastSignedOutEndReason()) }
            }
            defer { unsubscribe() }
            h.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: endReason))
            XCTAssertNil(h.getAccessToken(forceRefresh: true))
            XCTAssertEqual(h.auth.status(), .signedOut, "\(endReason ?? "absent")")
            XCTAssertNil(h.storedRefresh); XCTAssertNil(h.storedUserJson)
            XCTAssertNotNil(h.heldSlot(0), "held slots untouched by the current session's death")
            XCTAssertFalse(h.auth.cronArmed)
            XCTAssertEqual(h.transitionEventNames, ["signed_out"])
            guard case .signedOut(let reason)? = h.events.last else { XCTFail("signed_out last"); continue }
            XCTAssertEqual(reason, expected, "\(endReason ?? "absent")")
            XCTAssertEqual(seenInListener, .some(endReason.flatMap(SendoraCloudRefreshEndReason.init(rawValue:))), "endReason readable INSIDE the listener: \(endReason ?? "absent")")
            XCTAssertEqual(h.clearEffects.last?.rotateDeviceId, false, "no anon-id rotation on an involuntary death")
        }
        // from unknown (the gap-fill refresh died) → signed_out, never a mint. (s58.415: a limbo whose owner is
        // undeterminable is a guest → quarantined unless `deleted`; an access token saying "account" is cleared.)
        let limbo = AuthHarness()
        limbo.seedLimbo(refresh: "rt-limbo", access: Self.identToken())
        limbo.boot()
        limbo.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "revoked"))
        XCTAssertNil(limbo.getAccessToken())
        XCTAssertEqual(limbo.auth.status(), .signedOut)
        XCTAssertEqual(limbo.transport.requests(to: "/auth-service/anonymous").count, 0)
        guard case .signedOut(let limboReason)? = limbo.events.last else { return XCTFail("limbo death emits signed_out") }
        XCTAssertEqual(limboReason, .sessionExpired, "limbo death: reason stays sessionExpired (5.4.1)")
        XCTAssertEqual(limbo.auth.lastSignedOutEndReason(), .revoked, "limbo death: endReason carried separately")
        // A later deliberate signOut must not inherit the previous death's endReason.
        let fresh = anonymousHarness()
        fresh.boot()
        fresh.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "deleted"))
        XCTAssertNil(fresh.getAccessToken(forceRefresh: true))
        XCTAssertEqual(fresh.auth.lastSignedOutEndReason(), .deleted)
        fresh.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "fresh"), refresh: "rt-f"), status: 201))
        guard case .success = fresh.mint() else { return XCTFail("mint after the death") }
        fresh.waitVoid { done in fresh.auth.signOut(completion: done) }
        guard case .signedOut(.user)? = fresh.events.last else { return XCTFail("signOut emits signed_out{user}") }
        XCTAssertNil(fresh.auth.lastSignedOutEndReason(), "signOut clears the previous death's endReason")
    }

    func scenario_refresh_dead_held_slot() {
        // ⚠ Pin converted (s58.415, G1): released ONLY on `deleted` (was deleted|revoked|expired). Every other verdict
        // MOVES the token to a free quarantine slot (confirmed) and then releases the held slot by occupant
        // (`guest_released{dead}`) — was "kept in place". The refresh carries the slot's access token as the hint (G2).
        for (endReason, released) in [("deleted", true), ("revoked", false), ("expired", false), ("reuse", false), (nil, false), ("unknown", false)] as [(String?, Bool)] {
            let h = signedOutHarness()
            h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1, access: "at-held", origin: AuthHarness.origin))
            h.boot()
            h.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: endReason))
            let result: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.restoreHeldGuest(id: "g-held", completion: done) }
            let label = endReason ?? "absent"
            XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/token/refresh")?.body?["accessTokenHint"] as? String, "at-held", "\(label): the slot's access token is the hint")
            XCTAssertNil(h.heldSlot(0), "\(label): the held slot is emptied")
            // (s58.415, C5) `dead` = a confirmed `deleted` only; a move to quarantine is guest_released{quarantined}
            // THEN guest_quarantined{userId, endReason}.
            XCTAssertEqual(h.transitionEventNames, released ? ["guest_released"] : ["guest_released", "guest_quarantined"], label)
            if case .guestReleased(let id, let reason, let end)? = h.event(at: 1) {
                XCTAssertEqual(id, "g-held"); XCTAssertEqual(reason, released ? .dead : .quarantined, label); XCTAssertEqual(end?.rawValue, endReason)
            } else { XCTFail("\(label): guest_released first") }
            if !released, case .guestQuarantined(let id, let end)? = h.event(at: 2) {
                XCTAssertEqual(id, "g-held"); XCTAssertEqual(end, endReason.flatMap(SendoraCloudRefreshEndReason.init(rawValue:)) ?? .unknown, label)
            } else if !released { XCTFail("\(label): guest_quarantined second") }
            if released {
                XCTAssertEqual(result.failureError?.code, "HELD_GUEST_GONE", label)
                XCTAssertNil(h.quarantineSlot(0), "\(label): a confirmed deletion keeps nothing")
            } else {
                let q = h.quarantineSlot(0)
                XCTAssertEqual(q?.userId, "g-held", "\(label): moved to quarantine — never thrown away")
                XCTAssertEqual(q?.refreshToken, "rt-held"); XCTAssertEqual(q?.accessToken, "at-held"); XCTAssertEqual(q?.origin, AuthHarness.origin)
                XCTAssertEqual(result.failureError?.code, "RESTORE_FAILED", label)
                XCTAssertEqual(result.failureError?.retryable, true, label)
                XCTAssertEqual(h.auth.getQuarantinedGuests().map { $0.userId }, ["g-held"], label)
            }
        }
        // Quarantine FULL → the held slot is KEPT with autoRestore:false (confirmed); ensureSession() then never presents
        // it again and never fails RESTORE_FAILED for it — it mints.
        let full = signedOutHarness()
        full.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        for i in 0..<3 { full.seedQuarantine(i, userId: "q\(i)", refresh: "rq\(i)", at: Int64(i + 1)) }
        full.boot()
        full.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "revoked"))
        full.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "fresh"), refresh: "rt-fresh"), status: 201))
        guard case .success(let minted) = full.mint() else { return XCTFail("ensureSession mints past a parked slot") }
        XCTAssertEqual(minted.id, "fresh")
        XCTAssertEqual(full.heldSlot(0)?.userId, "g-held", "kept"); XCTAssertEqual(full.heldSlot(0)?.autoRestore, false, "parked")
        XCTAssertEqual(full.heldSlot(0)?.refreshToken, "rt-held")
        for i in 0..<3 { XCTAssertEqual(full.quarantineSlot(i)?.userId, "q\(i)", "a full quarantine is never overwritten") }
        XCTAssertEqual(full.transport.requests(to: "/auth-service/token/refresh").count, 1)
        full.waitVoid { done in full.auth.signOut(completion: done) }
        guard case .success = full.mint() else { return XCTFail("mint again") }
        XCTAssertEqual(full.transport.requests(to: "/auth-service/token/refresh").count, 1, "the parked slot is never presented again by auto-restore")
        // …while an explicit restore of it still surfaces RESTORE_FAILED (retryable).
        let explicit: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = full.wait { done in full.auth.restoreHeldGuest(id: "g-held", completion: done) }
        XCTAssertEqual(explicit.failureError?.code, "RESTORE_FAILED")
        XCTAssertEqual(full.heldSlot(0)?.userId, "g-held")
    }

    func scenario_refresh_transient_backoff() {
        for response in [Stub.rateLimited, Stub.serverError, .offline, .failure(status: 401, code: "UNAUTHORIZED", message: "key rotated")] {
            let h = anonymousHarness()
            h.transport.stub("POST", "/auth-service/token/refresh", response)
            let before = h.secure.snapshot()
            XCTAssertNil(h.getAccessToken(forceRefresh: true))
            XCTAssertEqual(h.auth.status(), .anonymous, "status \(response.status): NO identity change")
            // (T15) The INV-16 marker is a Keychain item now and an unanswered / refused refresh KEEPS it (outcome
            // unknown); every other key is byte-identical.
            var after = h.secure.snapshot()
            XCTAssertNotNil(after.removeValue(forKey: SendoraStorage.refreshInflightKey), "status \(response.status): the marker stays")
            XCTAssertEqual(after, before)
            XCTAssertEqual(h.transitionEventNames, [])
        }
    }

    func scenario_sign_out_local_first() {
        // ⚠ Pin converted back (decision C, 2026-10-26 — replaces J.1): a GUEST signs out exactly like an account —
        // token dropped + revoked, `signed_out` ONLY, nothing new held. The first rev-3 cut narrowed this row to
        // identified and HELD the guest instead; that bricked ensureSession() on the 5th sign-out (H1).
        for h in [anonymousHarness(), identifiedHarness()] {
            h.seedSlot(0, AuthHarness.slot(userId: "g", refresh: "rt-g", heldAt: 1))
            h.boot()
            let refresh = h.auth.getRefreshToken()
            h.waitVoid { done in h.auth.signOut(completion: done) }
            XCTAssertEqual(h.auth.status(), .signedOut)
            XCTAssertNil(h.storedRefresh); XCTAssertNil(h.storedSessionRecord)
            XCTAssertNotNil(h.heldSlot(0), "KEEP held slots")
            XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, refresh)
            XCTAssertEqual(h.transitionEventNames, ["signed_out"], "signed_out ONLY — never guest_held")
            if case .signedOut(let reason)? = h.events.last { XCTAssertEqual(reason, .user) }
            XCTAssertEqual(h.auth.heldGuests().map { $0.userId }, ["g"], "nothing new is held (the pre-existing slot only)")
            XCTAssertEqual(h.auth.getQuarantinedGuests().count, 0)
            XCTAssertEqual(h.clearEffects.last?.rotateDeviceId, true, "rotate the analytics anon id")
            XCTAssertEqual(h.clearEffects.last?.clearQueue, false, "keep the event queue")
            XCTAssertFalse(h.auth.cronArmed)
        }
    }

    func scenario_delete_account() {
        let h = identifiedHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "g0", refresh: "rt0", heldAt: 1))
        h.seedSlot(1, AuthHarness.slot(userId: "g1", refresh: "rt1", heldAt: 2))
        h.boot()
        h.transport.stub("DELETE", "/auth-service/me", .ok(["status": "purged", "graceDays": 0, "scheduledPurgeAt": NSNull()]))
        let result: Result<SendoraCloudAuth.AccountDeletionResult, Error> = h.wait { done in h.auth.deleteAccount(completion: done) }
        guard case .success(let outcome) = result else { return XCTFail("delete must succeed") }
        XCTAssertEqual(outcome.status, "purged"); XCTAssertEqual(outcome.heldGuests, 2)
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/me")?.headers["Authorization"], "Bearer \(Self.identToken())")
        XCTAssertEqual(h.auth.status(), .signedOut)
        XCTAssertEqual(h.heldSlot(0)?.autoRestore, false); XCTAssertEqual(h.heldSlot(1)?.autoRestore, false, "slots KEPT, stamped autoRestore:false")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/guest/discard").count, 0, "deleting an account never touches a held guest")
        XCTAssertEqual(h.transitionEventNames, ["signed_out"])
        if case .signedOut(let reason)? = h.events.last { XCTAssertEqual(reason, .accountDeleted) }
        XCTAssertEqual(h.clearEffects.last?.clearQueue, true, "CLEAR the event queue (s58.353)")
        XCTAssertEqual(h.clearEffects.last?.rotateDeviceId, true)
        // integrator test 9: the next boot mints fresh — no auto-restore after account_deleted
        h.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "fresh"), refresh: "rt-f"), status: 201))
        guard case .success(let fresh) = h.mint() else { return XCTFail("mint fresh") }
        XCTAssertEqual(fresh.id, "fresh")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/refresh").count, 0, "no held token presented")
        XCTAssertEqual(h.auth.heldGuests().count, 2)
        // explicit restore still works
        h.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse(userId: "g1", refresh: "rt1-2"))
        guard case .success(let restored) = (h.wait { done in h.auth.restoreHeldGuest(id: "g1", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("explicit restore") }
        XCTAssertEqual(restored.id, "g1")
        // alsoDiscardHeldGuests: /guest/discard per slot after the 2xx; failures reported, slots kept
        let d = identifiedHarness()
        d.seedSlot(0, AuthHarness.slot(userId: "g0", refresh: "rt0", heldAt: 1)); d.seedSlot(1, AuthHarness.slot(userId: "g1", refresh: "rt1", heldAt: 2))
        d.boot()
        d.transport.stub("DELETE", "/auth-service/me", .ok(["status": "pending", "graceDays": 7, "scheduledPurgeAt": "2026-10-17T00:00:00Z"]))
        d.transport.stub("POST", "/auth-service/guest/discard") { req in
            req.body?["refreshToken"] as? String == "rt0" ? Stub.serverError : .ok(["userId": "g1", "status": "purged"])
        }
        guard case .success(let out) = (d.wait { done in d.auth.deleteAccount(alsoDiscardHeldGuests: true, completion: done) } as Result<SendoraCloudAuth.AccountDeletionResult, Error>) else { return XCTFail("delete") }
        XCTAssertEqual(out.heldGuestsDiscardFailed, ["g0"]); XCTAssertEqual(out.heldGuests, 1)
        XCTAssertNotNil(d.heldSlot(0)); XCTAssertNil(d.heldSlot(1))
        XCTAssertEqual(d.transport.requests(to: "/auth-service/guest/discard").count, 2)
        guard let deleteIdx = d.transport.requests.firstIndex(where: { $0.path == "/auth-service/me" }),
              let discardIdx = d.transport.requests.firstIndex(where: { $0.path == "/auth-service/guest/discard" }) else {
            return XCTFail("DELETE /me and /guest/discard must both be sent")
        }
        XCTAssertLessThan(deleteIdx, discardIdx, "discards run AFTER the 2xx")
    }

    func scenario_claim_held_guest() {
        let h = identifiedHarness(expected: TestJWT.projectA)
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse())
        h.transport.stub("POST", "/auth-service/merge", .ok(["mergedUserId": Self.ident.id, "deletedAnonymousId": "g-held", "eventsReassigned": 7, "pushTokensReassigned": 1,
                                                            "tokens": Stub.tokens(access: Self.identToken(), refresh: "rt-ident-2"), "csrfToken": "c"]))
        guard case .success(let claim) = (h.wait { done in h.auth.claimHeldGuest(completion: done) } as Result<SendoraCloudClaimResult, SendoraCloudAuthError>) else { return XCTFail("claim") }
        XCTAssertEqual(claim.stats.eventsReassigned, 7); XCTAssertEqual(claim.stats.deletedAnonymousId, "g-held"); XCTAssertEqual(claim.user.id, Self.ident.id)
        let paths = h.transport.requests.map { $0.path }
        XCTAssertEqual(paths.filter { $0 == "/auth-service/token/refresh" || $0 == "/auth-service/merge" }, ["/auth-service/token/refresh", "/auth-service/merge"], "refreshHeld FIRST, then merge")
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/token/refresh")?.body?["refreshToken"] as? String, "rt-held", "the HELD token is what is presented")
        let merge = h.transport.lastRequest(to: "/auth-service/merge")?.body
        XCTAssertEqual(merge?["anonymousRefreshToken"] as? String, "rt-held-2"); XCTAssertEqual(merge?["targetRefreshToken"] as? String, "rt-ident")
        XCTAssertEqual(h.storedRefresh, "rt-ident-2", "the rotated target pair is installed")
        XCTAssertNil(h.heldSlot(0), "slot released")
        XCTAssertEqual(h.transitionEventNames, ["user_updated", "guest_released"])
        if case .userUpdated(_, let cause)? = h.event(at: 2) { XCTAssertEqual(cause, .merge) }
        if case .guestReleased(let id, let reason, _)? = h.event(at: 3) { XCTAssertEqual(id, "g-held"); XCTAssertEqual(reason, .claimed) }
        XCTAssertEqual(h.auth.status(), .identified)
        // two held + no id → AMBIGUOUS_HELD_GUEST, nothing mutated, no network
        let two = identifiedHarness()
        two.seedSlot(0, AuthHarness.slot(userId: "g0", refresh: "rt0", heldAt: 1)); two.seedSlot(1, AuthHarness.slot(userId: "g1", refresh: "rt1", heldAt: 2))
        two.boot()
        let mark = two.secure.writeCount
        XCTAssertEqual((two.wait { done in two.auth.claimHeldGuest(completion: done) } as Result<SendoraCloudClaimResult, SendoraCloudAuthError>).failureError?.code, "AMBIGUOUS_HELD_GUEST")
        XCTAssertEqual(two.transport.requestCount, 0); XCTAssertEqual(two.secure.writeCount, mark)
        // the deprecated merge(anonRefreshToken:) routes a journalled token to its slot → claim
        two.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse(userId: "g1", refresh: "rt1-2"))
        two.transport.stub("POST", "/auth-service/merge", .ok(["tokens": Stub.tokens(access: Self.identToken(), refresh: "rt-ident-2")]))
        guard case .success = (two.wait { done in two.auth.merge(anonRefreshToken: "rt1", completion: done) } as Result<SendoraCloudClaimResult, SendoraCloudAuthError>) else { return XCTFail("merge alias") }
        XCTAssertNil(two.heldSlot(1)); XCTAssertNotNil(two.heldSlot(0))
    }

    func scenario_restore_held_guest() {
        // from signed_out: install BEFORE the slot is removed; emits signed_in then guest_released
        let h = signedOutHarness(expected: TestJWT.projectA)
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse())
        let mark = h.secure.writeCount
        guard case .success(let user) = (h.wait { done in h.auth.restoreHeldGuest(completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("restore") }
        XCTAssertEqual(user.id, "g-held"); XCTAssertEqual(h.auth.status(), .anonymous)
        XCTAssertEqual(h.storedRefresh, "rt-held-2"); XCTAssertNil(h.heldSlot(0))
        let writes = h.secure.writesSince(mark)
        guard let installIdx = writes.firstIndex(where: { $0.key == "sendora_auth_refresh_token" && $0.value == "rt-held-2" }),
              let releaseIdx = writes.lastIndex(where: { $0.key == SendoraStorage.heldSlotKeys[0] && $0.op == "delete" }) else {
            return XCTFail("RESTORE must install the held record and delete its slot")
        }
        XCTAssertLessThan(installIdx, releaseIdx, "install the held record BEFORE removing the slot — never zero handles")
        XCTAssertEqual(h.transitionEventNames, ["signed_in", "guest_released"])
        XCTAssertEqual(h.auth.lastSignedInCause(), .restore)
        if case .guestReleased(let id, let reason, _)? = h.events.last { XCTAssertEqual(id, "g-held"); XCTAssertEqual(reason, .restored) }
        // from identified: the current session is revoked
        let ident = identifiedHarness()
        ident.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        ident.boot()
        ident.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse())
        guard case .success = (ident.wait { done in ident.auth.restoreHeldGuest(completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("restore from identified") }
        XCTAssertEqual(ident.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-ident")
        XCTAssertEqual(ident.auth.status(), .anonymous)
        // PROJECT CHECK FIRST: a mismatching slot project → refused client-side, no network, slot kept
        let mismatch = signedOutHarness(expected: TestJWT.projectA)
        mismatch.seedSlot(0, AuthHarness.slot(userId: "g-other", refresh: "rt-o", heldAt: 1, project: TestJWT.projectB))
        mismatch.boot()
        let err = (mismatch.wait { done in mismatch.auth.restoreHeldGuest(completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError
        XCTAssertEqual(err?.code, "HELD_GUEST_PROJECT_MISMATCH"); XCTAssertEqual(mismatch.transport.requestCount, 0); XCTAssertNotNil(mismatch.heldSlot(0))
        // config.projectId is the fallback comparison when the guard is off
        let cfg = AuthHarness(configProjectId: TestJWT.projectA)
        cfg.seedSlot(0, AuthHarness.slot(userId: "g-other", refresh: "rt-o", heldAt: 1, project: TestJWT.projectB))
        cfg.boot()
        XCTAssertEqual((cfg.wait { done in cfg.auth.restoreHeldGuest(completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError?.code, "HELD_GUEST_PROJECT_MISMATCH")
        // a nil slot project is judged on the RESPONSE: mismatch → rotation persisted, claim recorded, nothing installed
        let late = signedOutHarness(expected: TestJWT.projectA)
        late.seedSlot(0, AuthHarness.slot(userId: "g-null", refresh: "rt-n", heldAt: 1, project: nil))
        late.boot()
        late.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse(userId: "g-null", refresh: "rt-n-2", project: .some(TestJWT.projectB)))
        XCTAssertEqual((late.wait { done in late.auth.restoreHeldGuest(completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError?.code, "HELD_GUEST_PROJECT_MISMATCH")
        XCTAssertEqual(late.heldSlot(0)?.refreshToken, "rt-n-2", "the rotation is persisted to the slot")
        XCTAssertEqual(late.heldSlot(0)?.project, TestJWT.projectB, "the claim is recorded")
        XCTAssertEqual(late.auth.status(), .signedOut, "install nothing")
        XCTAssertEqual(late.auth.heldGuests().count, 1, "still counts toward T, excluded from auto-restore")
        late.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "fresh"), refresh: "rt-f"), status: 201))
        _ = late.mint()
        XCTAssertEqual(late.transport.requests(to: "/auth-service/token/refresh").count, 1, "excluded from auto-restore")
    }

    func scenario_restore_over_anonymous_holds_current() {
        let h = anonymousHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        var currentSlotAtRefresh: HeldSlotRecord?
        h.transport.onRequest = { req in if req.path == "/auth-service/token/refresh" { currentSlotAtRefresh = h.heldSlot(1) } }
        h.transport.stub("POST", "/auth-service/token/refresh", heldRefreshResponse())
        guard case .success(let user) = (h.wait { done in h.auth.restoreHeldGuest(id: "g-held", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("restore over anonymous") }
        XCTAssertEqual(user.id, "g-held")
        XCTAssertEqual(currentSlotAtRefresh?.userId, Self.anon.id, "HOLD the current guest (write the slot FIRST), then refreshHeld()")
        XCTAssertEqual(h.auth.heldGuests().map { $0.userId }, [Self.anon.id], "T unchanged: one slot freed, one filled")
        XCTAssertNil(h.heldSlot(0)); XCTAssertEqual(h.heldSlot(1)?.refreshToken, "rt-anon")
        XCTAssertEqual(h.transitionEventNames, ["guest_held", "signed_in", "guest_released"])
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/revoke").count, 0, "a held guest is never revoked")
        // a dead restore rolls the hold back: the guest stays current, no duplicate slot
        let dead = anonymousHarness()
        dead.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        dead.boot()
        dead.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "deleted"))
        XCTAssertEqual((dead.wait { done in dead.auth.restoreHeldGuest(id: "g-held", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError?.code, "HELD_GUEST_GONE")
        XCTAssertEqual(dead.auth.currentUser?.id, Self.anon.id); XCTAssertEqual(dead.auth.heldGuests().count, 0)
    }

    func scenario_discard_held_guest() {
        for (response, released) in [(StubResponse.ok(["userId": "g-held", "status": "purged"]), true), (.failure(status: 404, code: "NOT_FOUND", message: "Guest"), true), (Stub.serverError, false), (.offline, false)] {
            let h = anonymousHarness()
            h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
            h.boot()
            h.transport.stub("POST", "/auth-service/guest/discard", response)
            let result: Result<Void, SendoraCloudAuthError> = h.wait { done in h.auth.discardHeldGuest(completion: done) }
            XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/guest/discard")?.body?["refreshToken"] as? String, "rt-held")
            if released {
                XCTAssertNil(h.heldSlot(0), "status \(response.status): release the slot")
                XCTAssertNil(result.failureError)
                XCTAssertEqual(h.transitionEventNames, ["guest_released"])
                if case .guestReleased(_, let reason, _)? = h.events.last { XCTAssertEqual(reason, .discarded) }
            } else {
                XCTAssertNotNil(h.heldSlot(0), "status \(response.status): the guest is not gone — keep the slot")
                XCTAssertNotNil(result.failureError); XCTAssertEqual(h.transitionEventNames, [])
            }
            XCTAssertEqual(h.auth.currentUser?.id, Self.anon.id, "the current session is untouched")
        }
        let two = signedOutHarness()
        two.seedSlot(0, AuthHarness.slot(userId: "g0", refresh: "rt0", heldAt: 1)); two.seedSlot(1, AuthHarness.slot(userId: "g1", refresh: "rt1", heldAt: 2))
        two.boot()
        XCTAssertEqual((two.wait { done in two.auth.discardHeldGuest(completion: done) } as Result<Void, SendoraCloudAuthError>).failureError?.code, "AMBIGUOUS_HELD_GUEST")
        XCTAssertEqual(two.transport.requestCount, 0)
    }

    func scenario_reset_keeps_held() {
        // An identified account first; a guest below (decision C: the SIGN_OUT half drops a guest's token like an
        // account's — the first rev-3 cut held it).
        let h = identifiedHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "g0", refresh: "rt0", heldAt: 1)); h.seedSlot(1, AuthHarness.slot(userId: "g1", refresh: "rt1", heldAt: 2))
        h.boot()
        h.waitVoid { done in h.auth.resetFromParent(includeHeldGuests: false, completion: done) }
        XCTAssertEqual(h.auth.status(), .signedOut)
        XCTAssertNotNil(h.heldSlot(0)); XCTAssertNotNil(h.heldSlot(1), "reset() KEEPS held slots by default")
        XCTAssertEqual(h.transitionEventNames, ["signed_out"])
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-ident")
        h.waitVoid { done in h.auth.resetFromParent(includeHeldGuests: true, completion: done) }
        XCTAssertNil(h.heldSlot(0)); XCTAssertNil(h.heldSlot(1))
        XCTAssertEqual(h.transitionEventNames, ["signed_out", "guest_released", "guest_released"])
        XCTAssertEqual(h.transport.requests(to: "/auth-service/guest/discard").count, 0, "NO server delete")
        if case .guestReleased(_, let reason, _)? = h.events.last { XCTAssertEqual(reason, .reset) }
        // ⚠ Pin converted (decision C): RESET on a GUEST signs it out like an account (token dropped + revoked, no
        // hold — it used to HOLD it with no revoke); with includeHeldGuests every held AND quarantine slot then goes
        // (local release, no server delete).
        let g = anonymousHarness()
        g.seedSlot(0, AuthHarness.slot(userId: "g0", refresh: "rt0", heldAt: 1))
        g.seedQuarantine(0, userId: "g-q", refresh: "rt-q")
        g.boot()
        g.waitVoid { done in g.auth.resetFromParent(includeHeldGuests: false, completion: done) }
        XCTAssertEqual(g.auth.status(), .signedOut); XCTAssertNil(g.storedRefresh)
        XCTAssertEqual(g.heldSlot(0)?.userId, "g0", "the pre-existing held slot is kept"); XCTAssertNil(g.heldSlot(1), "the guest is NOT held")
        XCTAssertTrue(g.eventually { g.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String == "rt-anon" }, "the guest's token is revoked like an account's")
        XCTAssertEqual(g.transitionEventNames, ["signed_out"])
        XCTAssertNotNil(g.quarantineSlot(0), "reset() keeps the quarantine slots by default")
        g.waitVoid { done in g.auth.resetFromParent(includeHeldGuests: true, completion: done) }
        XCTAssertNil(g.heldSlot(0)); XCTAssertNil(g.quarantineSlot(0))
        XCTAssertEqual(g.transitionEventNames, ["signed_out", "guest_released", "guest_released"])
        XCTAssertEqual(g.transport.requests(to: "/auth-service/guest/discard").count, 0)
        // in withheld: RESET = DISCARD_WITHHELD (+ the parent's queue clear); held survives
        let w = withheldHarness()
        w.seedSlot(0, AuthHarness.slot(userId: "g0", refresh: "rt0", heldAt: 1))
        w.waitVoid { done in w.auth.resetFromParent(includeHeldGuests: false, completion: done) }
        XCTAssertEqual(w.auth.status(), .signedOut); XCTAssertNotNil(w.heldSlot(0))
    }

    func scenario_discard_withheld_precondition_false() {
        let limbo = AuthHarness(); limbo.seedLimbo(refresh: "rt-limbo"); limbo.boot()
        for h in [limbo, signedOutHarness(), anonymousHarness(), identifiedHarness()] {
            let before = h.secure.snapshot()
            let status = h.auth.status()
            XCTAssertFalse(h.wait { done in h.auth.discardWithheld(completion: done) }, "\(status): resolves false outside withheld")
            XCTAssertEqual(h.secure.snapshot(), before, "\(status): nothing mutated")
            XCTAssertEqual(h.auth.status(), status)
            XCTAssertEqual(h.transport.requestCount, 0, "\(status): no network")
        }
    }

    func scenario_claim_identified_only() {
        let limbo = AuthHarness(); limbo.seedLimbo(refresh: "rt-limbo"); limbo.boot()
        for h in [limbo, signedOutHarness(), anonymousHarness()] {
            h.seedSlot(0, AuthHarness.slot(userId: "g0", refresh: "rt0", heldAt: 1))
            h.boot()
            let before = h.secure.snapshot()
            let result: Result<SendoraCloudClaimResult, SendoraCloudAuthError> = h.wait { done in h.auth.claimHeldGuest(completion: done) }
            XCTAssertEqual(result.failureError?.kind, .invalidCredential, "\(h.auth.status()): reject")
            XCTAssertEqual(h.transport.requestCount, 0, "\(h.auth.status()): never reaches /merge, never presents the held token")
            XCTAssertEqual(h.secure.snapshot(), before)
        }
    }

    func scenario_session_verb_pass_through() {
        for h in [anonymousHarness(), identifiedHarness()] {
            let before = h.secure.snapshot()
            h.transport.stub("DELETE", "/auth-service/sessions/me", .ok([:]))
            XCTAssertNil((h.wait { done in h.auth.revokeAllSessions(completion: done) } as Result<Void, SendoraCloudAuthError>).failureError)
            XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/sessions/me")?.headers["Authorization"], "Bearer \(h.auth.accessToken!)", "runs on the current Bearer")
            h.transport.stub("DELETE", "/auth-service/sessions/me", Stub.recentAuthRequired)
            let refused: Result<Void, SendoraCloudAuthError> = h.wait { done in h.auth.revokeAllSessions(completion: done) }
            XCTAssertEqual(refused.failureError?.kind, .recentAuthRequired, "a refusal surfaces through the typed Result")
            XCTAssertEqual(h.secure.snapshot(), before, "NOT a transition: outside commit()")
            XCTAssertEqual(h.transitionEventNames, [])
        }
    }
}
