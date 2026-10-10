import XCTest
@testable import SendoraCloud

// ADR-033 INV-11 — one behavioural scenario per fixture row (part 1: HYDRATE,
// MINT, WITHHELD, LINK, SIGN-IN). Each scenario boots a harness in the row's
// `from` state, fires the row's event through the PUBLIC verbs, and asserts the
// state, the events (names + order) and the writes the row prescribes.

extension AuthMachineConformanceTests {
    static let anon = AuthHarness.anonymousUser()
    static let ident = AuthHarness.identifiedUser()
    static func anonToken(project: String?? = .some(TestJWT.projectA)) -> String {
        TestJWT.make(sub: anon.id, sid: "sid-anon", isAnonymous: true, project: project)
    }
    static func identToken(project: String?? = .some(TestJWT.projectA)) -> String {
        TestJWT.make(sub: ident.id, sid: "sid-ident", isAnonymous: false, project: project)
    }
    static let hintKeys = ["prevAnonRefreshToken", "linkAnonymous", "onCredentialInUse"]

    /// A booted harness holding an anonymous session (`rt-anon`).
    func anonymousHarness(expected: String? = nil, configProjectId: String? = nil, autoRestore: Bool = true) -> AuthHarness {
        let h = AuthHarness(expectedProjectId: expected, configProjectId: configProjectId, autoRestoreHeldGuest: autoRestore)
        h.seedSession(user: Self.anon, access: Self.anonToken(), refresh: "rt-anon")
        h.boot()
        XCTAssertEqual(h.auth.status(), .anonymous)
        return h
    }

    /// A booted harness holding an identified session (`rt-ident`).
    func identifiedHarness(expected: String? = nil) -> AuthHarness {
        let h = AuthHarness(expectedProjectId: expected)
        h.seedSession(user: Self.ident, access: Self.identToken(), refresh: "rt-ident")
        h.boot()
        XCTAssertEqual(h.auth.status(), .identified)
        return h
    }

    /// A booted, signed-out harness.
    func signedOutHarness(expected: String? = nil, autoRestore: Bool = true) -> AuthHarness {
        let h = AuthHarness(expectedProjectId: expected, autoRestoreHeldGuest: autoRestore)
        h.boot()
        XCTAssertEqual(h.auth.status(), .signedOut)
        return h
    }

    /// A booted harness withheld at hydrate (token project B, expected A).
    func withheldHarness() -> AuthHarness {
        let h = AuthHarness(expectedProjectId: TestJWT.projectA)
        h.seedSession(user: Self.anon, access: Self.anonToken(project: .some(TestJWT.projectB)), refresh: "rt-withheld")
        h.secure.seed("sendora_user_id", Self.anon.id)
        h.boot()
        XCTAssertEqual(h.auth.status(), .withheld)
        return h
    }

    func identifiedSignInResponse(refresh: String = "rt-b", sid: String = "sid-b") -> StubResponse {
        Stub.session(user: Stub.user(id: Self.ident.id, isAnonymous: false, email: "p@example.com"),
                     tokens: Stub.tokens(access: TestJWT.make(sub: Self.ident.id, sid: sid, isAnonymous: false), refresh: refresh),
                     extra: ["anonRetirement": "none"])
    }

    func assertNoGuestHint(_ body: [String: Any]?, _ label: String) {
        for key in Self.hintKeys { XCTAssertNil(body?[key], "\(label): a 5.4.0 body never carries \(key) (INV-3)") }
    }

    func rowScenarios() -> [String: () -> Void] {
        var map: [String: () -> Void] = [
            "hydrate.coherent_match": scenario_hydrate_coherent_match,
            "hydrate.project_mismatch": scenario_hydrate_project_mismatch,
            "hydrate.gap_fill": scenario_hydrate_gap_fill,
            "hydrate.stale_blob": scenario_hydrate_stale_blob,
            "unknown.queue": scenario_unknown_queue,
            "mint.fresh": scenario_mint_fresh,
            "mint.auto_restore": scenario_mint_auto_restore,
            "mint.cap_no_eligible": scenario_mint_cap_no_eligible,
            "mint.force_new_at_cap": scenario_mint_force_new_at_cap,
            "mint.noop_over_session": scenario_mint_noop_over_session,
            "mint.force_new_holds_guest": scenario_mint_force_new_holds_guest,
            "withheld.reject": scenario_withheld_reject,
            "withheld.recompute": scenario_withheld_recompute,
            "withheld.discard": scenario_withheld_discard,
            "link.upgrade_from_anonymous": scenario_link_upgrade_from_anonymous,
            "link.over_identified": scenario_link_over_identified,
            "link.signed_out_is_sign_in": scenario_link_signed_out_is_sign_in,
            "sign_in.switch": scenario_sign_in_switch,
        ]
        for (k, v) in rowScenariosPart2() { map[k] = v }
        return map
    }

    // MARK: HYDRATE

    func scenario_hydrate_coherent_match() {
        // (a) a 5.3.0 disk: four frozen keys, no record → install + write-forward.
        let legacy = AuthHarness(expectedProjectId: TestJWT.projectA)
        legacy.seedSession(user: Self.anon, access: Self.anonToken(), refresh: "rt-anon", withRecord: false)
        legacy.boot()
        XCTAssertEqual(legacy.auth.status(), .anonymous)
        XCTAssertEqual(legacy.eventNames, ["initial", "signed_in"], "initial once per subscriber (+ the pre-5.4.0 signed_in replay)")
        if case .initial(let status, let user, let withheld)? = legacy.event(at: 0) {
            XCTAssertEqual(status, .anonymous); XCTAssertEqual(user?.id, Self.anon.id); XCTAssertNil(withheld)
        } else { XCTFail("first replayed event must be initial") }
        XCTAssertEqual(legacy.storedSessionRecord?.refreshToken, "rt-anon", "write-forward of auth_session from the four legacy keys")
        XCTAssertEqual(legacy.plain.string(forKey: "sendora_schema_version"), "2")
        XCTAssertTrue(legacy.auth.cronArmed, "arm the proactive cron")
        XCTAssertEqual(legacy.identityChanges, [Self.anon.id])
        legacy.assertSecureWritesWithinAllowList(since: 0)
        // (b) a 5.4.0 disk: record present and equal → no write at all.
        let current = anonymousHarness(expected: TestJWT.projectA)
        XCTAssertEqual(current.secure.writeCount, 0, "a coherent record needs no write-forward")
        XCTAssertTrue(current.auth.cronArmed)
        // (c) downgrade coherence: a 5.3.0 rotated the four keys while the record stayed → the keys win.
        let rotated = AuthHarness()
        rotated.seedSession(user: Self.anon, access: Self.anonToken(), refresh: "rt-stale-record")
        rotated.secure.seed("sendora_auth_refresh_token", "rt-rotated-by-5.3.0")
        rotated.boot()
        XCTAssertEqual(rotated.auth.getRefreshToken(), "rt-rotated-by-5.3.0")
        XCTAssertEqual(rotated.storedSessionRecord?.refreshToken, "rt-rotated-by-5.3.0", "the record is re-forwarded from the keys")
    }

    func scenario_hydrate_project_mismatch() {
        let h = AuthHarness(expectedProjectId: TestJWT.projectA)
        h.seedSession(user: Self.anon, access: Self.anonToken(project: .some(TestJWT.projectB)), refresh: "rt-w")
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.secure.seed("sendora_user_id", Self.anon.id)
        let secureBefore = h.secure.snapshot(), plainBefore = h.plain.snapshot()
        h.boot()
        XCTAssertEqual(h.auth.status(), .withheld)
        XCTAssertEqual(h.secure.snapshot(), secureBefore, "NOTHING on disk — byte-identical")
        XCTAssertEqual(h.plain.snapshot(), plainBefore, "no schema_version bump")
        XCTAssertEqual(h.secure.writeCount, 0); XCTAssertEqual(h.plain.writeCount, 0)
        XCTAssertFalse(h.auth.cronArmed, "no cron")
        XCTAssertEqual(h.withheldHookCalls, 1, "onIdentityWithheld()")
        XCTAssertEqual(h.identityChanges, [])
        XCTAssertEqual(h.eventNames, ["initial"], "initial{withheld} once — never a replayed session_withheld")
        if case .initial(let status, let user, let withheld)? = h.event(at: 0) {
            XCTAssertEqual(status, .withheld); XCTAssertNil(user)
            XCTAssertEqual(withheld?.expectedProjectId, TestJWT.projectA)
            XCTAssertEqual(withheld?.actualProjectId, TestJWT.projectB)
            XCTAssertEqual(withheld?.userId, Self.anon.id)
        } else { XCTFail("initial expected") }
        XCTAssertEqual(h.auth.withheld()?.actualProjectId, TestJWT.projectB)
        XCTAssertNil(h.auth.currentUser); XCTAssertNil(h.auth.accessToken); XCTAssertNil(h.auth.getRefreshToken())
        XCTAssertEqual(h.auth.heldGuests().count, 1, "held slots intact")
        // explicit null claim = mismatch too (§8-Q13)
        let nullClaim = AuthHarness(expectedProjectId: TestJWT.projectA)
        nullClaim.seedSession(user: Self.anon, access: Self.anonToken(project: .some(nil)), refresh: "rt-n")
        nullClaim.boot()
        XCTAssertEqual(nullClaim.auth.status(), .withheld)
    }

    func scenario_hydrate_gap_fill() {
        // LIMBO_A: refresh token, unreadable user blob → unknown, cron armed, no mint.
        let limbo = AuthHarness()
        limbo.seedLimbo(refresh: "rt-limbo")
        limbo.boot()
        XCTAssertEqual(limbo.auth.status(), .unknown)
        XCTAssertTrue(limbo.auth.cronArmed, "arm the cron for the single gap-fill refresh")
        XCTAssertEqual(limbo.eventNames, ["initial"])
        XCTAssertEqual(limbo.transport.requests(to: "/auth-service/anonymous").count, 0, "never a mint")
        XCTAssertEqual(limbo.auth.getRefreshToken(), "rt-limbo", "the refresh token is KEPT — it is the only handle on the account")
        limbo.transport.stub("POST", "/auth-service/token/refresh",
                             Stub.session(user: Stub.user(id: Self.anon.id, isAnonymous: true), tokens: Stub.tokens(access: Self.anonToken(), refresh: "rt-limbo-2")))
        XCTAssertNotNil(limbo.getAccessToken())
        XCTAssertEqual(limbo.auth.status(), .anonymous, "the gap-fill installs the recovered identity")
        XCTAssertEqual(limbo.transitionEventNames, ["signed_in"])
        XCTAssertEqual(limbo.storedRefresh, "rt-limbo-2")
        // Unreadable claim (absent key) under the guard → unknown, re-judged on the refresh.
        let absent = AuthHarness(expectedProjectId: TestJWT.projectA)
        absent.seedSession(user: Self.anon, access: Self.anonToken(project: nil), refresh: "rt-abs")
        absent.boot()
        XCTAssertEqual(absent.auth.status(), .unknown, "absent claim = unknown, NEVER match (INV-15)")
        XCTAssertEqual(absent.secure.writeCount, 0)
        absent.transport.stub("POST", "/auth-service/token/refresh",
                              Stub.session(user: Stub.user(id: Self.anon.id, isAnonymous: true), tokens: Stub.tokens(access: Self.anonToken(project: .some(TestJWT.projectB)), refresh: "rt-abs-2")))
        _ = absent.getAccessToken()
        XCTAssertEqual(absent.auth.status(), .withheld, "the refresh result is re-judged BEFORE install")
        XCTAssertEqual(absent.storedRefresh, "rt-abs-2", "a server-performed rotation is persisted")
    }

    func scenario_hydrate_stale_blob() {
        let h = AuthHarness()
        h.seedStaleBlob(user: Self.anon)
        h.boot()
        XCTAssertEqual(h.auth.status(), .signedOut)
        XCTAssertNil(h.storedUserJson, "the stale blob is cleared")
        XCTAssertEqual(h.eventNames, ["initial"])
        if case .initial(let status, _, _)? = h.event(at: 0) { XCTAssertEqual(status, .signedOut) }
        XCTAssertEqual(h.transport.requestCount, 0)
    }

    func scenario_unknown_queue() {
        // MINT in unknown: queued until the gap-fill answers; /anonymous is never hit when it recovers a session.
        let h = AuthHarness()
        h.seedLimbo(refresh: "rt-limbo")
        h.boot()
        let gate = h.transport.gate("/auth-service/token/refresh")
        h.transport.stub("POST", "/auth-service/token/refresh",
                         Stub.session(user: Stub.user(id: Self.anon.id, isAnonymous: true), tokens: Stub.tokens(access: Self.anonToken(), refresh: "rt-l2")))
        h.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "fresh"), refresh: "rt-fresh"), status: 201))
        let sem = DispatchSemaphore(value: 0)
        var result: Result<SendoraCloudAuthUser, SendoraCloudAuthError>?
        h.auth.signInAnonymously { r in result = r; sem.signal() }
        usleep(150_000)
        XCTAssertNil(result, "MINT is QUEUED while unknown")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/anonymous").count, 0, "never execute the mint in unknown")
        gate.signal()
        XCTAssertEqual(sem.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(try? result?.get().id, Self.anon.id, "the recovered session is the answer")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/anonymous").count, 0)
        // SIGN_IN / LINK / RESTORE queue too: the refresh is on the wire before the verb's request.
        for (label, fire): (String, (AuthHarness, @escaping () -> Void) -> Void) in [
            ("SIGN_IN", { h, done in h.auth.signIn(email: "a@b.co", password: "x") { _ in done() } }),
            ("LINK", { h, done in h.auth.linkEmailPassword(email: "a@b.co", password: "x") { _ in done() } }),
            ("RESTORE", { h, done in h.auth.restoreHeldGuest(id: "g-held") { _ in done() } }),
        ] {
            let q = AuthHarness()
            q.seedLimbo(refresh: "rt-limbo")
            q.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
            q.boot()
            let g = q.transport.gate("/auth-service/token/refresh")
            q.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "revoked"))
            q.transport.stub("POST", "/auth-service/login", identifiedSignInResponse())
            q.transport.stub("POST", "/auth-service/me/link/email", .failure(status: 401, code: "UNAUTHORIZED"))
            let s = DispatchSemaphore(value: 0)
            fire(q) { s.signal() }
            usleep(150_000)
            XCTAssertEqual(q.transport.requestCount, 1, "\(label): only the gap-fill refresh is on the wire while unknown")
            g.signal()
            XCTAssertEqual(s.wait(timeout: .now() + 5), .success, label)
            XCTAssertEqual(q.transport.requests[0].path, "/auth-service/token/refresh", "\(label): the refresh settles the state first")
        }
    }

    // MARK: MINT

    func scenario_mint_fresh() {
        let h = signedOutHarness(expected: TestJWT.projectA)
        h.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: Self.anon.id, isAnonymous: true), tokens: Stub.tokens(access: Self.anonToken(), refresh: "rt-anon"), status: 201))
        let mark = h.secure.writeCount
        guard case .success(let user) = h.mint() else { return XCTFail("mint must succeed") }
        XCTAssertEqual(user.id, Self.anon.id)
        XCTAssertEqual(h.auth.status(), .anonymous)
        let req = h.transport.lastRequest(to: "/auth-service/anonymous")
        assertNoGuestHint(req?.body, "mint")
        let mintKey = req?.body?["mintKey"] as? String
        XCTAssertTrue((mintKey?.count ?? 0) >= 16 && (mintKey?.count ?? 0) <= 128, "B10 mintKey 16–128 chars")
        XCTAssertNil(h.plain.string(forKey: "sendora_auth_mint_key"), "the key is dropped on MINT_OK")
        XCTAssertEqual(h.transitionEventNames, ["signed_in"])
        XCTAssertEqual(h.auth.lastSignedInCause(), .mint)
        // dual-write: the four frozen keys AND the record
        for key in AuthHarness.frozenAuthKeys { XCTAssertNotNil(h.secure.get(key), "\(key) written (a 5.3.0 reads it)") }
        XCTAssertEqual(h.storedSessionRecord?.refreshToken, "rt-anon")
        XCTAssertEqual(h.plain.string(forKey: "sendora_schema_version"), "2")
        XCTAssertTrue(h.auth.cronArmed)
        h.assertSecureWritesWithinAllowList(since: mark)
        // The mint key survives a transient failure and is replayed on the retry.
        let retry = signedOutHarness()
        retry.transport.stub("POST", "/auth-service/anonymous", .offline)
        guard case .failure(let err) = retry.mint() else { return XCTFail("offline") }
        XCTAssertEqual(err.kind, .network)
        let kept = retry.plain.string(forKey: "sendora_auth_mint_key")
        XCTAssertNotNil(kept)
        retry.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "g", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "g"), refresh: "rt-g"), status: 201))
        _ = retry.mint()
        XCTAssertEqual(retry.transport.lastRequest(to: "/auth-service/anonymous")?.body?["mintKey"] as? String, kept, "same key on the retry → same guest")
    }

    func scenario_mint_auto_restore() {
        // newest slot DEAD (deleted) → released, next-newest alive → restored; /anonymous never hit.
        let h = signedOutHarness(expected: TestJWT.projectA)
        h.seedSlot(0, AuthHarness.slot(userId: "g-old", refresh: "rt-old", heldAt: 1_000))
        h.seedSlot(1, AuthHarness.slot(userId: "g-new", refresh: "rt-new", heldAt: 2_000))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh") { req in
            if req.body?["refreshToken"] as? String == "rt-new" { return Stub.refreshDead(endReason: "deleted") }
            return Stub.session(user: Stub.user(id: "g-old", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "g-old", sid: "sid-old"), refresh: "rt-old-2"))
        }
        guard case .success(let user) = h.mint() else { return XCTFail("restore must succeed") }
        XCTAssertEqual(user.id, "g-old")
        XCTAssertEqual(h.auth.status(), .anonymous)
        // The fixture's order (same as restore.held_guest): the dead release, then the
        // install → signed_in{restore}, then guest_released{restored} as the slot goes.
        XCTAssertEqual(h.transitionEventNames, ["guest_released", "signed_in", "guest_released"])
        if case .guestReleased(let id, let reason, let end)? = h.event(at: 1) { XCTAssertEqual(id, "g-new"); XCTAssertEqual(reason, .dead); XCTAssertEqual(end, .deleted) } else { XCTFail("dead release first") }
        if case .signedIn(let u)? = h.event(at: 2) { XCTAssertEqual(u.id, "g-old") } else { XCTFail("signed_in second") }
        if case .guestReleased(let id, let reason, _)? = h.event(at: 3) { XCTAssertEqual(id, "g-old"); XCTAssertEqual(reason, .restored) } else { XCTFail("restored release last") }
        XCTAssertEqual(h.auth.lastSignedInCause(), .restore)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/anonymous").count, 0)
        XCTAssertNil(h.heldSlot(0)); XCTAssertNil(h.heldSlot(1))
        // every slot dead → fall through to mint.fresh IN THE SAME CALL
        let fall = signedOutHarness()
        fall.seedSlot(0, AuthHarness.slot(userId: "g-dead", refresh: "rt-dead", heldAt: 1))
        fall.boot()
        fall.transport.stub("POST", "/auth-service/token/refresh", Stub.refreshDead(endReason: "expired"))
        fall.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "fresh"), refresh: "rt-fresh"), status: 201))
        guard case .success(let fresh) = fall.mint() else { return XCTFail("ensureSession() must never resolve without a session because of a dead slot") }
        XCTAssertEqual(fresh.id, "fresh")
        XCTAssertEqual(fall.transitionEventNames, ["guest_released", "signed_in"])
        // transient error → abort, state untouched
        let transient = signedOutHarness()
        transient.seedSlot(0, AuthHarness.slot(userId: "g", refresh: "rt-g", heldAt: 1))
        transient.boot()
        transient.transport.stub("POST", "/auth-service/token/refresh", Stub.rateLimited)
        guard case .failure(let err) = transient.mint() else { return XCTFail("transient must abort") }
        XCTAssertTrue(err.retryable, "a 429 is transient → retryable, nothing released")
        XCTAssertNotNil(transient.heldSlot(0)); XCTAssertEqual(transient.auth.status(), .signedOut)
        // autoRestoreHeldGuest=false → mint while T < K
        let off = signedOutHarness(autoRestore: false)
        off.seedSlot(0, AuthHarness.slot(userId: "g", refresh: "rt-g", heldAt: 1))
        off.boot()
        off.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "fresh"), refresh: "rt-f"), status: 201))
        _ = off.mint()
        XCTAssertEqual(off.transport.requests(to: "/auth-service/token/refresh").count, 0)
        XCTAssertNotNil(off.heldSlot(0), "the held guest stays held")
    }

    func scenario_mint_cap_no_eligible() {
        let h = AuthHarness()
        for i in 0..<5 { h.seedSlot(i, AuthHarness.slot(userId: "g\(i)", refresh: "rt\(i)", heldAt: Int64(i), autoRestore: false)) }
        h.boot()
        let mark = h.secure.writeCount
        guard case .failure(let err) = h.mint() else { return XCTFail("must throw HeldGuestLimitError") }
        XCTAssertEqual(err.code, "HELD_GUEST_LIMIT"); XCTAssertEqual(err.kind, .config)
        XCTAssertEqual(h.transport.requestCount, 0, "nothing mutated, no network")
        XCTAssertEqual(h.secure.writeCount, mark)
        XCTAssertEqual(h.auth.heldGuests().count, 5)
    }

    func scenario_mint_force_new_at_cap() {
        let h = AuthHarness()
        for i in 0..<4 { h.seedSlot(i, AuthHarness.slot(userId: "g\(i)", refresh: "rt\(i)", heldAt: Int64(i))) }
        h.seedSession(user: Self.anon, access: Self.anonToken(), refresh: "rt-anon")
        h.boot()
        let mark = h.secure.writeCount
        guard case .failure(let err) = h.mint(forceNew: true) else { return XCTFail("T == K: forceNew must throw") }
        XCTAssertEqual(err.code, "HELD_GUEST_LIMIT")
        XCTAssertEqual(h.transport.requestCount, 0); XCTAssertEqual(h.secure.writeCount, mark)
        XCTAssertEqual(h.auth.status(), .anonymous)
        // a plain mint over that guest is the no-op row, not a throw
        guard case .success(let same) = h.mint() else { return XCTFail("plain mint returns the current guest") }
        XCTAssertEqual(same.id, Self.anon.id)
    }

    func scenario_mint_noop_over_session() {
        for h in [anonymousHarness(), identifiedHarness()] {
            let before = h.secure.snapshot()
            guard case .success(let user) = h.mint() else { return XCTFail("no-op must succeed") }
            XCTAssertEqual(user.id, h.auth.currentUser?.id)
            XCTAssertEqual(h.transport.requestCount, 0, "no network — the 1.29 / 5.3.0 guard as ONE row")
            XCTAssertEqual(h.secure.snapshot(), before)
            XCTAssertEqual(h.transitionEventNames, [])
        }
    }

    func scenario_mint_force_new_holds_guest() {
        let h = anonymousHarness()
        var slotAtMintTime: HeldSlotRecord?
        h.transport.onRequest = { req in if req.path == "/auth-service/anonymous" { slotAtMintTime = h.heldSlot(0) } }
        h.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "fresh", sid: "sid-f"), refresh: "rt-fresh"), status: 201))
        let mark = h.secure.writeCount
        guard case .success(let user) = h.mint(forceNew: true) else { return XCTFail("forceNew must mint") }
        XCTAssertEqual(user.id, "fresh")
        XCTAssertEqual(slotAtMintTime?.userId, Self.anon.id, "the slot is written FIRST, then the mint goes out")
        XCTAssertEqual(slotAtMintTime?.refreshToken, "rt-anon")
        XCTAssertEqual(slotAtMintTime?.project, TestJWT.projectA, "the project claim is recorded at HOLD")
        XCTAssertEqual(h.transitionEventNames, ["guest_held", "signed_in"])
        if case .guestHeld(let id, let count)? = h.event(at: 2) { XCTAssertEqual(id, Self.anon.id); XCTAssertEqual(count, 1) }
        XCTAssertEqual(h.auth.lastSignedInCause(), .mint)
        h.assertSecureWritesWithinAllowList(since: mark)
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/guest/held")?.body?["refreshToken"] as? String, "rt-anon", "B15 report after the hold")
        // a failed mint after the hold rolls the hold back — the guest is still current
        let fail = anonymousHarness()
        fail.transport.stub("POST", "/auth-service/anonymous", Stub.serverError)
        guard case .failure = fail.mint(forceNew: true) else { return XCTFail("5xx") }
        XCTAssertNil(fail.heldSlot(0), "no duplicate handle after a failed mint")
        XCTAssertEqual(fail.auth.currentUser?.id, Self.anon.id)
    }

    // MARK: WITHHELD

    func scenario_withheld_reject() {
        let h = withheldHarness()
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        XCTAssertEqual(h.auth.status(), .withheld)
        let mark = h.secure.writeCount
        typealias Verb = (AuthHarness) -> SendoraCloudAuthError?
        let verbs: [(String, Verb)] = [
            ("MINT", { h in h.mint().failureError }),
            ("SIGN_IN", { h in h.signIn().failureError }),
            ("LINK", { h in h.wait { done in h.auth.linkEmailPassword(email: "a@b.co", password: "x", completion: done) }.failureError }),
            ("CLAIM", { h in (h.wait { done in h.auth.claimHeldGuest(completion: done) } as Result<SendoraCloudClaimResult, SendoraCloudAuthError>).failureError }),
            ("RESTORE", { h in h.wait { done in h.auth.restoreHeldGuest(completion: done) }.failureError }),
            ("DISCARD", { h in (h.wait { done in h.auth.discardHeldGuest(completion: done) } as Result<Void, SendoraCloudAuthError>).failureError }),
            ("DELETE", { h in
                let r: Result<SendoraCloudAuth.AccountDeletionResult, Error> = h.wait { done in h.auth.deleteAccount(completion: done) }
                if case .failure(let e) = r { return e as? SendoraCloudAuthError }
                return nil
            }),
            ("SESSION_VERB", { h in (h.wait { done in h.auth.revokeAllSessions(completion: done) } as Result<Void, SendoraCloudAuthError>).failureError }),
        ]
        XCTAssertEqual(verbs.map { $0.0 }, fixture.rejectedInWithheld, "one representative verb per rejected event")
        for (name, verb) in verbs {
            let error = verb(h)
            XCTAssertEqual(error?.code, "SESSION_WITHHELD", "\(name) must reject SESSION_WITHHELD")
            XCTAssertEqual(error?.kind, .config, name)
            XCTAssertEqual(error?.retryable, false, name)
        }
        // signUp must not read the refresh key in withheld
        XCTAssertEqual((h.wait { done in h.auth.signUp(email: "a@b.co", password: "pw", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError?.code, "SESSION_WITHHELD")
        XCTAssertNil(h.getAccessToken(), "access-token getters return nil")
        XCTAssertNil(h.auth.accessToken)
        XCTAssertEqual(h.transport.requestCount, 0, "NO network")
        XCTAssertEqual(h.secure.writeCount, mark, "NO storage write")
        XCTAssertEqual(h.auth.status(), .withheld)
        XCTAssertEqual(h.auth.heldGuests().count, 1)
    }

    func scenario_withheld_recompute() {
        let h = withheldHarness()
        // re-init with the matching key → the hydrate.coherent_match row (nothing was persisted, nothing to migrate)
        h.expectedProjectId = TestJWT.projectB
        h.boot()
        XCTAssertEqual(h.auth.status(), .anonymous)
        XCTAssertEqual(h.auth.currentUser?.id, Self.anon.id)
        // and without the guard at all (rollback)
        h.expectedProjectId = nil
        h.boot()
        XCTAssertEqual(h.auth.status(), .anonymous)
    }

    func scenario_withheld_discard() {
        for viaSignOut in [false, true] {
            let h = withheldHarness()
            h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
            h.plain.seedString("sendora_event_queue_marker", "kept")
            let mark = h.secure.writeCount
            if viaSignOut {
                h.waitVoid { done in h.auth.signOut(completion: done) }
            } else {
                XCTAssertTrue(h.wait { done in h.auth.discardWithheld(completion: done) })
            }
            XCTAssertEqual(h.auth.status(), .signedOut)
            let touched = Set(h.secure.writesSince(mark).map { $0.key })
            XCTAssertEqual(touched, Set(AuthHarness.frozenAuthKeys + [SendoraStorage.authSessionKey]), "clears EXACTLY the session keys")
            XCTAssertNotNil(h.heldSlot(0), "KEEP held slots")
            XCTAssertEqual(h.secure.get("sendora_user_id"), Self.anon.id, "KEEP user_id")
            XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-withheld", "fire-and-forget revoke like signOut()")
            XCTAssertEqual(h.transport.requests(to: "/auth-service/guest/discard").count, 0, "LOCAL ONLY — never a server delete")
            XCTAssertEqual(h.transitionEventNames, ["signed_out"])
            if case .signedOut(let reason)? = h.events.last { XCTAssertEqual(reason, .user) }
            XCTAssertEqual(h.clearEffects.last?.rotateDeviceId, false, "keeps the anonymous analytics id")
            XCTAssertEqual(h.clearEffects.last?.clearQueue, false, "keeps the event queue")
        }
    }

    // MARK: LINK

    func scenario_link_upgrade_from_anonymous() {
        let promoted = Stub.session(user: Stub.user(id: Self.anon.id, isAnonymous: false, email: "p@example.com"),
                                    tokens: Stub.tokens(access: TestJWT.make(sub: Self.anon.id, sid: "sid-anon", isAnonymous: false), refresh: "rt-anon-2"),
                                    extra: ["upgraded": true, "alreadyLinked": false, "linked": ["method": "password"]])
        // link*(): user_updated{link}, never signed_in
        let h = anonymousHarness(expected: TestJWT.projectA)
        h.transport.stub("POST", "/auth-service/me/link/email", promoted)
        guard case .success(let user) = (h.wait { done in h.auth.linkEmailPassword(email: "p@example.com", password: "pw", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("link must succeed") }
        XCTAssertEqual(user.id, Self.anon.id, "same sub")
        XCTAssertEqual(h.auth.status(), .identified)
        let req = h.transport.lastRequest(to: "/auth-service/me/link/email")
        XCTAssertEqual(req?.headers["Authorization"], "Bearer \(Self.anonToken())", "on the current Bearer")
        assertNoGuestHint(req?.body, "link")
        XCTAssertEqual(h.storedRefresh, "rt-anon-2", "the rotated pair is installed")
        XCTAssertEqual(h.transitionEventNames, ["user_updated"], "link*() emits user_updated{link} — NEVER a second signed_in")
        if case .userUpdated(_, let cause)? = h.events.last { XCTAssertEqual(cause, .link) }
        // legacy-signature signUp: ONE signed_in{cause:link}, no user_updated
        let legacy = anonymousHarness()
        legacy.transport.stub("POST", "/auth-service/me/link/email", promoted)
        guard case .success = (legacy.wait { done in legacy.auth.signUp(email: "p@example.com", password: "pw", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("signUp from anonymous = link") }
        XCTAssertEqual(legacy.transport.requests(to: "/auth-service/upgrade").count, 0, "never calls /upgrade")
        XCTAssertEqual(legacy.transitionEventNames, ["signed_in"])
        XCTAssertEqual(legacy.auth.lastSignedInCause(), .link)
        // 409 → typed credential_in_use, nothing mutated
        let collision = anonymousHarness()
        collision.transport.stub("POST", "/auth-service/me/link/email", Stub.credentialInUse(provider: "password", collision: "email"))
        let mark = collision.secure.writeCount
        guard case .success(.credentialInUse(let ctx)) = (collision.wait { done in collision.auth.link(.password(email: "p@example.com", password: "pw"), completion: done) } as Result<SendoraCloudLinkResult, SendoraCloudAuthError>) else { return XCTFail("typed 409") }
        XCTAssertEqual(ctx.provider, "password"); XCTAssertEqual(ctx.collision, .email)
        XCTAssertEqual(collision.secure.writeCount, mark); XCTAssertEqual(collision.auth.status(), .anonymous)
        XCTAssertEqual(collision.transitionEventNames, [])
        // signUp maps the same 409 onto its historical .emailAlreadyTaken
        if case .failure(let err) = (collision.wait { done in collision.auth.signUp(email: "p@example.com", password: "pw", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) {
            guard case .emailAlreadyTaken = err else { return XCTFail("signUp keeps .emailAlreadyTaken") }
        } else { XCTFail("409") }
    }

    func scenario_link_over_identified() {
        let gc = SendoraCloudCredential.gameCenter(publicKeyURL: "https://static.gc.apple.com/k", signature: "c2ln", salt: "c2FsdA", timestamp: 1, teamPlayerID: "T:1", bundleID: "com.x")
        // 200 alreadyLinked → quiet: no event, no write, no revoke
        let h = identifiedHarness()
        h.transport.stub("POST", "/auth-service/me/link/game-center", .ok(["user": Stub.user(id: Self.ident.id, isAnonymous: false, email: "p@example.com"), "linked": ["method": "gamecenter"], "alreadyLinked": true]))
        let mark = h.secure.writeCount
        guard case .success(.done(_, let upgraded, let already)) = (h.wait { done in h.auth.link(gc, completion: done) } as Result<SendoraCloudLinkResult, SendoraCloudAuthError>) else { return XCTFail("quiet 200") }
        XCTAssertTrue(already); XCTAssertFalse(upgraded)
        XCTAssertEqual(h.secure.writeCount, mark); XCTAssertEqual(h.transitionEventNames, [])
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/revoke").count, 0)
        // legacy wrapper with link:true over identified → /me/link/*, never /login
        guard case .success = (h.wait { done in h.auth.signInWithGameCenter(publicKeyURL: "u", signature: "s", salt: "x", timestamp: 1, teamPlayerID: "T:1", bundleID: "b", link: true, completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("alreadyLinked resolves quietly") }
        XCTAssertEqual(h.transport.requests(to: "/auth-service/login/game-center").count, 0, "link never switches (INV-14)")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/me/link/game-center").count, 2)
        // 200 attached → user_updated{link}, no token rotation
        let attach = identifiedHarness()
        attach.transport.stub("POST", "/auth-service/me/link/game-center", .ok(["user": Stub.user(id: Self.ident.id, isAnonymous: false, email: "p@example.com", name: "Priya GC"), "linked": ["method": "gamecenter"], "alreadyLinked": false]))
        guard case .success(.done(let u, let up, let al)) = (attach.wait { done in attach.auth.link(gc, completion: done) } as Result<SendoraCloudLinkResult, SendoraCloudAuthError>) else { return XCTFail("attach") }
        XCTAssertEqual(u.name, "Priya GC"); XCTAssertFalse(up); XCTAssertFalse(al)
        XCTAssertEqual(attach.storedRefresh, "rt-ident", "no token rotation on an identified attach")
        XCTAssertEqual(attach.transitionEventNames, ["user_updated"])
        // 409 → typed, nothing mutated; 403 → typed recent_auth_required, nothing mutated
        let refused = identifiedHarness()
        refused.transport.stub("POST", "/auth-service/me/link/game-center", Stub.credentialInUse(provider: "gamecenter", collision: "identity"))
        guard case .success(.credentialInUse(let ctx)) = (refused.wait { done in refused.auth.link(gc, completion: done) } as Result<SendoraCloudLinkResult, SendoraCloudAuthError>) else { return XCTFail("409") }
        XCTAssertEqual(ctx.collision, .identity)
        refused.transport.stub("POST", "/auth-service/me/link/game-center", Stub.recentAuthRequired)
        guard case .success(.recentAuthRequired) = (refused.wait { done in refused.auth.link(gc, completion: done) } as Result<SendoraCloudLinkResult, SendoraCloudAuthError>) else { return XCTFail("403") }
        guard case .failure(let legacyErr) = (refused.wait { done in refused.auth.linkGameCenter(publicKeyURL: "u", signature: "s", salt: "x", timestamp: 1, teamPlayerID: "T:1", bundleID: "b", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("legacy throws the typed kind") }
        XCTAssertEqual(legacyErr.kind, .recentAuthRequired)
        XCTAssertEqual(refused.auth.status(), .identified); XCTAssertEqual(refused.storedRefresh, "rt-ident")
        XCTAssertEqual(refused.transitionEventNames, [])
    }

    func scenario_link_signed_out_is_sign_in() {
        let h = signedOutHarness()
        h.transport.stub("POST", "/auth-service/login/game-center", identifiedSignInResponse())
        guard case .success = (h.wait { done in h.auth.signInWithGameCenter(publicKeyURL: "u", signature: "s", salt: "x", timestamp: 1, teamPlayerID: "T:1", bundleID: "b", link: true, completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>) else { return XCTFail("plain sign-in") }
        XCTAssertEqual(h.transport.requests(to: "/auth-service/me/link/game-center").count, 0, "nothing to attach to — no Bearer route")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/login/game-center").count, 1)
        XCTAssertEqual(h.auth.status(), .identified)
        XCTAssertEqual(h.transitionEventNames, ["signed_in"])
        guard case .success(.done(_, let upgraded, _)) = (h.wait { done in h.auth.link(.password(email: "p@example.com", password: "pw"), completion: done) } as Result<SendoraCloudLinkResult, SendoraCloudAuthError>) ?? .failure(.unknown("")) else {
            // link() over the now-identified session hits /me/link/email, which is unstubbed → a failure is fine here
            return
        }
        XCTAssertFalse(upgraded)
    }

    // MARK: SIGN-IN / SWITCH

    func scenario_sign_in_switch() {
        // from a guest: body has NO hint; the guest is HELD (slot first); guest_held then ONE signed_in; no signed_out
        let h = anonymousHarness(expected: TestJWT.projectA)
        h.transport.stub("POST", "/auth-service/login", identifiedSignInResponse())
        let mark = h.secure.writeCount
        guard case .success(let user) = h.signIn() else { return XCTFail("sign-in must succeed") }
        XCTAssertEqual(user.id, Self.ident.id)
        let login = h.transport.lastRequest(to: "/auth-service/login")
        assertNoGuestHint(login?.body, "login")
        XCTAssertEqual(h.heldSlot(0)?.userId, Self.anon.id); XCTAssertEqual(h.heldSlot(0)?.refreshToken, "rt-anon")
        XCTAssertEqual(h.heldSlot(0)?.tokenAtHold, "rt-anon"); XCTAssertEqual(h.heldSlot(0)?.project, TestJWT.projectA)
        XCTAssertEqual(h.transitionEventNames, ["guest_held", "signed_in"], "no signed_out on replace")
        XCTAssertEqual(h.auth.lastSignedInCause(), .signIn)
        XCTAssertEqual(h.storedRefresh, "rt-b"); XCTAssertEqual(h.auth.status(), .identified)
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/guest/held")?.body?["refreshToken"] as? String, "rt-anon", "B15 report after the HoldTx")
        XCTAssertEqual(h.storedSessionRecord?.heldReportPending ?? [], [], "acknowledged report cleared")
        h.assertSecureWritesWithinAllowList(since: mark)
        // the write order: the slot is set BEFORE the new session keys
        let writes = h.secure.writesSince(mark)
        // No force-unwrap: a missing write is a FAILURE here, not a crash that
        // would abort every scenario after this one (seen under mutations M05/M08).
        if let slotIdx = writes.firstIndex(where: { $0.key == SendoraStorage.heldSlotKeys[0] }),
           let refreshIdx = writes.firstIndex(where: { $0.key == "sendora_auth_refresh_token" }) {
            XCTAssertLessThan(slotIdx, refreshIdx, "HOLD writes the slot first")
        } else {
            XCTFail("HOLD must write slot 0 and the new refresh token")
        }
        // typed result: previous.held
        let typed = anonymousHarness()
        typed.transport.stub("POST", "/auth-service/login", identifiedSignInResponse())
        guard case .success(.done(_, let previous, _)) = (typed.wait { done in typed.auth.signIn(with: .password(email: "p@example.com", password: "pw"), completion: done) } as Result<SendoraCloudSignInResult, SendoraCloudAuthError>) else { return XCTFail("typed") }
        XCTAssertEqual(previous?.userId, Self.anon.id); XCTAssertEqual(previous?.held, true); XCTAssertEqual(previous?.isAnonymous, true)
        // from identified with a different sub: revoke the previous refresh, nothing held
        let ident = identifiedHarness()
        ident.transport.stub("POST", "/auth-service/login", Stub.session(user: Stub.user(id: "other", isAnonymous: false, email: "o@example.com"), tokens: Stub.tokens(access: TestJWT.make(sub: "other", sid: "sid-o", isAnonymous: false), refresh: "rt-o")))
        guard case .success = ident.signIn() else { return XCTFail("switch") }
        XCTAssertEqual(ident.transport.lastRequest(to: "/auth-service/token/revoke")?.body?["refreshToken"] as? String, "rt-ident", "Q12 hygiene")
        XCTAssertEqual(ident.auth.heldGuests().count, 0)
        XCTAssertEqual(ident.transitionEventNames, ["signed_in"])
        // a failed sign-in leaves the caller exactly as found
        let fail = anonymousHarness()
        fail.transport.stub("POST", "/auth-service/login", .failure(status: 401, code: "INVALID_CREDENTIALS", message: "bad password"))
        let before = fail.secure.snapshot()
        guard case .failure(let err) = fail.signIn() else { return XCTFail("401") }
        XCTAssertEqual(err.kind, .invalidCredential)
        XCTAssertEqual(fail.secure.snapshot(), before); XCTAssertEqual(fail.auth.status(), .anonymous); XCTAssertEqual(fail.transitionEventNames, [])
        // mfaRequired → state unchanged
        let mfa = anonymousHarness()
        mfa.transport.stub("POST", "/auth-service/login", .ok(["user": Stub.user(id: Self.ident.id, isAnonymous: false), "mfaRequired": true, "mfaChallengeToken": "ch-1"]))
        guard case .success(.mfaRequired(let challenge)) = (mfa.wait { done in mfa.auth.signIn(with: .password(email: "p@example.com", password: "pw"), completion: done) } as Result<SendoraCloudSignInResult, SendoraCloudAuthError>) else { return XCTFail("mfa") }
        XCTAssertEqual(challenge.challengeToken, "ch-1"); XCTAssertEqual(mfa.auth.status(), .anonymous)
        mfa.transport.stub("POST", "/auth-service/mfa/challenge", identifiedSignInResponse())
        guard case .success(.done) = (mfa.wait { done in challenge.verify(code: "123456", completion: done) } as Result<SendoraCloudSignInResult, SendoraCloudAuthError>) else { return XCTFail("verify") }
        XCTAssertEqual(mfa.transport.lastRequest(to: "/auth-service/mfa/challenge")?.body?["challengeToken"] as? String, "ch-1")
        XCTAssertEqual(mfa.auth.status(), .identified); XCTAssertEqual(mfa.auth.heldGuests().count, 1)
        // INTERLEAVING: a refresh rotates during the native sheet → the hold carries the POST-refresh token
        let race = anonymousHarness()
        let gate = race.transport.gate("/auth-service/token/refresh")
        race.transport.stub("POST", "/auth-service/token/refresh", Stub.session(user: Stub.user(id: Self.anon.id, isAnonymous: true), tokens: Stub.tokens(access: Self.anonToken(), refresh: "rt-anon-rotated")))
        race.transport.stub("POST", "/auth-service/login", identifiedSignInResponse())
        race.auth.getAccessToken(forceRefresh: true) { _ in }
        usleep(100_000)
        let sem = DispatchSemaphore(value: 0)
        race.auth.signIn(email: "p@example.com", password: "pw") { _ in sem.signal() }
        usleep(150_000)
        XCTAssertEqual(race.transport.requests(to: "/auth-service/login").count, 0, "the attempt AWAITS the in-flight refresh")
        gate.signal()
        XCTAssertEqual(sem.wait(timeout: .now() + 5), .success)
        XCTAssertEqual(race.heldSlot(0)?.refreshToken, "rt-anon-rotated", "held with its post-refresh tokens")
        XCTAssertEqual(race.heldSlot(0)?.tokenAtHold, "rt-anon-rotated")
        // switchAccount() is bound to the refused credential (same payload < 5 min)
        let adopt = anonymousHarness()
        let gc = SendoraCloudCredential.gameCenter(publicKeyURL: "u", signature: "s", salt: "x", timestamp: 1, teamPlayerID: "T:1", bundleID: "b")
        adopt.transport.stub("POST", "/auth-service/me/link/game-center", Stub.credentialInUse(provider: "gamecenter", collision: "identity"))
        adopt.transport.stub("POST", "/auth-service/login/game-center", identifiedSignInResponse())
        guard case .success(.credentialInUse(let ctx)) = (adopt.wait { done in adopt.auth.link(gc, completion: done) } as Result<SendoraCloudLinkResult, SendoraCloudAuthError>) else { return XCTFail("409") }
        guard case .success(.done(_, let prev, _)) = (adopt.wait { done in ctx.switchAccount(completion: done) } as Result<SendoraCloudSignInResult, SendoraCloudAuthError>) else { return XCTFail("switch") }
        XCTAssertEqual(prev?.held, true)
        XCTAssertEqual(adopt.transport.lastRequest(to: "/auth-service/login/game-center")?.body?["teamPlayerId"] as? String, "T:1", "same payload")
        // a stale payload re-fetched with a DIFFERENT teamPlayerId aborts credential_changed
        let stale = SendoraCloudCredentialInUse(provider: "gamecenter", collision: .identity, message: "m", credential: gc, boundAt: Date(timeIntervalSinceNow: -600)) { _, cb in cb(.failure(.unknown("must not be called"))) }
        let changed: Result<SendoraCloudSignInResult, SendoraCloudAuthError> = adopt.wait { done in
            stale.switchAccount(refetch: { give in give(.gameCenter(publicKeyURL: "u", signature: "s2", salt: "x", timestamp: 2, teamPlayerID: "T:OTHER", bundleID: "b")) }, completion: done)
        }
        XCTAssertEqual(changed.failureError?.code, "CREDENTIAL_CHANGED")
    }
}

extension Result where Failure == SendoraCloudAuthError {
    var failureError: SendoraCloudAuthError? {
        if case .failure(let e) = self { return e }
        return nil
    }
}
