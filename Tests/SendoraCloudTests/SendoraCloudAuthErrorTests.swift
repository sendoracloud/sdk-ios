import XCTest
@testable import SendoraCloud

/// The 4.13.0 error taxonomy (pure classification) and — since 5.4.0 — the
/// BEHAVIOURAL form of the ordering guarantees that used to be pinned against
/// the source text ("the wipe is glued to the persist"): a failed sign-in cannot
/// destroy the local session, the mint answers from the existing session, the
/// refresh recovers an identity it does not have, and a rate limit is not a
/// dead token. Each drives the real machine on a recording Keychain double.
final class SendoraCloudAuthErrorTests: XCTestCase {

    // MARK: - Taxonomy

    func test_kindRawValuesMatchTheCanonicalWireStrings() {
        XCTAssertEqual(SendoraCloudAuthErrorKind.rateLimited.rawValue, "rate_limited")
        XCTAssertEqual(SendoraCloudAuthErrorKind.invalidCredential.rawValue, "invalid_credential")
        XCTAssertEqual(SendoraCloudAuthErrorKind.accountLocked.rawValue, "account_locked")
        XCTAssertEqual(SendoraCloudAuthErrorKind.credentialInUse.rawValue, "credential_in_use")
        XCTAssertEqual(SendoraCloudAuthErrorKind.alreadyIdentified.rawValue, "already_identified")
        XCTAssertEqual(SendoraCloudAuthErrorKind.network.rawValue, "network")
    }

    func test_classifiesServerCodes() {
        let cases: [(String, Int, SendoraCloudAuthErrorKind, Bool)] = [
            ("RATE_LIMIT_EXCEEDED", 429, .rateLimited, true),
            ("ACCOUNT_LOCKED", 403, .accountLocked, true),
            ("INVALID_CREDENTIALS", 401, .invalidCredential, false),
            ("CREDENTIAL_IN_USE", 409, .credentialInUse, false),
            ("NOT_ANONYMOUS", 409, .alreadyIdentified, false),
            ("GAME_CENTER_UNAVAILABLE", 400, .config, false),
            ("SSO_CANCELLED", 400, .cancelled, false),
            ("PARSE_ERROR", 200, .server, true),
            ("RECENT_AUTH_REQUIRED", 403, .recentAuthRequired, false),
            // ADR-033 §3.5 [2c]: the project-guard refusals reuse kind `config`.
            ("SESSION_WITHHELD", 0, .config, false),
            ("PROJECT_MISMATCH", 0, .config, false),
            ("SOME_FUTURE_CODE", 503, .server, true),
            ("SOME_FUTURE_CODE", 422, .invalidCredential, false),
            ("SOME_FUTURE_CODE", 200, .unknown, false),
        ]
        for (code, status, kind, retryable) in cases {
            let err = SendoraCloudAuthError.rejected(code: code, message: "m", status: status, retryAfterSeconds: nil)
            XCTAssertEqual(err.kind, kind, "\(code)/\(status) → \(kind)")
            XCTAssertEqual(err.retryable, retryable, "\(code)/\(status) → retryable=\(retryable)")
        }
    }

    func test_legacyCasesCarryAKindWithoutChangingTheCase() {
        XCTAssertEqual(SendoraCloudAuthError.network("x").kind, .network)
        XCTAssertTrue(SendoraCloudAuthError.network("x").retryable)
        XCTAssertEqual(SendoraCloudAuthError.unauthorized("x").kind, .invalidCredential)
        XCTAssertEqual(SendoraCloudAuthError.emailAlreadyTaken("x").kind, .credentialInUse)
        XCTAssertEqual(SendoraCloudAuthError.alreadyIdentified("x").kind, .alreadyIdentified)
        XCTAssertEqual(SendoraCloudAuthError.credentialInUse("x").kind, .credentialInUse)
        XCTAssertEqual(SendoraCloudAuthError.unknown("x").kind, .unknown)
        XCTAssertNil(SendoraCloudAuthError.network("x").status)
        XCTAssertNil(SendoraCloudAuthError.network("x").retryAfterSeconds)
    }

    func test_adr033ClientRefusalsCarryCodeAndKind() {
        let info = SendoraCloudWithheldInfo(expectedProjectId: TestJWT.projectA, actualProjectId: TestJWT.projectB, userId: "u", isAnonymous: true)
        let table: [(SendoraCloudAuthError, String, SendoraCloudAuthErrorKind, Bool)] = [
            (.sessionWithheld(info), "SESSION_WITHHELD", .config, false),
            (.projectMismatch(expectedProjectId: TestJWT.projectA, actualProjectId: nil), "PROJECT_MISMATCH", .config, false),
            (.heldGuestLimit(held: 5, limit: 5), "HELD_GUEST_LIMIT", .config, false),
            (.heldGuestProjectMismatch(userId: "g", slotProject: TestJWT.projectB, expectedProjectId: TestJWT.projectA), "HELD_GUEST_PROJECT_MISMATCH", .config, false),
            (.ambiguousHeldGuest(held: 2), "AMBIGUOUS_HELD_GUEST", .config, false),
            (.heldGuestGone(userId: "g", endReason: .deleted), "HELD_GUEST_GONE", .invalidCredential, false),
            (.restoreFailed(userId: "g", endReason: .reuse), "RESTORE_FAILED", .server, true),
            (.credentialChanged("x"), "CREDENTIAL_CHANGED", .invalidCredential, false),
        ]
        for (error, code, kind, retryable) in table {
            XCTAssertEqual(error.code, code); XCTAssertEqual(error.kind, kind, code); XCTAssertEqual(error.retryable, retryable, code)
            XCTAssertFalse(error.message.isEmpty, code)
            XCTAssertEqual((error as Error).localizedDescription, error.message, code)
        }
        XCTAssertNil(SendoraCloudAuthError.network("x").code)
    }

    // MARK: - Coercion at the HTTP boundary

    func test_coercionAlwaysProducesADefinedKind() {
        let timedOut = SendoraCloudAuth.asAuthError(code: "NETWORK_TIMEOUT", message: "timed out", status: 0)
        XCTAssertEqual(timedOut.kind, .network)
        XCTAssertTrue(timedOut.retryable)
        let throttled = SendoraCloudAuth.asAuthError(code: "SOME_FUTURE_CODE", message: "slow down", status: 429, retryAfterSeconds: 30)
        XCTAssertEqual(throttled.kind, .rateLimited)
        XCTAssertEqual(throttled.retryAfterSeconds, 30)
        let downstream = SendoraCloudAuth.asAuthError(code: "SOME_FUTURE_CODE", message: "bad gateway", status: 502)
        XCTAssertEqual(downstream.kind, .server)
    }

    func test_coercionDefaultsToNonFatalUnknown() {
        let err = SendoraCloudAuth.asAuthError(code: "", message: "Auth request failed", status: 0)
        XCTAssertEqual(err.kind, .unknown)
        XCTAssertFalse(err.retryable)
    }

    func test_coercionStillProducesTheDedicatedCases() {
        guard case .emailAlreadyTaken = SendoraCloudAuth.asAuthError(code: "CONFLICT", message: "m", status: 409) else {
            return XCTFail("CONFLICT must stay .emailAlreadyTaken")
        }
        guard case .alreadyIdentified = SendoraCloudAuth.asAuthError(code: "NOT_ANONYMOUS", message: "m", status: 409) else {
            return XCTFail("NOT_ANONYMOUS must stay .alreadyIdentified")
        }
        guard case .credentialInUse = SendoraCloudAuth.asAuthError(code: "CREDENTIAL_IN_USE", message: "m", status: 409) else {
            return XCTFail("CREDENTIAL_IN_USE must stay .credentialInUse")
        }
        guard case .unauthorized = SendoraCloudAuth.asAuthError(code: "UNAUTHORIZED", message: "m", status: 401) else {
            return XCTFail("UNAUTHORIZED must stay .unauthorized")
        }
    }

    func test_typedErrorsKeepTheirMessageOnLocalizedDescription() {
        let err: Error = SendoraCloudAuthError.network("deleteAccount failed (network error)")
        XCTAssertEqual(err.localizedDescription, "deleteAccount failed (network error)")
    }

    func test_rejectedCarriesStatusAndRetryHint() {
        let err = SendoraCloudAuthError.rejected(code: "ACCOUNT_LOCKED", message: "locked", status: 403, retryAfterSeconds: 900)
        XCTAssertEqual(err.status, 403)
        XCTAssertEqual(err.retryAfterSeconds, 900)
        XCTAssertEqual(err.message, "locked")
        XCTAssertNil(SendoraCloudAuthError.rejected(code: "ACCOUNT_LOCKED", message: "l", status: 403, retryAfterSeconds: nil).retryAfterSeconds)
    }

    // MARK: - Behavioural guarantees (formerly source-text pins)

    private static let anon = AuthHarness.anonymousUser()
    private static let anonToken = TestJWT.make(sub: anon.id, sid: "sid-anon", isAnonymous: true)

    private func guestHarness() -> AuthHarness {
        let h = AuthHarness()
        h.seedSession(user: Self.anon, access: Self.anonToken, refresh: "rt-anon")
        h.boot()
        return h
    }

    /// A failed sign-in — wrong password, 5xx, dead radio, mistyped OTP, stale
    /// magic link, dismissed sheet — leaves the Keychain BYTE-IDENTICAL and the
    /// guest current. There is no pre-call wipe to reintroduce (INV-2).
    func test_aFailedSignInLeavesTheCallerExactlyAsFound() {
        let failures: [StubResponse] = [
            .failure(status: 401, code: "INVALID_CREDENTIALS", message: "wrong password"),
            Stub.serverError, .offline, Stub.rateLimited,
            .failure(status: 400, code: "GAME_CENTER_CANCELLED", message: "dismissed"),
        ]
        let paths = ["/auth-service/login", "/auth-service/login/social", "/auth-service/login/game-center", "/auth-service/magic-link/verify", "/auth-service/email-otp/verify", "/auth-service/mfa/challenge"]
        for failure in failures {
            let h = guestHarness()
            for path in paths { h.transport.stub("POST", path, failure) }
            let before = h.secure.snapshot()
            let results: [SendoraCloudAuthError?] = [
                h.signIn().failureError,
                (h.wait { done in h.auth.loginSocial(provider: "google", code: "c", redirectUri: "r", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError,
                (h.wait { done in h.auth.signInWithGameCenter(publicKeyURL: "u", signature: "s", salt: "x", timestamp: 1, teamPlayerID: "T", bundleID: "b", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError,
                (h.wait { done in h.auth.verifyMagicLink(token: "t", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError,
                (h.wait { done in h.auth.verifyEmailOtp(email: "a@b.co", code: "000000", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError,
                (h.wait { done in h.auth.challengeMfa(challengeToken: "ch", code: "000000", completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>).failureError,
            ]
            for r in results { XCTAssertNotNil(r, "status \(failure.status): every path must report the failure") }
            XCTAssertEqual(h.secure.snapshot(), before, "status \(failure.status): byte-identical Keychain")
            XCTAssertEqual(h.auth.status(), .anonymous)
            XCTAssertEqual(h.auth.currentUser?.id, Self.anon.id)
            XCTAssertEqual(h.transitionEventNames, [], "a failed sign-in emits NOTHING")
            XCTAssertEqual(h.auth.heldGuests().count, 0, "nothing was held either")
        }
    }

    /// No sign-in body carries the legacy guest hint (INV-3) — the field that
    /// let a 200 delete this device's guest.
    func test_noSignInBodyCarriesTheGuestHint() {
        let h = guestHarness()
        let response = Stub.session(user: Stub.user(id: "ident", isAnonymous: false), tokens: Stub.tokens(access: TestJWT.make(sub: "ident", sid: "s", isAnonymous: false), refresh: "rt-i"))
        for path in ["/auth-service/login", "/auth-service/login/social", "/auth-service/login/game-center", "/auth-service/magic-link/verify", "/auth-service/email-otp/verify"] {
            h.transport.stub("POST", path, response)
        }
        _ = h.signIn()
        let g2 = guestHarness(); g2.transport.stub("POST", "/auth-service/login/social", response)
        _ = (g2.wait { done in g2.auth.loginSocial(provider: "google", code: "c", redirectUri: "r", onCredentialInUse: .adopt, completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>)
        let g3 = guestHarness(); g3.transport.stub("POST", "/auth-service/login/game-center", response)
        _ = (g3.wait { done in g3.auth.signInWithGameCenter(publicKeyURL: "u", signature: "s", salt: "x", timestamp: 1, teamPlayerID: "T", bundleID: "b", onCredentialInUse: .reject, completion: done) } as Result<SendoraCloudAuthUser, SendoraCloudAuthError>)
        for req in h.transport.requests + g2.transport.requests + g3.transport.requests where req.path.hasPrefix("/auth-service/login") {
            for key in ["prevAnonRefreshToken", "linkAnonymous", "onCredentialInUse"] {
                XCTAssertNil(req.body?[key], "\(req.path) carries \(key)")
            }
        }
        XCTAssertEqual(g3.auth.heldGuests().count, 1, "the guest is HELD, not deleted, whatever the policy")
    }

    /// `signInAnonymously` answers from the session this device already has
    /// before it will mint (the 4.14.0 / 5.3.0 guard, now the `mint.noop_over_session` row).
    func test_anonymousSignInReusesTheExistingSessionBeforeMinting() {
        let h = guestHarness()
        guard case .success(let user) = h.mint() else { return XCTFail("reuse") }
        XCTAssertEqual(user.id, Self.anon.id)
        XCTAssertEqual(h.transport.requests(to: "/auth-service/anonymous").count, 0, "the mint is the fallback, not the default")
        // a cached user alone is NOT a session: without the refresh token the stale blob is cleared and the mint runs
        let blob = AuthHarness()
        blob.seedStaleBlob(user: Self.anon)
        blob.boot()
        blob.transport.stub("POST", "/auth-service/anonymous", Stub.session(user: Stub.user(id: "fresh", isAnonymous: true), tokens: Stub.tokens(access: TestJWT.make(sub: "fresh"), refresh: "rt-f"), status: 201))
        guard case .success(let fresh) = blob.mint() else { return XCTFail("mint") }
        XCTAssertEqual(fresh.id, "fresh")
    }

    /// `init` keeps the refresh token when the cached user blob is unreadable,
    /// and the refresh turns that token back into an identity (gap-fill only — a
    /// rotation over a live user is not a sign-in).
    func test_refreshRecoversAnIdentityItDoesNotHave() {
        let h = AuthHarness()
        h.seedLimbo(refresh: "rt-limbo", access: Self.anonToken)
        h.boot()
        XCTAssertEqual(h.storedRefresh, "rt-limbo", "an unreadable user blob must not cost the refresh token")
        XCTAssertEqual(h.auth.status(), .unknown)
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.session(user: Stub.user(id: Self.anon.id, isAnonymous: true), tokens: Stub.tokens(access: Self.anonToken, refresh: "rt-l2")))
        _ = h.getAccessToken(forceRefresh: true)
        XCTAssertEqual(h.auth.status(), .anonymous)
        XCTAssertEqual(h.transitionEventNames, ["signed_in"], "recovering an identity IS a transition")
        _ = h.getAccessToken(forceRefresh: true)
        XCTAssertEqual(h.transitionEventNames, ["signed_in"], "a rotation with a user already present emits nothing")
        // the route tolerates a missing user row: the rotation is kept, the state stays unknown
        let noUser = AuthHarness()
        noUser.seedLimbo(refresh: "rt-limbo")
        noUser.boot()
        noUser.transport.stub("POST", "/auth-service/token/refresh", .ok(["user": NSNull(), "tokens": Stub.tokens(access: Self.anonToken, refresh: "rt-l3")]))
        XCTAssertNotNil(noUser.getAccessToken())
        XCTAssertEqual(noUser.auth.status(), .unknown)
        XCTAssertEqual(noUser.storedRefresh, "rt-l3")
    }

    /// A 429 is throttling, not a dead token — wiping on it destroyed live sessions.
    func test_rateLimitIsNotADeadRefreshToken() {
        XCTAssertTrue(SendoraCloudAuth.isDeadRefreshError("INVALID_REFRESH_TOKEN"))
        for code in ["RATE_LIMIT", "RATE_LIMIT_EXCEEDED", "UNAUTHORIZED", "HTTP_401", ""] {
            XCTAssertFalse(SendoraCloudAuth.isDeadRefreshError(code), code)
        }
        let h = guestHarness()
        h.transport.stub("POST", "/auth-service/token/refresh", Stub.rateLimited)
        XCTAssertNil(h.getAccessToken(forceRefresh: true))
        XCTAssertEqual(h.auth.status(), .anonymous)
        XCTAssertEqual(h.storedRefresh, "rt-anon")
    }

    /// Every failure the SDK reports has to be classifiable.
    func test_noUntypedErrorEscapesTheAuthSurface() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let dir = root.appendingPathComponent("Sources/SendoraCloud")
        for file in try FileManager.default.contentsOfDirectory(atPath: dir.path) where file.hasPrefix("SendoraCloudAuth") {
            let source = try String(contentsOf: dir.appendingPathComponent(file), encoding: .utf8)
            XCTAssertFalse(source.contains("NSError(domain: \"SendoraCloud\""), "\(file): auth failures must travel as SendoraCloudAuthError, which always has a kind")
        }
    }

    // MARK: - INV-1 source guard: the storage key names live in ONE module

    func test_authStorageKeyNamesAppearOnlyInStorageSwift() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let dir = root.appendingPathComponent("Sources/SendoraCloud")
        let files = try FileManager.default.subpathsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".swift") && !$0.hasSuffix("Internal/Storage.swift") }
        for rel in files {
            let source = try String(contentsOf: dir.appendingPathComponent(rel), encoding: .utf8)
            XCTAssertFalse(source.contains("\"sendora_auth_"), "\(rel): auth Keychain key literals belong in Storage.swift only (INV-1)")
        }
    }
}
