import XCTest
@testable import SendoraCloud

/// Covers the two halves of 4.13.0 that are checkable without a device: the
/// error taxonomy (pure classification) and the ordering guarantee that a
/// failed sign-in cannot destroy the local session (pinned against the source,
/// since the ordering is what the customer incident turned on).
final class SendoraCloudAuthErrorTests: XCTestCase {

    // MARK: - Taxonomy

    func test_kindRawValuesMatchTheCanonicalWireStrings() {
        // Shared across all 4 SDKs (@sendora/shared `AuthErrorKind`) — an app
        // logging `kind.rawValue` gets the same token on every platform.
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
            // Codes this SDK has never heard of still classify from the status
            // rather than defaulting to "retry me".
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
        // No status / retry hint exists for a request that never got a response.
        XCTAssertNil(SendoraCloudAuthError.network("x").status)
        XCTAssertNil(SendoraCloudAuthError.network("x").retryAfterSeconds)
    }

    // MARK: - Coercion at the HTTP boundary

    /// Everything the SDK did not construct itself passes through
    /// `asAuthError`, so `kind` is defined on every rejection a caller sees —
    /// including the transport ones, which is the case an offline-first app
    /// most needs to tell apart from a real refusal.
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

    /// The default has to stay non-fatal: an unmapped failure with nothing to
    /// classify from is `.unknown` and NOT retryable — never a verdict on the
    /// session. It is what keeps the one-code dead-refresh allow-list safe
    /// rather than lucky.
    func test_coercionDefaultsToNonFatalUnknown() {
        let err = SendoraCloudAuth.asAuthError(code: "", message: "Auth request failed", status: 0)
        XCTAssertEqual(err.kind, .unknown)
        XCTAssertFalse(err.retryable)
    }

    /// Coercion must not swallow the cases shipped apps match with `case`.
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

    /// `deleteAccount` hands its failure back as a bare `Error`. The message
    /// has to survive that erasure — it used to ride an NSError's
    /// `NSLocalizedDescriptionKey`.
    func test_typedErrorsKeepTheirMessageOnLocalizedDescription() {
        let err: Error = SendoraCloudAuthError.network("deleteAccount failed (network error)")
        XCTAssertEqual(err.localizedDescription, "deleteAccount failed (network error)")
    }

    func test_rejectedCarriesStatusAndRetryHint() {
        let err = SendoraCloudAuthError.rejected(code: "ACCOUNT_LOCKED", message: "locked", status: 403, retryAfterSeconds: 900)
        XCTAssertEqual(err.status, 403)
        XCTAssertEqual(err.retryAfterSeconds, 900)
        XCTAssertEqual(err.message, "locked")
        // An ACCOUNT_LOCKED with NO hint is the permanent lock — still the same
        // kind, but the app has nothing to count down.
        XCTAssertNil(SendoraCloudAuthError.rejected(code: "ACCOUNT_LOCKED", message: "l", status: 403, retryAfterSeconds: nil).retryAfterSeconds)
    }

    // MARK: - Wipe-after-validate ordering (source-pinned)

    private func authSource() throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // SendoraCloudTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // package root
        return try String(contentsOf: root.appendingPathComponent("Sources/SendoraCloud/SendoraCloudAuth.swift"), encoding: .utf8)
    }

    /// Every identity-replacing sign-in must hand the wipe to `callAuthSync`,
    /// which only runs it from the success branch. A wipe placed in the method
    /// body again would sit BEFORE the network call — the regression that lost a
    /// production account.
    func test_signInPathsDelegateTheWipeToTheSuccessBranch() throws {
        let source = try authSource()
        let delegated = source.components(separatedBy: "replacesIdentity: true").count - 1
        XCTAssertEqual(delegated, 5, "login, social, game-center, magic-link, email-otp")
        let code = source.components(separatedBy: "\n")
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
        XCTAssertFalse(code.contains { $0.contains("wipeLocalIdentity()") },
                       "every wipe must state its reason; a bare call is the pre-call-wipe shape")
    }

    /// The wipe is glued to the persist that follows it: it may only ever run
    /// with a validated session already in hand.
    func test_replacementWipeIsAlwaysImmediatelyFollowedByPersist() throws {
        let lines = try authSource().components(separatedBy: "\n")
        var callSites = 0
        for (i, line) in lines.enumerated() where line.contains("wipeReplacedIdentityIfPresent()") && !line.contains("func ") {
            let next = lines[(i + 1)..<min(i + 3, lines.count)].joined(separator: "\n")
            XCTAssertTrue(next.contains("persist(user:"), "line \(i + 1) wipes without an immediate persist")
            callSites += 1
        }
        XCTAssertEqual(callSites, 3, "callAuthSync + signInWithMfaSupport + challengeMfa")
    }

    /// `signInAnonymously` must answer from the session this device already has
    /// before it will mint. Minting unconditionally overwrites the stored
    /// refresh token — the previous anonymous account's only durable handle —
    /// on a perfectly healthy network, which is the same permanent loss the
    /// wipe-after-validate ordering above exists to prevent.
    func test_anonymousSignInReusesTheExistingSessionBeforeMinting() throws {
        let source = try authSource()
        guard let start = source.range(of: "public func signInAnonymously("),
              let end = source.range(of: "public func signUp(") else {
            return XCTFail("signInAnonymously not found")
        }
        let method = String(source[start.lowerBound..<end.lowerBound])
        // Opt-in, defaulted to reuse — an existing caller keeps its behaviour
        // only if the default is the SAFE one.
        XCTAssertTrue(method.contains("forceNew: Bool = false"))
        // A cached user alone is not a session: without the refresh token the
        // account is already unreachable, so that arm has to mint.
        XCTAssertTrue(method.contains("storage.authRefreshToken != nil"))
        guard let reuse = method.range(of: "completion(.success(user))"),
              let mint = method.range(of: "callAuthSync(") else {
            return XCTFail("expected a reuse arm and a mint arm")
        }
        XCTAssertTrue(reuse.lowerBound < mint.lowerBound, "the mint must be the fallback, not the default")
    }

    /// Every failure the SDK reports has to be classifiable. An NSError carries
    /// no `kind`, so it left `deleteAccount` callers unable to tell a stalled
    /// radio from a server refusal on a one-shot destructive call.
    func test_noUntypedErrorEscapesTheAuthSurface() throws {
        let source = try authSource()
        XCTAssertFalse(source.contains("NSError(domain: \"SendoraCloud\""),
                       "auth failures must travel as SendoraCloudAuthError, which always has a kind")
    }

    /// `init` keeps the refresh token when the cached user blob is unreadable,
    /// and the refresh must be able to turn that token back into an identity —
    /// otherwise keeping it buys nothing: the session sits live with a nil
    /// `cachedUser` and the next sign-in orphans the account anyway. The adoption
    /// is gap-fill ONLY; a rotation over a live user is not a sign-in.
    func test_refreshRecoversAnIdentityItDoesNotHave() throws {
        let source = try authSource()
        guard let start = source.range(of: "private func refreshAccessToken("),
              let end = source.range(of: "// MARK: - Proactive refresh") else {
            return XCTFail("refreshAccessToken not found")
        }
        let method = String(source[start.lowerBound..<end.lowerBound])
        // Reuses the shared parser, so an absent / null / id-less `data.user`
        // (the route tolerates a missing user row) is never adopted.
        XCTAssertTrue(method.contains("parseSuccess(response)"))
        guard let gate = method.range(of: "return self.cachedUser != nil"),
              let adopt = method.range(of: "persist(user:") else {
            return XCTFail("expected the adoption to be gated on having no user")
        }
        XCTAssertTrue(gate.lowerBound < adopt.lowerBound,
                      "a refresh that overwrote a live user would report a rotation as a sign-in")
        XCTAssertEqual(method.components(separatedBy: "persist(user:").count - 1, 1,
                       "the gap-fill is the only persist on the refresh path")
        // The corrupt-cache guard that makes the recovery reachable.
        guard let initStart = source.range(of: "// Re-hydrate session from Keychain."),
              let initEnd = source.range(of: "self.hydrated = true") else {
            return XCTFail("hydrate guard not found")
        }
        let hydrate = String(source[initStart.lowerBound..<initEnd.lowerBound])
        XCTAssertFalse(hydrate.contains("clearAuthTokens()"),
                       "an unreadable user blob must not cost the refresh token")
    }

    /// A 429 is throttling, not a dead token — wiping on it destroyed live
    /// sessions (including anonymous ones, whose refresh token is their only
    /// durable handle).
    func test_rateLimitIsNotADeadRefreshToken() throws {
        let source = try authSource()
        guard let range = source.range(of: "private static func isDeadRefreshError") else {
            return XCTFail("isDeadRefreshError not found")
        }
        let body = String(source[range.lowerBound...].prefix(400))
        XCTAssertTrue(body.contains("INVALID_REFRESH_TOKEN"))
        XCTAssertFalse(body.contains("RATE_LIMIT"), "a rate limit says nothing about token validity")
    }
}
