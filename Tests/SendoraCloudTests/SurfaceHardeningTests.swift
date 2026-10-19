import XCTest
@testable import SendoraCloud

/// 5.6.0 (audit F67 follow-through) — what the SDK surfaces send now that the backend can prove things:
/// a Cloudflare challenge on an auth call, the password sign-in's `knownDeviceToken`, the push token's
/// Bearer, the link's `revokeToken`, and the support badge on the SDK's own client.
final class SurfaceHardeningTests: XCTestCase {
    private static let anon = AuthHarness.anonymousUser()
    private static let anonToken = TestJWT.make(sub: anon.id, sid: "sid-anon", isAnonymous: true)
    private static let account = AuthHarness.identifiedUser()

    private func guestHarness() -> AuthHarness {
        let h = AuthHarness()
        h.seedSession(user: Self.anon, access: Self.anonToken, refresh: "rt-anon")
        h.boot()
        return h
    }

    private func accountSession(kdt: String?, sid: String = "sid-acct") -> StubResponse {
        let tokens = Stub.tokens(access: TestJWT.make(sub: Self.account.id, sid: sid, isAnonymous: false), refresh: "rt-\(sid)")
        return Stub.session(user: Stub.user(from: Self.account), tokens: tokens, extra: kdt.map { ["knownDeviceToken": $0] } ?? [:])
    }

    private static let cfChallenge = StubResponse(status: 403, json: nil, headers: ["cf-mitigated": "challenge", "Content-Type": "text/html"],
                                                  rawBody: Data("<html>Just a moment...</html>".utf8))

    // MARK: - A Cloudflare challenge on an auth call is never a dead credential

    func test_challengeOnRefresh_keepsTheSession_evenWhenItsBodyNamesADeadCode() {
        let h = guestHarness()
        h.transport.stub("POST", "/auth-service/token/refresh",
                         StubResponse.failure(status: 403, code: "INVALID_REFRESH_TOKEN").with(headers: ["cf-mitigated": "challenge"]))
        _ = h.getAccessToken(forceRefresh: true)
        XCTAssertEqual(h.auth.status(), .anonymous, "a challenge ended the session")
        XCTAssertEqual(h.storedRefresh, "rt-anon")
        XCTAssertFalse(h.transitionEventNames.contains("signed_out"))

        // Control: the same answer from the API itself IS a dead session (the test discriminates).
        let c = guestHarness()
        c.transport.stub("POST", "/auth-service/token/refresh", StubResponse.failure(status: 403, code: "INVALID_REFRESH_TOKEN"))
        _ = c.getAccessToken(forceRefresh: true)
        XCTAssertEqual(c.auth.status(), .signedOut)
    }

    func test_challengeOnSignIn_isARetryableNetworkFailure_andChangesNothing() {
        let h = guestHarness()
        h.transport.stub("POST", "/auth-service/login", Self.cfChallenge)
        let before = h.secureSnapshot
        guard case .failure(let err) = h.signIn() else { return XCTFail("a challenge signed in") }
        XCTAssertEqual(err.kind, .network, "a challenge read as \(err.kind) — never a wrong credential")
        XCTAssertTrue(err.retryable)
        XCTAssertEqual(h.secureSnapshot, before)
        XCTAssertEqual(h.auth.status(), .anonymous)
    }

    // MARK: - knownDeviceToken

    func test_knownDeviceToken_savedFromLogin_sentOnTheNextLoginForThatAddress_survivesSignOut() {
        let h = guestHarness()
        let mark = h.secure.writeCount
        h.transport.stub("POST", "/auth-service/login", accountSession(kdt: "kdt1.A"))
        guard case .success = h.signIn(email: "p@example.com") else { return XCTFail("sign-in failed") }
        XCTAssertNil(h.transport.lastRequest(to: "/auth-service/login")?.body?["knownDeviceToken"], "nothing to send on the first sign-in")

        h.waitVoid { done in h.auth.signOut(completion: done) }
        h.transport.stub("POST", "/auth-service/login", accountSession(kdt: "kdt1.B", sid: "sid-2"))
        _ = h.signIn(email: "  P@Example.COM ")
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/login")?.body?["knownDeviceToken"] as? String, "kdt1.A",
                       "the token must survive signOut and match the address case-insensitively")

        h.waitVoid { done in h.auth.signOut(completion: done) }
        _ = h.signIn(email: "p@example.com")
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/login")?.body?["knownDeviceToken"] as? String, "kdt1.B", "the newest token replaces the old one")

        h.waitVoid { done in h.auth.signOut(completion: done) }
        h.transport.stub("POST", "/auth-service/login", StubResponse.failure(status: 401, code: "INVALID_CREDENTIALS"))
        _ = h.signIn(email: "someone-else@example.com")
        XCTAssertNil(h.transport.lastRequest(to: "/auth-service/login")?.body?["knownDeviceToken"], "another address's token was sent")

        h.assertSecureWritesWithinAllowList(since: mark)
        let stored = h.secure.get(SendoraStorage.knownDevicesKey) ?? ""
        XCTAssertFalse(stored.lowercased().contains("example.com"), "an email address is stored at rest")
        XCTAssertTrue(stored.contains("kdt1.B"))
    }

    func test_knownDeviceToken_fromMfaChallenge_isFiledUnderTheLoginsAddress() {
        let h = guestHarness()
        h.transport.stub("POST", "/auth-service/login", .ok(["mfaRequired": true, "mfaChallengeToken": "ct-1", "user": ["id": Self.account.id]]))
        let outcome: Result<SendoraCloudAuth.SignInOutcome, SendoraCloudAuthError> = h.wait { done in
            h.auth.signInWithMfaSupport(email: "mfa@example.com", password: "pw", completion: done)
        }
        guard case .success(.mfaRequired(let ct, _)) = outcome else { return XCTFail("expected an MFA challenge") }
        var account = Stub.user(from: Self.account)
        account["email"] = "other-on-file@example.com" // the pending /login's address wins over the user row
        h.transport.stub("POST", "/auth-service/mfa/challenge",
                         Stub.session(user: account, tokens: Stub.tokens(access: TestJWT.make(sub: Self.account.id, sid: "sid-m", isAnonymous: false), refresh: "rt-m"),
                                      extra: ["knownDeviceToken": "kdt1.M"]))
        let done: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { d in h.auth.challengeMfa(challengeToken: ct, code: "123456", completion: d) }
        guard case .success = done else { return XCTFail("challenge failed") }

        h.waitVoid { d in h.auth.signOut(completion: d) }
        h.transport.stub("POST", "/auth-service/login", accountSession(kdt: nil, sid: "sid-3"))
        _ = h.signIn(email: "MFA@example.com")
        XCTAssertEqual(h.transport.lastRequest(to: "/auth-service/login")?.body?["knownDeviceToken"] as? String, "kdt1.M")
    }

    func test_knownDeviceToken_survivesTheResetRow_deleteAccountRemovesOnlyThatAccount() {
        let h = guestHarness()
        h.storage.setKnownDeviceToken("kdt1.OTHER", forEmail: "sibling@example.com", atMs: 1)
        h.transport.stub("POST", "/auth-service/login", accountSession(kdt: "kdt1.A"))
        _ = h.signIn()
        h.waitVoid { done in h.auth.resetFromParent(includeHeldGuests: false, completion: done) }
        XCTAssertEqual(h.storage.knownDeviceToken(forEmail: "p@example.com"), "kdt1.A", "the RESET row must keep it (all four SDKs)")

        _ = h.signIn()
        h.transport.stub("DELETE", "/auth-service/me", .ok(["status": "purged", "graceDays": 0]))
        let deleted: Result<SendoraCloudAuth.AccountDeletionResult, Error> = h.wait { d in h.auth.deleteAccount(completion: d) }
        guard case .success = deleted else { return XCTFail("deleteAccount failed") }
        XCTAssertNil(h.storage.knownDeviceToken(forEmail: "p@example.com"), "the deleted account's token survived")
        XCTAssertEqual(h.storage.knownDeviceToken(forEmail: "sibling@example.com"), "kdt1.OTHER", "another account's token was removed")
    }

    func test_knownDeviceStore_keepsTheNewestTwenty_andRefusesOversizeTokens() {
        let storage = SendoraStorage(secure: RecordingSecureStore(), plain: RecordingPlainStore())
        for i in 0..<25 { storage.setKnownDeviceToken("kdt1.\(i)", forEmail: "u\(i)@example.com", atMs: Int64(i)) }
        for i in 0..<5 { XCTAssertNil(storage.knownDeviceToken(forEmail: "u\(i)@example.com"), "oldest \(i) kept") }
        for i in 5..<25 { XCTAssertEqual(storage.knownDeviceToken(forEmail: "u\(i)@example.com"), "kdt1.\(i)") }
        storage.setKnownDeviceToken(String(repeating: "x", count: 2049), forEmail: "big@example.com", atMs: 99)
        XCTAssertNil(storage.knownDeviceToken(forEmail: "big@example.com"))
    }

    // MARK: - Push: the player's own Bearer proves the device

    @MainActor
    func test_pushTokenCarriesTheBearerWhenSignedIn_andStillRegistersWithout() async {
        for token in ["at-player", nil] as [String?] {
            let transport = StubTransport()
            transport.stub("POST", "/push/tokens", .ok(["tokenId": "pt-1"]))
            let client = APIClient(baseUrl: "https://api.test", apiKey: "pk_dev_test", transport: transport)
            let push = SendoraCloudPush(client: client, accessTokenProvider: { done in done(token) })
            let exp = expectation(description: "registered")
            var result: Result<String, SendoraCloudPushError>?
            push.registerToken("abcd", userId: "u-1") { result = $0; exp.fulfill() }
            await fulfillment(of: [exp], timeout: 5)
            guard case .success("pt-1") = result else { return XCTFail("registration failed (token=\(token ?? "nil"))") }
            let req = transport.lastRequest(to: "/push/tokens")
            XCTAssertEqual(req?.headers["Authorization"], token.map { "Bearer \($0)" })
            XCTAssertEqual(req?.headers["X-API-Key"], "pk_dev_test")
        }
    }

    @MainActor
    func test_pushRegistrationDoesNotWaitForeverForTheToken() async {
        let transport = StubTransport()
        transport.stub("POST", "/push/tokens", .ok(["tokenId": "pt-2"]))
        let client = APIClient(baseUrl: "https://api.test", apiKey: "pk_dev_test", transport: transport)
        // A token lookup that never answers (a refresh stuck on a bad network).
        let push = SendoraCloudPush(client: client, accessTokenProvider: { _ in }, tokenTimeout: 0.2)
        let exp = expectation(description: "registered")
        push.registerToken("abcd") { _ in exp.fulfill() }
        await fulfillment(of: [exp], timeout: 3)
        XCTAssertNil(transport.lastRequest(to: "/push/tokens")?.headers["Authorization"])
        XCTAssertEqual(transport.requests(to: "/push/tokens").count, 1)
    }

    // MARK: - Links: the mint's revokeToken makes a revoke final

    private func linkClient() -> (SendoraCloudLinks, StubTransport, SendoraStorage) {
        let transport = StubTransport()
        let client = APIClient(baseUrl: "https://api.test", apiKey: "pk_dev_test", transport: transport)
        let storage = SendoraStorage(secure: RecordingSecureStore(), plain: RecordingPlainStore())
        return (SendoraCloudLinks(apiClient: client, bundleId: nil, linkHosts: [], storage: storage), transport, storage)
    }

    private func create(_ links: SendoraCloudLinks) -> SendoraCloudLinks.LinkCreateResult? {
        let sem = DispatchSemaphore(value: 0)
        var out: SendoraCloudLinks.LinkCreateResult?
        links.create(.init(title: "t")) { if case .success(let r) = $0 { out = r }; sem.signal() }
        _ = sem.wait(timeout: .now() + 5)
        return out
    }

    func test_revokeTokenIsKept_sentByTheOldRevoke_finalExposed_andForgottenOnSuccess() {
        let (links, transport, storage) = linkClient()
        transport.stub("POST", "/sdk/links", .ok(["id": "l1", "shortcode": "abc123", "url": "https://go.test/abc123",
                                                  "fallbackUrl": "https://x.test", "revokeToken": "lrt_mint"], status: 201))
        XCTAssertEqual(create(links)?.revokeToken, "lrt_mint")
        XCTAssertEqual(storage.linkRevokeToken(forShortcode: "abc123"), "lrt_mint")

        // A wrong token: 403, nothing forgotten.
        transport.stub("POST", "/sdk/links/abc123/revoke", StubResponse.failure(status: 403, code: "FORBIDDEN"))
        let wrong = DispatchSemaphore(value: 0)
        links.revoke(shortcode: "abc123", revokeToken: "lrt_wrong") { r in
            if case .success = r { XCTFail("a 403 succeeded") }
            wrong.signal()
        }
        _ = wrong.wait(timeout: .now() + 5)
        XCTAssertEqual(transport.lastRequest(to: "/sdk/links/abc123/revoke")?.body?["revokeToken"] as? String, "lrt_wrong")
        XCTAssertEqual(storage.linkRevokeToken(forShortcode: "abc123"), "lrt_mint")

        // The pre-5.6.0 signature sends the stored token.
        transport.stub("POST", "/sdk/links/abc123/revoke", .ok(["revoked": true, "final": true]))
        let sem = DispatchSemaphore(value: 0)
        links.revoke(shortcode: "abc123") { r in
            if case .failure = r { XCTFail("revoke failed") }
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 5)
        XCTAssertEqual(transport.lastRequest(to: "/sdk/links/abc123/revoke")?.body?["revokeToken"] as? String, "lrt_mint")
        XCTAssertNil(storage.linkRevokeToken(forShortcode: "abc123"), "kept after a successful revoke")

        // Nothing stored → a soft revoke, reported as such.
        transport.stub("POST", "/sdk/links/abc123/revoke", .ok(["revoked": true, "final": false]))
        let soft = DispatchSemaphore(value: 0)
        var final: Bool?
        links.revoke(shortcode: "abc123", revokeToken: nil) { r in if case .success(let v) = r { final = v.final }; soft.signal() }
        _ = soft.wait(timeout: .now() + 5)
        XCTAssertEqual(final, false)
        XCTAssertNil(transport.lastRequest(to: "/sdk/links/abc123/revoke")?.body?["revokeToken"])
    }

    func test_revokeTokenStore_keepsTheNewest200() {
        let storage = SendoraStorage(secure: RecordingSecureStore(), plain: RecordingPlainStore())
        for i in 0..<205 { storage.setLinkRevokeToken("lrt_\(i)", forShortcode: "s\(i)") }
        for i in 0..<5 { XCTAssertNil(storage.linkRevokeToken(forShortcode: "s\(i)")) }
        XCTAssertEqual(storage.linkRevokeToken(forShortcode: "s5"), "lrt_5")
        XCTAssertEqual(storage.linkRevokeToken(forShortcode: "s204"), "lrt_204")
    }

    // MARK: - Support badge goes through the SDK's client

    func test_unreadCountUsesTheSdkClient_withItsHeaders() {
        let transport = StubTransport()
        let client = APIClient(baseUrl: "https://api.test", apiKey: "pk_dev_test", transport: transport)
        let support = SendoraCloudSupport(apiBaseUrl: URL(string: "https://api.test")!, client: client, tokenProvider: { $0("tok-1") })
        transport.stub("GET", "/widgets/w1/my-tickets/unread-count", .ok(["count": 3]))
        let exp = expectation(description: "count")
        var count = -1
        support.getUnreadCount(widgetId: "w1") { count = $0; exp.fulfill() }
        wait(for: [exp], timeout: 5)
        XCTAssertEqual(count, 3)
        let req = transport.lastRequest(to: "/widgets/w1/my-tickets/unread-count")
        XCTAssertEqual(req?.headers["Authorization"], "Bearer tok-1")
        XCTAssertEqual(req?.headers["X-API-Key"], "pk_dev_test")
        XCTAssertEqual(req?.headers["X-Sendora-SDK-Version"], SendoraCloud.sdkVersion)
    }

    func test_noSourceFileUsesTheSharedURLSession() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let dir = root.appendingPathComponent("Sources/SendoraCloud")
        for rel in try FileManager.default.subpathsOfDirectory(atPath: dir.path) where rel.hasSuffix(".swift") {
            let source = try String(contentsOf: dir.appendingPathComponent(rel), encoding: .utf8)
            XCTAssertFalse(source.contains("URLSession.shared."), "\(rel): every call goes through APIClient (headers, key, no cookies, breaker)")
        }
    }
}
