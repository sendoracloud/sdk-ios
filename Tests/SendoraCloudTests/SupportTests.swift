import XCTest
@testable import SendoraCloud

/// 5.5.0 (s58.376) — support parity with RN 1.42.0, driven through the real `APIClient` over the scripted transport.
///
/// Mutations that must turn this red: drop the Bearer on `createTicket`; swallow a refusal into `[]`; send a support
/// call with no session; put the token in the query; stop dropping invalid metadata; let a non-hex accent through.
final class SupportTests: XCTestCase {
    private func make(token: String?) -> (SendoraCloudSupport, StubTransport) {
        let transport = StubTransport()
        let client = APIClient(baseUrl: "https://api.test", apiKey: "pk_dev_test", transport: transport)
        let support = SendoraCloudSupport(apiBaseUrl: URL(string: "https://api.test")!, client: client,
                                          tokenProvider: { done in done(token) })
        return (support, transport)
    }

    func test_listMyTickets_sendsTheBearerAndReturnsTheTickets() async throws {
        let (support, transport) = make(token: "tok-1")
        transport.stub("GET", "/widgets/w1/my-tickets", StubResponse(status: 200, json: ["success": true, "data": [
            ["id": "t1", "subject": "Stuck", "status": "pending", "priority": "normal", "createdAt": "x",
             "updatedAt": "y", "resolvedAt": NSNull(), "unread": true],
        ]]))
        let list = try await support.listMyTickets(widgetId: "w1")
        XCTAssertEqual(list, [SendoraMyTicketSummary(id: "t1", subject: "Stuck", status: "pending", priority: "normal",
                                                     createdAt: "x", updatedAt: "y", resolvedAt: nil, unread: true)])
        let req = try XCTUnwrap(transport.lastRequest(to: "/widgets/w1/my-tickets"))
        XCTAssertEqual(req.headers["Authorization"], "Bearer tok-1")
        XCTAssertEqual(req.headers["X-API-Key"], "pk_dev_test")
    }

    func test_aRefusalThrowsTheServersCode_neverAnEmptyList() async {
        let (support, transport) = make(token: "tok-1")
        transport.stub("GET", "/widgets/w1/my-tickets", .failure(status: 403, code: "PROJECT_MISMATCH"))
        do {
            _ = try await support.listMyTickets(widgetId: "w1")
            XCTFail("expected a refusal")
        } catch let e as SendoraSupportError {
            XCTAssertEqual(e.code, "PROJECT_MISMATCH")
            XCTAssertEqual(e.status, 403)
        } catch { XCTFail("wrong error \(error)") }
    }

    func test_noSession_throwsNotSignedIn_andSendsNothing() async {
        let (support, transport) = make(token: nil)
        do {
            _ = try await support.getMyTicket(widgetId: "w1", ticketId: "t1")
            XCTFail("expected NOT_SIGNED_IN")
        } catch let e as SendoraSupportError {
            XCTAssertEqual(e.code, "NOT_SIGNED_IN")
        } catch { XCTFail("wrong error \(error)") }
        XCTAssertEqual(transport.requestCount, 0)
    }

    func test_getMyTicket_andReply() async throws {
        let (support, transport) = make(token: "tok-1")
        transport.stub("GET", "/widgets/w1/my-tickets/t1", .ok([
            "id": "t1", "subject": "s", "body": "b", "status": "open", "priority": "normal", "createdAt": "x",
            "updatedAt": "y", "replies": [["id": "r0", "body": "Hi", "authorType": "agent", "createdAt": "z"]],
        ]))
        transport.stub("POST", "/widgets/w1/my-tickets/t1/replies", .ok(["id": "r1", "createdAt": "z", "reopened": true], status: 201))
        let t = try await support.getMyTicket(widgetId: "w1", ticketId: "t1")
        XCTAssertEqual(t.replies, [SendoraMyTicketReply(id: "r0", body: "Hi", authorType: "agent", createdAt: "z")])
        let r = try await support.replyToMyTicket(widgetId: "w1", ticketId: "t1", body: "Still broken")
        XCTAssertTrue(r.reopened)
        XCTAssertEqual(transport.lastRequest(to: "/widgets/w1/my-tickets/t1/replies")?.body?["body"] as? String, "Still broken")
    }

    func test_createTicket_sendsTheTokenWhenThereIsOne_andSanitisesMetadata() async throws {
        let created: [String: Any] = ["id": "t9", "subject": "s", "status": "open", "priority": "normal", "userIdVerified": true]
        let (signedIn, a) = make(token: "tok-2")
        a.stub("POST", "/support/tickets", .ok(created, status: 201))
        let t = try await signedIn.createTicket(subject: "Refund", body: "Charged twice",
                                                metadata: ["plan": "pro", "level": 40, "nested": ["a": 1], "<bad>": "x"])
        XCTAssertTrue(t.userIdVerified)
        let req = try XCTUnwrap(a.lastRequest(to: "/support/tickets"))
        XCTAssertEqual(req.headers["Authorization"], "Bearer tok-2")
        let meta = try XCTUnwrap(req.body?["metadata"] as? [String: Any])
        XCTAssertEqual(Set(meta.keys), ["plan", "level"])

        let (signedOut, b) = make(token: nil)
        b.stub("POST", "/support/tickets", .ok(created, status: 201))
        _ = try await signedOut.createTicket(subject: "Refund", body: "Charged twice")
        XCTAssertNil(b.lastRequest(to: "/support/tickets")?.headers["Authorization"])
    }

    func test_sanitizeMetadata_backendRules() {
        let many = Dictionary(uniqueKeysWithValues: (0..<40).map { ("k\($0)", $0 as Any) })
        XCTAssertEqual(SendoraCloudSupport.sanitizeMetadata(many).count, 30)
        let out = SendoraCloudSupport.sanitizeMetadata(["ok": true, "n": 1.5, "none": NSNull(), "inf": Double.infinity,
                                                        "arr": [1], "s": String(repeating: "x", count: 2000)])
        XCTAssertEqual(Set(out.keys), ["ok", "n", "none", "s"])
        XCTAssertEqual(out["ok"] as? Bool, true)
        XCTAssertEqual((out["s"] as? String)?.count, 1000)
    }

    func test_contactURL_tokenAndMetadataInTheFragment_accentOnlyWhenHex() throws {
        let url = try XCTUnwrap(SendoraCloudSupport.contactURL(
            host: URL(string: "https://go.test")!, widgetId: "w1", theme: "auto", prefillName: nil, prefillEmail: nil,
            prefillUserId: "u1", lockEmail: false, accent: "#22c55e", accessToken: "tok.a+b", metadata: ["plan": "pro & co"]))
        let comps = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        XCTAssertEqual(comps.queryItems?.first { $0.name == "accent" }?.value, "#22c55e")
        XCTAssertFalse(url.query?.contains("tok") ?? false)
        // The page decodes the fragment with URLSearchParams: every reserved character must arrive intact.
        var parsed = URLComponents()
        parsed.percentEncodedQuery = url.fragment
        XCTAssertEqual(parsed.queryItems?.first { $0.name == "access" }?.value, "tok.a+b")
        XCTAssertEqual(parsed.queryItems?.first { $0.name == "metadata" }?.value, #"{"plan":"pro & co"}"#)

        let bad = try XCTUnwrap(SendoraCloudSupport.contactURL(
            host: URL(string: "https://go.test")!, widgetId: "w1", theme: "auto", prefillName: nil, prefillEmail: nil,
            prefillUserId: nil, lockEmail: false, accent: "red;}</style>", accessToken: nil, metadata: [:]))
        XCTAssertNil(bad.fragment)
        XCTAssertFalse(bad.absoluteString.contains("accent"))
    }

    func test_deviceContext_carriesTheSdkVersion() {
        let (support, _) = make(token: nil)
        let ctx = support.deviceContext()
        XCTAssertEqual(ctx["sdk"] as? String, "\(SendoraCloud.sdkName)@\(SendoraCloud.sdkVersion)")
        XCTAssertNotNil(ctx["osVersion"] as? String)
        XCTAssertNotNil(ctx["deviceModel"] as? String)
    }
}
