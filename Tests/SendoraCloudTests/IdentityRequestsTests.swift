import XCTest
@testable import SendoraCloud

/// 5.7.0 — server consent + flags with identify()'s identityToken (port of RN `withInputIdentityToken`), through the
/// real `APIClient` over the scripted transport.
final class IdentityRequestsTests: XCTestCase {
    private let token = "hmac_v1:" + String(repeating: "a", count: 64)
    private func identified(_ uid: String = "u-1", token t: String? = nil, tokenUser: String? = nil) -> SendoraIdentitySnapshot {
        SendoraIdentitySnapshot(currentUserId: uid, tokenUserId: tokenUser ?? uid, token: t ?? token)
    }

    // MARK: - The rule

    func test_tokenRule() {
        typealias R = SendoraIdentityRequest
        let id = identified()
        XCTAssertEqual(R.identityToken(explicit: "explicit", callUserId: "someone-else", identity: id, maxLength: 128), "explicit", "an explicit argument wins")
        XCTAssertEqual(R.identityToken(explicit: nil, callUserId: "u-1", identity: id, maxLength: 128), token, "remembered for the identified user")
        XCTAssertNil(R.identityToken(explicit: nil, callUserId: "u-2", identity: id, maxLength: 128), "sent for ANOTHER userId")
        XCTAssertNil(R.identityToken(explicit: nil, callUserId: nil, identity: id, maxLength: 128), "sent with no userId")
        let long = String(repeating: "t", count: 129)
        XCTAssertNil(R.identityToken(explicit: nil, callUserId: "u-1", identity: identified(token: long), maxLength: R.flagsTokenMax), "over the flags limit")
        XCTAssertEqual(R.identityToken(explicit: nil, callUserId: "u-1", identity: identified(token: long), maxLength: R.consentTokenMax), long, "fits consent's 256")
        XCTAssertNil(R.identityToken(explicit: nil, callUserId: "u-1",
                                     identity: SendoraIdentitySnapshot(currentUserId: "u-1", tokenUserId: nil, token: nil), maxLength: 128),
                     "after reset (no token) nothing is sent")
        XCTAssertNil(R.identityToken(explicit: nil, callUserId: "u-2", identity: identified("u-2", tokenUser: "u-1"), maxLength: 128),
                     "a token issued for u-1 travelled with u-2 after auth switched the user")
        XCTAssertEqual(R.flagsTokenMax, 128)
        XCTAssertEqual(R.consentTokenMax, 256)
    }

    // MARK: - Flags

    private func flags(_ identity: SendoraIdentitySnapshot) -> (SendoraCloudFlags, StubTransport) {
        let t = StubTransport()
        let c = APIClient(baseUrl: "https://api.test", apiKey: "pk_dev_test", transport: t)
        return (SendoraCloudFlags(client: c, identity: { identity }), t)
    }

    func test_flagsEvaluate_defaultsToTheIdentifiedUser_carriesTheToken_andDecodesTheServerShape() async throws {
        let (f, t) = flags(identified())
        t.stub("POST", "/feature-flags/evaluate", .ok(["key": "new_ui", "value": true, "ruleMatched": "rule-7"]))
        let v = try await f.evaluate(key: "new_ui")
        XCTAssertEqual(v, SendoraFlagValue(key: "new_ui", value: .bool(true), variant: nil, reason: "rule-7"))
        let body = try XCTUnwrap(t.lastRequest(to: "/feature-flags/evaluate")?.body)
        XCTAssertEqual(body["userId"] as? String, "u-1")
        XCTAssertEqual(body["identityToken"] as? String, token)
        XCTAssertEqual(body["key"] as? String, "new_ui")
        XCTAssertNil(body["entityId"], "a nil field must be omitted, never null")

        _ = try await f.evaluate(key: "new_ui", userId: "u-2")
        XCTAssertNil(t.lastRequest(to: "/feature-flags/evaluate")?.body?["identityToken"], "the token went out for another userId")
    }

    func test_flagsEvaluateAll_mapsTheServersArrayByKey() async throws {
        let (f, t) = flags(identified())
        t.stub("POST", "/feature-flags/evaluate-all", StubResponse(status: 200, json: ["success": true, "data": [
            ["key": "a", "value": 3, "ruleMatched": "default"],
            ["key": "b", "value": "blue", "ruleMatched": "inactive"],
            ["key": "c", "value": ["x": [1, NSNull()]], "ruleMatched": "rule-1"],
        ]]))
        let all = try await f.evaluateAll()
        XCTAssertEqual(all["a"]?.value.intValue, 3)
        XCTAssertEqual(all["b"]?.value.stringValue, "blue")
        XCTAssertEqual(all["b"]?.reason, "inactive")
        XCTAssertEqual(all["c"]?.value, .object(["x": .array([.number(1), .null])]))
        XCTAssertEqual(t.lastRequest(to: "/feature-flags/evaluate-all")?.body?["identityToken"] as? String, token)
    }

    // MARK: - Consent

    private func consent(_ identity: SendoraIdentitySnapshot, client: Bool = true) -> (SendoraCloudConsent, StubTransport) {
        let t = StubTransport()
        let c = SendoraCloudConsent(initial: false)
        c.attach(client: client ? APIClient(baseUrl: "https://api.test", apiKey: "pk_dev_test", transport: t) : nil, identity: { identity })
        return (c, t)
    }

    func test_consentRecord_tokenOnlyForTheIdentifiedUser_andDecodes() async throws {
        let (c, t) = consent(identified())
        t.stub("POST", "/consent/record", .ok(["id": "r1", "purpose": "marketing", "granted": true, "userId": "u-1", "sourceVerified": true], status: 201))
        let r = try await c.record(purpose: .marketing, granted: true, userId: "u-1", source: "settings")
        XCTAssertEqual(r.id, "r1")
        XCTAssertEqual(r.sourceVerified, true)
        let body = try XCTUnwrap(t.lastRequest(to: "/consent/record")?.body)
        XCTAssertEqual(body["identityToken"] as? String, token)
        XCTAssertEqual(body["purpose"] as? String, "marketing")
        XCTAssertEqual(body["granted"] as? Bool, true)
        _ = try await c.record(purpose: .marketing, granted: false, userId: "u-2")
        XCTAssertNil(t.lastRequest(to: "/consent/record")?.body?["identityToken"], "another userId got the token")
        _ = try await c.record(purpose: .analytics, granted: true, email: "p@example.com")
        XCTAssertNil(t.lastRequest(to: "/consent/record")?.body?["identityToken"], "no userId, no token")
        XCTAssertTrue(c.isGranted == false, "the local gate is untouched by a server record")
    }

    func test_consentRequestDeletion_explicitTokenWins_andDecodes() async throws {
        let (c, t) = consent(identified())
        t.stub("POST", "/consent/deletion-request", .ok(["id": "d1", "status": "pending", "userId": "u-1"], status: 201))
        let d = try await c.requestDeletion(userId: "u-9", reason: "bye", identityToken: "given")
        XCTAssertEqual(d, SendoraDeletionRequest(id: "d1", status: "pending", userId: "u-1", email: nil, reason: nil, sourceVerified: nil, createdAt: nil))
        XCTAssertEqual(t.lastRequest(to: "/consent/deletion-request")?.body?["identityToken"] as? String, "given")
    }

    // MARK: - Errors are thrown, typed

    func test_aRefusalIsThrownWithStatusAndCode_neverNil() async {
        let (f, t) = flags(identified())
        t.stub("POST", "/feature-flags/evaluate", .failure(status: 403, code: "FORBIDDEN_SCOPE", message: "flags:sdk required"))
        do { _ = try await f.evaluate(key: "x"); XCTFail("a 403 returned a value") }
        catch let e as SendoraCloudAPIError { XCTAssertEqual(e.code, "FORBIDDEN_SCOPE"); XCTAssertEqual(e.status, 403) }
        catch { XCTFail("untyped \(error)") }

        t.stub("POST", "/feature-flags/evaluate", .offline)
        do { _ = try await f.evaluate(key: "x"); XCTFail("offline returned a value") }
        catch let e as SendoraCloudAPIError { XCTAssertEqual(e.code, "NETWORK"); XCTAssertEqual(e.status, 0) }
        catch { XCTFail("untyped \(error)") }

        let (c, ct) = consent(identified())
        ct.stub("POST", "/consent/record", StubResponse(status: 200, json: ["success": false]))
        do { _ = try await c.record(purpose: .necessary, granted: true); XCTFail("success:false returned a value") }
        catch let e as SendoraCloudAPIError { XCTAssertEqual(e.code, "BAD_RESPONSE") }
        catch { XCTFail("untyped \(error)") }

        let (u, _) = consent(identified(), client: false)
        do { _ = try await u.requestDeletion(userId: "u-1"); XCTFail("an unconfigured SDK returned a value") }
        catch let e as SendoraCloudAPIError { XCTAssertEqual(e.code, "NOT_CONFIGURED") }
        catch { XCTFail("untyped \(error)") }

        ct.stub("POST", "/consent/record", .failure(status: 422, code: "VALIDATION_ERROR"))
        do { _ = try await c.record(purpose: .marketing, granted: true, email: "not-an-email"); XCTFail("a 422 returned a value") }
        catch let e as SendoraCloudAPIError { XCTAssertEqual(e.status, 422); XCTAssertEqual(e.code, "VALIDATION_ERROR") }
        catch { XCTFail("untyped \(error)") }
    }
}
