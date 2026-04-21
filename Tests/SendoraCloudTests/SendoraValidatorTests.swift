import XCTest
@testable import SendoraCloud

final class SendoraValidatorTests: XCTestCase {
    func test_rejectsSecretKey() {
        XCTAssertThrowsError(try SendoraCloudValidator.validateApiKey("sk_test_abcdef"))
        XCTAssertThrowsError(try SendoraCloudValidator.validateApiKey("sendora_secret_xxx"))
    }

    func test_acceptsPublishableKey() {
        XCTAssertNoThrow(try SendoraCloudValidator.validateApiKey("pk_live_abcdefghijklmnop"))
    }

    func test_rejectsMalformedKey() {
        XCTAssertThrowsError(try SendoraCloudValidator.validateApiKey(""))
        XCTAssertThrowsError(try SendoraCloudValidator.validateApiKey("pk_short"))
    }

    func test_rejectsHttpUrl() {
        XCTAssertThrowsError(try SendoraCloudValidator.validateApiUrl("http://api.sendoracloud.com"))
    }

    func test_allowsHttpsAndLocalhost() {
        XCTAssertNoThrow(try SendoraCloudValidator.validateApiUrl("https://api.sendoracloud.com"))
        XCTAssertNoThrow(try SendoraCloudValidator.validateApiUrl("http://localhost:4000"))
    }

    func test_rejectsBadEventName() {
        XCTAssertThrowsError(try SendoraCloudValidator.validateEventName(""))
        XCTAssertThrowsError(try SendoraCloudValidator.validateEventName("0leading_digit"))
        XCTAssertThrowsError(try SendoraCloudValidator.validateEventName(String(repeating: "a", count: 129)))
    }

    func test_acceptsGoodEventName() {
        XCTAssertNoThrow(try SendoraCloudValidator.validateEventName("order.placed"))
        XCTAssertNoThrow(try SendoraCloudValidator.validateEventName("user.signed_up"))
    }

    func test_rejectsForbiddenKeys() {
        XCTAssertThrowsError(try SendoraCloudValidator.validateProperties(["__proto__": "x"]))
        XCTAssertThrowsError(try SendoraCloudValidator.validateProperties(["nested": ["constructor": 1]]))
    }

    func test_rejectsDeepNesting() {
        var nested: [String: Any] = ["a": 1]
        for _ in 0..<8 { nested = ["n": nested] }
        XCTAssertThrowsError(try SendoraCloudValidator.validateProperties(nested))
    }
}
