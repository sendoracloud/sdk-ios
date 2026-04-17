import XCTest
@testable import Sendora

final class SendoraValidatorTests: XCTestCase {
    func test_rejectsSecretKey() {
        XCTAssertThrowsError(try SendoraValidator.validateApiKey("sk_test_abcdef"))
        XCTAssertThrowsError(try SendoraValidator.validateApiKey("sendora_secret_xxx"))
    }

    func test_acceptsPublishableKey() {
        XCTAssertNoThrow(try SendoraValidator.validateApiKey("pk_live_abcdefghijklmnop"))
    }

    func test_rejectsMalformedKey() {
        XCTAssertThrowsError(try SendoraValidator.validateApiKey(""))
        XCTAssertThrowsError(try SendoraValidator.validateApiKey("pk_short"))
    }

    func test_rejectsHttpUrl() {
        XCTAssertThrowsError(try SendoraValidator.validateApiUrl("http://api.sendoracloud.com"))
    }

    func test_allowsHttpsAndLocalhost() {
        XCTAssertNoThrow(try SendoraValidator.validateApiUrl("https://api.sendoracloud.com"))
        XCTAssertNoThrow(try SendoraValidator.validateApiUrl("http://localhost:4000"))
    }

    func test_rejectsBadEventName() {
        XCTAssertThrowsError(try SendoraValidator.validateEventName(""))
        XCTAssertThrowsError(try SendoraValidator.validateEventName("0leading_digit"))
        XCTAssertThrowsError(try SendoraValidator.validateEventName(String(repeating: "a", count: 129)))
    }

    func test_acceptsGoodEventName() {
        XCTAssertNoThrow(try SendoraValidator.validateEventName("order.placed"))
        XCTAssertNoThrow(try SendoraValidator.validateEventName("user.signed_up"))
    }

    func test_rejectsForbiddenKeys() {
        XCTAssertThrowsError(try SendoraValidator.validateProperties(["__proto__": "x"]))
        XCTAssertThrowsError(try SendoraValidator.validateProperties(["nested": ["constructor": 1]]))
    }

    func test_rejectsDeepNesting() {
        var nested: [String: Any] = ["a": 1]
        for _ in 0..<8 { nested = ["n": nested] }
        XCTAssertThrowsError(try SendoraValidator.validateProperties(nested))
    }
}
