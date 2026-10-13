import XCTest
@testable import SendoraCloud

/// s58.360 — a held-slot refresh must come back for the held GUEST, and the transport sends no cookies.
///
/// TapMap (RN 1.41.1): before the server fix `/token/refresh` preferred the `sd_rt` cookie over the
/// body, and a native cookie jar (a URLSession — ephemeral included — keeps one) held the signed-in
/// ACCOUNT's cookie, so a held guest's refresh came back for the ACCOUNT and committing it overwrote
/// the guest's only token. Parity with RN 1.41.2 / web 3.24.2: refuse BEFORE the slot write.
/// Mutation that must turn this red: delete the `who != slot.userId` early return in `refreshHeld`.
extension AuthMachineConformanceTests {
    /// The pre-e09c86dc server: the held refresh answered for the signed-in ACCOUNT.
    private func accountAnsweredRefresh() -> StubResponse {
        Stub.session(user: Stub.user(id: Self.ident.id, isAnonymous: false), tokens: Stub.tokens(access: Self.identToken(), refresh: "rt-ident-by-cookie"))
    }

    func test_s58_360_claim_answeredForAnotherUser_isRefused_slotKept() {
        let h = identifiedHarness(expected: TestJWT.projectA)
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", accountAnsweredRefresh())
        h.transport.stub("POST", "/auth-service/merge", .ok(["mergedUserId": Self.ident.id, "deletedAnonymousId": "g-held",
                                                            "tokens": Stub.tokens(access: Self.identToken(), refresh: "rt-ident-2")]))
        let result: Result<SendoraCloudClaimResult, SendoraCloudAuthError> = h.wait { done in h.auth.claimHeldGuest(completion: done) }
        XCTAssertEqual(result.failureError?.code, "HELD_GUEST_IDENTITY_MISMATCH")
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "rt-held", "the guest's slot was overwritten with the account's token")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/merge").count, 0, "no /merge after a refused refresh")
        XCTAssertEqual(h.storedRefresh, "rt-ident", "the current account session is untouched")
        XCTAssertFalse(h.transitionEventNames.contains("guest_released"))
    }

    func test_s58_360_restore_answeredForAnotherUser_isRefused_accountKept() {
        let h = identifiedHarness(expected: TestJWT.projectA)
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        h.transport.stub("POST", "/auth-service/token/refresh", accountAnsweredRefresh())
        h.transport.stub("POST", "/auth-service/token/revoke", .ok([:]))
        let result: Result<SendoraCloudAuthUser, SendoraCloudAuthError> = h.wait { done in h.auth.restoreHeldGuest(completion: done) }
        XCTAssertEqual(result.failureError?.code, "HELD_GUEST_IDENTITY_MISMATCH")
        XCTAssertEqual(h.heldSlot(0)?.refreshToken, "rt-held", "the slot is KEPT — installing would 'restore' the account and drop the guest's only handle")
        XCTAssertEqual(h.auth.status(), .identified)
        XCTAssertEqual(h.storedRefresh, "rt-ident")
        XCTAssertEqual(h.transport.requests(to: "/auth-service/token/revoke").count, 0, "the account was not revoked")
        XCTAssertFalse(h.transitionEventNames.contains("guest_released"))
    }

    func test_s58_360_defaultTransport_sendsAndStoresNoCookies() {
        let config = APIClient.makeSessionConfiguration()
        XCTAssertFalse(config.httpShouldSetCookies, "cookies would be attached to requests")
        XCTAssertEqual(config.httpCookieAcceptPolicy, .never, "Set-Cookie would be stored")
        XCTAssertNil(config.httpCookieStorage, "an in-memory jar would persist for the session")
    }
}
