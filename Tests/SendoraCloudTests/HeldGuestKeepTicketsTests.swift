import XCTest
@testable import SendoraCloud

// 5.9.0 — `discardHeldGuest(id:keepSupportTickets:completion:)` (parity RN 1.45.0).
// The server moves the held guest's support tickets to the CURRENT account and
// then erases the guest; it needs the account's access token as the Bearer.
// Same recording doubles as the row scenarios; nothing here reads source text.

final class HeldGuestKeepTicketsTests: XCTestCase {
    private static let anon = AuthHarness.anonymousUser()
    private static let ident = AuthHarness.identifiedUser()
    private static let identAccess = TestJWT.make(sub: ident.id, sid: "sid-ident", isAnonymous: false)
    private static let anonAccess = TestJWT.make(sub: anon.id, sid: "sid-anon", isAnonymous: true)
    private static let path = "/auth-service/guest/discard"

    private func harness(identified: Bool) -> AuthHarness {
        let h = AuthHarness()
        if identified {
            h.seedSession(user: Self.ident, access: Self.identAccess, refresh: "rt-ident")
        } else {
            h.seedSession(user: Self.anon, access: Self.anonAccess, refresh: "rt-anon")
        }
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        XCTAssertEqual(h.auth.status(), identified ? .identified : .anonymous)
        return h
    }

    /// Identified + the option: the body carries the guest's refresh token AND
    /// `keepSupportTickets: true`, the Bearer is the ACCOUNT's access token (never
    /// the guest's), and a 2xx releases the slot.
    func test_keepTickets_onIdentified_sendsFlagAndAccountBearer_releasesSlot() {
        let h = harness(identified: true)
        h.transport.stub("POST", Self.path, .ok(["userId": "g-held", "status": "purged", "supportTicketsMoved": 2]))
        let result: Result<Void, SendoraCloudAuthError> = h.wait { done in
            h.auth.discardHeldGuest(id: "g-held", keepSupportTickets: true, completion: done)
        }
        XCTAssertNil(result.failureError)
        guard let req = h.transport.lastRequest(to: Self.path) else { return XCTFail("no discard request") }
        XCTAssertEqual(req.body?["refreshToken"] as? String, "rt-held")
        XCTAssertEqual(req.body?["keepSupportTickets"] as? Bool, true)
        let auth = req.headers["Authorization"]
        XCTAssertEqual(auth, "Bearer \(Self.identAccess)", "the CURRENT account's access token is the Bearer")
        XCTAssertFalse(auth?.contains("rt-held") ?? false, "the guest's token is never the Bearer")
        XCTAssertNil(h.heldSlot(0), "2xx releases the slot")
        XCTAssertEqual(h.transitionEventNames, ["guest_released"])
        XCTAssertEqual(h.auth.currentUser?.id, Self.ident.id, "the current session is untouched")
    }

    /// Without the option (both the 5.4.0 declaration and `keepSupportTickets:
    /// false`) the request is the pre-5.9.0 one: no flag, no Authorization header.
    func test_withoutKeepTickets_requestIsUnchanged() {
        for useOverload in [false, true] {
            let h = harness(identified: true)
            h.transport.stub("POST", Self.path, .ok(["userId": "g-held", "status": "purged"]))
            let result: Result<Void, SendoraCloudAuthError> = h.wait { done in
                if useOverload {
                    h.auth.discardHeldGuest(id: "g-held", keepSupportTickets: false, completion: done)
                } else {
                    h.auth.discardHeldGuest(id: "g-held", completion: done)
                }
            }
            XCTAssertNil(result.failureError)
            guard let req = h.transport.lastRequest(to: Self.path) else { return XCTFail("no discard request") }
            XCTAssertEqual(req.body?.keys.sorted(), ["refreshToken"], "overload=\(useOverload): body is only the refresh token")
            XCTAssertEqual(req.body?["refreshToken"] as? String, "rt-held")
            XCTAssertNil(req.headers["Authorization"], "overload=\(useOverload): no Authorization header")
            XCTAssertNil(h.heldSlot(0))
        }
    }

    /// Anonymous + the option: `KEEP_TICKETS_REQUIRES_IDENTIFIED` (kind config, not
    /// retryable), ZERO requests, the slot kept.
    func test_keepTickets_onAnonymous_refusesWithNoNetwork_keepsSlot() {
        let h = harness(identified: false)
        let before = h.transport.requestCount
        let result: Result<Void, SendoraCloudAuthError> = h.wait { done in
            h.auth.discardHeldGuest(id: "g-held", keepSupportTickets: true, completion: done)
        }
        guard let error = result.failureError else { return XCTFail("an anonymous keep-tickets discard succeeded") }
        XCTAssertEqual(error.code, "KEEP_TICKETS_REQUIRES_IDENTIFIED")
        XCTAssertEqual(error.kind, .config)
        XCTAssertFalse(error.retryable)
        XCTAssertEqual(h.transport.requestCount, before, "nothing is sent")
        XCTAssertNotNil(h.heldSlot(0), "the slot is kept")
        XCTAssertEqual(h.transitionEventNames, [])
    }

    /// A server refusal (422 — anonymous / other-project Bearer) throws and KEEPS
    /// the slot; so does a 401 (missing Bearer).
    func test_keepTickets_serverRefusal_throws_keepsSlot() {
        for (status, code) in [(422, "VALIDATION_ERROR"), (401, "UNAUTHORIZED")] {
            let h = harness(identified: true)
            h.transport.stub("POST", Self.path, .failure(status: status, code: code, message: "refused"))
            let result: Result<Void, SendoraCloudAuthError> = h.wait { done in
                h.auth.discardHeldGuest(id: "g-held", keepSupportTickets: true, completion: done)
            }
            XCTAssertNotNil(result.failureError, "\(status) must fail")
            if status == 422 { XCTAssertEqual(result.failureError?.code, code) }
            XCTAssertNotNil(h.heldSlot(0), "\(status): the guest is not gone — keep the slot")
            XCTAssertEqual(h.transitionEventNames, [], "\(status): no release event")
            XCTAssertEqual(h.auth.currentUser?.id, Self.ident.id)
        }
    }

    /// 404 (guest already gone) releases the slot, as without the option.
    func test_keepTickets_404_releasesSlot() {
        let h = harness(identified: true)
        h.transport.stub("POST", Self.path, .failure(status: 404, code: "NOT_FOUND", message: "Guest"))
        let result: Result<Void, SendoraCloudAuthError> = h.wait { done in
            h.auth.discardHeldGuest(id: "g-held", keepSupportTickets: true, completion: done)
        }
        XCTAssertNil(result.failureError)
        XCTAssertNil(h.heldSlot(0))
    }

    /// Withheld rejects first (existing gate), with no network.
    func test_keepTickets_inWithheld_rejectsSessionWithheld() {
        let h = AuthHarness(expectedProjectId: TestJWT.projectA)
        h.seedSession(user: Self.ident, access: TestJWT.make(sub: Self.ident.id, sid: "sid-w", isAnonymous: false, project: .some(TestJWT.projectB)), refresh: "rt-w")
        h.seedSlot(0, AuthHarness.slot(userId: "g-held", refresh: "rt-held", heldAt: 1))
        h.boot()
        XCTAssertEqual(h.auth.status(), .withheld)
        let before = h.transport.requestCount
        let result: Result<Void, SendoraCloudAuthError> = h.wait { done in
            h.auth.discardHeldGuest(id: "g-held", keepSupportTickets: true, completion: done)
        }
        XCTAssertEqual(result.failureError?.code, "SESSION_WITHHELD")
        XCTAssertEqual(h.transport.requestCount, before)
        XCTAssertNotNil(h.heldSlot(0))
    }

    /// The 5.4.0 declaration survives verbatim (unapplied reference + trailing closure).
    func test_preKeepTicketsDeclarationStillResolves() {
        let h = harness(identified: true)
        let discard: (String?, @escaping (Result<Void, SendoraCloudAuthError>) -> Void) -> Void = h.auth.discardHeldGuest(id:completion:)
        _ = discard
        h.transport.stub("POST", Self.path, .ok(["userId": "g-held", "status": "purged"]))
        let sem = DispatchSemaphore(value: 0)
        h.auth.discardHeldGuest(id: "g-held") { _ in sem.signal() }
        XCTAssertEqual(sem.wait(timeout: .now() + 5), .success)
    }
}
