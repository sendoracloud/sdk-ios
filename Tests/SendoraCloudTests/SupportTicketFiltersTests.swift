import XCTest
@testable import SendoraCloud

/// Unreleased (s58.406) — TicketHistory asks: `listMyTickets` filters + `listMyTicketsPage` cursor paging, `createTicket`
/// 409 `ACTIVE_TICKET_EXISTS`,
/// and the hosted ticket-history URL options. Driven through the real `APIClient` over the scripted transport.
///
/// Mutations that must turn this red: an option sent when not given; the comma list or flag spelled differently;
/// `limit` not range-checked; statuses + activeOnly let through; a bad option still sends a request; the 409's
/// `details.ticketId` dropped; a non-UUID `ticketId` let onto the page URL; an option added when unset; the cursor not
/// sent, sent unencoded or an empty one let through; `pagination.nextCursor` not read.
final class SupportTicketFiltersTests: XCTestCase {
    private let path = "/widgets/w1/my-tickets"

    private func make(token: String? = "tok-1") -> (SendoraCloudSupport, StubTransport) {
        let transport = StubTransport()
        let client = APIClient(baseUrl: "https://api.test", apiKey: "pk_dev_test", transport: transport)
        let support = SendoraCloudSupport(apiBaseUrl: URL(string: "https://api.test")!, client: client,
                                          tokenProvider: { done in done(token) })
        transport.stub("GET", path, StubResponse(status: 200, json: ["success": true, "data": [[String: Any]]()]))
        return (support, transport)
    }

    // MARK: listMyTickets

    func test_withoutOptions_theRequestIsUnchanged() async throws {
        let (support, transport) = make()
        _ = try await support.listMyTickets(widgetId: "w1")
        _ = try await support.listMyTickets(widgetId: "w1", statuses: nil, activeOnly: false, limit: nil)
        let reqs = transport.requests(to: path)
        XCTAssertEqual(reqs.count, 2)
        XCTAssertEqual(reqs.map { $0.query }, [nil, nil])
        XCTAssertEqual(reqs.last?.headers["Authorization"], "Bearer tok-1")
    }

    func test_eachOptionGoesOnTheQueryExactly() async throws {
        let cases: [(statuses: [String]?, activeOnly: Bool, limit: Int?, query: String)] = [
            (["open", "pending"], false, nil, "statuses=open,pending"),
            (["resolved", "closed", "resolved"], false, nil, "statuses=resolved,closed"),
            (nil, true, nil, "activeOnly=true"),
            (nil, false, 10, "limit=10"),
            (nil, false, 1, "limit=1"),
            (nil, false, 50, "limit=50"),
            (nil, true, 20, "activeOnly=true&limit=20"),
            (["closed"], false, 5, "statuses=closed&limit=5"),
        ]
        for c in cases {
            let (support, transport) = make()
            _ = try await support.listMyTickets(widgetId: "w1", statuses: c.statuses, activeOnly: c.activeOnly, limit: c.limit)
            XCTAssertEqual(transport.lastRequest(to: path)?.query, c.query, "\(c)")
        }
    }

    func test_aBadOption_throwsInvalidArgument_andSendsNothing() async {
        let cases: [(statuses: [String]?, activeOnly: Bool, limit: Int?)] = [
            (nil, false, 0), (nil, false, 51), (nil, false, -1),
            ([], false, nil), (["open", "archived"], false, nil), (["OPEN"], false, nil),
            (["open"], true, nil),
        ]
        for c in cases {
            let (support, transport) = make()
            do {
                _ = try await support.listMyTickets(widgetId: "w1", statuses: c.statuses, activeOnly: c.activeOnly, limit: c.limit)
                XCTFail("expected INVALID_ARGUMENT for \(c)")
            } catch let e as SendoraSupportError {
                XCTAssertEqual(e.code, "INVALID_ARGUMENT", "\(c)")
                XCTAssertNil(e.activeTicketId)
            } catch { XCTFail("wrong error \(error)") }
            XCTAssertEqual(transport.requestCount, 0, "\(c)")
        }
    }

    // MARK: listMyTicketsPage (cursor paging)

    private let row1: [String: Any] = ["id": "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b", "subject": "Lost coins", "status": "open",
                                       "priority": "normal", "createdAt": "2026-10-01T00:00:00Z",
                                       "updatedAt": "2026-10-02T00:00:00Z", "resolvedAt": NSNull(), "unread": true]
    private let row2: [String: Any] = ["id": "7a1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b", "subject": "Crash", "status": "closed",
                                       "priority": "high", "createdAt": "2026-09-01T00:00:00Z",
                                       "updatedAt": "2026-09-03T00:00:00Z", "resolvedAt": "2026-09-03T00:00:00Z",
                                       "unread": false]

    func test_page_sendsTheEncodedCursor_exactly() async throws {
        let cases: [(cursor: String?, limit: Int?, statuses: [String]?, activeOnly: Bool, query: String?)] = [
            (nil, nil, nil, false, nil),
            ("abc123", nil, nil, false, "cursor=abc123"),
            ("eyJ0Ijo+/=&x y", 10, nil, false, "limit=10&cursor=eyJ0Ijo%2B%2F%3D%26x%20y"),
            ("c-1._~", 5, ["open", "pending"], false, "statuses=open,pending&limit=5&cursor=c-1._~"),
            ("c2", nil, nil, true, "activeOnly=true&cursor=c2"),
        ]
        for c in cases {
            let (support, transport) = make()
            _ = try await support.listMyTicketsPage(widgetId: "w1", cursor: c.cursor, limit: c.limit,
                                                    statuses: c.statuses, activeOnly: c.activeOnly)
            XCTAssertEqual(transport.requests(to: path).count, 1, "\(c)")
            XCTAssertEqual(transport.lastRequest(to: path)?.query, c.query, "\(c)")
            XCTAssertEqual(transport.lastRequest(to: path)?.headers["Authorization"], "Bearer tok-1")
        }
    }

    func test_page_decodesTicketsAndNextCursor() async throws {
        let (support, transport) = make()
        transport.stub("GET", path, StubResponse(status: 200, json: [
            "success": true, "data": [row1, row2], "pagination": ["limit": 2, "nextCursor": "next+/=1"],
        ]))
        let page = try await support.listMyTicketsPage(widgetId: "w1", limit: 2)
        XCTAssertEqual(page.nextCursor, "next+/=1")
        XCTAssertEqual(page.tickets.map { $0.id }, ["6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b", "7a1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b"])
        XCTAssertEqual(page.tickets.first?.subject, "Lost coins")
        XCTAssertEqual(page.tickets.first?.unread, true)
        XCTAssertNil(page.tickets.first?.resolvedAt)
        XCTAssertEqual(page.tickets.last?.resolvedAt, "2026-09-03T00:00:00Z")
        // The next page round-trips the cursor, encoded.
        _ = try await support.listMyTicketsPage(widgetId: "w1", cursor: try XCTUnwrap(page.nextCursor), limit: 2)
        XCTAssertEqual(transport.lastRequest(to: path)?.query, "limit=2&cursor=next%2B%2F%3D1")
        // The list overload returns the same first page's rows and sends no cursor.
        let first = try await support.listMyTickets(widgetId: "w1", limit: 2)
        XCTAssertEqual(first, page.tickets)
        XCTAssertEqual(transport.lastRequest(to: path)?.query, "limit=2")
    }

    func test_page_withoutPagination_orANullCursor_isTheLastPage() async throws {
        let bodies: [[String: Any]] = [
            ["success": true, "data": [row1]],                                                  // an older server
            ["success": true, "data": [row1], "pagination": ["limit": 50, "nextCursor": NSNull()]],
            ["success": true, "data": [row1], "pagination": ["limit": 50]],
            ["success": true, "data": [row1], "pagination": ["limit": 50, "nextCursor": ""]],
        ]
        for body in bodies {
            let (support, transport) = make()
            transport.stub("GET", path, StubResponse(status: 200, json: body))
            let page = try await support.listMyTicketsPage(widgetId: "w1")
            XCTAssertNil(page.nextCursor, "\(body)")
            XCTAssertEqual(page.tickets.map { $0.subject }, ["Lost coins"])
        }
    }

    func test_page_anEmptyCursor_throwsInvalidArgument_andSendsNothing() async {
        for (cursor, limit) in [("", nil), ("", 10), ("ok", 0)] as [(String, Int?)] {
            let (support, transport) = make()
            do {
                _ = try await support.listMyTicketsPage(widgetId: "w1", cursor: cursor, limit: limit)
                XCTFail("expected INVALID_ARGUMENT for \(cursor) \(String(describing: limit))")
            } catch let e as SendoraSupportError {
                XCTAssertEqual(e.code, "INVALID_ARGUMENT")
                XCTAssertEqual(e.status, 0)
            } catch { XCTFail("wrong error \(error)") }
            XCTAssertEqual(transport.requestCount, 0)
        }
        // Refused before the token lookup: no session is needed to be told the cursor is bad.
        let (support, transport) = make(token: nil)
        do {
            _ = try await support.listMyTicketsPage(widgetId: "w1", cursor: "")
            XCTFail("expected INVALID_ARGUMENT")
        } catch let e as SendoraSupportError {
            XCTAssertEqual(e.code, "INVALID_ARGUMENT")
        } catch { XCTFail("wrong error \(error)") }
        XCTAssertEqual(transport.requestCount, 0)
    }

    // MARK: createTicket 409

    func test_createTicket_activeTicketExists_carriesTheTicketId() async {
        let (support, transport) = make()
        transport.stub("POST", "/support/tickets", .failure(status: 409, code: "ACTIVE_TICKET_EXISTS",
                                                            message: "An open ticket exists",
                                                            details: ["ticketId": "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b"]))
        do {
            _ = try await support.createTicket(subject: "s", body: "b")
            XCTFail("expected a refusal")
        } catch let e as SendoraSupportError {
            XCTAssertEqual(e.code, "ACTIVE_TICKET_EXISTS")
            XCTAssertEqual(e.status, 409)
            XCTAssertEqual(e.activeTicketId, "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b")
        } catch { XCTFail("wrong error \(error)") }
    }

    func test_otherRefusals_haveNoActiveTicketId() async {
        let (support, transport) = make()
        transport.stub("POST", "/support/tickets", .failure(status: 422, code: "VALIDATION_ERROR",
                                                            details: ["ticketId": "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b"]))
        do {
            _ = try await support.createTicket(subject: "s", body: "b")
            XCTFail("expected a refusal")
        } catch let e as SendoraSupportError {
            XCTAssertEqual(e.code, "VALIDATION_ERROR")
            XCTAssertNil(e.activeTicketId)
        } catch { XCTFail("wrong error \(error)") }
        // The 5.5.0 initializer still builds the same value.
        XCTAssertEqual(SendoraSupportError(code: "X", status: 1, message: "m"),
                       SendoraSupportError(code: "X", status: 1, message: "m", activeTicketId: nil))
    }

    // MARK: hosted ticket-history URL

    private func historyURL(ticketId: String? = nil, readOnlyFinished: Bool = false, statuses: [String]? = nil,
                            activeOnly: Bool = false, limit: Int? = nil, token: String? = "tok.1") throws -> URL {
        try XCTUnwrap(SendoraCloudSupport.ticketHistoryURL(
            host: URL(string: "https://go.test")!, widgetId: "w1", theme: "auto", accent: "#22c55e", accessToken: token,
            ticketId: ticketId, readOnlyFinished: readOnlyFinished, statuses: statuses, activeOnly: activeOnly, limit: limit))
    }

    func test_historyURL_withoutOptions_isThe550URL() throws {
        XCTAssertEqual(try historyURL().absoluteString,
                       "https://go.test/embed/tickets?widgetId=w1&theme=auto&accent=%2322c55e#access=tok.1")
        XCTAssertEqual(try historyURL(token: nil).absoluteString,
                       "https://go.test/embed/tickets?widgetId=w1&theme=auto&accent=%2322c55e")
    }

    func test_historyURL_addsEachOptionWhenSet() throws {
        let id = "6F1A2B3C-4d5e-4f60-8a9b-0c1d2e3f4a5b"
        let url = try historyURL(ticketId: id, readOnlyFinished: true, statuses: ["resolved", "closed"], limit: 20)
        XCTAssertEqual(url.query, "widgetId=w1&theme=auto&accent=%2322c55e&ticketId=\(id)&readOnlyFinished=1&statuses=resolved,closed&limit=20")
        XCTAssertEqual(url.fragment, "access=tok.1")
        XCTAssertEqual(try historyURL(activeOnly: true).query, "widgetId=w1&theme=auto&accent=%2322c55e&activeOnly=1")
    }

    func test_historyURL_dropsWhatTheServerWouldRefuse() throws {
        let base = "widgetId=w1&theme=auto&accent=%2322c55e"
        // Not a UUID (incl. an injection attempt) → no ticketId.
        for bad in ["t1", "", "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b&widgetId=x", "6f1a2b3c4d5e4f608a9b0c1d2e3f4a5b"] {
            XCTAssertEqual(try historyURL(ticketId: bad).query, base, bad)
        }
        XCTAssertEqual(try historyURL(statuses: ["archived", "OPEN"]).query, base)
        XCTAssertEqual(try historyURL(statuses: []).query, base)
        XCTAssertEqual(try historyURL(statuses: ["open", "archived", "open"]).query, base + "&statuses=open")
        XCTAssertEqual(try historyURL(statuses: ["open"], activeOnly: true).query, base + "&activeOnly=1")
        XCTAssertEqual(try historyURL(limit: 0).query, base)
        XCTAssertEqual(try historyURL(limit: 51).query, base)
        XCTAssertEqual(try historyURL(readOnlyFinished: false).query, base)
    }
}
