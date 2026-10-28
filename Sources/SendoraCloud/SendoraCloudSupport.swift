//
// SendoraCloudSupport.swift
//
// Wave 66 — Contact widget for iOS apps. Opens the worker-hosted
// embed at `https://go.sendoracloud.com/embed/contact?widgetId=…`
// inside a WKWebView wrapped in a UIViewController, presented
// modally. The HTML form posts to `POST /widgets/:id/submit` —
// same backend the web widget.js uses.
//
// On submit success the embed page navigates to
// `sendora://close?ticketId=…&portalUrl=…`. Our WKNavigationDelegate
// catches the scheme, cancels the navigation, parses the query,
// dismisses the modal, and fires the host's completion callback.
//
// 5.5.0 (s58.376, parity RN 1.42.0) — the API half works on every platform (not just UIKit):
//   - `createTicket(…)` sends the signed-in player's access token, so the ticket carries their VERIFIED user id;
//   - `listMyTickets` / `getMyTicket` / `replyToMyTicket` — the player's own conversations, for a native support
//     screen; refusals throw `SendoraSupportError` (never an empty list);
//   - `deviceContext()` — app version + build, OS + version, device model, SDK version;
//   - the contact widget takes `metadata`, `includeDeviceContext`, `attachSession`, `accent`; the token and the
//     metadata ride the URL FRAGMENT (never logged by a server).
// Support calls now use the CONFIGURED API base URL (they always went to production, even on a staging config).
// Unreleased (s58.406): `listMyTickets(widgetId:statuses:activeOnly:limit:)` (first page; client-side
// `INVALID_ARGUMENT`) + `listMyTicketsPage(widgetId:cursor:limit:statuses:activeOnly:)` (cursor paging),
// `createTicket` 409 `ACTIVE_TICKET_EXISTS` → `SendoraSupportError.activeTicketId`, and `presentTicketHistory`
// `ticketId:` / `readOnlyFinished:` / `statuses:` / `activeOnly:` / `limit:` (pure builder `ticketHistoryURL`).
//

import Foundation
#if canImport(UIKit)
import UIKit
import WebKit
#endif

public struct SendoraContactResult {
    /// UUID of the ticket created server-side. Empty if the user closed
    /// without submitting.
    public let ticketId: String
    /// Operator's tracking-portal URL for the ticket (or nil when the
    /// user closed without submitting).
    public let portalUrl: URL?
    /// True if the user submitted the form; false if they just closed.
    public let submitted: Bool
}

public enum SendoraContactError: Error {
    case notConfigured
    case invalidWidgetId
    case missingPresenter
    /// Wave 69: presentTicketHistory needs an active SDK auth session.
    case notSignedIn
}

/// 5.5.0 — a refused support call. `code` is the server's (`PROJECT_MISMATCH`, `NOT_FOUND`, `UNAUTHORIZED`, …) or
/// the SDK's own: `NOT_CONFIGURED`, `NOT_SIGNED_IN`, `NETWORK`, `BAD_RESPONSE`, `HTTP_<status>`, `INVALID_ARGUMENT`
/// (an option the SDK refused before sending anything).
public struct SendoraSupportError: Error, LocalizedError, Equatable {
    public let code: String
    public let status: Int
    public let message: String
    /// Unreleased (s58.406) — with `code == "ACTIVE_TICKET_EXISTS"` (409 from `createTicket`): the id of the player's
    /// ticket that is still open, so the app can open it instead (`getMyTicket` /
    /// `presentTicketHistory(ticketId:)`). nil for every other error.
    public let activeTicketId: String?
    public var errorDescription: String? { message }
    public init(code: String, status: Int, message: String) {
        self.init(code: code, status: status, message: message, activeTicketId: nil)
    }
    /// Unreleased (s58.406).
    public init(code: String, status: Int, message: String, activeTicketId: String?) {
        self.code = code
        self.status = status
        self.message = message
        self.activeTicketId = activeTicketId
    }
}

/// 5.5.0 — one of the player's tickets (`listMyTickets`). Status: `open` → `pending` → `resolved` / `closed`.
public struct SendoraMyTicketSummary: Equatable {
    public let id: String
    public let subject: String
    public let status: String
    public let priority: String
    /// ISO-8601.
    public let createdAt: String
    /// ISO-8601 — the last activity (a reply, a status change).
    public let updatedAt: String
    public let resolvedAt: String?
    /// Activity the player has not opened yet (`getMyTicket` clears it).
    public let unread: Bool
}

/// Unreleased (s58.406) — one page of `listMyTicketsPage`. `nextCursor` is nil on the last page (and from an older
/// server that does not page — its one answer is the whole list); otherwise pass it back as `cursor:` for the next.
public struct SendoraMyTicketPage: Equatable {
    public let tickets: [SendoraMyTicketSummary]
    public let nextCursor: String?
}

/// 5.5.0 — a public reply on a ticket. `authorType`: `customer` (the player) or `agent` (your team).
public struct SendoraMyTicketReply: Equatable {
    public let id: String
    public let body: String
    public let authorType: String
    public let createdAt: String
}

/// 5.5.0 — one ticket with its public replies (internal notes are never returned).
public struct SendoraMyTicket: Equatable {
    public let id: String
    public let subject: String
    /// The player's first message.
    public let body: String
    public let status: String
    public let priority: String
    public let createdAt: String
    public let updatedAt: String
    public let resolvedAt: String?
    public let replies: [SendoraMyTicketReply]
}

/// 5.5.0 — the result of `replyToMyTicket`. A resolved / closed ticket reopens (`reopened == true`).
public struct SendoraTicketReplyResult: Equatable {
    public let id: String
    public let createdAt: String
    public let reopened: Bool
}

/// 5.5.0 — the result of `createTicket`.
public struct SendoraCreatedTicket: Equatable {
    public let id: String
    public let subject: String
    public let status: String
    public let priority: String
    /// True when the ticket's user id came from the player's signed-in session.
    public let userIdVerified: Bool
}

public final class SendoraCloudSupport: @unchecked Sendable {
    private let widgetEmbedHost: URL
    private let apiBaseUrl: URL
    private let client: APIClient?
    /// The signed-in player's access token, or nil. A seam for tests; production reads `SendoraCloud.auth`.
    private let tokenProvider: (@escaping (String?) -> Void) -> Void

    internal init(widgetEmbedHost: URL = URL(string: "https://go.sendoracloud.com")!,
                  apiBaseUrl: URL = URL(string: "https://api.sendoracloud.com")!,
                  client: APIClient? = nil,
                  tokenProvider: ((@escaping (String?) -> Void) -> Void)? = nil) {
        self.widgetEmbedHost = widgetEmbedHost
        self.apiBaseUrl = apiBaseUrl
        self.client = client
        self.tokenProvider = tokenProvider ?? { done in
            guard let auth = SendoraCloud.auth else { done(nil); return }
            auth.getAccessToken { done($0) }
        }
    }

    // MARK: - Metadata + device context (5.5.0)

    /// The backend's metadata rules, applied on the device so a bad entry never costs the player their message (the
    /// server refuses the whole ticket with a 422): ≤ 30 keys of letters, digits, space, `_ . -` (max 64), values
    /// String (≤ 1000 chars) / finite number / Bool / NSNull. Anything else is DROPPED. Keys are taken in sorted
    /// order so the cap is deterministic.
    public static func sanitizeMetadata(_ input: [String: Any]?) -> [String: Any] {
        guard let input = input else { return [:] }
        var out: [String: Any] = [:]
        for key in input.keys.sorted() {
            if out.count >= 30 { break }
            guard key.range(of: "^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$", options: .regularExpression) != nil,
                  let value = input[key] else { continue }
            if value is NSNull {
                out[key] = NSNull()
            } else if let s = value as? String {
                out[key] = String(s.prefix(1000))
            } else if let n = value as? NSNumber {
                if CFGetTypeID(n) == CFBooleanGetTypeID() {
                    out[key] = n.boolValue
                } else if n.doubleValue.isFinite {
                    out[key] = n
                }
            }
        }
        return out
    }

    /// App version + build, OS + version, device model (e.g. `iPhone15,2`) and SDK version — ready to merge into
    /// `createTicket(metadata:)`. The contact widget attaches it by itself.
    public func deviceContext() -> [String: Any] {
        var out: [String: Any] = [:]
        let info = Bundle.main.infoDictionary
        if let v = info?["CFBundleShortVersionString"] as? String, !v.isEmpty { out["appVersion"] = v }
        if let b = info?["CFBundleVersion"] as? String, !b.isEmpty { out["appBuild"] = b }
        #if canImport(UIKit) && !os(watchOS)
        out["os"] = "iOS"
        out["osVersion"] = UIDevice.current.systemVersion
        #else
        out["os"] = "macOS"
        let v = ProcessInfo.processInfo.operatingSystemVersion
        out["osVersion"] = "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
        #endif
        var sys = utsname()
        uname(&sys)
        let machine = withUnsafeBytes(of: &sys.machine) { raw in
            String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
        if !machine.isEmpty { out["deviceModel"] = machine }
        out["sdk"] = "\(SendoraCloud.sdkName)@\(SendoraCloud.sdkVersion)"
        return out
    }

    /// The hosted contact form's URL. Token + metadata go in the FRAGMENT (no server sees or logs it); the accent in
    /// the query only when it is a hex colour.
    internal static func contactURL(host: URL, widgetId: String, theme: String, prefillName: String?,
                                    prefillEmail: String?, prefillUserId: String?, lockEmail: Bool,
                                    accent: String?, accessToken: String?, metadata: [String: Any]) -> URL? {
        var components = URLComponents(url: host.appendingPathComponent("/embed/contact"), resolvingAgainstBaseURL: false)
        var items: [URLQueryItem] = [
            URLQueryItem(name: "widgetId", value: widgetId),
            URLQueryItem(name: "theme", value: theme),
        ]
        if let n = prefillName, !n.isEmpty { items.append(URLQueryItem(name: "prefillName", value: n)) }
        if let e = prefillEmail, !e.isEmpty { items.append(URLQueryItem(name: "prefillEmail", value: e)) }
        if let u = prefillUserId, !u.isEmpty { items.append(URLQueryItem(name: "prefillUserId", value: u)) }
        if lockEmail, let e = prefillEmail, !e.isEmpty { items.append(URLQueryItem(name: "lockEmail", value: "1")) }
        if let a = accent, isHexColor(a) { items.append(URLQueryItem(name: "accent", value: a)) }
        components?.queryItems = items
        guard let base = components?.url else { return nil }
        let fragment = fragmentString(accessToken: accessToken, metadata: metadata)
        return fragment.isEmpty ? base : URL(string: base.absoluteString + "#" + fragment)
    }

    internal static func isHexColor(_ s: String) -> Bool {
        s.range(of: "^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$", options: .regularExpression) != nil
    }

    private static let fragmentAllowed: CharacterSet = {
        var set = CharacterSet.alphanumerics
        set.insert(charactersIn: "-._~")
        return set
    }()

    internal static func fragmentString(accessToken: String?, metadata: [String: Any]) -> String {
        var parts: [String] = []
        if let t = accessToken, !t.isEmpty, let e = t.addingPercentEncoding(withAllowedCharacters: fragmentAllowed) {
            parts.append("access=" + e)
        }
        if !metadata.isEmpty,
           let data = try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys]),
           let json = String(data: data, encoding: .utf8),
           let e = json.addingPercentEncoding(withAllowedCharacters: fragmentAllowed) {
            parts.append("metadata=" + e)
        }
        return parts.joined(separator: "&")
    }

    // MARK: - API (5.5.0)

    private func token() async -> String? {
        await withCheckedContinuation { (cont: CheckedContinuation<String?, Never>) in
            tokenProvider { cont.resume(returning: ($0?.isEmpty == false) ? $0 : nil) }
        }
    }

    private func requireClient() throws -> APIClient {
        guard let client = client else {
            throw SendoraSupportError(code: "NOT_CONFIGURED", status: 0, message: "SendoraCloud.configure() must run first.")
        }
        return client
    }

    private func bearer(_ verb: String) async throws -> [String: String] {
        guard let t = await token() else {
            throw SendoraSupportError(code: "NOT_SIGNED_IN", status: 401, message: "support.\(verb)() needs a signed-in (or guest) session.")
        }
        return ["Authorization": "Bearer \(t)"]
    }

    private static func myTicketsPath(_ widgetId: String) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "/")
        return "/widgets/\(widgetId.addingPercentEncoding(withAllowedCharacters: allowed) ?? widgetId)/my-tickets"
    }

    /// Unwrap `{ success, data }` or throw the server's refusal — never an empty answer for a failure.
    private static func data(_ json: [String: Any]?, _ verb: String) throws -> Any {
        guard let json = json else {
            throw SendoraSupportError(code: "NETWORK", status: 0, message: "support.\(verb)() could not reach the server.")
        }
        if json["success"] as? Bool == true, let data = json["data"] {
            return data
        }
        let error = json["error"] as? [String: Any]
        let status = error?["status"] as? Int ?? 0
        let code = error?["code"] as? String ?? "HTTP_\(status)"
        // 409 ACTIVE_TICKET_EXISTS names the player's open ticket in `error.details.ticketId`.
        let activeTicketId = code == "ACTIVE_TICKET_EXISTS"
            ? ((error?["details"] as? [String: Any])?["ticketId"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            : nil
        throw SendoraSupportError(
            code: code,
            status: status,
            message: error?["message"] as? String ?? "support.\(verb)() failed (\(status))",
            activeTicketId: activeTicketId
        )
    }

    // MARK: - Ticket filters (Unreleased, s58.406)

    /// The ticket states the server knows, in its own order.
    internal static let knownTicketStatuses: [String] = ["open", "pending", "resolved", "closed"]
    internal static let maxTicketsLimit = 50

    internal static func isUUID(_ s: String) -> Bool {
        s.range(of: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                options: .regularExpression) != nil
    }

    private static func invalid(_ message: String) -> SendoraSupportError {
        SendoraSupportError(code: "INVALID_ARGUMENT", status: 0, message: message)
    }

    /// A cursor is opaque: every byte outside the unreserved set is percent-encoded (`+`, `/`, `=`, `&` included).
    private static let cursorAllowed: CharacterSet = {
        var set = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        set.insert(charactersIn: "-._~")
        return set
    }()

    /// The `/my-tickets` query for the given options, or "" with none. Refuses (nothing is sent) a `limit` outside
    /// 1…50, an empty or unknown status, `statuses` together with `activeOnly` (the server answers that with 422),
    /// and an empty `cursor`. Order: `statuses`, `activeOnly`, `limit`, `cursor` (percent-encoded).
    internal static func myTicketsQuery(statuses: [String]?, activeOnly: Bool, limit: Int?,
                                        cursor: String? = nil) throws -> String {
        var items: [String] = []
        if let statuses = statuses {
            if activeOnly {
                throw invalid("support.listMyTickets(): pass statuses OR activeOnly, not both.")
            }
            if statuses.isEmpty {
                throw invalid("support.listMyTickets(): statuses must name at least one of open, pending, resolved, closed.")
            }
            var seen: [String] = []
            for s in statuses {
                guard knownTicketStatuses.contains(s) else {
                    throw invalid("support.listMyTickets(): unknown status \"\(s)\" (open, pending, resolved, closed).")
                }
                if !seen.contains(s) { seen.append(s) }
            }
            items.append("statuses=" + seen.joined(separator: ","))
        }
        if activeOnly { items.append("activeOnly=true") }
        if let limit = limit {
            guard (1...maxTicketsLimit).contains(limit) else {
                throw invalid("support.listMyTickets(): limit must be 1–\(maxTicketsLimit) (got \(limit)).")
            }
            items.append("limit=\(limit)")
        }
        if let cursor = cursor {
            guard !cursor.isEmpty, let encoded = cursor.addingPercentEncoding(withAllowedCharacters: cursorAllowed) else {
                throw invalid("support.listMyTicketsPage(): cursor must be a non-empty nextCursor from the previous page.")
            }
            items.append("cursor=" + encoded)
        }
        return items.isEmpty ? "" : "?" + items.joined(separator: "&")
    }

    /// The hosted ticket-history page's URL. The access token rides the FRAGMENT (no server sees or logs it). The
    /// options are lenient — the screen must always open: `ticketId` only when it is a UUID, `statuses` keep only the
    /// known values (omitted when none is left, and when `activeOnly` is on), `limit` only within 1…50, the flags only
    /// when true. With no options the URL is the one 5.5.0 built.
    internal static func ticketHistoryURL(host: URL, widgetId: String, theme: String, accent: String?,
                                          accessToken: String?, ticketId: String?, readOnlyFinished: Bool,
                                          statuses: [String]?, activeOnly: Bool, limit: Int?) -> URL? {
        guard var components = URLComponents(url: host.appendingPathComponent("/embed/tickets"),
                                             resolvingAgainstBaseURL: false) else { return nil }
        var items = [
            URLQueryItem(name: "widgetId", value: widgetId),
            URLQueryItem(name: "theme", value: theme),
        ]
        if let a = accent, isHexColor(a) { items.append(URLQueryItem(name: "accent", value: a)) }
        if let t = ticketId, isUUID(t) { items.append(URLQueryItem(name: "ticketId", value: t)) }
        if readOnlyFinished { items.append(URLQueryItem(name: "readOnlyFinished", value: "1")) }
        if activeOnly {
            items.append(URLQueryItem(name: "activeOnly", value: "1"))
        } else if let statuses = statuses {
            var kept: [String] = []
            for s in statuses where knownTicketStatuses.contains(s) && !kept.contains(s) { kept.append(s) }
            if !kept.isEmpty { items.append(URLQueryItem(name: "statuses", value: kept.joined(separator: ","))) }
        }
        if let l = limit, (1...maxTicketsLimit).contains(l) { items.append(URLQueryItem(name: "limit", value: String(l))) }
        components.queryItems = items
        guard var url = components.url else { return nil }
        // JWT goes in the fragment so it doesn't appear in server logs / referer headers. The embed HTML scrubs the
        // hash via history.replaceState on load.
        if let token = accessToken, !token.isEmpty,
           let escaped = token.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed),
           let withToken = URL(string: url.absoluteString + "#access=" + escaped) {
            url = withToken
        }
        return url
    }

    private func call(_ method: String, _ path: String, body: [String: Any]?, headers: [String: String]?) async throws -> [String: Any]? {
        let client = try requireClient()
        return await withCheckedContinuation { (cont: CheckedContinuation<[String: Any]?, Never>) in
            if method == "POST" {
                client.post(path: path, body: body ?? [:], headers: headers) { cont.resume(returning: $0) }
            } else {
                client.get(path: path, headers: headers) { cont.resume(returning: $0) }
            }
        }
    }

    private static func string(_ o: [String: Any], _ k: String) -> String { o[k] as? String ?? "" }

    private static func summary(_ o: [String: Any]) -> SendoraMyTicketSummary {
        SendoraMyTicketSummary(id: string(o, "id"), subject: string(o, "subject"), status: string(o, "status"),
                               priority: string(o, "priority"), createdAt: string(o, "createdAt"),
                               updatedAt: string(o, "updatedAt"), resolvedAt: o["resolvedAt"] as? String,
                               unread: o["unread"] as? Bool ?? false)
    }

    /// Open a ticket from your own Contact-us screen. Signed in (guest or account), the player's token is sent, so
    /// the ticket carries their VERIFIED user id; without a session it is still created and a `userId` you pass is
    /// shown to agents as "reported by the app, not verified". `metadata`: see `sanitizeMetadata` / `deviceContext()`.
    /// When the server refuses a new ticket because the player already has an active one, this throws code
    /// `ACTIVE_TICKET_EXISTS` (409) with `activeTicketId` set — open that ticket instead.
    public func createTicket(
        subject: String,
        body: String,
        priority: String? = nil,
        category: String? = nil,
        email: String? = nil,
        userId: String? = nil,
        metadata: [String: Any]? = nil
    ) async throws -> SendoraCreatedTicket {
        var payload: [String: Any] = ["subject": subject, "body": body]
        if let v = priority { payload["priority"] = v }
        if let v = category { payload["category"] = v }
        if let v = email { payload["email"] = v }
        if let v = userId { payload["userId"] = v }
        if let m = metadata { payload["metadata"] = Self.sanitizeMetadata(m) }
        let t = await token()
        let json = try await call("POST", "/support/tickets", body: payload, headers: t.map { ["Authorization": "Bearer \($0)"] })
        guard let d = try Self.data(json, "createTicket") as? [String: Any] else {
            throw SendoraSupportError(code: "BAD_RESPONSE", status: 0, message: "support.createTicket(): unexpected response")
        }
        return SendoraCreatedTicket(id: Self.string(d, "id"), subject: Self.string(d, "subject"), status: Self.string(d, "status"),
                                    priority: Self.string(d, "priority"), userIdVerified: d["userIdVerified"] as? Bool ?? false)
    }

    /// The signed-in player's tickets (newest activity first, up to 50 — the server's first page; page through all of
    /// them with `listMyTicketsPage`). `widgetId` = a contact widget of THIS app's project. Throws
    /// `SendoraSupportError` (`NOT_SIGNED_IN`, `PROJECT_MISMATCH`, …).
    public func listMyTickets(widgetId: String) async throws -> [SendoraMyTicketSummary] {
        try await listMyTickets(widgetId: widgetId, statuses: nil, activeOnly: false, limit: nil)
    }

    /// Unreleased (s58.406) — the FIRST page of `listMyTickets`, filtered (newest activity first). For the rest, use
    /// `listMyTicketsPage` and its `nextCursor`. Each option goes on the query only when given.
    /// - `statuses`: any of `open`, `pending`, `resolved`, `closed` (non-empty).
    /// - `activeOnly`: only `open` / `pending` tickets. Not together with `statuses`.
    /// - `limit`: page size, 1…50 (server default 50) — never more rows than that.
    /// A bad option throws `SendoraSupportError` code `INVALID_ARGUMENT` and sends nothing.
    public func listMyTickets(
        widgetId: String,
        statuses: [String]? = nil,
        activeOnly: Bool = false,
        limit: Int? = nil
    ) async throws -> [SendoraMyTicketSummary] {
        try await listMyTicketsPage(widgetId: widgetId, cursor: nil, limit: limit, statuses: statuses,
                                    activeOnly: activeOnly).tickets
    }

    /// Unreleased (s58.406) — one page of the player's tickets (newest activity first). Pass nil `cursor` for the first
    /// page, then each page's `nextCursor` until it is nil. Keep `limit` / `statuses` / `activeOnly` the same across a
    /// walk. `cursor` must be a non-empty `nextCursor` — an empty one, like any other bad option (see
    /// `listMyTickets(widgetId:statuses:activeOnly:limit:)`), throws `INVALID_ARGUMENT` and sends nothing.
    /// From an older server that does not page, `nextCursor` is nil and the one page is the whole list.
    public func listMyTicketsPage(
        widgetId: String,
        cursor: String? = nil,
        limit: Int? = nil,
        statuses: [String]? = nil,
        activeOnly: Bool = false
    ) async throws -> SendoraMyTicketPage {
        let query = try Self.myTicketsQuery(statuses: statuses, activeOnly: activeOnly, limit: limit, cursor: cursor)
        let headers = try await bearer("listMyTickets")
        let json = try await call("GET", Self.myTicketsPath(widgetId) + query, body: nil, headers: headers)
        guard let rows = try Self.data(json, "listMyTickets") as? [[String: Any]] else {
            throw SendoraSupportError(code: "BAD_RESPONSE", status: 0, message: "support.listMyTickets(): unexpected response")
        }
        // `pagination` sits beside `data` in the envelope; absent (an older server) → one page, no cursor.
        let next = ((json?["pagination"] as? [String: Any])?["nextCursor"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        return SendoraMyTicketPage(tickets: rows.map(Self.summary), nextCursor: next)
    }

    /// One ticket with its public replies. Marks it read (it drops out of the unread count).
    public func getMyTicket(widgetId: String, ticketId: String) async throws -> SendoraMyTicket {
        let headers = try await bearer("getMyTicket")
        let path = Self.myTicketsPath(widgetId) + "/" + (ticketId.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-"))) ?? ticketId)
        let json = try await call("GET", path, body: nil, headers: headers)
        guard let d = try Self.data(json, "getMyTicket") as? [String: Any] else {
            throw SendoraSupportError(code: "BAD_RESPONSE", status: 0, message: "support.getMyTicket(): unexpected response")
        }
        let replies = (d["replies"] as? [[String: Any]] ?? []).map {
            SendoraMyTicketReply(id: Self.string($0, "id"), body: Self.string($0, "body"),
                                 authorType: Self.string($0, "authorType"), createdAt: Self.string($0, "createdAt"))
        }
        return SendoraMyTicket(id: Self.string(d, "id"), subject: Self.string(d, "subject"), body: Self.string(d, "body"),
                               status: Self.string(d, "status"), priority: Self.string(d, "priority"),
                               createdAt: Self.string(d, "createdAt"), updatedAt: Self.string(d, "updatedAt"),
                               resolvedAt: d["resolvedAt"] as? String, replies: replies)
    }

    /// The player replies. A resolved / closed ticket reopens (`reopened == true`).
    public func replyToMyTicket(widgetId: String, ticketId: String, body: String) async throws -> SendoraTicketReplyResult {
        let headers = try await bearer("replyToMyTicket")
        let path = Self.myTicketsPath(widgetId) + "/" + (ticketId.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-"))) ?? ticketId) + "/replies"
        let json = try await call("POST", path, body: ["body": body], headers: headers)
        guard let d = try Self.data(json, "replyToMyTicket") as? [String: Any] else {
            throw SendoraSupportError(code: "BAD_RESPONSE", status: 0, message: "support.replyToMyTicket(): unexpected response")
        }
        return SendoraTicketReplyResult(id: Self.string(d, "id"), createdAt: Self.string(d, "createdAt"), reopened: d["reopened"] as? Bool ?? false)
    }

    /// Wave 73 — fetch the unread ticket count for the support tab
    /// badge. Bearer JWT auth via the SDK's current end-user session.
    /// Returns 0 when no SDK auth exists (anon or identified), or on any failure (safe to poll).
    ///
    /// Recommended polling cadence: on app foreground + every 60s
    /// while the app is active. Host app renders the resulting count
    /// as a tab badge / dot.
    public func getUnreadCount(
        widgetId: String,
        completion: @escaping (Int) -> Void
    ) {
        guard !widgetId.isEmpty, let client = client else { completion(0); return }
        tokenProvider { token in
            guard let token = token, !token.isEmpty else {
                DispatchQueue.main.async { completion(0) }
                return
            }
            // 5.6.0: through the SDK's `APIClient` like every other call — it went out
            // on `URLSession.shared`, i.e. with NO `X-API-Key` / SDK headers, the shared
            // cookie jar, no pinning and outside the breaker.
            client.get(path: Self.myTicketsPath(widgetId) + "/unread-count", headers: ["Authorization": "Bearer \(token)"]) { json in
                var count = 0
                if json?["success"] as? Bool == true,
                   let inner = json?["data"] as? [String: Any],
                   let n = inner["count"] as? Int {
                    count = n
                }
                DispatchQueue.main.async { completion(count) }
            }
        }
    }
}

#if canImport(UIKit)
extension SendoraCloudSupport {
    /// Open the in-app ticket history list (Wave 69).
    ///
    /// Requires an active SDK auth session (anon or identified). The
    /// SDK passes the current access token via URL hash fragment so
    /// the embed can call backend `/widgets/:widgetId/my-tickets*`
    /// endpoints as the signed-in end user.
    ///
    /// Returns `.failure(.notSignedIn)` if there's no auth row.
    /// - Parameters:
    ///   - accent: 5.5.0 — `#rgb` / `#rrggbb`; default = the widget's dashboard accent.
    ///   - ticketId: Unreleased (s58.406) — open this ticket directly (ignored unless it is a UUID).
    ///   - readOnlyFinished: Unreleased — resolved / closed tickets are shown read-only (no reply box).
    ///   - statuses: Unreleased — list only these (`open`, `pending`, `resolved`, `closed`; unknown values dropped).
    ///   - activeOnly: Unreleased — list only open / pending tickets (wins over `statuses`).
    ///   - limit: Unreleased — page size of the hosted list, 1…50 (ignored outside that range); the page shows
    ///     "Load more" for the rest.
    ///   Each goes on the page's URL only when set; the screen always opens.
    @MainActor
    public func presentTicketHistory(
        widgetId: String,
        from presenter: UIViewController,
        theme: String = "auto",
        accent: String? = nil,
        ticketId: String? = nil,
        readOnlyFinished: Bool = false,
        statuses: [String]? = nil,
        activeOnly: Bool = false,
        limit: Int? = nil,
        completion: ((Result<SendoraContactResult, SendoraContactError>) -> Void)? = nil
    ) {
        guard !widgetId.isEmpty else {
            completion?(.failure(.invalidWidgetId))
            return
        }
        guard SendoraCloud.auth != nil else {
            completion?(.failure(.notSignedIn))
            return
        }

        tokenProvider { [weak presenter] token in
            Task { @MainActor in
                guard let presenter = presenter else { return }
                guard let token = token, !token.isEmpty else {
                    completion?(.failure(.notSignedIn))
                    return
                }

                guard let url = Self.ticketHistoryURL(host: self.widgetEmbedHost, widgetId: widgetId, theme: theme,
                                                      accent: accent, accessToken: token, ticketId: ticketId,
                                                      readOnlyFinished: readOnlyFinished, statuses: statuses,
                                                      activeOnly: activeOnly, limit: limit) else {
                    completion?(.failure(.invalidWidgetId))
                    return
                }

                let vc = SendoraContactWidgetViewController(url: url, completion: completion)
                if #available(iOS 15.0, *) {
                    if let sheet = vc.sheetPresentationController {
                        sheet.detents = [.large()]
                        sheet.prefersGrabberVisible = true
                    }
                }
                presenter.present(vc, animated: true)
            }
        }
    }

    /// Open the contact widget modally over `presenter`.
    ///
    /// Identity handling (Wave 68): the widget auto-reads the SDK's
    /// current user state from `SendoraCloud.auth?.getCurrentUser()`
    /// when the caller doesn't override the prefill params:
    ///
    ///   - identified user (has verified email) → email field hidden,
    ///     read-only chip shown, `userId` posted with the ticket so it
    ///     stitches to the same profile as analytics events.
    ///   - anonymous SDK row (userId only, no email) → email field
    ///     shown for entry, anon `userId` posted.
    ///   - no SDK auth at all → standard form, no `userId`.
    ///
    /// - Parameters:
    ///   - widgetId: UUID of the widget configured in the Sendora
    ///     dashboard. Bot-check + rate-limit run server-side on submit.
    ///   - presenter: View controller used to present the modal sheet.
    ///   - theme: `"auto"`, `"light"`, or `"dark"`.
    ///   - prefillName / prefillEmail / prefillUserId: Optional overrides.
    ///     Default: read from `SendoraCloud.auth?.getCurrentUser()`.
    ///   - lockEmail: When true (and an email is prefilled), the email
    ///     field is hidden + read-only.
    ///   - metadata: 5.5.0 — extra details for your agents, shown on the ticket as "details from the app". See
    ///     `sanitizeMetadata` (invalid entries are dropped, never block the player).
    ///   - includeDeviceContext: 5.5.0 — attach `deviceContext()` (your `metadata` wins on a key clash). Default true.
    ///   - attachSession: 5.5.0 — send the player's access token so the ticket carries their VERIFIED user id.
    ///     Default true; a missing token still opens the form.
    ///   - accent: 5.5.0 — `#rgb` / `#rrggbb`; default = the widget's dashboard accent.
    ///   - completion: Fired when the user closes the sheet — either
    ///     after a successful submit (`submitted = true`) or via close
    ///     button (`submitted = false`).
    @MainActor
    public func presentContactWidget(
        widgetId: String,
        from presenter: UIViewController,
        theme: String = "auto",
        prefillName: String? = nil,
        prefillEmail: String? = nil,
        prefillUserId: String? = nil,
        lockEmail: Bool? = nil,
        metadata: [String: Any]? = nil,
        includeDeviceContext: Bool = true,
        attachSession: Bool = true,
        accent: String? = nil,
        completion: ((Result<SendoraContactResult, SendoraContactError>) -> Void)? = nil
    ) {
        guard !widgetId.isEmpty else {
            completion?(.failure(.invalidWidgetId))
            return
        }

        // Auto-resolve identity from SDK auth state when caller didn't
        // override. `SendoraCloud.auth?.currentUser` returns the anon
        // or identified row that's currently signed in.
        let sdkUser = SendoraCloud.auth?.currentUser
        let resolvedName = prefillName ?? sdkUser?.name
        let resolvedEmail = prefillEmail ?? sdkUser?.email
        let resolvedUserId = prefillUserId ?? sdkUser?.id
        // Lock the email field when we have a verified email on file
        // (identified user) and the caller didn't explicitly override.
        // Anonymous rows have no email so this naturally stays false.
        let resolvedLockEmail: Bool = lockEmail ?? (
            sdkUser?.email != nil
            && sdkUser?.emailVerified == true
            && sdkUser?.isAnonymous == false
        )
        var merged: [String: Any] = includeDeviceContext ? deviceContext() : [:]
        for (k, v) in metadata ?? [:] { merged[k] = v }
        let context = Self.sanitizeMetadata(merged)

        let open: (String?) -> Void = { [weak presenter] token in
            guard let presenter = presenter else { return }
            guard let url = Self.contactURL(host: self.widgetEmbedHost, widgetId: widgetId, theme: theme,
                                            prefillName: resolvedName, prefillEmail: resolvedEmail,
                                            prefillUserId: resolvedUserId, lockEmail: resolvedLockEmail,
                                            accent: accent, accessToken: token, metadata: context) else {
                completion?(.failure(.invalidWidgetId))
                return
            }
            let vc = SendoraContactWidgetViewController(url: url, completion: completion)
            if #available(iOS 15.0, *) {
                if let sheet = vc.sheetPresentationController {
                    sheet.detents = [.large()]
                    sheet.prefersGrabberVisible = true
                }
            }
            presenter.present(vc, animated: true)
        }
        guard attachSession else { open(nil); return }
        // A token problem never keeps the player from reaching support.
        tokenProvider { token in
            Task { @MainActor in open(token) }
        }
    }
}

// MARK: - Internal view controller

@MainActor
internal final class SendoraContactWidgetViewController: UIViewController, WKNavigationDelegate {
    private let targetUrl: URL
    private var webView: WKWebView!
    private var completion: ((Result<SendoraContactResult, SendoraContactError>) -> Void)?
    private var didFire = false

    init(url: URL,
         completion: ((Result<SendoraContactResult, SendoraContactError>) -> Void)?) {
        self.targetUrl = url
        self.completion = completion
        super.init(nibName: nil, bundle: nil)
        modalPresentationStyle = .formSheet
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) unsupported") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        let config = WKWebViewConfiguration()
        // Bridge contact form → native dismiss. We catch the
        // `sendora://close` redirect in the navigation delegate; no
        // postMessage handler needed.
        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        webView.navigationDelegate = self
        view.addSubview(webView)
        webView.load(URLRequest(url: targetUrl))
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.allow); return
        }
        if url.scheme == "sendora" && url.host == "close" {
            decisionHandler(.cancel)
            handleCloseRedirect(url: url)
            return
        }
        // First-party HTTPS only — refuse off-domain navigations
        // inside the embed (e.g. if a customer-supplied welcome
        // message somehow included a link).
        if url.scheme != "https" && url.scheme != "about" {
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    private func handleCloseRedirect(url: URL) {
        if didFire { return }
        didFire = true
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let ticketId = comps?.queryItems?.first(where: { $0.name == "ticketId" })?.value ?? ""
        let portalUrlStr = comps?.queryItems?.first(where: { $0.name == "portalUrl" })?.value ?? ""
        let portalUrl = portalUrlStr.isEmpty ? nil : URL(string: portalUrlStr)
        let submitted = !ticketId.isEmpty
        let result = SendoraContactResult(ticketId: ticketId, portalUrl: portalUrl, submitted: submitted)
        let cb = completion
        completion = nil
        dismiss(animated: true) {
            cb?(.success(result))
        }
    }
}
#endif
