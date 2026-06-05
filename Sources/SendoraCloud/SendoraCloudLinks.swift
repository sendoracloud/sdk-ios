import Foundation
import CryptoKit
#if canImport(UIKit)
import UIKit
#endif

/// Deep link surface for the iOS SDK (s58.50 rewrite — Branch / Firebase parity).
///
/// Mirrors `Sendora.links` on React Native + Android. Surface:
///   • `create(_:completion:)`                         — mint a Sendora short link.
///   • `prewarm(_:key:)` + `create(_:prewarmKey:...)`  — background-mint cache.
///   • `handleUniversalLink(url:completion:)`          — warm-path resolve.
///   • `matchDeferred(_:completion:)`                  — cold-launch deferred match.
///   • `onLinkOpened(_:)`                              — observer (warm + deferred).
///   • `revoke(shortcode:completion:)`                 — soft-delete.
///   • `getStats(shortcode:completion:)`               — totals + breakdowns.
///   • Static `computeDeviceFingerprint()`             — canonical recipe.
///   • Static `decodeLinkData<T:Decodable>(_:)`        — typed access to `linkData`.
public final class SendoraCloudLinks {

    // MARK: - Typed errors

    /// Code taxonomy mirrors RN / Android / backend. Branch on `error.code`
    /// rather than parsing `localizedDescription` strings.
    public enum LinkErrorCode: String {
        case bundleMismatch     = "BUNDLE_MISMATCH"
        case dataTooLarge       = "DATA_TOO_LARGE"
        case expired            = "EXPIRED"
        case network            = "NETWORK"
        case rateLimited        = "RATE_LIMITED"
        case notFound           = "NOT_FOUND"
        case unauthorized       = "UNAUTHORIZED"
        case invalidInput       = "INVALID_INPUT"
        case planLimit          = "PLAN_LIMIT"
        case fallbackRequired   = "FALLBACK_REQUIRED"
        case server             = "SERVER"
        case unknown            = "UNKNOWN"
    }

    public struct LinkError: Error, LocalizedError {
        public let code: LinkErrorCode
        public let message: String
        public let statusCode: Int
        public var errorDescription: String? { return "[LinkError \(code.rawValue)] \(message)" }
        public init(code: LinkErrorCode, message: String, statusCode: Int = 0) {
            self.code = code
            self.message = message
            self.statusCode = statusCode
        }
    }

    private static func mapError(status: Int, code: String?, message: String?) -> LinkError {
        let msg = message ?? "HTTP \(status)"
        if status == 0 { return LinkError(code: .network, message: msg, statusCode: 0) }
        if status == 401 || status == 403 { return LinkError(code: .unauthorized, message: msg, statusCode: status) }
        if status == 404 { return LinkError(code: .notFound, message: msg, statusCode: 404) }
        if status == 410 { return LinkError(code: .expired, message: msg, statusCode: 410) }
        if status == 412 { return LinkError(code: .invalidInput, message: msg, statusCode: 412) }
        if status == 429 { return LinkError(code: .rateLimited, message: msg, statusCode: 429) }
        if status == 422 {
            if msg.range(of: #"(?i)iOS bundle|Android package"#, options: .regularExpression) != nil {
                return LinkError(code: .bundleMismatch, message: msg, statusCode: 422)
            }
            if msg.range(of: #"(?i)2KB|10KB|linkData"#, options: .regularExpression) != nil {
                return LinkError(code: .dataTooLarge, message: msg, statusCode: 422)
            }
            if msg.range(of: #"(?i)fallbackUrl"#, options: .regularExpression) != nil &&
               msg.range(of: #"(?i)apps"#, options: .regularExpression) != nil {
                return LinkError(code: .fallbackRequired, message: msg, statusCode: 422)
            }
            return LinkError(code: .invalidInput, message: msg, statusCode: 422)
        }
        if status == 402 || code == "ENTITLEMENT_ERROR" || msg.range(of: #"(?i)plan limit"#, options: .regularExpression) != nil {
            return LinkError(code: .planLimit, message: msg, statusCode: status)
        }
        if status >= 500 { return LinkError(code: .server, message: msg, statusCode: status) }
        return LinkError(code: .unknown, message: msg, statusCode: status)
    }

    // MARK: - Inputs / outputs

    public struct LinkCreateInput {
        public var title: String
        /// **Optional as of 3.9.0** — backend defaults from the project's
        /// apps registry (web origin > iOS App Store URL > Android Play Store URL).
        public var fallbackUrl: String?
        /// How a **mobile visitor without the app installed** is routed
        /// (Adjust / Branch parity). `"auto"` (default) opens the app store
        /// when one is registered for the platform, else the web
        /// `fallbackUrl`; `"store"` prefers the store; `"web"` forces the web
        /// `fallbackUrl` even when a store URL exists. `nil` inherits the
        /// project default. Desktop is always web.
        public var noAppMode: String?
        public var iosDeepLinkPath: String?
        public var androidDeepLinkPath: String?
        /// Typed linkData. Use `decodeLinkData<T>` on the receiving event
        /// for full Codable round-trip; `[String: Any]` keeps the wire
        /// shape JSON-pure here without forcing every caller into Codable.
        public var linkData: [String: Any]?
        public var ogTitle: String?
        public var ogDescription: String?
        public var ogImageUrl: String?
        public var campaign: String?
        public var source: String?
        public var medium: String?
        public var channel: String?
        public var tags: [String]?
        public var expiresAt: Date?
        public var iosBundleId: String?
        public var androidPackageName: String?

        public init(
            title: String,
            fallbackUrl: String? = nil,
            noAppMode: String? = nil,
            iosDeepLinkPath: String? = nil,
            androidDeepLinkPath: String? = nil,
            linkData: [String: Any]? = nil,
            ogTitle: String? = nil,
            ogDescription: String? = nil,
            ogImageUrl: String? = nil,
            campaign: String? = nil,
            source: String? = nil,
            medium: String? = nil,
            channel: String? = nil,
            tags: [String]? = nil,
            expiresAt: Date? = nil,
            iosBundleId: String? = nil,
            androidPackageName: String? = nil
        ) {
            self.title = title
            self.fallbackUrl = fallbackUrl
            self.noAppMode = noAppMode
            self.iosDeepLinkPath = iosDeepLinkPath
            self.androidDeepLinkPath = androidDeepLinkPath
            self.linkData = linkData
            self.ogTitle = ogTitle
            self.ogDescription = ogDescription
            self.ogImageUrl = ogImageUrl
            self.campaign = campaign
            self.source = source
            self.medium = medium
            self.channel = channel
            self.tags = tags
            self.expiresAt = expiresAt
            self.iosBundleId = iosBundleId
            self.androidPackageName = androidPackageName
        }

        /// Convenience: build a `LinkCreateInput` from any `Encodable` body
        /// for `linkData`. Validates round-trip: rejects non-JSON-object
        /// shapes (arrays / scalars) since the backend stores `linkData`
        /// as JSONB object only.
        public init<T: Encodable>(
            title: String,
            typedLinkData: T,
            fallbackUrl: String? = nil,
            iosDeepLinkPath: String? = nil,
            androidDeepLinkPath: String? = nil,
            ogTitle: String? = nil,
            ogImageUrl: String? = nil
        ) throws {
            let raw = try JSONEncoder().encode(typedLinkData)
            guard let obj = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
                throw LinkError(code: .invalidInput, message: "typedLinkData must encode to a JSON object")
            }
            self.init(
                title: title,
                fallbackUrl: fallbackUrl,
                iosDeepLinkPath: iosDeepLinkPath,
                androidDeepLinkPath: androidDeepLinkPath,
                linkData: obj,
                ogTitle: ogTitle,
                ogImageUrl: ogImageUrl
            )
        }
    }

    public struct LinkCreateResult {
        public let id: String
        public let shortcode: String
        /// Fully-qualified share URL — pass to `UIActivityViewController`.
        public let url: String
        public let iosDeepLinkPath: String?
        public let androidDeepLinkPath: String?
        public let fallbackUrl: String
        public let linkData: [String: Any]
    }

    public struct LinkOpenedEvent {
        public let shortcode: String
        public let linkData: [String: Any]
        public let iosDeepLinkPath: String?
        public let androidDeepLinkPath: String?
        public let isDeferred: Bool

        /// Typed access via Codable. Throws `LinkError(invalidInput)` when
        /// `linkData` doesn't decode into `T`. Saves callers the JSONSerialization
        /// + JSONDecoder dance on every navigation.
        public func decodedLinkData<T: Decodable>(_: T.Type = T.self) throws -> T {
            let raw = try JSONSerialization.data(withJSONObject: linkData)
            return try JSONDecoder().decode(T.self, from: raw)
        }
    }

    public typealias LinkOpenedHandler = (LinkOpenedEvent) -> Void

    public struct DeferredMatchInput {
        public var fingerprintHash: String?
        public var installReferrer: String?
        public init(fingerprintHash: String? = nil, installReferrer: String? = nil) {
            self.fingerprintHash = fingerprintHash
            self.installReferrer = installReferrer
        }
    }

    public struct LinkStats {
        public let totalClicks: Int
        public let uniqueClicks: Int
        public let deferredMatches: Int
        public let byDevice: [(deviceType: String?, count: Int)]
        public let byCountry: [(country: String?, count: Int)]
        public let byOs: [(os: String?, count: Int)]
    }

    // MARK: - State

    private let apiClient: APIClient
    private let bundleId: String?
    private let linkHosts: [String]
    private let lock = NSLock()
    private var handlers: [(token: UUID, handler: LinkOpenedHandler)] = []

    // Prewarm cache — keyed promise-style, single-use entries with TTL.
    private struct PrewarmEntry {
        let result: Result<LinkCreateResult, Error>?
        let waiters: [(Result<LinkCreateResult, Error>) -> Void]
        let createdAt: Date
    }
    private var prewarmCache: [String: PrewarmEntry] = [:]
    private let prewarmTtl: TimeInterval = 5 * 60
    private let prewarmMax = 50
    /// Wave 28 — concurrent-mint cap. A runaway loop calling `prewarm()`
    /// (eg in a SwiftUI List row body) would otherwise burn through the
    /// backend's per-key rate limit + customer's plan quota. 5 inflight
    /// matches real share-row UIs.
    private var prewarmInflight = 0
    private let prewarmMaxInflight = 5

    internal init(apiClient: APIClient, bundleId: String?, linkHosts: [String]) {
        self.apiClient = apiClient
        self.bundleId = bundleId
        self.linkHosts = linkHosts
    }

    internal convenience init(client: APIClient, bundleId: String?, linkHosts: [String]) {
        self.init(apiClient: client, bundleId: bundleId, linkHosts: linkHosts)
    }

    /// Back-compat init — drops linkHosts gating. Prefer the 3-arg init.
    internal convenience init(client: APIClient, bundleId: String?) {
        self.init(apiClient: client, bundleId: bundleId, linkHosts: [])
    }

    // MARK: - Observers

    @discardableResult
    public func onLinkOpened(_ handler: @escaping LinkOpenedHandler) -> UUID {
        let token = UUID()
        lock.lock()
        handlers.append((token, handler))
        lock.unlock()
        return token
    }

    public func removeLinkOpenedHandler(_ token: UUID) {
        lock.lock()
        handlers.removeAll { $0.token == token }
        lock.unlock()
    }

    private func emit(_ event: LinkOpenedEvent) {
        lock.lock()
        let snapshot = handlers
        lock.unlock()
        DispatchQueue.main.async {
            for entry in snapshot {
                entry.handler(event)
            }
        }
    }

    // MARK: - create + prewarm

    private func cacheKey(_ input: LinkCreateInput, override: String?) -> String {
        if let o = override { return "k:\(o)" }
        // Stable hash of the canonical create payload. Avoid relying on
        // dictionary ordering — sort + JSON-encode the resolved body.
        let body = buildCreateBody(input)
        guard let data = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]) else {
            return "k:\(input.title)"
        }
        let digest = SHA256.hash(data: data)
        return "s:" + digest.prefix(12).map { String(format: "%02x", $0) }.joined()
    }

    private func evictExpired() {
        let now = Date()
        let stale = prewarmCache.compactMap { (k, v) -> String? in
            v.createdAt.addingTimeInterval(prewarmTtl) < now ? k : nil
        }
        for k in stale { prewarmCache.removeValue(forKey: k) }
        while prewarmCache.count > prewarmMax {
            // Oldest first.
            if let oldest = prewarmCache.min(by: { $0.value.createdAt < $1.value.createdAt })?.key {
                prewarmCache.removeValue(forKey: oldest)
            } else { break }
        }
    }

    private func buildCreateBody(_ input: LinkCreateInput) -> [String: Any] {
        var body: [String: Any] = ["title": input.title]
        if let v = input.fallbackUrl { body["fallbackUrl"] = v }
        if let v = input.noAppMode { body["noAppMode"] = v }
        if let v = input.iosDeepLinkPath { body["iosDeepLinkPath"] = v }
        if let v = input.androidDeepLinkPath { body["androidDeepLinkPath"] = v }
        if let v = input.linkData { body["linkData"] = v }
        if let v = input.ogTitle { body["ogTitle"] = v }
        if let v = input.ogDescription { body["ogDescription"] = v }
        if let v = input.ogImageUrl { body["ogImageUrl"] = v }
        if let v = input.campaign { body["campaign"] = v }
        if let v = input.source { body["source"] = v }
        if let v = input.medium { body["medium"] = v }
        if let v = input.channel { body["channel"] = v }
        if let v = input.tags { body["tags"] = v }
        if let v = input.expiresAt {
            let iso = ISO8601DateFormatter()
            iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            body["expiresAt"] = iso.string(from: v)
        }
        let resolvedBundle = input.iosBundleId ?? bundleId
        if let v = resolvedBundle { body["iosBundleId"] = v }
        if let v = input.androidPackageName { body["androidPackageName"] = v }
        return body
    }

    /// Background-mint a link + cache the promise. Fire-and-forget.
    ///
    /// Wave 28 — silently drops the call when more than
    /// `prewarmMaxInflight` mints are already in flight. Prewarm is
    /// fire-and-forget by contract; an overflow `prewarm()` is fine
    /// to skip because the next matching `create()` will do the mint
    /// inline.
    public func prewarm(_ input: LinkCreateInput, key: String? = nil) {
        guard !input.title.isEmpty else { return }
        lock.lock()
        evictExpired()
        let cacheKey = cacheKey(input, override: key)
        if prewarmCache[cacheKey] != nil { lock.unlock(); return }
        if prewarmInflight >= prewarmMaxInflight { lock.unlock(); return }
        prewarmInflight += 1
        prewarmCache[cacheKey] = PrewarmEntry(result: nil, waiters: [], createdAt: Date())
        lock.unlock()
        doCreate(input) { [weak self] result in
            guard let self = self else { return }
            self.lock.lock()
            let waiters = self.prewarmCache[cacheKey]?.waiters ?? []
            // On failure, drop the entry so a retry doesn't replay the error.
            if case .failure = result {
                self.prewarmCache.removeValue(forKey: cacheKey)
            } else {
                self.prewarmCache[cacheKey] = PrewarmEntry(result: result, waiters: [], createdAt: Date())
            }
            self.prewarmInflight -= 1
            self.lock.unlock()
            for w in waiters { w(result) }
        }
    }

    /// Mint a new short link. Uses prewarm cache when the input matches the
    /// supplied `prewarmKey` (or when the canonical payload hash matches a
    /// previous `prewarm(...)`).
    public func create(
        _ input: LinkCreateInput,
        prewarmKey: String? = nil,
        completion: @escaping (Result<LinkCreateResult, Error>) -> Void
    ) {
        guard !input.title.isEmpty else {
            completion(.failure(LinkError(code: .invalidInput, message: "title is required"))); return
        }

        lock.lock()
        evictExpired()
        let key = cacheKey(input, override: prewarmKey)
        if let entry = prewarmCache[key] {
            if let result = entry.result {
                // Cached + already resolved.
                prewarmCache.removeValue(forKey: key)
                lock.unlock()
                completion(result)
                return
            }
            // In-flight prewarm — attach as a waiter.
            var updated = entry
            updated = PrewarmEntry(
                result: nil,
                waiters: entry.waiters + [completion],
                createdAt: entry.createdAt
            )
            prewarmCache[key] = updated
            lock.unlock()
            return
        }
        lock.unlock()
        doCreate(input, completion: completion)
    }

    private func doCreate(_ input: LinkCreateInput, completion: @escaping (Result<LinkCreateResult, Error>) -> Void) {
        let body = buildCreateBody(input)
        apiClient.requestWithDetails(method: "POST", path: "/sdk/links", body: body) { rich in
            if !(200..<300).contains(rich.statusCode) {
                completion(.failure(SendoraCloudLinks.mapError(status: rich.statusCode, code: rich.errorCode, message: rich.errorMessage)))
                return
            }
            guard let data = rich.body?["data"] as? [String: Any],
                  let id = data["id"] as? String,
                  let shortcode = data["shortcode"] as? String,
                  let url = data["url"] as? String,
                  let fallback = data["fallbackUrl"] as? String else {
                completion(.failure(LinkError(code: .server, message: "links.create returned an unexpected payload", statusCode: rich.statusCode)))
                return
            }
            completion(.success(LinkCreateResult(
                id: id,
                shortcode: shortcode,
                url: url,
                iosDeepLinkPath: data["iosDeepLinkPath"] as? String,
                androidDeepLinkPath: data["androidDeepLinkPath"] as? String,
                fallbackUrl: fallback,
                linkData: (data["linkData"] as? [String: Any]) ?? [:]
            )))
        }
    }

    // MARK: - warm path

    /// Resolve a Universal Link delivery and fire `onLinkOpened`. Returns
    /// `false` immediately if the URL doesn't parse as a Sendora link.
    @discardableResult
    public func handleUniversalLink(
        url: URL,
        completion: ((LinkOpenedEvent?) -> Void)? = nil
    ) -> Bool {
        guard let shortcode = Self.extractShortcode(from: url, allowedHosts: linkHosts) else {
            completion?(nil)
            return false
        }
        apiClient.requestWithDetails(method: "GET", path: "/sdk/links/\(shortcode)", body: nil) { [weak self] rich in
            guard let self = self else { return }
            guard (200..<300).contains(rich.statusCode), let data = rich.body?["data"] as? [String: Any] else {
                completion?(nil)
                return
            }
            let event = LinkOpenedEvent(
                shortcode: data["shortcode"] as? String ?? shortcode,
                linkData: (data["linkData"] as? [String: Any]) ?? [:],
                iosDeepLinkPath: data["iosDeepLinkPath"] as? String,
                androidDeepLinkPath: data["androidDeepLinkPath"] as? String,
                isDeferred: false
            )
            self.emit(event)
            completion?(event)
        }
        return true
    }

    // MARK: - cold path

    public func matchDeferred(
        _ input: DeferredMatchInput = DeferredMatchInput(),
        completion: @escaping (LinkOpenedEvent?) -> Void
    ) {
        var fingerprintHash = input.fingerprintHash
        let installReferrer = input.installReferrer

        // Auto-compute the canonical fingerprint when caller supplied
        // neither input. Branch parity — host app no longer threads through
        // expo-style boilerplate.
        if fingerprintHash == nil && installReferrer == nil {
            fingerprintHash = Self.computeDeviceFingerprint()
        }
        guard fingerprintHash != nil || installReferrer != nil else {
            completion(nil)
            return
        }
        var body: [String: Any] = [:]
        if let v = fingerprintHash { body["fingerprintHash"] = v }
        if let v = installReferrer { body["installReferrer"] = v }
        if let v = bundleId { body["iosBundleId"] = v }

        apiClient.requestWithDetails(method: "POST", path: "/sdk/links/match", body: body) { [weak self] rich in
            guard let self = self else { return }
            guard (200..<300).contains(rich.statusCode),
                  let data = rich.body?["data"] as? [String: Any],
                  let shortcode = data["shortcode"] as? String else {
                completion(nil)
                return
            }
            let event = LinkOpenedEvent(
                shortcode: shortcode,
                linkData: (data["linkData"] as? [String: Any]) ?? [:],
                iosDeepLinkPath: data["iosDeepLinkPath"] as? String,
                androidDeepLinkPath: data["androidDeepLinkPath"] as? String,
                isDeferred: true
            )
            self.emit(event)
            completion(event)
        }
    }

    // MARK: - revoke

    public func revoke(shortcode: String, completion: @escaping (Result<Void, Error>) -> Void) {
        guard shortcode.range(of: #"^[a-z0-9-]{3,20}$"#, options: .regularExpression) != nil else {
            completion(.failure(LinkError(code: .invalidInput, message: "'\(shortcode)' is not a valid shortcode"))); return
        }
        apiClient.requestWithDetails(method: "POST", path: "/sdk/links/\(shortcode)/revoke", body: [:]) { rich in
            if (200..<300).contains(rich.statusCode) {
                completion(.success(()))
            } else {
                completion(.failure(Self.mapError(status: rich.statusCode, code: rich.errorCode, message: rich.errorMessage)))
            }
        }
    }

    // MARK: - stats

    public func getStats(shortcode: String, completion: @escaping (Result<LinkStats, Error>) -> Void) {
        guard shortcode.range(of: #"^[a-z0-9-]{3,20}$"#, options: .regularExpression) != nil else {
            completion(.failure(LinkError(code: .invalidInput, message: "'\(shortcode)' is not a valid shortcode"))); return
        }
        apiClient.requestWithDetails(method: "GET", path: "/sdk/links/\(shortcode)/stats", body: nil) { rich in
            if !(200..<300).contains(rich.statusCode) {
                completion(.failure(Self.mapError(status: rich.statusCode, code: rich.errorCode, message: rich.errorMessage)))
                return
            }
            guard let data = rich.body?["data"] as? [String: Any] else {
                completion(.failure(LinkError(code: .server, message: "getStats returned an unexpected payload", statusCode: rich.statusCode)))
                return
            }
            func tuples(_ rows: [[String: Any]], _ key: String) -> [(String?, Int)] {
                return rows.map { (($0[key] as? String), ($0["count"] as? Int) ?? 0) }
            }
            let stats = LinkStats(
                totalClicks: (data["totalClicks"] as? Int) ?? 0,
                uniqueClicks: (data["uniqueClicks"] as? Int) ?? 0,
                deferredMatches: (data["deferredMatches"] as? Int) ?? 0,
                byDevice: tuples((data["byDevice"] as? [[String: Any]]) ?? [], "deviceType"),
                byCountry: tuples((data["byCountry"] as? [[String: Any]]) ?? [], "country"),
                byOs: tuples((data["byOs"] as? [[String: Any]]) ?? [], "os")
            )
            completion(.success(stats))
        }
    }

    // MARK: - fingerprint (canonical recipe)

    /// Canonical device-fingerprint recipe matching the React Native + Android
    /// SDKs. Input: `${platform}|${screenW}x${screenH}|${timezone}|${locale}`.
    /// Output: lowercase hex SHA-256 (64 chars).
    public static func computeDeviceFingerprint() -> String {
        var screen = "0x0"
        #if canImport(UIKit)
        let bounds = UIScreen.main.bounds
        screen = "\(Int(bounds.size.width))x\(Int(bounds.size.height))"
        #endif
        let tz = TimeZone.current.identifier
        let locale = Locale.current.identifier
        let input = "ios|\(screen)|\(tz)|\(locale)"
        let digest = SHA256.hash(data: Data(input.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - helpers

    /// Extract a shortcode from a Sendora link URL. When `allowedHosts` is
    /// non-empty, only matches URLs whose host equals an entry (or is a
    /// subdomain of one). When empty, host-agnostic (back-compat). Accepts:
    ///   • `https://<host>/<shortcode>`
    ///   • `https://<host>/link/<shortcode>` (Worker rewrite)
    public static func extractShortcode(from url: URL, allowedHosts: [String] = []) -> String? {
        if !allowedHosts.isEmpty {
            guard let host = url.host?.lowercased() else { return nil }
            let ok = allowedHosts.contains { allowed in
                let a = allowed.lowercased()
                return host == a || host.hasSuffix(".\(a)")
            }
            if !ok { return nil }
        }
        let segments = url.pathComponents.filter { $0 != "/" }
        let tail: String?
        if segments.count >= 2, segments[0] == "link" {
            tail = segments[1]
        } else if segments.count == 1 {
            tail = segments[0]
        } else {
            tail = segments.last
        }
        guard let t = tail,
              t.range(of: #"^[a-z0-9-]{3,20}$"#, options: .regularExpression) != nil else {
            return nil
        }
        return t
    }
}

// MARK: - SendoraCloud bridge

extension SendoraCloud {
    /// Deep-link surface. `nil` until `SendoraCloud.configure(...)` runs.
    public static var links: SendoraCloudLinks? {
        return _links
    }
    internal static var _links: SendoraCloudLinks?
}
