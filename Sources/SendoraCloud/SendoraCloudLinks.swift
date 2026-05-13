import Foundation

/// Deep link surface for the iOS SDK. Mirrors `Sendora.links` on
/// React Native + Android. Three core moves:
///   • `create(...)` — mint a Sendora short link from inside the app.
///   • `handleUniversalLink(url:completion:)` — call from
///     `application(_:continue:restorationHandler:)` to resolve a
///     warm-path universal link delivery into a `LinkOpenedEvent`.
///   • `matchDeferred(completion:)` — call on cold launch to ask the
///     backend whether this fresh install came from a recent Sendora
///     click. Fires `onLinkOpened` with `isDeferred = true` on match.
///
/// `onLinkOpened(_:)` registers a callback fired for both warm + deferred
/// events. Multiple callbacks supported. Returns an unsubscribe token.
public final class SendoraCloudLinks {
    public struct LinkCreateInput {
        public var title: String
        public var fallbackUrl: String
        public var iosDeepLinkPath: String?
        public var androidDeepLinkPath: String?
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
            fallbackUrl: String,
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
    }

    public struct LinkCreateResult {
        public let id: String
        public let shortcode: String
        /// Fully-qualified share URL — pass to `UIActivityViewController` for share sheet.
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
    }

    public typealias LinkOpenedHandler = (LinkOpenedEvent) -> Void

    private let apiClient: APIClient
    private let bundleId: String?
    private let lock = NSLock()
    private var handlers: [(token: UUID, handler: LinkOpenedHandler)] = []

    internal init(apiClient: APIClient, bundleId: String?) {
        self.apiClient = apiClient
        self.bundleId = bundleId
    }

    /// Convenience init that matches the param-label pattern used by
    /// the other SDK modules (`SendoraCloudPush(client:)`).
    internal convenience init(client: APIClient, bundleId: String?) {
        self.init(apiClient: client, bundleId: bundleId)
    }

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

    // MARK: - create

    public func create(
        _ input: LinkCreateInput,
        completion: @escaping (Result<LinkCreateResult, Error>) -> Void
    ) {
        guard !input.title.isEmpty else {
            completion(.failure(LinksError.invalidInput("title is required")))
            return
        }
        guard !input.fallbackUrl.isEmpty else {
            completion(.failure(LinksError.invalidInput("fallbackUrl is required")))
            return
        }

        var body: [String: Any] = [
            "title": input.title,
            "fallbackUrl": input.fallbackUrl,
        ]
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

        apiClient.post(path: "/sdk/links", body: body) { response in
            guard let data = response?["data"] as? [String: Any],
                  let id = data["id"] as? String,
                  let shortcode = data["shortcode"] as? String,
                  let url = data["url"] as? String,
                  let fallback = data["fallbackUrl"] as? String else {
                completion(.failure(LinksError.serverError("links.create returned an unexpected payload")))
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
        guard let shortcode = Self.extractShortcode(from: url) else {
            completion?(nil)
            return false
        }
        apiClient.get(path: "/sdk/links/\(shortcode)") { [weak self] response in
            guard let self = self else { return }
            guard let data = response?["data"] as? [String: Any] else {
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

    public struct DeferredMatchInput {
        public var fingerprintHash: String?
        public var installReferrer: String?
        public init(fingerprintHash: String? = nil, installReferrer: String? = nil) {
            self.fingerprintHash = fingerprintHash
            self.installReferrer = installReferrer
        }
    }

    public func matchDeferred(
        _ input: DeferredMatchInput,
        completion: @escaping (LinkOpenedEvent?) -> Void
    ) {
        guard input.fingerprintHash != nil || input.installReferrer != nil else {
            completion(nil)
            return
        }
        var body: [String: Any] = [:]
        if let v = input.fingerprintHash { body["fingerprintHash"] = v }
        if let v = input.installReferrer { body["installReferrer"] = v }
        if let v = bundleId { body["iosBundleId"] = v }

        apiClient.post(path: "/sdk/links/match", body: body) { [weak self] response in
            guard let self = self else { return }
            guard let data = response?["data"] as? [String: Any],
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

    // MARK: - helpers

    /// Extract a shortcode from a Sendora link URL. Accepts:
    ///   • `https://go.sendoracloud.com/<shortcode>`
    ///   • `https://go.sendoracloud.com/link/<shortcode>` (Worker rewrite)
    /// Returns `nil` for malformed input.
    public static func extractShortcode(from url: URL) -> String? {
        let segments = url.pathComponents.filter { $0 != "/" }
        let tail: String?
        if segments.count >= 2, segments[0] == "link" {
            tail = segments[1]
        } else if segments.count == 1 {
            tail = segments[0]
        } else {
            tail = nil
        }
        guard let t = tail,
              t.range(of: #"^[a-z0-9-]{3,20}$"#, options: .regularExpression) != nil else {
            return nil
        }
        return t
    }
}

// Bridge — wired on configure() in SendoraCloud.swift via
// `SendoraCloud._links = SendoraCloudLinks(client: client, bundleId: ...)`.
extension SendoraCloud {
    /// Deep-link surface: create, handleUniversalLink, matchDeferred.
    /// `nil` until `SendoraCloud.configure(...)` runs.
    public static var links: SendoraCloudLinks? {
        return _links
    }
    internal static var _links: SendoraCloudLinks?
}

public enum LinksError: Error, LocalizedError {
    case invalidInput(String)
    case serverError(String)

    public var errorDescription: String? {
        switch self {
        case .invalidInput(let m): return "Invalid input: \(m)"
        case .serverError(let m): return "Server error: \(m)"
        }
    }
}
