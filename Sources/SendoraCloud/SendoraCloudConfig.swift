import Foundation

/// Configuration for the SendoraCloud SDK.
public struct SendoraCloudConfig {
    public let apiKey: String
    public let projectId: String
    public var apiBaseUrl: String
    public var flushInterval: TimeInterval
    public var flushAt: Int
    public var maxQueueSize: Int
    public var debug: Bool
    /// Host allowlist for `handleDeepLink`. Defaults to `["sendoracloud.com"]`.
    public var linkHosts: [String]
    /// When `false` (default), analytics events are buffered until `SendoraCloud.consent.grant()`
    /// is called. Set to `true` only if you've gathered consent outside the SDK.
    public var defaultConsent: Bool
    /// When `false`, `configure()` will NOT auto-start attribution / install reporting.
    /// Call `SendoraCloud.startAttribution()` after ATT prompt / consent. Default: `true`
    /// for backwards compatibility — set to `false` for App Store ATT compliance.
    public var autoStartAttribution: Bool

    public init(
        apiKey: String,
        projectId: String,
        apiBaseUrl: String = "https://api.sendoracloud.com",
        flushInterval: TimeInterval = 30,
        flushAt: Int = 20,
        maxQueueSize: Int = 1000,
        debug: Bool = false,
        linkHosts: [String] = ["sendoracloud.com"],
        defaultConsent: Bool = false,
        autoStartAttribution: Bool = true
    ) {
        self.apiKey = apiKey
        self.projectId = projectId
        self.apiBaseUrl = apiBaseUrl
        self.flushInterval = flushInterval
        self.flushAt = flushAt
        self.maxQueueSize = maxQueueSize
        self.debug = debug
        self.linkHosts = linkHosts
        self.defaultConsent = defaultConsent
        self.autoStartAttribution = autoStartAttribution
    }
}

/// Options for identifying a user.
public struct SendoraCloudIdentifyOptions {
    /// HMAC signature of `userId`, produced by your backend with a server-side secret.
    /// Required when the project is in strict-identity mode — the SendoraCloud backend verifies
    /// the HMAC before trusting the claim, blocking identity spoofing.
    public let identityToken: String?

    public init(identityToken: String? = nil) {
        self.identityToken = identityToken
    }
}
