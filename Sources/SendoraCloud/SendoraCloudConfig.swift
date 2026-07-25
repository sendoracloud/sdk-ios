import Foundation

/// Configuration for the SendoraCloud SDK.
public struct SendoraCloudConfig {
    public let apiKey: String
    /// Project UUID. Optional as of 3.0.0 — when omitted, the
    /// backend derives project + org + environment from the API
    /// key row server-side (matches sdk-web 2.7.0 behaviour).
    /// Pre-3.0.0 callers passing a value still work; the field is
    /// surfaced on every event payload for backwards compatibility.
    public let projectId: String?
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
    /// Optional certificate-pinning set. When non-empty the SDK enforces
    /// that the server's leaf-certificate Subject Public Key Info SHA-256
    /// matches one of the supplied base64 hashes — an attacker-installed
    /// enterprise CA can no longer MitM auth tokens. Compute the hash
    /// with: `openssl x509 -in cert.pem -pubkey -noout | openssl pkey
    /// -pubin -outform der | openssl dgst -sha256 -binary | openssl
    /// base64`. Always include at least one backup pin. Default: empty
    /// (system trust only).
    public var pinnedSPKIHashes: [String]
    /// Auto-collect lifecycle events. Mirrors Firebase Analytics' auto-collected
    /// surface: `app.opened` (per launch), `app.foregrounded` /
    /// `app.backgrounded` (UIApplication state transitions), `session.start` /
    /// `session.end` (launch-bounded session). Default: `true`. Set to
    /// `false` to opt out — useful when the host app already wires its
    /// own lifecycle telemetry.
    public var autoTrackLifecycle: Bool

    /// Auto-measure foreground engagement time per screen. When `true`
    /// (default), `trackScreen(_:)` emits an `app.engagement` event carrying
    /// foreground-only `durationMs` for the previous screen. Time while the
    /// app is backgrounded is never counted (GA4 engagement_time_msec model).
    /// Only measures screens you name via `trackScreen(_:)` — there is no
    /// UIViewController swizzling (deliberately, to keep screen names accurate
    /// and avoid counting container / nav / tab controllers).
    public var autoTrackEngagement: Bool

    public init(
        apiKey: String,
        projectId: String? = nil,
        apiBaseUrl: String = "https://api.sendoracloud.com",
        flushInterval: TimeInterval = 30,
        flushAt: Int = 20,
        maxQueueSize: Int = 1000,
        debug: Bool = false,
        linkHosts: [String] = ["go.sendoracloud.com", "sendoracloud.com"],
        defaultConsent: Bool = false,
        autoStartAttribution: Bool = true,
        pinnedSPKIHashes: [String] = [],
        autoTrackLifecycle: Bool = true,
        autoTrackEngagement: Bool = true
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
        self.pinnedSPKIHashes = pinnedSPKIHashes
        self.autoTrackLifecycle = autoTrackLifecycle
        self.autoTrackEngagement = autoTrackEngagement
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
