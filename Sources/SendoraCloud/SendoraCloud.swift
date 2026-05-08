import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// SendoraCloud iOS SDK — deep linking, attribution, event tracking.
///
/// ```swift
/// // Key prefix encodes env: pk_prod_*, pk_staging_*, pk_dev_* — the
/// // server forcibly tags events with the key's env (ADR-014). Legacy
/// // pk_live_* keys are still accepted and treated as prod.
/// SendoraCloud.configure(apiKey: "pk_prod_...", projectId: "<uuid>")
/// SendoraCloud.consent.grant()
///
/// // When you have an HMAC-signed identity token from your backend:
/// SendoraCloud.identify(userId: "user_123",
///                  traits: ["email": "a@b.co"],
///                  options: SendoraCloudIdentifyOptions(identityToken: "..."))
///
/// SendoraCloud.trackEvent("purchase", properties: ["amount": 29.99])
/// ```
///
/// Security notes
///  - Secret (`sk_...`) keys are refused. The SDK throws on `configure` if given one.
///  - `apiBaseUrl` must be HTTPS (localhost allowed in dev).
///  - `handleDeepLink` accepts only URLs whose host is in `config.linkHosts`.
///  - `identify` accepts an optional HMAC `identityToken`. Projects in strict mode
///    reject identifies without it, blocking spoofing.
public final class SendoraCloud {
    private static let serialQueue = DispatchQueue(label: "com.sendora.sdk.main")
    private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private static var config: SendoraCloudConfig?
    private static var apiClient: APIClient?
    private static var storage: SendoraStorage?
    private static var eventQueue: EventQueue?
    private static var deviceContext: DeviceContext?
    private static var fingerprintHash: String?
    private static var currentUserId: String?
    private static var currentIdentityToken: String?
    private static var isConfigured = false

    /// Consent gate. Events queue but do not send until `grant()` is called
    /// (unless `config.defaultConsent = true`).
    public static let consent = SendoraCloudConsent(initial: false)

    /// Auth Service surface. Lazily initialised in `configure()`.
    /// Access as `SendoraCloud.auth?.signInAnonymously { ... }`.
    public private(set) static var auth: SendoraCloudAuth?

    /// Native passkey flows (iOS only — gated on UIKit). Wired
    /// alongside `auth` on configure(). Use as
    /// `SendoraCloud.passkeys?.register(presentingWindow: window) { ... }`.
    #if canImport(UIKit)
    public private(set) static var passkeys: SendoraCloudPasskeys?
    /// OIDC SSO via ASWebAuthenticationSession (iOS only). Use as
    /// `SendoraCloud.sso?.signInWithOidc(returnTo:from:completion:)`.
    public private(set) static var sso: SendoraCloudSso?
    #endif

    /// iOS Live Activities helper (iOS 16.1+, ActivityKit). Wired on
    /// configure(). Use as `SendoraCloud.liveActivities?.track(activity:...)`.
    #if canImport(ActivityKit)
    @available(iOS 16.1, *)
    public static var liveActivities: SendoraCloudLiveActivities? {
        return _liveActivities as? SendoraCloudLiveActivities
    }
    private static var _liveActivities: AnyObject?
    #endif

    // MARK: - Public API

    /// Initialize the SDK. Must be called before any other method. Non-throwing
    /// for backwards compatibility — validation errors log and abort configure.
    /// 3.0.0: `projectId` is now optional. When omitted, the backend
    /// derives project + org + environment from the API key row.
    /// Existing callers passing a value continue to work unchanged.
    public static func configure(apiKey: String, projectId: String? = nil, options: SendoraCloudConfig? = nil) {
        let cfg = options ?? SendoraCloudConfig(apiKey: apiKey, projectId: projectId)
        let finalConfig = SendoraCloudConfig(
            apiKey: cfg.apiKey.isEmpty ? apiKey : cfg.apiKey,
            projectId: cfg.projectId ?? projectId,
            apiBaseUrl: cfg.apiBaseUrl,
            flushInterval: cfg.flushInterval,
            flushAt: cfg.flushAt,
            maxQueueSize: cfg.maxQueueSize,
            debug: cfg.debug,
            linkHosts: cfg.linkHosts,
            defaultConsent: cfg.defaultConsent,
            autoStartAttribution: cfg.autoStartAttribution,
            pinnedSPKIHashes: cfg.pinnedSPKIHashes,
            autoTrackLifecycle: cfg.autoTrackLifecycle
        )

        do {
            try SendoraCloudValidator.validateApiKey(finalConfig.apiKey)
            try SendoraCloudValidator.validateApiUrl(finalConfig.apiBaseUrl)
        } catch {
            SendoraCloudLogger.shared.error("\(error)")
            return
        }

        serialQueue.sync {
            self.config = finalConfig
            SendoraCloudLogger.shared.isEnabled = finalConfig.debug

            if finalConfig.defaultConsent {
                consent.grant()
            }

            let store = SendoraStorage()
            self.storage = store
            self.currentUserId = store.cachedUserId

            let device = DeviceContext.collect()
            self.deviceContext = device
            self.fingerprintHash = FingerprintGenerator.generate(device: device)

            let client = APIClient(
                baseUrl: finalConfig.apiBaseUrl,
                apiKey: finalConfig.apiKey,
                pinnedSPKIHashes: finalConfig.pinnedSPKIHashes
            )
            self.apiClient = client

            let queue = EventQueue(storage: store, flushAt: finalConfig.flushAt, maxSize: finalConfig.maxQueueSize)
            queue.setFlushHandler { events in
                if !consent.isGranted { return } // gate flushes on consent
                flushEvents(events, client: client)
            }
            queue.startTimer(interval: finalConfig.flushInterval)
            self.eventQueue = queue

            self.auth = SendoraCloudAuth(
                client: client,
                storage: store,
                onIdentityChange: { userId in
                    self.serialQueue.sync {
                        self.currentUserId = userId
                        store.cachedUserId = userId
                    }
                },
                onAnonymousWipe: {
                    // Switching identities — rotate device-side state
                    // so events from the new user can't carry over the
                    // prior anonymous attribution. Also drain the
                    // event queue: pending events were captured under
                    // the prior currentUserId and shouldn't surface
                    // under the next.
                    self.serialQueue.sync {
                        self.currentUserId = nil
                        self.currentIdentityToken = nil
                        store.cachedUserId = nil
                        store.regenerateDeviceId()
                        // Force-mint a fresh device id immediately so
                        // any concurrent track() that races the wipe
                        // sees the new id rather than a transiently
                        // missing one.
                        _ = store.deviceId
                        store.sessionId = UUID().uuidString
                    }
                    self.eventQueue?.dropAll()
                }
            )

            // Wire passkeys against the same client + auth instance so
            // the WebAuthn flows can read the bearer token + share the
            // network stack. iOS only — UIKit gate keeps this clean
            // for the macOS slice of the package.
            #if canImport(UIKit)
            if let auth = self.auth {
                self.passkeys = SendoraCloudPasskeys(client: client, auth: auth)
                self.sso = SendoraCloudSso(client: client, auth: auth)
            }
            #endif

            #if canImport(ActivityKit)
            if #available(iOS 16.1, *) {
                self._liveActivities = SendoraCloudLiveActivities(
                    client: client,
                    configProvider: { return self.config }
                )
            }
            #endif

            self.isConfigured = true
        }

        // When consent is granted later, flush what we've buffered.
        consent.subscribe { granted in
            if granted { self.eventQueue?.flush() }
        }

        SendoraCloudLogger.shared.debug("Configured — project: \(projectId)")

        if finalConfig.autoStartAttribution {
            DispatchQueue.global(qos: .utility).async {
                reportInstallIfNeeded()
                trackSessionStart()
            }
        }

        #if canImport(UIKit)
        NotificationCenter.default.addObserver(
            forName: UIApplication.willResignActiveNotification,
            object: nil, queue: .main
        ) { _ in
            eventQueue?.persistToDisk()
            trackSessionEnd()
            if finalConfig.autoTrackLifecycle {
                trackEvent("app.backgrounded", properties: [
                    "sessionId": storage?.sessionId ?? ""
                ])
            }
        }
        if finalConfig.autoTrackLifecycle {
            // app.opened fires once per `configure` (per-launch). Mirrors
            // Firebase's `app_open` auto-event.
            trackEvent("app.opened", properties: [
                "sessionId": storage?.sessionId ?? ""
            ])
            NotificationCenter.default.addObserver(
                forName: UIApplication.didBecomeActiveNotification,
                object: nil, queue: .main
            ) { _ in
                trackEvent("app.foregrounded", properties: [
                    "sessionId": storage?.sessionId ?? ""
                ])
            }
        }
        #endif
    }

    /// Explicitly start attribution (install reporting + session tracking).
    /// Call after your ATT prompt when `autoStartAttribution = false`.
    public static func startAttribution() {
        guard isConfigured else { return }
        DispatchQueue.global(qos: .utility).async {
            reportInstallIfNeeded()
            trackSessionStart()
        }
    }

    /// Handle an incoming deep link. Returns `nil` for URLs not in `config.linkHosts`.
    public static func handleDeepLink(url: URL) -> SendoraCloudLinkData? {
        guard isConfigured, let config = config else {
            SendoraCloudLogger.shared.error("SDK not configured. Call configure() first.")
            return nil
        }

        // Host allowlist
        guard let host = url.host?.lowercased(),
              config.linkHosts.contains(where: { host == $0 || host.hasSuffix(".\($0)") }) else {
            return nil
        }

        // Parse /link/<shortcode> or /<shortcode> (single path segment only)
        let segments = url.pathComponents.filter { $0 != "/" }
        let shortcode: String
        if segments.count >= 2, segments[0] == "link" {
            shortcode = segments[1]
        } else if segments.count == 1 {
            shortcode = segments[0]
        } else {
            return nil
        }

        guard !shortcode.isEmpty, shortcode.count <= 40,
              shortcode.range(of: #"^[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil else {
            return nil
        }

        SendoraCloudLogger.shared.debug("Deep link handled")
        trackEvent("links.opened", properties: ["shortcode": shortcode])
        return SendoraCloudLinkData(shortcode: shortcode)
    }

    /// Check for a deferred deep link (first launch after install).
    public static func checkDeferredDeepLink(completion: @escaping (SendoraCloudLinkData?) -> Void) {
        guard isConfigured, let client = apiClient, let config = config, let storage = storage else {
            DispatchQueue.main.async { completion(nil) }
            return
        }
        guard storage.isFirstLaunch else {
            DispatchQueue.main.async { completion(nil) }
            return
        }

        DispatchQueue.global(qos: .utility).async {
            var body: [String: Any] = ["projectId": config.projectId]
            if let fp = fingerprintHash { body["fingerprintHash"] = fp }
            body["deviceId"] = storage.deviceId

            client.post(path: "/attribution/deferred", body: body) { response in
                let data = response?["data"] as? [String: Any]
                let found = data?["found"] as? Bool ?? false
                if found {
                    let linkData = SendoraCloudLinkData(
                        shortcode: "",
                        deepLinkPath: data?["deepLinkPath"] as? String,
                        campaign: data?["campaign"] as? String,
                        source: data?["source"] as? String,
                        medium: data?["medium"] as? String,
                        linkData: data?["deepLinkData"] as? [String: Any] ?? [:]
                    )
                    DispatchQueue.main.async { completion(linkData) }
                } else {
                    DispatchQueue.main.async { completion(nil) }
                }
            }
        }
    }

    /// Track a custom event. Events are batched and sent in the background.
    public static func trackEvent(_ name: String, properties: [String: Any]? = nil) {
        guard isConfigured, let config = config, let queue = eventQueue else { return }
        do {
            try SendoraCloudValidator.validateEventName(name)
            try SendoraCloudValidator.validateProperties(properties)
        } catch {
            SendoraCloudLogger.shared.error("\(error)")
            return
        }

        var event: [String: Any] = [
            "projectId": config.projectId,
            "module": "custom",
            "eventType": name,
            "timestamp": isoFormatter.string(from: Date()),
            "properties": properties ?? [:],
            "context": [
                "device": deviceContext?.toDictionary() ?? [:],
                "sdk": ["name": "sendora-ios", "version": "3.3.0"],
            ],
            "sessionId": storage?.sessionId ?? "",
            "consent": ["analytics"],
        ]
        if let uid = currentUserId { event["userId"] = uid }
        if let tok = currentIdentityToken { event["identityToken"] = tok }

        queue.add(event: event)
    }

    /// Identify the current user. Pass an HMAC `identityToken` from your backend
    /// to prevent spoofing (required in strict-identity projects).
    public static func identify(userId: String, traits: [String: Any]? = nil, options: SendoraCloudIdentifyOptions? = nil) {
        guard isConfigured else { return }
        guard !userId.isEmpty, userId.count <= 256 else {
            SendoraCloudLogger.shared.error("userId must be 1-256 chars")
            return
        }
        serialQueue.sync {
            currentUserId = userId
            currentIdentityToken = options?.identityToken
            storage?.cachedUserId = userId
        }
        trackEvent("user.identified", properties: traits)
    }

    /// Reset the current user identity. Regenerates device id and session.
    public static func reset() {
        guard isConfigured else { return }
        serialQueue.sync {
            currentUserId = nil
            currentIdentityToken = nil
            storage?.cachedUserId = nil
            storage?.regenerateDeviceId()
            storage?.sessionId = UUID().uuidString
        }
        SendoraCloudLogger.shared.debug("Identity reset")
    }

    // MARK: - Private

    private static func reportInstallIfNeeded() {
        guard let storage = storage, storage.isFirstLaunch,
              let client = apiClient, let config = config else { return }
        storage.isFirstLaunch = false
        let body: [String: Any] = [
            "projectId": config.projectId,
            "deviceId": storage.deviceId,
            "fingerprintHash": fingerprintHash ?? "",
            "appVersion": deviceContext?.appVersion ?? "",
            "os": "iOS",
            "osVersion": deviceContext?.osVersion ?? "",
        ]
        client.post(path: "/attribution/install", body: body) { _ in }
    }

    private static func trackSessionStart() {
        let newSession = UUID().uuidString
        serialQueue.sync { storage?.sessionId = newSession }
        trackEvent("session.started", properties: ["sessionId": newSession])
    }

    private static func trackSessionEnd() {
        trackEvent("session.ended", properties: ["sessionId": storage?.sessionId ?? ""])
    }

    private static func flushEvents(_ events: [[String: Any]], client: APIClient) {
        guard !events.isEmpty else { return }
        if events.count == 1, let event = events.first {
            client.post(path: "/events", body: event) { _ in }
        } else {
            client.postBatch(path: "/events/batch", events: events) { _ in }
        }
    }
}
