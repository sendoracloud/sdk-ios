// SendoraCloudPush.swift
//
// Generic push-token registration. Wraps `POST /api/v1/push/tokens` so
// host apps don't have to hand-roll URLSession + JSON for the most common
// flow. Live Activities have their own helper (SendoraCloudLiveActivities);
// this module covers vanilla APNs device tokens for user-facing pushes.
//
// Usage in AppDelegate:
//
//   func application(
//       _ application: UIApplication,
//       didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
//   ) {
//       let token = deviceToken.map { String(format: "%02x", $0) }.joined()
//       SendoraCloud.push?.registerToken(token) { result in
//           switch result {
//           case .success(let tokenId): print("Sendora token id:", tokenId)
//           case .failure(let err): print("Sendora register failed:", err)
//           }
//       }
//   }
//
// Identify the user FIRST so the token binds to a userId — anonymous tokens
// can't be targeted via { userIds: [...] }.

import Foundation

public enum SendoraCloudPushPlatform: String {
    /// APNs (iOS / iPadOS / macOS Catalyst). Token must be the hex string
    /// of the raw APNs deviceToken Data, not the description() output.
    case ios

    /// Web Push subscription. The web SDK uses this; native iOS apps
    /// generally don't.
    case web
}

public enum SendoraCloudPushError: Error {
    case sdkNotConfigured
    case invalidResponse
    case backendError(String)
}

@MainActor
public final class SendoraCloudPush {
    private let client: APIClient
    /// 5.6.0: the signed-in player's access token, or nil. A seam for tests;
    /// production reads `SendoraCloud.auth` (built after this object).
    private let accessTokenProvider: @Sendable (@escaping (String?) -> Void) -> Void
    /// 5.6.0: the longest registration waits for the token (a refresh on a bad network)
    /// before it registers WITHOUT the Bearer.
    private let tokenTimeout: TimeInterval

    /// `nonisolated` (5.7.0): `configure()` builds this inside `serialQueue.sync`, off the main actor. The init
    /// only stores constants — no main-actor state — so it needs no hop (and `configure()` never blocks on main).
    nonisolated init(client: APIClient, accessTokenProvider: (@Sendable (@escaping (String?) -> Void) -> Void)? = nil, tokenTimeout: TimeInterval = 5) {
        self.client = client
        self.tokenTimeout = tokenTimeout
        self.accessTokenProvider = accessTokenProvider ?? { done in
            guard let auth = SendoraCloud.auth else { done(nil); return }
            auth.getAccessToken(completion: done)
        }
    }

    /// Register an APNs device token with Sendora. Token is bound to the
    /// currently-identified user (call `SendoraCloud.identify(...)` first
    /// for targeted sends; otherwise the token is anonymous and only
    /// reachable via direct `tokens: [...]` arrays).
    ///
    /// - Parameters:
    ///   - token: Hex-encoded APNs device token (no <…> brackets, no spaces).
    ///   - platform: Defaults to `.ios`.
    ///   - userId: Optional override. Defaults to currently identified user.
    ///   - locale: BCP-47 (e.g. "en-US"). Powers `localizedBody` resolution.
    ///   - timezone: IANA TZ (e.g. "America/Los_Angeles"). Powers quiet hours.
    ///   - completion: Returns the Sendora `tokenId` UUID on success.
    public func registerToken(
        _ token: String,
        platform: SendoraCloudPushPlatform = .ios,
        userId: String? = nil,
        locale: String? = nil,
        timezone: String? = nil,
        completion: @escaping (Result<String, SendoraCloudPushError>) -> Void
    ) {
        var body: [String: Any] = [
            "platform": platform.rawValue,
            "token": token,
        ]
        if let userId = userId {
            body["userId"] = userId
        } else if let cached = SendoraCloud.currentUserId {
            body["userId"] = cached
        }
        if let locale = locale ?? Locale.current.identifier as String? {
            body["locale"] = locale
        }
        body["timezone"] = timezone ?? TimeZone.current.identifier
        body["appVersion"] = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String

        // 5.6.0 (backend F53): the player's own Bearer is what PROVES whose device
        // this is (a body `userId` from a publishable key is only a hint, and a
        // project in `enforce` skips unproven devices on user-addressed sends).
        // Best-effort: no session → registered exactly as before, unproven.
        let once = OnceGate()
        let client = self.client
        let proceed: (String?) -> Void = { accessToken in
            guard once.claim() else { return }
            let headers = accessToken.flatMap { $0.isEmpty ? nil : ["Authorization": "Bearer \($0)"] }
            Self.register(client: client, body: body, headers: headers, completion: completion)
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + tokenTimeout) { proceed(nil) }
        accessTokenProvider { proceed($0) }
    }

    private nonisolated static func register(
        client: APIClient,
        body: [String: Any],
        headers: [String: String]?,
        completion: @escaping (Result<String, SendoraCloudPushError>) -> Void
    ) {
        client.post(path: "/push/tokens", body: body, headers: headers) { response in
            guard let response = response else {
                completion(.failure(.invalidResponse))
                return
            }
            if let success = response["success"] as? Bool, success {
                if let data = response["data"] as? [String: Any],
                   let tokenId = data["tokenId"] as? String {
                    completion(.success(tokenId))
                    return
                }
                completion(.failure(.invalidResponse))
                return
            }
            let message = (response["error"] as? [String: Any])?["message"] as? String ?? "unknown"
            completion(.failure(.backendError(message)))
        }
    }

    /// Notify Sendora that a notification was opened. SDK fires this
    /// automatically from the `userNotificationCenter(_:didReceive:)`
    /// handler on the host app's UNUserNotificationCenter delegate;
    /// you generally don't call this manually.
    ///
    /// - Parameters:
    ///   - sendId: From the APNs payload `data.sendoraSendId`.
    ///   - clickAction: Action button id (when user tapped a button).
    ///                  Pass `nil` for body taps.
    public func trackOpen(
        sendId: String,
        clickAction: String? = nil
    ) {
        // Backend `trackPushOpenSchema` requires `pushSendId` (uuid) + `action`
        // (defaults to "body" for a notification-surface tap). The public
        // parameter names stay the same for API stability; only the wire keys
        // are mapped to what the backend validates.
        let body: [String: Any] = [
            "pushSendId": sendId,
            "action": clickAction ?? "body",
        ]
        client.post(path: "/push/track-open", body: body) { _ in }
    }
}

/// First caller wins (the token or the timeout).
private final class OnceGate: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}

// Bridge — wired on configure() in SendoraCloud.swift via
// `SendoraCloud._push = SendoraCloudPush(client: client)`.
extension SendoraCloud {
    /// Generic push-token registration + open tracking. `nil` until
    /// `SendoraCloud.configure(...)` runs.
    public static var push: SendoraCloudPush? {
        return _push
    }
    internal static var _push: SendoraCloudPush?
}
