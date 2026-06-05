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

    init(client: APIClient) {
        self.client = client
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

        client.post(path: "/push/tokens", body: body) { response in
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
