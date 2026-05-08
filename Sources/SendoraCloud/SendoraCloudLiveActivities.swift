import Foundation
#if canImport(ActivityKit)
import ActivityKit
#endif

/// iOS Live Activities helper (iOS 16.1+).
///
/// Wraps `ActivityKit.Activity<T>` so the host app can:
///   1. Start an activity client-side.
///   2. Watch for the per-activity push token.
///   3. Auto-register that token with Sendora's backend so server-side
///      updates can dispatch via APNs `push-type=liveactivity`.
///
/// Usage:
/// ```swift
/// import ActivityKit
///
/// struct OrderAttributes: ActivityAttributes {
///     public struct ContentState: Codable, Hashable {
///         var status: String
///         var minutesAway: Int
///     }
///     var orderId: String
/// }
///
/// // Start the activity in the host app, on a user gesture:
/// let activity = try Activity<OrderAttributes>.request(
///     attributes: OrderAttributes(orderId: "1234"),
///     contentState: OrderAttributes.ContentState(status: "preparing", minutesAway: 30),
///     pushType: .token
/// )
///
/// // Hand it to Sendora — the helper watches pushTokenUpdates +
/// // registers each token with the backend so server-side updates work.
/// SendoraCloud.liveActivities.track(
///     activity: activity,
///     activityType: "OrderAttributes",
///     externalId: "order-1234",
///     userId: "user-42"
/// )
/// ```
///
/// Apple notes:
///  - `pushType: .token` is required to receive a push token. Without
///    it the activity is local-only.
///  - Tokens rotate per activity. The helper iterates `pushTokenUpdates`
///    so an in-flight rotation re-registers automatically.
///  - 4-hour idle / 12-hour max enforced by Apple. Sendora marks the
///    row `ended` on a 410-class APNs response.
@available(iOS 16.1, *)
public final class SendoraCloudLiveActivities {
    private let client: APIClient
    private let configProvider: () -> SendoraCloudConfig?

    /// Active token-watch tasks keyed by activity id. Cancelled on `end()`.
    private var watchers: [String: Task<Void, Never>] = [:]

    init(client: APIClient, configProvider: @escaping () -> SendoraCloudConfig?) {
        self.client = client
        self.configProvider = configProvider
    }

    #if canImport(ActivityKit)
    /// Watch an Activity's push-token stream + register every token rotation
    /// with Sendora's backend. Idempotent — calling twice for the same
    /// activity replaces the prior watcher.
    ///
    /// `attributes` and `initialContentState` ship to Sendora so the row
    /// includes a snapshot for the dashboard. `externalId` is your stable
    /// reference (order id, ride id, match id) — Sendora indexes on it
    /// for fan-in lookups when an external system wants to update the
    /// activity by business id.
    public func track<T: ActivityAttributes>(
        activity: Activity<T>,
        activityType: String,
        externalId: String? = nil,
        userId: String? = nil
    ) where T.ContentState: Encodable {
        let activityId = activity.id
        watchers[activityId]?.cancel()

        watchers[activityId] = Task { [weak self] in
            for await tokenData in activity.pushTokenUpdates {
                if Task.isCancelled { break }
                let hex = tokenData.map { String(format: "%02x", $0) }.joined()
                self?.registerToken(
                    activity: activity,
                    activityType: activityType,
                    pushToken: hex,
                    externalId: externalId,
                    userId: userId
                )
            }
        }
    }

    /// Mark an activity ended on the server side. APNs `event=end`
    /// dispatch is the backend's responsibility — this just tells
    /// Sendora to flip the row + cancel the local token watcher.
    /// Use `Activity.end()` for the client-side dismissal.
    public func untrack(activityId: String) {
        watchers[activityId]?.cancel()
        watchers.removeValue(forKey: activityId)
    }

    private func registerToken<T: ActivityAttributes>(
        activity: Activity<T>,
        activityType: String,
        pushToken: String,
        externalId: String?,
        userId: String?
    ) where T.ContentState: Encodable {
        guard let config = configProvider() else { return }

        // Encode attributes + contentState. Activity.attributes is
        // ActivityAttributes (Encodable); contentState is ContentState
        // (Encodable per the protocol).
        let encoder = JSONEncoder()
        let attributesJson = (try? encoder.encode(activity.attributes))
            .flatMap { try? JSONSerialization.jsonObject(with: $0) }
            ?? [:]
        let contentStateJson = (try? encoder.encode(activity.contentState))
            .flatMap { try? JSONSerialization.jsonObject(with: $0) }
            ?? [:]

        // Backend derives org from the API key (Stripe / Clerk model);
        // only include projectId when the host app set one explicitly.
        var body: [String: Any] = [
            "pushToken": pushToken,
            "activityType": activityType,
            "attributes": attributesJson,
            "contentState": contentStateJson,
        ]
        if let projectId = config.projectId { body["projectId"] = projectId }
        if let externalId = externalId { body["externalId"] = externalId }
        if let userId = userId { body["userId"] = userId }
        if let bundleId = Bundle.main.bundleIdentifier { body["bundleId"] = bundleId }

        client.post(path: "/push/live-activities/start-token", body: body) { _ in }
    }
    #endif
}
