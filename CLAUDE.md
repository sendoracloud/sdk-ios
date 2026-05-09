# sdk-ios (SwiftPM)

Published at `github.com/sendoracloud/sdk-ios`. Swift 5.9+, iOS 15+.

## Public API

```swift
Sendora.configure(apiKey:, projectId:, options:)
Sendora.handleDeepLink(url:)
Sendora.checkDeferredDeepLink(completion:)
Sendora.trackEvent(_:properties:)
Sendora.identify(userId:, traits:, options:)
Sendora.consent.grant() / revoke()
```

## Security

- `SendoraValidator` refuses `sk_` keys, non-HTTPS URLs, bad event names, deep props.
- userId + deviceId in Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
- Event queue persisted with PII stripped.
- `handleDeepLink` host-allowlists via `config.linkHosts`.

## Push action buttons (s58.18)

Sendora forwards action buttons in the APNs payload as `data.sendoraActions: [{id, title, url?}]` (max 4 per send — APNs hard limit). iOS UNNotificationCategory does NOT support dynamic per-message actions; the only way is to register a single catch-all category at launch + render the buttons from the payload at notification-display time via a Notification Service Extension.

**Host-app pattern** (one-time AppDelegate setup):

```swift
import UserNotifications

func registerSendoraNotificationCategory() {
    let max = 4
    let actions = (0..<max).map { i in
        UNNotificationAction(
            identifier: "sendora.action.\(i)",
            title: "Action \(i + 1)", // Title overwritten per-message via service extension
            options: [.foreground]
        )
    }
    let category = UNNotificationCategory(
        identifier: "sendora_actions",
        actions: actions,
        intentIdentifiers: [],
        options: []
    )
    UNUserNotificationCenter.current().setNotificationCategories([category])
}
```

**Notification Service Extension** (per-message rewrite):
The extension reads `userInfo["sendoraActions"]`, mutates the `bestAttemptContent` to replace the placeholder action titles with the per-message `title` field. This is the only way Apple permits dynamic action labels.

**Tap routing**: SDK exposes `userNotificationCenter(_:didReceive:)` handler that maps `response.actionIdentifier` → `sendoraActions[i].id` and fires `POST /push/track-open` with `action=<id>`. Body taps fire with `action="body"`.

## Geofences (s58.22)

Server-managed geofences via `CLLocationManager` region monitoring. Operator defines circular regions in the dashboard; SDK auto-fetches + registers up to **20** regions (Apple's hard cap).

**Permission requirements:**
- `NSLocationAlwaysAndWhenInUseUsageDescription` + `NSLocationWhenInUseUsageDescription` in Info.plist.
- `CLLocationManager().requestAlwaysAuthorization()` at runtime — geofences only fire when in `.authorizedAlways` state. `.authorizedWhenInUse` misses background transitions.

**Usage:**
```swift
SendoraCloud.geofences?.start()         // pulls active list + arms regions
// On app foreground:
SendoraCloud.geofences?.refresh()
// On logout / opt-out:
SendoraCloud.geofences?.stop()
```

Enter / exit transitions emit `geofence.entered` / `.exited` events with `geofenceId + latitude + longitude` properties; wire workflows server-side to fire push.

**Notes:**
- Apple's 20-region cap is per-app, shared with any other CLLocationManager regions the host app monitors. SDK identifiers prefixed `sendora:` so dedup works.
- `dwell` trigger type isn't natively supported by CLLocationManager v1 — backend accepts it but iOS SDK currently reports as `enter`. Android implements properly.

## Critical Alerts (s58.20)

iOS Critical Alerts bypass Do Not Disturb / Focus / silent mode. Used for emergency / safety alerts (fall detection, security breach, on-call ops). Requirements:

1. **Apple entitlement** (`com.apple.developer.usernotifications.critical-alerts`) — request via developer.apple.com support form. Approval typically 1-3 weeks. Apple rejects apps without strong safety / health justification.
2. **User permission** at runtime via `UNUserNotificationCenter.requestAuthorization(.criticalAlert)`.

Without either, APNs silently downgrades to a regular alert.

**Permission helper:**
```swift
SendoraCloudCriticalAlerts.requestPermission { granted in
    // Show in-product UI based on outcome
}

SendoraCloudCriticalAlerts.currentSetting { enabled in
    // Re-prompt logic if user previously denied
}
```

**Server-side dispatch** — the dashboard compose page exposes a "Critical Alert" checkbox; the API accepts `criticalAlert: { soundName?, volume? }` on send + template. APNs payload then includes:
```json
{
  "aps": {
    "alert": { "title": "...", "body": "..." },
    "sound": { "critical": 1, "name": "siren.caf", "volume": 1.0 },
    "interruption-level": "critical"
  }
}
```

## Live Activities (s58.19)

iOS 16.1+ via ActivityKit. Persistent rich notifications on lock screen + Dynamic Island. Server-side updates via APNs `push-type=liveactivity`.

**Host-app setup:**
1. Add `NSSupportsLiveActivities=YES` to Info.plist.
2. Create a Widget Extension with the Activity views (lockScreen + Dynamic Island compactLeading / compactTrailing / minimal / expanded).
3. Define `ActivityAttributes` w/ `ContentState`.

**Start + register:**
```swift
import ActivityKit

struct OrderAttributes: ActivityAttributes {
    public struct ContentState: Codable, Hashable {
        var status: String
        var minutesAway: Int
    }
    var orderId: String
}

let activity = try Activity<OrderAttributes>.request(
    attributes: OrderAttributes(orderId: "1234"),
    contentState: OrderAttributes.ContentState(status: "preparing", minutesAway: 30),
    pushType: .token   // <-- REQUIRED for server-side push updates
)

if #available(iOS 16.1, *) {
    SendoraCloud.liveActivities?.track(
        activity: activity,
        activityType: "OrderAttributes",
        externalId: "order-1234",
        userId: "user-42"
    )
}
```

The SDK watches `activity.pushTokenUpdates` and re-registers the per-activity token with Sendora on every rotation. Server updates target the row at `pushLiveActivities.id` (returned from `/push/live-activities/start-token`).

**Server-side update** (operator dashboard or workflow):
```
PATCH /api/v1/orgs/:orgId/push/live-activities/:id/update
{ "contentState": { "status": "delivered", "minutesAway": 0 },
  "alert": { "title": "Order delivered", "body": "Enjoy!" } }
```

**End** (operator or auto on Apple's 4h-idle / 12h-max):
```
DELETE /api/v1/orgs/:orgId/push/live-activities/:id
```

**Apple gotchas:**
- `pushType: .token` REQUIRED at activity start. Without it the activity is local-only and server pushes silently fail.
- Per-activity token rotates. SDK helper handles this; don't cache the token client-side.
- APNs topic suffix `<bundleId>.push-type.liveactivity` is mandatory. Backend sets it automatically.
- Per-activity update budget is opaque. Dashboard warns when `updatesThisHour ≥ 30`. Higher rates may silently throttle.
- `aps.timestamp` must be monotonic; backend uses `Math.floor(Date.now()/1000)` per send.
- iOS 17+: APNs can also START activities (not just update). Sendora doesn't surface this yet — host app must start v1.

## Publish

`git tag <semver> && git push origin <semver>`. Release via `gh release create`.
