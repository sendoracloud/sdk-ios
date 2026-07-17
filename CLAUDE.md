# sdk-ios (SwiftPM)

Published at `github.com/sendoracloud/sdk-ios`. Swift 5.9+, **iOS 15+** (`Package.swift` = `.iOS(.v15)`). Passkeys (`ASAuthorizationPlatformPublicKeyCredentialProvider`, iOS 16) are `@available(iOS 16)`-gated — `SendoraCloud.passkeys` + the `SendoraCloudPasskeys` class are iOS-16-only; everything else incl. `SendoraCloudLinks.create()` works on iOS 15. **History:** 2.3.0–4.5.0 forced iOS 16 (unguarded passkey provider); **4.6.0 (s58.235) restored iOS 15** by `@available`-gating passkeys — same treatment Live Activities (iOS 16.1) always had. The type-erased `_passkeys` backing store in `SendoraCloud.swift` exists because Swift forbids `@available` on a stored property.

> ⚠ **ADR-023 frozen contract.** UserDefaults/Keychain keys (`sendora_*`), the `X-Sendora-SDK-{Name,Version}` headers, and the `sendora_schema_version` marker are depended on by installed apps — never rename/remove a key (orphans session/queue on upgrade) or drop the header/marker. The version lives ONLY in `SDKVersion.swift`. Additive only; a format change is MAJOR + needs a migration. CI cap: `apps/backend/src/modules/developer-tools/sdk-contract-golden.test.ts`. Law: `docs/decisions/023-sdk-api-compatibility.md`.

## Public API

```swift
Sendora.configure(apiKey:, projectId:, options:)
Sendora.handleDeepLink(url:)
Sendora.checkDeferredDeepLink(completion:)
Sendora.trackEvent(_:properties:)
Sendora.identify(userId:, traits:, options:)
Sendora.consent.grant() / revoke()
```

## MFA-from-anonymous device-takeover (4.1.3)

`signInWithMfaSupport()` must NOT wipe the anon identity before the MFA challenge resolves — else `challengeMfa()`'s `takeoverHint()` reads a cleared `cachedUser` and forwards no `prevAnonRefreshToken`, so the backend never retires the anon row / reassigns push tokens (device ends with two user_ids + duplicate pushes). The fix captures the anon refresh BEFORE any wipe, stashes it in `pendingAnonTakeover` keyed to the `mfaChallengeToken`, and `challengeMfa()` forwards it + wipes **only on a successful mint** (a wrong code preserves the anon session for retry). Mirrors the non-MFA `signIn()` wipe-after-success ordering. Backend `/auth-service/mfa/challenge` already accepts `prevAnonRefreshToken`.

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

## 4.7.0 — anon→social link-in-place (ADR-025)

`loginSocial` / `signInWithApple` / `signInWithGoogle` gain an opt-in `link: Bool = false`. When anonymous + `link: true`, the anon→social upgrade sends `linkAnonymous` so the backend promotes the anon row IN PLACE — `sub` PRESERVED (fires `auth.user_upgraded`) instead of a device-takeover (new id); Firebase `linkWithCredential` parity. No effect off-anon or on a collision. Source-compatible default (trailing-closure callers unaffected); additive. Design: `docs/decisions/025-anon-social-link-in-place.md`.

## 4.5.0 — SDK/API compatibility (ADR-023)

4.5.0 — ADR-023: single-source sdkVersion constant (no more hardcoded drift) +
X-Sendora-SDK-{Name,Version} headers + sendora_schema_version=1 marker (additive).

The version string used to be hardcoded as `"4.4.0"` in two places (the event
body `context.sdk` and a `Package.swift` reference) — drift risk. Now the ONLY
source of truth is `Internal/SDKVersion.swift` (`SendoraCloud.sdkVersion` /
`.sdkName`); the event body reads it and `Package.swift` just carries a comment
kept in lockstep with the git tag. Every HTTP request (`APIClient`, both the
plain `request` and `requestWithDetails` builders) now also sends
`X-Sendora-SDK-Name: sendora-ios` + `X-Sendora-SDK-Version: <sdkVersion>` so the
backend gets a version signal on non-event routes too (auth/links/push) — the
backend ignores them today. On `configure`, `Storage.initSchemaVersionIfAbsent()`
writes UserDefaults key `sendora_schema_version = "1"` if absent (non-sensitive →
UserDefaults tier, NOT Keychain), giving a future in-place upgrade a hook to
branch a local-storage migration. Read nowhere yet; no existing key renamed
(frozen per ADR-023 §3.4). All additive + backward-compatible.

## 4.4.0 — appVersion in device context (ADR-022)

`DeviceInfo.toDictionary()` now also emits `appVersion` (already collected from
`CFBundleShortVersionString`) alongside the existing `type` / `os` / `osVersion`
/ `model`. So every event's `context.device` carries the host app version,
powering the dashboard Analytics → Audience app-version breakdown. No config or
host-app change — auto-detected from the bundle. The native SDKs already led on
device context; this just surfaces the app version that was being collected but
not sent.

## Engagement time (Wave 75 — 4.1.0)

`SendoraCloud.trackScreen(_:properties:)` emits `screen.viewed` and flushes the
previous screen's `app.engagement { durationMs, screen, sessionId }` (foreground
-only). New `autoTrackEngagement` config flag (default on). `willResignActive`
flushes + pauses; `didBecomeActive` resumes (the observer is now registered when
lifecycle OR engagement is on). State guarded by the existing `serialQueue`;
spans <250ms dropped, >6h clamped, emit happens outside the lock. **No
UIViewController swizzling** — deliberately, so screen names stay accurate
(swizzle counts container / nav / tab controllers) and there's zero added crash
surface. Matches GA4 `engagement_time_msec`; powers `/analytics/engagement`.

## Account deletion (s58.209)

`auth.deleteAccount(completion:)` (Bearer) deletes the signed-in user's account
for Apple App Store Guideline 5.1.1(v). `Result<AccountDeletionResult, Error>` —
`status` is `"purged"` (grace 0) or `"pending"` (disabled + sessions revoked now;
hard-deleted at `scheduledPurgeAt`, cancellable by signing back in within grace).
Wipes local identity on success. Grace period is a per-project Auth setting.

**4.3.1 — refresh-before-delete.** `deleteAccount(completion:)` now resolves a
fresh access token via `getAccessToken` (refreshing a past-expiry cached token)
BEFORE the `DELETE` instead of sending the raw cached token via `bearerHeaders()`.
This is a one-shot destructive action — a 401 from a stale token (typical when a
user taps "delete" after the app sat idle past the short access TTL) would
silently strand them with an undeleted account (cause of prod
`DELETE /auth-service/me 401`s). **Host-app note:** wire your delete button to
`auth.deleteAccount()` — NOT `consent.requestDeletion()` (GDPR ledger only).

## Deep Links no-app routing mode (s58.208)

`LinkCreateInput` gains an optional `noAppMode: String?` (`"auto"`/`"store"`/`"web"`)
forwarded as `noAppMode` on `POST /sdk/links`. Controls what a **mobile visitor
without the app installed** gets: `auto` (default) = store-if-registered-else-web,
`store` = prefer store, `web` = force the web fallback even when a store URL
exists. `nil` inherits the project default. Additive + backwards-compatible.
Desktop is always web.

## Publish

`git tag <semver> && git push origin <semver>`. Release via `gh release create`.
