# Changelog

## 4.1.1

**macOS build fix.** `Package.swift` declares `.macOS(.v13)`, but
`SendoraCloudLiveActivities.swift` guarded ActivityKit usage with only
`#if canImport(ActivityKit)`. ActivityKit's module *is* importable on macOS, yet
`Activity` / `ActivityAttributes` are `@available(macOS, unavailable)`, so
`swift build` on a macOS host failed with "'ActivityAttributes' is unavailable
in macOS". Both guards now use `#if canImport(ActivityKit) && os(iOS)` (true on
iOS / iPadOS / Mac Catalyst, where the types are real). No API change; the iOS
build path is unchanged. Unblocks the Swift Package Index macOS compatibility check.

## 4.1.0

**Engagement-time analytics** (Wave 75). New `SendoraCloud.trackScreen(_:properties:)`
emits `screen.viewed` and flushes the previous screen's
`app.engagement { durationMs, screen, sessionId }` (foreground-only). New
`autoTrackEngagement` config flag (default on); `willResignActive` flushes +
pauses, `didBecomeActive` resumes. Spans <250ms dropped, >6h clamped. No
UIViewController swizzling. Matches GA4 `engagement_time_msec`; powers
`/analytics/engagement`.

## 4.0.5

**Device-takeover inline listener** (parity with RN 1.0.5).

New API on `SendoraCloud.auth`:

```swift
let unsub = SendoraCloud.auth?.onDeviceTakeover { evt in
    // evt.retiredAnonUserId — the anon user_id Sendora hard-deleted
    // evt.identifiedUserId  — the identified user_id that took over
    // evt.at                — Date the SDK observed the event
    // Delete the matching row from your local users mirror so
    // audience queries joining on user_id stop matching the stale
    // anon row.
}

let last = SendoraCloud.auth?.getLastDeviceTakeover()
```

Fires on every identified-signin path when the backend retired an anon
row during the request: `signIn`, `loginSocial` / `signInWithApple` /
`signInWithGoogle` / `signInWithGitHub` / `signInWithMicrosoft` /
`signInWithLinkedIn` / `signInWithFacebook` / `signInWithDiscord`,
`verifyMagicLink`, `verifyEmailOtp`, `challengeMfa`, passkey
authenticate, and OIDC SSO callback (`sendora_retired_anon` URL
fragment).

Local-only — survives webhook receiver downtime. For server-pipeline
cleanup also subscribe to the `auth.device_takeover` webhook.

See `/docs/device-takeover` on sendoracloud.com for the full
architecture writeup.

## 4.0.4

Device-takeover plumbing: every identified-signin path forwards the
anon refresh token to the backend as `prevAnonRefreshToken` so the
anon `user_id` is retired + push tokens reassigned to the
identified user. Inline listener API added in 4.0.5.

## 4.0.0

**Major bump** to align with backend s58.104 unprefixed alias routes.

- Backend resolves `orgId` from the API key server-side. No SDK-side
  `orgId` config field exists (and never did on iOS) — nothing to change
  in your `SendoraCloud.configure(apiKey:projectId:options:)` call.
- Internal URL construction was already unprefixed (`/api/v1/<path>`), so
  this release is API-compatible in source.
- Bundled SDK `version` string used in event `context.sdk.version` bumped
  to `4.0.0`.

### Migration

```diff
- .package(url: "https://github.com/sendoracloud/sdk-ios", from: "3.9.0"),
+ .package(url: "https://github.com/sendoracloud/sdk-ios", from: "4.0.0"),
```

No code changes required. All public method signatures (`configure`,
`trackEvent`, `identify`, `links.*`, `push.*`, `auth.*`, …) are unchanged.

## 3.9.0 and earlier

See git tags at https://github.com/sendoracloud/sdk-ios/tags
