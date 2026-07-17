# Changelog

## 4.7.0 — anon→social link-in-place (ADR-025)

`loginSocial` / `signInWithApple` / `signInWithGoogle` gain an opt-in `link: Bool = false`. When the device is anonymous and `link: true`, an anon→social upgrade sends `linkAnonymous` so the backend promotes the anonymous account **in place** — the user id (`sub`) is **preserved** (fires `auth.user_upgraded`) instead of a device-takeover that mints a new id (Firebase `linkWithCredential` parity). No effect when not anonymous, or on a collision (the social identity already belongs to another account, or the email is taken → falls back to the prior takeover/merge). Source-compatible default (existing trailing-closure callers unaffected); additive.

## 4.6.0 — restore iOS 15 support (deep links incl. `links.create()` on iOS 15)

Lowers the deployment floor back to **iOS 15** (2.3.0–4.5.0 required iOS 16). The package had been pinned to iOS 16 only because the passkey provider (`ASAuthorizationPlatformPublicKeyCredentialProvider`, iOS 16) wasn't availability-guarded. Now `SendoraCloudPasskeys` + `SendoraCloud.passkeys` are `@available(iOS 16, *)`-gated (same treatment Live Activities already had), so **deep links (including runtime `links.create()`), analytics, push, auth, and SSO all work on iOS 15 again**. Passkeys remain iOS 16+ — guard those call sites with `if #available(iOS 16, *)`. No other behavior change.

## 4.1.3 — MFA-from-anonymous device-takeover fix (audit s58.203 follow-up)

Fixes lost device-takeover when an MFA-enabled user signs in from an anonymous device:
- `signInWithMfaSupport()` previously called `wipeLocalIdentity()` **before** the MFA challenge resolved, so `challengeMfa()`'s `takeoverHint()` returned nil — no `prevAnonRefreshToken` was forwarded, the backend never retired the anon row / reassigned push tokens, and the device ended with **two user_ids + duplicate pushes**.
- Now: `signInWithMfaSupport()` captures the anon refresh token (no pre-call wipe) and on an MFA-required response **stashes** it keyed to the `mfaChallengeToken`. `challengeMfa()` forwards the stashed token and wipes the anon identity **only after a successful mint** — a wrong/expired code preserves the anon session for retry. The no-MFA direct-success path now also forwards the takeover hint (it previously didn't). Public API unchanged.

## 4.1.2 — s58.203 audit P0: offline data loss + push tracking fixed

Two production-breaking fixes:
- **Offline event batches >100 were permanently dropped.** The queue buffered up to 1000 events offline but flushed the whole batch to a fire-and-forget send and cleared the queue immediately; the backend `/events/batch` caps at 100, so any flush >100 (or any rejection) 400'd and the events were already gone. Now chunks outbound batches to ≤100 and only removes events the backend actually accepted (re-enqueues the rest), preserving order.
- **Push open / action-button tracking 400'd on every call.** `trackOpen` sent `sendId` + `clickAction`, but the backend requires `pushSendId` + `action`. Renamed the wire keys; public `trackOpen(sendId:clickAction:)` signature unchanged.

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
