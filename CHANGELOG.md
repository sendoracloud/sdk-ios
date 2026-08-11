# Changelog

## 4.20.0 — unlink(provider): remove a linked sign-in method

Parity: RN 1.35.0 / web 3.19.0 / iOS 4.20.0 / Android 4.20.0. Additive.

The write half of `listLinkedIdentities()`. An app could already render
"Connected: Google · Game Center"; ``auth.unlink(provider:)`` is what the Disconnect
button beside each entry calls.

**⚠ The server refuses to remove the last way into the account** — code
`LAST_CREDENTIAL`, kind ``.lastCredential``. An account with no credentials still
exists and still holds the user's data, but nothing can ever authenticate into
it again: no password to reset, no identity to present. That is permanent
lockout, not an inconvenience, and it is unrecoverable without manual database
surgery. A password counts as a credential, so an account with email+password
plus one social identity may drop the social one.

Supabase enforces the same floor (`unlinkIdentity` requires >= 2 identities);
Firebase's `unlink()` does not and will strip the last provider. We follow
Supabase, deliberately.

**Prefer preventing the tap to explaining the refusal.** Read
`listLinkedIdentities()` and disable Disconnect when
`identities.count + (hasPassword ? 1 : 0) <= 1`. The error is the backstop, not the UX.

An unlinked provider returns `NOT_FOUND` rather than reporting success — a
screen saying "disconnected" about a credential that is still attached tells
the user something untrue about their account.


## 4.19.0 — getAccessToken() no longer returns a token past its own `exp`

Parity: RN 1.34.0 / web 3.18.0 / iOS 4.19.0 / Android 4.19.0. Customer-reported
(Word Hurdle) against the React Native SDK; all four shared the defect.

**Fixed (HIGH — silent, up to a full token TTL).** `getAccessToken()` promises
it never returns a token past its `exp`, but enforced a different value: a
deadline computed as `now + expiresIn` at mint, persisted, restored verbatim.
That deadline is deliberately **skew-invariant** — a permanently wrong clock
cancels on both sides, because it is written in the same frame it is read in —
but blind to a clock that **moves**. Corrected clock after a long power-off, a
restore, or a manual set, and the tracked deadline is stale by exactly the size
of the correction, across relaunches. Observed on a physical device with a token
**1929 seconds past its `exp`**: every request 401'd while the app still looked
signed in.

The token's own `exp` is now required as well. **Requiring it alone would have
been worse than the bug** — a clock fast by more than the token TTL reads every
freshly-minted token as already expired, so every call refreshes, forever
(measured at 10 reads → 10 refreshes). A one-shot probe bounds it: when a
refresh performed *because* the two deadlines disagreed returns a token that
STILL reads expired, the clock is proven fast rather than the deadline stale,
and the guard is released for that process. Never persisted.

Also fixed: the post-lock re-check inside the refresh path applied no `exp`
check and no safety margin, on the one path meant to repair an expired token; and the
proactive-refresh cron reasoned only from the stale deadline, so it never fired
during the window.

**Added — `getAccessToken(forceRefresh: true) { token in … }`.** The supported way to say "your tracked deadline is wrong".
Skips the cache but not the single-flight or the backoff cooldown, so
force-refreshing on every 401 cannot turn an outage into a hot loop.

`storagePrefix` is deliberately NOT part of this release for iOS: UserDefaults
and the Keychain are already scoped per bundle identifier, so a debug variant is
isolated by construction. The React Native and web SDKs, where one JS bundle can
point at two projects, get the option.


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
