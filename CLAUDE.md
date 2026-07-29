# sdk-ios (SwiftPM)

Published at `github.com/sendoracloud/sdk-ios`. Swift 5.9+, **iOS 15+** (`Package.swift` = `.iOS(.v15)`). Passkeys (`ASAuthorizationPlatformPublicKeyCredentialProvider`, iOS 16) are `@available(iOS 16)`-gated — `SendoraCloud.passkeys` + the `SendoraCloudPasskeys` class are iOS-16-only; everything else incl. `SendoraCloudLinks.create()` works on iOS 15. **History:** 2.3.0–4.5.0 forced iOS 16 (unguarded passkey provider); **4.6.0 (s58.235) restored iOS 15** by `@available`-gating passkeys — same treatment Live Activities (iOS 16.1) always had. The type-erased `_passkeys` backing store in `SendoraCloud.swift` exists because Swift forbids `@available` on a stored property.

> ⚠ **ADR-023 frozen contract.** UserDefaults/Keychain keys (`sendora_*`), the `X-Sendora-SDK-{Name,Version}` headers, and the `sendora_schema_version` marker are depended on by installed apps — never rename/remove a key (orphans session/queue on upgrade) or drop the header/marker. The version lives ONLY in `SDKVersion.swift`. Additive only; a format change is MAJOR + needs a migration. CI cap: `apps/backend/src/modules/developer-tools/sdk-contract-golden.test.ts`. Law: `docs/decisions/023-sdk-api-compatibility.md`.



## 4.16.0 — onDeviceTakeover doc fix: the account-deleting paths were missing (s58.273)

Parity: RN 1.31.0 / web 3.15.0 / Android 4.16.0. **Documentation-only in the SDK; no behaviour change.**

Customer-reported (Word Hurdle). The doc comment on `onDeviceTakeover` enumerated
where the listener fires — signIn / loginSocial / verifyMagicLink / verifyEmailOtp
/ challengeMfa / passkey / SSO — and **omitted the Game Center and Play Games
paths, the only ones that can DELETE an account.** It does fire there (centrally,
from the persist path), so this was purely a doc defect; but an integrator reading
that list would reasonably conclude a gaming adopt produces no takeover and skip
the one handler that path most needs. That is the path that destroys accounts.

The comment now names the gaming sign-ins explicitly and states the consequence:
a takeover means the anonymous account was retired — its row DELETED server-side
— while **the call itself resolved successfully**, so this listener is the only
client-side signal. It also points at `onCredentialInUse: reject` for callers
who would rather it not happen.

Guarded so the list cannot drift again: `credential-collision.test.ts` asserts
each SDK's doc block (the 1600 chars immediately above the declaration, not the
whole file) names its gaming path. Mutation-proven — redacting the tokens from
all four doc windows fails 4.

## 4.15.0 — credential-collision policy + anonymous link promotion (s58.272)

Parity: RN 1.30.0 / web 3.14.0 / Android 4.15.0. Full write-up in the RN CLAUDE.md 1.30.0 section.

- **`onCredentialInUse` (`adopt`|`reject`)** on the credentialed sign-in
  methods. **Omitted = adopt = every prior release** (no field is sent). On a
  collision the sign-in ADOPTS the owning account and — because the anon refresh
  hint is forwarded whenever the local user is anonymous — the server hard-deletes
  this device's anonymous row. That is a 200, so the wipe-ordering fix never
  covered it. `reject` fails with the credential-in-use error and changes nothing.
- **The collision error carries the taxonomy** (`kind`/`retryable`/`code`/`status`)
  plus `provider` + `collision` (`identity`|`email`).
- **Linking from an ANONYMOUS session** promotes the account in place (sub
  preserved) and the server ROTATES the session, because the `is_anonymous` JWT
  claim changed. The link path installs the returned `tokens` when the response
  carries `upgraded: true` — **not optional**, the old refresh token is revoked
  server-side. An identified link is unchanged (no tokens, cached user updated in
  place). Firebase `linkWithCredential` / Supabase `linkIdentity` parity.

`SendoraCloudAuth.CredentialCollisionPolicy` is a defaulted (`nil`) parameter on
`loginSocial` + `signInWithGameCenter`, so every existing call site compiles
unchanged. `swift build` clean; `swift test` 23/23.

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

## 4.14.0 — anonymous-session reuse, total error coercion, + 4 MFA/delete defects (s58.271d)

Parity with RN 1.29.0 / web 3.13.0 / Android 4.14.0.

- **A corrupt user blob is now actually recoverable.** Keeping the refresh token
  when the cached user fails to parse was only half a fix: nothing could turn
  that token back into an identity, because the refresh discarded the `user` the
  backend returns in the very same response — so the session sat live with a
  permanently null user and the next sign-in orphaned the account anyway. The
  refresh now adopts that user, but **only when there is none** (a refresh is a
  token rotation, not an identity change), only when it is well-formed (the
  route tolerates a missing user row), and it emits `signed_in` because
  recovering an identity IS a transition — while a plain rotation with a user
  already present still emits nothing.

- **`signInAnonymously(forceNew:)` reuses an existing anonymous session.** It
  minted a brand-new user unconditionally, and `persist` overwrote the stored
  refresh token — the previous anonymous account's ONLY durable handle — with no
  takeover, no webhook and no state event. An app calling it defensively on
  every cold launch fragmented the player across a new `user_id` per launch:
  the same lost-progress outcome as a failed sign-in wiping the session, except
  on a **healthy** network. Now short-circuits when the cached user is anonymous
  AND a refresh token is in the Keychain (Firebase's `signInAnonymously` does
  exactly this). `forceNew: Bool = false` is a defaulted parameter, so every
  existing call site compiles unchanged.
- **Every rejection carries a `kind`.** The default must stay non-fatal — that
  is what makes the one-code `isDeadRefreshError` allow-list safe rather than
  lucky: an unmapped failure can only become session-fatal through a deliberate
  edit.

**⚠ Four real defects surfaced while doing the coercion pass — all fixed:**

- `deleteAccount` threw bare `NSError`s, so the destructive path had literally
  no `.kind` at all.
- `enrollMfa` reported a **timeout** as `.unknown("Malformed enrollment
  response")` — non-retryable, so the app would not retry a call that had
  simply timed out.
- `confirmMfa` reported a **timeout** as `.success(false)` — i.e. "your code is
  wrong". The user retypes a correct code and is told it is wrong.
- `disableMfa` reported a **timeout** as `.success(())` **while MFA was still
  armed** — the app tells the user MFA is off when it is on. That is a
  security-relevant lie, not just a UX bug.
- Related: the dictionary `parseError` collapsed EVERY unmapped code into
  `.unknown`, so a 429 or 503 on magic-link, email-OTP, password-reset,
  verify-email, `link*` and `listLinkedIdentities` could never classify as
  `.rateLimited` / `.server`.

**⚠ TWO CARRIER CHANGES (same additive class as 4.13.0's `.rejected`):**

1. `deleteAccount`'s completion type is unchanged (`Result<AccountDeletionResult,
   Error>`) but the value inside is now `SendoraCloudAuthError`, not `NSError`.
   An app reading `(error as NSError).code == 401 / -1 / 500` must move to
   `.kind` / `.status`. Message strings are byte-identical, and a new
   `LocalizedError` conformance keeps them on `error.localizedDescription`
   (which previously printed Foundation's generic "operation couldn't be
   completed" for the enum).
2. On the plain `post`/`get` auth paths an unmapped backend code now surfaces as
   `.rejected(code:message:status:retryAfterSeconds:)` instead of
   `.unknown("CODE: message")` — that is what gives it a real `kind`. Codes with
   a dedicated case (`CONFLICT`/`EMAIL_ALREADY_TAKEN`, `NOT_ANONYMOUS`,
   `CREDENTIAL_IN_USE`, `UNAUTHORIZED`/`HTTP_401`) still produce exactly the
   same case as before, pinned by a test. Side effect: `.message` no longer
   carries the `"CODE: "` prefix on those paths — the code is available
   structurally instead.

`swift build` clean; `swift test` **22/22** (was 16/16).

## 4.14.0 — token refresh + transport: the remaining loss routes (s58.271b)

Parity with RN 1.29.0 / web 3.13.0 / Android 4.14.0. See the RN CLAUDE.md
1.29.0 section for the full write-up.

- **⚠ `/token/refresh` shape (CRITICAL, pre-existing).** Refresh read the flat
  `data.*` the backend abandoned in s58.76 — the rotated trio is under
  `data.tokens`. It silently returned nil forever, so the session died at
  access-token expiry and the app minted a fresh guest. Both levels accepted now.
- **`APIClient.request` no longer discards a non-2xx body** (the same defect
  fixed in sdk-android 4.13.0). It nil'd every error response, so the 4.13.0
  taxonomy could not classify anything and `.signedOut(.sessionExpired)` was
  unreachable. The body is returned, the HTTP status is stamped onto the error
  envelope, and only a 5xx or a transport failure trips the breaker.
- **The circuit breaker no longer latches permanently.** `shouldSkip` hard-tripped
  on `consecutiveFailures > maxFailures`, which can never reset — no request is
  attempted, so no success is recorded — wedging the whole SDK for the process
  lifetime after ~6 minutes offline. Now purely time-based (half-open by
  construction), matching sdk-android.
- **A generic 401 no longer wipes the session** (`isDeadRefreshError` narrowed to
  `INVALID_REFRESH_TOKEN`), and the refresh race is gated both directions by
  `tokenStillCurrent(sent)`.

## 4.13.0 — a failed sign-in can no longer destroy the account (s58.271)

**The bug (customer-reported, HIGH — silent permanent data loss).** Five
credentialed sign-in paths cleared local identity — `wipeLocalIdentity()`,
which drops the Keychain tokens AND fires `onAnonymousWipe` (device/session id
rotation + event-queue drop) — BEFORE their network call, and no failure path
restored it. For an anonymous user the stored refresh token is the ONLY durable
handle on the account, so once the wipe landed and the call failed the account
was unreachable from the device forever; offline it was not a race but a
**guarantee**. Word Hurdle lost a real production account this way (30
purchases incl. an active subscription, 3,355-gem balance) through Game Center
sign-in on a flaky network. Affected: `signIn`, `loginSocial` (and all seven
`signInWith*` wrappers), `signInWithGameCenter`, `verifyMagicLink`,
`verifyEmailOtp` — the last three wiped before ANY input was validated, so a
mistyped OTP or a stale tapped magic link cost the account too.

**The invariant now, everywhere: a failed auth attempt leaves the caller
exactly as it found them.** Each path captures the anon refresh via
`takeoverHint()` (no wipe), calls, and hands the clear to `callAuthSync`'s new
`replacesIdentity:` flag, which runs `wipeReplacedIdentityIfPresent()` **only
from the success branch, glued to the `persist`** — the shape
`signInWithMfaSupport` / `challengeMfa` already used since the s58.203 fix (see
"4.1.3" above) and which was never propagated to their siblings. `signUp`
(in-place `/upgrade`) and `signInAnonymously` pass false: nothing to replace.
Same fix in RN 1.28.0 / web 3.12.0 / Android 4.12.0.

Three things ship alongside it, because the fix changes what a rejection
*means* and an app must be able to act on it:

- **Error taxonomy — `.kind` / `.retryable` / `.retryAfterSeconds` / `.status`**
  as computed properties on `SendoraCloudAuthError`, plus the
  `SendoraCloudAuthErrorKind` closed set (`network` · `server` · `rate_limited`
  · `invalid_credential` · `account_locked` · `credential_in_use` ·
  `already_identified` · `cancelled` · `config` · `unknown`, raw values
  identical to `@sendora/shared` `AuthErrorKind` so `kind.rawValue` logs the
  same token on all 4 SDKs). `retryAfterSeconds` comes from
  `error.details.retryAfterSeconds` (429 backoff + the new backend
  `ACCOUNT_LOCKED` 403; **absent = the lock needs support**).
  **⚠ Two carrier changes to know about:** (1) a NEW enum case
  `.rejected(code:message:status:retryAfterSeconds:)` — a Swift enum can't carry
  per-instance data otherwise; every pre-4.13.0 case is still produced for the
  exact same codes (mapping centralised in `mapKnownErrorCode`), but an app that
  switches over the enum **exhaustively** must add a `default:` (same class of
  additive change as 4.10.0's `.alreadyIdentified`/`.credentialInUse`). (2) the
  sign-in paths now POST through `APIClient.requestWithDetails` instead of
  `post`, which collapsed EVERY non-2xx to `nil` — that is why a wrong password,
  a 409 and a dead radio all surfaced as `.network("Network request failed")`
  and why `parseError`'s code branches were effectively dead. Auth 4xx also no
  longer trips the client-wide circuit breaker (only a status-0 transport
  failure does).
- **`onAuthStateChanged(listener) -> unsubscribe`** — one stream:
  `.signedIn` / `.signedOut(reason: .user | .sessionExpired | .accountDeleted)`
  / `.deviceTakeover` / `.deletionCancelled`. The load-bearing case is
  `.sessionExpired`: a session that died in the background (dead refresh token)
  previously emitted **nothing**, so an app couldn't tell it from a deliberate
  sign-out and only noticed when `getAccessToken` returned nil. Replays the
  current state on subscribe once the Keychain hydrate has run (`hydrated` flag,
  set at the end of `init`) — never before, which would report "signed out"
  during restore — and emits nothing for a signed-out cold start. **A
  `.replaced` wipe (the internal pre-`persist` clear) emits NOTHING**, else every
  sign-in would look like a logout/login pair. A failed sign-in emits nothing at
  all: no state changed. `onDeviceTakeover` / `onDeletionCancelled` unchanged.
- **A rate limit is no longer treated as a dead session.**
  `isDeadRefreshError` dropped `RATE_LIMIT` / `RATE_LIMIT_EXCEEDED`: a 429 is
  transient throttling (shared NAT/CGN egress, refresh burst) and says nothing
  about token validity, yet it was wiping live sessions from the background
  refresh path. Relatedly, `init`'s corrupt-cache guard no longer calls
  `storage.clearAuthTokens()` when only the cached USER blob failed to decode —
  it drops the user + access token and **keeps the refresh token**, the only
  thing that can recover that account.

Tests: `Tests/SendoraCloudTests/SendoraCloudAuthErrorTests.swift` (taxonomy
table + source guards pinning wipe-after-validate — the wipe must be glued to
the persist, and every wipe must state its reason). `swift build` + `swift test`
16/16 clean. Additive: no frozen Keychain key / header / route / wire shape
touched (ADR-023), no error code renamed, no method signature changed.

## 4.12.0 — listLinkedIdentities() (read side of ADR-030, s58.270)

`auth.listLinkedIdentities { result in }` → `Result<LinkedIdentitiesResult,
SendoraCloudAuthError>` where `LinkedIdentitiesResult` = `{ identities:
[LinkedIdentity(provider, email?, linkedAt)], hasPassword }`. The full set of
credentials on the current account — the cross-device / reinstall-durable source
of truth for a "Connected: Game Center · Google" UI (`getCurrentUser()` only
holds the primary `signupMethod`/`lastLoginMethod`). Bearer-authenticated GET
`/auth-service/me/identities` that resolves a fresh access token first (mirrors
`deleteAccount`); `.unauthorized` when signed out. Firebase `user.providerData` /
Supabase `user.identities` parity. Version in `SDKVersion.swift`. `swift build`
clean. Additive, SDK-only (not in the golden contract). Parity with RN 1.27.0 /
web 3.11.0 / Android 4.11.0.

## 4.11.0 — onDeletionCancelled (account-restore listener, s58.269)

`auth.onDeletionCancelled { evt in }` + `getLastDeletionCancelled()` (returns
`DeletionCancelledEvent`) — mirrors `onDeviceTakeover` (UUID-keyed, lock-safe,
snapshot-then-dispatch). Fires when a sign-in cancelled a pending self-service
deletion within grace (account restored, same sub). The 4 per-path device-takeover
fire sites were unified into `fireLifecycleSignals(from:identifiedUserId:)`, which
parses BOTH `retiredAnonUserId` and the new `reactivatedFromDeletion` off the
response and fires the matching listener — so every sign-in path emits both
consistently. Pairs with backend `auth.deletion_cancelled`/`auth.deletion_scheduled`
webhooks. `swift build` clean. Additive, not in the golden contract. Parity with
RN 1.26.0 / web 3.10.0 / Android 4.10.0.

## 4.10.0 — identity linking on an identified session (ADR-030) + signUp() fix

Non-anonymous sibling of ADR-025. New `auth.linkEmailPassword` / `linkSocial`
(+ `linkGoogle`/`linkApple`) / `linkGameCenter` attach a 2nd credential to an
already-identified account (sub preserved), Bearer-authenticated (mirror
`deleteAccount`'s `getAccessToken` → Bearer POST flow), and refresh the cached
user in place via `updateLocalUser` — **NO token rotation**. Collision → new
`SendoraCloudAuthError.credentialInUse`. Play Games is Android-only, so iOS ships
`linkGameCenter` but not `linkPlayGames`. **signUp() fix:** on iOS, `signUp()`
only hit `/upgrade` when anonymous; a non-anon signUp used to wipe + fresh-signup
(= duplicate account). It now returns the new `.alreadyIdentified` error (no wipe,
no second account); `parseError` also maps the backend's new `NOT_ANONYMOUS` code
→ `.alreadyIdentified` and `CREDENTIAL_IN_USE` → `.credentialInUse`. Additive,
SDK-only (not in the golden wire contract); no frozen key/header touched. Version
in `SDKVersion.swift`. Parity with RN 1.25.0 / web 3.9.0.

## 4.9.0 — `signupMethod` + `lastLoginMethod` on the auth user

`SendoraCloudAuthUser` gains two optional read-only fields: `signupMethod` (how the account was first created, immutable) + `lastLoginMethod` (most recent auth). Free-form provider tokens (`password`/`anonymous`/`google`/`apple`/`gamecenter`/`playgames`/`magic_link`/`passkey`/`oidc`/…). Backend populates them on the login/signup/social/game response (s58.266, mig 0094). Both are `String?` on the `Codable` struct, so decoding a cached user from a pre-4.9.0 build stays safe (absent → nil); `parseSuccess` also reads them off the response dict. Display-only — never an authorization signal. No frozen key/header/wire-shape touched (ADR-023); not in the golden wire contract. Parity with RN 1.24.0 / web 3.8.0 / Android 4.8.0.

## 4.8.0 — Game Center sign-in

`auth.signInWithGameCenter(publicKeyURL:signature:salt:timestamp:teamPlayerID:bundleID:link:completion:)` — email-less, player-keyed sign-in. Pass the payload from `GKLocalPlayer.local.fetchItems(forIdentityVerificationSignature:)` + the app's bundle id; forwards to `POST /auth-service/login/game-center`. Mirrors `loginSocial` exactly (opsQueue, anon-takeover hint read BEFORE wipe → `prevAnonRefreshToken`, `link:true` → `linkAnonymous` for ADR-025 link-in-place, `callAuthSync`). Additive, SDK-only (not in golden wire contract). App obtains the GameKit payload itself (no GameKit dep forced on the SDK). Ships alongside backend Phase 1 + RN 1.21.0.

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

Native SDKs ship via a git tag on the **separate public mirror** `github.com/sendoracloud/sdk-ios` (SwiftPM), not npm. From a monorepo checkout:

1. Guard the version: `node scripts/publish.mjs ios` (verifies `SDKVersion.swift` is consistent).
2. Mirror it (operator, needs a clone of the mirror + push creds):
   `node scripts/publish-native-mirror.mjs ios --mirror-dir <clone> [--push] [--delete]` — rsyncs `packages/sdk-ios/` → the mirror clone (excludes `.build`/`.swiftpm`), commits, tags `<semver>`, pushes. **DRY by default**; `--push` executes; `--delete` makes the mirror an exact copy. It refuses a wrong/monorepo mirror dir or an existing tag. First time: `git clone https://github.com/sendoracloud/sdk-ios.git <clone>`.

Raw path (equivalent): rsync source into the mirror clone, then `git tag <semver> && git push origin main --tags`; release via `gh release create`.
