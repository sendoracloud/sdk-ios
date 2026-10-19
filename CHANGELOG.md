# Changelog

## 5.6.0 — the server's wait is honoured, Cloudflare challenges are never refusals, a poison event no longer blocks the queue

Additive; no frozen key, header or route changed. One NEW public overload, one new optional property.

- **`Retry-After` is honoured.** A 503 (overload) keeps every SDK call off the network for the server's wait
  (`Retry-After`, else `error.details.retryAfterSeconds`; capped at 1 hour). A 429 (one lane's budget) holds the whole
  client for at most 60 s — a quota 429 that asks until the month resets must not block sign-in or token refresh — and
  the full wait (≤ 1 h) pauses only the event queue. A 429 used to RESET the breaker. Backoff after a failure is now full jitter (`random(0, min(60 s, 2^n s))`), so devices that
  failed together no longer retry together. A plain 4xx still never trips the breaker.
- **Cloudflare challenges** (`cf-mitigated: challenge`, a 403 or 503 from Cloudflare, not the API) are treated as "the
  request did not arrive": a retryable `.network` error, held ≥ 60 s. A challenge can no longer end a session or be read
  as a wrong password.
- **Event queue.** Chunks are ≤ 100 events AND ≤ 60 KB (the batch route refuses bodies over 64 KB). A 400 / 413 / 422
  on a multi-event chunk is halved and resent, so only the one bad event is dropped; other permanent refusals (401 /
  403 / 404 …) drop the chunk — it used to be retried forever and every event behind it was never delivered. A 429 is no
  longer counted as delivered. A transient failure (offline, 408, 429, 5xx, a challenge, 401 `IDENTITY_UNVERIFIED`)
  keeps the events, and so does an event a 201 batch answer lists as an identity refusal
  (`data.rejected[i].code == "IDENTITY_UNVERIFIED"`) — the rest of that batch is removed; each event may fail 50 times on a server answer (408 / 5xx / `IDENTITY_UNVERIFIED`) before it is
  dropped — offline time, 429s and challenges never spend that budget. Sent events are removed by identity (an event
  trimmed at the queue cap mid-flight can no longer cost an unsent one). A single event over 30 KB goes to
  `/events/batch` (the `/events` cap is 32 KB). `trackScreen` refuses a name over 128 characters (it 400'd the batch).
- **The event queue backs off on its own** — full jitter, 1 s doubling to 5 min, after every failed delivery (a
  server's wait raises the floor), reset by a delivered send; no flush starts before it, including the ones
  `trackEvent` triggers. During a 5xx outage every tracked event used to re-send the same head chunk. A refused chunk
  stays halved until a send succeeds (then doubles back), one flush makes at most 20 requests, and three 5xx answers in
  a row for the same multi-event chunk halve it too, so one event the server always fails on cannot hold 99 others.
  Cloudflare's 520–527 / 530 (origin unreachable) never spend an event's budget.
- **Identity token attached when sent, not when tracked.** An event queued before `identify()` handed over a token now
  carries it; the token is no longer written to the persisted queue. (It counts toward the 60 KB chunk limit.)
- **Password sign-in remembers this device.** The `knownDeviceToken` `/auth-service/login` and `/mfa/challenge` return
  is kept per account (Keychain, keyed by a hash of the address, newest 20) and sent on the next sign-in for that address,
  so an account under a password-guessing attack still admits its owner's phone. Survives `signOut()` and the reset;
  `deleteAccount()` removes that account's entry.
- **Push tokens are proven.** `push.registerToken` sends the player's access token (`Authorization: Bearer`) when a
  session exists, so the backend can bind the device to the player. Without a session — or if the token takes over
  5 s (a refresh on a bad network) — it registers exactly as before.
- **Links: final revokes.** `LinkCreateResult.revokeToken` (new, optional). The SDK keeps it per shortcode (Keychain,
  newest 200) and `revoke(shortcode:)` sends it, which makes the revoke final; it is forgotten on success. New
  `revoke(shortcode:revokeToken:completion:)` → `LinkRevokeResult { shortcode, final }`.
- **Fix (found by the live staging run): events from an app configured without `projectId` were all refused.** A
  missing project id was sent as JSON `null`, which the server rejects (422) — so with the key-only setup documented
  since 3.0.0 no event was ever delivered. It is now omitted (the key identifies the project); the same fix applies to
  the install and deferred-link reports.
- **Fix:** `support.getUnreadCount` went out on `URLSession.shared` — without the API key, the SDK headers, pinning or
  the no-cookies session. It now uses the SDK's own client.

## 5.5.0 — Support: the player's own conversations, verified reporter, ticket context, theming

Parity with RN 1.42.0 (s58.376, asked for by Sudoku Hurdle). Additive; nothing existing changes shape.

- **`SendoraCloud.support?.listMyTickets(widgetId:)` / `getMyTicket(widgetId:ticketId:)` /
  `replyToMyTicket(widgetId:ticketId:body:)`** (`async throws`) — the player's own tickets for a native support
  screen. Refusals throw `SendoraSupportError` (`code`, `status`) — never an empty list.
- **`createTicket(subject:body:…:metadata:)`** (`async throws`) — new on iOS; sends the player's access token when
  signed in, so the ticket carries their VERIFIED user id. **`deviceContext()`** — app version + build, OS + version,
  device model (`iPhone15,2`), SDK version. `sanitizeMetadata(_:)` — the backend's rules.
- **`presentContactWidget`** gains `metadata:`, `includeDeviceContext:` (default true), `attachSession:` (default
  true — the token rides the URL fragment), `accent:`; **`presentTicketHistory`** gains `accent:`. All defaulted and
  placed before `completion:`, so existing calls compile unchanged.
- **Fix:** support calls (incl. `getUnreadCount`) always went to production — they now use the configured
  `apiBaseUrl`. `SendoraCloud.support` (the API half) now exists on every platform; the hosted screens stay iOS-only.

## 5.4.3 — README install pin

No code or behaviour change (only `SDKVersion.sdkVersion`, which the SDK reports in `X-Sendora-SDK-Version`). The README told
new integrators `from: "4.0.0"`; SwiftPM's `from:` never crosses a major version, so that resolved to the
latest **4.x**, a whole major behind. It now names the current release, and a new "Upgrading from 4.x"
section lists the three completion-handler signatures 5.0.0 changed.

## 5.4.2 — claiming or restoring a held guest works within one launch

Parity with RN 1.41.2. Before the server fix (e09c86dc, already live), `/token/refresh` preferred the `sd_rt` refresh cookie over the token in the request body. A phone keeps a native cookie jar, and after a sign-in that jar holds the ACCOUNT's cookie — so refreshing a HELD guest's token was answered for the account, and the SDK wrote the account's token into the guest's slot. The device lost its only copy of the guest's credential; `claimHeldGuest()` / `merge()` then failed with 401 and `restoreHeldGuest()` released the guest. The guest's account was never touched on the server. An ephemeral `URLSession` still keeps an in-memory cookie jar for the life of the process, so sign-in → claim in one launch was exposed.

- **No cookies.** The SDK's session configuration now sets `httpShouldSetCookies = false`, `httpCookieAcceptPolicy = .never` and no cookie storage.
- **Identity check on a held refresh** — a response for anyone but the held guest fails with `HELD_GUEST_IDENTITY_MISMATCH` (`.rejected` code) and changes nothing.

## 5.4.1 — a dead session is `.sessionExpired` again; the server's detail is `lastSignedOutEndReason()`

**Fix to a 5.4.0 behaviour change (ADR-023: a new value is additive only for a NEW situation).**
A session that died on a server-rejected refresh was reported as `.sessionExpired` through
5.3.0. 5.4.0 reported the server's own verdict as the reason instead (`.revoked` / `.deleted`),
which gave two old situations new names: "account deleted on another device" and "sessions
revoked". Adding a value to a union is additive for the compiler, not for a listener that
matched the old value. A listener that acted only on `.sessionExpired` (the documented pattern, and
the RopoLabs template's session-death handler) silently ignored both, leaving the app on a
signed-in screen where every request fails. Reported by RopoLabs against the published
tarball before any production install.

- `.signedOut(reason:)` is `.sessionExpired` for EVERY server-rejected refresh, exactly as 5.3.0.
- New `SendoraCloudAuth.lastSignedOutEndReason() -> SendoraCloudRefreshEndReason?`: the server's
  verdict (`revoked` / `deleted` / `expired` / `reuse` / `unknown`), set BEFORE the event is
  delivered so a listener reads it inside its `.signedOut` arm (same pattern as
  `lastSignedInCause()` — the case's payload is frozen for source compatibility). `nil` after
  `signOut()` / `deleteAccount()` / `discardWithheld()` and from an older backend.
- `.revoked` / `.evicted` / `.deleted` stay in `SendoraCloudAuthSignedOutReason` so code written
  against 5.4.0 compiles; they are never emitted again.
- Nothing else changed (storage, wipe effects, held-slot release rules).

Parity: RN 1.41.1 / web 3.24.1 / Android 4.26.1. Guard: `AuthMachineRowScenarios2`
`scenario_refresh_dead_current` (every endReason → `.sessionExpired`; the accessor read INSIDE a
listener equals the server's verdict; limbo death; `signOut` clears it).

## 5.4.0 — sign-in no longer retires the guest — it is held on the device (ADR-033 wave 1)

**Two behaviour changes, both strictly less destructive than before; everything else is additive
(MINOR under ADR-023). Lockstep with RN 1.41.0 / web 3.24.0 / Android 4.26.0.**

1. **Sign-in no longer retires the guest — it is held on the device.** A credentialed sign-in
   (`signIn`, `loginSocial` and every `signInWith*`, `signInWithGameCenter`, `verifyMagicLink`,
   `verifyEmailOtp`, `challengeMfa`, passkey, SSO) from a guest no longer sends the guest's refresh
   token (`prevAnonRefreshToken` / `linkAnonymous` / `onCredentialInUse` are never sent). The guest
   is HELD in one of 5 fixed Keychain slots (`sendora_auth_held_0…4`) and the server row survives.
   `onAuthStateChanged` emits `.guestHeld(userId:count:)` then ONE `.signedIn` — no `.signedOut`.
   Read `heldGuests()` / `heldGuest()`, then `restoreHeldGuest(id:)` (sign back in as the guest),
   `claimHeldGuest(id:)` (merge it INTO the current account — destructive, optional) or
   `discardHeldGuest(id:)` (real server delete). `signInAnonymously()` / `ensureSession()` in the
   signed-out state restores the newest eligible held guest before minting (`autoRestoreHeldGuest`,
   default on) — visibly: `.signedIn` with `lastSignedInCause() ==
   .restore` (re-register push) then `.guestReleased(.restored)` — the same order on every restore path. `onDeviceTakeover` / `getLastAnonRetirement()` / `.deviceTakeover`
   stay callable and never fire for this SDK's sign-ins.
2. **`link: true` over an identified session attaches or errors — it never switches.**
   `loginSocial(link: true)`, `signInWithApple/Google(link: true)` and `signInWithGameCenter(link:
   true)` from `anonymous` AND `identified` go to `/me/link/*` on the current Bearer: a promotion keeps
   the `sub`; an identity already on this account is a quiet success (no event); an identity owned
   elsewhere is `.credentialInUse` (pass `onCredentialInUse: .adopt` to fall through to a plain
   sign-in bound to the SAME credential — the guest is held); a stale session is `RECENT_AUTH_REQUIRED`
   (kind `.recentAuthRequired`). In the signed-out state `link: true` is a plain sign-in.

**New (additive):**
- `status()` → `SendoraCloudAuthStatus` (`unknown | signedOut | anonymous | identified | withheld`) and
  `authStateReady(completion:)`. ⚠ NORMATIVE: default-branch on it (`default:` / no exhaustive
  switch); a later value is a MAJOR. `status()` is the ONLY way to tell `withheld` from `signedOut`
  (`currentUser` is nil in both). `getRefreshToken()`, `lastSignedInCause()`.
- `SendoraCloudAuthStateChange` gains `.initial(status:user:withheld:)` (replayed once per subscriber,
  INCLUDING signed-out / unknown / withheld — the `.signedIn` replay is kept too), `.userUpdated(user:cause:)`,
  `.guestHeld`, `.guestReleased(userId:reason:endReason:)`, `.sessionWithheld`. `eventName` gives the
  shared snake_case token. `SendoraCloudAuthSignedOutReason` gains `revoked | evicted | deleted` (B11).
  ⚠ An exhaustive `switch` over either enum needs a `default:` (same additive class as 4.13.0).
- Typed verbs: `signIn(with: SendoraCloudCredential)` → `SendoraCloudSignInResult`
  (`.done(user:previous:reactivated:)` / `.mfaRequired(challenge)` with `verify(code:)`), and
  `link(_:)` → `SendoraCloudLinkResult` (`.done(user:upgraded:alreadyLinked:)` /
  `.credentialInUse(ctx)` with `ctx.switchAccount(refetch:completion:)` + `ctx.keepCurrent()` /
  `.recentAuthRequired`). `switchAccount()` is bound to the refused credential: same payload under 5
  minutes, otherwise `refetch` must hand back a fresh native credential and a changed `teamPlayerID`
  aborts with `.credentialChanged`.
- Project guard (opt-in): `SendoraCloudConfig(expectedProjectId:)` — a UUID, equal to `projectId` when
  both are set (`configure()` logs + aborts otherwise). A stored session whose JWT `project` claim
  disagrees is `status() == .withheld`: nothing wiped, NOTHING written (byte-identical Keychain),
  `withheld()` populated, every identity verb refuses `AuthError(kind: .config, code: "SESSION_WITHHELD")`
  with no network; `discardWithheld()` (= `signOut()` in that state) clears exactly the session keys,
  revokes server-side and keeps the held guests, queue and analytics id. A fresh mint under the wrong
  key rejects `PROJECT_MISMATCH` and revokes the minted token — no relaunch loop.
- `deleteAccount(alsoDiscardHeldGuests:)` → `AccountDeletionResult.heldGuests` /
  `heldGuestsDiscardFailed`. Held guests SURVIVE a delete (device + server) and are never auto-restored
  afterwards (explicit `restoreHeldGuest(id:)` only).
- `SendoraCloud.reset(includeHeldGuests:)` — accepted for parity with RN/web. iOS `reset()` keeps its
  5.3.0 semantics exactly: it resets the analytics identity only and never signs out (RN/web `reset()`
  always signed out; iOS never did, and changing that is not a MINOR). The flag therefore has no effect
  on iOS; `signOut()` is the auth call and keeps held guests.
- New typed errors: `.sessionWithheld`, `.projectMismatch`, `.heldGuestLimit`, `.heldGuestProjectMismatch`,
  `.ambiguousHeldGuest` (kind `.config`), `.heldGuestGone`, `.credentialChanged` (`.invalidCredential`),
  `.restoreFailed` (`.server`, retryable) — all with `.code`. `SendoraCloudAuthUser.project` (B17).
  `SendoraCloudPasskeyError.authError` / `SendoraCloudSsoError.authError`.
- `refreshAccessToken(completion:)` is public (the README documented it for years); `getAccessToken(forceRefresh: true)`
  now genuinely bypasses the cached token (it was short-circuited by the stashed-token check).
- On-device: `sendora_auth_session` is dual-written beside the four frozen keys (a 5.3.0 reads the
  session after a downgrade; the slots are simply ignored), `sendora_schema_version` → `"2"` on the
  first install commit, `sendora_auth_mint_key` (B10 idempotent mint, non-secret, cleared on success).

**Fixed en route:** `SendoraCloudConfig.autoTrackEngagement: false` was silently dropped by
`configure()`; the OIDC SSO callback read `/token/refresh`'s tokens from the flat level (they are
nested under `data.tokens` since s58.76) so it could never complete. The event queue is now dropped
ONLY by `deleteAccount` (the shared table); 5.3.0 dropped it on every identity wipe — sign-out, a
sign-in that replaced a guest, a session death — losing events already tracked. iOS `reset()` never
touched the queue and still does not.

**Passkey + OIDC sign-ins are CAS-guarded from the moment the sheet opens:** a result that lands after
a `signOut()` (or another sign-in) made while the system sheet / browser was up is dropped and its
server session revoked, instead of installed over the newer state.

**Downgrade-cycle safety:** a 5.3.0 `signOut()` / `deleteAccount()` clears only the four frozen keys,
so after 5.4.0 → 5.3.0 → sign-out → 5.4.0 the `sendora_auth_session` record of the signed-out (or
deleted) account is still on disk. 5.4.0 trusts that record ONLY when its refresh token equals the
frozen one; a record with no matching frozen counterpart is a leftover and is cleared silently (no
event beyond the boot `.initial`, no network) — it is never reinstalled. Installs write the four frozen
keys before the record, so a crash can never leave a record-only disk.

**Kept from 5.3.0 verbatim:** `deleteAccount(completion:)` and `SendoraCloud.reset()` are separate
overloads beside the new `deleteAccount(alsoDiscardHeldGuests:completion:)` /
`reset(includeHeldGuests:)` (not defaulted parameters), and `onAuthStateChanged` still replays
`.signedIn(user:)` after the new `.initial` when a session exists.

**Known gap (backend):** `POST /me/link/email` accepts `email` + `password` only, so
`signUp(name:)` from a guest drops `name` (the pre-5.4.0 `/upgrade` path kept it).


## 5.3.0 — signInAnonymously() no longer replaces a signed-in account

**Behaviour change.** Parity with RN 1.40.0 (reported by RopoLabs on the RN SDK; the
guard here was identical). `signInAnonymously(forceNew:)` reused an existing *anonymous*
session but fell through when the cached session was an identified account: it minted a
guest and persisted over the account's Keychain tokens with no `.signedOut` on
`onAuthStateChanged`. It now returns the current session whatever its kind; `forceNew:
true` is the only way to replace an identified session, and it does so silently. Read
`isAnonymous` to know which you got. The account itself was never at risk server-side.
Same fix in web 3.23.0 / Android 4.25.0.

## 5.0.0 — three methods stopped reporting failure as success

⚠⚠ **BREAKING.** Three completion handlers change from `() -> Void` to
`(Result<Void, SendoraCloudAuthError>) -> Void`. Swift rejects a zero-argument closure literal in a
one-argument closure context, so this will not compile until you update the call sites — which is the
point: the old signature had **no failure channel at all**, and every one of these could fail
silently.

- `SendoraCloudPasskeys.deletePasskey(_:completion:)`
- `SendoraCloudAuth.revokeSession(sessionId:completion:)`
- `SendoraCloudAuth.revokeAllSessions(completion:)`

**Why they could not stay.** `APIClient.request`'s completion is non-throwing and deliberately
delivers the response body on a non-2xx. So a discarded result is the ONLY place a refusal could ever
have surfaced, and these three discarded it. Concretely:

- `deletePasskey` is **step-up gated** since the backend added `requireRecentAuth`. A 403
  `RECENT_AUTH_REQUIRED` — and a 404 when the id is not the caller's — both looked exactly like a
  200. The app removed the row from the list while the credential stayed **live on the account**.
- `revokeSession` / `revokeAllSessions` back a "sign out this device" button. That is the one place a
  user acts on the claim and then stops worrying about a device they no longer control.

Migration:

```swift
// before
auth.revokeAllSessions { self.reload() }

// after
auth.revokeAllSessions { result in
    switch result {
    case .success:            self.reload()
    case .failure(let error): self.show(error.message)
    }
}
```

**New error kind: `.recentAuthRequired`** (`SendoraCloudAuthErrorKind`, raw value
`"recent_auth_required"`). The credential is valid; the *authentication behind it* is too old to
authorise a credential change. ⚠ It is **not** a request for new input — re-run whatever sign-in the
user already has and retry the same call. For Game Center that re-assertion is silent.
`details.maxAgeSeconds` is the window. Without this it classified as `.invalidCredential`, whose own
documentation says "needs NEW input" — the opposite of the truth.

`SendoraCloudAuth.parseError` is now `internal` rather than `private` so `SendoraCloudPasskeys`, a
separate file, can surface the refusal.

⚠ `disableMfa` was already correct here (fixed in 4.14.0, its comment names this exact defect class).
The equivalent web/React-Native/Android methods were not.


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
