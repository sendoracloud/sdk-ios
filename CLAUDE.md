# sdk-ios (SwiftPM)

Published at `github.com/sendoracloud/sdk-ios`. Swift 5.9+, **iOS 15+** (`Package.swift` = `.iOS(.v15)`). Passkeys (`ASAuthorizationPlatformPublicKeyCredentialProvider`, iOS 16) are `@available(iOS 16)`-gated — `SendoraCloud.passkeys` + the `SendoraCloudPasskeys` class are iOS-16-only; everything else incl. `SendoraCloudLinks.create()` works on iOS 15. **History:** 2.3.0–4.5.0 forced iOS 16 (unguarded passkey provider); **4.6.0 (s58.235) restored iOS 15** by `@available`-gating passkeys — same treatment Live Activities (iOS 16.1) always had. The type-erased `_passkeys` backing store in `SendoraCloud.swift` exists because Swift forbids `@available` on a stored property.

> ⚠ **ADR-023 frozen contract.** UserDefaults/Keychain keys (`sendora_*`), the `X-Sendora-SDK-{Name,Version}` headers, and the `sendora_schema_version` marker are depended on by installed apps — never rename/remove a key (orphans session/queue on upgrade) or drop the header/marker. The version lives ONLY in `SDKVersion.swift`. Additive only; a format change is MAJOR + needs a migration. CI cap: `apps/backend/src/modules/developer-tools/sdk-contract-golden.test.ts`. Law: `docs/decisions/023-sdk-api-compatibility.md`.



## 5.7.1 (s58.405) — built, not published

`saveEventQueue` no longer strips `userId` / `properties.traits` (nothing ever restored them; a restored identified event went out with neither `userId` nor `anonymousId` and never got its send-time token) and removes any `identityToken` as a belt; old files decode with `userId` absent. Key error says 19+ chars (was "17+"). Guard `PersistedQueueIdentityTests.swift` (4; re-adding the strip → 5 red) + `test_malformedKeyMessageMatchesThePattern`; `swift test` 113 (3 skipped).

## 5.7.0 — server consent + feature flags, with identify()'s identityToken

**What.** `SendoraCloud.consent.record(purpose:granted:entityId:userId:email:source:identityToken:)` →
`POST /consent/record`, `requestDeletion(entityId:userId:email:reason:identityToken:)` → `POST /consent/deletion-request`
(methods ADDED to the same `SendoraCloudConsent`; `grant()` / `revoke()` / `isGranted` untouched — `attach(client:identity:)`
wires the server half at `configure()`). `SendoraCloud.flags?.evaluate(key:userId:entityId:environment:identityToken:)` /
`evaluateAll(…)` (`SendoraCloudFlags.swift`). All `async throws` → `SendoraCloudAPIError(code, status, message,
retryAfterSeconds)`: a non-2xx / `success:false` / offline / unconfigured is THROWN, never nil. Bodies omit nil fields.
**Real server shapes** (found here and by the Android port; RN's types say `{value, variant, reason}` keyed by flag — wrong):
`evaluate` → `data: {key, value, ruleMatched}`, `evaluate-all` → `data: [{key, value, ruleMatched}]`, decoded into
`SendoraFlagValue(key, value: SendoraJSONValue, variant (only if sent), reason: ruleMatched)` and a `[key: SendoraFlagValue]`
map (a map is tolerated too). `SendoraJSONValue` keeps a JSON bool a bool (CFBoolean check).
**Token rule** (`SendoraIdentityRequest.identityToken`, port of RN `withInputIdentityToken`, one function): explicit wins
as given; else identify()'s token only when the call's userId (flags: default = identified user; consent: explicit
`userId` only, as RN) equals the user the token was ISSUED FOR (`identityTokenUserId`, new, memory only) AND the
current user, and it fits the route (flags ≤ 128, consent ≤ 256). `reset()` / an identity clear drop both. ⚠ This is
stricter than RN: auth's `onIdentityChange` switches `currentUserId` without clearing the token, so RN/old iOS could pair
user A's token with user B; the event decorator now uses the same snapshot.
**Guards.** `IdentityRequestsTests.swift` (6): rule table, flags/consent bodies + decoding, error mapping. 103 / 103
offline (2 live skipped). Mutations (`scratchpad/mutate570.py`, backups `sdkios570_<M>_bak_<path>`), all red / 103:

| # | Mutation | Red |
|---|---|---|
| M64 | an explicit identityToken does not win | 2 |
| M65 | the remembered token goes with ANY userId | 4 |
| M66 | the token's own user is not checked | 1 |
| M67 | no route length limit | 1 |
| M68 | flags limit 256 instead of 128 | 2 |
| M69 | flags do not default to the identified user | 3 |
| M70 | nil fields sent as null | 4 |
| M71 | a refusal returns an empty answer | 3 |
| M72 | the server code is dropped | 2 |
| M73 | evaluateAll does not decode the server array | 1 |
| M74 | reason not read from `ruleMatched` | 2 |
| M75 | a JSON bool decoded as a number | 1 |
| M76 | `consent.record` never sends the token | 1 |

⚠ Not unit-tested (need `configure()`'s statics): `identify()` recording `identityTokenUserId`, and the event decorator's
switch to the snapshot. **Live T8** (`LiveStagingTests.scenarioConsentAndFlags`): record 201, deletion 201, evaluate 200,
evaluate-all 200, evaluate for another userId 200; the token rode the four identified bodies and NOT the other-user one.
The token is a placeholder (a valid HMAC needs the project's identity secret), so staging answers unproven
(`sourceVerified:false`, deletion `unconfirmed`) — T8 proves routing + which body carried it, not verification.
Full live run 2026-10-19: 29/29 required steps (A/B/W1/T1–T8), `judgeLiveRun` ok, `sdkReportedVersion` 5.7.0.
README: "Consent + feature flags (5.7.0)" section (snippet gate green; a broken label in it fails the gate — checked).

**5.7.0 pre-publish consumer test (iOS Simulator, real Keychain) — three fixes.**
(1) ⚠⚠ **Device-id race, pre-existing since 4/2026.** `SendoraStorage.deviceId` was `get` → `set` with no lock.
On a fresh install `reportInstallIfNeeded` (background queue) and `app.opened` (main) both missed, both minted, the
loser's add failed `-25299` and it KEPT its unsaved UUID: a request trace in a consumer app showed
`/attribution/install` with one id and `/events` with another (HEAD `9020007b`). Never visible on macOS — the live
gate runs on in-memory stores. Now: one process-wide `deviceIdLock` (all `SendoraStorage`s share one Keychain);
`SendoraSecureStore.addIfAbsent` (add-only, never delete-then-add; `.added | .duplicate | .failed(OSStatus)`, an
extension default for in-memory doubles); `.duplicate` → re-read and ADOPT the stored id; `.failed` (e.g.
`errSecInteractionNotAllowed` before first unlock) → `unsavedDeviceId` memo, reused and retried until a write lands
(a readable stored id always wins; `regenerateDeviceId` clears it). Same consumer trace after: ONE id across
install + events + batch on 4 of 4 fresh installs (`simctl keychain reset` + reinstall each time); relaunch restores
the same user. Key name unchanged (ADR-023). ⚠ A HOSTLESS `xcodebuild test` bundle has no keychain entitlement (every
add is -34018), so `test_realKeychain_…` skips there — the real-Keychain proof is the consumer-app run.
(2) Flaky `test_everyTransitionRowIsReplayed` on the simulator only (4/12 red, macOS 0/12): `TestJWT.make` serialised
the header/claims without `.sortedKeys`, so two tokens from the same claims could differ byte-wise. Test-only fix;
simulator 12/12 green after.
(3) `SendoraCloudPush.init` is `nonisolated` (it only stores constants; `configure()` builds it inside
`serialQueue.sync`, off main) and `accessTokenProvider` is `@Sendable` (internal init — no public API change). The
`SendoraCloud.swift:242` ActorIsolatedCall warning is gone; consumer-app `push.registerToken` → 201 after.
**Guards.** `DeviceIdTests.swift` (5; a Keychain-semantics double with widened read→add windows): 50 concurrent
callers on two storages → one id, persisted; injected duplicate → adopts; unwritable Keychain → one id, then that
same id is stored; regenerate; real Keychain (iOS, hosted only). `swift test` 108 (3 skipped: 2 live + real-Keychain),
simulator `xcodebuild test` 108 (3 skipped) 12/12 green, live `swift test --filter Live` 29/29 on macOS after the fix.
Mutations (`scratchpad/mutate570b.py`, backups `sdkios570_<M>_bak_<path>`, restored byte-identical), red / 107:

| # | Mutation | Red |
|---|---|---|
| M77 | the device-id lock removed | 3 |
| M78 | -25299 keeps its own unsaved id | 1 |
| M79 | the pre-5.7.0 get-then-set (no lock, overwrite) | 10 |
| M80 | no memo: an unwritable Keychain mints per call | 3 |

⚠ M77 is caught ONLY by the unwritable-Keychain test (3/3 runs): with the Keychain working, `.duplicate` → adopt
already yields one id, so the 50-caller test stays green without the lock. The lock is what keeps the memo path to one
id. ⚠ Not test-covered: the push isolation fix (a compiler diagnostic — verified by the build log, not a test).

## 5.6.0 — the response contract, client half (audit F67, backend s58.402; + adversarial review)

**What.** (1) `APIClient`: `Retry-After` (delta-seconds or HTTP-date, else `error.details.retryAfterSeconds`) on a
**503** holds the breaker that long (cap 1 h, `maxServerWait`); on a **429** the WHOLE-client hold is clamped to 60 s
(`rateLimitMaxHold` — review H2: the events quota 429 asks until the month resets and held `/token/refresh`, `/login`,
push for an hour, all month; Android clamps the same) while the full wait (≤ 1 h) still reaches the caller in
`RichResponse.retryAfterSeconds` / the stamped `details`. `cf-mitigated: challenge` holds ≥ 60 s and is delivered as
the TRANSPORT class (`statusCode == 0`, `cfMitigated`, `challengeStatus`; plain path → nil). Full-jitter backoff
`random(0, min(60, 2^n))` (seams `jitter`, `clock`, `breakerOpenUntil`). A 429 used to reset the breaker. Other 4xx:
never trip.
(2) `EventQueue` (outcome = `APIClient.DeliveryOutcome`): chunks ≤ 100 events AND ≤ 60,000 serialized bytes
(`maxChunkBytes`; `/events/batch` 413s over 64 KB); a lone event over the byte cap goes alone. 400 / 413 / 422 on a
multi-event chunk → BISECT (`bisectLimit`, halved, reset per flush); a single refused event drops. Other permanent
4xx (401 / 403 / 404 …) drop the chunk. `.retryLater(countsAttempt:after:)`: 408 / 5xx / 401 `IDENTITY_UNVERIFIED`
spend the per-event budget (`maxAttempts` 50, `_sendoraAttempts` in the persisted event, stripped before send);
offline / breaker / 429 / challenge do not. `after` = the server's wait → `holdUntil` (≤ 1 h): no flush starts
before it. Sent events are removed by IDENTITY (in-memory `Queued.id`) — positional removal deleted unsent events
when `add()` trimmed at `maxSize` mid-flight. `flushEvents` sends a single event > 30 KB to `/events/batch` (the
`/events` cap is 32 KB). `trackScreen` refuses names > 128 chars (eventType was already capped by `eventPattern`).
A 201 whose `data.rejected[i]` is an identity refusal (`code == "IDENTITY_UNVERIFIED"`, else a code-less row whose
`reason` contains "identity", case-insensitive — `APIClient.identityRejectedIndices`) → `.acceptedExcept(retry:)`:
those events stay, spend ONE attempt (answered-transient, like the identity 401) and are skipped for the rest of that
flush (`deferredThisFlush`, else they'd be resent at once until their budget ran out); every other row is removed, by
identity. "Unanswered" (never spends) = no response / transport timeout / 429 / challenge / Cloudflare 520–527 and
530 — the same set as RN / web / Android (408 is answered).
**Round 3 (second review).** The queue has its OWN full-jitter backoff (`applyBackoff`: `random(0, min(300 s,
1 s·2^(n-1)))` after EVERY retry-later, a server wait raises the floor, `noteSuccess` resets it); `performFlush` starts
nothing before `holdUntil`, including the flushes `add()` triggers past `flushAt` — events go through
`requestWithDetails`, which never trips the breaker on 500 / 502 / 504, so a 5xx outage re-sent the head chunk on every
`trackEvent`. Bisection is bounded: `bisectLimit` stays halved until a SUCCESS, then doubles back toward 100; one flush
makes at most `maxPostsPerFlush` (20) POSTs, then backs off. Three answered 5xx in a row on the SAME multi-event chunk
(by id set) halve it (`serverErrorBisectAfter`); a lone event follows the 50-attempt budget (it blocks the events behind
it until then — the normal head rule). The identity token is attached at SEND time (`EventQueue.decorator` →
`SendoraCloud.decorateForSend`: only on an event whose `userId` is the identified user), never stored, and counted in
the 60 KB cap. ⚠ Pre-existing, NOT changed: `saveEventQueue` strips `userId` and nothing restores it after a relaunch, so
a persisted event loses its user (and so gets no token).
(3) A challenge on any auth call is `.network` (retryable): never dead, never a wipe (choke point = `APIClient`).
(4) `knownDeviceToken`: `sendora_auth_known_devices` (Keychain, in `secureKeys`), `[{k: sha256(normalised email), t,
at}]`, newest 20, ≤ 2048. **Survives signOut AND the RESET row** (rule on all four SDKs); `deleteAccount` removes THAT
account's entry (`commitForgetKnownDevice`, email read before the DELETE). Writes only via +Commit (INV-1). Sent/saved
in `performSwitch` only (every `/login` goes through it); `/mfa/challenge` files under the `/login` address
(`pendingMfaEmails`, ≤ 8), else the response user's email. Never logged.
(5) Push: `Authorization: Bearer` when a session exists; the token lookup is bounded (`tokenTimeout` 5 s, `OnceGate`)
— then it registers without. (6) Links: `LinkCreateResult.revokeToken`; `sendora_link_revoke_tokens` (Keychain, 200);
`revoke(shortcode:)` sends it; `revoke(shortcode:revokeToken:completion:)` (NOT defaulted — a default makes
`revoke(shortcode:) { _ in }` ambiguous) → `LinkRevokeResult { shortcode, final }`; forgotten on 2xx, kept on 403.
(7) `support.getUnreadCount` → `APIClient.get` (was `URLSession.shared`).

**Why.** Backend s58.402 guarantees the wait; Cloudflare challenges reached the auth taxonomy as 403
`invalidCredential`; a poison event wedged the queue forever; F23 / F53 / F34 need the device to send the proof.

**Guards.** `ResponseContractTests.swift` (24) + `SurfaceHardeningTests.swift` (12); harness `StubResponse` gained
`headers` / `rawBody`. `swift build` + `swift test` **93 / 93** (Swift 6.4), iOS-Simulator `xcodebuild` green.
Mutations (`scratchpad/mutate560b.py`: cp backup → edit → `swift test` → restore → byte-compare), all red
(failures / 93, the whole set re-run after round 3; backups named `sdkios560_<M>_bak_<path>`):

| # | Mutation | Red |
|---|---|---|
| M01 | 429 records success (breaker reset) again | 7 |
| M02 | ignore the Retry-After header | 13 |
| M03 | ignore details.retryAfterSeconds | 2 |
| M04 | no 1 h cap on the server wait | 2 |
| M05 | a challenge does not hold the breaker | 1 |
| M06 | details path delivers a challenge as its 403 | 9 |
| M07 | plain path hands the challenge body to the caller | 1 |
| M08 | fixed doubling instead of full jitter | 8 |
| M09 | a plain 4xx trips the breaker | 8 |
| M10 | queue: 429 counted as delivered | 3 |
| M11 | queue: permanent 4xx retried (old behaviour) | 25 |
| M12 | queue: rejected chunk kept at the head | 20 |
| M13 | queue: no per-event attempt cap | 3 |
| M14 | queue: offline / challenge spend the budget | 3 |
| M15 | queue: budget field sent on the wire | 1 |
| M16 | queue: chunks of 1000 | 1 |
| M17 | knownDeviceToken never sent | 3 |
| M18 | knownDeviceToken cleared by signOut | 8 |
| M19 | email not normalised | 3 |
| M20 | MFA token not filed under the /login address | 1 |
| M21 | RESET row clears the known-device token | 1 |
| M22 | email stored in plaintext | 1 |
| M23 | no 20-account cap | 5 |
| M24 | push registered without the Bearer | 1 |
| M25 | links: revokeToken not persisted | 3 |
| M26 | links: stored token not sent | 1 |
| M27 | links: token not forgotten on success | 2 |
| M28 | links: `final` not read from the answer | 1 |
| M29 | links: no 200 cap | 5 |
| M30 | support badge back on URLSession.shared | 5 |
| M31 | a 429 holds the whole client for the full wait | 3 |
| M32 | no 60 KB chunk cap | 3 |
| M33 | no bisection of a refused multi-event chunk | 7 |
| M34 | bisect every 4xx (incl. 401) | 2 |
| M35 | 401 IDENTITY_UNVERIFIED treated as permanent | 1 |
| M36 | sent events removed by position | 6 |
| M37 | queue ignores the server wait | 14 |
| M38 | deleteAccount keeps that account's token | 1 |
| M39 | deleteAccount removes every account's token | 1 |
| M40 | push waits for the token forever | 2 |
| M41 | 201 identity rows treated as delivered | 6 |
| M42 | no reason fallback for a code-less row | 5 |
| M43 | reason fallback case-sensitive | 5 |
| M44 | kept identity rows spend no attempt | 1 |
| M45 | kept identity rows resent in the same flush | 5 |
| M46 | partial 201 keeps the whole chunk | 2 |
| M47 | row code ignored (reason decides) | 3 |
| M48 | queue has no backoff of its own | 14 |
| M49 | backoff not reset by a success | 1 |
| M50 | no 300 s backoff cap | 2 |
| M51 | a server wait does not raise the backoff floor | 1 |
| M52 | decorator never applied (no send-time token) | 1 |
| M53 | token on any user's event | 1 |
| M54 | decoration not counted in the byte cap | 1 |
| M55 | no 5xx bisection | 2 |
| M56 | 5xx bisection on the first failure | 1 |
| M57 | halved cap reset every flush | 2 |
| M58 | halved cap never doubles back | 1 |
| M59 | halved cap jumps straight back to 100 | 1 |
| M60 | no per-flush POST cap | 2 |
| M61 | Cloudflare 52x / 530 counted as answered | 9 |
| M62 | a nil `projectId` serialised as `null` on events (/ 96) | 2 |
| M63 | install report builds `projectId` from the optional again (/ 96) | 1 |

**LIVE run against STAGING (`Tests/SendoraCloudTests/LiveStagingTests.swift`).** Skipped unless `SENDORA_LIVE=1`
(offline `swift test` = 96, 1 skipped). Real `URLSession` (the SDK's own session config), real `APIClient` /
`EventQueue` / `SendoraCloudAuth` / `SendoraCloudLinks` / `SendoraCloudPush`; in-memory stores (no Keychain). Host
pinned to `api-dev.sendoracloud.com`; key from `SENDORA_PK`, refused unless `pk_dev_`; the recorder keeps statuses,
counts, sizes and response-header values only. Run:
`set -a; . ../../.env.e2e.local; set +a; SENDORA_LIVE=1 swift test --filter LiveStagingTests`.
10/10 PASS (2026-10-18): 250 events → 3 × 201 (100/100/50, max 36 KB); 12 × 8 KB → 2 posts (57.9 KB, 41.4 KB); one 70 KB
event → `201/10, 413/1, 201/10`; one 200-char eventType → bisected `422/21 … 422/1` then 201s, 20/20 accepted, 10
posts; signUp→signIn sends `knownDeviceToken`, SHA-256-keyed, RESET keeps it, `deleteAccount` 200 `purged` removes
it; push 201 with Bearer; link create → `revokeToken` stored → revoke sent it → 200 `final: true`; a real ingest 429
(`RateLimit-Policy: "ingest";q=200;w=60`, `Retry-After` 1–2 s) → no POST inside the wait, 0 attempts, refresh out in
1 s, delivered after 2 s.
**Live-run gate (contract 2, `scripts/e2e/live-run-contract.mjs`; suite `swift test --filter Live`).**
`LiveLifecycleTests.swift` ports `scripts/e2e/auth-lifecycle.mts` (A1–A7, B1–B5, W1-a/b/c/d/g/g2/e, B8, B9) onto the
iOS public API over a COOKIE-KEEPING `URLSession` (`.default` + its own `HTTPCookieStorage` — the phone condition;
W1-a asserts the jar holds the ACCOUNT's `sd_rt`); `LiveStagingTests` reports T1–T7. `LiveReport.swift` (shared) =
the guard (`LiveEnv.require`: `SENDORA_LIVE=1`, host `api-dev.sendoracloud.com` only, no `pk_|sk_(prod|live)_`) and the
result file (`SENDORA_LIVE_RESULT`, rewritten after every step; `sdkReportedVersion` = `SendoraCloud.sdkVersion` at
runtime; details scrubbed of JWT / key / email shapes). Fail-fast per step like the reference; created accounts are
deleted. Run 2026-10-19: **28/28 required steps pass**, `judgeLiveRun` ok. iOS readings: W1-g's 409 `CONFLICT`
surfaces as the frozen pre-4.13 case `.emailAlreadyTaken` (no `code` / `status` on that case — by design, though the
`status` doc comment "nil when the request never reached the server" over-promises); B8 uses a fresh instance (iOS
has no cross-instance rehydrate after W1-e's `discardWithheld`). T4 needs continuous raw pressure (a fresh client per
request — one client's own breaker stops at the first 429) because staging's ingest lane refills ~3.3/s.
⚠⚠ **Bug the live run found (every earlier test was green): a nil `projectId` went out as JSON `null`.** `projectId`
is optional since 3.0.0; a nil `String?` in `[String: Any]` bridges to `NSNull`, and the schema is
`z.string().uuid().optional()` — absent passes, `null` is `422 events.0.projectId: Expected string, received null`.
So an app configured with the key only NEVER delivered an event (≤ 5.5 retried them forever; 5.6.0's
permanent-refusal rule would have bisected and DELETED all of them — the first live run did exactly that, 260 POSTs
for 250 events). Fixed in `buildEvent` (now the one event builder, used by `trackEvent` and the live test),
`/attribution/install` and `/attribution/deferred`. Guards `test_anEventWithoutAProjectIdOmitsTheField_neverSendsNull`
(behavioural) + a source pin on the two body literals. ⚠ Lesson: a stub transport accepts any body; only a real
server's zod schema could see this. ⚠ The 60 s whole-client 429 clamp was NOT exercised live with a long wait
(staging's ingest Retry-After was 1–2 s); it is unit-tested only.
⚠ M01–M61 ran before the live test existed (93 tests, no skip); M62/M63 against 96 with the runner's regex fixed to
read "with 1 test skipped and N failures" (the old regex silently read a per-suite line — "0 failures / 12").
⚠ M21's first form (forget AFTER `commitClear`) was a no-op mutation and stayed green — `current` is already nil
there; re-run inserted before the clear → red. ⚠ Not test-covered: the `trackScreen` 128-char guard and the
> 30 KB single-event routing (both need `configure()`'s static state). ⚠ A one-off extra red on
`test_everyTransitionRowIsReplayed` under a loaded machine did not reproduce; M18's conformance hit is real.

## 5.5.0 — Support parity with RN 1.42.0 (s58.376)

`SendoraCloudSupport.swift` is now split: the API half compiles on EVERY platform (so `swift test` on macOS covers
it) — `createTicket` / `listMyTickets` / `getMyTicket` / `replyToMyTicket` (`async throws`, through the configured
`APIClient`; refusals → `SendoraSupportError`), `deviceContext()` (CFBundle version + build, `UIDevice` OS version,
`utsname` machine id, SDK), `sanitizeMetadata` (sorted keys → deterministic cap), `contactURL` (token + metadata in
the FRAGMENT, strict `-._~` encoding so `&`, `=`, `+` survive `URLSearchParams`). The hosted screens stay in a
`#if canImport(UIKit)` `@MainActor` extension; `presentContactWidget` gained `metadata:` / `includeDeviceContext:` /
`attachSession:` / `accent:` (defaulted, before `completion:`), `presentTicketHistory` `accent:`.
⚠ `SendoraCloud.support` was built with hardcoded production URLs — a staging config polled the PROD API. Now
`SendoraCloudSupport(apiBaseUrl: config.apiBaseUrl, client:)`, on every platform. The class is no longer
`@MainActor` (only the present methods are) — `getUnreadCount` is callable off the main actor.
Verified: `swift build`, `xcodebuild -scheme SendoraCloud -destination 'generic/platform=iOS Simulator' build`,
`swift test --filter SupportTests` 8/8 (stub transport via `APIClient(transport:)`); mutations all red (token
dropped, refusal swallowed, no-session check, key check, accent check, token in the query).

## 5.4.2 — held-slot refresh identity tripwire (parity RN 1.41.2, s58.360)

Full write-up in the RN CLAUDE.md 1.41.2 section. A held guest's refresh must come back for that guest;
a response for anyone else → `HELD_GUEST_IDENTITY_MISMATCH` before the slot write (claim: no `/merge`;
restore: nothing installed, slot kept). Also: `APIClient.makeSessionConfiguration()` (a test seam) turns cookies off — an ephemeral session still keeps an in-memory jar. `swift build` + `swift test` 49/49 on this Mac (Swift 6.4); tripwire mutation → 10 failures.

## 5.4.1 — dead session is `.sessionExpired` again; server detail in `lastSignedOutEndReason()` (set under the lock BEFORE `emitAuthState`, like `lastSignedInCause()`; the enum payload is frozen) (RopoLabs, 2026-10-10)

5.4.0 mapped the B11 `endReason` onto `signed_out.reason` (`revoked` / `deleted`). Those are two
OLD situations ("account deleted elsewhere", "sessions revoked") that 5.3.0 reported as
`.sessionExpired`, so a listener matching `.sessionExpired` stopped seeing them — RopoLabs' template
(`auth-store.ts:665`) and our own `/docs/auth-errors` example both did. ⚠ **A new union value is
additive only for a NEW situation; re-labelling an existing one is a behaviour change**
(ADR-023), even though it compiles. Fix: `reason` is `.sessionExpired` for EVERY dead verdict; the
detail is `lastSignedOutEndReason()` (set under the lock BEFORE `emitAuthState`, like `lastSignedInCause()`; the enum payload is frozen). The three values stay in the type (never emitted) so 1.41.0-era code compiles.
Shared table row `refresh_dead.current` now emits `signed_out{reason:'session_expired', endReason}`.
Guard `scenario_refresh_dead_current` (reads the accessor INSIDE a listener; limbo death; signOut resets it); mutations: map revoked/deleted back onto `reason` → 2 red; drop the endReason → 7 red; set the accessor AFTER delivery → 6 red.

## ADR-033 wave 1 (5.4.0) — "One Slot, Two Verbs": held guests, single commit, project guard

Law: `docs/decisions/033-sdk-auth-mechanism.md` §3.2–§3.5, §5 wave 1 (a)–(f); the table is
`packages/shared/src/auth-machine/transitions.ts` and this port is an INTERPRETER of it. Lockstep:
RN 1.41.0 / web 3.24.0 / Android 4.26.0. Backend contract = prod `7aa740a0` (B1–B17). Not yet
mirror-published; the mirror tag is operator-gated behind the staging live-run marker (B9).

**The machine.** Five states (`SendoraCloudAuthStatus`: `unknown | signedOut | anonymous | identified
| withheld`; NORMATIVE default-branch, `status()` is the only way to tell `withheld` from `signedOut`).
Files:
- `SendoraCloudAuth.swift` — public types + the class core: hydrate (read-first `sendora_auth_session`,
  the four frozen keys as the authority on WHETHER a session exists — after a downgrade→upgrade cycle
  they are the fresher source, so a differing legacy refresh token rebuilds the record and
  write-forwards; the record is trusted ONLY when its refresh token equals the frozen one — a record
  with no frozen counterpart is a downgrade-cycle LEFTOVER and is cleared silently, see below), the token layer (`performRefresh` → `routeRefreshResult` by the SENT token, the
  s58.281 two-deadline rule unchanged, `forceRefresh` now really bypasses the stashed-token
  short-circuit), listeners, the Bearer session verbs, parsing. `revokeSession` / `revokeAllSessions`
  / `listLinkedIdentities` / `onDeviceTakeover` / `fireLifecycleSignals` MUST stay in this file —
  `auth-error-kind-parity`, `identities.test.ts`, `credential-collision.test.ts`,
  `anon-retirement.test.ts` and `sdk-contract-golden` read it by name (the golden needs the first
  `"/auth-service/token/refresh"` literal followed by `data["tokens"]` — no optional chaining there).
- `SendoraCloudAuth+Commit.swift` — **`commit*`, the ONLY writer** (INV-1): every assignment to
  `current` / `limbo` / `withheldState` / `slots`, every Keychain write, cron arm/stop and parent hook.
  `commitInstall` = sid-CAS or sent-token CAS → `projectVerdict` → dual-write (four frozen keys +
  record, schema → `"2"`) → cron → `onIdentityChange`. `commitClear` is the one local-first exception.
  Source guard: `test_authStorageKeyNamesAppearOnlyInStorageSwift` (no `"sendora_auth_` literal outside
  `Storage.swift`).
- `SendoraCloudAuth+Engines.swift` — one engine per event family (`performSwitch` / `performLink` /
  `performMint` / `performRestoreCore` / `performClaim` / `performDiscard` / `refreshHeld`), all ON
  `opsQueue`, all awaiting an in-flight refresh at start (and at commit for a switch), all handing a
  PROPOSAL to the funnel. `installSwitchResponse` is shared with passkeys + SSO
  (`completeExternalSignIn`). No engine assigns state.
- `SendoraCloudAuth+Verbs.swift` — the public verbs: every pre-5.4.0 signature unchanged; `signUp`
  routes by status (anonymous → `/me/link/email`, never `/upgrade`; signedOut → `/signup`; identified →
  local `.alreadyIdentified`; unknown → settle); the legacy wrappers map typed outcomes onto their
  historical shapes (`signUp` keeps `.emailAlreadyTaken` for the 409; `link:true` over identified
  THROWS `.credentialInUse` / `RECENT_AUTH_REQUIRED`, `alreadyLinked` resolves quietly).
- `Internal/AuthMachineTypes.swift` (status / cause / reason enums, `SendoraCloudCredential`,
  `SendoraCloudSignInResult`, `SendoraCloudLinkResult` with `SendoraCloudCredentialInUse.switchAccount(refetch:)`
  + `keepCurrent()` as METHODS, `SendoraCloudMfaChallenge.verify(code:)`, the `AuthSessionRecord` and
  `HeldSlotRecord` disk shapes), `Internal/ProjectVerdict.swift` (verbatim port, own base64url + strict
  UTF-8 decoder, no signature check; absent claim = `unknown`, explicit null = `mismatch`).

**Keychain.** Four frozen keys unchanged (a 5.3.0 reads them after a downgrade) + `sendora_auth_session`
(dual-written on every install, carries `sid` and the B15 `heldReportPending` list — never held
material) + the K = 5 FIXED slots `sendora_auth_held_0…4` (LITERAL names in `Storage.heldSlotKeys`;
`Storage.secureKeys` is the closed allow-list the recording double enforces — a per-guest dynamic key
fails the suite). Slot record = shared `HeldGuest` v1 (`project` encoded as explicit JSON null). An
unreadable slot is KEPT and ignored, never cleared. `sendora_auth_mint_key` (UserDefaults) is the B10
per-attempt idempotent mint key, cleared on MINT_OK or a fresh-mint mismatch.

**Hooks to the parent.** `onIdentityChange(id)` (unchanged); `onIdentityCleared(ClearEffects)` replaces
`onAnonymousWipe(Bool)`: rotate the device id ONLY on `signOut` / `deleteAccount` (and the internal RESET
row); drop the queue ONLY on `deleteAccount` (the table — 5.3.0 dropped it on EVERY wipe, incl. a
sign-in that replaced a guest and a session death);
`onIdentityWithheld()` nulls `currentUserId` in memory only. ⚠ `configure()` now builds the auth
surface AFTER `serialQueue.sync` — the hydrate hooks `sync` that queue, and nesting them was a
deadlock for any launch with a cached session.

**iOS readings of the ADR (document, do not re-litigate):**
- `signedIn.cause` cannot ride the frozen `case signedIn(user:)` payload (adding an associated value
  breaks `case .signedIn(let user)` at every call site) → `lastSignedInCause()`, set before the emit.
- The subscribe-time replay is `.initial(...)` AND the pre-5.4.0 `.signedIn(user:)` replay (dropping
  the latter would break installed Home-on-signedIn listeners).
- `unknown` queues MINT / SIGN_IN / LINK / RESTORE by driving the gap-fill refresh inline
  (`settleUnknownIfNeeded`); offline the verb fails `.network` (retryable) instead of hanging a
  completion forever. ⚠ **Known divergence from RN** (which keeps such verbs queued until the status
  settles): both never mint and never wipe in `unknown` — the iOS one returns a retryable error the
  app can re-issue, RN holds the promise. Not destructive; kept deliberately. `getAccessToken()` in `unknown` drives the gap-fill too, with the stashed access
  token as the offline fallback. CLAIM / DISCARD / `discardWithheld` are NOT queued (rows
  `claim.identified_only`, `discard.held_guest`).
- Restore emission order is ONE order on every path (the regenerated fixture, lockstep): install, then
  `signedIn` (`lastSignedInCause() == .restore`), then `guestReleased(.restored)` as the slot goes —
  MINT auto-restore, `restoreHeldGuest()` and restore-over-a-guest alike (mutation M31).
- A fresh response whose claim is unreadable installs (not a mismatch); hydrate / gap-fill with an
  unreadable claim stay `unknown` (persisting a rotation only).
- `onCredentialInUse` on a PLAIN sign-in is accepted and ignored (no hint is sent, so the server cannot
  refuse a collision; the guest is held, never deleted). `.adopt` is consulted only on a `link:true`
  409, where it falls through to a sign-in bound to the same credential.
- `switchAccount(refetch:)`: the SDK has no GameKit dependency, so after 5 minutes the APP re-fetches
  and the SDK compares `teamPlayerID` (`credentialChanged` on mismatch); without `refetch` a stale
  payload is refused.
- `signOut()` in `unknown` clears the limbo keys + revokes; in `signedOut` it is a quiet no-op (both
  `UNSPECIFIED_BY_ADR`).
- **`SendoraCloud.reset()` keeps its 5.3.0 semantics (lockstep ruling 2): iOS is the "reset() never
  signed out" case.** It has always reset ONLY the analytics identity (user id, device id, session id)
  — no auth session, no Keychain tokens, no event queue (RN/web `reset()` always signed out). So the
  ADR RESET row has no public entry on iOS: `resetFromParent(includeHeldGuests:)` implements it for
  the conformance replay only, and the public `reset(includeHeldGuests:)` overload accepts the flag for
  parity and ignores it (held guests are released only by the explicit verbs).
- **Subscribe replay (lockstep ruling 1):** `onAuthStateChanged` replays `.initial(status:user:withheld:)`
  and THEN — when a session exists — the 5.3.0 `.signedIn(user:)`, per subscriber; no session →
  `.initial` only. Pinned by `test_subscribeReplaysInitialThenTheLegacySignedInWhenASessionExists` +
  `…OnlyInitialWithoutASession` (mutation M27).
- **Downgrade cycle (lockstep, RN-found):** a 5.3.0 `signOut()` / `deleteAccount()` clears only the
  four frozen keys, so the 5.4 record survives 5.4→5.3→sign-out→5.4. Hydrate trusts the record ONLY
  when `record.refreshToken == frozen refresh`: no frozen refresh → the record is cleared with the
  stale blob (`signedOut`, boot `initial` only, no network); a different frozen refresh in LIMBO_A →
  the record is dropped (`commitHydrateLimbo(clearLeftoverRecord:)`); `writeRotationOnly` rotates the
  record only when it belongs to the same session, else drops it (a withhold-on-refresh must not
  graft C's tokens onto A's user). Frozen keys are written BEFORE the record (`writeCurrentRecord`).
  Mutations M28–M30, M32.
- **Passkey + OIDC take the identity CAS when the sheet OPENS** (`externalAttemptStart()` →
  `completeExternalSignIn(startedFrom:)`): a result landing after a `signOut()` / switch made during the
  native sheet is dropped + revoked (row 19). Before this the CAS was snapshotted when the response
  arrived, which compared the state with itself (mutation M24). A standalone callback with no known
  start snapshots at arrival.
- **5.3.0 declarations kept verbatim:** `deleteAccount(completion:)` and `SendoraCloud.reset()` are
  separate overloads, not defaulted parameters (an unapplied reference to either still compiles —
  `test_preWaveDeclarationsAreStillThere`).
- B15: a pending `/guest/held` report is retried on the next hydrate, never in `withheld` (no network
  of any kind there).

**Guards.** `Tests/SendoraCloudTests/AuthMachineConformanceTests.swift` (+ `AuthMachineRowScenarios*.swift`,
`AuthTestHarness.swift`): loads `packages/shared/src/auth-machine/auth-transitions.conformance.json`
by path (never copied), replays ALL 36 transition rows (a fixture row without a scenario fails) and
all 19 verdict cases (the 5 transition-context cases drive the install path), and pins the constants
(slot keys, dead codes, release reasons, withheld reject list, states). Doubles: recording Keychain /
UserDefaults + a scripted transport with per-path one-shot gates (the "refresh rotates during the
native sheet" interleaving) + a frozen-clock seam (`MachineConfig.clock`).
`AuthMachineBehaviourTests.swift`: §5 integrator test 10 (two guests → count 1 then 2, newest first),
two holds at a frozen clock never tie, the B15 report retry (and none in `withheld`), the native-sheet
CAS, the subscribe replay (ruling 1), the downgrade-cycle leftover record (three shapes), frozen keys
written before the record, the 5.3.0 declarations. `SendoraCloudAuthErrorTests.swift`: the taxonomy +
the FORMER source-text pins rewritten behaviourally. `swift test` **46 tests, 0 failures**
(13 behaviour + 8 conformance + 16 error-taxonomy + 9 validator). Scenario files never force-unwrap
an event / write index (`h.event(at:)`, guard-let) — a crash would abort every scenario after it and
hide the real failure count (it did, under M05/M08, before this was fixed).

**Mutation record (each: `cp` backup → apply → `swift test` → `cp` restore → anchor grep-proven both
ways; scripts `scratchpad/mutate.py` (M01–M21) + `scratchpad/mutate-w1b.py` (M22–M33); final run
against the 46-test suite, no crashes):**

| # | Mutation | Red (assertions) |
|---|---|---|
| M01 | delete the sid-CAS (engine guard AND `commitInstall`) | 9 |
| M02 | re-add `prevAnonRefreshToken` to the sign-in body | 4 |
| M03 | mint in `unknown` (drop the settle) | 4 |
| M04 | second `signedIn` on upgrade via `link()`/`link*()` | 1 |
| M05 | drop the dual-write (four frozen keys) | 20 |
| M06 | delete the await-refresh-before-hold (start + commit) | 3 |
| M07 | route `link:true` + identified to `/login` | 1 |
| M08 | build a held key name dynamically (per guest) | 26 |
| M09 | RESET row default wipes held | 3 |
| M10 | no-arg destructive verb with 2 held | 4 |
| M11 | mint at T == K | 3 |
| M12 | dead newest slot aborts `ensureSession()` | 1 |
| M13 | claim without persisting the rotation into its slot | 4 |
| M14 | release held on `reuse` / absent `endReason` | 12 |
| M15 | auto-restore after `account_deleted` | 4 |
| M16 | delete the withheld gate on the access-token getter (+ snapshot) | 2 |
| M17 | `signUp` reads the refresh key in `withheld` | 1 |
| M18 | evaluate the verdict only at hydrate | 15 |
| M19 | treat an absent claim as `match` | 10 |
| M20 | write `auth_session` in a withheld hydrate | 2 |
| M21 | resolve `withheld` via RESET / wipe a slot on `discardWithheld` | 5 |
| M22 | drop the `switchAccount` credential comparison | 1 |
| M23a | revoke the session on `alreadyLinked` (client side) | 1 |
| M23b | emit `userUpdated` on `alreadyLinked` | 1 |
| M24 | snapshot the passkey/OIDC CAS at the response, not the sheet opening | 5 |
| M25 | retry the hold report in a withheld hydrate | 1 |
| M26 | never retry a pending hold report on hydrate | 3 |
| M27 | drop the legacy `.signedIn` subscribe replay | 9 |
| M28 | reinstall from a record whose frozen keys are gone (downgrade cycle) | 12 |
| M29 | keep a mismatched record in LIMBO_A | 1 |
| M30 | rotate any record on a withhold rotation | 2 |
| M31 | auto-restore emits `guestReleased(.restored)` before `signedIn` | 5 |
| M32 | write the record before the frozen keys | 4 |
| M33 | let two holds tie on `heldAt` | 4 |

(A first M01 that deleted only the engine guard stayed GREEN — `commitInstall` re-checks the CAS, so the
mutation had to remove both. "1" rows are scenarios that `guard … else { return XCTFail }` at the first
divergence. ⚠ An earlier version of this table recorded several rows as "then the suite crashed": the
runner's regex only matched the plural "failures", so a 1-failure run was misread as a crash; the
two real crashes (M05/M08, a force-unwrapped write index) are fixed in the scenarios.)

**Pins converted (source-text → behavioural):** `test_signInPathsDelegateTheWipeToTheSuccessBranch`,
`test_replacementWipeIsAlwaysImmediatelyFollowedByPersist` → `test_aFailedSignInLeavesTheCallerExactlyAsFound`
(byte-identical Keychain across six paths × five failures) + `test_noSignInBodyCarriesTheGuestHint`;
`test_anonymousSignInReusesTheExistingSessionBeforeMinting`, `test_refreshRecoversAnIdentityItDoesNotHave`,
`test_rateLimitIsNotADeadRefreshToken` → driven on the real machine.

**Upgrade / downgrade.** 5.3.0 → 5.4.0: first launch reads the four keys, writes `sendora_auth_session`
+ schema `"2"`, no network, same status. 5.4.0 → 5.3.0: the four keys are current, the session
survives; the slots are ignored (orphans server-side, readable again on re-upgrade); a 5.3.0 `signOut`
clears the four keys only, which the 5.4.0 hydrate treats as signed-out (keys are the authority).

**Known gaps / for the caller:** `linkEmailSchema` is `email` + `password` only, so `signUp(name:)`
from a guest drops `name` (backend follow-up). Play Games is Android-only — `SendoraCloudCredential` has no
`playGames` case.


## 5.3.0 — signInAnonymously() over an identified session is a no-op (RopoLabs A2, parity RN 1.40.0)

Full write-up in the RN CLAUDE.md 1.40.0 section. The reuse guard
(`SendoraCloudAuth.swift` `signInAnonymously`) required `user.isAnonymous`, so over a LIVE
ACCOUNT session it fell through, minted a guest and persisted over the account's Keychain
tokens with no state event. The `user.isAnonymous` clause is dropped: an identified session
with a refresh token in the Keychain is returned as-is; `forceNew: true` is the single
explicit replace. All four SDKs carried the identical guard and ship the fix in lockstep
(RN 1.40.0 / web 3.23.0 / Android 4.25.0). Version in `SDKVersion.swift` only (5.3.0).
⚠ No Swift compile gate exists in this repo — `swift build` + the on-device smoke are the
operator's pre-mirror step, as with every native release. ⚠ Not yet mirror-published.

## 5.2.0 — no device fingerprinting (App Store compliance, SudokuHurdle)

**Removed the capability, not just gated it.** `FingerprintGenerator` (which hashed
`model|osVersion|screen|locale|timezone`) is **deleted**, and the SDK no longer
computes or transmits a device fingerprint anywhere. This closes the silent,
default-on exposure the research flagged: `configure()` (with the default
`autoStartAttribution = true`) used to compute a fingerprint at init and POST it to
`/attribution/install` **on first launch, before any ATT prompt**, bypassing the
consent queue. Apple prohibits deriving a device identifier from device signals for
attribution (App Store 5.1.2 / DPLA §3.3.9) regardless of ATT, and App Review actively
rejects on it.

- The auto install report (`reportInstallIfNeeded`) now carries deterministic signals
  only — `deviceId`, `appVersion`, `os`, `osVersion`. **`autoStartAttribution` stays
  `true`** deliberately (it also gates `trackSessionStart()`, which fires inside the
  same guard while `session.ended` fires outside it — flipping the default would
  silently kill session-start analytics).
- `/attribution/deferred` drops the fingerprint too (it matched on fingerprint
  equality only — no IP fallback — so it now transmits nothing device-derived and
  simply won't match on that path; use `SendoraCloud.links?.matchDeferred` for
  deferred routing, and note iOS has no deterministic deferred signal — see RN 1.37.0).
- ADR-023 safe: no frozen key/header/route touched; a body field was removed, which the
  backend already treats as optional. `swift build` clean.

⚠ Parity: RN shipped the `matchDeferred` half in 1.37.0; **Android 4.23.0** ships this
native removal in lockstep. Publish + on-device smoke before release.

## 5.1.0 — deviceId survives identify/upgrade (SudokuHurdle r6)

Parity with RN 1.38.0 (full write-up there). The device (anonymous analytics) id
rotated on EVERY auth transition — including the anon→identified upgrade where the
server preserves the `sub`. It now survives identify/upgrade and rotates only at a
person-boundary. `onAnonymousWipe` gained a `Bool` (rotateDeviceId);
`wipeLocalIdentity` passes `true` only for `.signedOut(.user)` / `.signedOut(.accountDeleted)`,
so `.replaced` (sign-in/upgrade) and `.sessionExpired` clear the userId but KEEP the
`deviceId` (same person → pre-auth analytics link to them), while an explicit
`signOut()` and the public `reset()` still rotate it (shared-device isolation:
`coalesce(user_id, anonymous_id)` makes the anon id the identity only while signed
out). ADR-023 safe: the `sendora_*` Keychain key is unchanged, only the value's
regeneration frequency drops. Alias/merge stays server-authoritative
(`prevAnonRefreshToken` → `user_upgraded`/`user_merged`). `swift build` clean.
⚠ **Separate pre-existing note (NOT changed here):** the `deviceId` is Keychain-stored
with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so it survives REINSTALL —
more persistent than the industry norm (FID/Amplitude die on uninstall) and the one
thing Apple pushes back on. That's orthogonal to this change; revisit separately.

## 4.18.0 — getLastAnonRetirement(): did my guest account survive? (s58.278)

Parity: RN 1.33.0 / web 3.17.0 / Android 4.18.0. Additive; no behaviour change to any existing call.

`retiredAnonUserId` is present-or-absent, and the absence covered two
situations that need opposite handling: the guest account was retired but not
named, versus nothing was retired and the guest is still alive and claimable.
A customer hit exactly that — saw no `retiredAnonUserId` after an adopt and
had to ask us which it was, because it is not answerable from outside (the
device-takeover's no-ops are silent by design).

Sign-in responses now carry `anonRetirement`, and `getLastAnonRetirement()`
returns the last value (cleared on sign-out):

- `retired` — the guest row was deleted; its id arrives via `onDeviceTakeover`.
- `preserved` — a guest token WAS sent and the guest was NOT retired. That
  account still exists, so "recover your other account" is a real offer.
- `none` — no guest token was sent; nothing to reconcile.

⚠ The value is recorded ONLY when the server states it. An older backend omits
the field entirely, and treating that as `none` would assert a fact we were
never told — absent and `none` are different answers.

⚠ The third case is named `nothingToRetire` (wire value `"none"`), NOT `none`.
A Swift enum case called `none` collides with `Optional.none`, so
`outcome == .none` would be ambiguous between "no guest was presented" and "no
value at all" — reintroducing the exact conflation this field removes.

## 4.17.0 — the collision default is now safe by construction (s58.274)

Parity: RN 1.32.0 / web 3.16.0 / Android 4.17.0. **Behaviour change to the DEFAULT** — see below for who it affects (in practice: nobody with real users).

`onCredentialInUse` shipped in the previous release with a default of `adopt`, kept
for compatibility. That was the wrong call: the destructive path was what you got by
not knowing the option existed, and it succeeded silently, so there was no error to
prompt a second look. The next integrator would have had to lose an account to learn.

**The hazard was never "a collision happened" — it is "a collision happened AND
adopting would DELETE a live guest account on this device".** Those deserve different
answers, and now get them:

- **Fresh install / no guest session** → nothing to lose, so it adopts. This is the
  reinstall-recovery path, and it is never refused.
- **Live guest session** → adopting would retire it (row deleted). Refused with
  `CREDENTIAL_IN_USE` so the app can ask the player.

So the safe behaviour is now the behaviour, and `onCredentialInUse` becomes a pure
override: `"adopt"` to switch anyway (the old semantics), `"reject"` to fail on any
collision at all.

⚠ **If you relied on silent adopt** — i.e. you consume the device-takeover signal to
migrate progress on a returning player — pass `onCredentialInUse: "adopt"` explicitly.
Everything else is unchanged: the adopt path still retires the row and still fires the
takeover webhook.


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
- Event queue persisted as sent (s58.405: `userId` kept; the identity token never written).
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
