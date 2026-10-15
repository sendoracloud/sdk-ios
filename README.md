# SendoraCloud iOS SDK

Official SendoraCloud iOS SDK — deep linking (Branch / Firebase Dynamic Links parity), attribution, event tracking, auth, push, Live Activities, geofences. Swift 5.9+, iOS 15+ (native passkeys require iOS 16 and are `@available`-gated). **4.6.0 restored the iOS 15 floor** — the full Links surface, including runtime `create()`, works on iOS 15; only passkeys need iOS 16. (2.3.0–4.5.0 forced iOS 16 because the passkey provider wasn't version-guarded.)

Full docs: [sendoracloud.com/sdks](https://sendoracloud.com/sdks)

## Install (via Swift Package Manager)

In Xcode → File → Add Package Dependencies → paste:

```
https://github.com/sendoracloud/sdk-ios
```

Choose **Up to Next Major Version**, with the current release as the minimum.

Or in `Package.swift`:

```swift
.package(url: "https://github.com/sendoracloud/sdk-ios", from: "5.5.0"),
```

### Upgrading from 4.x

SwiftPM's `from:` never crosses a major version, so an app that pinned `from: "4.x.y"` stays on 4.x
until you raise the minimum to 5. 5.0.0 changed three completion handlers to
`(Result<Void, SendoraCloudAuthError>) -> Void`, so their failures are no longer silent:
`SendoraCloudPasskeys.deletePasskey(_:completion:)`, `SendoraCloudAuth.revokeSession(sessionId:completion:)`
and `SendoraCloudAuth.revokeAllSessions(completion:)`. Update those call sites when you raise the
minimum; `CHANGELOG.md` 5.0.0 shows the before and after.

### Upgrading from 3.x

4.0.0 aligns with the backend's unprefixed alias routes (s58.104) — the
backend now resolves the org from the API key server-side. The iOS SDK
already used unprefixed URLs internally, so no host-app changes are
required other than bumping the SwiftPM pin. All public method signatures
(`configure`, `trackEvent`, `identify`, `links.*`, `push.*`, `auth.*`, …)
are unchanged.

## Quick start

```swift
import SendoraCloud

// AppDelegate / @main entry
SendoraCloud.configure(apiKey: "pk_prod_...", projectId: "<uuid>")

// Grant consent (GDPR / ePrivacy). Events buffer until this is called.
SendoraCloud.consent.grant()

// Identify with HMAC identity token signed by your backend
SendoraCloud.identify(
    userId: "user_123",
    traits: ["email": "user@example.com"],
    options: SendoraCloudIdentifyOptions(identityToken: "<HMAC>")
)

// Track a custom event
SendoraCloud.trackEvent("purchase", properties: ["amount": 29.99])

// Register the device push token
func application(_ app: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken token: Data) {
    let hex = token.map { String(format: "%02x", $0) }.joined()
    SendoraCloud.push?.registerToken(hex, platform: .ios) { _ in }
}
```

## Deep links (SDK-side mint + warm + deferred + revoke + stats)

```swift
// 0. Mint typed linkData via Codable for full type-safety on both ends.
struct ArticleLink: Codable {
    let type: String
    let articleId: String
    let category: String
    let sharedBy: String
}

let article = ArticleLink(type: "article", articleId: "art_42", category: "tech", sharedBy: "u_42")
let input = try SendoraCloudLinks.LinkCreateInput(
    title: "Share article",
    typedLinkData: article,
    iosDeepLinkPath: "/articles/\(article.articleId)",
    androidDeepLinkPath: "/articles/\(article.articleId)"
    // fallbackUrl: omit — backend defaults from your project's apps registry
)

// 1. Prewarm on cell display so share tap is instant.
SendoraCloud.links?.prewarm(input, key: "article:\(article.articleId)")

// 2. Mint on tap — returns from cache when key matches.
SendoraCloud.links?.create(input, prewarmKey: "article:\(article.articleId)") { result in
    switch result {
    case .success(let link):
        // present UIActivityViewController(activityItems: [URL(string: link.url)!])
        break
    case .failure(let err):
        if let le = err as? SendoraCloudLinks.LinkError {
            switch le.code {
            case .bundleMismatch:   print("Register bundle in Dashboard → Apps")
            case .planLimit:        print("Upgrade plan")
            case .rateLimited:      print("Back off + retry")
            case .fallbackRequired: print("Configure App Store URL in apps registry")
            default:                print(le.message)
            }
        }
    }
}

// 3. Subscribe to opens (warm + deferred), typed via Codable.
SendoraCloud.links?.onLinkOpened { event in
    do {
        let payload: ArticleLink = try event.decodedLinkData()
        AppRouter.shared.navigate(toArticle: payload.articleId)
    } catch { /* legacy linkData shape */ }
}

// 4. Warm path — wire from SceneDelegate:
func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
    guard let url = userActivity.webpageURL else { return }
    SendoraCloud.links?.handleUniversalLink(url: url)
}

// 5. Cold path — call once on first foregrounded launch. SDK auto-computes
//    the canonical fingerprint when neither input is supplied. Backend
//    pins it to the click's IP for a 2h window.
SendoraCloud.links?.matchDeferred { _ in /* event also fires through onLinkOpened above */ }

// 6. Revoke (private-content unsend). Idempotent.
SendoraCloud.links?.revoke(shortcode: "ab3xk9p") { _ in }

// 7. Stats — no dashboard scraping.
SendoraCloud.links?.getStats(shortcode: "ab3xk9p") { result in
    if case .success(let stats) = result {
        print(stats.totalClicks, stats.uniqueClicks, stats.deferredMatches)
    }
}
```

### Typed errors

`SendoraCloudLinks.LinkError` carries a typed `code: LinkErrorCode` so callers `switch` on it directly:

```
.bundleMismatch | .dataTooLarge | .expired | .network | .rateLimited
| .notFound | .unauthorized | .invalidInput | .planLimit
| .fallbackRequired | .server | .unknown
```

### Custom share host

Set `linkHosts` in `SendoraCloudConfig` (default `["go.sendoracloud.com", "sendoracloud.com"]`). The Links module filters incoming Universal Link URLs against this list — non-matching hosts are returned to your host app's existing router untouched.

```swift
let cfg = SendoraCloudConfig(apiKey: key, linkHosts: ["pulse.link"])
SendoraCloud.configure(apiKey: key, projectId: id, options: cfg)
```

### Canonical fingerprint

```swift
let hash = SendoraCloudLinks.computeDeviceFingerprint()
// `${platform}|${screenW}x${screenH}|${timezone}|${locale}` → SHA-256 hex.
// Identical recipe across iOS / Android / RN SDKs.
```

## Auth Service

`SendoraCloud.auth` exposes the full end-user auth surface: anonymous sign-in, email + password, magic link, email OTP, TOTP MFA, recovery codes, OIDC / SAML SSO, sign in with Apple, Google, Game Center.

```swift
SendoraCloud.auth?.signUp(email: "u@e.co", password: "...") { result in
    // result.success -> AuthUser (from a guest: the same account, promoted in place)
}
SendoraCloud.auth?.signInAnonymously { _ in }      // = ensureSession(): the session this device has, else a mint
SendoraCloud.auth?.sendMagicLink(email: "u@e.co") { _ in }
SendoraCloud.auth?.refreshAccessToken { _ in }
```

### Boot state (5.4.0)

```swift
switch SendoraCloud.auth?.status() {
case .anonymous, .identified: showHome()
case .signedOut:              showSignIn()
case .withheld:               // only with `expectedProjectId` — see below
    let info = SendoraCloud.auth?.withheld()
    SendoraCloud.auth?.discardWithheld { _ in }
default:                      // `.unknown` (a session is being settled) AND any future value
    break
}
```

`status()` is sync and settles at `configure()` (the Keychain hydrate never waits on the network).
⚠ **Always default-branch on `SendoraCloudAuthStatus`** — `withheld` was added while the type was
new; any later value ships only in a MAJOR. ⚠ **`status()` is the only way to tell `withheld` from
`signedOut`**: `currentUser` is `nil` and the access-token getters return `nil` in both.

### Held guests (5.4.0 — ADR-033 "One Slot, Two Verbs")

A credentialed sign-in from a guest device **never deletes the guest**: the guest is HELD in one of
five fixed Keychain slots and the account survives on the server. The app decides what to do with it:

```swift
SendoraCloud.auth?.onAuthStateChanged { change in
    switch change {
    case .guestHeld(let userId, let count):
        // Ask: "We found a guest account on this device — keep its progress?"
        //   keep  → SendoraCloud.auth?.restoreHeldGuest(id: userId) { _ in }   // sign back in AS the guest
        //   merge → SendoraCloud.auth?.claimHeldGuest(id: userId) { _ in }     // fold INTO the current account (destructive;
        //                                                                      // only if your backend acts on auth.user_merged)
        //   drop  → SendoraCloud.auth?.discardHeldGuest(id: userId) { _ in }   // real server delete, on the player's behalf
    case .guestReleased(let userId, let reason, _):
        // reason: .claimed | .restored | .discarded | .dead (unavailable — never say "lost") | .reset
    case .signedIn(let user):
        if SendoraCloud.auth?.lastSignedInCause() == .restore { registerPushAgain() }
    default: break
    }
}
let held = SendoraCloud.auth?.heldGuests()   // newest first; never exposes tokens
```

- `signInAnonymously()` / `ensureSession()` in the signed-out state **restores the newest eligible
  held guest** before minting (`autoRestoreHeldGuest`, default `true`), visibly:
  `.signedIn` (`lastSignedInCause() == .restore`) then `.guestReleased(.restored)` — the same order as
  `restoreHeldGuest(id:)`.
- `id` may be omitted on the three verbs only when exactly one guest is held (`.ambiguousHeldGuest`).
- At most 5 guests are held; a `forceNew` mint at the cap fails with `.heldGuestLimit` — nothing is
  ever displaced. There is no expiry: neither the SDK nor the server releases a held guest by age.
- `signOut()` KEEPS held guests. `deleteAccount()` keeps them too and suppresses auto-restore;
  `deleteAccount(alsoDiscardHeldGuests: true)` deletes them server-side as well.
- `SendoraCloud.reset()` is unchanged: it resets the ANALYTICS identity (user id, device id, session
  id) and has never touched the auth session on iOS — use `SendoraCloud.auth?.signOut` to sign out.
  `reset(includeHeldGuests:)` exists for parity with RN/web and has no effect on iOS (held guests are
  released only by the explicit verbs).

### Linking (never switches)

`link: true` on `loginSocial` / `signInWithApple` / `signInWithGoogle` / `signInWithGameCenter`, and
the typed `link(_:)`, attach a credential to the CURRENT account — from a guest (promotion, same
`sub`) **and from an identified account**: an identity already on this account is a quiet success;
one owned elsewhere is `.credentialInUse` (typed `link(_:)` returns a context whose `switchAccount()`
is the only path to a sign-in and is bound to that same credential); a stale session is
`RECENT_AUTH_REQUIRED` (`kind == .recentAuthRequired`). Plain `signIn*` is the only switch.

```swift
SendoraCloud.auth?.link(.gameCenter(publicKeyURL: url, signature: sig, salt: salt, timestamp: ts,
                                     teamPlayerID: id, bundleID: bundle)) { result in
    switch result {
    case .success(.done(let user, let upgraded, let alreadyLinked)): break
    case .success(.credentialInUse(let ctx)):   // ask, then ctx.switchAccount { _ in } or ctx.keepCurrent()
        break
    case .success(.recentAuthRequired):         // re-authenticate with a credential already on the account
        break
    case .failure(let error): print(error.kind, error.code ?? "")
    }
}
```

### Project guard (opt-in)

```swift
let cfg = SendoraCloudConfig(apiKey: key, projectId: project, expectedProjectId: project)
```

With `expectedProjectId` set (a UUID, equal to `projectId`), every installed session is judged against
its JWT `project` claim. A stored session that disagrees — a wrong-key build, a reinstall under another
project's key — is reported as `status() == .withheld`: nothing is wiped, nothing is written, every
identity verb refuses `AuthError(kind: .config, code: "SESSION_WITHHELD")` with no network, and the two
exits are `discardWithheld()` (keeps held guests, the queue and the analytics id) or relaunching with the
matching key. A fresh mint under the wrong key rejects `PROJECT_MISMATCH` and revokes the minted token.

Passkeys via `SendoraCloud.passkeys?` (iOS 16+ via ASAuthorization).
OIDC SSO via `SendoraCloud.sso?.signInWithOidc(returnTo:from:completion:)` (ASWebAuthenticationSession).

## Support (5.5.0)

Create a **Contact Widget** for this app's project in the dashboard and use its id. Signed in (guest or account), the
SDK sends the player's session, so tickets carry their verified user id.

```swift
// Hosted form + My messages (iOS)
SendoraCloud.support?.presentContactWidget(
    widgetId: "your-widget-id",
    from: viewController,
    metadata: ["plan": "pro", "level": 40],   // + app version, build, OS, model, SDK — added for you
    accent: "#22c55e"
) { result in }
SendoraCloud.support?.presentTicketHistory(widgetId: "your-widget-id", from: viewController, accent: "#22c55e")

// Your own screens
let tickets = try await SendoraCloud.support?.listMyTickets(widgetId: "your-widget-id")
let ticket = try await SendoraCloud.support?.getMyTicket(widgetId: "your-widget-id", ticketId: "ticket-id")
let reply = try await SendoraCloud.support?.replyToMyTicket(widgetId: "your-widget-id", ticketId: "ticket-id", body: "Still happening")
let created = try await SendoraCloud.support?.createTicket(subject: "Purchase not restored", body: "Bought the hint pack")
```

Refusals throw `SendoraSupportError` (`code` — e.g. `PROJECT_MISMATCH`, `NOT_SIGNED_IN` — and `status`).

## Push

`SendoraCloud.push?.registerToken(...)`, `SendoraCloud.push?.trackOpen(...)`.

Live Activities (iOS 16.1+): `SendoraCloud.liveActivities?.track(activity:...)` watches `pushTokenUpdates` and re-registers per-activity token with the backend.

Critical Alerts: `SendoraCloudCriticalAlerts.requestPermission { granted in ... }` (Apple entitlement required).

## Security model

- **Secret-key refusal.** `configure()` aborts if given a key starting with `sk_`.
- **HTTPS only.** `APIClient` refuses non-https URLs (except localhost in dev).
- **SPKI cert pinning.** Configure `pinnedSPKIHashes` to harden against user-installed enterprise / MitM CAs.
- **Identity tokens.** `identify()` accepts an HMAC `identityToken` (signed by your backend) to block client-side spoofing.
- **Host allowlist.** `handleDeepLink` returns `nil` for URLs whose host isn't in `config.linkHosts` (default `sendoracloud.com`).
- **Bundle-id gate.** `links.create()` forwards `Bundle.main.bundleIdentifier` automatically; backend rejects a leaked public key + wrong bundle as `LinkError(code: .bundleMismatch, statusCode: 422)`.
- **Keychain storage.** `userId` + `deviceId` in `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Event queue persisted with PII stripped.
- **Input validation.** Event names + property depth + key blocklist enforced via `SendoraCloudValidator`.
- **Consent gating.** Events buffer in memory until `consent.grant()`.
- **Exponential backoff + circuit breaker.** `APIClient` backs off to 60s after repeated failures.

## License

Apache-2.0 © SendoraCloud
