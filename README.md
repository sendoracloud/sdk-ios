# SendoraCloud iOS SDK

Official SendoraCloud iOS SDK — deep linking (Branch / Firebase Dynamic Links parity), attribution, event tracking, auth, push, Live Activities, geofences. Swift 5.9+, iOS 15+.

Full docs: [sendoracloud.com/sdks](https://sendoracloud.com/sdks)

## Install (via Swift Package Manager)

In Xcode → File → Add Package Dependencies → paste:

```
https://github.com/sendoracloud/sdk-ios
```

Pin to `3.9.0` or newer for the new `SendoraCloud.links` surface (typed errors, prewarm, revoke, getStats, computeDeviceFingerprint).

Or in `Package.swift`:

```swift
.package(url: "https://github.com/sendoracloud/sdk-ios", from: "3.9.0"),
```

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

`SendoraCloud.auth` exposes the full end-user auth surface: anonymous sign-in, email + password, magic link, email OTP, TOTP MFA, recovery codes, OIDC / SAML SSO, sign in with Apple, Google.

```swift
SendoraCloud.auth?.signUp(email: "u@e.co", password: "...") { result in
    // result.success -> AuthUser + AuthTokens
}
SendoraCloud.auth?.signInAnonymously { _ in }
SendoraCloud.auth?.sendMagicLink(email: "u@e.co") { _ in }
SendoraCloud.auth?.refreshAccessToken { _ in }
```

Passkeys via `SendoraCloud.passkeys?` (iOS 16+ via ASAuthorization).
OIDC SSO via `SendoraCloud.sso?.signInWithOidc(returnTo:from:completion:)` (ASWebAuthenticationSession).

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
