# SendoraCloud iOS SDK

Official SendoraCloud iOS SDK — deep linking, attribution, event tracking, auth, push, Live Activities, geofences. Swift 5.9+, iOS 15+.

Full docs: [sendoracloud.com/sdks](https://sendoracloud.com/sdks)

## Install (via Swift Package Manager)

In Xcode → File → Add Package Dependencies → paste:

```
https://github.com/sendoracloud/sdk-ios
```

Pin to `3.8.0` or newer for the `SendoraCloud.links` surface.

Or in `Package.swift`:

```swift
.package(url: "https://github.com/sendoracloud/sdk-ios", from: "3.8.0"),
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

// Register the device push token (UIApplicationDelegate)
func application(_ app: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken token: Data) {
    let hex = token.map { String(format: "%02x", $0) }.joined()
    SendoraCloud.push?.registerToken(hex, platform: .ios) { _ in }
}
```

## Deep links (SDK-side mint + warm + deferred)

Three moves under `SendoraCloud.links` (3.8.0+):

```swift
// 1. Mint a share link from inside the app (Branch / Firebase parity).
//    Bundle id auto-supplied from Bundle.main.bundleIdentifier;
//    backend validates against the iOS app registered in Dashboard → Apps.
let input = SendoraCloudLinks.LinkCreateInput(
    title: article.title,
    fallbackUrl: "https://yourapp.com/articles/\(article.id)",
    iosDeepLinkPath: "/articles/\(article.id)",
    androidDeepLinkPath: "/articles/\(article.id)",
    linkData: ["articleId": article.id]
)
SendoraCloud.links?.create(input) { result in
    if case .success(let link) = result {
        // Present share sheet with link.url
    }
}

// 2. Register the open-callback. Fires for warm (Universal Link)
//    AND deferred (cold-launch after install) opens.
SendoraCloud.links?.onLinkOpened { event in
    if let articleId = event.linkData["articleId"] as? String {
        AppRouter.shared.navigate(toArticle: articleId)
    }
}

// 3. Warm path — wire from SceneDelegate:
func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
    guard let url = userActivity.webpageURL else { return }
    SendoraCloud.links?.handleUniversalLink(url: url)
}

// 4. Cold path — call once on first foregrounded launch. Pass a
//    fingerprint hash (hex SHA-256 of ip+ua+screen+tz); backend
//    pins it to the click's IP for a 2h window.
let input = SendoraCloudLinks.DeferredMatchInput(
    fingerprintHash: yourFingerprintProvider.compute()
)
SendoraCloud.links?.matchDeferred(input) { _ in
    // event also fires through onLinkOpened above
}
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
- **Keychain storage.** `userId` + `deviceId` in `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Event queue persisted with PII stripped.
- **Input validation.** Event names + property depth + key blocklist enforced via `SendoraCloudValidator`.
- **Consent gating.** Events buffer in memory until `consent.grant()`.
- **Exponential backoff + circuit breaker.** `APIClient` backs off to 60s after repeated failures.

## License

Apache-2.0 © SendoraCloud
