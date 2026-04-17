# iOS SDK

Swift Package for handling Universal Links, deferred deep links, and event reporting.

## Requirements

- Swift 5.9+, iOS 15+
- No external dependencies — keep the SDK lightweight
- All network calls use URLSession (no Alamofire)
- Thread safety: all callbacks on main thread

## Public API surface (keep minimal)

```swift
Sendora.configure(apiKey: String, appId: String)
Sendora.handleDeepLink(url: URL) -> SendoraLinkData?
Sendora.checkDeferredDeepLink(completion: (SendoraLinkData?) -> Void)
Sendora.trackEvent(name: String, params: [String: Any]?)
```

## Universal Link handling

- App delegate: `application(_:continue:restorationHandler:)` or SwiftUI `onOpenURL`
- Parse the URL path, extract shortcode, call Sendora API to get link data
- Return structured link data to the app for routing

## Deferred deep link flow

1. On first app launch (check UserDefaults flag), call `GET /api/deferred?fingerprint=<hash>`
2. Fingerprint = SHA-256 of: IP (from server) + UA string + screen size + locale
3. Server matches against recent clicks within 24hr window
4. If match found, return original link data
5. App routes user to deep-linked content
6. Set UserDefaults flag so this only runs once

## Edge cases

- App launched from Spotlight search (not a deep link — ignore)
- App launched from push notification (not a deep link — ignore)
- Universal Link opened in Safari instead of app (user chose "Open in Safari" — can't prevent)
- App launched cold vs warm (both must handle deep links)
- Multiple scene support on iPad
