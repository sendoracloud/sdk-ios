# sdk-ios (SwiftPM)

Published at `github.com/sendoracloud/sdk-ios`. Swift 5.9+, iOS 15+.

## Public API

```swift
Sendora.configure(apiKey:, projectId:, options:)
Sendora.handleDeepLink(url:)
Sendora.checkDeferredDeepLink(completion:)
Sendora.trackEvent(_:properties:)
Sendora.identify(userId:, traits:, options:)
Sendora.consent.grant() / revoke()
```

## Security

- `SendoraValidator` refuses `sk_` keys, non-HTTPS URLs, bad event names, deep props.
- userId + deviceId in Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
- Event queue persisted with PII stripped.
- `handleDeepLink` host-allowlists via `config.linkHosts`.

## Publish

`git tag <semver> && git push origin <semver>`. Release via `gh release create`.
