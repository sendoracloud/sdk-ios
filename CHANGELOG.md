# Changelog

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
