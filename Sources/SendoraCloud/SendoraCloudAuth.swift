import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Auth Service surface for the iOS SDK.
///
/// Three flows mirroring the web + RN SDKs:
///   - `signInAnonymously(...)`            — POST /auth-service/anonymous
///   - `signUp(email:password:...)`        — upgrades the same row in
///                                           place when called from an
///                                           anonymous session; otherwise
///                                           creates a fresh account.
///   - `signIn(email:password:...)`        — logs into an existing account.
///                                           Local identity is wiped FIRST
///                                           so any track() during the
///                                           round-trip can't attach to
///                                           the prior identity.
///   - `signOut(completion:)`              — wipe FIRST, fire-and-forget
///                                           revoke. User is logged out
///                                           on device even if the
///                                           network call hangs.
///
/// All public ops are serialized through a private dispatch queue so a
/// double-tap can't race two anonymous mints or interleave signIn +
/// signOut. Response payloads are validated non-empty before persisting
/// — a malformed/MitM'd response can't install an `id = ""` user.
///
/// Tokens persist in Keychain with `kSecAttrAccessibleAfterFirstUnlock-
/// ThisDeviceOnly` (no iCloud sync, sandboxed to this app's bundle id).
public struct SendoraCloudAuthUser: Codable {
    public let id: String
    public let email: String?
    public let emailVerified: Bool
    public let name: String?
    public let isAnonymous: Bool
    /// How this account was FIRST created (`signupMethod`, immutable) and how it
    /// MOST RECENTLY authenticated (`lastLoginMethod`). Free-form provider tokens
    /// (`password`/`anonymous`/`google`/`apple`/`gamecenter`/`playgames`/
    /// `magic_link`/`passkey`/`oidc`/…). Read-only, display-only — never an
    /// authorization signal. `nil` against a backend older than s58.266, or for a
    /// row created before it (backfilled on next sign-in). sdk-ios 4.9.0+.
    /// Optional (Codable decodes to nil when absent) → decoding a cached user from
    /// a pre-4.9.0 build stays safe.
    public let signupMethod: String?
    public let lastLoginMethod: String?
}

public struct SendoraCloudAuthTokens: Codable {
    public let accessToken: String
    public let refreshToken: String
    public let expiresIn: Int
    public let tokenType: String
}

public enum SendoraCloudAuthError: Error {
    case emailAlreadyTaken(String)
    /// `signUp()` on a session already signed in with an identity (ADR-030 §4).
    /// Use `linkEmailPassword()` / `linkGoogle()` / … to add a credential to
    /// THIS account, or sign out first — do not create a second account.
    case alreadyIdentified(String)
    /// A credential passed to `link*()` is already attached to a DIFFERENT
    /// account (ADR-030 §2). Sendora never auto-merges two real accounts.
    case credentialInUse(String)
    case unauthorized(String)
    case network(String)
    case unknown(String)
}

/// Detail handed to onDeviceTakeover subscribers. Fires once per
/// signin call where the backend retired an anonymous user_id
/// (anon → identified flip on the same device, s58.111+). The
/// host app's only job is to delete the matching row from any
/// local mirror table so audience queries joining on user_id
/// stop matching the stale anon row.
public struct DeviceTakeoverEvent {
    public let retiredAnonUserId: String
    public let identifiedUserId: String
    public let at: Date
}

/// Detail handed to `onDeletionCancelled` subscribers (s58.269). Fires once
/// per sign-in that cancelled a pending self-service account deletion within
/// its grace window — the account is restored with the SAME user_id.
public struct DeletionCancelledEvent {
    public let userId: String
    public let at: Date
}

public final class SendoraCloudAuth {
    private let client: APIClient
    private let storage: SendoraStorage
    private let onIdentityChange: (String?) -> Void
    private let onAnonymousWipe: () -> Void
    private var cachedUser: SendoraCloudAuthUser?
    private var cachedExpiresAt: Int64 = 0
    /// Anon refresh token captured at `signInWithMfaSupport` time, stashed
    /// keyed to the issued `mfaChallengeToken` so the later `challengeMfa`
    /// can forward it for device-takeover (s58.111). Without this, the MFA
    /// branch wiped the anon identity before the challenge resolved → the
    /// takeover hint was lost → one device ended with two user_ids +
    /// duplicate pushes (audit s58.203 fix).
    private var pendingAnonTakeover: (challengeToken: String, prevAnonRefreshToken: String)?
    private let lock = NSLock()
    /// Serial queue for public auth ops. All signIn/signUp/signOut/anonymous
    /// calls funnel through here so concurrent invocations execute one at
    /// a time. Refresh runs on a separate single-flight Promise.
    private let opsQueue = DispatchQueue(label: "com.sendora.sdk.auth.ops")
    private var refreshInFlight: [(String?) -> Void] = []
    private var isRefreshing = false
    private let refreshSafetyMs: Int64 = 30_000
    /// Inline device-takeover listeners. UUID-keyed so callers can
    /// unsubscribe via the returned closure. Lock-protected.
    private var takeoverListeners: [UUID: (DeviceTakeoverEvent) -> Void] = [:]
    private var lastTakeover: DeviceTakeoverEvent?
    /// Inline deletion-cancelled listeners (s58.269). UUID-keyed; lock-protected.
    private var deletionCancelledListeners: [UUID: (DeletionCancelledEvent) -> Void] = [:]
    private var lastDeletionCancelled: DeletionCancelledEvent?

    init(
        client: APIClient,
        storage: SendoraStorage,
        onIdentityChange: @escaping (String?) -> Void,
        onAnonymousWipe: @escaping () -> Void
    ) {
        self.client = client
        self.storage = storage
        self.onIdentityChange = onIdentityChange
        self.onAnonymousWipe = onAnonymousWipe

        // Re-hydrate session from Keychain.
        if let json = storage.authUserJson,
           let data = json.data(using: .utf8),
           let user = try? JSONDecoder().decode(SendoraCloudAuthUser.self, from: data),
           !user.id.isEmpty {
            self.cachedUser = user
            self.cachedExpiresAt = storage.authAccessExpiresAt
            self.onIdentityChange(user.id)
        } else if storage.authUserJson != nil {
            // Malformed cached user — drop it rather than carry a bad
            // identity into the session.
            storage.clearAuthTokens()
        }
    }

    public var currentUser: SendoraCloudAuthUser? {
        lock.lock(); defer { lock.unlock() }
        return cachedUser
    }

    /// Synchronous read — returns whatever's cached, even if expired.
    /// Prefer `getAccessToken(completion:)` for transparent refresh.
    public var accessToken: String? {
        return storage.authAccessToken
    }

    /// Returns a non-expired access token. Triggers a single-flight
    /// refresh if the cached token is past expiry.
    ///
    /// s58.47 — when the cached ACCESS token is missing but a refresh
    /// token is still in the Keychain (cold start after the access
    /// token's 15-min TTL elapsed, or partial persist), drive a
    /// refresh instead of returning nil. Pre-s58.47 we bailed
    /// immediately, which left the host app reading nil and
    /// triggering a fresh anonymous mint on every cold launch.
    public func getAccessToken(completion: @escaping (String?) -> Void) {
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let exp = cachedExpiresAt
        if let token = storage.authAccessToken, exp > 0, nowMs < exp - refreshSafetyMs {
            completion(token)
            return
        }
        // Either no access token at all, or it's past (expiry - safety).
        // refreshAccessToken handles both: it short-circuits when no
        // refresh token is in storage either, returning nil.
        refreshAccessToken(completion: completion)
    }

    public func signInAnonymously(
        name: String? = nil,
        metadata: [String: Any]? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            var body: [String: Any] = [:]
            if let name = name { body["name"] = name }
            if let metadata = metadata { body["metadata"] = metadata }
            self.callAuthSync(path: "/auth-service/anonymous", body: body, completion: completion)
        }
    }

    public func signUp(
        email: String,
        password: String,
        name: String? = nil,
        metadata: [String: Any]? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            // Snapshot anonymity inside the serial queue so a concurrent
            // signOut/signIn can't race the read.
            let isAnonymous: Bool = {
                self.lock.lock(); defer { self.lock.unlock() }
                return self.cachedUser?.isAnonymous == true
            }()
            let refresh = self.storage.authRefreshToken

            if isAnonymous, let refresh = refresh {
                var body: [String: Any] = [
                    "refreshToken": refresh,
                    "email": email,
                    "password": password,
                ]
                if let name = name { body["name"] = name }
                self.callAuthSync(path: "/auth-service/upgrade", body: body, completion: completion)
                return
            }

            // ADR-030 §4: already signed in with an identity. signUp() would
            // orphan the current account by minting a second one — refuse and
            // point at link*() (was: silently wiped + fresh-signup = duplicate
            // account). A genuinely signed-out caller (no cachedUser) still
            // falls through to a fresh signup below.
            let wasIdentified: Bool = {
                self.lock.lock(); defer { self.lock.unlock() }
                return self.cachedUser != nil && self.cachedUser?.isAnonymous == false
            }()
            if wasIdentified {
                completion(.failure(.alreadyIdentified("Already signed in. Use linkEmailPassword() to add a password to this account, or sign out first.")))
                return
            }

            var body: [String: Any] = ["email": email, "password": password]
            if let name = name { body["name"] = name }
            if let metadata = metadata { body["metadata"] = metadata }
            self.callAuthSync(path: "/auth-service/signup", body: body, completion: completion)
        }
    }

    public func signIn(
        email: String,
        password: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            // Device-takeover (backend s58.111): if this device holds
            // an anonymous session, forward its refresh token to
            // /login so the backend revokes the anon session,
            // reassigns this device's push tokens to the identified
            // user, and deletes the anon user row. One device → one
            // user_id on the platform side. Read BEFORE wipe.
            var prevAnonRefreshToken: String? = nil
            self.lock.lock()
            let hadUser = self.cachedUser != nil
            let isAnon = self.cachedUser?.isAnonymous == true
            self.lock.unlock()
            if isAnon { prevAnonRefreshToken = self.storage.authRefreshToken }

            if hadUser { self.wipeLocalIdentity() }

            var body: [String: Any] = ["email": email, "password": password]
            if let prev = prevAnonRefreshToken { body["prevAnonRefreshToken"] = prev }
            self.callAuthSync(path: "/auth-service/login", body: body, completion: completion)
        }
    }

    /// Login MFA challenge — when an account has MFA enabled, signIn returns
    /// a `mfaChallenge` outcome instead of an authenticated user. Caller
    /// follows up with `challengeMfa(challengeToken:code:)`.
    public enum SignInOutcome {
        case authenticated(SendoraCloudAuthUser)
        case mfaRequired(challengeToken: String, userId: String)
    }

    /// Like signIn(), but discriminates the MFA-required path. Use this
    /// when you support MFA on your end-users.
    public func signInWithMfaSupport(
        email: String,
        password: String,
        completion: @escaping (Result<SignInOutcome, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            // Capture the device-takeover hint BEFORE any wipe, exactly like
            // signIn(). Do NOT wipe the anon identity here — the MFA challenge
            // may not resolve (or may fail), so the anon session must survive
            // until challengeMfa() actually mints a real session. On the
            // no-MFA direct-success path we wipe-then-persist inside the
            // success branch below (audit s58.203 device-takeover fix).
            var prevAnonRefreshToken: String? = nil
            self.lock.lock()
            let hadUser = self.cachedUser != nil
            let isAnon = self.cachedUser?.isAnonymous == true
            self.lock.unlock()
            if isAnon { prevAnonRefreshToken = self.storage.authRefreshToken }

            var body: [String: Any] = ["email": email, "password": password]
            if let prev = prevAnonRefreshToken { body["prevAnonRefreshToken"] = prev }
            let semaphore = DispatchSemaphore(value: 0)
            self.client.post(path: "/auth-service/login", body: body) { response in
                if let err = self.parseError(response) {
                    completion(.failure(err))
                    semaphore.signal()
                    return
                }
                guard let data = response?["data"] as? [String: Any] else {
                    completion(.failure(.unknown("Malformed response")))
                    semaphore.signal()
                    return
                }
                if let mfaRequired = data["mfaRequired"] as? Bool,
                   mfaRequired,
                   let challengeToken = data["mfaChallengeToken"] as? String {
                    // Stash the anon takeover token keyed to this challenge so
                    // challengeMfa() can forward it. Anon identity stays intact.
                    if let prev = prevAnonRefreshToken {
                        self.lock.lock()
                        self.pendingAnonTakeover = (challengeToken: challengeToken, prevAnonRefreshToken: prev)
                        self.lock.unlock()
                    }
                    let userDict = data["user"] as? [String: Any]
                    let userId = (userDict?["id"] as? String) ?? ""
                    completion(.success(.mfaRequired(challengeToken: challengeToken, userId: userId)))
                    semaphore.signal()
                    return
                }
                guard let user = self.parseSuccess(response),
                      let tokens = self.parseTokens(response) else {
                    completion(.failure(.unknown("Malformed response")))
                    semaphore.signal()
                    return
                }
                // Direct success (account has no MFA): clear the old anon
                // identity now, after the new session is confirmed, then persist.
                if hadUser { self.wipeLocalIdentity() }
                self.persist(user: user, tokens: tokens)
                self.fireLifecycleSignals(from: response, identifiedUserId: user.id)
                completion(.success(.authenticated(user)))
                semaphore.signal()
            }
            semaphore.wait()
        }
    }

    /// Returns the stored anon refresh token iff the local subject is
    /// currently anonymous. Used by every identified-session-mint path
    /// so the backend can run device-takeover (s58.111 + s58.112).
    /// Exposed as `internal` so cross-file helpers (e.g. passkey
    /// assertion) can read it without copying the gating logic.
    internal func takeoverHint() -> String? {
        self.lock.lock(); defer { self.lock.unlock() }
        guard cachedUser?.isAnonymous == true else { return nil }
        return self.storage.authRefreshToken
    }

    // MARK: - Device-takeover listener (s58.116 parity with RN 1.0.5)

    /// Register a callback fired when the backend retires an anon
    /// `user_id` during a signin on this device. Use it to delete
    /// the matching row from any local mirror table — Sendora's own
    /// `auth_service_users` + `push_tokens` are already cleaned up
    /// server-side. Returns an unsubscribe closure.
    ///
    /// Listeners fire on every identified-signin path:
    /// signIn / loginSocial / verifyMagicLink / verifyEmailOtp /
    /// challengeMfa / passkey authenticate / OIDC SSO callback.
    /// Local-only — survives webhook receiver downtime. For
    /// server-pipeline cleanup also subscribe `auth.device_takeover`
    /// webhook.
    @discardableResult
    public func onDeviceTakeover(_ listener: @escaping (DeviceTakeoverEvent) -> Void) -> () -> Void {
        let key = UUID()
        lock.lock()
        takeoverListeners[key] = listener
        lock.unlock()
        return { [weak self] in
            guard let self = self else { return }
            self.lock.lock(); defer { self.lock.unlock() }
            self.takeoverListeners.removeValue(forKey: key)
        }
    }

    /// Returns the most recent takeover the SDK observed in this
    /// session, or nil if none. Lets late subscribers pick up the
    /// takeover their handler missed.
    public func getLastDeviceTakeover() -> DeviceTakeoverEvent? {
        lock.lock(); defer { lock.unlock() }
        return lastTakeover
    }

    /// Internal — called from every identified-signin path with the
    /// `retiredAnonUserId` parsed off the backend response (or off
    /// the SSO redirect fragment). Snapshot + dispatch outside the
    /// lock so a listener can't deadlock by re-entering the auth
    /// surface.
    ///
    /// Validates UUID shape before firing. The value comes from a
    /// URL fragment / response body that a MitM could tamper; a
    /// non-UUID value handed to a listener that interpolates it
    /// into a path (the documented pattern) becomes a
    /// path-injection sink in the host app.
    func fireDeviceTakeover(retiredAnonUserId: String, identifiedUserId: String) {
        guard Self.isCanonicalUuid(retiredAnonUserId) else { return }
        let evt = DeviceTakeoverEvent(
            retiredAnonUserId: retiredAnonUserId,
            identifiedUserId: identifiedUserId,
            at: Date()
        )
        let snapshot: [(DeviceTakeoverEvent) -> Void] = {
            lock.lock(); defer { lock.unlock() }
            lastTakeover = evt
            return Array(takeoverListeners.values)
        }()
        for fn in snapshot { fn(evt) }
    }

    /// Subscribe to deletion-cancelled events (s58.269): fires when a sign-in
    /// cancelled a pending self-service account deletion within its grace
    /// window (the account is restored, same user_id). Surface "your deletion
    /// was cancelled" + reconcile local state. Returns an unsubscribe closure.
    @discardableResult
    public func onDeletionCancelled(_ listener: @escaping (DeletionCancelledEvent) -> Void) -> () -> Void {
        let key = UUID()
        lock.lock()
        deletionCancelledListeners[key] = listener
        lock.unlock()
        return { [weak self] in
            guard let self = self else { return }
            self.lock.lock(); defer { self.lock.unlock() }
            self.deletionCancelledListeners.removeValue(forKey: key)
        }
    }

    /// The most recent deletion-cancelled event this session, or nil.
    public func getLastDeletionCancelled() -> DeletionCancelledEvent? {
        lock.lock(); defer { lock.unlock() }
        return lastDeletionCancelled
    }

    /// Internal — fan out deletion-cancelled to subscribers + cache the latest.
    func fireDeletionCancelled(userId: String) {
        let evt = DeletionCancelledEvent(userId: userId, at: Date())
        let snapshot: [(DeletionCancelledEvent) -> Void] = {
            lock.lock(); defer { lock.unlock() }
            lastDeletionCancelled = evt
            return Array(deletionCancelledListeners.values)
        }()
        for fn in snapshot { fn(evt) }
    }

    /// Fire BOTH lifecycle listeners (device-takeover + deletion-cancelled)
    /// from a backend auth response — the single place that parses the two
    /// optional signals so every sign-in path emits them consistently (s58.269).
    func fireLifecycleSignals(from response: [String: Any]?, identifiedUserId: String) {
        let data = response?["data"] as? [String: Any]
        if let retired = data?["retiredAnonUserId"] as? String, !retired.isEmpty {
            fireDeviceTakeover(retiredAnonUserId: retired, identifiedUserId: identifiedUserId)
        }
        if let restored = data?["reactivatedFromDeletion"] as? Bool, restored {
            fireDeletionCancelled(userId: identifiedUserId)
        }
    }

    /// Exchange the `mfaChallengeToken` from `signInWithMfaSupport` + a
    /// 6-digit TOTP code (or a 17-char recovery code) for a real session.
    public func challengeMfa(
        challengeToken: String,
        code: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            // Forward the device-takeover hint: prefer the token stashed at
            // signInWithMfaSupport() time (keyed to this challenge), falling
            // back to the live anon refresh (covers callers who reached an
            // MFA challenge through a path that didn't stash). Captured BEFORE
            // any wipe. The anon identity is wiped ONLY on a successful mint
            // below — a wrong/expired code preserves the anon session so the
            // user can retry (audit s58.203 device-takeover fix).
            let stashed: String? = {
                self.lock.lock(); defer { self.lock.unlock() }
                if let p = self.pendingAnonTakeover, p.challengeToken == challengeToken {
                    return p.prevAnonRefreshToken
                }
                return nil
            }()
            let prevAnonRefreshToken = stashed ?? self.takeoverHint()
            let hadUser: Bool = {
                self.lock.lock(); defer { self.lock.unlock() }
                return self.cachedUser != nil
            }()

            var body: [String: Any] = ["challengeToken": challengeToken, "code": code]
            if let prev = prevAnonRefreshToken { body["prevAnonRefreshToken"] = prev }

            let semaphore = DispatchSemaphore(value: 0)
            self.client.post(path: "/auth-service/mfa/challenge", body: body) { response in
                if let err = self.parseError(response) {
                    completion(.failure(err)) // anon identity preserved on failure
                    semaphore.signal()
                    return
                }
                guard let user = self.parseSuccess(response),
                      let tokens = self.parseTokens(response) else {
                    completion(.failure(.unknown("Malformed response")))
                    semaphore.signal()
                    return
                }
                // Success: clear the stash + old anon identity, then persist.
                self.lock.lock()
                if self.pendingAnonTakeover?.challengeToken == challengeToken {
                    self.pendingAnonTakeover = nil
                }
                self.lock.unlock()
                if hadUser { self.wipeLocalIdentity() }
                self.persist(user: user, tokens: tokens)
                self.fireLifecycleSignals(from: response, identifiedUserId: user.id)
                completion(.success(user))
                semaphore.signal()
            }
            semaphore.wait()
        }
    }

    // MARK: - Magic link

    /// Send a magic-link email. Always resolves successfully regardless
    /// of whether the email matches a known user.
    public func sendMagicLink(
        email: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: "/auth-service/magic-link/request", body: ["email": email]) { response in
            if let err = self.parseError(response) {
                completion(.failure(err))
            } else {
                completion(.success(()))
            }
        }
    }

    // MARK: - Social sign-in (8 providers)

    /// Verify an IdP-issued credential and mint a Sendora session.
    /// Customer's app handles the IdP dance — typically via
    /// ASAuthorization (Apple), ASWebAuthenticationSession (web-based
    /// providers), or a 3rd-party SDK — then hands the result here.
    ///
    /// `provider` is one of: google, github, apple, microsoft,
    /// linkedin, facebook, twitter, discord. Twitter is rejected
    /// server-side per OAuth 2.0 verified-email gap.
    ///
    /// Pass either `code` + `redirectUri` (authorization-code flow)
    /// OR `idToken` (Apple-native flow). Apple's first-time prompt
    /// also yields name fields — pass via `appleFirstName` /
    /// `appleLastName`. Apple only sends them once.
    public func loginSocial(
        provider: String,
        code: String? = nil,
        idToken: String? = nil,
        redirectUri: String? = nil,
        codeVerifier: String? = nil,
        appleFirstName: String? = nil,
        appleLastName: String? = nil,
        // ADR-025 link-in-place opt-in. When anonymous + `link: true`, an
        // anon→social upgrade KEEPS the same user id (sub) — promoted in place
        // (like Firebase linkWithCredential) instead of a device-takeover that
        // mints a new id. No effect off-anon or on a collision.
        link: Bool = false,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            // Device-takeover hint — same posture as signIn().
            var prevAnonRefreshToken: String? = nil
            self.lock.lock()
            let hadUser = self.cachedUser != nil
            let isAnon = self.cachedUser?.isAnonymous == true
            self.lock.unlock()
            if isAnon { prevAnonRefreshToken = self.storage.authRefreshToken }

            if hadUser { self.wipeLocalIdentity() }

            var body: [String: Any] = ["provider": provider]
            if let code = code { body["code"] = code }
            if let idToken = idToken { body["idToken"] = idToken }
            if let redirectUri = redirectUri { body["redirectUri"] = redirectUri }
            if let codeVerifier = codeVerifier { body["codeVerifier"] = codeVerifier }
            if appleFirstName != nil || appleLastName != nil {
                var name: [String: String] = [:]
                if let f = appleFirstName { name["firstName"] = f }
                if let l = appleLastName { name["lastName"] = l }
                body["appleName"] = name
            }
            if let prev = prevAnonRefreshToken { body["prevAnonRefreshToken"] = prev }
            // ADR-025: opt into link-in-place (backend ignores it unless anon + new identity).
            if link { body["linkAnonymous"] = true }
            self.callAuthSync(path: "/auth-service/login/social", body: body, completion: completion)
        }
    }

    /// Convenience: Google authorization-code login.
    public func signInWithGoogle(
        code: String,
        redirectUri: String,
        link: Bool = false,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) { loginSocial(provider: "google", code: code, redirectUri: redirectUri, link: link, completion: completion) }

    /// Convenience: GitHub authorization-code login.
    public func signInWithGitHub(
        code: String,
        redirectUri: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) { loginSocial(provider: "github", code: code, redirectUri: redirectUri, completion: completion) }

    /// Apple Sign In via native ASAuthorization. Pass the
    /// `identityToken` from `ASAuthorizationAppleIDCredential`. On
    /// first sign-in, also pass the user's first + last name from
    /// `fullName` — Apple won't send them again.
    public func signInWithApple(
        idToken: String,
        firstName: String? = nil,
        lastName: String? = nil,
        // ADR-025: keep the same user id on an anon→Apple upgrade. See `loginSocial`.
        link: Bool = false,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        loginSocial(
            provider: "apple",
            idToken: idToken,
            appleFirstName: firstName,
            appleLastName: lastName,
            link: link,
            completion: completion
        )
    }

    /// Apple Game Center sign-in (email-less, player-keyed). Pass the payload
    /// from `GKLocalPlayer.local.fetchItems(forIdentityVerificationSignature:)`
    /// plus your app's bundle id — obtain them via GameKit (or the Sendora
    /// helper). `link: true` KEEPS the same user id when upgrading an anonymous
    /// device (ADR-025 link-in-place); no effect off-anon or on a collision.
    /// `signature`/`salt` are base64; `timestamp` is GameKit's millisecond value.
    public func signInWithGameCenter(
        publicKeyURL: String,
        signature: String,
        salt: String,
        timestamp: UInt64,
        teamPlayerID: String,
        bundleID: String,
        link: Bool = false,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            // Device-takeover hint — same posture as loginSocial().
            var prevAnonRefreshToken: String? = nil
            self.lock.lock()
            let hadUser = self.cachedUser != nil
            let isAnon = self.cachedUser?.isAnonymous == true
            self.lock.unlock()
            if isAnon { prevAnonRefreshToken = self.storage.authRefreshToken }

            if hadUser { self.wipeLocalIdentity() }

            var body: [String: Any] = [
                "publicKeyUrl": publicKeyURL,
                "signature": signature,
                "salt": salt,
                "timestamp": timestamp,
                "teamPlayerId": teamPlayerID,
                "bundleId": bundleID,
            ]
            if let prev = prevAnonRefreshToken { body["prevAnonRefreshToken"] = prev }
            // ADR-025: opt into link-in-place (backend ignores it unless anon + new identity).
            if link { body["linkAnonymous"] = true }
            self.callAuthSync(path: "/auth-service/login/game-center", body: body, completion: completion)
        }
    }

    /// Convenience: Microsoft Azure AD authorization-code login.
    public func signInWithMicrosoft(
        code: String,
        redirectUri: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) { loginSocial(provider: "microsoft", code: code, redirectUri: redirectUri, completion: completion) }

    /// Convenience: LinkedIn (Sign In with LinkedIn using OpenID Connect).
    public func signInWithLinkedIn(
        code: String,
        redirectUri: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) { loginSocial(provider: "linkedin", code: code, redirectUri: redirectUri, completion: completion) }

    /// Convenience: Facebook Graph login. Refuses if email permission not granted.
    public func signInWithFacebook(
        code: String,
        redirectUri: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) { loginSocial(provider: "facebook", code: code, redirectUri: redirectUri, completion: completion) }

    /// Convenience: Discord OAuth2. Refuses if account email not verified.
    public func signInWithDiscord(
        code: String,
        redirectUri: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) { loginSocial(provider: "discord", code: code, redirectUri: redirectUri, completion: completion) }

    /// Consume a magic-link token (extracted from the deep-link the user
    /// tapped) and mint a session.
    public func verifyMagicLink(
        token: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            let prev = self.takeoverHint()
            let hadUser: Bool = {
                self.lock.lock(); defer { self.lock.unlock() }
                return self.cachedUser != nil
            }()
            if hadUser { self.wipeLocalIdentity() }
            var body: [String: Any] = ["token": token]
            if let prev = prev { body["prevAnonRefreshToken"] = prev }
            self.callAuthSync(path: "/auth-service/magic-link/verify", body: body, completion: completion)
        }
    }

    // MARK: - Email OTP (6-digit cross-device code)

    /// Send a 6-digit email OTP. Always resolves successfully
    /// regardless of whether the email matches a known user.
    public func sendEmailOtp(
        email: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: "/auth-service/email-otp/request", body: ["email": email]) { response in
            if let err = self.parseError(response) {
                completion(.failure(err))
            } else {
                completion(.success(()))
            }
        }
    }

    /// Verify a typed 6-digit code + the email it was sent to.
    public func verifyEmailOtp(
        email: String,
        code: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            let prev = self.takeoverHint()
            let hadUser: Bool = {
                self.lock.lock(); defer { self.lock.unlock() }
                return self.cachedUser != nil
            }()
            if hadUser { self.wipeLocalIdentity() }
            var body: [String: Any] = ["email": email, "code": code]
            if let prev = prev { body["prevAnonRefreshToken"] = prev }
            self.callAuthSync(path: "/auth-service/email-otp/verify", body: body, completion: completion)
        }
    }

    // MARK: - Password reset + email verification

    /// Trigger a password-reset email. Backend always resolves
    /// successfully even when the address is unknown — prevents
    /// account enumeration.
    public func requestPasswordReset(
        email: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: "/auth-service/password/forgot", body: ["email": email]) { response in
            if let err = self.parseError(response) {
                completion(.failure(err))
            } else {
                completion(.success(()))
            }
        }
    }

    /// Pair the reset-email token with the user's new password.
    public func resetPassword(
        token: String,
        newPassword: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: "/auth-service/password/reset", body: ["token": token, "newPassword": newPassword]) { response in
            if let err = self.parseError(response) {
                completion(.failure(err))
            } else {
                completion(.success(()))
            }
        }
    }

    /// Verify the email-address token from the link Sendora sent on
    /// signup. Flips `emailVerified=true` on the user row.
    public func verifyEmail(
        token: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: "/auth-service/email/verify", body: ["token": token]) { response in
            if let err = self.parseError(response) {
                completion(.failure(err))
            } else {
                completion(.success(()))
            }
        }
    }

    /// Re-send the email-verification email for the currently-
    /// signed-in user. No-op when already verified.
    public func sendVerificationEmail(
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        bearerCall(path: "/auth-service/email/verify/resend", body: [:]) { response in
            if let err = self.parseError(response) {
                completion(.failure(err))
            } else {
                completion(.success(()))
            }
        }
    }

    // MARK: - MFA enrollment management (Bearer-authenticated)

    public struct MfaEnrollment {
        public let secret: String
        public let otpauthUrl: String
        public let recoveryCodes: [String]
    }

    /// Begin MFA enrollment. Returns the otpauth:// URL + 8 recovery
    /// codes — shown ONCE.
    public func enrollMfa(completion: @escaping (Result<MfaEnrollment, SendoraCloudAuthError>) -> Void) {
        bearerCall(path: "/auth-service/mfa/enroll/start", body: [:]) { response in
            guard let data = response?["data"] as? [String: Any],
                  let secret = data["secret"] as? String,
                  let url = data["otpauthUrl"] as? String,
                  let codes = data["recoveryCodes"] as? [String] else {
                completion(.failure(.unknown("Malformed enrollment response")))
                return
            }
            completion(.success(MfaEnrollment(secret: secret, otpauthUrl: url, recoveryCodes: codes)))
        }
    }

    public func confirmMfa(code: String, completion: @escaping (Result<Bool, SendoraCloudAuthError>) -> Void) {
        bearerCall(path: "/auth-service/mfa/enroll/confirm", body: ["code": code]) { response in
            let confirmed = (response?["data"] as? [String: Any])?["confirmed"] as? Bool ?? false
            completion(.success(confirmed))
        }
    }

    public func disableMfa(completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void) {
        bearerCall(path: "/auth-service/mfa/disable", body: [:]) { _ in completion(.success(())) }
    }

    // MARK: - Device sessions self-service

    public struct DeviceSession {
        public let id: String
        public let deviceInfo: String?
        public let lastUsedAt: String?
        public let createdAt: String
    }

    public func listMySessions(completion: @escaping ([DeviceSession]) -> Void) {
        guard let headers = bearerHeaders() else { completion([]); return }
        client.get(path: "/auth-service/sessions/me", headers: headers) { response in
            guard let arr = response?["data"] as? [[String: Any]] else { completion([]); return }
            completion(arr.compactMap { row in
                guard let id = row["id"] as? String, !id.isEmpty,
                      let createdAt = row["createdAt"] as? String else { return nil }
                return DeviceSession(
                    id: id,
                    deviceInfo: row["deviceInfo"] as? String,
                    lastUsedAt: row["lastUsedAt"] as? String,
                    createdAt: createdAt
                )
            })
        }
    }

    public func revokeSession(sessionId: String, completion: @escaping () -> Void) {
        guard let headers = bearerHeaders() else { completion(); return }
        client.delete(path: "/auth-service/sessions/me/\(sessionId)", headers: headers) { _ in completion() }
    }

    public func revokeAllSessions(completion: @escaping () -> Void) {
        guard let headers = bearerHeaders() else { completion(); return }
        client.delete(path: "/auth-service/sessions/me", headers: headers) { _ in completion() }
    }

    /// Outcome of `deleteAccount`. `status` is `"purged"` (hard-deleted now,
    /// grace = 0) or `"pending"` (deactivated + sessions revoked now, hard
    /// delete scheduled at `scheduledPurgeAt`; cancellable by signing back in).
    public struct AccountDeletionResult {
        public let status: String
        public let scheduledPurgeAt: String?
        public let graceDays: Int
    }

    /// Delete the signed-in user's account (Apple App Store Guideline 5.1.1(v)).
    /// Honors the project's configured grace period. Wipes local identity on
    /// success (the server has revoked the session). Fails when no user is
    /// signed in or the request errors.
    ///
    /// Resolves a FRESH access token via `getAccessToken` first (refreshing a
    /// past-expiry cached token) — this is a one-shot destructive action, so a
    /// 401 from a stale token would silently strand the user with an undeleted
    /// account (the cause of the prod 401s when "delete" was tapped after the
    /// app sat idle).
    public func deleteAccount(completion: @escaping (Result<AccountDeletionResult, Error>) -> Void) {
        getAccessToken { [weak self] token in
            guard let self = self else { return }
            guard let token = token else {
                completion(.failure(NSError(domain: "SendoraCloud", code: 401,
                    userInfo: [NSLocalizedDescriptionKey: "deleteAccount requires a signed-in user"])))
                return
            }
            let headers = ["Authorization": "Bearer \(token)"]
            self.client.delete(path: "/auth-service/me", headers: headers) { [weak self] response in
                guard let response = response else {
                    completion(.failure(NSError(domain: "SendoraCloud", code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "deleteAccount failed (network error)"])))
                    return
                }
                if let error = response["error"] as? [String: Any] {
                    let msg = (error["message"] as? String) ?? "deleteAccount failed"
                    completion(.failure(NSError(domain: "SendoraCloud", code: 500,
                        userInfo: [NSLocalizedDescriptionKey: msg])))
                    return
                }
                // Account is gone / deactivated server-side — drop local identity.
                self?.wipeLocalIdentity()
                let data = response["data"] as? [String: Any]
                completion(.success(AccountDeletionResult(
                    status: (data?["status"] as? String) ?? "pending",
                    scheduledPurgeAt: data?["scheduledPurgeAt"] as? String,
                    graceDays: (data?["graceDays"] as? Int) ?? 0
                )))
            }
        }
    }

    // MARK: - Identity linking (ADR-030)
    //
    // Attach a SECOND credential to the CURRENT signed-in account, preserving
    // the same user id (sub). Unlike signUp()/loginSocial(link:) — which
    // preserve the sub only from an ANONYMOUS session — these operate on an
    // already-identified account. Bearer-authenticated; NO token rotation (the
    // cached user is refreshed in place). Collision → `.credentialInUse` (never
    // merges). Primary use: one account across platforms — a Game Center player
    // links email/Google, then signs in on Android to the SAME sub.

    /// Link email + password to the current account (sub preserved).
    public func linkEmailPassword(
        email: String,
        password: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        linkCredential(path: "/auth-service/me/link/email", body: ["email": email, "password": password], completion: completion)
    }

    /// Link an OAuth social identity to the current account. Pass a native
    /// `idToken` OR a web `code` + `redirectURI`.
    public func linkSocial(
        provider: String,
        idToken: String? = nil,
        code: String? = nil,
        redirectURI: String? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        var body: [String: Any] = ["provider": provider]
        if let idToken = idToken { body["idToken"] = idToken }
        if let code = code { body["code"] = code }
        if let redirectURI = redirectURI { body["redirectUri"] = redirectURI }
        linkCredential(path: "/auth-service/me/link/social", body: body, completion: completion)
    }

    /// Convenience: link a Google identity (native `idToken`, or web `code`+`redirectURI`).
    public func linkGoogle(
        idToken: String? = nil,
        code: String? = nil,
        redirectURI: String? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        linkSocial(provider: "google", idToken: idToken, code: code, redirectURI: redirectURI, completion: completion)
    }

    /// Convenience: link an Apple identity (native ASAuthorization `idToken`).
    public func linkApple(
        idToken: String? = nil,
        code: String? = nil,
        redirectURI: String? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        linkSocial(provider: "apple", idToken: idToken, code: code, redirectURI: redirectURI, completion: completion)
    }

    /// Link an Apple Game Center identity to the current account. Pass the
    /// payload from `GKLocalPlayer.local.fetchItems(forIdentityVerificationSignature:)`
    /// + the app's bundle id (same inputs as `signInWithGameCenter`).
    public func linkGameCenter(
        publicKeyURL: String,
        signature: String,
        salt: String,
        timestamp: Int,
        teamPlayerID: String,
        bundleID: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        let body: [String: Any] = [
            "publicKeyUrl": publicKeyURL,
            "signature": signature,
            "salt": salt,
            "timestamp": timestamp,
            "teamPlayerId": teamPlayerID,
            "bundleId": bundleID,
        ]
        linkCredential(path: "/auth-service/me/link/game-center", body: body, completion: completion)
    }

    /// Shared link executor. Resolves a fresh access token, POSTs the credential
    /// with the Bearer header, then refreshes the cached user IN PLACE (no token
    /// rotation — the sub is unchanged). Mirrors `deleteAccount`'s Bearer flow.
    private func linkCredential(
        path: String,
        body: [String: Any],
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        getAccessToken { [weak self] token in
            guard let self = self else { return }
            guard let token = token else {
                completion(.failure(.unauthorized("Sign in before linking a credential")))
                return
            }
            let headers = ["Authorization": "Bearer \(token)"]
            self.client.post(path: path, body: body, headers: headers) { [weak self] response in
                guard let self = self else { return }
                if let err = self.parseError(response) {
                    completion(.failure(err))
                    return
                }
                guard let user = self.parseSuccess(response) else {
                    completion(.failure(.unknown("Malformed link response")))
                    return
                }
                self.updateLocalUser(user)
                completion(.success(user))
            }
        }
    }

    /// Refresh the cached user after a link — the sub is unchanged, so only the
    /// user object + its stored copy change (no token/identity rotation).
    private func updateLocalUser(_ user: SendoraCloudAuthUser) {
        lock.lock()
        cachedUser = user
        lock.unlock()
        if let json = try? JSONEncoder().encode(user),
           let str = String(data: json, encoding: .utf8) {
            storage.authUserJson = str
        }
    }

    // MARK: - Internals (Bearer)

    /// Internal helper used by passkey + SSO flows. Parses the
    /// standard `{ data: { user, tokens } }` envelope and persists.
    /// Returns the user on success, nil on malformed payload. Fires
    /// the device-takeover listener when `data.retiredAnonUserId`
    /// is present.
    func persistFromAuthResponse(_ response: [String: Any]?) -> SendoraCloudAuthUser? {
        guard let user = parseSuccess(response),
              let tokens = parseTokens(response) else {
            return nil
        }
        persist(user: user, tokens: tokens)
        fireLifecycleSignals(from: response, identifiedUserId: user.id)
        return user
    }

    /// Build the Authorization header for end-user-authenticated routes.
    /// Returns nil when no current session — callers bail.
    func bearerHeaders() -> [String: String]? {
        guard let token = storage.authAccessToken else { return nil }
        return ["Authorization": "Bearer \(token)"]
    }

    private func bearerCall(
        path: String,
        body: [String: Any],
        completion: @escaping ([String: Any]?) -> Void
    ) {
        guard let headers = bearerHeaders() else {
            completion(nil)
            return
        }
        client.post(path: path, body: body, headers: headers, completion: completion)
    }

    public func signOut(completion: @escaping () -> Void) {
        opsQueue.async {
            // Wipe FIRST so the user is logged out on device even if
            // the revoke request hangs (airplane mode, 5xx, circuit
            // open). Refresh token still expires server-side.
            let refresh = self.storage.authRefreshToken
            self.wipeLocalIdentity()
            if let refresh = refresh {
                self.client.post(path: "/auth-service/token/revoke",
                                 body: ["refreshToken": refresh]) { _ in
                    completion()
                }
            } else {
                completion()
            }
        }
    }

    // MARK: - Internals

    /// Synchronous wrapper that blocks the opsQueue until the network
    /// call completes — keeps one auth op at a time per SDK instance.
    private func callAuthSync(
        path: String,
        body: [String: Any],
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        let semaphore = DispatchSemaphore(value: 0)
        client.post(path: path, body: body) { [weak self] response in
            guard let self = self else { semaphore.signal(); return }
            if let err = self.parseError(response) {
                completion(.failure(err))
                semaphore.signal()
                return
            }
            guard let user = self.parseSuccess(response),
                  let tokens = self.parseTokens(response) else {
                completion(.failure(.unknown("Malformed response")))
                semaphore.signal()
                return
            }
            self.persist(user: user, tokens: tokens)
            self.fireLifecycleSignals(from: response, identifiedUserId: user.id)
            completion(.success(user))
            semaphore.signal()
        }
        semaphore.wait()
    }

    private func refreshAccessToken(completion: @escaping (String?) -> Void) {
        opsQueue.async {
            self.lock.lock()
            self.refreshInFlight.append(completion)
            if self.isRefreshing {
                self.lock.unlock()
                return
            }
            self.isRefreshing = true
            self.lock.unlock()

            // s58.73: re-read the stored refresh token at firing time
            // (NOT at completion enqueue). If a sibling task (background
            // push handler, deferred deep-link cold-start) rotated the
            // token while this call was queued, we get the fresh value
            // and dodge the backend's reuse-detection grace race.
            guard let refresh = self.storage.authRefreshToken else {
                self.completeRefresh(token: nil)
                return
            }

            // Short-circuit: if we have a fresh access token in storage
            // already (sibling rotated successfully + populated it
            // before we acquired isRefreshing), return it directly.
            // Saves a redundant /refresh round-trip.
            let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
            if let stashedAccess = self.storage.authAccessToken,
               !stashedAccess.isEmpty,
               self.storage.authAccessExpiresAt > nowMs {
                self.lock.lock()
                self.cachedExpiresAt = self.storage.authAccessExpiresAt
                self.lock.unlock()
                self.completeRefresh(token: stashedAccess)
                return
            }

            self.client.post(path: "/auth-service/token/refresh",
                             body: ["refreshToken": refresh]) { [weak self] response in
                guard let self = self else { return }
                // s58.46 — stored token is dead. Wipe local identity
                // so the next op doesn't loop on the same refresh
                // value. Pre-s58.46 we silently returned nil and the
                // host app re-tried indefinitely (Pulse News iOS hit
                // /refresh ~1×/s for hours).
                if let error = response?["error"] as? [String: Any],
                   let code = error["code"] as? String,
                   Self.isDeadRefreshError(code) {
                    self.wipeLocalIdentity()
                    self.completeRefresh(token: nil)
                    return
                }
                guard let data = response?["data"] as? [String: Any],
                      let accessToken = data["accessToken"] as? String,
                      !accessToken.isEmpty,
                      let refreshToken = data["refreshToken"] as? String,
                      !refreshToken.isEmpty,
                      let expiresIn = data["expiresIn"] as? Int else {
                    self.completeRefresh(token: nil)
                    return
                }
                let expMs = Int64(Date().timeIntervalSince1970 * 1000) + Int64(expiresIn) * 1000
                self.storage.authAccessToken = accessToken
                self.storage.authRefreshToken = refreshToken
                self.storage.authAccessExpiresAt = expMs
                self.lock.lock()
                self.cachedExpiresAt = expMs
                self.lock.unlock()
                self.completeRefresh(token: accessToken)
            }
        }
    }

    // MARK: - Proactive refresh (s58.73)

    /// Background timer + UIApplication.didBecomeActive observer that
    /// triggers a refresh when the access token enters the last 20%
    /// of its TTL ± 30s jitter. Refresh becomes a scheduled event,
    /// never a 401-driven race. Started on persist(), stopped on
    /// wipeLocalIdentity().
    private var proactiveTimer: Timer?
    private var proactiveAppActiveObserver: NSObjectProtocol?

    fileprivate func startProactiveRefreshCron() {
        guard proactiveTimer == nil else { return }
        let tick: () -> Void = { [weak self] in
            guard let self = self else { return }
            guard let _ = self.storage.authAccessToken else { return }
            let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
            let expMs = self.storage.authAccessExpiresAt
            let remainingMs = expMs - nowMs
            if remainingMs <= 0 { return }
            // Assume 15-min default access-TTL when we can't observe the
            // originally-issued lifetime; pad with jitter so multiple
            // app instances on the same network don't synchronize the
            // refresh herd.
            let guessOriginalMs: Int64 = max(remainingMs, 5 * 60 * 1000)
            let jitter = Int64.random(in: -30_000...30_000)
            let fireWhenRemainingMs = Int64(Double(guessOriginalMs) * 0.2) + jitter
            if remainingMs <= fireWhenRemainingMs {
                self.refreshAccessToken { _ in }
            }
        }
        // Fire immediately on start in case the app launched with a
        // near-expired token.
        tick()
        // Then every 60s.
        let t = Timer(timeInterval: 60.0, repeats: true) { _ in tick() }
        RunLoop.main.add(t, forMode: .common)
        self.proactiveTimer = t

        // Also tick when the app comes back to foreground.
        #if canImport(UIKit)
        self.proactiveAppActiveObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { _ in tick() }
        #endif
    }

    fileprivate func stopProactiveRefreshCron() {
        proactiveTimer?.invalidate()
        proactiveTimer = nil
        if let obs = proactiveAppActiveObserver {
            NotificationCenter.default.removeObserver(obs)
            proactiveAppActiveObserver = nil
        }
    }

    private func completeRefresh(token: String?) {
        let callbacks: [(String?) -> Void] = {
            lock.lock(); defer { lock.unlock() }
            let cs = refreshInFlight
            refreshInFlight.removeAll()
            isRefreshing = false
            return cs
        }()
        for cb in callbacks { cb(token) }
    }

    private func parseError(_ response: [String: Any]?) -> SendoraCloudAuthError? {
        guard let response = response else {
            return .network("Network request failed")
        }
        if let success = response["success"] as? Bool, success { return nil }
        let error = response["error"] as? [String: Any]
        let code = error?["code"] as? String ?? ""
        let message = error?["message"] as? String ?? "Auth request failed"
        if code == "NOT_ANONYMOUS" {
            return .alreadyIdentified(message)
        }
        if code == "CREDENTIAL_IN_USE" {
            return .credentialInUse(message)
        }
        if code == "CONFLICT" || code == "EMAIL_ALREADY_TAKEN" {
            return .emailAlreadyTaken(message)
        }
        if code == "UNAUTHORIZED" || code.hasPrefix("HTTP_401") {
            return .unauthorized(message)
        }
        return .unknown("\(code): \(message)")
    }

    private func parseSuccess(_ response: [String: Any]?) -> SendoraCloudAuthUser? {
        guard let data = response?["data"] as? [String: Any],
              let userDict = data["user"] as? [String: Any],
              let id = userDict["id"] as? String,
              !id.isEmpty else { return nil }
        return SendoraCloudAuthUser(
            id: id,
            email: userDict["email"] as? String,
            emailVerified: userDict["emailVerified"] as? Bool ?? false,
            name: userDict["name"] as? String,
            isAnonymous: userDict["isAnonymous"] as? Bool ?? false,
            signupMethod: userDict["signupMethod"] as? String,   // s58.266
            lastLoginMethod: userDict["lastLoginMethod"] as? String
        )
    }

    private func parseTokens(_ response: [String: Any]?) -> SendoraCloudAuthTokens? {
        guard let data = response?["data"] as? [String: Any],
              let tokensDict = data["tokens"] as? [String: Any],
              let accessToken = tokensDict["accessToken"] as? String,
              !accessToken.isEmpty,
              let refreshToken = tokensDict["refreshToken"] as? String,
              !refreshToken.isEmpty,
              let expiresIn = tokensDict["expiresIn"] as? Int,
              expiresIn > 0 else { return nil }
        return SendoraCloudAuthTokens(
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresIn: expiresIn,
            tokenType: tokensDict["tokenType"] as? String ?? "Bearer"
        )
    }

    private func persist(user: SendoraCloudAuthUser, tokens: SendoraCloudAuthTokens) {
        let expMs = Int64(Date().timeIntervalSince1970 * 1000) + Int64(tokens.expiresIn) * 1000
        lock.lock()
        cachedUser = user
        cachedExpiresAt = expMs
        lock.unlock()

        storage.authAccessToken = tokens.accessToken
        storage.authRefreshToken = tokens.refreshToken
        storage.authAccessExpiresAt = expMs
        if let json = try? JSONEncoder().encode(user),
           let str = String(data: json, encoding: .utf8) {
            storage.authUserJson = str
        }
        onIdentityChange(user.id)
        startProactiveRefreshCron()
    }

    private func wipeLocalIdentity() {
        lock.lock()
        cachedUser = nil
        cachedExpiresAt = 0
        pendingAnonTakeover = nil
        lock.unlock()
        storage.clearAuthTokens()
        stopProactiveRefreshCron()
        onAnonymousWipe()
    }

    /// Canonical UUID validator. Defends against tampered
    /// `sendora_retired_anon` fragment / response values reaching
    /// host-app listeners as a path-injection sink.
    private static func isCanonicalUuid(_ s: String) -> Bool {
        return UUID(uuidString: s) != nil
    }

    /// Backend error codes on /token/refresh that mean the stored
    /// refresh token is permanently dead — SDK must wipe local
    /// identity + stop retrying. INVALID_REFRESH_TOKEN is the s58.46
    /// canonical code; UNAUTHORIZED / HTTP_401 cover older backend
    /// builds; RATE_LIMIT means the per-IP back-off tripped — also a
    /// sign the loop has run amok.
    private static func isDeadRefreshError(_ code: String) -> Bool {
        return code == "INVALID_REFRESH_TOKEN"
            || code == "UNAUTHORIZED"
            || code == "HTTP_401"
            || code == "RATE_LIMIT_EXCEEDED"
            || code == "RATE_LIMIT"
    }
}
