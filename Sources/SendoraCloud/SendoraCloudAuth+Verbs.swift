import Foundation

// ADR-033 §3.5 — the public verbs. Every one is sugar for a row of the shared
// transition table: it picks the engine (SendoraCloudAuth+Engines.swift) by
// `status()` and maps the engine's typed outcome onto the method's historical
// result shape. All signatures that existed before 5.4.0 are unchanged.

extension SendoraCloudAuth {
    private func mapSwitch(_ result: Result<SwitchOutcome, SendoraCloudAuthError>) -> Result<SendoraCloudAuthUser, SendoraCloudAuthError> {
        switch result {
        case .success(.done(let user, _, _)): return .success(user)
        case .success(.mfaRequired): return .failure(.unknown("MFA required — use signInWithMfaSupport() / signIn(with:)"))
        case .failure(let error): return .failure(error)
        }
    }

    private func recentAuthError(_ message: String) -> SendoraCloudAuthError {
        return .rejected(code: "RECENT_AUTH_REQUIRED", message: message, status: 403, retryAfterSeconds: nil)
    }

    // MARK: - MINT

    /// Return this device's session, minting a guest only when it has none.
    ///
    /// The MINT rows (§3.3): an existing session — anonymous OR identified — is
    /// returned as-is with no network (5.3.0); in `signedOut` the newest eligible
    /// HELD guest is restored first when `autoRestoreHeldGuest` is on (visible as
    /// `.signedIn`, cause `.restore`, then `.guestReleased(.restored)`), a dead
    /// slot falls through to the next and finally to a fresh mint IN THE SAME
    /// CALL; in `unknown` the call waits for the gap-fill refresh; in `withheld`
    /// it rejects `SESSION_WITHHELD`. `forceNew: true` HOLDS the current guest
    /// (or replaces an identified session) and mints — refused with
    /// `.heldGuestLimit` when all 5 slots are in use.
    public func signInAnonymously(
        name: String? = nil,
        metadata: [String: Any]? = nil,
        forceNew: Bool = false,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            completion(self.performMint(name: name, metadata: metadata, forceNew: forceNew))
        }
    }

    /// Alias of `signInAnonymously()` with no options (§3.5).
    public func ensureSession(completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void) {
        signInAnonymously(completion: completion)
    }

    // MARK: - signUp (routes by status; never calls /upgrade)

    /// `anonymous` → `POST /me/link/email` on the current Bearer (the promotion
    /// keeps the `sub`; a taken email is `.emailAlreadyTaken`); `signedOut` →
    /// `POST /signup`; `identified` → `.alreadyIdentified` locally; `unknown` →
    /// waits for the state to settle; `withheld` → `SESSION_WITHHELD`.
    public func signUp(
        email: String,
        password: String,
        name: String? = nil,
        metadata: [String: Any]? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            if let refusal = self.withheldRefusal() { completion(.failure(refusal)); return }
            if let unsettled = self.settleUnknownIfNeeded() { completion(.failure(unsettled)); return }
            switch self.status() {
            case .anonymous:
                switch self.performLink(path: "/auth-service/me/link/email", body: ["email": email, "password": password], emit: .legacySignature) {
                case .success(.done(let user, _, _)): completion(.success(user))
                case .success(.credentialInUse(_, _, let message)): completion(.failure(.emailAlreadyTaken(message)))
                case .success(.recentAuthRequired(let message)): completion(.failure(self.recentAuthError(message)))
                case .failure(let error): completion(.failure(error))
                }
            case .identified:
                // ADR-030 §4: signUp() would orphan the current account by minting a
                // second one — refuse and point at link*().
                completion(.failure(.alreadyIdentified("Already signed in. Use linkEmailPassword() to add a password to this account, or sign out first.")))
            case .signedOut:
                var body: [String: Any] = ["email": email, "password": password]
                if let name = name { body["name"] = name }
                if let metadata = metadata { body["metadata"] = metadata }
                completion(self.mapSwitch(self.performSwitch(path: "/auth-service/signup", body: body)))
            default:
                completion(.failure(.network("Session state did not settle; retry")))
            }
        }
    }

    // MARK: - Sign-in (switch) — unchanged signatures, no guest hint ever sent

    public func signIn(
        email: String,
        password: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            completion(self.mapSwitch(self.performSwitch(path: "/auth-service/login", body: ["email": email, "password": password])))
        }
    }

    /// Login MFA challenge — when an account has MFA enabled, signIn returns
    /// a `mfaChallenge` outcome instead of an authenticated user. Caller
    /// follows up with `challengeMfa(challengeToken:code:)`.
    public enum SignInOutcome {
        case authenticated(SendoraCloudAuthUser)
        case mfaRequired(challengeToken: String, userId: String)
    }

    /// Like signIn(), but discriminates the MFA-required path. The current
    /// session (a guest included) is untouched until the challenge resolves.
    public func signInWithMfaSupport(
        email: String,
        password: String,
        completion: @escaping (Result<SignInOutcome, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            switch self.performSwitch(path: "/auth-service/login", body: ["email": email, "password": password]) {
            case .success(.done(let user, _, _)): completion(.success(.authenticated(user)))
            case .success(.mfaRequired(let token, let userId)): completion(.success(.mfaRequired(challengeToken: token, userId: userId)))
            case .failure(let error): completion(.failure(error))
            }
        }
    }

    /// Exchange the `mfaChallengeToken` from `signInWithMfaSupport` + a
    /// 6-digit TOTP code (or a 17-char recovery code) for a real session. A
    /// wrong code preserves the current session for a retry.
    public func challengeMfa(
        challengeToken: String,
        code: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            completion(self.mapSwitch(self.performSwitch(path: "/auth-service/mfa/challenge", body: ["challengeToken": challengeToken, "code": code])))
        }
    }

    /// Verify an IdP-issued credential and mint a Sendora session. `provider`
    /// is one of: google, github, apple, microsoft, linkedin, facebook, twitter,
    /// discord. Pass either `code` + `redirectUri` OR `idToken`.
    ///
    /// `link: true` (ADR-025/033): from `anonymous` → `/me/link/social`, the guest
    /// is promoted in place (same `sub`); from `identified` → attaches or returns
    /// a typed refusal (`.credentialInUse`, `RECENT_AUTH_REQUIRED`); an identity
    /// already on this account resolves quietly. In `signedOut` it is a plain
    /// sign-in. `onCredentialInUse: .adopt` on a 409 falls through to a plain
    /// sign-in bound to the same credential (the guest is HELD, never deleted).
    public func loginSocial(
        provider: String,
        code: String? = nil,
        idToken: String? = nil,
        redirectUri: String? = nil,
        codeVerifier: String? = nil,
        appleFirstName: String? = nil,
        appleLastName: String? = nil,
        link: Bool = false,
        onCredentialInUse: CredentialCollisionPolicy? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        let credential = SendoraCloudCredential.social(provider: provider, code: code, idToken: idToken, redirectUri: redirectUri,
                                                       codeVerifier: codeVerifier, appleFirstName: appleFirstName, appleLastName: appleLastName)
        opsQueue.async {
            self.legacyCredentialedSignIn(credential, link: link, policy: onCredentialInUse, completion: completion)
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

    /// Apple Sign In via native ASAuthorization. Pass the `identityToken` from
    /// `ASAuthorizationAppleIDCredential`; on first sign-in also the name parts.
    public func signInWithApple(
        idToken: String,
        firstName: String? = nil,
        lastName: String? = nil,
        link: Bool = false,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        loginSocial(provider: "apple", idToken: idToken, appleFirstName: firstName, appleLastName: lastName, link: link, completion: completion)
    }

    /// Apple Game Center sign-in (email-less, player-keyed). Pass the payload
    /// from `GKLocalPlayer.local.fetchItems(forIdentityVerificationSignature:)`
    /// plus your app's bundle id. `link: true` routes to `/me/link/game-center`
    /// from `anonymous` (promotion, same `sub`) AND `identified` (attach or typed
    /// refusal — never a silent switch); a plain call is a sign-in that HOLDS the
    /// device's guest. `signature`/`salt` are base64; `timestamp` is GameKit's ms.
    public func signInWithGameCenter(
        publicKeyURL: String,
        signature: String,
        salt: String,
        timestamp: UInt64,
        teamPlayerID: String,
        bundleID: String,
        link: Bool = false,
        onCredentialInUse: CredentialCollisionPolicy? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        let credential = SendoraCloudCredential.gameCenter(publicKeyURL: publicKeyURL, signature: signature, salt: salt, timestamp: timestamp,
                                                           teamPlayerID: teamPlayerID, bundleID: bundleID)
        opsQueue.async {
            self.legacyCredentialedSignIn(credential, link: link, policy: onCredentialInUse, completion: completion)
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

    /// Consume a magic-link token (from the deep link the user tapped) and mint
    /// a session. An expired / consumed token costs nothing: the current session stays.
    public func verifyMagicLink(
        token: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            completion(self.mapSwitch(self.performSwitch(path: "/auth-service/magic-link/verify", body: ["token": token])))
        }
    }

    /// Verify a typed 6-digit code + the email it was sent to. A mistyped code
    /// leaves the current session in place for a retry.
    public func verifyEmailOtp(
        email: String,
        code: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            completion(self.mapSwitch(self.performSwitch(path: "/auth-service/email-otp/verify", body: ["email": email, "code": code])))
        }
    }

    /// The legacy-signature routing (§3.5): `link: true` in `anonymous` |
    /// `identified` → `/me/link/*`; `signedOut` → a plain sign-in; `unknown` →
    /// settle first; `withheld` → reject. Over an identified session the typed
    /// kinds are THROWN (`.credentialInUse` / `RECENT_AUTH_REQUIRED`) and
    /// `alreadyLinked` resolves quietly. Runs ON `opsQueue`.
    private func legacyCredentialedSignIn(
        _ credential: SendoraCloudCredential,
        link: Bool,
        policy: CredentialCollisionPolicy?,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        if let refusal = withheldRefusal() { completion(.failure(refusal)); return }
        if let unsettled = settleUnknownIfNeeded() { completion(.failure(unsettled)); return }
        let st = status()
        if link, st == .anonymous || st == .identified, let request = linkRequest(for: credential) {
            switch performLink(path: request.path, body: request.body, emit: .legacySignature) {
            case .success(.done(let user, _, _)):
                completion(.success(user))
            case .success(.credentialInUse(_, _, let message)):
                if policy == .adopt {
                    // The consented switch + hold, bound to the SAME credential
                    // (fresh — the same call). INV-14: the only path from a refused
                    // link to a sign-in.
                    let signIn = signInRequest(for: credential)
                    completion(mapSwitch(performSwitch(path: signIn.path, body: signIn.body)))
                } else {
                    completion(.failure(.credentialInUse(message)))
                }
            case .success(.recentAuthRequired(let message)):
                completion(.failure(recentAuthError(message)))
            case .failure(let error):
                completion(.failure(error))
            }
            return
        }
        let signIn = signInRequest(for: credential)
        completion(mapSwitch(performSwitch(path: signIn.path, body: signIn.body)))
    }

    // MARK: - Typed verbs (§3.5 `signInWith(credential)` / `link(credential)`)

    /// A plain sign-in (switch) with a typed credential. From a guest the guest
    /// is HELD (`previous.held == true`); from an identified account the previous
    /// session is revoked (`previous.isAnonymous == false` ⇒ reset local save
    /// state). `.mfaRequired` carries a `verify(code:)` method.
    public func signIn(
        with credential: SendoraCloudCredential,
        completion: @escaping (Result<SendoraCloudSignInResult, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            let request = self.signInRequest(for: credential)
            switch self.performSwitch(path: request.path, body: request.body) {
            case .success(.done(let user, let previous, let reactivated)):
                completion(.success(.done(user: user, previous: previous, reactivated: reactivated)))
            case .success(.mfaRequired(let challengeToken, let userId)):
                let challenge = SendoraCloudMfaChallenge(challengeToken: challengeToken, userId: userId) { [weak self] code, cb in
                    guard let self = self else { cb(.failure(.unknown("SDK deallocated"))); return }
                    self.signIn(with: .mfa(challengeToken: challengeToken, code: code), completion: cb)
                }
                completion(.success(.mfaRequired(challenge)))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }

    /// Attach a credential to the CURRENT account (the only upgrade, INV-4):
    /// `anonymous` → promoted in place (same `sub`, `upgraded: true`);
    /// `identified` → attached (`upgraded: false`) or a typed refusal with nothing
    /// mutated; `alreadyLinked` is a quiet 200 (no event). `signedOut` → a plain
    /// sign-in (nothing to attach to). Emits `.userUpdated(cause: .link)`, never
    /// `.signedIn`.
    public func link(
        _ credential: SendoraCloudCredential,
        completion: @escaping (Result<SendoraCloudLinkResult, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            if let refusal = self.withheldRefusal() { completion(.failure(refusal)); return }
            if let unsettled = self.settleUnknownIfNeeded() { completion(.failure(unsettled)); return }
            let boundAt = Date()
            switch self.status() {
            case .signedOut:
                let request = self.signInRequest(for: credential)
                switch self.performSwitch(path: request.path, body: request.body) {
                case .success(.done(let user, _, _)): completion(.success(.done(user: user, upgraded: false, alreadyLinked: false)))
                case .success(.mfaRequired): completion(.failure(.unknown("MFA required — use signIn(with:)")))
                case .failure(let error): completion(.failure(error))
                }
            case .anonymous, .identified:
                guard let request = self.linkRequest(for: credential) else {
                    completion(.failure(.rejected(code: "UNSUPPORTED_LINK_CREDENTIAL", message: "A \(credential.kind) credential cannot be linked; use signIn(with:)", status: 0, retryAfterSeconds: nil)))
                    return
                }
                switch self.performLink(path: request.path, body: request.body, emit: .linkMethod) {
                case .success(.done(let user, let upgraded, let alreadyLinked)):
                    completion(.success(.done(user: user, upgraded: upgraded, alreadyLinked: alreadyLinked)))
                case .success(.credentialInUse(let provider, let collision, let message)):
                    let context = SendoraCloudCredentialInUse(provider: provider, collision: collision, message: message,
                                                              credential: credential, boundAt: boundAt) { [weak self] cred, cb in
                        guard let self = self else { cb(.failure(.unknown("SDK deallocated"))); return }
                        self.signIn(with: cred, completion: cb)
                    }
                    completion(.success(.credentialInUse(context)))
                case .success(.recentAuthRequired):
                    completion(.success(.recentAuthRequired))
                case .failure(let error):
                    completion(.failure(error))
                }
            default:
                completion(.failure(.network("Session state did not settle; retry")))
            }
        }
    }

    // MARK: - Identity linking (ADR-030) — attach a SECOND credential to the current account

    /// Link email + password to the current account (sub preserved).
    public func linkEmailPassword(
        email: String,
        password: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        linkLegacyMethod(.password(email: email, password: password), completion: completion)
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
        linkLegacyMethod(.social(provider: provider, code: code, idToken: idToken, redirectUri: redirectURI), completion: completion)
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

    /// Link an Apple Game Center identity to the current account (same inputs as
    /// `signInWithGameCenter`).
    public func linkGameCenter(
        publicKeyURL: String,
        signature: String,
        salt: String,
        timestamp: Int,
        teamPlayerID: String,
        bundleID: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        linkLegacyMethod(.gameCenter(publicKeyURL: publicKeyURL, signature: signature, salt: salt, timestamp: UInt64(max(0, timestamp)),
                                     teamPlayerID: teamPlayerID, bundleID: bundleID), completion: completion)
    }

    /// `link*()`: `/me/link/*` from `anonymous` (promotion, `userUpdated`) or
    /// `identified` (attach / typed refusal); `.unauthorized` when signed out.
    private func linkLegacyMethod(
        _ credential: SendoraCloudCredential,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            if let refusal = self.withheldRefusal() { completion(.failure(refusal)); return }
            if let unsettled = self.settleUnknownIfNeeded() { completion(.failure(unsettled)); return }
            switch self.status() {
            case .anonymous, .identified:
                guard let request = self.linkRequest(for: credential) else {
                    completion(.failure(.unknown("This credential cannot be linked")))
                    return
                }
                switch self.performLink(path: request.path, body: request.body, emit: .linkMethod) {
                case .success(.done(let user, _, _)): completion(.success(user))
                case .success(.credentialInUse(_, _, let message)): completion(.failure(.credentialInUse(message)))
                case .success(.recentAuthRequired(let message)): completion(.failure(self.recentAuthError(message)))
                case .failure(let error): completion(.failure(error))
                }
            default:
                completion(.failure(.unauthorized("Sign in before linking a credential")))
            }
        }
    }

    // MARK: - Held guests (§3.5)

    /// Every held guest, newest first. Best-effort: a guest may be dead
    /// server-side until its token is presented. Never exposes tokens.
    public func heldGuests() -> [SendoraCloudHeldGuest] {
        return heldSlotsNewestFirst().map {
            SendoraCloudHeldGuest(userId: $0.slot.userId, heldAt: $0.slot.heldAt, autoRestore: $0.slot.autoRestore, project: $0.slot.project)
        }
    }

    /// The newest held guest, or `nil`.
    public func heldGuest() -> SendoraCloudHeldGuest? {
        return heldGuests().first
    }

    /// Fold a held guest INTO the current identified account (`POST /merge`):
    /// reassigns its events / profiles / push tokens and DELETES the guest row.
    /// OPTIONAL and irreversible — an app whose backend does not act on
    /// `auth.user_merged` MUST NOT call it. `id` may be omitted only when exactly
    /// one guest is held. Emits `.userUpdated(cause: .merge)` then
    /// `.guestReleased(.claimed)`.
    public func claimHeldGuest(id: String? = nil, completion: @escaping (Result<SendoraCloudClaimResult, SendoraCloudAuthError>) -> Void) {
        opsQueue.async {
            if let refusal = self.withheldRefusal() { completion(.failure(refusal)); return }
            // claim.identified_only: CLAIM is not queued in `unknown` (INV-5 names
            // MINT / SIGN_IN / LINK / RESTORE) — any non-identified state rejects
            // with no network and nothing mutated.
            guard self.status() == .identified else {
                completion(.failure(.unauthorized("claimHeldGuest() requires an identified session")))
                return
            }
            switch self.resolveSlotIndex(id: id) {
            case .failure(let error): completion(.failure(error))
            case .success(let index): completion(self.performClaim(index: index))
            }
        }
    }

    /// Sign back in AS the held guest, without merging. From `identified` the
    /// current session is revoked; from `anonymous` the current guest is HELD
    /// first. Rejects `.heldGuestProjectMismatch` client-side when the slot's
    /// project disagrees, `.heldGuestGone` when the server says the guest is
    /// unavailable (slot released), `.restoreFailed` (slot kept) when the verdict
    /// does not prove it gone. Emits `.signedIn` (cause `.restore` ⇒ re-register
    /// push) then `.guestReleased(.restored)`.
    public func restoreHeldGuest(id: String? = nil, completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void) {
        opsQueue.async {
            if let refusal = self.withheldRefusal() { completion(.failure(refusal)); return }
            if let unsettled = self.settleUnknownIfNeeded() { completion(.failure(unsettled)); return }
            switch self.resolveSlotIndex(id: id) {
            case .failure(let error):
                completion(.failure(error))
            case .success(let index):
                let userId = self.slotAt(index)?.userId ?? (id ?? "")
                switch self.performRestoreCore(index: index) {
                case .installed(let user): completion(.success(user))
                case .dead(let endReason): completion(.failure(.heldGuestGone(userId: userId, endReason: endReason)))
                case .projectMismatch(let error), .keptRetryable(let error), .failed(let error): completion(.failure(error))
                }
            }
        }
    }

    /// Delete a held guest for good (`POST /guest/discard` — a REAL server
    /// delete, `auth.user_deleted { reason: "guest_discarded" }`). The app is the
    /// requester; the SDK never calls this on its own. Emits `.guestReleased(.discarded)`.
    public func discardHeldGuest(id: String? = nil, completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void) {
        opsQueue.async {
            if let refusal = self.withheldRefusal() { completion(.failure(refusal)); return }
            switch self.resolveSlotIndex(id: id) {
            case .failure(let error): completion(.failure(error))
            case .success(let index): completion(self.performDiscard(index: index))
            }
        }
    }

    /// DEPRECATED alias of `claimHeldGuest(id:)`: a token that matches a held slot
    /// (its current or at-hold refresh token) claims THAT guest — a DESTRUCTIVE
    /// merge; any other token is sent to `POST /merge` raw. Requires an
    /// identified session.
    public func merge(anonRefreshToken: String, completion: @escaping (Result<SendoraCloudClaimResult, SendoraCloudAuthError>) -> Void) {
        opsQueue.async {
            if let refusal = self.withheldRefusal() { completion(.failure(refusal)); return }
            let (previous, cas) = self.snapshotForAttempt()
            guard let prev = previous, !prev.user.isAnonymous else {
                completion(.failure(.unauthorized("merge() requires an identified session")))
                return
            }
            if let index = self.heldSlotsNewestFirst().first(where: { $0.slot.refreshToken == anonRefreshToken || $0.slot.tokenAtHold == anonRefreshToken })?.index {
                completion(self.performClaim(index: index))
                return
            }
            self.awaitRefreshInflight()
            let rich = self.requestSync(method: "POST", path: "/auth-service/merge",
                                        body: ["anonymousRefreshToken": anonRefreshToken, "targetRefreshToken": prev.refreshToken])
            if let err = self.parseError(rich) { completion(.failure(err)); return }
            guard let tokens = self.parseTokens(rich.body) else { completion(.failure(.unknown("Malformed merge response"))); return }
            let data = (rich.body?["data"] as? [String: Any]) ?? [:]
            let record = AuthSessionRecord(user: prev.user, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken,
                                           accessExpiresAt: self.nowMs() + Int64(tokens.expiresIn) * 1000,
                                           sid: jwtStringClaim(tokens.accessToken, "sid") ?? prev.sid, heldReportPending: prev.heldReportPending)
            switch self.commitInstall(record: record, reason: .claim, expectSid: cas) {
            case .installed:
                self.emitAuthState(.userUpdated(user: prev.user, cause: .merge))
                let int: (String) -> Int = { key in (data[key] as? NSNumber)?.intValue ?? 0 }
                completion(.success(SendoraCloudClaimResult(user: prev.user, stats: SendoraCloudMergeStats(
                    mergedUserId: data["mergedUserId"] as? String ?? prev.user.id,
                    deletedAnonymousId: data["deletedAnonymousId"] as? String ?? "",
                    eventsReassigned: int("eventsReassigned"), profilesReassigned: int("profilesReassigned"),
                    profilesDropped: int("profilesDropped"), entitiesReassigned: int("entitiesReassigned"),
                    entitiesDropped: int("entitiesDropped"), pushTokensReassigned: int("pushTokensReassigned")
                ))))
            default:
                self.fireAndForgetRevoke(tokens.refreshToken)
                completion(.failure(.unknown("Merge result dropped: the session changed while the request was in flight")))
            }
        }
    }

    // MARK: - Withheld (§3.2, opt-in via `expectedProjectId`)

    /// Why the stored session is withheld, or `nil`. Never exposes tokens.
    public func withheld() -> SendoraCloudWithheldInfo? {
        lock.lock(); defer { lock.unlock() }
        return withheldState?.info
    }

    /// Resolve `withheld`: clear exactly the current-session keys, fire-and-forget
    /// `/token/revoke` (like `signOut()`), KEEP held slots, the event queue and the
    /// analytics id. LOCAL ONLY — never a server delete. `false` when not withheld.
    public func discardWithheld(completion: @escaping (Bool) -> Void) {
        opsQueue.async {
            guard let refresh = self.commitDiscardWithheld() else { completion(false); return }
            self.fireAndForgetRevoke(refresh)
            completion(true)
        }
    }

    // MARK: - signOut / deleteAccount / reset

    /// Local-first (the one deliberate exception to proposal-then-CAS): the user
    /// is signed out on device even if the revoke request hangs. KEEPS held
    /// guests. In `withheld` this is `discardWithheld()`.
    public func signOut(completion: @escaping () -> Void) {
        opsQueue.async {
            if let refresh = self.commitDiscardWithheld() {
                self.fireAndForgetRevoke(refresh)
                completion()
                return
            }
            let refresh = self.getRefreshToken()
            guard self.commitClear(reason: .user), let token = refresh else {
                completion()
                return
            }
            self.client.post(path: "/auth-service/token/revoke", body: ["refreshToken": token]) { _ in completion() }
        }
    }

    /// The machine's RESET row (`reset.keeps_held`): the SIGN_OUT row, plus —
    /// ONLY with `includeHeldGuests` — every slot released locally
    /// (`.guestReleased(.reset)`), with NO server delete. Replayed by the
    /// conformance suite. ⚠ It has NO public entry on iOS: `SendoraCloud.reset()`
    /// never touched the auth session (5.3.0 and earlier), and the lockstep
    /// ruling keeps it that way in a MINOR — see `SendoraCloud.reset()`.
    internal func resetFromParent(includeHeldGuests: Bool, completion: @escaping () -> Void) {
        opsQueue.async {
            if let refresh = self.commitDiscardWithheld() {
                self.fireAndForgetRevoke(refresh)
            } else {
                let refresh = self.getRefreshToken()
                if self.commitClear(reason: .user), let token = refresh { self.fireAndForgetRevoke(token) }
            }
            if includeHeldGuests {
                for i in 0..<Self.heldGuestSlots {
                    if let released = self.commitRelease(index: i) {
                        self.emitAuthState(.guestReleased(userId: released.userId, reason: .reset, endReason: nil))
                    }
                }
            }
            completion()
        }
    }

    /// Outcome of `deleteAccount`. `status` is `"purged"` (hard-deleted now,
    /// grace = 0) or `"pending"` (deactivated + sessions revoked now, hard
    /// delete scheduled at `scheduledPurgeAt`; cancellable by signing back in).
    /// 5.4.0: `heldGuests` = guests still held on this device afterwards (they
    /// SURVIVE on device and server unless `alsoDiscardHeldGuests`), and
    /// `heldGuestsDiscardFailed` names the ones a discard could not reach.
    public struct AccountDeletionResult {
        public let status: String
        public let scheduledPurgeAt: String?
        public let graceDays: Int
        public let heldGuests: Int
        public let heldGuestsDiscardFailed: [String]
    }

    /// Delete the signed-in user's account (App Store Guideline 5.1.1(v)).
    /// Resolves a FRESH access token first (a stale token would strand the user
    /// with an undeleted account). On 2xx: local identity cleared, the event queue
    /// dropped, held guests KEPT but never auto-restored again
    /// (`restoreHeldGuest(id:)` explicit only); `alsoDiscardHeldGuests: true` is
    /// the player's explicit ask to `/guest/discard` each one afterwards.
    public func deleteAccount(completion: @escaping (Result<AccountDeletionResult, Error>) -> Void) {
        deleteAccount(alsoDiscardHeldGuests: false, completion: completion)
    }

    /// `deleteAccount(completion:)` plus the explicit ask to discard every held
    /// guest after the 2xx (failures reported in `heldGuestsDiscardFailed`, the
    /// slots kept). A separate overload, not a defaulted parameter, so the
    /// pre-5.4.0 declaration survives verbatim (unapplied references included).
    public func deleteAccount(alsoDiscardHeldGuests: Bool, completion: @escaping (Result<AccountDeletionResult, Error>) -> Void) {
        opsQueue.async {
            if let refusal = self.withheldRefusal() { completion(.failure(refusal)); return }
            if let unsettled = self.settleUnknownIfNeeded() { completion(.failure(unsettled)); return }
            guard let token = self.bearerTokenOnQueue() else {
                completion(.failure(SendoraCloudAuthError.unauthorized("deleteAccount requires a signed-in user")))
                return
            }
            let rich = self.requestSync(method: "DELETE", path: "/auth-service/me", body: nil, headers: ["Authorization": "Bearer \(token)"])
            if rich.statusCode == 0 {
                completion(.failure(SendoraCloudAuthError.network("deleteAccount failed (network error)")))
                return
            }
            if let error = rich.body?["error"] as? [String: Any], !(200..<300).contains(rich.statusCode) || (rich.body?["success"] as? Bool) == false {
                let msg = (error["message"] as? String) ?? "deleteAccount failed"
                completion(.failure(SendoraCloudAuth.asAuthError(
                    code: (error["code"] as? String) ?? "",
                    message: msg,
                    status: rich.statusCode,
                    retryAfterSeconds: SendoraCloudAuth.readRetryAfterSeconds(error)
                )))
                return
            }
            // Account is gone / deactivated server-side — clear local identity,
            // keep the held guests, suppress their auto-restore (test 9).
            self.commitClear(reason: .accountDeleted, suppressHeldAutoRestore: true)
            var failed: [String] = []
            if alsoDiscardHeldGuests {
                for held in self.heldSlotsNewestFirst() {
                    if case .failure = self.performDiscard(index: held.index) { failed.append(held.slot.userId) }
                }
            }
            let data = rich.body?["data"] as? [String: Any]
            completion(.success(AccountDeletionResult(
                status: (data?["status"] as? String) ?? "pending",
                scheduledPurgeAt: data?["scheduledPurgeAt"] as? String,
                graceDays: (data?["graceDays"] as? Int) ?? 0,
                heldGuests: self.heldCount(),
                heldGuestsDiscardFailed: failed
            )))
        }
    }
}
