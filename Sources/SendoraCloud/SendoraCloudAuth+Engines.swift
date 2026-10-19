import Foundation

// ADR-033 §3.3 — the attempt engines: one per event family (SIGN-IN / LINK /
// MINT / RESTORE / CLAIM / DISCARD). Each runs ON `opsQueue` (one identity
// attempt at a time), awaits any in-flight refresh at start, performs the
// network call synchronously, and hands the RESULT to the commit funnel
// (SendoraCloudAuth+Commit.swift), which applies it only under the sid-CAS and
// the ProjectGuard. Nothing in here assigns state or touches the Keychain.

extension SendoraCloudAuth {
    internal enum SwitchOutcome {
        case done(user: SendoraCloudAuthUser, previous: SendoraCloudPreviousSession?, reactivated: Bool)
        case mfaRequired(challengeToken: String, userId: String)
    }

    internal enum LinkEmitMode {
        /// `signInWith*(link:)`, `loginSocial(link:)`, `signUp` — keep the 1.30–1.40
        /// `signedIn` on a same-`sub` promotion (ADR-023, §8-Q18).
        case legacySignature
        /// `link*()` / `link(_:)` — `userUpdated(cause: .link)`, never `signedIn`.
        case linkMethod
    }

    internal enum LinkOutcome {
        case done(user: SendoraCloudAuthUser, upgraded: Bool, alreadyLinked: Bool)
        case credentialInUse(provider: String, collision: SendoraCloudLinkCollision, message: String)
        case recentAuthRequired(message: String)
    }

    internal enum HeldRefreshResult {
        case rotated(tokens: SendoraCloudAuthTokens, user: SendoraCloudAuthUser?, response: [String: Any]?)
        case dead(SendoraCloudRefreshEndReason?)
        case transient(SendoraCloudAuthError)
    }

    internal enum RestoreResult {
        case installed(SendoraCloudAuthUser)
        /// Released with `guestReleased(.dead)`; the caller moves to the next slot or mints.
        case dead(SendoraCloudRefreshEndReason?)
        /// Client-side or response-side project mismatch; slot KEPT (now ineligible).
        case projectMismatch(SendoraCloudAuthError)
        /// `reuse` / absent endReason: slot KEPT, retryable.
        case keptRetryable(SendoraCloudAuthError)
        case failed(SendoraCloudAuthError)
    }

    internal func nowMs() -> Int64 {
        if let clock = machineConfig.clock { return clock() }
        return Int64(Date().timeIntervalSince1970 * 1000)
    }

    internal func snapshotForAttempt() -> (previous: AuthSessionRecord?, cas: IdentityCAS) {
        lock.lock(); defer { lock.unlock() }
        return (current, IdentityCAS(sid: current?.sid))
    }

    internal func slotAt(_ index: Int) -> HeldSlotRecord? {
        lock.lock(); defer { lock.unlock() }
        guard slots.indices.contains(index) else { return nil }
        return slots[index]
    }

    internal func heldCount() -> Int {
        lock.lock(); defer { lock.unlock() }
        return heldCountLocked()
    }

    /// INV-5: in `unknown` every session-installing event QUEUES until the
    /// gap-fill refresh answers — never executes the network call in `unknown`.
    /// Offline the state cannot settle, so the op fails with a retryable
    /// `.network` instead of hanging its completion forever (the iOS reading).
    internal func settleUnknownIfNeeded() -> SendoraCloudAuthError? {
        guard status() == .unknown else { return nil }
        _ = performRefreshSync()
        guard status() == .unknown else { return nil }
        return .network("Session state is unknown: the stored session could not be refreshed yet. Retry when online.")
    }

    /// `id` may be omitted ONLY when exactly one guest is held (§3.5).
    internal func resolveSlotIndex(id: String?) -> Result<Int, SendoraCloudAuthError> {
        let held = heldSlotsNewestFirst()
        if let id = id {
            guard let match = held.first(where: { $0.slot.userId == id }) else {
                return .failure(.heldGuestGone(userId: id, endReason: nil))
            }
            return .success(match.index)
        }
        if held.isEmpty { return .failure(.heldGuestGone(userId: "", endReason: nil)) }
        if held.count > 1 { return .failure(.ambiguousHeldGuest(held: held.count)) }
        return .success(held[0].index)
    }

    private func holdRecord(for prev: AuthSessionRecord) -> HeldSlotRecord {
        return HeldSlotRecord(
            userId: prev.user.id,
            sid: prev.sid,
            refreshToken: prev.refreshToken,
            tokenAtHold: prev.refreshToken,
            heldAt: nowMs(),
            project: jwtProjectClaimForSlot(prev.accessToken),
            autoRestore: true
        )
    }

    private func sessionRecord(user: SendoraCloudAuthUser, tokens: SendoraCloudAuthTokens, fallbackSid: String?, pending: [String]) -> AuthSessionRecord {
        return AuthSessionRecord(
            user: user,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            accessExpiresAt: nowMs() + Int64(tokens.expiresIn) * 1000,
            sid: jwtStringClaim(tokens.accessToken, "sid") ?? fallbackSid,
            heldReportPending: pending
        )
    }

    // MARK: - SIGN-IN / SWITCH (§3.3 row 18 + 19)

    /// A credentialed sign-in. The request carries NO guest hint (INV-3). On
    /// success the previous guest is HELD, a previous identified session is
    /// revoked (Q12), the new session is installed under the sid-CAS, and the
    /// emission is `guestHeld` (if held) then ONE `signedIn(cause: .signIn)`.
    internal func performSwitch(path: String, body: [String: Any]) -> Result<SwitchOutcome, SendoraCloudAuthError> {
        if let refusal = withheldRefusal() { return .failure(refusal) }
        if let unsettled = settleUnknownIfNeeded() { return .failure(unsettled) }
        awaitRefreshInflight()
        let (previous, cas) = snapshotForAttempt()
        // 5.6.0 (F67 / backend F23): EVERY `/login` body is built here, so this is
        // the one place the device's `knownDeviceToken` for that address is sent.
        var body = body
        let deviceEmail = knownDeviceEmail(path: path, body: body)
        if path == Self.passwordLoginPath, let email = deviceEmail,
           let token = storage.knownDeviceToken(forEmail: email) {
            body["knownDeviceToken"] = token
        }
        let rich = requestSync(method: "POST", path: path, body: body)
        if let err = parseError(rich) { return .failure(err) }
        let data = rich.body?["data"] as? [String: Any]
        // Filed under the address it was minted for. An `/mfa/challenge` whose
        // `/login` ran in another process falls back to the account's own email.
        var tokenEmail = deviceEmail
        if tokenEmail == nil, path == Self.mfaChallengePath {
            tokenEmail = (data?["user"] as? [String: Any])?["email"] as? String
        }
        if let email = tokenEmail, !email.isEmpty,
           let token = data?["knownDeviceToken"] as? String, !token.isEmpty {
            commitKnownDeviceToken(email: email, token: token)
        }
        if let data = data,
           data["mfaRequired"] as? Bool == true,
           let challengeToken = data["mfaChallengeToken"] as? String {
            if path == Self.passwordLoginPath, let email = deviceEmail { rememberMfaEmail(challengeToken: challengeToken, email: email) }
            let userId = ((data["user"] as? [String: Any])?["id"] as? String) ?? ""
            return .success(.mfaRequired(challengeToken: challengeToken, userId: userId))
        }
        if path == Self.mfaChallengePath, let challengeToken = body["challengeToken"] as? String {
            forgetMfaEmail(challengeToken: challengeToken)
        }
        return installSwitchResponse(rich.body, previous: previous, cas: cas)
    }

    internal static let passwordLoginPath = "/auth-service/login"
    internal static let mfaChallengePath = "/auth-service/mfa/challenge"

    /// The address a `knownDeviceToken` belongs to: the `/login` body's email, or
    /// the email of the `/login` that issued this `/mfa/challenge` token.
    private func knownDeviceEmail(path: String, body: [String: Any]) -> String? {
        if path == Self.passwordLoginPath { return (body["email"] as? String).flatMap { $0.isEmpty ? nil : $0 } }
        if path == Self.mfaChallengePath, let challengeToken = body["challengeToken"] as? String {
            lock.lock(); defer { lock.unlock() }
            return pendingMfaEmails.first(where: { $0.challengeToken == challengeToken })?.email
        }
        return nil
    }

    private func rememberMfaEmail(challengeToken: String, email: String) {
        lock.lock(); defer { lock.unlock() }
        pendingMfaEmails.removeAll { $0.challengeToken == challengeToken }
        pendingMfaEmails.append((challengeToken, email))
        if pendingMfaEmails.count > 8 { pendingMfaEmails.removeFirst(pendingMfaEmails.count - 8) }
    }

    private func forgetMfaEmail(challengeToken: String) {
        lock.lock(); defer { lock.unlock() }
        pendingMfaEmails.removeAll { $0.challengeToken == challengeToken }
    }

    /// Apply a sign-in response: validate → await refresh at commit → sid-CAS →
    /// ProjectGuard → HOLD the previous guest (slot FIRST) → install → emit.
    /// Shared with the passkey and SSO paths (`completeExternalSignIn`).
    internal func installSwitchResponse(_ response: [String: Any]?, previous: AuthSessionRecord?, cas: IdentityCAS) -> Result<SwitchOutcome, SendoraCloudAuthError> {
        guard let user = parseSuccess(response), let tokens = parseTokens(response) else {
            return .failure(.unknown("Malformed response"))
        }
        awaitRefreshInflight()
        let (currentNow, _) = snapshotForAttempt()
        // Identity CAS: the session this result was derived from must still be
        // current, else DROP and revoke so server session B is not left live.
        guard currentNow?.sid == cas.sid else {
            fireAndForgetRevoke(tokens.refreshToken)
            return .failure(.unknown("Sign-in result dropped: the session changed while the request was in flight"))
        }
        // ProjectGuard on a FRESH response, before anything is held or written.
        if projectVerdict(expectedProjectId: machineConfig.expectedProjectId, accessJwt: tokens.accessToken) == .mismatch {
            fireAndForgetRevoke(tokens.refreshToken)
            return .failure(.projectMismatch(expectedProjectId: machineConfig.expectedProjectId ?? "", actualProjectId: jwtProjectClaimForSlot(tokens.accessToken)))
        }

        let sameSub = currentNow?.user.id == user.id
        var pending = currentNow?.heldReportPending ?? []
        var heldIndex: Int?
        var heldRefreshToken: String?
        var previousSummary: SendoraCloudPreviousSession?
        if let prev = currentNow {
            if !sameSub && prev.user.isAnonymous {
                // HOLD the guest with its post-refresh tokens and project claim.
                let slot = holdRecord(for: prev)
                guard let idx = commitHold(slot) else {
                    fireAndForgetRevoke(tokens.refreshToken)
                    return .failure(.heldGuestLimit(held: heldCount(), limit: Self.heldGuestSlots))
                }
                heldIndex = idx
                heldRefreshToken = slot.refreshToken
                pending.append(prev.user.id)
                previousSummary = SendoraCloudPreviousSession(userId: prev.user.id, isAnonymous: true, held: true)
            } else {
                if !sameSub { fireAndForgetRevoke(prev.refreshToken) }
                previousSummary = SendoraCloudPreviousSession(userId: prev.user.id, isAnonymous: prev.user.isAnonymous, held: false)
            }
        }

        let record = sessionRecord(user: user, tokens: tokens, fallbackSid: nil, pending: pending)
        switch commitInstall(record: record, reason: .signIn, expectSid: cas) {
        case .installed(let userChanged):
            if let prev = currentNow, let heldToken = heldRefreshToken {
                emitAuthState(.guestHeld(userId: prev.user.id, count: heldCount()))
                reportGuestHeld(userId: prev.user.id, refreshToken: heldToken)
            }
            if !sameSub {
                setLastSignedInCause(.signIn)
                emitAuthState(.signedIn(user: user))
            } else if userChanged {
                emitAuthState(.userUpdated(user: user, cause: .refresh))
            }
            fireLifecycleSignals(from: response, identifiedUserId: user.id)
            let reactivated = ((response?["data"] as? [String: Any])?["reactivatedFromDeletion"] as? Bool) == true
            return .success(.done(user: user, previous: previousSummary, reactivated: reactivated))
        case .projectMismatch(let actual):
            if let idx = heldIndex { _ = commitRelease(index: idx) }
            fireAndForgetRevoke(tokens.refreshToken)
            return .failure(.projectMismatch(expectedProjectId: machineConfig.expectedProjectId ?? "", actualProjectId: actual))
        default:
            if let idx = heldIndex { _ = commitRelease(index: idx) }
            fireAndForgetRevoke(tokens.refreshToken)
            return .failure(.unknown("Sign-in result dropped: the session changed while the request was in flight"))
        }
    }

    /// The identity CAS of an attempt whose network leg runs OUTSIDE `opsQueue`
    /// (the passkey sheet, the OIDC browser). Taken when the ceremony STARTS, so
    /// a result that lands after a `signOut()` / another sign-in made during the
    /// sheet is DROPPED (and its session revoked) instead of installed (§3.3
    /// row 19, INV-2) — the same guarantee `signIn` gets from its in-queue
    /// snapshot.
    internal func externalAttemptStart() -> IdentityCAS {
        return snapshotForAttempt().cas
    }

    /// Passkey / SSO: the response arrived outside `opsQueue`; run the SIGN-IN
    /// commit on it (hold the guest, CAS, ProjectGuard) exactly like `signIn`.
    /// `startedFrom` is the CAS taken by `externalAttemptStart()` when the
    /// ceremony began; `nil` (a standalone callback with no known start, e.g.
    /// a cold-start deep link) snapshots now.
    internal func completeExternalSignIn(
        response: [String: Any]?,
        startedFrom: IdentityCAS? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            if let refusal = self.withheldRefusal() { completion(.failure(refusal)); return }
            if let unsettled = self.settleUnknownIfNeeded() { completion(.failure(unsettled)); return }
            self.awaitRefreshInflight()
            let (previous, snapshot) = self.snapshotForAttempt()
            let cas = startedFrom ?? snapshot
            switch self.installSwitchResponse(response, previous: previous, cas: cas) {
            case .success(.done(let user, _, _)): completion(.success(user))
            case .success(.mfaRequired): completion(.failure(.unknown("MFA required")))
            case .failure(let error): completion(.failure(error))
            }
        }
    }

    // MARK: - LINK (§3.3 rows 15 + 16)

    /// `POST /me/link/*` on the current Bearer. Precondition: status is
    /// `anonymous` or `identified` (the caller routes `signedOut` to a plain
    /// sign-in and settles `unknown` first). 409 / 403 are TYPED outcomes with
    /// nothing mutated; a promotion installs the rotated pair (same `sub`); an
    /// attach installs the user; `alreadyLinked` writes and emits nothing.
    internal func performLink(path: String, body: [String: Any], emit: LinkEmitMode) -> Result<LinkOutcome, SendoraCloudAuthError> {
        awaitRefreshInflight()
        guard let bearer = bearerTokenOnQueue() else {
            return .failure(.unauthorized("Sign in before linking a credential"))
        }
        let (previous, cas) = snapshotForAttempt()
        guard let prev = previous else { return .failure(.unauthorized("Sign in before linking a credential")) }
        let rich = requestSync(method: "POST", path: path, body: body, headers: ["Authorization": "Bearer \(bearer)"])

        let ok = (200..<300).contains(rich.statusCode) && (rich.body?["success"] as? Bool) == true
        if !ok {
            let error = rich.body?["error"] as? [String: Any]
            let code = rich.errorCode ?? (error?["code"] as? String) ?? ""
            let message = rich.errorMessage ?? (error?["message"] as? String) ?? "Link failed"
            if code == "CREDENTIAL_IN_USE" {
                let details = error?["details"] as? [String: Any]
                let fallbackProvider = (body["provider"] as? String) ?? (path.hasSuffix("/email") ? "password" : (path.hasSuffix("/game-center") ? "gamecenter" : "unknown"))
                let provider = (details?["provider"] as? String) ?? fallbackProvider
                let collision = SendoraCloudLinkCollision(rawValue: (details?["collision"] as? String) ?? "")
                    ?? (path.hasSuffix("/email") ? .email : .identity)
                return .success(.credentialInUse(provider: provider, collision: collision, message: message))
            }
            if code == "RECENT_AUTH_REQUIRED" {
                return .success(.recentAuthRequired(message: message))
            }
            return .failure(parseError(rich) ?? .unknown(message))
        }

        let data = (rich.body?["data"] as? [String: Any]) ?? [:]
        guard let user = parseSuccess(rich.body) else { return .failure(.unknown("Malformed link response")) }
        if data["upgraded"] as? Bool == true, let tokens = parseTokens(rich.body) {
            // A guest promotion: same sub, rotated pair (the old refresh token is
            // revoked server-side, so installing the pair is NOT optional).
            let record = sessionRecord(user: user, tokens: tokens, fallbackSid: prev.sid, pending: prev.heldReportPending)
            switch commitInstall(record: record, reason: .upgrade, expectSid: cas) {
            case .installed:
                switch emit {
                case .legacySignature:
                    setLastSignedInCause(.link)
                    emitAuthState(.signedIn(user: user))
                case .linkMethod:
                    emitAuthState(.userUpdated(user: user, cause: .link))
                }
                fireLifecycleSignals(from: rich.body, identifiedUserId: user.id)
                return .success(.done(user: user, upgraded: true, alreadyLinked: false))
            case .projectMismatch(let actual):
                fireAndForgetRevoke(tokens.refreshToken)
                return .failure(.projectMismatch(expectedProjectId: machineConfig.expectedProjectId ?? "", actualProjectId: actual))
            default:
                fireAndForgetRevoke(tokens.refreshToken)
                return .failure(.unknown("Link result dropped: the session changed while the request was in flight"))
            }
        }
        if data["alreadyLinked"] as? Bool == true {
            // Quiet 200: no event, no write, no revoke (B13).
            return .success(.done(user: user, upgraded: false, alreadyLinked: true))
        }
        guard commitUser(user, expectSid: cas) else {
            return .failure(.unknown("Link result dropped: the session changed while the request was in flight"))
        }
        emitAuthState(.userUpdated(user: user, cause: .link))
        return .success(.done(user: user, upgraded: false, alreadyLinked: false))
    }

    // MARK: - MINT (§3.3 rows 6–11)

    internal func performMint(name: String?, metadata: [String: Any]?, forceNew: Bool) -> Result<SendoraCloudAuthUser, SendoraCloudAuthError> {
        if let refusal = withheldRefusal() { return .failure(refusal) }
        if let unsettled = settleUnknownIfNeeded() { return .failure(unsettled) }
        awaitRefreshInflight()
        let (previous, cas) = snapshotForAttempt()

        // mint.noop_over_session: an existing session — anonymous OR identified
        // (5.3.0) — is returned as-is, no network.
        if let prev = previous, !forceNew { return .success(prev.user) }

        lock.lock()
        let t = tLocked()
        let held = heldCountLocked()
        lock.unlock()

        if forceNew {
            // mint.force_new_at_cap
            if t >= Self.heldGuestSlots { return .failure(.heldGuestLimit(held: held, limit: Self.heldGuestSlots)) }
            if let prev = previous, prev.user.isAnonymous {
                // mint.force_new_holds_guest: write the slot FIRST, then mint.
                let slot = holdRecord(for: prev)
                guard let idx = commitHold(slot) else { return .failure(.heldGuestLimit(held: held, limit: Self.heldGuestSlots)) }
                let result = mintFresh(name: name, metadata: metadata, cas: cas, pending: prev.heldReportPending + [prev.user.id])
                switch result {
                case .success(let user):
                    emitAuthState(.guestHeld(userId: prev.user.id, count: heldCount()))
                    reportGuestHeld(userId: prev.user.id, refreshToken: slot.refreshToken)
                    setLastSignedInCause(.mint)
                    emitAuthState(.signedIn(user: user))
                case .failure:
                    // The mint failed: the guest is still current, so the slot is a
                    // duplicate handle — roll the hold back silently.
                    _ = commitRelease(index: idx)
                }
                return result
            }
            if let prev = previous {
                let result = mintFresh(name: name, metadata: metadata, cas: cas, pending: prev.heldReportPending)
                if case .success(let user) = result {
                    fireAndForgetRevoke(prev.refreshToken) // identified → replaced: orthogonal hygiene (Q12)
                    setLastSignedInCause(.mint)
                    emitAuthState(.signedIn(user: user))
                }
                return result
            }
            let result = mintFresh(name: name, metadata: metadata, cas: cas, pending: [])
            if case .success(let user) = result {
                setLastSignedInCause(.mint)
                emitAuthState(.signedIn(user: user))
            }
            return result
        }

        // signedOut: auto-restore the newest ELIGIBLE held guest before minting.
        let eligible = heldSlotsNewestFirst().filter { isEligibleForAutoRestore($0.slot) }
        if eligible.isEmpty && t >= Self.heldGuestSlots {
            // mint.cap_no_eligible — the one boot corner that does not self-heal (§8-Q22).
            return .failure(.heldGuestLimit(held: held, limit: Self.heldGuestSlots))
        }
        if !eligible.isEmpty && (machineConfig.autoRestoreHeldGuest || t >= Self.heldGuestSlots) {
            for candidate in eligible {
                switch performRestoreCore(index: candidate.index) {
                case .installed(let user): return .success(user)
                case .dead: continue            // released {dead}; try the next-newest eligible
                case .projectMismatch: continue // claim recorded on the slot → now ineligible
                case .keptRetryable(let error), .failed(let error): return .failure(error) // transient → abort, state untouched
                }
            }
            // none left → fall through to mint.fresh IN THE SAME CALL
        }
        let result = mintFresh(name: name, metadata: metadata, cas: cas, pending: [])
        if case .success(let user) = result {
            setLastSignedInCause(.mint)
            emitAuthState(.signedIn(user: user))
        }
        return result
    }

    /// mint.fresh: `POST /anonymous` (+ `mintKey`, B10) → ProjectGuard on the
    /// RESPONSE → install. A fresh-mint mismatch rejects `PROJECT_MISMATCH`,
    /// revokes the minted refresh token and installs nothing (§8-Q14).
    private func mintFresh(name: String?, metadata: [String: Any]?, cas: IdentityCAS, pending: [String]) -> Result<SendoraCloudAuthUser, SendoraCloudAuthError> {
        var body: [String: Any] = [:]
        if let name = name { body["name"] = name }
        if let metadata = metadata { body["metadata"] = metadata }
        let mintKey = storage.pendingMintKey ?? Self.generateMintKey()
        commitMintKey(mintKey)
        body["mintKey"] = mintKey

        let rich = requestSync(method: "POST", path: "/auth-service/anonymous", body: body)
        if let err = parseError(rich) { return .failure(err) }
        guard let user = parseSuccess(rich.body), let tokens = parseTokens(rich.body) else {
            return .failure(.unknown("Malformed response"))
        }
        let record = sessionRecord(user: user, tokens: tokens, fallbackSid: nil, pending: pending)
        switch commitInstall(record: record, reason: .mint, expectSid: cas) {
        case .installed:
            commitMintKey(nil)
            fireLifecycleSignals(from: rich.body, identifiedUserId: user.id)
            return .success(user)
        case .projectMismatch(let actual):
            fireAndForgetRevoke(tokens.refreshToken)
            commitMintKey(nil) // a retry with the same key would return the same wrong-project guest
            return .failure(.projectMismatch(expectedProjectId: machineConfig.expectedProjectId ?? "", actualProjectId: actual))
        default:
            fireAndForgetRevoke(tokens.refreshToken)
            return .failure(.unknown("Mint result dropped: the session changed while the request was in flight"))
        }
    }

    /// 32 hex chars of randomness (B10 asks for 16–128).
    internal static func generateMintKey() -> String {
        return UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    }

    // MARK: - refreshHeld (§3.3 rows 22 + 25 for a held slot)

    /// Present a HELD token to `/token/refresh`. A rotation is persisted into
    /// THAT slot by token (CAS per slot) BEFORE the caller takes the next step;
    /// a dead verdict is returned with its `endReason` for the caller's release
    /// rule; anything else is transient and changes nothing.
    internal func refreshHeld(index: Int) -> HeldRefreshResult {
        guard let slot = slotAt(index) else { return .transient(.heldGuestGone(userId: "", endReason: nil)) }
        let sent = slot.refreshToken
        let rich = requestSync(method: "POST", path: "/auth-service/token/refresh", body: ["refreshToken": sent])
        if rich.statusCode == 0 { return .transient(.network("Network request failed")) }
        if !(200..<300).contains(rich.statusCode) {
            let error = rich.body?["error"] as? [String: Any]
            let code = rich.errorCode ?? (error?["code"] as? String) ?? ""
            if Self.isDeadRefreshError(code) { return .dead(Self.readEndReason(error)) }
            return .transient(parseError(rich) ?? .unknown("Refresh failed"))
        }
        let data = rich.body?["data"] as? [String: Any]
        let fields = (data?["tokens"] as? [String: Any]) ?? data
        guard let accessToken = fields?["accessToken"] as? String, !accessToken.isEmpty,
              let refreshToken = fields?["refreshToken"] as? String, !refreshToken.isEmpty,
              let expiresIn = fields?["expiresIn"] as? Int, expiresIn > 0 else {
            return .transient(.unknown("Malformed refresh response"))
        }
        let tokens = SendoraCloudAuthTokens(accessToken: accessToken, refreshToken: refreshToken, expiresIn: expiresIn,
                                            tokenType: fields?["tokenType"] as? String ?? "Bearer")
        // ⚠ IDENTITY TRIPWIRE (s58.360, parity RN 1.41.2 / web 3.24.2). The refresh
        // must come back for the held GUEST. Before the server fix `/token/refresh`
        // preferred the `sd_rt` cookie over the body, and a URLSession jar (ephemeral
        // keeps one in memory) held the signed-in ACCOUNT's cookie — so this 200 was
        // the account's, and committing it overwrote the guest's only token. Refuse
        // BEFORE the slot write: nothing written, nothing installed, slot kept.
        let answeredFor = parseSuccess(rich.body)?.id ?? (decodeJwtPayload(tokens.accessToken)?["sub"] as? String)
        if let who = answeredFor, !who.isEmpty, who != slot.userId {
            return .transient(.rejected(code: "HELD_GUEST_IDENTITY_MISMATCH",
                                        message: "The held guest's refresh was answered for a different account; nothing was changed",
                                        status: rich.statusCode, retryAfterSeconds: nil))
        }
        guard commitSlotRotation(index: index, expectRefresh: sent, newRefresh: tokens.refreshToken) else {
            return .transient(.unknown("Held slot changed while refreshing"))
        }
        return .rotated(tokens: tokens, user: parseSuccess(rich.body), response: rich.body)
    }

    // MARK: - RESTORE (§3.3 rows 30 + 31)

    /// Restore slot `index` as the current session. Client-side project check
    /// FIRST (no network); from `anonymous` the current guest is HELD first (slot
    /// written FIRST); `refreshHeld()` → ProjectGuard on the response → an
    /// identified current is revoked → install BEFORE the slot is removed.
    internal func performRestoreCore(index: Int) -> RestoreResult {
        guard let slot = slotAt(index) else { return .failed(.heldGuestGone(userId: "", endReason: nil)) }
        let expectedOrConfig = machineConfig.expectedProjectId ?? machineConfig.configProjectId
        if let project = slot.project, let expected = expectedOrConfig, project != expected {
            return .projectMismatch(.heldGuestProjectMismatch(userId: slot.userId, slotProject: project, expectedProjectId: expected))
        }
        awaitRefreshInflight()
        let (previous, cas) = snapshotForAttempt()

        var heldPreviousIndex: Int?
        var heldPreviousToken: String?
        if let prev = previous, prev.user.isAnonymous {
            let holdSlot = holdRecord(for: prev)
            guard let idx = commitHold(holdSlot) else {
                return .failed(.heldGuestLimit(held: heldCount(), limit: Self.heldGuestSlots))
            }
            heldPreviousIndex = idx
            heldPreviousToken = holdSlot.refreshToken
        }
        let rollbackHold: () -> Void = { [self] in
            if let i = heldPreviousIndex { _ = self.commitRelease(index: i) }
        }

        switch refreshHeld(index: index) {
        case .transient(let error):
            rollbackHold()
            return .failed(error)
        case .dead(let endReason):
            rollbackHold()
            if let reason = endReason, Self.releaseHeldOnEndReasons.contains(reason) {
                if let released = commitRelease(index: index) {
                    emitAuthState(.guestReleased(userId: released.userId, reason: .dead, endReason: reason))
                }
                return .dead(reason)
            }
            return .keptRetryable(.restoreFailed(userId: slot.userId, endReason: endReason))
        case .rotated(let tokens, let user, let response):
            if projectVerdict(expectedProjectId: machineConfig.expectedProjectId, accessJwt: tokens.accessToken) == .mismatch {
                rollbackHold()
                let actual = jwtProjectClaimForSlot(tokens.accessToken)
                commitSlotProject(index: index, project: actual)
                return .projectMismatch(.heldGuestProjectMismatch(userId: slot.userId, slotProject: actual, expectedProjectId: machineConfig.expectedProjectId ?? ""))
            }
            guard let user = user else {
                rollbackHold()
                return .failed(.unknown("Malformed refresh response (no user)"))
            }
            if let prev = previous, !prev.user.isAnonymous { fireAndForgetRevoke(prev.refreshToken) }
            var pending = previous?.heldReportPending ?? []
            if heldPreviousIndex != nil, let prev = previous { pending.append(prev.user.id) }
            pending.removeAll { $0 == slot.userId }
            let record = sessionRecord(user: user, tokens: tokens, fallbackSid: slot.sid, pending: pending)
            switch commitInstall(record: record, reason: .restore, expectSid: cas) {
            case .installed:
                _ = commitRelease(index: index) // AFTER the install — never zero handles
                if let prev = previous, let heldToken = heldPreviousToken {
                    emitAuthState(.guestHeld(userId: prev.user.id, count: heldCount()))
                    reportGuestHeld(userId: prev.user.id, refreshToken: heldToken)
                }
                // ONE order on every restore path (MINT auto-restore, restoreHeldGuest,
                // restore over a guest) — the shared fixture's: install first, so
                // `signedIn(cause: .restore)`, THEN `guestReleased(.restored)` as the
                // slot is released.
                setLastSignedInCause(.restore)
                emitAuthState(.signedIn(user: user))
                emitAuthState(.guestReleased(userId: user.id, reason: .restored, endReason: nil))
                fireLifecycleSignals(from: response, identifiedUserId: user.id)
                return .installed(user)
            default:
                rollbackHold()
                return .failed(.unknown("Restore result dropped: the session changed while the request was in flight"))
            }
        }
    }

    // MARK: - CLAIM (§3.3 row 29)

    /// (1) `refreshHeld()` — persist the rotated pair into the slot BEFORE step 2;
    /// (2) `POST /merge`; (3) install the rotated target pair, release the slot.
    internal func performClaim(index: Int) -> Result<SendoraCloudClaimResult, SendoraCloudAuthError> {
        awaitRefreshInflight()
        let (previous, cas) = snapshotForAttempt()
        guard let prev = previous, !prev.user.isAnonymous else {
            return .failure(.unauthorized("claimHeldGuest() requires an identified session"))
        }
        guard let slot = slotAt(index) else { return .failure(.heldGuestGone(userId: "", endReason: nil)) }

        switch refreshHeld(index: index) {
        case .transient(let error):
            return .failure(error)
        case .dead(let endReason):
            if let reason = endReason, Self.releaseHeldOnEndReasons.contains(reason) {
                if let released = commitRelease(index: index) {
                    emitAuthState(.guestReleased(userId: released.userId, reason: .dead, endReason: reason))
                }
                return .failure(.heldGuestGone(userId: slot.userId, endReason: reason))
            }
            return .failure(.restoreFailed(userId: slot.userId, endReason: endReason))
        case .rotated(let heldTokens, _, _):
            let targetRefresh = snapshotForAttempt().previous?.refreshToken ?? prev.refreshToken
            let rich = requestSync(method: "POST", path: "/auth-service/merge",
                                   body: ["anonymousRefreshToken": heldTokens.refreshToken, "targetRefreshToken": targetRefresh])
            if let err = parseError(rich) { return .failure(err) }
            guard let tokens = parseTokens(rich.body) else { return .failure(.unknown("Malformed merge response")) }
            let data = (rich.body?["data"] as? [String: Any]) ?? [:]
            let pending = prev.heldReportPending.filter { $0 != slot.userId }
            let record = sessionRecord(user: prev.user, tokens: tokens, fallbackSid: prev.sid, pending: pending)
            switch commitInstall(record: record, reason: .claim, expectSid: cas) {
            case .installed:
                if let released = commitRelease(index: index) {
                    emitAuthState(.userUpdated(user: prev.user, cause: .merge))
                    emitAuthState(.guestReleased(userId: released.userId, reason: .claimed, endReason: nil))
                }
                let int: (String) -> Int = { key in (data[key] as? NSNumber)?.intValue ?? 0 }
                let stats = SendoraCloudMergeStats(
                    mergedUserId: data["mergedUserId"] as? String ?? prev.user.id,
                    deletedAnonymousId: data["deletedAnonymousId"] as? String ?? slot.userId,
                    eventsReassigned: int("eventsReassigned"),
                    profilesReassigned: int("profilesReassigned"),
                    profilesDropped: int("profilesDropped"),
                    entitiesReassigned: int("entitiesReassigned"),
                    entitiesDropped: int("entitiesDropped"),
                    pushTokensReassigned: int("pushTokensReassigned")
                )
                return .success(SendoraCloudClaimResult(user: prev.user, stats: stats))
            case .projectMismatch(let actual):
                fireAndForgetRevoke(tokens.refreshToken)
                return .failure(.projectMismatch(expectedProjectId: machineConfig.expectedProjectId ?? "", actualProjectId: actual))
            default:
                fireAndForgetRevoke(tokens.refreshToken)
                return .failure(.unknown("Claim result dropped: the session changed while the request was in flight"))
            }
        }
    }

    // MARK: - DISCARD (§3.3 row 32)

    /// `POST /guest/discard { refreshToken: held }` — a REAL server delete (B5).
    /// 2xx or 404 releases the slot; a 5xx / network error keeps it (the guest is
    /// not gone).
    internal func performDiscard(index: Int) -> Result<Void, SendoraCloudAuthError> {
        guard let slot = slotAt(index) else { return .failure(.heldGuestGone(userId: "", endReason: nil)) }
        let rich = requestSync(method: "POST", path: "/auth-service/guest/discard", body: ["refreshToken": slot.refreshToken])
        if (200..<300).contains(rich.statusCode) || rich.statusCode == 404 {
            if let released = commitRelease(index: index) {
                emitAuthState(.guestReleased(userId: released.userId, reason: .discarded, endReason: nil))
            }
            return .success(())
        }
        return .failure(parseError(rich) ?? .unknown("Discard failed"))
    }

    // MARK: - Request builders for typed credentials (INV-3: no guest hint)

    internal static func socialBody(provider: String, code: String?, idToken: String?, redirectUri: String?, codeVerifier: String?,
                                    appleFirstName: String?, appleLastName: String?) -> [String: Any] {
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
        return body
    }

    internal static func gameCenterBody(publicKeyURL: String, signature: String, salt: String, timestamp: UInt64, teamPlayerID: String, bundleID: String) -> [String: Any] {
        return [
            "publicKeyUrl": publicKeyURL,
            "signature": signature,
            "salt": salt,
            "timestamp": timestamp,
            "teamPlayerId": teamPlayerID,
            "bundleId": bundleID,
        ]
    }

    /// The plain sign-in route for a credential (SIGN_IN row).
    internal func signInRequest(for credential: SendoraCloudCredential) -> (path: String, body: [String: Any]) {
        switch credential {
        case .password(let email, let password):
            return ("/auth-service/login", ["email": email, "password": password])
        case .social(let provider, let code, let idToken, let redirectUri, let codeVerifier, let first, let last):
            return ("/auth-service/login/social", Self.socialBody(provider: provider, code: code, idToken: idToken, redirectUri: redirectUri,
                                                                  codeVerifier: codeVerifier, appleFirstName: first, appleLastName: last))
        case .gameCenter(let url, let signature, let salt, let timestamp, let teamPlayerID, let bundleID):
            return ("/auth-service/login/game-center", Self.gameCenterBody(publicKeyURL: url, signature: signature, salt: salt, timestamp: timestamp,
                                                                           teamPlayerID: teamPlayerID, bundleID: bundleID))
        case .magicLink(let token):
            return ("/auth-service/magic-link/verify", ["token": token])
        case .emailOtp(let email, let code):
            return ("/auth-service/email-otp/verify", ["email": email, "code": code])
        case .passkey(let assertion):
            return ("/auth-service/passkeys/authenticate/finish", assertion)
        case .mfa(let challengeToken, let code):
            return ("/auth-service/mfa/challenge", ["challengeToken": challengeToken, "code": code])
        }
    }

    /// The `/me/link/*` route for a credential, or `nil` for one that cannot be
    /// attached (magic link, email OTP, passkey assertion, MFA code).
    internal func linkRequest(for credential: SendoraCloudCredential) -> (path: String, body: [String: Any])? {
        switch credential {
        case .password(let email, let password):
            return ("/auth-service/me/link/email", ["email": email, "password": password])
        case .social(let provider, let code, let idToken, let redirectUri, let codeVerifier, let first, let last):
            return ("/auth-service/me/link/social", Self.socialBody(provider: provider, code: code, idToken: idToken, redirectUri: redirectUri,
                                                                    codeVerifier: codeVerifier, appleFirstName: first, appleLastName: last))
        case .gameCenter(let url, let signature, let salt, let timestamp, let teamPlayerID, let bundleID):
            return ("/auth-service/me/link/game-center", Self.gameCenterBody(publicKeyURL: url, signature: signature, salt: salt, timestamp: timestamp,
                                                                             teamPlayerID: teamPlayerID, bundleID: bundleID))
        case .magicLink, .emailOtp, .passkey, .mfa:
            return nil
        }
    }
}
