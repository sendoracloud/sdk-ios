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
        /// Any verdict but `deleted` (s58.415, G1): the token was moved to quarantine, or the slot parked with
        /// `autoRestore: false` — retryable for an explicit restore; auto-restore moves on to the next slot (it never
        /// throws RESTORE_FAILED for a slot it will not present again).
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
        // rev 3 INV-16: an unconfirmed write is repaired before any identity verb.
        retryPendingCommitIfNeeded()
        // rev 3 INV-17: a storage READ is failing — re-read (every second, up to the queue window), never mint
        // over a session we cannot see; then the normal unknown-settle below.
        if let unreadable = awaitStorageReadable() { return unreadable }
        guard status() == .unknown else { return nil }
        // `force` (s58.415, found by the ADR-037 kill test): a LIMBO_A whose stashed access token is still servable used
        // to short-circuit here — no request, still `unknown` — so every queued verb failed until that token expired.
        // The gap-fill must actually ask the server (as `getAccessToken()` in `unknown` always did).
        _ = performRefreshSync(force: true)
        guard status() == .unknown else { return nil }
        return .network("Session state is unknown: the stored session could not be refreshed yet. Retry when online.")
    }

    /// The INV-17 refusal (`AUTH_DURABILITY_CODES.STORAGE_UNAVAILABLE`): kind `network`, retryable.
    internal static func storageUnavailableError() -> SendoraCloudAuthError {
        return .rejected(code: "STORAGE_UNAVAILABLE",
                         message: "The device's secure storage cannot be read right now (e.g. the phone has not been unlocked since it restarted); the stored session is kept — retry once it is readable",
                         status: 0, retryAfterSeconds: nil)
    }

    /// INV-17 (rev 3): while a storage read is failing, a session-installing verb re-reads every second for up to
    /// `storageUnavailableQueueMs` (shared 10 s), then rejects `STORAGE_UNAVAILABLE` — NEVER a mint over a session
    /// it cannot read (the mint's first write after unlock would overwrite the real account, FS3). `nil` = readable.
    ///
    /// (step-2 review T2) A read that keeps failing for the WHOLE window while the device is known to be unlocked
    /// (`isProtectedDataAvailable`; off UIKit there is no lock) will never succeed — −34018 with no keychain
    /// entitlement, `errSecDecode` bytes on a fresh install. Then the verb PROCEEDS as if those keys were absent
    /// (`acceptPermanentReadFailure`, nothing deleted) instead of locking the player out for good. A window in
    /// which any sample said "locked" — or none said "unlocked" — still rejects `STORAGE_UNAVAILABLE`.
    internal func awaitStorageReadable() -> SendoraCloudAuthError? {
        if recoverStorageIfNeeded() { return nil }
        var sawLocked = false
        var sawUnlocked = false
        let sample = { [self] in
            switch deviceUnlockedSample() {
            case .some(true): sawUnlocked = true
            case .some(false): sawLocked = true
            case .none: break
            }
        }
        sample()
        let queueMs = max(0, machineConfig.storageUnavailableQueueMs)
        let pollMs = max(5, min(1_000, queueMs / 10))
        let deadline = Date().addingTimeInterval(Double(queueMs) / 1000)
        while Date() < deadline {
            usleep(useconds_t(pollMs * 1000))
            if recoverStorageIfNeeded() { return nil }
            sample()
        }
        if sawUnlocked && !sawLocked {
            acceptPermanentReadFailure()
            return nil
        }
        return Self.storageUnavailableError()
    }

    /// The `HoldOutcome` refusal a verb surfaces (nothing held → nothing switched / minted / cleared).
    internal func holdRefusal(_ outcome: HoldOutcome) -> SendoraCloudAuthError {
        if case .writeFailed = outcome { return Self.storageUnavailableError() }
        return .heldGuestLimit(held: heldCount(), limit: Self.heldGuestSlots)
    }

    /// (step-2 review T5) Before a HOLD (sign-in / switch / forceNew / restore / recover over a guest): when the
    /// current guest's last refresh outcome is UNKNOWN (a grace schedule is open for its token — the server may
    /// already have rotated it), run ONE refresh first so the slot gets the live successor. Holding the possibly-
    /// spent token used to cancel the grace retries (they only retry the CURRENT token) and strand the guest past
    /// the server's 60 s window (iOS M1, Codex F2). Offline it stays as it is (a restore inside the grace replays).
    /// Call on `opsQueue`.
    internal func settleUncertainRefreshBeforeHold() {
        awaitRefreshInflight()
        lock.lock()
        let uncertain = current?.user.isAnonymous == true && graceRetry != nil && graceRetry?.sent == current?.refreshToken
        lock.unlock()
        // `force`: the cached access token may well be valid — what is uncertain is the REFRESH token.
        if uncertain { _ = performRefreshSync(force: true, graceRetry: true) }
    }

    /// (s58.415, G8) Before a restore / recover COMMIT: await an in-flight refresh of the current session. If it rotated
    /// the guest that was just held (same user, new token), the held slot is moved onto the live successor first — the
    /// slot must never keep the spent token while the install replaces the session that holds the live one.
    internal func awaitRefreshAndSyncHeldPrevious(heldIndex: Int?, previous: AuthSessionRecord?) {
        awaitRefreshInflight()
        guard let i = heldIndex, let prev = previous, let now = snapshotForAttempt().previous,
              now.user.id == prev.user.id, now.refreshToken != prev.refreshToken else { return }
        _ = commitSlotRotation(index: i, expectRefresh: prev.refreshToken, newRefresh: now.refreshToken, newAccess: now.accessToken)
    }

    /// The identity CAS after `settleUncertainRefreshBeforeHold()`: a rotation of the SAME session (same user) is
    /// not a different session, even when the rotated access token carries a new `sid`.
    internal func casAfterSettle(_ cas: IdentityCAS, before: AuthSessionRecord?) -> IdentityCAS {
        guard let b = before, b.sid == cas.sid, let now = snapshotForAttempt().previous, now.user.id == b.user.id else { return cas }
        return IdentityCAS(sid: now.sid)
    }

    /// `id` may be omitted ONLY when exactly one guest is held (§3.5).
    /// (s58.415, G5) An explicit `id` naming the CURRENT user resolves (the verb then refuses `SLOT_IS_CURRENT`); the
    /// omitted-id count is over the guests `heldGuests()` lists (the current user excluded).
    internal func resolveSlotIndex(id: String?) -> Result<Int, SendoraCloudAuthError> {
        if let id = id {
            guard let match = heldSlotsNewestFirst().first(where: { $0.slot.userId == id }) else {
                return .failure(.heldGuestGone(userId: id, endReason: nil))
            }
            return .success(match.index)
        }
        let held = visibleHeldSlotsNewestFirst()
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
            autoRestore: true,
            // (s58.415, G2 / G3) the session's last access token (the slot's refresh hint) and its issuing origin.
            accessToken: prev.accessToken.isEmpty ? nil : prev.accessToken,
            origin: prev.origin ?? configuredOrigin
        )
    }

    private func sessionRecord(user: SendoraCloudAuthUser, tokens: SendoraCloudAuthTokens, fallbackSid: String?, pending: [String]) -> AuthSessionRecord {
        return AuthSessionRecord(
            user: user,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            accessExpiresAt: nowMs() + Int64(tokens.expiresIn) * 1000,
            sid: jwtStringClaim(tokens.accessToken, "sid") ?? fallbackSid,
            heldReportPending: pending,
            origin: configuredOrigin
        )
    }

    /// (s58.415, G2) A slot refresh body: the slot's token + its last access token as `accessTokenHint` (none known →
    /// no hint).
    internal static func slotRefreshBody(refreshToken: String, accessToken: String?) -> [String: Any] {
        var body: [String: Any] = ["refreshToken": refreshToken]
        if let a = accessToken, !a.isEmpty { body["accessTokenHint"] = a }
        return body
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
        // (T5) Settle an uncertain refresh of the guest about to be held (a rotation of the same session keeps the CAS).
        let (beforeSettle, _) = snapshotForAttempt()
        if beforeSettle?.sid == cas.sid, beforeSettle?.user.isAnonymous == true, parseSuccess(response)?.id != beforeSettle?.user.id {
            settleUncertainRefreshBeforeHold()
        }
        let cas = casAfterSettle(cas, before: beforeSettle)
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
        var heldStamp: Int64?
        var heldRefreshToken: String?
        var previousSummary: SendoraCloudPreviousSession?
        if let prev = currentNow {
            if !sameSub && prev.user.isAnonymous {
                // HOLD the guest with its post-refresh tokens and project claim. (T4) The slot write is CONFIRMED
                // before the install replaces the current token; unconfirmed → nothing installed, B revoked.
                let slot = holdRecord(for: prev)
                let hold = commitHold(slot)
                guard case .held(let idx) = hold else {
                    fireAndForgetRevoke(tokens.refreshToken)
                    return .failure(holdRefusal(hold))
                }
                heldIndex = idx
                heldStamp = slotAt(idx)?.heldAt
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
                emitAuthState(.guestHeld(userId: prev.user.id, count: heldEventCount()))
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
            if let idx = heldIndex, let prev = currentNow { _ = commitRelease(index: idx, userId: prev.user.id, heldAt: heldStamp) }
            fireAndForgetRevoke(tokens.refreshToken)
            return .failure(.projectMismatch(expectedProjectId: machineConfig.expectedProjectId ?? "", actualProjectId: actual))
        default:
            if let idx = heldIndex, let prev = currentNow { _ = commitRelease(index: idx, userId: prev.user.id, heldAt: heldStamp) }
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
        if forceNew { settleUncertainRefreshBeforeHold() } // (T5) the guest about to be held gets its live token
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
                let hold = commitHold(slot)
                guard case .held(let idx) = hold else { return .failure(holdRefusal(hold)) }
                let result = mintFresh(name: name, metadata: metadata, cas: cas, pending: prev.heldReportPending + [prev.user.id])
                switch result {
                case .success(let user):
                    emitAuthState(.guestHeld(userId: prev.user.id, count: heldEventCount()))
                    reportGuestHeld(userId: prev.user.id, refreshToken: slot.refreshToken)
                    setLastSignedInCause(.mint)
                    emitAuthState(.signedIn(user: user))
                case .failure:
                    // The mint failed: the guest is still current, so the slot is a
                    // duplicate handle — roll the hold back silently.
                    _ = commitRelease(index: idx, userId: prev.user.id, heldAt: slotAt(idx)?.heldAt)
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
                // (s58.415, G1) quarantined / parked autoRestore:false: never presented again by auto-restore, and
                // never a RESTORE_FAILED out of ensureSession() for it — try the next one.
                case .keptRetryable: continue
                case .failed(let error): return .failure(error) // transient → abort, state untouched
                }
            }
            // none left → fall through to mint.fresh IN THE SAME CALL (re-checking the cap: a parked slot still counts)
            lock.lock()
            let tAfter = tLocked()
            let heldAfter = heldCountLocked()
            lock.unlock()
            if tAfter >= Self.heldGuestSlots { return .failure(.heldGuestLimit(held: heldAfter, limit: Self.heldGuestSlots)) }
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
        // (s58.415, C2) A key given up as unreadable (T2) reads again: the session on disk comes back (re-hydrated,
        // announced with `.signedIn`) instead of a second guest being minted over it. Retryable: the retry returns it.
        if storage.acceptedKeyHoldsValue() {
            rehydrateAfterAcceptedKeyRecovered()
            return .failure(Self.storageUnavailableError())
        }
        var body: [String: Any] = [:]
        if let name = name { body["name"] = name }
        if let metadata = metadata { body["metadata"] = metadata }
        // (s58.415, G6 / C3) The key is written and CONFIRMED (Keychain) before `/anonymous`: a mint whose key is not
        // stored could not be retried into the SAME guest after a kill (B10). A key we cannot READ is not "none" — no mint.
        let stored = storage.readPendingMintKey()
        if stored.isUnavailable { return .failure(Self.storageUnavailableError()) }
        let mintKey = stored.valueOrNil ?? Self.generateMintKey()
        guard commitMintKey(mintKey) else { return .failure(Self.storageUnavailableError()) }
        body["mintKey"] = mintKey

        let rich = requestSync(method: "POST", path: "/auth-service/anonymous", body: body)
        if let err = parseError(rich) { return .failure(err) }
        guard let user = parseSuccess(rich.body), let tokens = parseTokens(rich.body) else {
            return .failure(.unknown("Malformed response"))
        }
        let record = sessionRecord(user: user, tokens: tokens, fallbackSid: nil, pending: pending)
        switch commitInstall(record: record, reason: .mint, expectSid: cas) {
        case .installed:
            // (G6) Cleared only once the minted session is DURABLE — an unconfirmed install keeps the key until the
            // pending commit lands (a kill before then relaunches signed out; the retry returns the SAME guest).
            commitMintKeyAfterInstall()
            fireLifecycleSignals(from: rich.body, identifiedUserId: user.id)
            return .success(user)
        case .projectMismatch(let actual):
            fireAndForgetRevoke(tokens.refreshToken)
            commitMintKey(nil) // a retry with the same key would return the same wrong-project guest
            return .failure(.projectMismatch(expectedProjectId: machineConfig.expectedProjectId ?? "", actualProjectId: actual))
        case .notDurable:
            // (C3) Never handed to the app; the KEPT mint key replays this same guest on the next attempt (B10, 24 h;
            // past that the server releases the expired key and mints fresh — nothing was ever exposed).
            return .failure(Self.storageUnavailableError())
        case .storeRecovered:
            // (C2) The unreadable store came back with a session in it: that session is kept (re-hydrated), this
            // fresh guest dropped + revoked and its key forgotten (it was never exposed).
            fireAndForgetRevoke(tokens.refreshToken)
            commitMintKey(nil)
            return .failure(Self.storageUnavailableError())
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
        // (s58.415, G3) A slot issued by another API origin is never presented here.
        if isForeignOrigin(slot.origin) { return .transient(.restoreFailed(userId: slot.userId, endReason: nil)) }
        // (s58.415, C1) A rotated token not yet durable is never presented again: confirm it first, else no network.
        guard commitConfirmHeldSlotDurable(index) else { return .transient(Self.storageUnavailableError()) }
        let sent = slot.refreshToken
        let rich = requestSync(method: "POST", path: "/auth-service/token/refresh",
                               body: Self.slotRefreshBody(refreshToken: sent, accessToken: slot.accessToken))
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
        switch commitSlotRotation(index: index, expectRefresh: sent, newRefresh: tokens.refreshToken, newAccess: tokens.accessToken) {
        case .confirmed: break
        case .casMismatch: return .transient(.unknown("Held slot changed while refreshing"))
        case .writeFailed:
            // (T8) The rotated token is NOT on disk yet (the old one is spent server-side): nothing may rely on it.
            // It is kept in memory (a retry presents it) and re-written on the next retry — RESTORE_FAILED, retryable.
            return .transient(.restoreFailed(userId: slot.userId, endReason: nil))
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
        if let refusal = slotIsCurrentRefusal(slot.userId) { return .failed(refusal) } // (G5)
        let expectedOrConfig = machineConfig.expectedProjectId ?? machineConfig.configProjectId
        if let project = slot.project, let expected = expectedOrConfig, project != expected {
            return .projectMismatch(.heldGuestProjectMismatch(userId: slot.userId, slotProject: project, expectedProjectId: expected))
        }
        awaitRefreshInflight()
        settleUncertainRefreshBeforeHold() // (T5)
        let (previous, cas) = snapshotForAttempt()

        var heldPreviousIndex: Int?
        var heldPreviousToken: String?
        var heldPreviousStamp: Int64?
        if let prev = previous, prev.user.isAnonymous {
            // (T4) Confirmed on disk BEFORE anything else happens to the current guest.
            let holdSlot = holdRecord(for: prev)
            let hold = commitHold(holdSlot)
            guard case .held(let idx) = hold else { return .failed(holdRefusal(hold)) }
            heldPreviousIndex = idx
            heldPreviousToken = holdSlot.refreshToken
            heldPreviousStamp = slotAt(idx)?.heldAt
        }
        let rollbackHold: () -> Void = { [self] in
            if let i = heldPreviousIndex, let prev = previous { _ = self.commitRelease(index: i, userId: prev.user.id, heldAt: heldPreviousStamp) }
        }

        switch refreshHeld(index: index) {
        case .transient(let error):
            rollbackHold()
            return .failed(error)
        case .dead(let endReason):
            rollbackHold()
            if let reason = endReason, Self.releaseHeldOnEndReasons.contains(reason) {
                if let released = commitRelease(index: index, userId: slot.userId, heldAt: slot.heldAt) {
                    emitAuthState(.guestReleased(userId: released.userId, reason: .dead, endReason: reason))
                }
                return .dead(reason)
            }
            // (s58.415, G1) Not proof the guest is gone: quarantine it (or park the slot autoRestore:false).
            commitHeldSlotNotDropped(index: index, occupant: slotAt(index) ?? slot, endReason: endReason)
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
            // (s58.415, G8) "await at start AND before commit": a refresh of the current session that landed while
            // the slot was presented is settled first (a same-user rotation keeps the CAS).
            awaitRefreshAndSyncHeldPrevious(heldIndex: heldPreviousIndex, previous: previous)
            switch commitInstall(record: record, reason: .restore, expectSid: casAfterSettle(cas, before: previous)) {
            case .installed:
                // AFTER the install — never zero handles. (T7, iOS H3) And only once the installed session is
                // CONFIRMED on disk: until then the slot (rotated in place by `refreshHeld`) is the guest's only
                // durable copy. Unconfirmed → the release waits for the pending commit to land.
                let releasedNow = installConfirmed() && commitRelease(index: index, userId: slot.userId, heldAt: slot.heldAt) != nil
                if !releasedNow && !installConfirmed() {
                    deferRelease(PendingRelease(kind: .held, index: index, userId: slot.userId, stamp: slot.heldAt,
                                                installedRefresh: tokens.refreshToken, reason: .restored))
                }
                if let prev = previous, let heldToken = heldPreviousToken {
                    emitAuthState(.guestHeld(userId: prev.user.id, count: heldEventCount()))
                    reportGuestHeld(userId: prev.user.id, refreshToken: heldToken)
                }
                // ONE order on every restore path (MINT auto-restore, restoreHeldGuest,
                // restore over a guest) — the shared fixture's: install first, so
                // `signedIn(cause: .restore)`, THEN `guestReleased(.restored)` as the
                // slot is released.
                setLastSignedInCause(.restore)
                emitAuthState(.signedIn(user: user))
                if releasedNow { emitAuthState(.guestReleased(userId: user.id, reason: .restored, endReason: nil)) }
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
        if let refusal = slotIsCurrentRefusal(slot.userId) { return .failure(refusal) } // (G5)

        switch refreshHeld(index: index) {
        case .transient(let error):
            return .failure(error)
        case .dead(let endReason):
            if let reason = endReason, Self.releaseHeldOnEndReasons.contains(reason) {
                if let released = commitRelease(index: index, userId: slot.userId, heldAt: slot.heldAt) {
                    emitAuthState(.guestReleased(userId: released.userId, reason: .dead, endReason: reason))
                }
                return .failure(.heldGuestGone(userId: slot.userId, endReason: reason))
            }
            // (s58.415, G1) quarantine (or park) — never released on a verdict the server could not confirm.
            commitHeldSlotNotDropped(index: index, occupant: slotAt(index) ?? slot, endReason: endReason)
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
                // (T7) The slot goes only once the account's rotated pair is CONFIRMED on disk.
                if installConfirmed() {
                    if let released = commitRelease(index: index, userId: slot.userId, heldAt: slot.heldAt) {
                        emitAuthState(.userUpdated(user: prev.user, cause: .merge))
                        emitAuthState(.guestReleased(userId: released.userId, reason: .claimed, endReason: nil))
                    }
                } else {
                    emitAuthState(.userUpdated(user: prev.user, cause: .merge))
                    deferRelease(PendingRelease(kind: .held, index: index, userId: slot.userId, stamp: slot.heldAt,
                                                installedRefresh: tokens.refreshToken, reason: .claimed))
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
    /// 2xx or 404 releases the slot; any other failure (5xx / network / a 401 or
    /// 422 refusal of the keep-tickets Bearer) keeps it (the guest is not gone).
    ///
    /// `keepTicketsBearer` (5.9.0): the CURRENT account's access token. When
    /// present the body gains `keepSupportTickets: true` and the request carries
    /// `Authorization: Bearer` — the server moves the guest's support tickets to
    /// that account before erasing the guest. When nil the request is exactly the
    /// pre-5.9.0 one (no extra key, no Authorization header).
    internal func performDiscard(index: Int, keepTicketsBearer: String? = nil) -> Result<Void, SendoraCloudAuthError> {
        guard let slot = slotAt(index) else { return .failure(.heldGuestGone(userId: "", endReason: nil)) }
        // (s58.415, G5) `/guest/discard` with a token of the CURRENT user erases the live account. (G3) Another
        // origin's token is never sent here.
        if let refusal = slotIsCurrentRefusal(slot.userId) { return .failure(refusal) }
        if isForeignOrigin(slot.origin) { return .failure(.heldGuestGone(userId: slot.userId, endReason: nil)) }
        var body: [String: Any] = ["refreshToken": slot.refreshToken]
        var headers: [String: String]? = nil
        if let bearer = keepTicketsBearer {
            body["keepSupportTickets"] = true
            headers = ["Authorization": "Bearer \(bearer)"]
        }
        let rich = requestSync(method: "POST", path: "/auth-service/guest/discard", body: body, headers: headers)
        if (200..<300).contains(rich.statusCode) || rich.statusCode == 404 {
            if let released = commitRelease(index: index, userId: slot.userId, heldAt: slot.heldAt) {
                emitAuthState(.guestReleased(userId: released.userId, reason: .discarded, endReason: nil))
            }
            return .success(())
        }
        return .failure(parseError(rich) ?? .unknown("Discard failed"))
    }

    // MARK: - QUARANTINE (ADR-033 rev 3 §3.8 — RECOVER_QUARANTINED / DISCARD_QUARANTINED)

    internal static let unknownOccupantPrefix = "unknown:"

    /// `QUARANTINE_UNRECOVERABLE` (kind `server`, retryable): the slot is KEPT.
    internal static func quarantineUnrecoverable(_ q: QuarantineSlotRecord, endReason: SendoraCloudRefreshEndReason?, status: Int, otherOrigin: Bool) -> SendoraCloudAuthError {
        let why = otherOrigin
            ? "it was issued by another API origin (\(q.origin ?? "?")) and is never sent to this one"
            : "the server still refuses this guest's token (\(endReason?.rawValue ?? "no end reason"))"
        return .rejected(code: "QUARANTINE_UNRECOVERABLE", message: "Not recovered: \(why); it stays quarantined — retry later",
                         status: status, retryAfterSeconds: nil)
    }

    internal static func quarantinedGuestNotFound(_ userId: String) -> SendoraCloudAuthError {
        return .rejected(code: "QUARANTINED_GUEST_NOT_FOUND", message: "No quarantined guest with userId \(userId)", status: 0, retryAfterSeconds: nil)
    }

    /// `recover_quarantined.as_restore`: present the slot's token (+ its last access token as `accessTokenHint`); OK →
    /// the RESTORE rows (hold a current guest FIRST, revoke a current account, install BEFORE releasing the slot);
    /// dead with `deleted` → release (s58.415: deleted ONLY); any other verdict → KEEP, `QUARANTINE_UNRECOVERABLE`
    /// (retryable). A slot of another origin is never presented. Every slot write names its occupant.
    internal func performRecoverQuarantined(userId: String) -> Result<SendoraCloudAuthUser, SendoraCloudAuthError> {
        guard let index = quarantineIndex(forUserId: userId), let q = quarantineAt(index) else {
            return .failure(Self.quarantinedGuestNotFound(userId))
        }
        if let refusal = slotIsCurrentRefusal(q.userId) { return .failure(refusal) } // (G5)
        // (s58.415, G3) a slot of another origin is never presented: kept, QUARANTINE_UNRECOVERABLE.
        if isForeignOrigin(q.origin) { return .failure(Self.quarantineUnrecoverable(q, endReason: nil, status: 0, otherOrigin: true)) }
        // (s58.415, C1) the slot's pending rotation must be durable before its token is presented again.
        guard commitConfirmQuarantineSlotDurable(index) else { return .failure(Self.storageUnavailableError()) }
        awaitRefreshInflight()
        settleUncertainRefreshBeforeHold() // (T5)
        let (previous, cas) = snapshotForAttempt()
        var heldPreviousIndex: Int?
        var heldPreviousStamp: Int64?
        if let prev = previous, prev.user.isAnonymous {
            let hold = commitHold(holdRecord(for: prev)) // (T4) confirmed before anything else
            guard case .held(let idx) = hold else { return .failure(holdRefusal(hold)) }
            heldPreviousIndex = idx
            heldPreviousStamp = slotAt(idx)?.heldAt
        }
        let rollbackHold: () -> Void = { [self] in
            if let i = heldPreviousIndex, let prev = previous { _ = self.commitRelease(index: i, userId: prev.user.id, heldAt: heldPreviousStamp) }
        }

        let rich = requestSync(method: "POST", path: "/auth-service/token/refresh",
                               body: Self.slotRefreshBody(refreshToken: q.refreshToken, accessToken: q.accessToken))
        if rich.statusCode == 0 { rollbackHold(); return .failure(.network("Network request failed")) }
        if !(200..<300).contains(rich.statusCode) {
            rollbackHold()
            let error = rich.body?["error"] as? [String: Any]
            let code = rich.errorCode ?? (error?["code"] as? String) ?? ""
            guard Self.isDeadRefreshError(code) else { return .failure(parseError(rich) ?? .unknown("Recover failed")) }
            let endReason = Self.readEndReason(error)
            if let reason = endReason, Self.releaseHeldOnEndReasons.contains(reason) {
                if let released = commitQuarantineRelease(index: index, userId: q.userId, quarantinedAt: q.quarantinedAt) {
                    emitAuthState(.guestReleased(userId: released.userId, reason: .dead, endReason: reason))
                }
                return .failure(.heldGuestGone(userId: q.userId, endReason: reason))
            }
            return .failure(Self.quarantineUnrecoverable(q, endReason: endReason, status: rich.statusCode, otherOrigin: false))
        }
        let data = rich.body?["data"] as? [String: Any]
        let fields = (data?["tokens"] as? [String: Any]) ?? data
        guard let accessToken = fields?["accessToken"] as? String, !accessToken.isEmpty,
              let refreshToken = fields?["refreshToken"] as? String, !refreshToken.isEmpty,
              let expiresIn = fields?["expiresIn"] as? Int, expiresIn > 0 else {
            rollbackHold()
            return .failure(.unknown("Malformed refresh response"))
        }
        let tokens = SendoraCloudAuthTokens(accessToken: accessToken, refreshToken: refreshToken, expiresIn: expiresIn,
                                            tokenType: fields?["tokenType"] as? String ?? "Bearer")
        // The s58.360 tripwire, as for a held slot: the answer must be for THIS guest.
        let answeredFor = parseSuccess(rich.body)?.id ?? (decodeJwtPayload(tokens.accessToken)?["sub"] as? String)
        // (s58.415) An `unknown:<hash>` occupant (an owner the SDK could not determine) is named by this answer.
        let occupantKnown = !q.userId.hasPrefix(Self.unknownOccupantPrefix)
        if occupantKnown, let who = answeredFor, !who.isEmpty, who != q.userId {
            rollbackHold()
            return .failure(.rejected(code: "HELD_GUEST_IDENTITY_MISMATCH",
                                      message: "The quarantined guest's refresh was answered for a different account; nothing was changed",
                                      status: rich.statusCode, retryAfterSeconds: nil))
        }
        // Persist the rotation into the slot FIRST (the presented token is now spent server-side) — and CONFIRM it
        // (T8): not on disk → nothing is installed; the slot keeps R2 in memory (a retry presents it, the next
        // pending-commit retry re-writes it).
        switch commitQuarantineRotation(index: index, expectRefresh: q.refreshToken, newRefresh: tokens.refreshToken, newAccess: tokens.accessToken) {
        case .confirmed: break
        case .casMismatch:
            rollbackHold()
            return .failure(.unknown("Quarantine slot changed while recovering"))
        case .writeFailed:
            rollbackHold()
            return .failure(Self.storageUnavailableError())
        }
        if projectVerdict(expectedProjectId: machineConfig.expectedProjectId, accessJwt: tokens.accessToken) == .mismatch {
            rollbackHold()
            return .failure(.heldGuestProjectMismatch(userId: q.userId, slotProject: jwtProjectClaimForSlot(tokens.accessToken),
                                                      expectedProjectId: machineConfig.expectedProjectId ?? ""))
        }
        let user = parseSuccess(rich.body) ?? SendoraCloudAuthUser(id: occupantKnown ? q.userId : (answeredFor ?? q.userId), email: nil, emailVerified: false, name: nil, isAnonymous: true,
                                                                  signupMethod: nil, lastLoginMethod: nil, project: q.project)
        if let prev = previous, !prev.user.isAnonymous { fireAndForgetRevoke(prev.refreshToken) }
        var pending = previous?.heldReportPending ?? []
        if heldPreviousIndex != nil, let prev = previous { pending.append(prev.user.id) }
        let record = sessionRecord(user: user, tokens: tokens, fallbackSid: q.sid.isEmpty ? nil : q.sid, pending: pending)
        awaitRefreshAndSyncHeldPrevious(heldIndex: heldPreviousIndex, previous: previous) // (s58.415, G8) await before commit too
        switch commitInstall(record: record, reason: .restore, expectSid: casAfterSettle(cas, before: previous)) {
        case .installed:
            // AFTER the install — never zero handles; (T7) and only once the installed session is CONFIRMED on disk.
            let releasedNow = installConfirmed() && commitQuarantineRelease(index: index, userId: q.userId, quarantinedAt: q.quarantinedAt) != nil
            if !releasedNow && !installConfirmed() {
                deferRelease(PendingRelease(kind: .quarantine, index: index, userId: q.userId, stamp: q.quarantinedAt,
                                            installedRefresh: tokens.refreshToken, reason: .restored))
            }
            if let prev = previous, heldPreviousIndex != nil {
                emitAuthState(.guestHeld(userId: prev.user.id, count: heldEventCount()))
                reportGuestHeld(userId: prev.user.id, refreshToken: prev.refreshToken)
            }
            setLastSignedInCause(.restore)
            emitAuthState(.signedIn(user: user))
            if releasedNow { emitAuthState(.guestReleased(userId: user.id, reason: .restored, endReason: nil)) }
            return .success(user)
        default:
            rollbackHold()
            return .failure(.unknown("Recover result dropped: the session changed while the request was in flight"))
        }
    }

    /// `discard_quarantined.slot`: `POST /guest/discard` with the slot's token; 2xx / 404 → release BY OCCUPANT.
    internal func performDiscardQuarantined(userId: String) -> Result<Void, SendoraCloudAuthError> {
        guard let index = quarantineIndex(forUserId: userId), let q = quarantineAt(index) else {
            return .failure(Self.quarantinedGuestNotFound(userId))
        }
        if let refusal = slotIsCurrentRefusal(q.userId) { return .failure(refusal) } // (G5)
        if isForeignOrigin(q.origin) { return .failure(Self.quarantineUnrecoverable(q, endReason: nil, status: 0, otherOrigin: true)) } // (G3)
        let rich = requestSync(method: "POST", path: "/auth-service/guest/discard", body: ["refreshToken": q.refreshToken])
        if (200..<300).contains(rich.statusCode) || rich.statusCode == 404 {
            if let released = commitQuarantineRelease(index: index, userId: q.userId, quarantinedAt: q.quarantinedAt) {
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
