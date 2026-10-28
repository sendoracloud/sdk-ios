import Foundation
import CryptoKit

// ADR-033 §3.3 — `commit()`: THE ONLY WRITER (INV-1).
//
// Every assignment to `current` / `limbo` / `withheldState` / `slots`, every
// Keychain write of an auth key, every arm/stop of the refresh cron and every
// call into the parent hooks lives in this file. Public verbs and the engines
// (SendoraCloudAuth+Engines.swift) build a PROPOSAL from a network result and
// hand it here; a commit applies it only if the session it was derived from is
// still current — `sid` for identity commits, the sent refresh token for token
// commits (INV-2) — and only after the ProjectGuard (INV-15) has judged it.
//
// A failed, abandoned or superseded attempt therefore leaves the caller exactly
// as found, including offline: there is no "wipe" API to call before a network
// call, so the s58.271 class cannot be reintroduced at a call site.
//
// Convention: `commit*` functions write; the function that OWNS a transition
// emits its events (the background refresh paths own theirs here).

extension SendoraCloudAuth {
    internal enum InstallReason {
        case mint, signIn, upgrade, refresh, claim, restore, recover, hydrate
    }

    internal enum InstallOutcome {
        /// Installed; `userChanged` is true when the user object differs from the
        /// one it replaced (drives `userUpdated(cause: .refresh)`).
        case installed(userChanged: Bool)
        /// The session this result was derived from is no longer current — DROPPED.
        case casMismatch
        /// A FRESH response (mint / sign-in / upgrade / claim / restore) carries
        /// the wrong `project` claim: install nothing (the caller revokes).
        case projectMismatch(actual: String?)
        /// A hydrated / refreshed / recovered record was WITHHELD (state `withheld`).
        case withheld
        /// The claim is unreadable on a hydrate / gap-fill: stay `unknown`.
        case stayedUnknown
        /// (s58.415, C3) A MINT whose session did not reach disk: NOTHING installed (the guest is never handed to the
        /// app), the mint key kept — a retry with it replays the same guest (B10).
        case notDurable
        /// (s58.415, C2) A key given up as unreadable (T2) holds a value again: nothing installed, the store is
        /// re-hydrated (the session on disk is kept); the caller drops — and revokes — the fresh result.
        case storeRecovered
    }

    /// The identity CAS key for an attempt: the `sid` of the session the attempt
    /// started from (`nil` = started from `signedOut` / `unknown`).
    internal struct IdentityCAS {
        let sid: String?
    }

    internal enum ClearReason {
        case user
        case sessionDeath(SendoraCloudRefreshEndReason?)
        case accountDeleted
    }

    // MARK: - Install (every InstallTx: ProjectGuard, then CAS, then write)

    /// Install `record` as the current session.
    ///
    /// Order: CAS (identity `sid`, or the sent refresh token) → `projectVerdict`
    /// on the record's access token → assign + dual-write (four frozen keys +
    /// `sendora_auth_session`, schema marker → "2") → arm the cron → identity hook.
    /// `writeDisk: false` is the hydrate of a record that is already on disk.
    @discardableResult
    internal func commitInstall(
        record proposed: AuthSessionRecord,
        reason: InstallReason,
        expectSid: IdentityCAS? = nil,
        expectRefresh: String? = nil,
        writeDisk: Bool = true
    ) -> InstallOutcome {
        var record = proposed
        // (s58.415, G3) A session the configured backend just issued / rotated is bound to its origin. A hydrated
        // record keeps whatever it had (absent = written before s58.415).
        if reason != .hydrate, record.origin == nil { record.origin = configuredOrigin }
        lock.lock()
        if let cas = expectSid, current?.sid != cas.sid {
            lock.unlock()
            return .casMismatch
        }
        if let expected = expectRefresh, (current?.refreshToken ?? limbo?.refreshToken) != expected {
            lock.unlock()
            return .casMismatch
        }

        let verdict = projectVerdict(expectedProjectId: machineConfig.expectedProjectId, accessJwt: record.accessToken)
        switch verdict {
        case .mismatch:
            switch reason {
            case .hydrate, .refresh, .recover:
                // → withheld. Hydrate: NOTHING on disk (byte-identical). Refresh /
                // recover: persist ONLY the rotation the server already performed
                // (the sent-token CAS passed above), so the next launch does not
                // present a spent token.
                if reason != .hydrate {
                    commitRotationOnlyLocked(access: record.accessToken, refresh: record.refreshToken, expiresAt: record.accessExpiresAt)
                }
                guard let expected = machineConfig.expectedProjectId else { lock.unlock(); return .withheld }
                withheldState = WithheldState(
                    info: SendoraCloudWithheldInfo(
                        expectedProjectId: expected,
                        actualProjectId: jwtProjectClaimForSlot(record.accessToken),
                        userId: record.user.id,
                        isAnonymous: record.user.isAnonymous
                    ),
                    refreshToken: record.refreshToken,
                    accessToken: record.accessToken,
                    accessExpiresAt: record.accessExpiresAt,
                    user: record.user,
                    origin: record.origin
                )
                current = nil
                limbo = nil
                clockSkewConfirmed = false
                lock.unlock()
                stopProactiveRefreshCron()
                onIdentityWithheld()
                return .withheld
            default:
                lock.unlock()
                return .projectMismatch(actual: jwtProjectClaimForSlot(record.accessToken))
            }
        case .unknown:
            switch reason {
            case .hydrate:
                // A pre-s58.276 token on disk: `unknown` until the single gap-fill
                // refresh answers with a claim and is re-judged (INV-15 — never
                // `match`, never a mint, never signed out). No write.
                limbo = LimboRecord(refreshToken: record.refreshToken, accessToken: record.accessToken, accessExpiresAt: record.accessExpiresAt)
                current = nil
                lock.unlock()
                startProactiveRefreshCron()
                return .stayedUnknown
            case .recover:
                // The gap-fill answered without a readable claim: keep the
                // rotation (token CAS passed), stay `unknown`.
                commitRotationOnlyLocked(access: record.accessToken, refresh: record.refreshToken, expiresAt: record.accessExpiresAt)
                limbo = LimboRecord(refreshToken: record.refreshToken, accessToken: record.accessToken, accessExpiresAt: record.accessExpiresAt)
                lock.unlock()
                return .stayedUnknown
            default:
                break // a fresh response without a readable claim is not a mismatch — install
            }
        case .match:
            break
        }

        // (s58.415, C2) Before anything is written over a session key given up as unreadable (T2): re-read it. A value
        // now = the failure was transient and those bytes may be a guest's only token — install NOTHING, re-hydrate.
        // (A rotation of the installed session goes through the write-time guard instead: its pair is kept in memory
        // and the memory session is held by the re-hydrate.)
        if writeDisk, reason != .hydrate, reason != .refresh, storage.acceptedKeyHoldsValue() {
            lock.unlock()
            scheduleRehydrateAfterAcceptedKeyRecovered()
            return .storeRecovered
        }
        // (s58.415, C3) A minted guest is handed to the app only once its session is ON DISK: written first, and not
        // installed at all when the write does not confirm (the previous session, if any, is put back best-effort).
        // A key given up as unreadable that STILL fails to read is never written over (C2): nothing is written at all
        // (not even the access token beside it — a partial write would only confuse the next hydrate).
        if writeDisk, reason == .mint, storage.acceptedKeyStillUnreadable() || !writeCurrentRecord(record) {
            if let previous = current { _ = writeCurrentRecord(previous) }
            let recovered = storage.takeAcceptedKeyFoundValue()
            lock.unlock()
            if recovered { scheduleRehydrateAfterAcceptedKeyRecovered() }
            return .notDurable
        }
        let userChanged = current.map { $0.user != record.user } ?? true
        current = record
        limbo = nil
        withheldState = nil
        var recoveredAcceptedKey = false
        if writeDisk {
            // rev 3 INV-16: a CONFIRMED write retires the refresh marker; an unconfirmed one keeps the record in
            // memory as a PENDING COMMIT (the session keeps working, the write is retried — never re-rotated) and
            // keeps the marker, so a relaunch refreshes at once inside the grace.
            // (s58.415, G7) EVERY install — mint, sign-in, SSO, upgrade, link, claim, restore, recover — goes through
            // here, so every one is confirmed on disk or becomes a pending commit (retried; blocks the next rotation).
            if reason == .mint || writeCurrentRecord(record) { // (C3) a mint's record is already confirmed above
                pendingCommit = false
                pendingRotation = nil
                // A hydrate write-forward re-writes what was ALREADY on disk: the marker it found must survive
                // until the immediate refresh it calls for (hydrate.refresh_inflight) confirms its own pair.
                if reason != .hydrate { storage.setRefreshInflightMarker(nil) }
                // (s58.415, G5) Same-user coherence at every CONFIRMED install: a slot holding the very token now
                // installed is a duplicate. (Restore / recover / claim release their own slot by occupant, with its
                // event — they are left to do so.) Compared against the NEWLY installed token only: a guest being held
                // for this install holds the PREVIOUS token, never this one.
                if reason != .restore && reason != .claim && reason != .recover { dropSlotsDuplicatingCurrentLocked() }
            } else {
                pendingCommit = true
                // (iOS #10) The write found a value under a key given up as unreadable: re-hydrate before anything
                // is written over it.
                recoveredAcceptedKey = storage.takeAcceptedKeyFoundValue()
            }
        }
        lock.unlock()
        onIdentityChange(record.user.id)
        startProactiveRefreshCron()
        if recoveredAcceptedKey { scheduleRehydrateAfterAcceptedKeyRecovered() }
        return .installed(userChanged: userChanged)
    }

    // MARK: - Hydrate commits (boot entry from `unknown`)

    internal func commitHydrate(record: AuthSessionRecord, writeForward: Bool, slots readSlots: [HeldSlotRecord?], unreadable: Set<Int>) {
        lock.lock()
        slots = readSlots
        unreadableSlots = unreadable
        lock.unlock()
        let outcome = commitInstall(record: record, reason: .hydrate, writeDisk: writeForward)
        if case .installed = outcome {
            // INV-9 coherence. ⚠ (s58.415, G5) A held / quarantine slot is dropped as a duplicate of the current
            // session ONLY when it holds the SAME refresh token (a restore / recover / HOLD whose release never landed).
            // It used to be dropped by userId alone: a guest that registered a passkey, was held, then signed back in
            // with that passkey is the same user in a NEW family — the slot's token was dropped with no handle left.
            lock.lock()
            dropSlotsDuplicatingCurrentLocked()
            lock.unlock()
        }
        lock.lock(); hydrated = true; lock.unlock()
    }

    /// (s58.415, G5) Drop every held / quarantine slot whose refresh token IS the current session's (an exact
    /// duplicate — the current session already holds that credential). Lock held by the caller.
    internal func dropSlotsDuplicatingCurrentLocked() {
        guard let c = current else { return }
        for i in slots.indices where slots[i]?.refreshToken == c.refreshToken {
            if storage.setHeldSlotJson(i, nil) { slots[i] = nil }
        }
        for i in quarantine.indices where quarantine[i]?.refreshToken == c.refreshToken {
            if storage.setQuarantineSlotJson(i, nil) { quarantine[i] = nil }
        }
    }

    /// (s58.415, G3) `hydrate.project_mismatch` for an ORIGIN mismatch: the stored session was issued by another API
    /// origin — `withheld{origin_mismatch}`. NOTHING on disk, no network, no cron (the token is never sent anywhere).
    internal func commitHydrateOriginMismatch(record: AuthSessionRecord, slots readSlots: [HeldSlotRecord?], unreadable: Set<Int>) {
        lock.lock()
        slots = readSlots
        unreadableSlots = unreadable
        withheldState = WithheldState(
            info: SendoraCloudWithheldInfo(
                reason: "origin_mismatch",
                expectedProjectId: machineConfig.expectedProjectId ?? machineConfig.configProjectId ?? "",
                actualProjectId: jwtProjectClaimForSlot(record.accessToken),
                userId: record.user.id,
                isAnonymous: record.user.isAnonymous
            ),
            refreshToken: record.refreshToken,
            accessToken: record.accessToken,
            accessExpiresAt: record.accessExpiresAt,
            user: record.user,
            origin: record.origin
        )
        current = nil
        limbo = nil
        hydrated = true
        lock.unlock()
        stopProactiveRefreshCron()
        onIdentityWithheld()
    }

    /// (s58.415, G7) A session record the frozen keys LACK or CONTRADICT may hold a guest's only token. Returns `true`
    /// when dropping / overwriting it loses nothing: an account (credentials recover it), an older generation of the
    /// live session, a token already in a slot — or it has just been written to a free quarantine slot (confirmed).
    /// `false` = keep the record's bytes (no free quarantine slot, or the write did not confirm).
    @discardableResult
    internal func commitRescueLeftoverRecord(_ r: AuthSessionRecord, liveUserId: String?, slots readSlots: [HeldSlotRecord?]) -> Bool {
        if !r.user.isAnonymous { return true }
        if let live = liveUserId, live == r.user.id { return true }
        lock.lock(); defer { lock.unlock() }
        if readSlots.contains(where: { $0?.refreshToken == r.refreshToken })
            || quarantine.contains(where: { $0?.refreshToken == r.refreshToken }) { return true }
        guard let i = quarantineSlotIndexLocked() else { return false }
        let q = QuarantineSlotRecord(userId: r.user.id, sid: r.sid ?? "", refreshToken: r.refreshToken, quarantinedAt: nowMs(),
                                     project: jwtProjectClaimForSlot(r.accessToken),
                                     accessToken: r.accessToken.isEmpty ? nil : r.accessToken, origin: r.origin)
        guard let json = q.encodeJson(), storage.setQuarantineSlotJson(i, json) else { return false }
        quarantine[i] = q
        return true
    }

    internal func commitHydrateLimbo(_ limboRecord: LimboRecord, clearLeftoverRecord: Bool, slots readSlots: [HeldSlotRecord?], unreadable: Set<Int>) {
        lock.lock()
        slots = readSlots
        unreadableSlots = unreadable
        // A record that does not match the frozen refresh token belongs to
        // another session — drop it so no later rotation can graft this
        // session's tokens onto that record's user.
        if clearLeftoverRecord { storage.authSessionJson = nil }
        limbo = limboRecord
        hydrated = true
        lock.unlock()
        // Arm the cron for the single gap-fill refresh (§3.3 row 3).
        startProactiveRefreshCron()
    }

    /// LIMBO_B: a user blob with no refresh token → clear the stale blob, `signedOut`.
    internal func commitHydrateStaleBlob(slots readSlots: [HeldSlotRecord?], unreadable: Set<Int>) {
        lock.lock()
        slots = readSlots
        unreadableSlots = unreadable
        storage.clearAuthTokens()
        hydrated = true
        lock.unlock()
    }

    internal func commitHydrateSignedOut(slots readSlots: [HeldSlotRecord?], unreadable: Set<Int>) {
        lock.lock()
        slots = readSlots
        unreadableSlots = unreadable
        hydrated = true
        lock.unlock()
    }

    // MARK: - rev 3 durability commits (ADR-033 §3.8)

    /// The quarantine mirror at hydrate. Memory only — nothing is written.
    internal func commitHydrateQuarantine(_ records: [QuarantineSlotRecord?], reserved: Set<Int>) {
        lock.lock()
        quarantine = records
        reservedQuarantine = reserved
        lock.unlock()
    }

    /// `hydrate.read_error` (INV-17): stay `unknown{storageUnavailable}`. NOTHING written or removed, no cron, no
    /// identity hook — the session on disk is intact, we just cannot see it yet.
    internal func commitHydrateStorageUnavailable(slots readSlots: [HeldSlotRecord?], unreadable: Set<Int>) {
        lock.lock()
        slots = readSlots
        unreadableSlots = unreadable
        current = nil
        limbo = nil
        storageUnavailableState = true
        hydrated = true
        lock.unlock()
    }

    /// The store reads again: leave `storageUnavailable` so the re-hydrate can install what is on disk.
    internal func commitStorageReadable() {
        lock.lock()
        storageUnavailableState = false
        lock.unlock()
    }

    /// INV-16: write (and CONFIRM) or remove the refresh-in-flight marker. `false` = the marker write did not land
    /// (the caller ABORTS the refresh — never send without it).
    @discardableResult
    internal func commitRefreshMarker(sid: String?, set: Bool) -> Bool {
        guard set else { return storage.setRefreshInflightMarker(nil) }
        var marker: [String: Any] = ["v": 1, "startedAt": nowMs()]
        marker["sid"] = sid.map { $0 as Any } ?? NSNull()
        guard let data = try? JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys]),
              let json = String(data: data, encoding: .utf8) else { return false }
        return storage.setRefreshInflightMarker(json)
    }

    /// INV-16: re-write the in-memory session whose write never confirmed (next refresh, next tick, next verb).
    /// NEVER re-rotates: presenting the previous token again would burn the pair the server just issued.
    /// (T8) Also re-writes slots whose rotated token lives in memory only; (T7) once the session write confirms,
    /// runs the slot releases that waited for it (and emits their `guestReleased`).
    internal func retryPendingCommitIfNeeded() {
        lock.lock()
        for i in dirtyHeldSlots.sorted() {
            if !slots.indices.contains(i) { dirtyHeldSlots.remove(i); continue }
            if storage.setHeldSlotJson(i, slots[i]?.encodeJson()) { dirtyHeldSlots.remove(i) }
        }
        for i in dirtyQuarantineSlots.sorted() {
            if !quarantine.indices.contains(i) { dirtyQuarantineSlots.remove(i); continue }
            if storage.setQuarantineSlotJson(i, quarantine[i]?.encodeJson()) { dirtyQuarantineSlots.remove(i) }
        }
        var recoveredAcceptedKey = false
        if pendingCommit {
            if let c = current {
                if writeCurrentRecord(c) {
                    pendingCommit = false
                    pendingRotation = nil
                    storage.setRefreshInflightMarker(nil)
                } else {
                    recoveredAcceptedKey = storage.takeAcceptedKeyFoundValue()
                }
            } else {
                pendingCommit = false
            }
        }
        // (s58.415, iOS #8) a rotation-only write (limbo gap-fill / withhold-on-refresh) that did not confirm.
        if let p = pendingRotation, !pendingCommit {
            if writeRotationOnly(access: p.access, refresh: p.refresh, expiresAt: p.expiresAt) {
                pendingRotation = nil
                storage.setRefreshInflightMarker(nil)
            } else {
                recoveredAcceptedKey = storage.takeAcceptedKeyFoundValue() || recoveredAcceptedKey
            }
        }
        // (s58.415, G6) The minted session is on disk now: its mint key has done its job.
        if mintKeyClearPending && !pendingCommit && current != nil {
            if storage.writePendingMintKey(nil) { mintKeyClearPending = false }
        }
        let released = pendingCommit ? [] : runPendingReleasesLocked()
        // ⚠ (s58.415) NO duplicate-slot drop here. This runs from ANY thread (`getAccessToken`), and between a HOLD and
        // the install that follows it the held slot legitimately holds the CURRENT token — dropping it as a "duplicate"
        // and then installing the new session left the guest with no handle at all (found by the G8 test, which runs a
        // refresh during a restore's hold). The slot releases a pending install owes run above, by occupant.
        lock.unlock()
        for (rec, reason) in released { emitAuthState(.guestReleased(userId: rec, reason: reason, endReason: nil)) }
        if recoveredAcceptedKey { scheduleRehydrateAfterAcceptedKeyRecovered() }
    }

    /// (s58.415, iOS #8) Persist a server-performed rotation with no installed record to write (limbo / withheld). An
    /// unconfirmed write is a PENDING ROTATION: retried by `retryPendingCommitIfNeeded`, blocks the next rotation (T12).
    /// Lock held by the caller.
    internal func commitRotationOnlyLocked(access: String, refresh: String, expiresAt: Int64) {
        if writeRotationOnly(access: access, refresh: refresh, expiresAt: expiresAt) {
            pendingRotation = nil
            storage.setRefreshInflightMarker(nil)
        } else {
            pendingRotation = (access, refresh, expiresAt)
        }
    }

    /// (T7) Queue a slot release until the installed session (`installedRefresh`) is confirmed on disk.
    internal func deferRelease(_ release: PendingRelease) {
        lock.lock()
        pendingReleases.append(release)
        lock.unlock()
    }

    /// (T7) `true` when the session the last install put in place is confirmed on disk (no pending commit).
    internal func installConfirmed() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !pendingCommit
    }

    /// Run the waiting releases whose session is the current, confirmed one; drop those whose session is gone (the
    /// slot then stays — the next hydrate's coherence step drops it if it really is a duplicate).
    private func runPendingReleasesLocked() -> [(String, SendoraCloudGuestReleasedReason)] {
        guard !pendingReleases.isEmpty else { return [] }
        var out: [(String, SendoraCloudGuestReleasedReason)] = []
        for r in pendingReleases where current?.refreshToken == r.installedRefresh {
            switch r.kind {
            case .held:
                if let s = slots.indices.contains(r.index) ? slots[r.index] : nil, s.userId == r.userId, s.heldAt == r.stamp,
                   storage.setHeldSlotJson(r.index, nil) {
                    slots[r.index] = nil
                    out.append((r.userId, r.reason))
                }
            case .quarantine:
                if let q = quarantine.indices.contains(r.index) ? quarantine[r.index] : nil, q.userId == r.userId, q.quarantinedAt == r.stamp,
                   storage.setQuarantineSlotJson(r.index, nil) {
                    quarantine[r.index] = nil
                    out.append((r.userId, r.reason))
                }
            }
        }
        pendingReleases.removeAll()
        return out
    }

    // MARK: - Refresh commits (REFRESH_OK / REFRESH_DEAD, routed by the SENT token)

    /// `REFRESH_OK(sent)`: install the rotated pair into whichever record holds
    /// `sent` — the current session (re-judged by the ProjectGuard; a rotation is
    /// not a transition), the limbo record (gap-fill → install the recovered
    /// identity, or stay `unknown`), or a held slot (per-slot CAS, routing by
    /// token). `sent` matching nothing is DROPPED (P16). Returns the access token
    /// to hand to the waiting callers.
    internal func commitRefreshOk(sent: String, tokens: SendoraCloudAuthTokens, user: SendoraCloudAuthUser?) -> String? {
        let expMs = Int64(Date().timeIntervalSince1970 * 1000) + Int64(tokens.expiresIn) * 1000
        let sid = jwtStringClaim(tokens.accessToken, "sid")

        lock.lock()
        if let c = current, c.refreshToken == sent {
            let record = AuthSessionRecord(
                user: user ?? c.user, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken,
                accessExpiresAt: expMs, sid: sid ?? c.sid, heldReportPending: c.heldReportPending
            )
            let previousUserId = c.user.id
            lock.unlock()
            switch commitInstall(record: record, reason: .refresh, expectRefresh: sent) {
            case .installed(let userChanged):
                if userChanged { emitAuthState(.userUpdated(user: record.user, cause: .refresh)) }
                return tokens.accessToken
            case .withheld:
                emitAuthState(.sessionWithheld(
                    expectedProjectId: machineConfig.expectedProjectId ?? "",
                    actualProjectId: jwtProjectClaimForSlot(tokens.accessToken),
                    userId: previousUserId
                ))
                return nil
            default:
                return nil
            }
        }
        if let l = limbo, l.refreshToken == sent {
            if let user = user {
                let record = AuthSessionRecord(
                    user: user, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken,
                    accessExpiresAt: expMs, sid: sid, heldReportPending: []
                )
                lock.unlock()
                switch commitInstall(record: record, reason: .recover, expectRefresh: sent) {
                case .installed:
                    // Recovering an identity IS a transition (the 4.14.0 contract):
                    // the subscriber saw `initial{unknown}` and needs the settle.
                    setLastSignedInCause(.signIn)
                    emitAuthState(.signedIn(user: user))
                    return tokens.accessToken
                case .withheld:
                    emitAuthState(.sessionWithheld(
                        expectedProjectId: machineConfig.expectedProjectId ?? "",
                        actualProjectId: jwtProjectClaimForSlot(tokens.accessToken),
                        userId: user.id
                    ))
                    return nil
                default:
                    return tokens.accessToken
                }
            }
            // The route tolerates a missing user row: keep the rotation, stay unknown. (iOS #8: an unconfirmed
            // rotation-only write is retried and blocks the next rotation.)
            commitRotationOnlyLocked(access: tokens.accessToken, refresh: tokens.refreshToken, expiresAt: expMs)
            limbo = LimboRecord(refreshToken: tokens.refreshToken, accessToken: tokens.accessToken, accessExpiresAt: expMs)
            lock.unlock()
            return tokens.accessToken
        }
        // Unrouted (the session ended or was replaced meanwhile): a marker left with no session is stale.
        if current == nil && limbo == nil { storage.setRefreshInflightMarker(nil) }
        lock.unlock()
        // A held slot's token (restore / claim presenting it): CAS per slot.
        if let i = slotIndex(holdingRefreshToken: sent) {
            _ = commitSlotRotation(index: i, expectRefresh: sent, newRefresh: tokens.refreshToken, newAccess: tokens.accessToken)
        }
        return nil
    }

    /// (T8) A slot rotation's outcome: a CAS miss (the slot holds someone / something else) is not a write failure.
    internal enum SlotWrite {
        case confirmed
        case casMismatch
        /// The rotated token is kept IN MEMORY (marked dirty, re-written by `retryPendingCommitIfNeeded`); the disk
        /// still holds the spent one. The caller must not rely on it yet.
        case writeFailed
    }

    /// `REFRESH_DEAD(sent, INVALID_REFRESH_TOKEN)`: act ONLY on the record that holds `sent`.
    /// ⚠⚠ (s58.415, G1 — zero guest-account loss) A GUEST's token is thrown away ONLY on a server-confirmed `deleted`
    /// (the refresh carried `accessTokenHint`). Every other verdict — `reuse` / `revoked` / `expired` / `unknown` /
    /// absent — moves the token to a free quarantine slot (confirmed) before anything is cleared; no free slot → the
    /// session is KEPT and backed off (T6). An identified account is cleared as before (its credentials recover it).
    /// A held slot is released only on `deleted`; any other verdict moves it to quarantine (or parks it
    /// `autoRestore: false` when quarantine is full). Returns true when something changed.
    @discardableResult
    internal func commitRefreshDead(sent: String, endReason: SendoraCloudRefreshEndReason?) -> Bool {
        let tokenDropped = endReason.map { Self.releaseHeldOnEndReasons.contains($0) } ?? false
        lock.lock()
        if let c = current, c.refreshToken == sent {
            lock.unlock()
            if c.user.isAnonymous && !tokenDropped {
                // `refresh_dead.current_guest_quarantine`: nobody on the device holds a live successor — this token
                // is the only handle left (the server keeps a guest's family; ADR-036 may recover it).
                return commitQuarantineCurrent(sent: sent, userId: c.user.id, sid: c.sid,
                                               project: jwtProjectClaimForSlot(c.accessToken), endReason: endReason,
                                               accessToken: c.accessToken, origin: c.origin ?? configuredOrigin)
            }
            return commitClear(reason: .sessionDeath(endReason), expectRefresh: sent)
        }
        if let l = limbo, l.refreshToken == sent {
            // (T10) The disk record in `unknown`: the access token's own claims first (they describe the token), else
            // the disk user blob. (s58.415, G1) An owner the SDK cannot determine — no readable `is_anonymous` claim,
            // no user — is treated as a GUEST: only a proven account is cleared without a handle.
            let claims = l.accessToken.flatMap { decodeJwtPayload($0) }
            let claimSaysIdentified = (claims?["is_anonymous"] as? Bool) == false
            let blobSaysIdentified = claims?["is_anonymous"] == nil && l.diskUser?.isAnonymous == false
            let isIdentified = claimSaysIdentified || blobSaysIdentified
            let knownId = (claims?["sub"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? l.diskUser?.id
            if !isIdentified && !tokenDropped {
                lock.unlock()
                return commitQuarantineCurrent(sent: sent, userId: knownId ?? Self.unknownOccupantId(sent),
                                               sid: l.accessToken.flatMap { jwtStringClaim($0, "sid") },
                                               project: l.accessToken.flatMap { jwtProjectClaimForSlot($0) } ?? l.diskUser?.project,
                                               endReason: endReason, accessToken: l.accessToken, origin: configuredOrigin)
            }
            limbo = nil
            clockSkewConfirmed = false
            storage.clearAuthTokens()
            pendingCommit = false
            pendingRotation = nil
            graceRetry = nil
            lastSignedOutEndReasonValue = endReason
            lock.unlock()
            stopProactiveRefreshCron()
            onIdentityCleared(ClearEffects(rotateDeviceId: false, clearQueue: false))
            emitAuthState(.signedOut(reason: .sessionExpired))
            return true
        }
        // (L3 / T14) The slot holding `sent` and its occupant read in ONE lock section, released by userId + heldAt.
        let holder = slots.indices.first { slots[$0]?.refreshToken == sent }.flatMap { i in slots[i].map { (i, $0) } }
        lock.unlock()
        if let (i, occupant) = holder {
            if let reason = endReason, tokenDropped {
                if let released = commitRelease(index: i, userId: occupant.userId, heldAt: occupant.heldAt) {
                    emitAuthState(.guestReleased(userId: released.userId, reason: .dead, endReason: reason))
                    return true
                }
                return false
            }
            return commitHeldSlotNotDropped(index: i, occupant: occupant, endReason: endReason) != .unchanged
        }
        return false
    }

    /// (s58.415, G1) A held slot's token was refused with anything but `deleted`.
    internal enum HeldDeadDisposition: Equatable {
        /// Written to a free quarantine slot (confirmed), then the held slot released by occupant (`guestReleased{dead}`).
        case quarantined
        /// No free quarantine slot: the held slot is KEPT with `autoRestore: false` — auto-restore never presents it again.
        case parked
        /// The slot changed meanwhile (another occupant), or nothing could be written: left exactly as it was.
        case unchanged
    }

    /// (s58.415, G1 `refresh_dead.held_slot`) Never throw a held guest's token away on a verdict the server could not
    /// confirm: move it to a FREE quarantine slot (confirmed) THEN release the held slot by occupant; quarantine full →
    /// keep the held slot with `autoRestore: false` (confirmed write — re-tried if it does not land; memory says false
    /// at once so this process never presents it again).
    @discardableResult
    internal func commitHeldSlotNotDropped(index: Int, occupant: HeldSlotRecord, endReason: SendoraCloudRefreshEndReason?) -> HeldDeadDisposition {
        lock.lock()
        guard slots.indices.contains(index), let s = slots[index], s.userId == occupant.userId, s.heldAt == occupant.heldAt else {
            lock.unlock(); return .unchanged
        }
        // Already quarantined (a move whose held-slot release never landed): only the release is left.
        let alreadyQuarantined = quarantine.contains { $0?.refreshToken == s.refreshToken }
        if !alreadyQuarantined, let qi = quarantineSlotIndexLocked() {
            let q = QuarantineSlotRecord(userId: s.userId, sid: s.sid ?? "", refreshToken: s.refreshToken, quarantinedAt: nowMs(),
                                         project: s.project, accessToken: s.accessToken, origin: s.origin)
            if let json = q.encodeJson(), storage.setQuarantineSlotJson(qi, json) {
                quarantine[qi] = q
                lock.unlock()
                emitMovedToQuarantine(index: index, occupant: s, endReason: endReason)
                return .quarantined
            }
        } else if alreadyQuarantined {
            lock.unlock()
            emitMovedToQuarantine(index: index, occupant: s, endReason: endReason)
            return .quarantined
        }
        // No free quarantine slot (or its write did not confirm): park the held slot.
        guard s.autoRestore else { lock.unlock(); return .parked }
        var parked = s
        parked.autoRestore = false
        slots[index] = parked
        if !storage.setHeldSlotJson(index, parked.encodeJson()) { dirtyHeldSlots.insert(index) }
        lock.unlock()
        return .parked
    }

    /// (C5) `guest_released{quarantined, endReason}` THEN `guest_quarantined{userId, endReason}` — the held slot is
    /// released by occupant only after the quarantine copy is on disk. (`dead` is reserved for a confirmed `deleted`.)
    private func emitMovedToQuarantine(index: Int, occupant s: HeldSlotRecord, endReason: SendoraCloudRefreshEndReason?) {
        guard let released = commitRelease(index: index, userId: s.userId, heldAt: s.heldAt) else { return }
        emitAuthState(.guestReleased(userId: released.userId, reason: .quarantined, endReason: endReason))
        emitAuthState(.guestQuarantined(userId: released.userId, endReason: endReason ?? .unknown))
    }

    /// (s58.415, C1) A slot whose rotated token lives only in memory (T8 dirty) is made DURABLE before it is presented
    /// again: `true` when the slot's in-memory value is on disk (or nothing is pending). `false` = still not durable —
    /// the caller sends NOTHING (re-rotating an undurable R2 → R3 would strand R1: ADR-036 recovers only a direct
    /// successor that was never presented).
    internal func commitConfirmHeldSlotDurable(_ index: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard dirtyHeldSlots.contains(index) else { return true }
        guard slots.indices.contains(index), storage.setHeldSlotJson(index, slots[index]?.encodeJson()) else { return false }
        dirtyHeldSlots.remove(index)
        return true
    }

    internal func commitConfirmQuarantineSlotDurable(_ index: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard dirtyQuarantineSlots.contains(index) else { return true }
        guard quarantine.indices.contains(index), storage.setQuarantineSlotJson(index, quarantine[index]?.encodeJson()) else { return false }
        dirtyQuarantineSlots.remove(index)
        return true
    }

    /// (s58.415, G1) The occupant name of a quarantined token whose owner cannot be determined (no readable claims, no
    /// user blob): `unknown:` + the first 16 hex of sha256(refreshToken) — stable, and never the token itself.
    internal static func unknownOccupantId(_ refreshToken: String) -> String {
        let digest = SHA256.hash(data: Data(refreshToken.utf8))
        return "unknown:" + digest.map { String(format: "%02x", $0) }.joined().prefix(16)
    }

    // MARK: - Clear (SIGN_OUT / session death / DELETE)

    /// Drop the current session (or the limbo record). Local-first — the one
    /// deliberate exception to proposal-then-CAS (it has a rollback: a sign-in).
    /// Keeps the held slots; `suppressHeldAutoRestore` stamps `autoRestore:false`
    /// on each of them (DELETE row, integrator test 9).
    /// `before` (rev 3) is emitted after the hooks and BEFORE the `signedOut` — `guestQuarantined` on `reuse`, so the
    /// order is `guest_quarantined, signed_out` like RN.
    @discardableResult
    internal func commitClear(reason: ClearReason, expectRefresh: String? = nil, suppressHeldAutoRestore: Bool = false,
                              before: SendoraCloudAuthStateChange? = nil) -> Bool {
        lock.lock()
        guard current != nil || limbo != nil else { lock.unlock(); return false }
        if let expected = expectRefresh, (current?.refreshToken ?? limbo?.refreshToken) != expected {
            lock.unlock()
            return false
        }
        current = nil
        limbo = nil
        clockSkewConfirmed = false
        pendingCommit = false
        pendingRotation = nil
        graceRetry = nil
        reuseBackoff = nil
        pendingReleases.removeAll() // their session is gone: the slots stay (never zero handles)
        // (G6) a mint key kept for an unconfirmed minted session goes with that session.
        if mintKeyClearPending { storage.writePendingMintKey(nil); mintKeyClearPending = false }
        storage.clearAuthTokens()
        if suppressHeldAutoRestore {
            for i in slots.indices {
                guard var s = slots[i], s.autoRestore else { continue }
                s.autoRestore = false
                slots[i] = s
                storage.setHeldSlotJson(i, s.encodeJson())
            }
        }
        lock.unlock()
        stopProactiveRefreshCron()
        let effects: ClearEffects
        let event: SendoraCloudAuthStateChange
        var endReasonForEvent: SendoraCloudRefreshEndReason?
        switch reason {
        case .user:
            // Rotate the analytics device id at a person-boundary; keep the queue
            // (§3.3 SIGN_OUT row — events already carry the user they happened under).
            effects = ClearEffects(rotateDeviceId: true, clearQueue: false)
            event = .signedOut(reason: .user)
        case .sessionDeath(let endReason):
            effects = ClearEffects(rotateDeviceId: false, clearQueue: false)
            // ALWAYS sessionExpired (5.4.1): the server's detail is
            // `lastSignedOutEndReason()`, never the reason — see the enum's doc.
            event = .signedOut(reason: .sessionExpired)
            endReasonForEvent = endReason
        case .accountDeleted:
            // The s58.353 rule as a table column: the deleted account's queued
            // events never surface.
            effects = ClearEffects(rotateDeviceId: true, clearQueue: true)
            event = .signedOut(reason: .accountDeleted)
        }
        lock.lock()
        lastSignedOutEndReasonValue = endReasonForEvent
        lock.unlock()
        onIdentityCleared(effects)
        if let pre = before { emitAuthState(pre) }
        emitAuthState(event)
        return true
    }

    internal enum DiscardWithheldOutcome {
        case notWithheld
        /// Cleared. `revoke` = the refresh token to revoke (an identified session), `nil` for a guest moved to a held slot.
        case cleared(revoke: String?)
        /// (G4) An anonymous withheld session and no free held slot: it STAYS withheld.
        case heldLimit
        /// (G4) The held-slot write did not confirm: it stays withheld.
        case writeFailed
    }

    /// DISCARD_WITHHELD: CAS on the withheld refresh token, LOCAL ONLY — never `/guest/discard`, never a server
    /// delete. Keeps the held slots, the event queue and the frozen `sendora_user_id` / device id.
    /// ⚠⚠ (s58.415, G4) An ANONYMOUS withheld session (another project's / origin's guest) is MOVED to a free held slot
    /// `{autoRestore: false, project, origin, accessToken}` — confirmed — and NEVER revoked: its token was another
    /// build's guest's only handle. No free slot (or the write does not confirm) → it stays withheld. An IDENTIFIED one
    /// is cleared + revoked as before.
    internal func commitDiscardWithheld() -> DiscardWithheldOutcome {
        lock.lock()
        guard let w = withheldState else { lock.unlock(); return .notWithheld }
        let anonymous = w.user?.isAnonymous ?? w.info.isAnonymous
        lock.unlock()
        var heldGuestId: String?
        if anonymous {
            let slot = HeldSlotRecord(userId: w.info.userId, sid: jwtStringClaim(w.accessToken, "sid"), refreshToken: w.refreshToken,
                                      tokenAtHold: w.refreshToken, heldAt: nowMs(), project: w.info.actualProjectId, autoRestore: false,
                                      accessToken: w.accessToken.isEmpty ? nil : w.accessToken, origin: w.origin ?? configuredOrigin)
            switch commitHold(slot) {
            case .held: heldGuestId = w.info.userId
            case .noFreeSlot: return .heldLimit
            case .writeFailed: return .writeFailed
            }
        }
        lock.lock()
        guard withheldState?.refreshToken == w.refreshToken else { lock.unlock(); return .notWithheld }
        withheldState = nil
        pendingRotation = nil
        storage.clearAuthTokens()
        lastSignedOutEndReasonValue = nil
        lock.unlock()
        onIdentityCleared(ClearEffects(rotateDeviceId: false, clearQueue: false))
        // (C5) guest_held{userId} BEFORE signed_out{user} for a moved guest.
        if let id = heldGuestId { emitAuthState(.guestHeld(userId: id, count: heldEventCount())) }
        emitAuthState(.signedOut(reason: .user))
        return .cleared(revoke: anonymous ? nil : w.refreshToken)
    }

    /// (s58.415, iOS #10) Drop the in-memory session (the one written over keys accepted as unreadable) so the
    /// re-hydrate can install what is really on disk. Its token has been held / revoked by the caller first.
    internal func commitDropMemoryOnlySession() {
        lock.lock()
        current = nil
        limbo = nil
        pendingCommit = false
        pendingRotation = nil
        pendingReleases.removeAll()
        graceRetry = nil
        reuseBackoff = nil
        lock.unlock()
    }

    // MARK: - UserTx (same sub, different user object)

    /// Replace the user object of the current session (link attach, unlink,
    /// email verified). No token rotation. sid-CAS.
    @discardableResult
    internal func commitUser(_ user: SendoraCloudAuthUser, expectSid: IdentityCAS) -> Bool {
        lock.lock()
        guard var c = current, c.sid == expectSid.sid else { lock.unlock(); return false }
        c.user = user
        current = c
        if !writeCurrentRecord(c) { pendingCommit = true } // rev 3: retried like a rotation's write
        lock.unlock()
        onIdentityChange(user.id)
        return true
    }

    // MARK: - Held slots (HOLD / RELEASE / per-slot rotation / patches)

    internal enum HoldOutcome {
        case held(Int)
        /// Every slot is occupied or reserved.
        case noFreeSlot
        /// rev 3 INV-16: the slot write did not CONFIRM — nothing was held; the caller must not drop the guest.
        case writeFailed
    }

    /// Write `slot` into a free slot FIRST (there is never a window with zero
    /// handles to a guest). rev 3: the write is CONFIRMED before the hold counts.
    internal func commitHold(_ slot: HeldSlotRecord) -> HoldOutcome {
        lock.lock()
        guard let i = freeSlotIndexLocked() else { lock.unlock(); return .noFreeSlot }
        // `heldAt` is STRICTLY greater than every held slot's: two holds in the
        // same millisecond (or after a backwards clock step) would otherwise tie,
        // and "newest" — the `heldGuests()` order and the auto-restore pick —
        // would be undefined (lockstep; web saw it as a 1-in-4 flake).
        var slot = slot
        if let newest = slots.compactMap({ $0?.heldAt }).max() {
            slot.heldAt = max(slot.heldAt, newest + 1)
        }
        guard storage.setHeldSlotJson(i, slot.encodeJson()) else { lock.unlock(); return .writeFailed }
        slots[i] = slot
        lock.unlock()
        return .held(i)
    }

    /// Empty slot `index` — RELEASE BY OCCUPANT (rev 3, N4): the commit names the guest it is about, and a slot
    /// that now holds anyone else (a delayed discard / release racing a new hold) is left alone. Returns the
    /// released record (the caller emits `guestReleased` with its reason), or `nil` when nothing was released.
    /// (T14) `heldAt`, when given, must match too — the same guest re-held in that slot meanwhile is a new occupant.
    internal func commitRelease(index: Int, userId: String, heldAt: Int64? = nil) -> HeldSlotRecord? {
        lock.lock()
        guard slots.indices.contains(index), let s = slots[index], s.userId == userId,
              heldAt == nil || s.heldAt == heldAt else { lock.unlock(); return nil }
        slots[index] = nil
        storage.setHeldSlotJson(index, nil)
        lock.unlock()
        return s
    }

    /// CAS PER SLOT: re-read slot `index` at write time; if it no longer holds
    /// `expectRefresh`, DROP; else rotate its refresh token in place.
    /// (T8) The rotated token is ALWAYS kept in memory (the old one is spent server-side); a write that does not
    /// confirm marks the slot dirty (re-written by `retryPendingCommitIfNeeded`) and is reported as `.writeFailed`.
    @discardableResult
    internal func commitSlotRotation(index: Int, expectRefresh: String, newRefresh: String, newAccess: String? = nil) -> SlotWrite {
        lock.lock()
        defer { lock.unlock() }
        guard slots.indices.contains(index), var s = slots[index], s.refreshToken == expectRefresh else { return .casMismatch }
        s.refreshToken = newRefresh
        // (G2) the rotated pair's access token is the slot's next refresh hint.
        if let a = newAccess, !a.isEmpty { s.accessToken = a }
        slots[index] = s
        guard storage.setHeldSlotJson(index, s.encodeJson()) else { dirtyHeldSlots.insert(index); return .writeFailed }
        dirtyHeldSlots.remove(index)
        return .confirmed
    }

    /// Record the `project` claim learned from a refresh response on a slot whose
    /// claim was unreadable at HOLD (restore row: "persist the rotation to the
    /// slot, record the claim, throw").
    internal func commitSlotProject(index: Int, project: String?) {
        lock.lock()
        guard slots.indices.contains(index), var s = slots[index] else { lock.unlock(); return }
        s.project = project
        slots[index] = s
        if !storage.setHeldSlotJson(index, s.encodeJson()) { dirtyHeldSlots.insert(index) }
        lock.unlock()
    }

    /// B15 bookkeeping: the server acknowledged the `/guest/held` report.
    internal func commitHeldReportAcknowledged(userId: String) {
        lock.lock()
        guard var c = current, c.heldReportPending.contains(userId) else { lock.unlock(); return }
        c.heldReportPending.removeAll { $0 == userId }
        current = c
        if !writeCurrentRecord(c) { pendingCommit = true }
        lock.unlock()
    }

    /// B10: the per-attempt mint key lives in the NON-secret tier until the minted session is durable.
    /// (s58.415, G6) CONFIRMED: `false` = it did not land (the caller does not mint).
    @discardableResult
    internal func commitMintKey(_ key: String?) -> Bool {
        return storage.writePendingMintKey(key)
    }

    /// (G6) The minted session is installed but its write is pending: keep the mint key until it lands.
    internal func commitMintKeyAfterInstall() {
        lock.lock()
        let confirmed = !pendingCommit
        if !confirmed { mintKeyClearPending = true }
        lock.unlock()
        if confirmed { commitMintKey(nil) }
    }

    /// 5.6.0 (F67 / backend F23): file the `knownDeviceToken` a password sign-in
    /// (or MFA completion) returned under its account. A device credential, not
    /// session state — no listener, no state change, and `commitClear` never
    /// touches it (it survives `signOut`). Never logged.
    internal func commitKnownDeviceToken(email: String, token: String) {
        storage.setKnownDeviceToken(token, forEmail: email, atMs: nowMs())
    }

    /// `deleteAccount` removes THAT account's entry. Nothing else clears the map:
    /// it survives `signOut` AND the RESET row (the rule on all four SDKs).
    internal func commitForgetKnownDevice(email: String) {
        storage.forgetKnownDeviceToken(forEmail: email)
    }

    internal func setLastSignedInCause(_ cause: SendoraCloudAuthSignedInCause) {
        lock.lock()
        lastSignedInCauseValue = cause
        lock.unlock()
    }

    // MARK: - Quarantine (rev 3 §3.8, decision D)

    /// `refresh_dead.current_guest_quarantine`: write the current guest's record to a FREE quarantine slot and
    /// CONFIRM it, THEN clear → `guestQuarantined` → `signedOut(sessionExpired)` with `lastSignedOutEndReason()` = the
    /// server's verdict. (s58.415) Any verdict but `deleted` lands here, not only `reuse`; `guestQuarantined.endReason`
    /// is the verdict, `.unknown` when the server named none (the case's payload is non-optional).
    /// (T6) No FREE readable slot (s58.415: a full quarantine is never overwritten) or a slot write that does not
    /// confirm: the session is KEPT as it is (clearing would leave NO handle at all) and the token is not presented
    /// again for `reuseBackoffMs` — no refresh storm against the server's alarm.
    @discardableResult
    internal func commitQuarantineCurrent(sent: String, userId: String, sid: String?, project: String?,
                                          endReason: SendoraCloudRefreshEndReason? = .reuse,
                                          accessToken: String? = nil, origin: String? = nil) -> Bool {
        lock.lock()
        guard (current?.refreshToken ?? limbo?.refreshToken) == sent else { lock.unlock(); return false }
        let record = QuarantineSlotRecord(userId: userId, sid: sid ?? "", refreshToken: sent,
                                          quarantinedAt: nowMs(), project: project,
                                          accessToken: (accessToken?.isEmpty ?? true) ? nil : accessToken, origin: origin)
        guard let i = quarantineSlotIndexLocked(), storage.setQuarantineSlotJson(i, record.encodeJson()) else {
            reuseBackoff = (sent, nowMs() + Self.reuseBackoffMs)
            lock.unlock()
            return false
        }
        quarantine[i] = record
        lock.unlock()
        stopProactiveRefreshCron()
        return commitClear(reason: .sessionDeath(endReason), expectRefresh: sent,
                           before: .guestQuarantined(userId: userId, endReason: endReason ?? .unknown))
    }

    /// (T6) How long a kept `reuse` token is not presented again (RN: 30 s).
    internal static let reuseBackoffMs: Int64 = 30_000

    /// A FREE quarantine slot, or `nil`. ⚠ (s58.415) A full quarantine is NEVER overwritten: ADR-036 (amended) can
    /// recover a quarantined token for as long as nobody presented its successor, so the oldest slot is a live handle,
    /// not a best-effort one. Reserved slots are never touched.
    internal func quarantineSlotIndexLocked() -> Int? {
        return quarantine.indices.first(where: { quarantine[$0] == nil && !reservedQuarantine.contains($0) })
    }

    /// Quarantine slot rotation (recover presented the token): CAS on the slot's token.
    /// (T8) As `commitSlotRotation`: the rotated token stays in memory even when its write fails (it used to be
    /// dropped — the slot kept only the spent token).
    @discardableResult
    internal func commitQuarantineRotation(index: Int, expectRefresh: String, newRefresh: String, newAccess: String? = nil) -> SlotWrite {
        lock.lock()
        defer { lock.unlock() }
        guard quarantine.indices.contains(index), var q = quarantine[index], q.refreshToken == expectRefresh else { return .casMismatch }
        q.refreshToken = newRefresh
        if let a = newAccess, !a.isEmpty { q.accessToken = a }
        quarantine[index] = q
        guard storage.setQuarantineSlotJson(index, q.encodeJson()) else { dirtyQuarantineSlots.insert(index); return .writeFailed }
        dirtyQuarantineSlots.remove(index)
        return .confirmed
    }

    /// Release a quarantine slot BY OCCUPANT (N4). Returns the released record, or `nil` (slot now holds someone
    /// else, or is empty).
    /// (T14) `quarantinedAt`, when given, must match too.
    internal func commitQuarantineRelease(index: Int, userId: String, quarantinedAt: Int64? = nil) -> QuarantineSlotRecord? {
        lock.lock()
        defer { lock.unlock() }
        guard quarantine.indices.contains(index), let q = quarantine[index], q.userId == userId,
              quarantinedAt == nil || q.quarantinedAt == quarantinedAt else { return nil }
        quarantine[index] = nil
        storage.setQuarantineSlotJson(index, nil)
        return q
    }

    internal func quarantineAt(_ index: Int) -> QuarantineSlotRecord? {
        lock.lock(); defer { lock.unlock() }
        guard quarantine.indices.contains(index) else { return nil }
        return quarantine[index]
    }

    internal func quarantineIndex(forUserId userId: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        return quarantine.firstIndex { $0?.userId == userId }
    }

    // MARK: - Storage primitives (lock held by the caller)

    /// The dual-write (INV-10): the four frozen keys a downgraded build reads, the
    /// 5.4.0 record beside them, and the schema marker → "2".
    ///
    /// rev 3 INV-16: every write is CONFIRMED (`true` only when all landed). If the frozen REFRESH key does not
    /// land, the record is NOT written either — a record whose refresh token the frozen key does not hold is a
    /// state hydrate reads as a leftover (and used to clear as a stale blob with the only copy of R2 in it).
    @discardableResult
    private func writeCurrentRecord(_ r: AuthSessionRecord) -> Bool {
        // (H2) The ACCESS token first, and nothing after it if it fails: "the refresh key landed" then implies its
        // own access token landed beside it, so a hydrate can always check the user blob against that token's `sub`.
        guard storage.write(.accessToken, r.accessToken) else { return false }
        var ok = true
        guard storage.write(.refreshToken, r.refreshToken) else { return false }
        ok = storage.write(.accessExpires, r.accessExpiresAt > 0 ? String(r.accessExpiresAt) : nil) && ok
        if let userJson = Self.encodeUser(r.user) { ok = storage.write(.user, userJson) && ok }
        ok = storage.write(.session, Self.encodeSessionRecord(r)) && ok
        if storage.schemaVersion != "2" { storage.schemaVersion = "2" }
        return ok
    }

    /// Persist ONLY a server-performed rotation (limbo gap-fill without a user,
    /// withhold-on-refresh): the token keys, and the record's tokens when a
    /// record exists — never the user, never the slots.
    @discardableResult
    private func writeRotationOnly(access: String, refresh: String, expiresAt: Int64) -> Bool {
        // The record is rotated ONLY when it belongs to the same session (its
        // refresh token equals the frozen one being replaced). A record that
        // does not is a leftover of another session (downgrade cycle): rotating
        // it would graft these tokens onto THAT record's user and make the next
        // hydrate trust it — it is dropped instead. Frozen keys first, then the
        // record, so a crash in between can never leave a record-only disk.
        let priorFrozenRefresh = storage.authRefreshToken
        let existing = storage.authSessionJson.flatMap { Self.decodeSessionRecord($0) }
        var ok = storage.write(.accessToken, access)
        guard storage.write(.refreshToken, refresh) else { return false }
        ok = storage.write(.accessExpires, expiresAt > 0 ? String(expiresAt) : nil) && ok
        if var record = existing, record.refreshToken == priorFrozenRefresh {
            record.accessToken = access
            record.refreshToken = refresh
            record.accessExpiresAt = expiresAt
            ok = storage.write(.session, Self.encodeSessionRecord(record)) && ok
        } else if storage.authSessionJson != nil {
            ok = storage.write(.session, nil) && ok
        }
        return ok
    }

    // MARK: - Slot queries (read-only)

    /// First empty, READABLE slot. An unreadable slot occupies its key and is
    /// never overwritten (INV-9: never clear what you cannot parse).
    internal func freeSlotIndexLocked() -> Int? {
        for i in slots.indices where slots[i] == nil && !unreadableSlots.contains(i) { return i }
        return nil
    }

    internal func heldCountLocked() -> Int {
        return slots.compactMap { $0 }.count
    }

    /// (T17) `guestHeld.count` = the guests held AFTER the hold, reserved (unreadable) slots INCLUDED — they may
    /// hold a guest (RN / web / Android count them; iOS used to count parsed slots only).
    internal func heldEventCount() -> Int {
        lock.lock(); defer { lock.unlock() }
        return heldCountLocked() + unreadableSlots.count
    }

    /// T = |held| + |reserved held| + (current anonymous ? 1 : 0) — the MINT bound (§3.2). rev 3: a slot that
    /// cannot be read or parsed may hold a guest, so it COUNTS (it is never free). Quarantine slots never count.
    internal func tLocked() -> Int {
        return heldCountLocked() + unreadableSlots.count + ((current?.user.isAnonymous == true) ? 1 : 0)
    }

    internal func slotIndex(holdingRefreshToken token: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        return slots.firstIndex { $0?.refreshToken == token }
    }

    internal func slotIndex(forUserId userId: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        return slots.firstIndex { $0?.userId == userId }
    }

    /// The held slots newest first (`heldAt` desc), as `(index, record)`. (s58.415, G3) A slot issued by ANOTHER API
    /// origin is not here: it is reserved (counted in T), never presented, never released.
    internal func heldSlotsNewestFirst() -> [(index: Int, slot: HeldSlotRecord)] {
        lock.lock(); defer { lock.unlock() }
        return slots.enumerated()
            .compactMap { i, s in s.map { (index: i, slot: $0) } }
            .filter { !isForeignOrigin($0.slot.origin) }
            .sorted { $0.slot.heldAt > $1.slot.heldAt }
    }

    /// (s58.415, G5) What the app may act on: `heldSlotsNewestFirst()` minus a slot whose occupant IS the current user.
    internal func visibleHeldSlotsNewestFirst() -> [(index: Int, slot: HeldSlotRecord)] {
        let me = currentUserIdSnapshot()
        return heldSlotsNewestFirst().filter { me == nil || $0.slot.userId != me }
    }

    internal func currentUserIdSnapshot() -> String? {
        lock.lock(); defer { lock.unlock() }
        return current?.user.id
    }

    /// (s58.415, G5) The refusal for a verb aimed at a slot whose occupant is the current user — acting on it would
    /// erase (discard) or replace (restore / claim / recover) the LIVE session. Nothing is sent.
    internal func slotIsCurrentRefusal(_ userId: String) -> SendoraCloudAuthError? {
        guard let me = currentUserIdSnapshot(), me == userId else { return nil }
        return .rejected(code: "SLOT_IS_CURRENT",
                         message: "That held / quarantined guest is the CURRENT session (\(userId)); nothing was sent",
                         status: 0, retryAfterSeconds: nil)
    }

    /// Eligible for auto-restore: `autoRestore` not `false` and the slot's project
    /// does not mismatch `expectedProjectId ?? projectId` (a `nil` slot project is
    /// judged on the refresh response). An ineligible slot still counts toward T.
    internal func isEligibleForAutoRestore(_ slot: HeldSlotRecord) -> Bool {
        guard slot.autoRestore, !isForeignOrigin(slot.origin) else { return false }
        if let project = slot.project, let expected = machineConfig.expectedProjectId ?? machineConfig.configProjectId,
           project != expected {
            return false
        }
        return true
    }
}
