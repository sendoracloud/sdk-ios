import Foundation

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
        record: AuthSessionRecord,
        reason: InstallReason,
        expectSid: IdentityCAS? = nil,
        expectRefresh: String? = nil,
        writeDisk: Bool = true
    ) -> InstallOutcome {
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
                    writeRotationOnly(access: record.accessToken, refresh: record.refreshToken, expiresAt: record.accessExpiresAt)
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
                    user: record.user
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
                writeRotationOnly(access: record.accessToken, refresh: record.refreshToken, expiresAt: record.accessExpiresAt)
                limbo = LimboRecord(refreshToken: record.refreshToken, accessToken: record.accessToken, accessExpiresAt: record.accessExpiresAt)
                lock.unlock()
                return .stayedUnknown
            default:
                break // a fresh response without a readable claim is not a mismatch — install
            }
        case .match:
            break
        }

        let userChanged = current.map { $0.user != record.user } ?? true
        current = record
        limbo = nil
        withheldState = nil
        if writeDisk { writeCurrentRecord(record) }
        lock.unlock()
        onIdentityChange(record.user.id)
        startProactiveRefreshCron()
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
            // INV-9 held-slot coherence: a slot whose userId equals the current
            // user is dropped (current wins — a HOLD whose install never landed).
            lock.lock()
            for i in slots.indices where slots[i]?.userId == record.user.id {
                slots[i] = nil
                storage.setHeldSlotJson(i, nil)
            }
            lock.unlock()
        }
        lock.lock(); hydrated = true; lock.unlock()
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
            // The route tolerates a missing user row: keep the rotation, stay unknown.
            writeRotationOnly(access: tokens.accessToken, refresh: tokens.refreshToken, expiresAt: expMs)
            limbo = LimboRecord(refreshToken: tokens.refreshToken, accessToken: tokens.accessToken, accessExpiresAt: expMs)
            lock.unlock()
            return tokens.accessToken
        }
        lock.unlock()
        // A held slot's token (restore / claim presenting it): CAS per slot.
        if let i = slotIndex(holdingRefreshToken: sent) {
            _ = commitSlotRotation(index: i, expectRefresh: sent, newRefresh: tokens.refreshToken)
        }
        return nil
    }

    /// `REFRESH_DEAD(sent, INVALID_REFRESH_TOKEN)`: clear ONLY the record that
    /// holds `sent`. For a held slot, release it ONLY on `deleted|revoked|expired`
    /// (B11); `reuse` / absent keeps the slot. Returns true when something changed.
    @discardableResult
    internal func commitRefreshDead(sent: String, endReason: SendoraCloudRefreshEndReason?) -> Bool {
        lock.lock()
        if let c = current, c.refreshToken == sent {
            lock.unlock()
            return commitClear(reason: .sessionDeath(endReason), expectRefresh: sent)
        }
        if let l = limbo, l.refreshToken == sent {
            limbo = nil
            clockSkewConfirmed = false
            storage.clearAuthTokens()
            lastSignedOutEndReasonValue = endReason
            lock.unlock()
            stopProactiveRefreshCron()
            onIdentityCleared(ClearEffects(rotateDeviceId: false, clearQueue: false))
            emitAuthState(.signedOut(reason: .sessionExpired))
            return true
        }
        lock.unlock()
        if let i = slotIndex(holdingRefreshToken: sent) {
            guard let reason = endReason, Self.releaseHeldOnEndReasons.contains(reason) else { return false }
            if let released = commitRelease(index: i) {
                emitAuthState(.guestReleased(userId: released.userId, reason: .dead, endReason: reason))
                return true
            }
        }
        return false
    }

    // MARK: - Clear (SIGN_OUT / session death / DELETE)

    /// Drop the current session (or the limbo record). Local-first — the one
    /// deliberate exception to proposal-then-CAS (it has a rollback: a sign-in).
    /// Keeps the held slots; `suppressHeldAutoRestore` stamps `autoRestore:false`
    /// on each of them (DELETE row, integrator test 9).
    @discardableResult
    internal func commitClear(reason: ClearReason, expectRefresh: String? = nil, suppressHeldAutoRestore: Bool = false) -> Bool {
        lock.lock()
        guard current != nil || limbo != nil else { lock.unlock(); return false }
        if let expected = expectRefresh, (current?.refreshToken ?? limbo?.refreshToken) != expected {
            lock.unlock()
            return false
        }
        current = nil
        limbo = nil
        clockSkewConfirmed = false
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
        emitAuthState(event)
        return true
    }

    /// DISCARD_WITHHELD: clear exactly the four frozen auth keys (+ their 5.4.0
    /// mirror record), CAS on the withheld refresh token, LOCAL ONLY — never
    /// `/guest/discard`, never a server delete. Keeps the held slots, the event
    /// queue and the frozen `sendora_user_id` / device id. Returns the refresh
    /// token to revoke, or `nil` when not withheld.
    internal func commitDiscardWithheld() -> String? {
        lock.lock()
        guard let w = withheldState else { lock.unlock(); return nil }
        withheldState = nil
        storage.clearAuthTokens()
        lastSignedOutEndReasonValue = nil
        lock.unlock()
        onIdentityCleared(ClearEffects(rotateDeviceId: false, clearQueue: false))
        emitAuthState(.signedOut(reason: .user))
        return w.refreshToken
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
        writeCurrentRecord(c)
        lock.unlock()
        onIdentityChange(user.id)
        return true
    }

    // MARK: - Held slots (HOLD / RELEASE / per-slot rotation / patches)

    /// Write `slot` into a free slot FIRST (there is never a window with zero
    /// handles to a guest). Returns the slot index, or `nil` when no slot is free.
    internal func commitHold(_ slot: HeldSlotRecord) -> Int? {
        lock.lock()
        guard let i = freeSlotIndexLocked() else { lock.unlock(); return nil }
        // `heldAt` is STRICTLY greater than every held slot's: two holds in the
        // same millisecond (or after a backwards clock step) would otherwise tie,
        // and "newest" — the `heldGuests()` order and the auto-restore pick —
        // would be undefined (lockstep; web saw it as a 1-in-4 flake).
        var slot = slot
        if let newest = slots.compactMap({ $0?.heldAt }).max() {
            slot.heldAt = max(slot.heldAt, newest + 1)
        }
        slots[i] = slot
        storage.setHeldSlotJson(i, slot.encodeJson())
        lock.unlock()
        return i
    }

    /// Empty slot `index`. Returns the released record (the caller emits
    /// `guestReleased` with its reason), or `nil` when the slot was already empty.
    internal func commitRelease(index: Int) -> HeldSlotRecord? {
        lock.lock()
        guard slots.indices.contains(index), let s = slots[index] else { lock.unlock(); return nil }
        slots[index] = nil
        storage.setHeldSlotJson(index, nil)
        lock.unlock()
        return s
    }

    /// CAS PER SLOT: re-read slot `index` at write time; if it no longer holds
    /// `expectRefresh`, DROP; else rotate its refresh token in place.
    @discardableResult
    internal func commitSlotRotation(index: Int, expectRefresh: String, newRefresh: String) -> Bool {
        lock.lock()
        guard slots.indices.contains(index), var s = slots[index], s.refreshToken == expectRefresh else {
            lock.unlock()
            return false
        }
        s.refreshToken = newRefresh
        slots[index] = s
        storage.setHeldSlotJson(index, s.encodeJson())
        lock.unlock()
        return true
    }

    /// Record the `project` claim learned from a refresh response on a slot whose
    /// claim was unreadable at HOLD (restore row: "persist the rotation to the
    /// slot, record the claim, throw").
    internal func commitSlotProject(index: Int, project: String?) {
        lock.lock()
        guard slots.indices.contains(index), var s = slots[index] else { lock.unlock(); return }
        s.project = project
        slots[index] = s
        storage.setHeldSlotJson(index, s.encodeJson())
        lock.unlock()
    }

    /// B15 bookkeeping: the server acknowledged the `/guest/held` report.
    internal func commitHeldReportAcknowledged(userId: String) {
        lock.lock()
        guard var c = current, c.heldReportPending.contains(userId) else { lock.unlock(); return }
        c.heldReportPending.removeAll { $0 == userId }
        current = c
        writeCurrentRecord(c)
        lock.unlock()
    }

    /// B10: the per-attempt mint key lives in the NON-secret tier until MINT_OK.
    internal func commitMintKey(_ key: String?) {
        storage.pendingMintKey = key
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

    // MARK: - Storage primitives (lock held by the caller)

    /// The dual-write (INV-10): the four frozen keys a downgraded build reads, the
    /// 5.4.0 record beside them, and the schema marker → "2".
    private func writeCurrentRecord(_ r: AuthSessionRecord) {
        storage.authAccessToken = r.accessToken
        storage.authRefreshToken = r.refreshToken
        storage.authAccessExpiresAt = r.accessExpiresAt
        if let userJson = Self.encodeUser(r.user) { storage.authUserJson = userJson }
        storage.authSessionJson = Self.encodeSessionRecord(r)
        if storage.schemaVersion != "2" { storage.schemaVersion = "2" }
    }

    /// Persist ONLY a server-performed rotation (limbo gap-fill without a user,
    /// withhold-on-refresh): the token keys, and the record's tokens when a
    /// record exists — never the user, never the slots.
    private func writeRotationOnly(access: String, refresh: String, expiresAt: Int64) {
        // The record is rotated ONLY when it belongs to the same session (its
        // refresh token equals the frozen one being replaced). A record that
        // does not is a leftover of another session (downgrade cycle): rotating
        // it would graft these tokens onto THAT record's user and make the next
        // hydrate trust it — it is dropped instead. Frozen keys first, then the
        // record, so a crash in between can never leave a record-only disk.
        let priorFrozenRefresh = storage.authRefreshToken
        let existing = storage.authSessionJson.flatMap { Self.decodeSessionRecord($0) }
        storage.authAccessToken = access
        storage.authRefreshToken = refresh
        storage.authAccessExpiresAt = expiresAt
        if var record = existing, record.refreshToken == priorFrozenRefresh {
            record.accessToken = access
            record.refreshToken = refresh
            record.accessExpiresAt = expiresAt
            storage.authSessionJson = Self.encodeSessionRecord(record)
        } else if storage.authSessionJson != nil {
            storage.authSessionJson = nil
        }
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

    /// T = |held| + (current anonymous ? 1 : 0) — the MINT bound (§3.2).
    internal func tLocked() -> Int {
        return heldCountLocked() + ((current?.user.isAnonymous == true) ? 1 : 0)
    }

    internal func slotIndex(holdingRefreshToken token: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        return slots.firstIndex { $0?.refreshToken == token }
    }

    internal func slotIndex(forUserId userId: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        return slots.firstIndex { $0?.userId == userId }
    }

    /// The held slots newest first (`heldAt` desc), as `(index, record)`.
    internal func heldSlotsNewestFirst() -> [(index: Int, slot: HeldSlotRecord)] {
        lock.lock(); defer { lock.unlock() }
        return slots.enumerated()
            .compactMap { i, s in s.map { (index: i, slot: $0) } }
            .sorted { $0.slot.heldAt > $1.slot.heldAt }
    }

    /// Eligible for auto-restore: `autoRestore` not `false` and the slot's project
    /// does not mismatch `expectedProjectId ?? projectId` (a `nil` slot project is
    /// judged on the refresh response). An ineligible slot still counts toward T.
    internal func isEligibleForAutoRestore(_ slot: HeldSlotRecord) -> Bool {
        guard slot.autoRestore else { return false }
        if let project = slot.project, let expected = machineConfig.expectedProjectId ?? machineConfig.configProjectId,
           project != expected {
            return false
        }
        return true
    }
}
