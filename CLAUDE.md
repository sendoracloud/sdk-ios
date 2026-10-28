# sdk-ios (SwiftPM)

Published at `github.com/sendoracloud/sdk-ios`. Swift 5.9+, **iOS 15+** (`Package.swift` = `.iOS(.v15)`). Passkeys (`ASAuthorizationPlatformPublicKeyCredentialProvider`, iOS 16) are `@available(iOS 16)`-gated — `SendoraCloud.passkeys` + the `SendoraCloudPasskeys` class are iOS-16-only; everything else incl. `SendoraCloudLinks.create()` works on iOS 15. **History:** 2.3.0–4.5.0 forced iOS 16 (unguarded passkey provider); **4.6.0 (s58.235) restored iOS 15** by `@available`-gating passkeys — same treatment Live Activities (iOS 16.1) always had. The type-erased `_passkeys` backing store in `SendoraCloud.swift` exists because Swift forbids `@available` on a stored property.

> ⚠ **ADR-023 frozen contract.** UserDefaults/Keychain keys (`sendora_*`), the `X-Sendora-SDK-{Name,Version}` headers, and the `sendora_schema_version` marker are depended on by installed apps — never rename/remove a key (orphans session/queue on upgrade) or drop the header/marker. The version lives ONLY in `SDKVersion.swift`. Additive only; a format change is MAJOR + needs a migration. CI cap: `apps/backend/src/modules/developer-tools/sdk-contract-golden.test.ts`. Law: `docs/decisions/023-sdk-api-compatibility.md`.



## Unreleased — token durability, ADR-033 rev 3 §3.8 (s58.415) — version 5.10.0, NOT yet published

Law: ADR-033 "Revision 3" + §3.8 (INV-16, INV-17, quarantine, sign-out (decision C), release by occupant); shared rows in
`packages/shared/src/auth-machine/transitions.ts` (golden = 45 rows). Audit: `docs/audit/sdk-auth-s58.415/ios.md`
H1/H2/H3 (+ M3); spec FS1–FS6: `docs/audit/sdk-auth-s58.415/faulty-storage-scenarios.md`. Lockstep with RN `d4009948`.

- **`Storage.swift` / `KeychainSecureStore`** — `read` (INV-17: `.absent` ONLY for `errSecItemNotFound`; −25308 / −34018 /
  undecodable = `.unavailable`), `write` (`SecItemUpdate` IN PLACE, `SecItemAdd` only on NotFound, a racing add →
  update; every OSStatus checked → `Bool`), `remove`. `set`/`get`/`delete` delegate (the 5.9.0 delete-then-add is gone —
  a failed add or a kill between the two left the frozen refresh key GONE, and the next hydrate cleared the record
  holding R2 as a stale blob). Security calls behind `KeychainAPI` (seam; `.system` in production).
  **Accessibility: every SDK item was already `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (no `WhenUnlocked` in
  the history); every write now also passes it to `SecItemUpdate`, so an item of any other class migrates on its next
  write. Reads never filter on it.** New keys: `sendora_auth_quarantine_0…2` (Keychain, in `secureKeys`) and
  `sendora_auth_refresh_inflight` (Keychain since step-2 T15 — the first cut's UserDefaults read-back proved nothing
  about the disk).
- **INV-16** — `performRefresh` writes + confirms the marker `{v:1,sid,startedAt}` BEFORE `/token/refresh` (a marker
  that cannot be written ABORTS the refresh). The rotated pair's dual-write is CONFIRMED (`writeCurrentRecord` → `Bool`;
  if the frozen refresh key fails the record is not written either); confirmed → marker removed; unconfirmed →
  `pendingCommit` (R2 lives in memory, the marker stays), re-written by `retryPendingCommitIfNeeded()` on the next
  `getAccessToken`, refresh, cron tick and identity verb — never re-rotated. A hydrate that finds the marker refreshes
  AT ONCE (`hydrate.refresh_inflight`; a write-forward does not clear it). Status 0 / an unreadable 2xx = outcome
  unknown: marker kept, grace retries of the SAME token at 2/5/15/35 s from the first attempt (deadline 50 s), also
  first for a transient refusal. `/token/refresh` passes `bypassBreaker: true` (audit C) and captures `self` strongly
  (audit M3).
- **INV-17** — any of the five session keys `.unavailable` at hydrate → `unknown`, `auth.storageUnavailable == true`,
  NOTHING written / removed, no cron; slots and quarantine slots that error or fail to parse are RESERVED (in T, never
  free, never released). `settleUnknownIfNeeded` (every MINT / SIGN_IN / LINK / RESTORE / RECOVER / DELETE) re-reads
  every second for `storageUnavailableQueueMs` (10 s) then fails `STORAGE_UNAVAILABLE` (`.rejected`, kind `.network`,
  retryable) — never a mint. Re-hydrate on `UIApplication.protectedDataDidBecomeAvailableNotification` (the same NAME
  is observed off UIKit so `swift test` drives it) and at the top of every refresh; a recovered session emits `.signedIn`.
- **Quarantine (decision D)** — `reuse` on the CURRENT guest (or a limbo whose access token says `is_anonymous`) →
  slot written + CONFIRMED (free, else oldest; reserved never touched) → clear → `.guestQuarantined(userId:endReason:)`
  → `.signedOut(.sessionExpired)` with `lastSignedOutEndReason() == .reuse`. Unconfirmed slot write → session NOT
  cleared. Not in T, never auto-restored, never refreshed in the background. `getQuarantinedGuests()`,
  `recoverQuarantinedGuest(_:)` (OK → restore rows; deleted|revoked|expired → released + `HELD_GUEST_GONE`; reuse →
  kept + `QUARANTINE_UNRECOVERABLE`, kind `.server`, retryable), `discardQuarantinedGuest(_:)` (2xx/404 release).
- **Guest `signOut()` — ⚠ SUPERSEDED by decision C (see "Step-2 review fixes" below).** The first cut (J.1) HELD the
  guest (`autoRestore:false`, no revoke) with a quarantine fallback; it is GONE. New overload
  `signOut(discardGuest:completion: (Result<Void, …>))` — `true` → `POST /guest/discard` then clear (a refused discard
  clears + revokes + fails). `signOut(completion:)` unchanged signature. RESET row: the SIGN_OUT half (a guest's token
  dropped + revoked like an account's); `includeHeldGuests` also releases the quarantine slots.
- **Release by occupant (N4)** — `commitRelease(index:userId:)` / `commitQuarantineRelease(index:userId:)`; a slot that
  now holds anyone else is left alone. `commitHold` returns `HoldOutcome` (`.held` / `.noFreeSlot` / `.writeFailed`).
- **iOS readings (differ from RN, on purpose):** `storageUnavailable` is a property read inside the `.initial` arm, not
  a 4th payload (the case is frozen — same move as `lastSignedInCause()`); the two codes ride `.rejected(code:)` +
  `classifyKind` (no new error case); `.guestQuarantined` is a new state-change case (additive, consumers already
  default-branch). The hold write is confirmed BEFORE the install (T4; RN now confirms too). `MachineConfig.graceRetryScale` (`nil` in `AuthHarness` = no background retries; `FaultyHarness` 0.01)
  and `storageUnavailableQueueMs` are test seams; production = 1 / 10 000.
- **Guards.** `FaultyStorageTests.swift` FS1–FS6 ALL PLAIN (18; FS1 ×2 faults × {process keeps running, relaunch
  inside the grace}; FS2 rewritten to the corrected spec: inside the grace → recovered, past it → quarantined; the
  double now models the rev-3 store — failed write keeps the OLD value, a kill = the write never landed).
  `AuthMachineRowScenarios3.swift` drives the 9 rev-3 rows + N4; `test_tableIsTotalOverStatesTimesEvents` (90 pairs,
  covered XOR unspecified) + `test_durabilityVocabulariesEqualTheFixture`; `KeychainStoreSemanticsTests.swift` (6, the
  real store over a fake Security.framework). Pins converted (in-file notes): `sign_out.local_first`,
  `reset.keeps_held`, `refresh_ok.unrouted_drop`, `refresh_dead.current`(reuse) → IDENTIFIED;
  `test_anExternalSignInThatLandsAfterSignOutIsDroppedAndRevoked` (the signed-out guest is now held).
  `swift test --skip Live` 157 (1 skipped). ⚠ No test name may contain "Live" — `--skip Live` is a regex.
- Mutations (`scratchpad/ios-durability-mut.py`, backups `ios-dur-bak__<path>`, restore in `finally` + `cmp` vs backup
  AND the pristine snapshot, subprocess timeout = red), assertion failures / 157 — ALL 17 RED: D1 no marker before
  refresh 32 · D2 marker removed before the write confirmed 29 · D3 re-rotate to repair a failed write 4 · D4
  delete-then-add back in the Keychain write 6 · D5a Keychain non-NotFound status read as absent 5 · D5b hydrate reads a
  session read error as absent 21 · D6 reuse on a guest clears (no quarantine) 21 · D7 quarantined guest auto-restored 1
  · D8 release without the occupant check 9 · D9a guest signOut revokes 1 · D9b guest held with autoRestore:true 4 ·
  D10 no grace retry 12 · D11 unreadable held slot read as free 3 · D12 refresh held by the breaker 6 · D13 quarantine
  counted in T 2 · D14 verbs skip the STORAGE_UNAVAILABLE wait 4 · D15 a failed session write reported as landed 40.
  ⚠ D4/D5a are caught ONLY by `KeychainStoreSemanticsTests` (every other suite runs on doubles).
  ⚠ Not test-covered: the real `protectedDataDidBecomeAvailableNotification` delivery on a device (the name is pinned,
  the delivery is UIKit's); a real-Keychain run before first unlock needs a device — the operator's pre-mirror smoke.

### Step-2 review fixes (s58.415, `docs/audit/sdk-auth-s58.415/TRIAGE-step2.md`) — same Unreleased batch, lockstep RN `cebf4bf4`

⚠ **Decision C (operator, 2026-10-26) replaces J.1:** a guest's plain `signOut()` drops its token like an account's
(local clear + fire-and-forget revoke, `.signedOut(.user)` ONLY — never `.guestHeld`, never held, never quarantined).
The hold bricked `ensureSession()` after 5 sign-outs (review H1) and its `.guestHeld` made the README's "keep →
restore" handler undo the sign-out. `commitQuarantineOnSignOut` deleted; `signOut(discardGuest:)` unchanged; RESET =
the same SIGN_OUT half. Fixes (iOS file:line findings: `review-internal-ios.md` H2/H3/M1–M4, L3/L5/L7; Codex F2/F3/F7/F9):
- **T1** `beginGraceWindow(newAttempt:)` — every non-grace attempt starts a NEW 2/5/15/35 s schedule (`gen` stamps it;
  a superseded timer fires nothing); grace timers call `refreshAccessToken(force:graceRetry: true)`.
- **T2** `awaitStorageReadable` samples `deviceUnlockedSample()` (UIKit: `ProtectedDataMonitor` — `isProtectedDataAvailable`
  via the `sharedApplication` selector on MAIN, kept current by protected-data / didBecomeActive notifications; no
  `UIApplication.shared`, so extension-safe; off UIKit always `true`; seam `MachineConfig.deviceUnlocked`). Failing the
  whole window with ≥1 "unlocked" and no "locked" sample → `acceptPermanentReadFailure()`: `SendoraStorage` marks the
  failing session keys accepted-unreadable (read as `.absent`, NEVER removed by `clearAuthTokens` / `write(nil)`, a
  successful write un-marks), re-hydrates (no stale-blob clear over an accepted refresh key), runs a deferred sign-out.
  A memory-only session (`sessionIsMemoryOnly`) refreshes without the marker / T12 block (−34018: nothing on disk to protect).
- **T4** the hold is already confirmed before the install on iOS (`commitHold` → `.writeFailed` → `STORAGE_UNAVAILABLE`,
  B revoked, the guest's token never revoked) — now pinned. **T5** `settleUncertainRefreshBeforeHold()` (sign-in /
  `forceNew` / restore / recover): an open grace schedule for the current guest's token → ONE forced refresh first;
  `casAfterSettle` keeps the identity CAS across a same-user rotation (its `sid` may change).
- **T6** `reuse` with no readable quarantine slot or an unconfirmed slot write → session KEPT, `reuseBackoff` 30 s on
  that token (no storm). **T7 (iOS H3)** restore / recover / claim release their slot only when `installConfirmed()`;
  else `PendingRelease` runs (with its `guestReleased`) when `retryPendingCommitIfNeeded` lands THAT session; a clear
  drops pending releases (slot kept); hydrate drops a quarantine slot that is an exact duplicate (same token) of the
  current session. **T8** `commitSlotRotation` / `commitQuarantineRotation` → `SlotWrite` (`confirmed | casMismatch |
  writeFailed`); the successor stays in memory, the slot is dirty and re-written by `retryPendingCommitIfNeeded`;
  `refreshHeld` → `RESTORE_FAILED` (retryable), recover → `STORAGE_UNAVAILABLE`.
- **T9** `performSignOut` re-reads once; still unreadable → `deferredSignOut`, deletes nothing, reports success; recovery
  (signal / didBecomeActive / verb / T2) runs it (clear + revoke + ONE `.signedOut(.user)`, no `.signedIn` first). `signOut(discardGuest: true)` while unreadable fails `STORAGE_UNAVAILABLE` (retryable) and defers nothing (an erase is never downgraded; lockstep RN / web / Android). A verb
  that recovers the store runs the sign-out BEFORE itself (RN queues it after — iOS is stricter). **T10** limbo quarantine:
  access-token claims first, else `LimboRecord.diskUser` (kept only with no access token). **T12** a pending commit whose
  disk refresh ≠ memory blocks the next rotation. **T14** `commitRelease(…heldAt:)` / `commitQuarantineRelease(…quarantinedAt:)`
  everywhere (the dead-slot branch reads token + occupant in one lock, L3). **T15** marker = Keychain item (in
  `secureKeys`; present when its read fails); storage recovery also observes `appDidBecomeActiveNotification`.
  **T17** `heldEventCount()` (reserved slots included) for every `.guestHeld`; `RecordingSecureStore` `set`/`delete` honour `failWrites`.
- **iOS H2** hydrate rebuilds from the frozen keys ONLY when the user blob is the access token's `sub` (else LIMBO_A →
  gap-fill names the user; no slot dropped); `writeCurrentRecord` writes access FIRST and stops if it fails, so "refresh
  landed" ⇒ its access token landed.
- Not applicable: T3 / T11 / T13 (RN), T16 (Android). Deferred list untouched (`beginBackgroundTask`, multi-instance…).
- **Guards.** `DurabilityReviewTests.swift` (22). Pins converted (in-file notes): `sign_out.local_first` (guest AND
  account), `reset.keeps_held` (guest dropped + revoked), `test_anExternalSignInThatLandsAfterSignOut…` (nothing held),
  `refresh_transient.backoff` (marker kept in the Keychain), the marker-tier assertion, FS1 `.locked` (lock starts after
  the request — the marker is written before it), `refresh_ok.write_failed`. `sign_out.guest_holds` → `sign_out.deferred_unreadable`;
  unspecified 9 → 8. `swift test --skip Live` **179 (1 skipped), 0 failures**; iOS Simulator `xcodebuild` green.
  ⚠ The first draft of the T5 test was named `…LiveSuccessor` and was SILENTLY SKIPPED by `--skip Live` — it hid a real
  bug (the settle refresh was short-circuited by a still-valid access token; it is `force: true` now). Never put "Live" in a test name.
- Mutations (`scratchpad/ios-review-mut.py`, backups `ios-rev-bak__<id>__<path>`, restore in `finally`, `cmp` vs backup AND
  pristine, timeout = red), failures / 179 — ALL 32 RED: C1 guest signOut skips the revoke 11 · C2 guest signOut holds 5 ·
  T1 2 · T2a never accepted 1 · T2b stale-blob clear over accepted key 1 · T2c clear deletes accepted keys 1 · T2d a
  "locked" sample ignored 1 · T4 hold write unconfirmed 7 · T5 2 · T6a clears 6 · T6b no back-off 1 · T7a restore 2 · T7b
  recover 2 · T7c claim 1 · T7d deferred releases never run 6 · T7e duplicate quarantine kept 1 · T8a 6 · T8b 4 · T8c dirty
  never re-written 1 · T8d/T8e successor dropped from memory 2/1 · T9a not deferred 8 · T9b signedIn announced first 2 ·
  T10 2 · T12 3 · T14a/b 3/3 · T15a no didBecomeActive re-check 2 · T15b UserDefaults read-back 41 · T17 1 · H2a no sub
  check 5 · H2b refresh written after a failed access write 6.
  ⚠ Not test-covered: `ProtectedDataMonitor` itself (UIKit-only, compiled by the simulator build; the seam drives the rule).

### Zero guest-loss batch (s58.415)

Spec `docs/audit/sdk-auth-s58.415/SPEC-guest-loss-sdk.md` (G1–G8 + iOS D2 / #4 / #8 / #9 / #10 / #11); findings
`guest-loss/audit-ios.md`; shared rows regenerated in `transitions.ts` (`RELEASE_HELD_ON_END_REASONS = ["deleted"]`).
Server half already on the branch (`accessTokenHint`, ADR-036 amended). Same Unreleased batch, version NOT bumped.
- **G1** a guest's token is thrown away ONLY on a server-confirmed `deleted`. CURRENT guest — or a limbo whose owner
  cannot be determined (no readable `is_anonymous`, no user blob → occupant `unknown:<first 16 hex of sha256(token)>`)
  — on ANY other verdict → `commitQuarantineCurrent` (free slot, confirmed) → clear; `guestQuarantined.endReason` = the
  verdict (`.unknown` when absent — the payload is non-optional); no free slot / unconfirmed → kept + 30 s back-off (T6).
  ⚠ A full quarantine is NEVER overwritten (`quarantineSlotIndexLocked` = free only). HELD slot, non-`deleted`:
  `commitHeldSlotNotDropped` → free quarantine slot (confirmed) then release by occupant (`guestReleased{dead}`), else
  PARK it `autoRestore:false` (confirmed, dirty-retried). Restore / claim surface `RESTORE_FAILED`; ensureSession()'s
  auto-restore moves on (`.keptRetryable: continue`, cap re-checked) — never RESTORE_FAILED for a slot it will not
  present again. Recover: `deleted` releases, anything else kept + `QUARANTINE_UNRECOVERABLE`; an `unknown:` occupant
  skips the identity tripwire (the answer names it).
- **G2** `accessTokenHint` on every refresh: current (stashed access), held (`HeldSlotRecord.accessToken`, set at HOLD
  and on every `commitSlotRotation(newAccess:)`), quarantine (`QuarantineSlotRecord.accessToken`). None known → none sent.
- **G3** `origin` (`APIClient.apiOrigin`: scheme://host[:port], lower-case) on `AuthSessionRecord` (stamped by every
  non-hydrate install), held + quarantine slots. Hydrate: record origin ≠ configured → `withheld{reason:"origin_mismatch"}`
  (`commitHydrateOriginMismatch`, no network, no writes, even with a marker). Foreign slots: not listed, not eligible,
  never presented / discarded / released (reset included), counted in T. Absent = matching.
  `SendoraCloudWithheldInfo.reason` is now a stored `let` (internal init, default `project_mismatch`) — read-only for apps.
- **G4** `commitDiscardWithheld` → `DiscardWithheldOutcome`: an ANONYMOUS withheld session is HELD first
  (`autoRestore:false`, project, origin, accessToken), never revoked; no free slot → stays withheld
  (`discardWithheld` → false, `signOut(discardGuest:)` → `HELD_GUEST_LIMIT`; unconfirmed → `STORAGE_UNAVAILABLE`).
  Identified → clear + revoke as before. (iOS `SendoraCloud.reset()` never touched auth — nothing to inherit.)
- **G5** hydrate drops a held / quarantine slot ONLY when its refresh token equals the current one
  (`dropSlotsDuplicatingCurrentLocked`, also after every confirmed non-restore install, comparing against the NEW
  token). `heldGuests()` / `getQuarantinedGuests()` exclude the current user; discard / claim / restore / recover /
  discardQuarantined refuse it with `.rejected(code: "SLOT_IS_CURRENT")` (kind `.config`, classifyKind), nothing sent.
  ⚠⚠ A duplicate drop on every pending-commit LANDING (`retryPendingCommitIfNeeded`, callable from any thread via
  `getAccessToken`) was written and REMOVED: between a HOLD and its install the held slot legitimately holds the CURRENT
  token, and the drop + install left the guest with zero handles. The G8 test found it (mutation G5e pins it).
- **G6** mint key written and CONFIRMED (read back, `writePendingMintKey`) before `/anonymous` (fails →
  `STORAGE_UNAVAILABLE`, no request); cleared only when the minted session is durable (`commitMintKeyAfterInstall`,
  else `mintKeyClearPending` → cleared when the pending commit lands, or by a clear of that session). ⚠ Stays
  UserDefaults like RN / web / Android: the read-back proves process-visible state only (T15's caveat).
- **G7** every install already went through `commitInstall` → confirmed or pending (T12). Hydrate never deletes a
  record whose refresh token the frozen keys lack / contradict without `commitRescueLeftoverRecord` first: a GUEST's
  record not held elsewhere and not an older generation of the live user → free quarantine slot (confirmed); no slot →
  record left as it is (no clear, no write-forward over it). Accounts: cleared as before (credentials recover them).
- **G8** restore / recover: `awaitRefreshAndSyncHeldPrevious` before `commitInstall` — awaits the in-flight refresh
  and, if it rotated the guest just held, moves the held slot onto the successor (sid is the family id: the CAS would
  NOT catch a same-user rotation, so the held slot kept the spent token).
- **D2** `KeychainSecureStore.accessibility(forKey:)`: `SendoraStorage.travellingAuthKeys` (four frozen keys, record,
  5 held, 3 quarantine, marker) → `kSecAttrAccessibleAfterFirstUnlock`; everything else (device id via `addIfAbsent`,
  user id, known devices, link revoke tokens) stays `…ThisDeviceOnly`. `SecItemUpdate` carries the class, so existing
  items migrate on their next write (pinned on the fake Security.framework). The mint key is UserDefaults (no class).
- **#4** `beginRefreshActivity` before the marker write → `endRefreshActivityIfIdle` after the commit (held while a grace
  retry is scheduled; a superseded timer ends it). UIKit: `ExpiringActivity` (`ProcessInfo.performExpiringActivity`,
  block waits ≤ 170 s on a semaphore; extension-safe); off UIKit a no-op; seam `MachineConfig.backgroundActivity`.
- **#8** an unconfirmed rotation-only write (limbo gap-fill without a user, withhold-on-refresh) → `pendingRotation`,
  retried by `retryPendingCommitIfNeeded`, blocks the next rotation (T12). **#9** limbo hydrate + marker → refresh at
  once. **#10** `SendoraStorage.write` re-reads an accepted-unreadable key; a value → refuse + `acceptedKeyFoundValue` →
  `rehydrateAfterAcceptedKeyRecovered` (on `opsQueue`: HOLD the memory-only guest — revoke an account — then
  un-accept, hydrate, `.signedIn`). **#11** frozen refresh absent + frozen access == record.accessToken → rebuilt from
  the record + write-forward (5.9.0 delete-then-add leftover), not cleared.
- **Guards.** `GuestLossTests.swift` (18). Pins converted (in-file notes): `refresh_dead.current` (non-`deleted` →
  identified; `deleted` both), `refresh_dead.held_slot` (only `deleted` releases; others → quarantine; full → parked),
  `refresh_dead.current_guest_quarantine` (full quarantine kept, not overwritten; every verdict; `unknown:` occupant),
  `recover_quarantined.as_restore` (revoked/expired/unknown kept), `withheld.discard` (clear+revoke = identified only;
  guest moved), `hydrate.project_mismatch` (+ origin mismatch), `test_aRecordWhoseFrozenKeysAreGone…` (guest rescued),
  KeychainStoreSemantics ThisDeviceOnly → AfterFirstUnlock (+ D2 test). `swift test --skip Live` **198 (1 skipped), 0
  failures** (×4); iOS Simulator `xcodebuild` green; `check-sdk-request-bodies` green (all three refresh bodies read
  `{refreshToken, accessTokenHint}`); `check-sdk-snippets` green (README prose/comment edits only).
- Mutations (`scratchpad/ios-gl-mut.py`, backups `ios-gl-bak__<id>__<path>`, restore in `finally` + `cmp` vs backup AND
  pristine, timeout = red), failures / 198 — ALL 38 RED: D2a auth keys ThisDeviceOnly 21 · D2b device id travels 3 ·
  G1a guest dropped on non-reuse 26 · G1b undeterminable limbo cleared 6 · G1c release on revoked|expired 47 · G1d full
  quarantine overwrites oldest 11 · G1e held slot neither moved nor parked 44 · G1f parked keeps autoRestore 3 · G1g
  auto-restore aborts 3 · G1h occupant without hash 1 · G2a no hint (current) 7 · G2b no hint (slot) 9 · G2c hold
  without access 2 · G2d rotation keeps old access 1 · G3a hydrate ignores origin 12 · G3b foreign held listed 2 · G3c
  foreign quarantine presented 2 · G3d reset releases foreign 4 · G4a withheld guest revoked 2 · G4b not held 21 · G4c
  no slot → cleared 4 · G5a drop by userId 8 · G5b current listed 2 · G5c no SLOT_IS_CURRENT 13 · G5d current
  quarantine listed 1 · G5e landing drop (the hold race) 1 · G6a unconfirmed mint key 4 · G6b key cleared early 3 · G7a
  no rescue 5 · G7b unconfirmed install not pending 36 · G8a no await 1 · G8b held not synced 1 · I4a no activity 4 ·
  I4b ended during grace 2 · I8 rotation-only not pending 1 · I9 no limbo refresh 3 · I10 no re-read 4 · I11 5.9.0
  leftover cleared 4. (G1h's first form did not compile — `SHA256Digest.count` — re-run in a compiling form.)
  ⚠ Not test-covered: `ExpiringActivity` itself (UIKit-only; compiled by the simulator build — the seam drives the
  rule); a real backup → restore of `AfterFirstUnlock` items onto a second iPhone (device-only — operator smoke).

### Zero guest-loss batch C (s58.415, Codex review `review-codex-guest-loss.md`) — on top of batch A `e928129f`

Spec: `SPEC-guest-loss-sdk.md` "## Batch C". Shared rows (golden regenerated): `GuestReleasedReason` + `quarantined`;
`refresh_dead.held_slot` emits `guest_released{quarantined}` then `guest_quarantined`; `withheld.discard` emits
`guest_held` before `signed_out`. C4 is RN-only.
- **C1 (Codex #1)** `commitConfirmHeldSlotDurable` / `commitConfirmQuarantineSlotDurable`: before ANY held / quarantine
  `/token/refresh` (`refreshHeld` — restore, claim, auto-restore — and recover) a T8-dirty slot is re-written and
  CONFIRMED; still not durable → `STORAGE_UNAVAILABLE` (retryable), NO network. (Re-rotating an undurable R2 → R3
  stranded R1: ADR-036 recovers only a direct successor never presented.) Auto-restore under the fault aborts the mint.
- **C2 (Codex #3; iOS #10 verified + closed)** `SendoraStorage.write` over a key T2 accepted as unreadable re-reads it:
  value → refused + `acceptedKeyFoundValue`; ⚠ STILL unreadable → refused too (#10 only refused on a value — the gap
  Codex named); absent → written. `commitInstall` (every reason but hydrate / refresh) re-reads the given-up keys first:
  a value → `.storeRecovered` (nothing installed, re-hydrate scheduled; mint revokes its pair + forgets its key; other
  verbs drop + revoke through their default branch). `mintFresh` re-checks BEFORE `/anonymous` (healed → re-hydrate,
  `STORAGE_UNAVAILABLE`, no second guest). The re-hydrate holds a memory-only guest only if no slot holds it already.
  ⚠ Consequence (by design): with the keys STILL unreadable, T2's "proceed as absent" no longer yields a session from a
  mint (C3 drops it) — a sign-in still works in memory (G7 pending). A device whose Keychain is broken for good (−34018,
  no entitlement) gets no guest until it reads; the mint key replays one guest, so nothing piles up server-side.
- **C3 (Codex #4 + #7)** `commitInstall(.mint)` writes FIRST and installs only when the write confirmed (and nothing is
  written while a given-up key still fails to read); otherwise `.notDurable`: no `current`, no event, no identity hook,
  the previous session (forceNew) put back best-effort, the mint key KEPT → `STORAGE_UNAVAILABLE`; `performMint` rolls
  back a forceNew hold. A retry replays the same guest (B10); past 24 h the server releases the expired key (server
  fix in `e928129f`). ⚠ The mint key moved to the KEYCHAIN (`SendoraStorage.mintKeyKey`, same literal as the UserDefaults
  key; in `secureKeys` + `travellingAuthKeys`; legacy UserDefaults value read as a fallback and removed on the next
  write); an unreadable mint key → `STORAGE_UNAVAILABLE`, never a new key. G6's `mintKeyClearPending` is now dead for
  mints (kept for no other path) — batch-A mutant G6b is EQUIVALENT under C3 (an install is always durable).
- **C5** `SendoraCloudGuestReleasedReason.quarantined` (additive; doc says default-branch, like `.guestQuarantined`);
  `emitMovedToQuarantine` = `guestReleased(.quarantined, endReason)` → `guestQuarantined(userId, endReason ?? .unknown)`;
  `.dead` only on `deleted`. `commitDiscardWithheld` emits `guestHeld` before `signedOut(.user)` for a moved guest.
- **Guards.** `GuestLossTests` (21): + `test_C1_…` (one /token/refresh under a repeated slot fault; R2 written before it
  is presented; quarantine too), `test_C2_storageHealsDuringTheMint…` (Codex's probe + healed-between-mints),
  `test_10_C2_aStillUnreadableKey…`, `test_C3_…` (never exposed, key kept, same key on the retry, forceNew rollback),
  `test_C5_guestReleasedReasonsEqualTheSharedUnion` (reads `shared/…/types.ts`), G6 converted to the Keychain key.
  Pins converted (in-file notes): DurabilityReview T2 (mint after the window fails STORAGE_UNAVAILABLE, bytes untouched),
  `mint.fresh` mint-key tier, `mint.auto_restore` (+ guest_quarantined), `refresh_dead.held_slot` (quarantined, then
  guest_quarantined), `withheld.discard` (guest_held first), fresh-mint verdict case (mint key excluded from "no auth
  key"), D2 test (+ mint key). `swift test --skip Live` **201 (1 skipped), 0 failures** (×4); iOS Simulator `xcodebuild`
  green; `check-sdk-request-bodies` + `check-sdk-snippets` green.
- Mutations (`scratchpad/ios-glc-mut.py`, backups `ios-glc-bak__<id>__<path>`, restore in `finally` + `cmp`), failures /
  201 — ALL 17 RED: C1a held slot not confirmed 5 · C1b quarantine not confirmed 1 · C1c confirmation never writes 5 ·
  C2a still-unreadable key written over 4 · C2b recovered key written over 3 · C2c no install pre-check 1 · C2d no mint
  pre-check 1 (survived the first run — the healed-between-mints case was added) · C2e mint writes beside an unreadable
  key 1 · C3a non-durable mint installed 13 · C3b mint key forgotten 3 · C3c mint key back in UserDefaults 7 · C3d
  unreadable mint key read as none 2 · C5a moved = dead 6 · C5b no guestQuarantined 11 · C5c no guestHeld 4 · C5d
  guestHeld after signedOut 4 · G3c2 (batch-A G3c, anchor moved by C1) 2.
  Batch-A set re-run against this code (`ios-glA2`): 35 red; G6b equivalent (above); I10 superseded by C2a/C2b (anchor
  rewritten); G3c re-anchored → G3c2 red.

## Unreleased — TicketHistory asks (s58.406) — version 5.10.0, NOT yet published

`SendoraCloudSupport.swift`: (1) `listMyTickets(widgetId:statuses:activeOnly:limit:)` — NEW overload (all three
defaulted); `listMyTickets(widgetId:)` kept verbatim and forwards (an unapplied reference still compiles; Swift picks
the default-free one for a bare call — checked). `myTicketsQuery` (internal static) validates BEFORE the token lookup:
limit 1…50, non-empty known statuses, not both with `activeOnly` → `SendoraSupportError` `INVALID_ARGUMENT` (status 0),
no request; query order `statuses=a,b` (deduped, raw commas) `&activeOnly=true&limit=N`; no options → no `?`.
(1b) CURSOR PAGING (backend moved to `{data, pagination:{limit, nextCursor}}`, never more than `limit` rows; the old
"newest N plus active/unread extras" is gone): `listMyTicketsPage(widgetId:cursor:limit:statuses:activeOnly:) ->
SendoraMyTicketPage { tickets; nextCursor }`; the filtered `listMyTickets` overload = `listMyTicketsPage(cursor: nil)
.tickets` (first page). `myTicketsQuery(…, cursor:)` refuses an empty cursor (`INVALID_ARGUMENT`, before the token
lookup) and appends `&cursor=` LAST, encoded with an unreserved-only set (`+ / = &` all escaped). `nextCursor` is read
from the envelope (`call` returns the whole dict; `data()` only unwraps `data`) at `pagination.nextCursor`; absent /
null / "" → nil (an older server = one page).
(2) `SendoraSupportError.activeTicketId: String?` + a 4-arg init; the 3-arg init kept (forwards nil); `data()` reads
`error.details.ticketId` only for code `ACTIVE_TICKET_EXISTS`. (3) `presentTicketHistory` (its `limit` = page size of the hosted list, which pages with "Load more") gained defaulted
`ticketId:readOnlyFinished:statuses:activeOnly:limit:` before `completion:` (same move as 5.5.0's `accent:`; none is
a closure, so trailing-closure calls stay unambiguous). URL built by the pure `ticketHistoryURL(...)` (outside the
UIKit block → `swift test` covers it): lenient — UUID-shaped `ticketId` only, unknown statuses dropped, `activeOnly`
wins over `statuses`, `limit` only 1…50, flags as `=1`; token still `#access=` (`.urlFragmentAllowed`); with no
options byte-identical to the 5.5.0 URL (pinned). Harness: `StubTransport.Recorded.query` (new, defaulted).
Guard `SupportTicketFiltersTests.swift` (12: +4 paging). `swift test` 133 (3 skipped); `xcodebuild … iOS Simulator` green.
Mutations (`scratchpad/mutate406.py`, backups `s406_ios_M<n>_bak_*`, restored byte-identical), red assertions / 129:
limit unchecked 6 · statuses+activeOnly let through 2 · 409 ticketId dropped 1 · hosted ticketId not UUID-checked 3 ·
list query not sent 8 · unknown status accepted 4. Paging (`scratchpad/mutate406p.py`, backups
`s406p_ios_M<n>_bak_*`, restored byte-identical), red / 133: cursor sent unencoded 2 · empty cursor let through 5
assertions (1 test) · `pagination.nextCursor` not read 2 (1 test).
⚠ Not test-covered: the UIKit `presentTicketHistory` wiring itself (compile only) — the URL builder is.

## 5.9.0 (s58.405-k) — published — keep a held guest's support tickets on discard

New overload `discardHeldGuest(id:keepSupportTickets:completion:)` (no default on the flag, so existing calls stay unambiguous; the old verb forwards with false →
byte-identical request). On: withheld gate → not identified → `KEEP_TICKETS_REQUIRES_IDENTIFIED` (config, nothing sent) →
the account's access token via `bearerTokenOnQueue()` (on `opsQueue`; `getAccessToken` would deadlock) → body
`keepSupportTickets: true` + `Authorization: Bearer`. Slot rules unchanged (2xx / 404 release). Guard `HeldGuestKeepTicketsTests.swift` (7); mutations
(no Bearer; no identified check) → red.

## 5.8.0 (s58.405-j) — published — `account_locked` is retryable only with a wait

`retryable` for `account_locked` = `retryAfterSeconds` present. The server's per-network and 20/hour waits send one;
the 100-failure hard stop sends none and does not lift with time (reset the password / sign in another way). Every
other kind unchanged. Guard `SendoraCloudAuthErrorTests.test_accountLockedIsRetryableOnlyWithAWait` (+ the classify table row flipped to false); mutation (always true for `account_locked`) → 2 red.

## 5.7.1 (s58.405) — published

`saveEventQueue` no longer strips `userId` / `properties.traits` (nothing ever restored them; a restored identified event went out with neither `userId` nor `anonymousId` and never got its send-time token) and removes any `identityToken` as a belt; old files decode with `userId` absent. Key error says 19+ chars (was "17+"). Guard `PersistedQueueIdentityTests.swift` (4; re-adding the strip → 5 red) + `test_malformedKeyMessageMatchesThePattern`; `swift test` 113 (3 skipped).

## 5.7.0 — server consent + feature flags, with identify()'s identityToken

**What.** `SendoraCloud.consent.record(purpose:granted:entityId:userId:email:source:identityToken:)` →
`POST /consent/record`, `requestDeletion(entityId:userId:email:reason:identityToken:)` → `POST /consent/deletion-request`
(methods ADDED to the same `SendoraCloudConsent`; `grant()` / `revoke()` / `isGranted` untouched — `attach(client:identity:)`
wires the server half at `configure()`). `SendoraCloud.flags?.evaluate(key:userId:entityId:environment:identityToken:)` /
`evaluateAll(…)` (`SendoraCloudFlags.swift`). All `async throws` → `SendoraCloudAPIError(code, status, message,
retryAfterSeconds)`: a non-2xx / `success:false` / offline / unconfigured is THROWN, never nil. Bodies omit nil fields.
**Real server shapes** (found here and by the Android port; RN's types say `{value, variant, reason}` keyed by flag — wrong):
`evaluate` → `data: {key, value, ruleMatched}`, `evaluate-all` → `data: [{key, value, ruleMatched}]`, decoded into
`SendoraFlagValue(key, value: SendoraJSONValue, variant (only if sent), reason: ruleMatched)` and a `[key: SendoraFlagValue]`
map (a map is tolerated too). `SendoraJSONValue` keeps a JSON bool a bool (CFBoolean check).
**Token rule** (`SendoraIdentityRequest.identityToken`, port of RN `withInputIdentityToken`, one function): explicit wins
as given; else identify()'s token only when the call's userId (flags: default = identified user; consent: explicit
`userId` only, as RN) equals the user the token was ISSUED FOR (`identityTokenUserId`, new, memory only) AND the
current user, and it fits the route (flags ≤ 128, consent ≤ 256). `reset()` / an identity clear drop both. ⚠ This is
stricter than RN: auth's `onIdentityChange` switches `currentUserId` without clearing the token, so RN/old iOS could pair
user A's token with user B; the event decorator now uses the same snapshot.
**Guards.** `IdentityRequestsTests.swift` (6): rule table, flags/consent bodies + decoding, error mapping. 103 / 103
offline (2 live skipped). Mutations (`scratchpad/mutate570.py`, backups `sdkios570_<M>_bak_<path>`), all red / 103:

| # | Mutation | Red |
|---|---|---|
| M64 | an explicit identityToken does not win | 2 |
| M65 | the remembered token goes with ANY userId | 4 |
| M66 | the token's own user is not checked | 1 |
| M67 | no route length limit | 1 |
| M68 | flags limit 256 instead of 128 | 2 |
| M69 | flags do not default to the identified user | 3 |
| M70 | nil fields sent as null | 4 |
| M71 | a refusal returns an empty answer | 3 |
| M72 | the server code is dropped | 2 |
| M73 | evaluateAll does not decode the server array | 1 |
| M74 | reason not read from `ruleMatched` | 2 |
| M75 | a JSON bool decoded as a number | 1 |
| M76 | `consent.record` never sends the token | 1 |

⚠ Not unit-tested (need `configure()`'s statics): `identify()` recording `identityTokenUserId`, and the event decorator's
switch to the snapshot. **Live T8** (`LiveStagingTests.scenarioConsentAndFlags`): record 201, deletion 201, evaluate 200,
evaluate-all 200, evaluate for another userId 200; the token rode the four identified bodies and NOT the other-user one.
The token is a placeholder (a valid HMAC needs the project's identity secret), so staging answers unproven
(`sourceVerified:false`, deletion `unconfirmed`) — T8 proves routing + which body carried it, not verification.
Full live run 2026-10-19: 29/29 required steps (A/B/W1/T1–T8), `judgeLiveRun` ok, `sdkReportedVersion` 5.7.0.
README: "Consent + feature flags (5.7.0)" section (snippet gate green; a broken label in it fails the gate — checked).

**5.7.0 pre-publish consumer test (iOS Simulator, real Keychain) — three fixes.**
(1) ⚠⚠ **Device-id race, pre-existing since 4/2026.** `SendoraStorage.deviceId` was `get` → `set` with no lock.
On a fresh install `reportInstallIfNeeded` (background queue) and `app.opened` (main) both missed, both minted, the
loser's add failed `-25299` and it KEPT its unsaved UUID: a request trace in a consumer app showed
`/attribution/install` with one id and `/events` with another (HEAD `9020007b`). Never visible on macOS — the live
gate runs on in-memory stores. Now: one process-wide `deviceIdLock` (all `SendoraStorage`s share one Keychain);
`SendoraSecureStore.addIfAbsent` (add-only, never delete-then-add; `.added | .duplicate | .failed(OSStatus)`, an
extension default for in-memory doubles); `.duplicate` → re-read and ADOPT the stored id; `.failed` (e.g.
`errSecInteractionNotAllowed` before first unlock) → `unsavedDeviceId` memo, reused and retried until a write lands
(a readable stored id always wins; `regenerateDeviceId` clears it). Same consumer trace after: ONE id across
install + events + batch on 4 of 4 fresh installs (`simctl keychain reset` + reinstall each time); relaunch restores
the same user. Key name unchanged (ADR-023). ⚠ A HOSTLESS `xcodebuild test` bundle has no keychain entitlement (every
add is -34018), so `test_realKeychain_…` skips there — the real-Keychain proof is the consumer-app run.
(2) Flaky `test_everyTransitionRowIsReplayed` on the simulator only (4/12 red, macOS 0/12): `TestJWT.make` serialised
the header/claims without `.sortedKeys`, so two tokens from the same claims could differ byte-wise. Test-only fix;
simulator 12/12 green after.
(3) `SendoraCloudPush.init` is `nonisolated` (it only stores constants; `configure()` builds it inside
`serialQueue.sync`, off main) and `accessTokenProvider` is `@Sendable` (internal init — no public API change). The
`SendoraCloud.swift:242` ActorIsolatedCall warning is gone; consumer-app `push.registerToken` → 201 after.
**Guards.** `DeviceIdTests.swift` (5; a Keychain-semantics double with widened read→add windows): 50 concurrent
callers on two storages → one id, persisted; injected duplicate → adopts; unwritable Keychain → one id, then that
same id is stored; regenerate; real Keychain (iOS, hosted only). `swift test` 108 (3 skipped: 2 live + real-Keychain),
simulator `xcodebuild test` 108 (3 skipped) 12/12 green, live `swift test --filter Live` 29/29 on macOS after the fix.
Mutations (`scratchpad/mutate570b.py`, backups `sdkios570_<M>_bak_<path>`, restored byte-identical), red / 107:

| # | Mutation | Red |
|---|---|---|
| M77 | the device-id lock removed | 3 |
| M78 | -25299 keeps its own unsaved id | 1 |
| M79 | the pre-5.7.0 get-then-set (no lock, overwrite) | 10 |
| M80 | no memo: an unwritable Keychain mints per call | 3 |

⚠ M77 is caught ONLY by the unwritable-Keychain test (3/3 runs): with the Keychain working, `.duplicate` → adopt
already yields one id, so the 50-caller test stays green without the lock. The lock is what keeps the memo path to one
id. ⚠ Not test-covered: the push isolation fix (a compiler diagnostic — verified by the build log, not a test).

## 5.6.0 — the response contract, client half (audit F67, backend s58.402; + adversarial review)

**What.** (1) `APIClient`: `Retry-After` (delta-seconds or HTTP-date, else `error.details.retryAfterSeconds`) on a
**503** holds the breaker that long (cap 1 h, `maxServerWait`); on a **429** the WHOLE-client hold is clamped to 60 s
(`rateLimitMaxHold` — review H2: the events quota 429 asks until the month resets and held `/token/refresh`, `/login`,
push for an hour, all month; Android clamps the same) while the full wait (≤ 1 h) still reaches the caller in
`RichResponse.retryAfterSeconds` / the stamped `details`. `cf-mitigated: challenge` holds ≥ 60 s and is delivered as
the TRANSPORT class (`statusCode == 0`, `cfMitigated`, `challengeStatus`; plain path → nil). Full-jitter backoff
`random(0, min(60, 2^n))` (seams `jitter`, `clock`, `breakerOpenUntil`). A 429 used to reset the breaker. Other 4xx:
never trip.
(2) `EventQueue` (outcome = `APIClient.DeliveryOutcome`): chunks ≤ 100 events AND ≤ 60,000 serialized bytes
(`maxChunkBytes`; `/events/batch` 413s over 64 KB); a lone event over the byte cap goes alone. 400 / 413 / 422 on a
multi-event chunk → BISECT (`bisectLimit`, halved, reset per flush); a single refused event drops. Other permanent
4xx (401 / 403 / 404 …) drop the chunk. `.retryLater(countsAttempt:after:)`: 408 / 5xx / 401 `IDENTITY_UNVERIFIED`
spend the per-event budget (`maxAttempts` 50, `_sendoraAttempts` in the persisted event, stripped before send);
offline / breaker / 429 / challenge do not. `after` = the server's wait → `holdUntil` (≤ 1 h): no flush starts
before it. Sent events are removed by IDENTITY (in-memory `Queued.id`) — positional removal deleted unsent events
when `add()` trimmed at `maxSize` mid-flight. `flushEvents` sends a single event > 30 KB to `/events/batch` (the
`/events` cap is 32 KB). `trackScreen` refuses names > 128 chars (eventType was already capped by `eventPattern`).
A 201 whose `data.rejected[i]` is an identity refusal (`code == "IDENTITY_UNVERIFIED"`, else a code-less row whose
`reason` contains "identity", case-insensitive — `APIClient.identityRejectedIndices`) → `.acceptedExcept(retry:)`:
those events stay, spend ONE attempt (answered-transient, like the identity 401) and are skipped for the rest of that
flush (`deferredThisFlush`, else they'd be resent at once until their budget ran out); every other row is removed, by
identity. "Unanswered" (never spends) = no response / transport timeout / 429 / challenge / Cloudflare 520–527 and
530 — the same set as RN / web / Android (408 is answered).
**Round 3 (second review).** The queue has its OWN full-jitter backoff (`applyBackoff`: `random(0, min(300 s,
1 s·2^(n-1)))` after EVERY retry-later, a server wait raises the floor, `noteSuccess` resets it); `performFlush` starts
nothing before `holdUntil`, including the flushes `add()` triggers past `flushAt` — events go through
`requestWithDetails`, which never trips the breaker on 500 / 502 / 504, so a 5xx outage re-sent the head chunk on every
`trackEvent`. Bisection is bounded: `bisectLimit` stays halved until a SUCCESS, then doubles back toward 100; one flush
makes at most `maxPostsPerFlush` (20) POSTs, then backs off. Three answered 5xx in a row on the SAME multi-event chunk
(by id set) halve it (`serverErrorBisectAfter`); a lone event follows the 50-attempt budget (it blocks the events behind
it until then — the normal head rule). The identity token is attached at SEND time (`EventQueue.decorator` →
`SendoraCloud.decorateForSend`: only on an event whose `userId` is the identified user), never stored, and counted in
the 60 KB cap. ⚠ Pre-existing, NOT changed: `saveEventQueue` strips `userId` and nothing restores it after a relaunch, so
a persisted event loses its user (and so gets no token).
(3) A challenge on any auth call is `.network` (retryable): never dead, never a wipe (choke point = `APIClient`).
(4) `knownDeviceToken`: `sendora_auth_known_devices` (Keychain, in `secureKeys`), `[{k: sha256(normalised email), t,
at}]`, newest 20, ≤ 2048. **Survives signOut AND the RESET row** (rule on all four SDKs); `deleteAccount` removes THAT
account's entry (`commitForgetKnownDevice`, email read before the DELETE). Writes only via +Commit (INV-1). Sent/saved
in `performSwitch` only (every `/login` goes through it); `/mfa/challenge` files under the `/login` address
(`pendingMfaEmails`, ≤ 8), else the response user's email. Never logged.
(5) Push: `Authorization: Bearer` when a session exists; the token lookup is bounded (`tokenTimeout` 5 s, `OnceGate`)
— then it registers without. (6) Links: `LinkCreateResult.revokeToken`; `sendora_link_revoke_tokens` (Keychain, 200);
`revoke(shortcode:)` sends it; `revoke(shortcode:revokeToken:completion:)` (NOT defaulted — a default makes
`revoke(shortcode:) { _ in }` ambiguous) → `LinkRevokeResult { shortcode, final }`; forgotten on 2xx, kept on 403.
(7) `support.getUnreadCount` → `APIClient.get` (was `URLSession.shared`).

**Why.** Backend s58.402 guarantees the wait; Cloudflare challenges reached the auth taxonomy as 403
`invalidCredential`; a poison event wedged the queue forever; F23 / F53 / F34 need the device to send the proof.

**Guards.** `ResponseContractTests.swift` (24) + `SurfaceHardeningTests.swift` (12); harness `StubResponse` gained
`headers` / `rawBody`. `swift build` + `swift test` **93 / 93** (Swift 6.4), iOS-Simulator `xcodebuild` green.
Mutations (`scratchpad/mutate560b.py`: cp backup → edit → `swift test` → restore → byte-compare), all red
(failures / 93, the whole set re-run after round 3; backups named `sdkios560_<M>_bak_<path>`):

| # | Mutation | Red |
|---|---|---|
| M01 | 429 records success (breaker reset) again | 7 |
| M02 | ignore the Retry-After header | 13 |
| M03 | ignore details.retryAfterSeconds | 2 |
| M04 | no 1 h cap on the server wait | 2 |
| M05 | a challenge does not hold the breaker | 1 |
| M06 | details path delivers a challenge as its 403 | 9 |
| M07 | plain path hands the challenge body to the caller | 1 |
| M08 | fixed doubling instead of full jitter | 8 |
| M09 | a plain 4xx trips the breaker | 8 |
| M10 | queue: 429 counted as delivered | 3 |
| M11 | queue: permanent 4xx retried (old behaviour) | 25 |
| M12 | queue: rejected chunk kept at the head | 20 |
| M13 | queue: no per-event attempt cap | 3 |
| M14 | queue: offline / challenge spend the budget | 3 |
| M15 | queue: budget field sent on the wire | 1 |
| M16 | queue: chunks of 1000 | 1 |
| M17 | knownDeviceToken never sent | 3 |
| M18 | knownDeviceToken cleared by signOut | 8 |
| M19 | email not normalised | 3 |
| M20 | MFA token not filed under the /login address | 1 |
| M21 | RESET row clears the known-device token | 1 |
| M22 | email stored in plaintext | 1 |
| M23 | no 20-account cap | 5 |
| M24 | push registered without the Bearer | 1 |
| M25 | links: revokeToken not persisted | 3 |
| M26 | links: stored token not sent | 1 |
| M27 | links: token not forgotten on success | 2 |
| M28 | links: `final` not read from the answer | 1 |
| M29 | links: no 200 cap | 5 |
| M30 | support badge back on URLSession.shared | 5 |
| M31 | a 429 holds the whole client for the full wait | 3 |
| M32 | no 60 KB chunk cap | 3 |
| M33 | no bisection of a refused multi-event chunk | 7 |
| M34 | bisect every 4xx (incl. 401) | 2 |
| M35 | 401 IDENTITY_UNVERIFIED treated as permanent | 1 |
| M36 | sent events removed by position | 6 |
| M37 | queue ignores the server wait | 14 |
| M38 | deleteAccount keeps that account's token | 1 |
| M39 | deleteAccount removes every account's token | 1 |
| M40 | push waits for the token forever | 2 |
| M41 | 201 identity rows treated as delivered | 6 |
| M42 | no reason fallback for a code-less row | 5 |
| M43 | reason fallback case-sensitive | 5 |
| M44 | kept identity rows spend no attempt | 1 |
| M45 | kept identity rows resent in the same flush | 5 |
| M46 | partial 201 keeps the whole chunk | 2 |
| M47 | row code ignored (reason decides) | 3 |
| M48 | queue has no backoff of its own | 14 |
| M49 | backoff not reset by a success | 1 |
| M50 | no 300 s backoff cap | 2 |
| M51 | a server wait does not raise the backoff floor | 1 |
| M52 | decorator never applied (no send-time token) | 1 |
| M53 | token on any user's event | 1 |
| M54 | decoration not counted in the byte cap | 1 |
| M55 | no 5xx bisection | 2 |
| M56 | 5xx bisection on the first failure | 1 |
| M57 | halved cap reset every flush | 2 |
| M58 | halved cap never doubles back | 1 |
| M59 | halved cap jumps straight back to 100 | 1 |
| M60 | no per-flush POST cap | 2 |
| M61 | Cloudflare 52x / 530 counted as answered | 9 |
| M62 | a nil `projectId` serialised as `null` on events (/ 96) | 2 |
| M63 | install report builds `projectId` from the optional again (/ 96) | 1 |

**LIVE run against STAGING (`Tests/SendoraCloudTests/LiveStagingTests.swift`).** Skipped unless `SENDORA_LIVE=1`
(offline `swift test` = 96, 1 skipped). Real `URLSession` (the SDK's own session config), real `APIClient` /
`EventQueue` / `SendoraCloudAuth` / `SendoraCloudLinks` / `SendoraCloudPush`; in-memory stores (no Keychain). Host
pinned to `api-dev.sendoracloud.com`; key from `SENDORA_PK`, refused unless `pk_dev_`; the recorder keeps statuses,
counts, sizes and response-header values only. Run:
`set -a; . ../../.env.e2e.local; set +a; SENDORA_LIVE=1 swift test --filter LiveStagingTests`.
10/10 PASS (2026-10-18): 250 events → 3 × 201 (100/100/50, max 36 KB); 12 × 8 KB → 2 posts (57.9 KB, 41.4 KB); one 70 KB
event → `201/10, 413/1, 201/10`; one 200-char eventType → bisected `422/21 … 422/1` then 201s, 20/20 accepted, 10
posts; signUp→signIn sends `knownDeviceToken`, SHA-256-keyed, RESET keeps it, `deleteAccount` 200 `purged` removes
it; push 201 with Bearer; link create → `revokeToken` stored → revoke sent it → 200 `final: true`; a real ingest 429
(`RateLimit-Policy: "ingest";q=200;w=60`, `Retry-After` 1–2 s) → no POST inside the wait, 0 attempts, refresh out in
1 s, delivered after 2 s.
**Live-run gate (contract 2, `scripts/e2e/live-run-contract.mjs`; suite `swift test --filter Live`).**
`LiveLifecycleTests.swift` ports `scripts/e2e/auth-lifecycle.mts` (A1–A7, B1–B5, W1-a/b/c/d/g/g2/e, B8, B9) onto the
iOS public API over a COOKIE-KEEPING `URLSession` (`.default` + its own `HTTPCookieStorage` — the phone condition;
W1-a asserts the jar holds the ACCOUNT's `sd_rt`); `LiveStagingTests` reports T1–T7. `LiveReport.swift` (shared) =
the guard (`LiveEnv.require`: `SENDORA_LIVE=1`, host `api-dev.sendoracloud.com` only, no `pk_|sk_(prod|live)_`) and the
result file (`SENDORA_LIVE_RESULT`, rewritten after every step; `sdkReportedVersion` = `SendoraCloud.sdkVersion` at
runtime; details scrubbed of JWT / key / email shapes). Fail-fast per step like the reference; created accounts are
deleted. Run 2026-10-19: **28/28 required steps pass**, `judgeLiveRun` ok. iOS readings: W1-g's 409 `CONFLICT`
surfaces as the frozen pre-4.13 case `.emailAlreadyTaken` (no `code` / `status` on that case — by design, though the
`status` doc comment "nil when the request never reached the server" over-promises); B8 uses a fresh instance (iOS
has no cross-instance rehydrate after W1-e's `discardWithheld`). T4 needs continuous raw pressure (a fresh client per
request — one client's own breaker stops at the first 429) because staging's ingest lane refills ~3.3/s.
⚠⚠ **Bug the live run found (every earlier test was green): a nil `projectId` went out as JSON `null`.** `projectId`
is optional since 3.0.0; a nil `String?` in `[String: Any]` bridges to `NSNull`, and the schema is
`z.string().uuid().optional()` — absent passes, `null` is `422 events.0.projectId: Expected string, received null`.
So an app configured with the key only NEVER delivered an event (≤ 5.5 retried them forever; 5.6.0's
permanent-refusal rule would have bisected and DELETED all of them — the first live run did exactly that, 260 POSTs
for 250 events). Fixed in `buildEvent` (now the one event builder, used by `trackEvent` and the live test),
`/attribution/install` and `/attribution/deferred`. Guards `test_anEventWithoutAProjectIdOmitsTheField_neverSendsNull`
(behavioural) + a source pin on the two body literals. ⚠ Lesson: a stub transport accepts any body; only a real
server's zod schema could see this. ⚠ The 60 s whole-client 429 clamp was NOT exercised live with a long wait
(staging's ingest Retry-After was 1–2 s); it is unit-tested only.
⚠ M01–M61 ran before the live test existed (93 tests, no skip); M62/M63 against 96 with the runner's regex fixed to
read "with 1 test skipped and N failures" (the old regex silently read a per-suite line — "0 failures / 12").
⚠ M21's first form (forget AFTER `commitClear`) was a no-op mutation and stayed green — `current` is already nil
there; re-run inserted before the clear → red. ⚠ Not test-covered: the `trackScreen` 128-char guard and the
> 30 KB single-event routing (both need `configure()`'s static state). ⚠ A one-off extra red on
`test_everyTransitionRowIsReplayed` under a loaded machine did not reproduce; M18's conformance hit is real.

## 5.5.0 — Support parity with RN 1.42.0 (s58.376)

`SendoraCloudSupport.swift` is now split: the API half compiles on EVERY platform (so `swift test` on macOS covers
it) — `createTicket` / `listMyTickets` / `getMyTicket` / `replyToMyTicket` (`async throws`, through the configured
`APIClient`; refusals → `SendoraSupportError`), `deviceContext()` (CFBundle version + build, `UIDevice` OS version,
`utsname` machine id, SDK), `sanitizeMetadata` (sorted keys → deterministic cap), `contactURL` (token + metadata in
the FRAGMENT, strict `-._~` encoding so `&`, `=`, `+` survive `URLSearchParams`). The hosted screens stay in a
`#if canImport(UIKit)` `@MainActor` extension; `presentContactWidget` gained `metadata:` / `includeDeviceContext:` /
`attachSession:` / `accent:` (defaulted, before `completion:`), `presentTicketHistory` `accent:`.
⚠ `SendoraCloud.support` was built with hardcoded production URLs — a staging config polled the PROD API. Now
`SendoraCloudSupport(apiBaseUrl: config.apiBaseUrl, client:)`, on every platform. The class is no longer
`@MainActor` (only the present methods are) — `getUnreadCount` is callable off the main actor.
Verified: `swift build`, `xcodebuild -scheme SendoraCloud -destination 'generic/platform=iOS Simulator' build`,
`swift test --filter SupportTests` 8/8 (stub transport via `APIClient(transport:)`); mutations all red (token
dropped, refusal swallowed, no-session check, key check, accent check, token in the query).

## 5.4.2 — held-slot refresh identity tripwire (parity RN 1.41.2, s58.360)

Full write-up in the RN CLAUDE.md 1.41.2 section. A held guest's refresh must come back for that guest;
a response for anyone else → `HELD_GUEST_IDENTITY_MISMATCH` before the slot write (claim: no `/merge`;
restore: nothing installed, slot kept). Also: `APIClient.makeSessionConfiguration()` (a test seam) turns cookies off — an ephemeral session still keeps an in-memory jar. `swift build` + `swift test` 49/49 on this Mac (Swift 6.4); tripwire mutation → 10 failures.

## 5.4.1 — dead session is `.sessionExpired` again; server detail in `lastSignedOutEndReason()` (set under the lock BEFORE `emitAuthState`, like `lastSignedInCause()`; the enum payload is frozen) (RopoLabs, 2026-10-10)

5.4.0 mapped the B11 `endReason` onto `signed_out.reason` (`revoked` / `deleted`). Those are two
OLD situations ("account deleted elsewhere", "sessions revoked") that 5.3.0 reported as
`.sessionExpired`, so a listener matching `.sessionExpired` stopped seeing them — RopoLabs' template
(`auth-store.ts:665`) and our own `/docs/auth-errors` example both did. ⚠ **A new union value is
additive only for a NEW situation; re-labelling an existing one is a behaviour change**
(ADR-023), even though it compiles. Fix: `reason` is `.sessionExpired` for EVERY dead verdict; the
detail is `lastSignedOutEndReason()` (set under the lock BEFORE `emitAuthState`, like `lastSignedInCause()`; the enum payload is frozen). The three values stay in the type (never emitted) so 1.41.0-era code compiles.
Shared table row `refresh_dead.current` now emits `signed_out{reason:'session_expired', endReason}`.
Guard `scenario_refresh_dead_current` (reads the accessor INSIDE a listener; limbo death; signOut resets it); mutations: map revoked/deleted back onto `reason` → 2 red; drop the endReason → 7 red; set the accessor AFTER delivery → 6 red.

## ADR-033 wave 1 (5.4.0) — "One Slot, Two Verbs": held guests, single commit, project guard

Law: `docs/decisions/033-sdk-auth-mechanism.md` §3.2–§3.5, §5 wave 1 (a)–(f); the table is
`packages/shared/src/auth-machine/transitions.ts` and this port is an INTERPRETER of it. Lockstep:
RN 1.41.0 / web 3.24.0 / Android 4.26.0. Backend contract = prod `7aa740a0` (B1–B17). Not yet
mirror-published; the mirror tag is operator-gated behind the staging live-run marker (B9).

**The machine.** Five states (`SendoraCloudAuthStatus`: `unknown | signedOut | anonymous | identified
| withheld`; NORMATIVE default-branch, `status()` is the only way to tell `withheld` from `signedOut`).
Files:
- `SendoraCloudAuth.swift` — public types + the class core: hydrate (read-first `sendora_auth_session`,
  the four frozen keys as the authority on WHETHER a session exists — after a downgrade→upgrade cycle
  they are the fresher source, so a differing legacy refresh token rebuilds the record and
  write-forwards; the record is trusted ONLY when its refresh token equals the frozen one — a record
  with no frozen counterpart is a downgrade-cycle LEFTOVER and is cleared silently, see below), the token layer (`performRefresh` → `routeRefreshResult` by the SENT token, the
  s58.281 two-deadline rule unchanged, `forceRefresh` now really bypasses the stashed-token
  short-circuit), listeners, the Bearer session verbs, parsing. `revokeSession` / `revokeAllSessions`
  / `listLinkedIdentities` / `onDeviceTakeover` / `fireLifecycleSignals` MUST stay in this file —
  `auth-error-kind-parity`, `identities.test.ts`, `credential-collision.test.ts`,
  `anon-retirement.test.ts` and `sdk-contract-golden` read it by name (the golden needs the first
  `"/auth-service/token/refresh"` literal followed by `data["tokens"]` — no optional chaining there).
- `SendoraCloudAuth+Commit.swift` — **`commit*`, the ONLY writer** (INV-1): every assignment to
  `current` / `limbo` / `withheldState` / `slots`, every Keychain write, cron arm/stop and parent hook.
  `commitInstall` = sid-CAS or sent-token CAS → `projectVerdict` → dual-write (four frozen keys +
  record, schema → `"2"`) → cron → `onIdentityChange`. `commitClear` is the one local-first exception.
  Source guard: `test_authStorageKeyNamesAppearOnlyInStorageSwift` (no `"sendora_auth_` literal outside
  `Storage.swift`).
- `SendoraCloudAuth+Engines.swift` — one engine per event family (`performSwitch` / `performLink` /
  `performMint` / `performRestoreCore` / `performClaim` / `performDiscard` / `refreshHeld`), all ON
  `opsQueue`, all awaiting an in-flight refresh at start (and at commit for a switch), all handing a
  PROPOSAL to the funnel. `installSwitchResponse` is shared with passkeys + SSO
  (`completeExternalSignIn`). No engine assigns state.
- `SendoraCloudAuth+Verbs.swift` — the public verbs: every pre-5.4.0 signature unchanged; `signUp`
  routes by status (anonymous → `/me/link/email`, never `/upgrade`; signedOut → `/signup`; identified →
  local `.alreadyIdentified`; unknown → settle); the legacy wrappers map typed outcomes onto their
  historical shapes (`signUp` keeps `.emailAlreadyTaken` for the 409; `link:true` over identified
  THROWS `.credentialInUse` / `RECENT_AUTH_REQUIRED`, `alreadyLinked` resolves quietly).
- `Internal/AuthMachineTypes.swift` (status / cause / reason enums, `SendoraCloudCredential`,
  `SendoraCloudSignInResult`, `SendoraCloudLinkResult` with `SendoraCloudCredentialInUse.switchAccount(refetch:)`
  + `keepCurrent()` as METHODS, `SendoraCloudMfaChallenge.verify(code:)`, the `AuthSessionRecord` and
  `HeldSlotRecord` disk shapes), `Internal/ProjectVerdict.swift` (verbatim port, own base64url + strict
  UTF-8 decoder, no signature check; absent claim = `unknown`, explicit null = `mismatch`).

**Keychain.** Four frozen keys unchanged (a 5.3.0 reads them after a downgrade) + `sendora_auth_session`
(dual-written on every install, carries `sid` and the B15 `heldReportPending` list — never held
material) + the K = 5 FIXED slots `sendora_auth_held_0…4` (LITERAL names in `Storage.heldSlotKeys`;
`Storage.secureKeys` is the closed allow-list the recording double enforces — a per-guest dynamic key
fails the suite). Slot record = shared `HeldGuest` v1 (`project` encoded as explicit JSON null). An
unreadable slot is KEPT and ignored, never cleared. `sendora_auth_mint_key` (UserDefaults) is the B10
per-attempt idempotent mint key, cleared on MINT_OK or a fresh-mint mismatch.

**Hooks to the parent.** `onIdentityChange(id)` (unchanged); `onIdentityCleared(ClearEffects)` replaces
`onAnonymousWipe(Bool)`: rotate the device id ONLY on `signOut` / `deleteAccount` (and the internal RESET
row); drop the queue ONLY on `deleteAccount` (the table — 5.3.0 dropped it on EVERY wipe, incl. a
sign-in that replaced a guest and a session death);
`onIdentityWithheld()` nulls `currentUserId` in memory only. ⚠ `configure()` now builds the auth
surface AFTER `serialQueue.sync` — the hydrate hooks `sync` that queue, and nesting them was a
deadlock for any launch with a cached session.

**iOS readings of the ADR (document, do not re-litigate):**
- `signedIn.cause` cannot ride the frozen `case signedIn(user:)` payload (adding an associated value
  breaks `case .signedIn(let user)` at every call site) → `lastSignedInCause()`, set before the emit.
- The subscribe-time replay is `.initial(...)` AND the pre-5.4.0 `.signedIn(user:)` replay (dropping
  the latter would break installed Home-on-signedIn listeners).
- `unknown` queues MINT / SIGN_IN / LINK / RESTORE by driving the gap-fill refresh inline
  (`settleUnknownIfNeeded`); offline the verb fails `.network` (retryable) instead of hanging a
  completion forever. ⚠ **Known divergence from RN** (which keeps such verbs queued until the status
  settles): both never mint and never wipe in `unknown` — the iOS one returns a retryable error the
  app can re-issue, RN holds the promise. Not destructive; kept deliberately. `getAccessToken()` in `unknown` drives the gap-fill too, with the stashed access
  token as the offline fallback. CLAIM / DISCARD / `discardWithheld` are NOT queued (rows
  `claim.identified_only`, `discard.held_guest`).
- Restore emission order is ONE order on every path (the regenerated fixture, lockstep): install, then
  `signedIn` (`lastSignedInCause() == .restore`), then `guestReleased(.restored)` as the slot goes —
  MINT auto-restore, `restoreHeldGuest()` and restore-over-a-guest alike (mutation M31).
- A fresh response whose claim is unreadable installs (not a mismatch); hydrate / gap-fill with an
  unreadable claim stay `unknown` (persisting a rotation only).
- `onCredentialInUse` on a PLAIN sign-in is accepted and ignored (no hint is sent, so the server cannot
  refuse a collision; the guest is held, never deleted). `.adopt` is consulted only on a `link:true`
  409, where it falls through to a sign-in bound to the same credential.
- `switchAccount(refetch:)`: the SDK has no GameKit dependency, so after 5 minutes the APP re-fetches
  and the SDK compares `teamPlayerID` (`credentialChanged` on mismatch); without `refetch` a stale
  payload is refused.
- `signOut()` in `unknown` clears the limbo keys + revokes; in `signedOut` it is a quiet no-op (both
  `UNSPECIFIED_BY_ADR`).
- **`SendoraCloud.reset()` keeps its 5.3.0 semantics (lockstep ruling 2): iOS is the "reset() never
  signed out" case.** It has always reset ONLY the analytics identity (user id, device id, session id)
  — no auth session, no Keychain tokens, no event queue (RN/web `reset()` always signed out). So the
  ADR RESET row has no public entry on iOS: `resetFromParent(includeHeldGuests:)` implements it for
  the conformance replay only, and the public `reset(includeHeldGuests:)` overload accepts the flag for
  parity and ignores it (held guests are released only by the explicit verbs).
- **Subscribe replay (lockstep ruling 1):** `onAuthStateChanged` replays `.initial(status:user:withheld:)`
  and THEN — when a session exists — the 5.3.0 `.signedIn(user:)`, per subscriber; no session →
  `.initial` only. Pinned by `test_subscribeReplaysInitialThenTheLegacySignedInWhenASessionExists` +
  `…OnlyInitialWithoutASession` (mutation M27).
- **Downgrade cycle (lockstep, RN-found):** a 5.3.0 `signOut()` / `deleteAccount()` clears only the
  four frozen keys, so the 5.4 record survives 5.4→5.3→sign-out→5.4. Hydrate trusts the record ONLY
  when `record.refreshToken == frozen refresh`: no frozen refresh → the record is cleared with the
  stale blob (`signedOut`, boot `initial` only, no network); a different frozen refresh in LIMBO_A →
  the record is dropped (`commitHydrateLimbo(clearLeftoverRecord:)`); `writeRotationOnly` rotates the
  record only when it belongs to the same session, else drops it (a withhold-on-refresh must not
  graft C's tokens onto A's user). Frozen keys are written BEFORE the record (`writeCurrentRecord`).
  Mutations M28–M30, M32.
- **Passkey + OIDC take the identity CAS when the sheet OPENS** (`externalAttemptStart()` →
  `completeExternalSignIn(startedFrom:)`): a result landing after a `signOut()` / switch made during the
  native sheet is dropped + revoked (row 19). Before this the CAS was snapshotted when the response
  arrived, which compared the state with itself (mutation M24). A standalone callback with no known
  start snapshots at arrival.
- **5.3.0 declarations kept verbatim:** `deleteAccount(completion:)` and `SendoraCloud.reset()` are
  separate overloads, not defaulted parameters (an unapplied reference to either still compiles —
  `test_preWaveDeclarationsAreStillThere`).
- B15: a pending `/guest/held` report is retried on the next hydrate, never in `withheld` (no network
  of any kind there).

**Guards.** `Tests/SendoraCloudTests/AuthMachineConformanceTests.swift` (+ `AuthMachineRowScenarios*.swift`,
`AuthTestHarness.swift`): loads `packages/shared/src/auth-machine/auth-transitions.conformance.json`
by path (never copied), replays ALL 36 transition rows (a fixture row without a scenario fails) and
all 19 verdict cases (the 5 transition-context cases drive the install path), and pins the constants
(slot keys, dead codes, release reasons, withheld reject list, states). Doubles: recording Keychain /
UserDefaults + a scripted transport with per-path one-shot gates (the "refresh rotates during the
native sheet" interleaving) + a frozen-clock seam (`MachineConfig.clock`).
`AuthMachineBehaviourTests.swift`: §5 integrator test 10 (two guests → count 1 then 2, newest first),
two holds at a frozen clock never tie, the B15 report retry (and none in `withheld`), the native-sheet
CAS, the subscribe replay (ruling 1), the downgrade-cycle leftover record (three shapes), frozen keys
written before the record, the 5.3.0 declarations. `SendoraCloudAuthErrorTests.swift`: the taxonomy +
the FORMER source-text pins rewritten behaviourally. `swift test` **46 tests, 0 failures**
(13 behaviour + 8 conformance + 16 error-taxonomy + 9 validator). Scenario files never force-unwrap
an event / write index (`h.event(at:)`, guard-let) — a crash would abort every scenario after it and
hide the real failure count (it did, under M05/M08, before this was fixed).

**Mutation record (each: `cp` backup → apply → `swift test` → `cp` restore → anchor grep-proven both
ways; scripts `scratchpad/mutate.py` (M01–M21) + `scratchpad/mutate-w1b.py` (M22–M33); final run
against the 46-test suite, no crashes):**

| # | Mutation | Red (assertions) |
|---|---|---|
| M01 | delete the sid-CAS (engine guard AND `commitInstall`) | 9 |
| M02 | re-add `prevAnonRefreshToken` to the sign-in body | 4 |
| M03 | mint in `unknown` (drop the settle) | 4 |
| M04 | second `signedIn` on upgrade via `link()`/`link*()` | 1 |
| M05 | drop the dual-write (four frozen keys) | 20 |
| M06 | delete the await-refresh-before-hold (start + commit) | 3 |
| M07 | route `link:true` + identified to `/login` | 1 |
| M08 | build a held key name dynamically (per guest) | 26 |
| M09 | RESET row default wipes held | 3 |
| M10 | no-arg destructive verb with 2 held | 4 |
| M11 | mint at T == K | 3 |
| M12 | dead newest slot aborts `ensureSession()` | 1 |
| M13 | claim without persisting the rotation into its slot | 4 |
| M14 | release held on `reuse` / absent `endReason` | 12 |
| M15 | auto-restore after `account_deleted` | 4 |
| M16 | delete the withheld gate on the access-token getter (+ snapshot) | 2 |
| M17 | `signUp` reads the refresh key in `withheld` | 1 |
| M18 | evaluate the verdict only at hydrate | 15 |
| M19 | treat an absent claim as `match` | 10 |
| M20 | write `auth_session` in a withheld hydrate | 2 |
| M21 | resolve `withheld` via RESET / wipe a slot on `discardWithheld` | 5 |
| M22 | drop the `switchAccount` credential comparison | 1 |
| M23a | revoke the session on `alreadyLinked` (client side) | 1 |
| M23b | emit `userUpdated` on `alreadyLinked` | 1 |
| M24 | snapshot the passkey/OIDC CAS at the response, not the sheet opening | 5 |
| M25 | retry the hold report in a withheld hydrate | 1 |
| M26 | never retry a pending hold report on hydrate | 3 |
| M27 | drop the legacy `.signedIn` subscribe replay | 9 |
| M28 | reinstall from a record whose frozen keys are gone (downgrade cycle) | 12 |
| M29 | keep a mismatched record in LIMBO_A | 1 |
| M30 | rotate any record on a withhold rotation | 2 |
| M31 | auto-restore emits `guestReleased(.restored)` before `signedIn` | 5 |
| M32 | write the record before the frozen keys | 4 |
| M33 | let two holds tie on `heldAt` | 4 |

(A first M01 that deleted only the engine guard stayed GREEN — `commitInstall` re-checks the CAS, so the
mutation had to remove both. "1" rows are scenarios that `guard … else { return XCTFail }` at the first
divergence. ⚠ An earlier version of this table recorded several rows as "then the suite crashed": the
runner's regex only matched the plural "failures", so a 1-failure run was misread as a crash; the
two real crashes (M05/M08, a force-unwrapped write index) are fixed in the scenarios.)

**Pins converted (source-text → behavioural):** `test_signInPathsDelegateTheWipeToTheSuccessBranch`,
`test_replacementWipeIsAlwaysImmediatelyFollowedByPersist` → `test_aFailedSignInLeavesTheCallerExactlyAsFound`
(byte-identical Keychain across six paths × five failures) + `test_noSignInBodyCarriesTheGuestHint`;
`test_anonymousSignInReusesTheExistingSessionBeforeMinting`, `test_refreshRecoversAnIdentityItDoesNotHave`,
`test_rateLimitIsNotADeadRefreshToken` → driven on the real machine.

**Upgrade / downgrade.** 5.3.0 → 5.4.0: first launch reads the four keys, writes `sendora_auth_session`
+ schema `"2"`, no network, same status. 5.4.0 → 5.3.0: the four keys are current, the session
survives; the slots are ignored (orphans server-side, readable again on re-upgrade); a 5.3.0 `signOut`
clears the four keys only, which the 5.4.0 hydrate treats as signed-out (keys are the authority).

**Known gaps / for the caller:** `linkEmailSchema` is `email` + `password` only, so `signUp(name:)`
from a guest drops `name` (backend follow-up). Play Games is Android-only — `SendoraCloudCredential` has no
`playGames` case.


## 5.3.0 — signInAnonymously() over an identified session is a no-op (RopoLabs A2, parity RN 1.40.0)

Full write-up in the RN CLAUDE.md 1.40.0 section. The reuse guard
(`SendoraCloudAuth.swift` `signInAnonymously`) required `user.isAnonymous`, so over a LIVE
ACCOUNT session it fell through, minted a guest and persisted over the account's Keychain
tokens with no state event. The `user.isAnonymous` clause is dropped: an identified session
with a refresh token in the Keychain is returned as-is; `forceNew: true` is the single
explicit replace. All four SDKs carried the identical guard and ship the fix in lockstep
(RN 1.40.0 / web 3.23.0 / Android 4.25.0). Version in `SDKVersion.swift` only (5.3.0).
⚠ No Swift compile gate exists in this repo — `swift build` + the on-device smoke are the
operator's pre-mirror step, as with every native release. ⚠ Not yet mirror-published.

## 5.2.0 — no device fingerprinting (App Store compliance, SudokuHurdle)

**Removed the capability, not just gated it.** `FingerprintGenerator` (which hashed
`model|osVersion|screen|locale|timezone`) is **deleted**, and the SDK no longer
computes or transmits a device fingerprint anywhere. This closes the silent,
default-on exposure the research flagged: `configure()` (with the default
`autoStartAttribution = true`) used to compute a fingerprint at init and POST it to
`/attribution/install` **on first launch, before any ATT prompt**, bypassing the
consent queue. Apple prohibits deriving a device identifier from device signals for
attribution (App Store 5.1.2 / DPLA §3.3.9) regardless of ATT, and App Review actively
rejects on it.

- The auto install report (`reportInstallIfNeeded`) now carries deterministic signals
  only — `deviceId`, `appVersion`, `os`, `osVersion`. **`autoStartAttribution` stays
  `true`** deliberately (it also gates `trackSessionStart()`, which fires inside the
  same guard while `session.ended` fires outside it — flipping the default would
  silently kill session-start analytics).
- `/attribution/deferred` drops the fingerprint too (it matched on fingerprint
  equality only — no IP fallback — so it now transmits nothing device-derived and
  simply won't match on that path; use `SendoraCloud.links?.matchDeferred` for
  deferred routing, and note iOS has no deterministic deferred signal — see RN 1.37.0).
- ADR-023 safe: no frozen key/header/route touched; a body field was removed, which the
  backend already treats as optional. `swift build` clean.

⚠ Parity: RN shipped the `matchDeferred` half in 1.37.0; **Android 4.23.0** ships this
native removal in lockstep. Publish + on-device smoke before release.

## 5.1.0 — deviceId survives identify/upgrade (SudokuHurdle r6)

Parity with RN 1.38.0 (full write-up there). The device (anonymous analytics) id
rotated on EVERY auth transition — including the anon→identified upgrade where the
server preserves the `sub`. It now survives identify/upgrade and rotates only at a
person-boundary. `onAnonymousWipe` gained a `Bool` (rotateDeviceId);
`wipeLocalIdentity` passes `true` only for `.signedOut(.user)` / `.signedOut(.accountDeleted)`,
so `.replaced` (sign-in/upgrade) and `.sessionExpired` clear the userId but KEEP the
`deviceId` (same person → pre-auth analytics link to them), while an explicit
`signOut()` and the public `reset()` still rotate it (shared-device isolation:
`coalesce(user_id, anonymous_id)` makes the anon id the identity only while signed
out). ADR-023 safe: the `sendora_*` Keychain key is unchanged, only the value's
regeneration frequency drops. Alias/merge stays server-authoritative
(`prevAnonRefreshToken` → `user_upgraded`/`user_merged`). `swift build` clean.
⚠ **Separate pre-existing note (NOT changed here):** the `deviceId` is Keychain-stored
with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so it survives REINSTALL —
more persistent than the industry norm (FID/Amplitude die on uninstall) and the one
thing Apple pushes back on. That's orthogonal to this change; revisit separately.

## 4.18.0 — getLastAnonRetirement(): did my guest account survive? (s58.278)

Parity: RN 1.33.0 / web 3.17.0 / Android 4.18.0. Additive; no behaviour change to any existing call.

`retiredAnonUserId` is present-or-absent, and the absence covered two
situations that need opposite handling: the guest account was retired but not
named, versus nothing was retired and the guest is still alive and claimable.
A customer hit exactly that — saw no `retiredAnonUserId` after an adopt and
had to ask us which it was, because it is not answerable from outside (the
device-takeover's no-ops are silent by design).

Sign-in responses now carry `anonRetirement`, and `getLastAnonRetirement()`
returns the last value (cleared on sign-out):

- `retired` — the guest row was deleted; its id arrives via `onDeviceTakeover`.
- `preserved` — a guest token WAS sent and the guest was NOT retired. That
  account still exists, so "recover your other account" is a real offer.
- `none` — no guest token was sent; nothing to reconcile.

⚠ The value is recorded ONLY when the server states it. An older backend omits
the field entirely, and treating that as `none` would assert a fact we were
never told — absent and `none` are different answers.

⚠ The third case is named `nothingToRetire` (wire value `"none"`), NOT `none`.
A Swift enum case called `none` collides with `Optional.none`, so
`outcome == .none` would be ambiguous between "no guest was presented" and "no
value at all" — reintroducing the exact conflation this field removes.

## 4.17.0 — the collision default is now safe by construction (s58.274)

Parity: RN 1.32.0 / web 3.16.0 / Android 4.17.0. **Behaviour change to the DEFAULT** — see below for who it affects (in practice: nobody with real users).

`onCredentialInUse` shipped in the previous release with a default of `adopt`, kept
for compatibility. That was the wrong call: the destructive path was what you got by
not knowing the option existed, and it succeeded silently, so there was no error to
prompt a second look. The next integrator would have had to lose an account to learn.

**The hazard was never "a collision happened" — it is "a collision happened AND
adopting would DELETE a live guest account on this device".** Those deserve different
answers, and now get them:

- **Fresh install / no guest session** → nothing to lose, so it adopts. This is the
  reinstall-recovery path, and it is never refused.
- **Live guest session** → adopting would retire it (row deleted). Refused with
  `CREDENTIAL_IN_USE` so the app can ask the player.

So the safe behaviour is now the behaviour, and `onCredentialInUse` becomes a pure
override: `"adopt"` to switch anyway (the old semantics), `"reject"` to fail on any
collision at all.

⚠ **If you relied on silent adopt** — i.e. you consume the device-takeover signal to
migrate progress on a returning player — pass `onCredentialInUse: "adopt"` explicitly.
Everything else is unchanged: the adopt path still retires the row and still fires the
takeover webhook.


## 4.16.0 — onDeviceTakeover doc fix: the account-deleting paths were missing (s58.273)

Parity: RN 1.31.0 / web 3.15.0 / Android 4.16.0. **Documentation-only in the SDK; no behaviour change.**

Customer-reported (Word Hurdle). The doc comment on `onDeviceTakeover` enumerated
where the listener fires — signIn / loginSocial / verifyMagicLink / verifyEmailOtp
/ challengeMfa / passkey / SSO — and **omitted the Game Center and Play Games
paths, the only ones that can DELETE an account.** It does fire there (centrally,
from the persist path), so this was purely a doc defect; but an integrator reading
that list would reasonably conclude a gaming adopt produces no takeover and skip
the one handler that path most needs. That is the path that destroys accounts.

The comment now names the gaming sign-ins explicitly and states the consequence:
a takeover means the anonymous account was retired — its row DELETED server-side
— while **the call itself resolved successfully**, so this listener is the only
client-side signal. It also points at `onCredentialInUse: reject` for callers
who would rather it not happen.

Guarded so the list cannot drift again: `credential-collision.test.ts` asserts
each SDK's doc block (the 1600 chars immediately above the declaration, not the
whole file) names its gaming path. Mutation-proven — redacting the tokens from
all four doc windows fails 4.

## 4.15.0 — credential-collision policy + anonymous link promotion (s58.272)

Parity: RN 1.30.0 / web 3.14.0 / Android 4.15.0. Full write-up in the RN CLAUDE.md 1.30.0 section.

- **`onCredentialInUse` (`adopt`|`reject`)** on the credentialed sign-in
  methods. **Omitted = adopt = every prior release** (no field is sent). On a
  collision the sign-in ADOPTS the owning account and — because the anon refresh
  hint is forwarded whenever the local user is anonymous — the server hard-deletes
  this device's anonymous row. That is a 200, so the wipe-ordering fix never
  covered it. `reject` fails with the credential-in-use error and changes nothing.
- **The collision error carries the taxonomy** (`kind`/`retryable`/`code`/`status`)
  plus `provider` + `collision` (`identity`|`email`).
- **Linking from an ANONYMOUS session** promotes the account in place (sub
  preserved) and the server ROTATES the session, because the `is_anonymous` JWT
  claim changed. The link path installs the returned `tokens` when the response
  carries `upgraded: true` — **not optional**, the old refresh token is revoked
  server-side. An identified link is unchanged (no tokens, cached user updated in
  place). Firebase `linkWithCredential` / Supabase `linkIdentity` parity.

`SendoraCloudAuth.CredentialCollisionPolicy` is a defaulted (`nil`) parameter on
`loginSocial` + `signInWithGameCenter`, so every existing call site compiles
unchanged. `swift build` clean; `swift test` 23/23.

## Public API

```swift
Sendora.configure(apiKey:, projectId:, options:)
Sendora.handleDeepLink(url:)
Sendora.checkDeferredDeepLink(completion:)
Sendora.trackEvent(_:properties:)
Sendora.identify(userId:, traits:, options:)
Sendora.consent.grant() / revoke()
```

## MFA-from-anonymous device-takeover (4.1.3)

`signInWithMfaSupport()` must NOT wipe the anon identity before the MFA challenge resolves — else `challengeMfa()`'s `takeoverHint()` reads a cleared `cachedUser` and forwards no `prevAnonRefreshToken`, so the backend never retires the anon row / reassigns push tokens (device ends with two user_ids + duplicate pushes). The fix captures the anon refresh BEFORE any wipe, stashes it in `pendingAnonTakeover` keyed to the `mfaChallengeToken`, and `challengeMfa()` forwards it + wipes **only on a successful mint** (a wrong code preserves the anon session for retry). Mirrors the non-MFA `signIn()` wipe-after-success ordering. Backend `/auth-service/mfa/challenge` already accepts `prevAnonRefreshToken`.

## Security

- `SendoraValidator` refuses `sk_` keys, non-HTTPS URLs, bad event names, deep props.
- userId + deviceId in Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
- Event queue persisted as sent (s58.405: `userId` kept; the identity token never written).
- `handleDeepLink` host-allowlists via `config.linkHosts`.

## Push action buttons (s58.18)

Sendora forwards action buttons in the APNs payload as `data.sendoraActions: [{id, title, url?}]` (max 4 per send — APNs hard limit). iOS UNNotificationCategory does NOT support dynamic per-message actions; the only way is to register a single catch-all category at launch + render the buttons from the payload at notification-display time via a Notification Service Extension.

**Host-app pattern** (one-time AppDelegate setup):

```swift
import UserNotifications

func registerSendoraNotificationCategory() {
    let max = 4
    let actions = (0..<max).map { i in
        UNNotificationAction(
            identifier: "sendora.action.\(i)",
            title: "Action \(i + 1)", // Title overwritten per-message via service extension
            options: [.foreground]
        )
    }
    let category = UNNotificationCategory(
        identifier: "sendora_actions",
        actions: actions,
        intentIdentifiers: [],
        options: []
    )
    UNUserNotificationCenter.current().setNotificationCategories([category])
}
```

**Notification Service Extension** (per-message rewrite):
The extension reads `userInfo["sendoraActions"]`, mutates the `bestAttemptContent` to replace the placeholder action titles with the per-message `title` field. This is the only way Apple permits dynamic action labels.

**Tap routing**: SDK exposes `userNotificationCenter(_:didReceive:)` handler that maps `response.actionIdentifier` → `sendoraActions[i].id` and fires `POST /push/track-open` with `action=<id>`. Body taps fire with `action="body"`.

## Geofences (s58.22)

Server-managed geofences via `CLLocationManager` region monitoring. Operator defines circular regions in the dashboard; SDK auto-fetches + registers up to **20** regions (Apple's hard cap).

**Permission requirements:**
- `NSLocationAlwaysAndWhenInUseUsageDescription` + `NSLocationWhenInUseUsageDescription` in Info.plist.
- `CLLocationManager().requestAlwaysAuthorization()` at runtime — geofences only fire when in `.authorizedAlways` state. `.authorizedWhenInUse` misses background transitions.

**Usage:**
```swift
SendoraCloud.geofences?.start()         // pulls active list + arms regions
// On app foreground:
SendoraCloud.geofences?.refresh()
// On logout / opt-out:
SendoraCloud.geofences?.stop()
```

Enter / exit transitions emit `geofence.entered` / `.exited` events with `geofenceId + latitude + longitude` properties; wire workflows server-side to fire push.

**Notes:**
- Apple's 20-region cap is per-app, shared with any other CLLocationManager regions the host app monitors. SDK identifiers prefixed `sendora:` so dedup works.
- `dwell` trigger type isn't natively supported by CLLocationManager v1 — backend accepts it but iOS SDK currently reports as `enter`. Android implements properly.

## Critical Alerts (s58.20)

iOS Critical Alerts bypass Do Not Disturb / Focus / silent mode. Used for emergency / safety alerts (fall detection, security breach, on-call ops). Requirements:

1. **Apple entitlement** (`com.apple.developer.usernotifications.critical-alerts`) — request via developer.apple.com support form. Approval typically 1-3 weeks. Apple rejects apps without strong safety / health justification.
2. **User permission** at runtime via `UNUserNotificationCenter.requestAuthorization(.criticalAlert)`.

Without either, APNs silently downgrades to a regular alert.

**Permission helper:**
```swift
SendoraCloudCriticalAlerts.requestPermission { granted in
    // Show in-product UI based on outcome
}

SendoraCloudCriticalAlerts.currentSetting { enabled in
    // Re-prompt logic if user previously denied
}
```

**Server-side dispatch** — the dashboard compose page exposes a "Critical Alert" checkbox; the API accepts `criticalAlert: { soundName?, volume? }` on send + template. APNs payload then includes:
```json
{
  "aps": {
    "alert": { "title": "...", "body": "..." },
    "sound": { "critical": 1, "name": "siren.caf", "volume": 1.0 },
    "interruption-level": "critical"
  }
}
```

## Live Activities (s58.19)

iOS 16.1+ via ActivityKit. Persistent rich notifications on lock screen + Dynamic Island. Server-side updates via APNs `push-type=liveactivity`.

**Host-app setup:**
1. Add `NSSupportsLiveActivities=YES` to Info.plist.
2. Create a Widget Extension with the Activity views (lockScreen + Dynamic Island compactLeading / compactTrailing / minimal / expanded).
3. Define `ActivityAttributes` w/ `ContentState`.

**Start + register:**
```swift
import ActivityKit

struct OrderAttributes: ActivityAttributes {
    public struct ContentState: Codable, Hashable {
        var status: String
        var minutesAway: Int
    }
    var orderId: String
}

let activity = try Activity<OrderAttributes>.request(
    attributes: OrderAttributes(orderId: "1234"),
    contentState: OrderAttributes.ContentState(status: "preparing", minutesAway: 30),
    pushType: .token   // <-- REQUIRED for server-side push updates
)

if #available(iOS 16.1, *) {
    SendoraCloud.liveActivities?.track(
        activity: activity,
        activityType: "OrderAttributes",
        externalId: "order-1234",
        userId: "user-42"
    )
}
```

The SDK watches `activity.pushTokenUpdates` and re-registers the per-activity token with Sendora on every rotation. Server updates target the row at `pushLiveActivities.id` (returned from `/push/live-activities/start-token`).

**Server-side update** (operator dashboard or workflow):
```
PATCH /api/v1/orgs/:orgId/push/live-activities/:id/update
{ "contentState": { "status": "delivered", "minutesAway": 0 },
  "alert": { "title": "Order delivered", "body": "Enjoy!" } }
```

**End** (operator or auto on Apple's 4h-idle / 12h-max):
```
DELETE /api/v1/orgs/:orgId/push/live-activities/:id
```

**Apple gotchas:**
- `pushType: .token` REQUIRED at activity start. Without it the activity is local-only and server pushes silently fail.
- Per-activity token rotates. SDK helper handles this; don't cache the token client-side.
- APNs topic suffix `<bundleId>.push-type.liveactivity` is mandatory. Backend sets it automatically.
- Per-activity update budget is opaque. Dashboard warns when `updatesThisHour ≥ 30`. Higher rates may silently throttle.
- `aps.timestamp` must be monotonic; backend uses `Math.floor(Date.now()/1000)` per send.
- iOS 17+: APNs can also START activities (not just update). Sendora doesn't surface this yet — host app must start v1.

## 4.14.0 — anonymous-session reuse, total error coercion, + 4 MFA/delete defects (s58.271d)

Parity with RN 1.29.0 / web 3.13.0 / Android 4.14.0.

- **A corrupt user blob is now actually recoverable.** Keeping the refresh token
  when the cached user fails to parse was only half a fix: nothing could turn
  that token back into an identity, because the refresh discarded the `user` the
  backend returns in the very same response — so the session sat live with a
  permanently null user and the next sign-in orphaned the account anyway. The
  refresh now adopts that user, but **only when there is none** (a refresh is a
  token rotation, not an identity change), only when it is well-formed (the
  route tolerates a missing user row), and it emits `signed_in` because
  recovering an identity IS a transition — while a plain rotation with a user
  already present still emits nothing.

- **`signInAnonymously(forceNew:)` reuses an existing anonymous session.** It
  minted a brand-new user unconditionally, and `persist` overwrote the stored
  refresh token — the previous anonymous account's ONLY durable handle — with no
  takeover, no webhook and no state event. An app calling it defensively on
  every cold launch fragmented the player across a new `user_id` per launch:
  the same lost-progress outcome as a failed sign-in wiping the session, except
  on a **healthy** network. Now short-circuits when the cached user is anonymous
  AND a refresh token is in the Keychain (Firebase's `signInAnonymously` does
  exactly this). `forceNew: Bool = false` is a defaulted parameter, so every
  existing call site compiles unchanged.
- **Every rejection carries a `kind`.** The default must stay non-fatal — that
  is what makes the one-code `isDeadRefreshError` allow-list safe rather than
  lucky: an unmapped failure can only become session-fatal through a deliberate
  edit.

**⚠ Four real defects surfaced while doing the coercion pass — all fixed:**

- `deleteAccount` threw bare `NSError`s, so the destructive path had literally
  no `.kind` at all.
- `enrollMfa` reported a **timeout** as `.unknown("Malformed enrollment
  response")` — non-retryable, so the app would not retry a call that had
  simply timed out.
- `confirmMfa` reported a **timeout** as `.success(false)` — i.e. "your code is
  wrong". The user retypes a correct code and is told it is wrong.
- `disableMfa` reported a **timeout** as `.success(())` **while MFA was still
  armed** — the app tells the user MFA is off when it is on. That is a
  security-relevant lie, not just a UX bug.
- Related: the dictionary `parseError` collapsed EVERY unmapped code into
  `.unknown`, so a 429 or 503 on magic-link, email-OTP, password-reset,
  verify-email, `link*` and `listLinkedIdentities` could never classify as
  `.rateLimited` / `.server`.

**⚠ TWO CARRIER CHANGES (same additive class as 4.13.0's `.rejected`):**

1. `deleteAccount`'s completion type is unchanged (`Result<AccountDeletionResult,
   Error>`) but the value inside is now `SendoraCloudAuthError`, not `NSError`.
   An app reading `(error as NSError).code == 401 / -1 / 500` must move to
   `.kind` / `.status`. Message strings are byte-identical, and a new
   `LocalizedError` conformance keeps them on `error.localizedDescription`
   (which previously printed Foundation's generic "operation couldn't be
   completed" for the enum).
2. On the plain `post`/`get` auth paths an unmapped backend code now surfaces as
   `.rejected(code:message:status:retryAfterSeconds:)` instead of
   `.unknown("CODE: message")` — that is what gives it a real `kind`. Codes with
   a dedicated case (`CONFLICT`/`EMAIL_ALREADY_TAKEN`, `NOT_ANONYMOUS`,
   `CREDENTIAL_IN_USE`, `UNAUTHORIZED`/`HTTP_401`) still produce exactly the
   same case as before, pinned by a test. Side effect: `.message` no longer
   carries the `"CODE: "` prefix on those paths — the code is available
   structurally instead.

`swift build` clean; `swift test` **22/22** (was 16/16).

## 4.14.0 — token refresh + transport: the remaining loss routes (s58.271b)

Parity with RN 1.29.0 / web 3.13.0 / Android 4.14.0. See the RN CLAUDE.md
1.29.0 section for the full write-up.

- **⚠ `/token/refresh` shape (CRITICAL, pre-existing).** Refresh read the flat
  `data.*` the backend abandoned in s58.76 — the rotated trio is under
  `data.tokens`. It silently returned nil forever, so the session died at
  access-token expiry and the app minted a fresh guest. Both levels accepted now.
- **`APIClient.request` no longer discards a non-2xx body** (the same defect
  fixed in sdk-android 4.13.0). It nil'd every error response, so the 4.13.0
  taxonomy could not classify anything and `.signedOut(.sessionExpired)` was
  unreachable. The body is returned, the HTTP status is stamped onto the error
  envelope, and only a 5xx or a transport failure trips the breaker.
- **The circuit breaker no longer latches permanently.** `shouldSkip` hard-tripped
  on `consecutiveFailures > maxFailures`, which can never reset — no request is
  attempted, so no success is recorded — wedging the whole SDK for the process
  lifetime after ~6 minutes offline. Now purely time-based (half-open by
  construction), matching sdk-android.
- **A generic 401 no longer wipes the session** (`isDeadRefreshError` narrowed to
  `INVALID_REFRESH_TOKEN`), and the refresh race is gated both directions by
  `tokenStillCurrent(sent)`.

## 4.13.0 — a failed sign-in can no longer destroy the account (s58.271)

**The bug (customer-reported, HIGH — silent permanent data loss).** Five
credentialed sign-in paths cleared local identity — `wipeLocalIdentity()`,
which drops the Keychain tokens AND fires `onAnonymousWipe` (device/session id
rotation + event-queue drop) — BEFORE their network call, and no failure path
restored it. For an anonymous user the stored refresh token is the ONLY durable
handle on the account, so once the wipe landed and the call failed the account
was unreachable from the device forever; offline it was not a race but a
**guarantee**. Word Hurdle lost a real production account this way (30
purchases incl. an active subscription, 3,355-gem balance) through Game Center
sign-in on a flaky network. Affected: `signIn`, `loginSocial` (and all seven
`signInWith*` wrappers), `signInWithGameCenter`, `verifyMagicLink`,
`verifyEmailOtp` — the last three wiped before ANY input was validated, so a
mistyped OTP or a stale tapped magic link cost the account too.

**The invariant now, everywhere: a failed auth attempt leaves the caller
exactly as it found them.** Each path captures the anon refresh via
`takeoverHint()` (no wipe), calls, and hands the clear to `callAuthSync`'s new
`replacesIdentity:` flag, which runs `wipeReplacedIdentityIfPresent()` **only
from the success branch, glued to the `persist`** — the shape
`signInWithMfaSupport` / `challengeMfa` already used since the s58.203 fix (see
"4.1.3" above) and which was never propagated to their siblings. `signUp`
(in-place `/upgrade`) and `signInAnonymously` pass false: nothing to replace.
Same fix in RN 1.28.0 / web 3.12.0 / Android 4.12.0.

Three things ship alongside it, because the fix changes what a rejection
*means* and an app must be able to act on it:

- **Error taxonomy — `.kind` / `.retryable` / `.retryAfterSeconds` / `.status`**
  as computed properties on `SendoraCloudAuthError`, plus the
  `SendoraCloudAuthErrorKind` closed set (`network` · `server` · `rate_limited`
  · `invalid_credential` · `account_locked` · `credential_in_use` ·
  `already_identified` · `cancelled` · `config` · `unknown`, raw values
  identical to `@sendora/shared` `AuthErrorKind` so `kind.rawValue` logs the
  same token on all 4 SDKs). `retryAfterSeconds` comes from
  `error.details.retryAfterSeconds` (429 backoff + the new backend
  `ACCOUNT_LOCKED` 403; **absent = the lock needs support**).
  **⚠ Two carrier changes to know about:** (1) a NEW enum case
  `.rejected(code:message:status:retryAfterSeconds:)` — a Swift enum can't carry
  per-instance data otherwise; every pre-4.13.0 case is still produced for the
  exact same codes (mapping centralised in `mapKnownErrorCode`), but an app that
  switches over the enum **exhaustively** must add a `default:` (same class of
  additive change as 4.10.0's `.alreadyIdentified`/`.credentialInUse`). (2) the
  sign-in paths now POST through `APIClient.requestWithDetails` instead of
  `post`, which collapsed EVERY non-2xx to `nil` — that is why a wrong password,
  a 409 and a dead radio all surfaced as `.network("Network request failed")`
  and why `parseError`'s code branches were effectively dead. Auth 4xx also no
  longer trips the client-wide circuit breaker (only a status-0 transport
  failure does).
- **`onAuthStateChanged(listener) -> unsubscribe`** — one stream:
  `.signedIn` / `.signedOut(reason: .user | .sessionExpired | .accountDeleted)`
  / `.deviceTakeover` / `.deletionCancelled`. The load-bearing case is
  `.sessionExpired`: a session that died in the background (dead refresh token)
  previously emitted **nothing**, so an app couldn't tell it from a deliberate
  sign-out and only noticed when `getAccessToken` returned nil. Replays the
  current state on subscribe once the Keychain hydrate has run (`hydrated` flag,
  set at the end of `init`) — never before, which would report "signed out"
  during restore — and emits nothing for a signed-out cold start. **A
  `.replaced` wipe (the internal pre-`persist` clear) emits NOTHING**, else every
  sign-in would look like a logout/login pair. A failed sign-in emits nothing at
  all: no state changed. `onDeviceTakeover` / `onDeletionCancelled` unchanged.
- **A rate limit is no longer treated as a dead session.**
  `isDeadRefreshError` dropped `RATE_LIMIT` / `RATE_LIMIT_EXCEEDED`: a 429 is
  transient throttling (shared NAT/CGN egress, refresh burst) and says nothing
  about token validity, yet it was wiping live sessions from the background
  refresh path. Relatedly, `init`'s corrupt-cache guard no longer calls
  `storage.clearAuthTokens()` when only the cached USER blob failed to decode —
  it drops the user + access token and **keeps the refresh token**, the only
  thing that can recover that account.

Tests: `Tests/SendoraCloudTests/SendoraCloudAuthErrorTests.swift` (taxonomy
table + source guards pinning wipe-after-validate — the wipe must be glued to
the persist, and every wipe must state its reason). `swift build` + `swift test`
16/16 clean. Additive: no frozen Keychain key / header / route / wire shape
touched (ADR-023), no error code renamed, no method signature changed.

## 4.12.0 — listLinkedIdentities() (read side of ADR-030, s58.270)

`auth.listLinkedIdentities { result in }` → `Result<LinkedIdentitiesResult,
SendoraCloudAuthError>` where `LinkedIdentitiesResult` = `{ identities:
[LinkedIdentity(provider, email?, linkedAt)], hasPassword }`. The full set of
credentials on the current account — the cross-device / reinstall-durable source
of truth for a "Connected: Game Center · Google" UI (`getCurrentUser()` only
holds the primary `signupMethod`/`lastLoginMethod`). Bearer-authenticated GET
`/auth-service/me/identities` that resolves a fresh access token first (mirrors
`deleteAccount`); `.unauthorized` when signed out. Firebase `user.providerData` /
Supabase `user.identities` parity. Version in `SDKVersion.swift`. `swift build`
clean. Additive, SDK-only (not in the golden contract). Parity with RN 1.27.0 /
web 3.11.0 / Android 4.11.0.

## 4.11.0 — onDeletionCancelled (account-restore listener, s58.269)

`auth.onDeletionCancelled { evt in }` + `getLastDeletionCancelled()` (returns
`DeletionCancelledEvent`) — mirrors `onDeviceTakeover` (UUID-keyed, lock-safe,
snapshot-then-dispatch). Fires when a sign-in cancelled a pending self-service
deletion within grace (account restored, same sub). The 4 per-path device-takeover
fire sites were unified into `fireLifecycleSignals(from:identifiedUserId:)`, which
parses BOTH `retiredAnonUserId` and the new `reactivatedFromDeletion` off the
response and fires the matching listener — so every sign-in path emits both
consistently. Pairs with backend `auth.deletion_cancelled`/`auth.deletion_scheduled`
webhooks. `swift build` clean. Additive, not in the golden contract. Parity with
RN 1.26.0 / web 3.10.0 / Android 4.10.0.

## 4.10.0 — identity linking on an identified session (ADR-030) + signUp() fix

Non-anonymous sibling of ADR-025. New `auth.linkEmailPassword` / `linkSocial`
(+ `linkGoogle`/`linkApple`) / `linkGameCenter` attach a 2nd credential to an
already-identified account (sub preserved), Bearer-authenticated (mirror
`deleteAccount`'s `getAccessToken` → Bearer POST flow), and refresh the cached
user in place via `updateLocalUser` — **NO token rotation**. Collision → new
`SendoraCloudAuthError.credentialInUse`. Play Games is Android-only, so iOS ships
`linkGameCenter` but not `linkPlayGames`. **signUp() fix:** on iOS, `signUp()`
only hit `/upgrade` when anonymous; a non-anon signUp used to wipe + fresh-signup
(= duplicate account). It now returns the new `.alreadyIdentified` error (no wipe,
no second account); `parseError` also maps the backend's new `NOT_ANONYMOUS` code
→ `.alreadyIdentified` and `CREDENTIAL_IN_USE` → `.credentialInUse`. Additive,
SDK-only (not in the golden wire contract); no frozen key/header touched. Version
in `SDKVersion.swift`. Parity with RN 1.25.0 / web 3.9.0.

## 4.9.0 — `signupMethod` + `lastLoginMethod` on the auth user

`SendoraCloudAuthUser` gains two optional read-only fields: `signupMethod` (how the account was first created, immutable) + `lastLoginMethod` (most recent auth). Free-form provider tokens (`password`/`anonymous`/`google`/`apple`/`gamecenter`/`playgames`/`magic_link`/`passkey`/`oidc`/…). Backend populates them on the login/signup/social/game response (s58.266, mig 0094). Both are `String?` on the `Codable` struct, so decoding a cached user from a pre-4.9.0 build stays safe (absent → nil); `parseSuccess` also reads them off the response dict. Display-only — never an authorization signal. No frozen key/header/wire-shape touched (ADR-023); not in the golden wire contract. Parity with RN 1.24.0 / web 3.8.0 / Android 4.8.0.

## 4.8.0 — Game Center sign-in

`auth.signInWithGameCenter(publicKeyURL:signature:salt:timestamp:teamPlayerID:bundleID:link:completion:)` — email-less, player-keyed sign-in. Pass the payload from `GKLocalPlayer.local.fetchItems(forIdentityVerificationSignature:)` + the app's bundle id; forwards to `POST /auth-service/login/game-center`. Mirrors `loginSocial` exactly (opsQueue, anon-takeover hint read BEFORE wipe → `prevAnonRefreshToken`, `link:true` → `linkAnonymous` for ADR-025 link-in-place, `callAuthSync`). Additive, SDK-only (not in golden wire contract). App obtains the GameKit payload itself (no GameKit dep forced on the SDK). Ships alongside backend Phase 1 + RN 1.21.0.

## 4.7.0 — anon→social link-in-place (ADR-025)

`loginSocial` / `signInWithApple` / `signInWithGoogle` gain an opt-in `link: Bool = false`. When anonymous + `link: true`, the anon→social upgrade sends `linkAnonymous` so the backend promotes the anon row IN PLACE — `sub` PRESERVED (fires `auth.user_upgraded`) instead of a device-takeover (new id); Firebase `linkWithCredential` parity. No effect off-anon or on a collision. Source-compatible default (trailing-closure callers unaffected); additive. Design: `docs/decisions/025-anon-social-link-in-place.md`.

## 4.5.0 — SDK/API compatibility (ADR-023)

4.5.0 — ADR-023: single-source sdkVersion constant (no more hardcoded drift) +
X-Sendora-SDK-{Name,Version} headers + sendora_schema_version=1 marker (additive).

The version string used to be hardcoded as `"4.4.0"` in two places (the event
body `context.sdk` and a `Package.swift` reference) — drift risk. Now the ONLY
source of truth is `Internal/SDKVersion.swift` (`SendoraCloud.sdkVersion` /
`.sdkName`); the event body reads it and `Package.swift` just carries a comment
kept in lockstep with the git tag. Every HTTP request (`APIClient`, both the
plain `request` and `requestWithDetails` builders) now also sends
`X-Sendora-SDK-Name: sendora-ios` + `X-Sendora-SDK-Version: <sdkVersion>` so the
backend gets a version signal on non-event routes too (auth/links/push) — the
backend ignores them today. On `configure`, `Storage.initSchemaVersionIfAbsent()`
writes UserDefaults key `sendora_schema_version = "1"` if absent (non-sensitive →
UserDefaults tier, NOT Keychain), giving a future in-place upgrade a hook to
branch a local-storage migration. Read nowhere yet; no existing key renamed
(frozen per ADR-023 §3.4). All additive + backward-compatible.

## 4.4.0 — appVersion in device context (ADR-022)

`DeviceInfo.toDictionary()` now also emits `appVersion` (already collected from
`CFBundleShortVersionString`) alongside the existing `type` / `os` / `osVersion`
/ `model`. So every event's `context.device` carries the host app version,
powering the dashboard Analytics → Audience app-version breakdown. No config or
host-app change — auto-detected from the bundle. The native SDKs already led on
device context; this just surfaces the app version that was being collected but
not sent.

## Engagement time (Wave 75 — 4.1.0)

`SendoraCloud.trackScreen(_:properties:)` emits `screen.viewed` and flushes the
previous screen's `app.engagement { durationMs, screen, sessionId }` (foreground
-only). New `autoTrackEngagement` config flag (default on). `willResignActive`
flushes + pauses; `didBecomeActive` resumes (the observer is now registered when
lifecycle OR engagement is on). State guarded by the existing `serialQueue`;
spans <250ms dropped, >6h clamped, emit happens outside the lock. **No
UIViewController swizzling** — deliberately, so screen names stay accurate
(swizzle counts container / nav / tab controllers) and there's zero added crash
surface. Matches GA4 `engagement_time_msec`; powers `/analytics/engagement`.

## Account deletion (s58.209)

`auth.deleteAccount(completion:)` (Bearer) deletes the signed-in user's account
for Apple App Store Guideline 5.1.1(v). `Result<AccountDeletionResult, Error>` —
`status` is `"purged"` (grace 0) or `"pending"` (disabled + sessions revoked now;
hard-deleted at `scheduledPurgeAt`, cancellable by signing back in within grace).
Wipes local identity on success. Grace period is a per-project Auth setting.

**4.3.1 — refresh-before-delete.** `deleteAccount(completion:)` now resolves a
fresh access token via `getAccessToken` (refreshing a past-expiry cached token)
BEFORE the `DELETE` instead of sending the raw cached token via `bearerHeaders()`.
This is a one-shot destructive action — a 401 from a stale token (typical when a
user taps "delete" after the app sat idle past the short access TTL) would
silently strand them with an undeleted account (cause of prod
`DELETE /auth-service/me 401`s). **Host-app note:** wire your delete button to
`auth.deleteAccount()` — NOT `consent.requestDeletion()` (GDPR ledger only).

## Deep Links no-app routing mode (s58.208)

`LinkCreateInput` gains an optional `noAppMode: String?` (`"auto"`/`"store"`/`"web"`)
forwarded as `noAppMode` on `POST /sdk/links`. Controls what a **mobile visitor
without the app installed** gets: `auto` (default) = store-if-registered-else-web,
`store` = prefer store, `web` = force the web fallback even when a store URL
exists. `nil` inherits the project default. Additive + backwards-compatible.
Desktop is always web.

## Publish

Native SDKs ship via a git tag on the **separate public mirror** `github.com/sendoracloud/sdk-ios` (SwiftPM), not npm. From a monorepo checkout:

1. Guard the version: `node scripts/publish.mjs ios` (verifies `SDKVersion.swift` is consistent).
2. Mirror it (operator, needs a clone of the mirror + push creds):
   `node scripts/publish-native-mirror.mjs ios --mirror-dir <clone> [--push] [--delete]` — rsyncs `packages/sdk-ios/` → the mirror clone (excludes `.build`/`.swiftpm`), commits, tags `<semver>`, pushes. **DRY by default**; `--push` executes; `--delete` makes the mirror an exact copy. It refuses a wrong/monorepo mirror dir or an existing tag. First time: `git clone https://github.com/sendoracloud/sdk-ios.git <clone>`.

Raw path (equivalent): rsync source into the mirror clone, then `git tag <semver> && git push origin main --tags`; release via `gh release create`.
