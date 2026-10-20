import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Auth Service surface for the iOS SDK.
///
/// 5.4.0 (ADR-033 "One Slot, Two Verbs") — the surface is an INTERPRETER of the
/// shared transition table `packages/shared/src/auth-machine/transitions.ts`:
///
///   - **Sign-in never carries the guest.** A credentialed sign-in from a guest
///     device HOLDS the guest on-device (`heldGuests()`, K = 5 fixed Keychain
///     slots) and switches; the server row survives. No body ever carries
///     `prevAnonRefreshToken` / `linkAnonymous` / `onCredentialInUse` (INV-3).
///   - **Link is the only upgrade.** `signUp()`, `signInWith*(link: true)`,
///     `loginSocial(link: true)` and `link*()` go to `/me/link/*` on the current
///     Bearer session from `anonymous` AND `identified`; over an identified
///     session a link attaches or returns a typed refusal — it never switches.
///   - **One slot, one writer.** `commit*` (SendoraCloudAuth+Commit.swift) is the
///     only code that assigns the session, writes the Keychain, arms the refresh
///     cron and calls the parent hooks. Every public method is sugar for a row.
///   - **Proposal, then CAS.** A network call changes nothing until it succeeds,
///     and its result is applied only if the session it was derived from is still
///     current — `sid` for identity commits, the sent refresh token for rotations.
///   - **Boot is observable.** `status()` is `.unknown | .signedOut | .anonymous |
///     .identified | .withheld`; `authStateReady()` resolves after the Keychain
///     hydrate, never waiting on the network.
///
/// **Invariant (kept from 4.13.0): a failed auth attempt leaves the caller
/// exactly as it found them.** For an anonymous user the stored refresh token is
/// the ONLY durable handle on the account.
///
/// All public identity ops are serialized through `opsQueue`, so a double-tap
/// can't race two mints or interleave signIn + signOut. Response payloads are
/// validated non-empty before persisting.
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
    /// The account's project pool (ADR-033 B17, 5.4.0) — the same value as the
    /// JWT `project` claim. `nil` against a pre-B17 backend AND for the org-wide
    /// pool (Swift cannot carry the wire's absent-vs-null distinction here; the
    /// project guard reads the JWT claim, not this field).
    public let project: String?
}

/// 5.4.0: field-wise equality, used by the machine to decide whether a refresh
/// changed the user object (`userUpdated(cause: .refresh)`).
extension SendoraCloudAuthUser: Equatable {}

public struct SendoraCloudAuthTokens: Codable {
    public let accessToken: String
    public let refreshToken: String
    public let expiresIn: Int
    public let tokenType: String
}

/// Closed set of auth failure categories (4.13.0). Branch on `kind` instead of
/// matching the ~20 raw codes the backend and the transport can produce.
///
/// Pairs with the guarantee this release introduces: **a failed auth attempt
/// never changes the local session.** An offline sign-in, a mistyped OTP, a
/// dismissed Game Center sheet and a 429 all leave `currentUser` and the stored
/// refresh token exactly as they were.
public enum SendoraCloudAuthErrorKind: String {
    /// Device offline, TLS failure, request timed out. Retry the same input.
    case network
    /// 5xx or an unreadable response body. Retry later.
    case server
    /// 429. Retry after `retryAfterSeconds`.
    case rateLimited = "rate_limited"
    /// Wrong password / OTP, expired magic link, stale OAuth code — and the
    /// deliberate mask for a disabled account (anti-enumeration). Needs NEW input.
    case invalidCredential = "invalid_credential"
    /// Repeated failures locked the account. A present `retryAfterSeconds` means
    /// it unlocks on its own; absent means support has to intervene.
    case accountLocked = "account_locked"
    /// The credential belongs to a different account (409).
    case credentialInUse = "credential_in_use"
    /// Refusing to unlink the ONLY way into this account (409). The account
    /// would still exist and still hold the user's data with nothing able to
    /// authenticate into it — permanent lockout. Add another credential first.
    case lastCredential = "last_credential"
    /// The credential is VALID; the authentication behind it is too old to
    /// authorise a credential change (403 `RECENT_AUTH_REQUIRED`). NOT a bad
    /// credential — re-run whatever sign-in the user already has and retry the
    /// SAME call. For Game Center that re-assertion is silent.
    /// `details.maxAgeSeconds` is the freshness window.
    case recentAuthRequired = "recent_auth_required"
    // NOTE: `CredentialCollisionPolicy` (4.15.0) lives below on
    // `SendoraCloudAuth` — it is a request option, not an error kind.
    /// The session is already identified — use `link*()`.
    case alreadyIdentified = "already_identified"
    /// The user dismissed a native / browser sheet. Not an error condition.
    case cancelled
    /// The method is disabled or plan-gated for this project — and, since 5.4.0,
    /// the client-side refusals of the ADR-033 machine (`SESSION_WITHHELD`,
    /// `PROJECT_MISMATCH`, `HELD_GUEST_LIMIT`, `HELD_GUEST_PROJECT_MISMATCH`,
    /// `AMBIGUOUS_HELD_GUEST`): non-retryable, the app must change what it asks.
    case config
    /// Unmapped — treat as non-retryable.
    case unknown
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
    /// The server rejected the attempt in machine-readable terms (4.13.0):
    /// the backend `code` verbatim, the HTTP `status`, and the server's
    /// `retryAfterSeconds` hint when it sent one (429 backoff, ACCOUNT_LOCKED
    /// cool-off). Produced for codes without a dedicated case above — the
    /// pre-4.13.0 cases are still produced for the exact same codes, so
    /// existing matches keep working. Prefer branching on `kind`.
    case rejected(code: String, message: String, status: Int, retryAfterSeconds: Int?)

    // ── 5.4.0 (ADR-033) — client-side refusals of the auth machine. Additive:
    // an exhaustive `switch` needs a `default:` (same class as 4.13.0's `.rejected`).

    /// `status() == .withheld`: the stored session's `project` claim disagrees
    /// with `expectedProjectId`. Every identity verb refuses with this — no
    /// network, no write. Exit via `discardWithheld()`. Code `SESSION_WITHHELD`.
    case sessionWithheld(SendoraCloudWithheldInfo)
    /// A session minted by THIS process under THIS key carries the wrong
    /// `project` claim (wrong-key build): nothing installed, the minted refresh
    /// token revoked. Code `PROJECT_MISMATCH`.
    case projectMismatch(expectedProjectId: String, actualProjectId: String?)
    /// All 5 held-guest slots are in use (`forceNew` at the cap, or every slot
    /// ineligible for auto-restore). Restore or discard one. Code `HELD_GUEST_LIMIT`.
    case heldGuestLimit(held: Int, limit: Int)
    /// The held slot's `project` claim mismatches `expectedProjectId ?? projectId`
    /// (client-side, no network; slot kept). Code `HELD_GUEST_PROJECT_MISMATCH`.
    case heldGuestProjectMismatch(userId: String, slotProject: String?, expectedProjectId: String)
    /// `id` omitted while more than one guest is held. Code `AMBIGUOUS_HELD_GUEST`.
    case ambiguousHeldGuest(held: Int)
    /// The held guest's token was presented and the server reported it gone
    /// (`endReason` ∈ deleted|revoked|expired) or no such guest is held. The
    /// slot is released. Code `HELD_GUEST_GONE`. Say "unavailable", never "lost".
    case heldGuestGone(userId: String, endReason: SendoraCloudRefreshEndReason?)
    /// The held token was refused with `reuse` or no `endReason` — that does not
    /// prove the guest is gone, so the slot is KEPT; retry later. Code
    /// `RESTORE_FAILED` (retryable).
    case restoreFailed(userId: String, endReason: SendoraCloudRefreshEndReason?)
    /// `switchAccount()` re-read the device identity and it differs from the
    /// credential the player confirmed (INV-14). Nothing mutated. Code `CREDENTIAL_CHANGED`.
    case credentialChanged(String)
}

/// Keeps `error.localizedDescription` useful wherever a typed auth error
/// travels as a bare `Error` (`deleteAccount`). Without it Foundation prints
/// "The operation couldn't be completed", and the server's message — the part
/// an app actually shows — is lost.
extension SendoraCloudAuthError: LocalizedError {
    public var errorDescription: String? { message }
}

public extension SendoraCloudAuthError {
    /// Human-readable detail, whichever case this is.
    var message: String {
        switch self {
        case .emailAlreadyTaken(let m), .alreadyIdentified(let m), .credentialInUse(let m),
             .unauthorized(let m), .network(let m), .unknown(let m), .credentialChanged(let m):
            return m
        case .rejected(_, let m, _, _):
            return m
        case .sessionWithheld(let info):
            return "Session withheld: its project claim (\(info.actualProjectId ?? "null")) does not match expectedProjectId \(info.expectedProjectId). Call discardWithheld() or relaunch with the matching key."
        case .projectMismatch(let expected, let actual):
            return "The server minted a session for project \(actual ?? "null"), not the expected \(expected). Nothing was installed; check the API key / expectedProjectId pairing."
        case .heldGuestLimit(let held, let limit):
            return "All \(limit) held-guest slots are in use (\(held) held). Restore or discard a held guest first."
        case .heldGuestProjectMismatch(let userId, let slotProject, let expected):
            return "Held guest \(userId) belongs to project \(slotProject ?? "null"), not \(expected); it was not restored."
        case .ambiguousHeldGuest(let held):
            return "\(held) guests are held — pass the id of the one to act on."
        case .heldGuestGone(let userId, let endReason):
            return "Held guest \(userId.isEmpty ? "" : userId + " ")is no longer available (\(endReason?.rawValue ?? "not held"))."
        case .restoreFailed(let userId, let endReason):
            return "Held guest \(userId) could not be restored right now (\(endReason?.rawValue ?? "no end reason")); the slot was kept — retry."
        }
    }

    /// The machine-readable code, when there is one: the backend `code` of a
    /// `.rejected`, or the ADR-033 client code of a 5.4.0 refusal. `nil` for
    /// the pre-4.13.0 cases, which carry only a message.
    var code: String? {
        switch self {
        case .rejected(let code, _, _, _): return code
        case .sessionWithheld: return "SESSION_WITHHELD"
        case .projectMismatch: return "PROJECT_MISMATCH"
        case .heldGuestLimit: return "HELD_GUEST_LIMIT"
        case .heldGuestProjectMismatch: return "HELD_GUEST_PROJECT_MISMATCH"
        case .ambiguousHeldGuest: return "AMBIGUOUS_HELD_GUEST"
        case .heldGuestGone: return "HELD_GUEST_GONE"
        case .restoreFailed: return "RESTORE_FAILED"
        case .credentialChanged: return "CREDENTIAL_CHANGED"
        default: return nil
        }
    }

    /// Category of the failure — the field to branch on. Never affects which
    /// case is produced, which stays exactly what shipped before 4.13.0.
    var kind: SendoraCloudAuthErrorKind {
        switch self {
        // The email is attached to another account: same shape as a link
        // collision, so it groups under the same kind.
        case .emailAlreadyTaken: return .credentialInUse
        case .alreadyIdentified: return .alreadyIdentified
        case .credentialInUse: return .credentialInUse
        case .unauthorized: return .invalidCredential
        case .network: return .network
        case .unknown: return .unknown
        case .rejected(let code, _, let status, _):
            return SendoraCloudAuthError.classifyKind(code: code, status: status)
        case .sessionWithheld, .projectMismatch, .heldGuestLimit, .heldGuestProjectMismatch, .ambiguousHeldGuest:
            return .config
        case .heldGuestGone, .credentialChanged:
            return .invalidCredential
        case .restoreFailed:
            return .server
        }
    }

    /// True when retrying the SAME input can plausibly succeed later.
    /// `accountLocked` is retryable ONLY when the server said when the lock lifts
    /// (`retryAfterSeconds`): the 100-failure hard stop carries no wait and does
    /// not lift with time.
    var retryable: Bool {
        switch kind {
        case .network, .server, .rateLimited: return true
        case .accountLocked: return retryAfterSeconds != nil
        default: return false
        }
    }

    /// Seconds to wait before retrying, when the server said so (429 backoff, or
    /// an ACCOUNT_LOCKED cool-off). `nil` means no server hint — for
    /// `accountLocked` specifically that means the lock does NOT lift with time:
    /// reset the password, or sign in another way (magic link, email code,
    /// social), to continue — and `retryable` is false.
    var retryAfterSeconds: Int? {
        if case .rejected(_, _, _, let seconds) = self { return seconds }
        return nil
    }

    /// HTTP status when the failure came from a response; `nil` when the request
    /// never reached the server.
    var status: Int? {
        if case .rejected(_, _, let status, _) = self { return status }
        return nil
    }

    /// Map a raw error code (+ HTTP status) onto the taxonomy. Unknown codes fall
    /// back to a status-derived kind, then `.unknown` — so a backend that adds a
    /// code this SDK has never heard of still classifies sanely instead of being
    /// reported as retryable.
    internal static func classifyKind(code: String, status: Int) -> SendoraCloudAuthErrorKind {
        switch code {
        case "NETWORK_ERROR", "NETWORK_TIMEOUT", "NETWORK":
            return .network
        case "PARSE_ERROR":
            return .server
        case "RATE_LIMITED", "RATE_LIMIT", "RATE_LIMIT_EXCEEDED", "QUOTA_EXCEEDED":
            return .rateLimited
        case "ACCOUNT_LOCKED":
            return .accountLocked
        case "CREDENTIAL_IN_USE":
            return .credentialInUse
        case "LAST_CREDENTIAL":
            return .lastCredential
        // ⚠ A CODE case, not a status one. The status tail below maps any 4xx
        // to `.invalidCredential` ("needs new input"), which is the opposite of
        // what a step-up refusal means. Also do NOT add this to
        // `mapKnownErrorCode` — returning `.unauthorized` there re-collapses it
        // onto a dead credential.
        case "RECENT_AUTH_REQUIRED":
            return .recentAuthRequired
        case "NOT_ANONYMOUS", "FORBIDDEN_NON_ANONYMOUS":
            return .alreadyIdentified
        case "PASSKEY_USER_CANCELLED", "GAME_CENTER_CANCELLED", "PLAY_GAMES_CANCELLED", "SSO_CANCELLED":
            return .cancelled
        case "GAME_CENTER_UNAVAILABLE", "PLAY_GAMES_UNAVAILABLE", "ENTITLEMENT_ERROR", "tier_required":
            return .config
        // ADR-033 §3.5 [2c]: the two project-guard refusals REUSE kind `config`;
        // the closed `AuthErrorKind` is NOT widened.
        case "SESSION_WITHHELD", "PROJECT_MISMATCH", "HELD_GUEST_LIMIT", "HELD_GUEST_PROJECT_MISMATCH", "AMBIGUOUS_HELD_GUEST":
            return .config
        // 5.9.0: `discardHeldGuest(keepSupportTickets: true)` outside an
        // identified session — the app must sign in first (client-side, no network).
        case "KEEP_TICKETS_REQUIRES_IDENTIFIED":
            return .config
        case "HELD_GUEST_GONE", "CREDENTIAL_CHANGED":
            return .invalidCredential
        case "RESTORE_FAILED":
            return .server
        case "UNAUTHORIZED", "INVALID_CREDENTIALS", "INVALID_REFRESH_TOKEN",
             "EMAIL_OTP_INVALID", "MAGIC_LINK_INVALID", "PASSKEY_RP_MISMATCH", "NOT_SIGNED_IN":
            return .invalidCredential
        default:
            break
        }
        if status == 429 { return .rateLimited }
        if status >= 500 { return .server }
        // 401/403/404/409/422 on an auth attempt all mean "this credential/input
        // will not work as-is" — the app must collect something new.
        if status >= 400 { return .invalidCredential }
        return .unknown
    }
}

/// Why the local session ended (4.13.0). Before this, a session that died in the
/// background emitted NOTHING — an app could not tell a deliberate sign-out
/// apart from an expired refresh token, and only discovered the difference when
/// `getAccessToken` started returning nil.
///
/// 5.4.1: EVERY dead refresh verdict is `sessionExpired`, exactly as through
/// 5.3.0. The server's own `endReason` (ADR-033 B11) is read from
/// `SendoraCloudAuth.lastSignedOutEndReason()` inside the listener (the case's
/// payload is frozen for source compatibility).
///
/// ⚠ `revoked` / `evicted` / `deleted` were emitted by 5.4.0 ONLY. 5.4.0 put the
/// server's `endReason` here, which renamed "account deleted elsewhere" and
/// "sessions revoked" (both `sessionExpired` through 5.3.0) and silently broke
/// listeners matching `sessionExpired`. The cases stay so code written against
/// 5.4.0 still compiles. Consumers default-branch.
public enum SendoraCloudAuthSignedOutReason: String {
    /// The app called `signOut`.
    case user
    /// The server rejected the stored refresh token (revoked, expired, rotated
    /// away, account deleted elsewhere — read `lastSignedOutEndReason()` for
    /// which). Transient network failures and rate limits do NOT produce this.
    case sessionExpired = "session_expired"
    /// `deleteAccount` succeeded.
    case accountDeleted = "account_deleted"
    /// 5.4.0 only — never emitted since 5.4.1 (now `sessionExpired` + `lastSignedOutEndReason() == .revoked`).
    case revoked
    /// 5.4.0 only — reserved, never emitted.
    case evicted
    /// 5.4.0 only — never emitted since 5.4.1 (now `sessionExpired` + `lastSignedOutEndReason() == .deleted`).
    case deleted
}

/// A single auth-state transition (4.13.0). Subscribe with `onAuthStateChanged`
/// — one stream covering everything that used to need separate listeners (or
/// had no signal at all).
///
/// 5.4.0 (ADR-033, additive — an exhaustive `switch` needs a `default:`):
/// `initial`, `userUpdated`, `guestHeld`, `guestReleased`, `sessionWithheld`.
/// The `cause` of a `signedIn` is read from `SendoraCloudAuth.lastSignedInCause()`
/// inside the listener (the case's payload is frozen for source compatibility).
public enum SendoraCloudAuthStateChange {
    case signedIn(user: SendoraCloudAuthUser)
    case signedOut(reason: SendoraCloudAuthSignedOutReason)
    /// LEGACY after ADR-033: fires only when the SERVER reports a retirement,
    /// which a 5.4.0 sign-in never requests (it holds the guest instead).
    case deviceTakeover(user: SendoraCloudAuthUser?, retiredAnonUserId: String)
    case deletionCancelled(user: SendoraCloudAuthUser?)
    /// The settled boot state, exactly once per subscriber — INCLUDING
    /// `.signedOut`, `.unknown` and `.withheld` (the pre-5.4.0 replay carried
    /// only `.signedIn`, so a subscriber could not tell "no session" from "not
    /// hydrated yet"). `withheld` is non-nil iff `status == .withheld`.
    case initial(status: SendoraCloudAuthStatus, user: SendoraCloudAuthUser?, withheld: SendoraCloudWithheldInfo?)
    /// Same `sub`, different user object: a `link*()` attach, an unlink, email
    /// verification, a refresh that changed the user, or a claim (`merge`).
    case userUpdated(user: SendoraCloudAuthUser, cause: SendoraCloudAuthUserUpdatedCause)
    /// A guest was moved into a held slot (sign-in from a guest, `forceNew`
    /// mint, restore over a guest). `count` = guests held afterwards.
    case guestHeld(userId: String, count: Int)
    /// A held slot was emptied. `dead` = the server said "unavailable" when the
    /// token was presented — NOT an erasure signal.
    case guestReleased(userId: String, reason: SendoraCloudGuestReleasedReason, endReason: SendoraCloudRefreshEndReason?)
    /// An in-process transition INTO `withheld` (a refresh answered with a
    /// mismatching `project` claim). Never replayed — a hydrate that lands in
    /// `withheld` emits `.initial(status: .withheld, …)` instead.
    case sessionWithheld(expectedProjectId: String, actualProjectId: String?, userId: String)

    /// The shared snake_case wire name of this event (`AuthStateEvent`), the same
    /// token on all four SDKs.
    public var eventName: String {
        switch self {
        case .signedIn: return "signed_in"
        case .signedOut: return "signed_out"
        case .deviceTakeover: return "device_takeover"
        case .deletionCancelled: return "deletion_cancelled"
        case .initial: return "initial"
        case .userUpdated: return "user_updated"
        case .guestHeld: return "guest_held"
        case .guestReleased: return "guest_released"
        case .sessionWithheld: return "session_withheld"
        }
    }
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

/// What happened to the guest ("anonymous") account this device presented, on a
/// sign-in that produced an identified session (s58.278).
///
/// ⚠ The `nothingToRetire` case carries the wire value `"none"`. It is NOT
/// named `none` on purpose: a Swift enum case called `none` collides with
/// `Optional.none` at every comparison site, so `outcome == .none` would be
/// ambiguous between "no guest was presented" and "no value at all" — exactly
/// the conflation this whole field exists to remove.
///
/// LEGACY after ADR-033: a 5.4.0 sign-in never presents a guest token, so the
/// server answers `"none"` for every one of this SDK's sign-ins.
public enum AnonRetirementOutcome: String {
    /// The guest row was deleted. Its id arrives via `onDeviceTakeover`.
    case retired = "retired"
    /// A guest token WAS presented and the guest was NOT retired — that
    /// account still exists, so offering "recover your other account" is real.
    case preserved = "preserved"
    /// No guest token was presented; nothing to reconcile.
    case nothingToRetire = "none"
}

/// Detail handed to `onDeletionCancelled` subscribers (s58.269). Fires once
/// per sign-in that cancelled a pending self-service account deletion within
/// its grace window — the account is restored with the SAME user_id.
public struct DeletionCancelledEvent {
    public let userId: String
    public let at: Date
}

public final class SendoraCloudAuth {
    /// What a credentialed sign-in should do when the credential you present
    /// already belongs to an account (4.15.0).
    ///
    /// 5.4.0 (ADR-033): this option is consulted ONLY on a `link: true` call
    /// that is refused with 409 `CREDENTIAL_IN_USE`. `.adopt` then falls through
    /// to a plain sign-in bound to the same credential (`switchAccount()`): the
    /// device's guest is HELD on-device, never deleted. `.reject` / nil surfaces
    /// `.credentialInUse` so you can ask the player. On a plain sign-in (no
    /// `link`) it is accepted and IGNORED — a 5.4.0 body never carries a guest
    /// hint, so there is no destructive collision left to refuse.
    public enum CredentialCollisionPolicy: String {
        case adopt
        case reject
    }

    /// ADR-033 wave 1 — the machine's configuration, fixed at `configure()`.
    internal struct MachineConfig {
        var expectedProjectId: String?
        var configProjectId: String?
        var autoRestoreHeldGuest: Bool = true
        /// Test seam: when `false` the proactive cron is ARMED (observable via
        /// `cronArmed`) but no `Timer` / lifecycle observer is created.
        var schedulesTimers: Bool = true
        /// Test seam: a fixed clock (epoch ms). `nil` = the wall clock.
        var clock: (() -> Int64)? = nil
    }

    /// What the parent SDK does when the current identity is cleared (the
    /// `commit()` "anon-id/queue hook with the reason", INV-1).
    internal struct ClearEffects {
        /// Rotate the analytics device id — ONLY at a person-boundary (explicit
        /// signOut, account deletion). A switch or an involuntary session death
        /// is the same person, so the id survives (SudokuHurdle r6).
        let rotateDeviceId: Bool
        /// Drop the queued events — only on `accountDeleted` (the s58.353 rule
        /// as a table column) and `reset()`.
        let clearQueue: Bool
    }

    /// The held-guest capacity K (ADR-033 §3.2, confirmed §8-Q19).
    public static let heldGuestSlots = 5
    /// The ONLY server codes that mean "this refresh token is dead" (INV-6).
    internal static let deadCodes: [String] = ["INVALID_REFRESH_TOKEN"]
    /// A held slot is released on a dead verdict ONLY for these end reasons
    /// (rev 2 2b); `reuse` / absent keeps the slot (`restoreFailed`, retryable).
    internal static let releaseHeldOnEndReasons: [SendoraCloudRefreshEndReason] = [.deleted, .revoked, .expired]
    /// The events `withheld` rejects by name (§3.2); mirrored from the fixture.
    internal static let rejectedInWithheld: [String] = ["MINT", "SIGN_IN", "LINK", "CLAIM", "RESTORE", "DISCARD", "DELETE", "SESSION_VERB"]

    internal let client: APIClient
    internal let storage: SendoraStorage
    internal let machineConfig: MachineConfig
    internal let onIdentityChange: (String?) -> Void
    internal let onIdentityCleared: (ClearEffects) -> Void
    internal let onIdentityWithheld: () -> Void

    // ── Machine state. Every field below is written ONLY by the commit funnel
    // (SendoraCloudAuth+Commit.swift) under `lock`.

    /// The installed session (`anonymous` / `identified`).
    internal var current: AuthSessionRecord?
    /// A refresh token on disk with no readable user — LIMBO_A = `unknown`.
    internal var limbo: LimboRecord?
    /// `withheld`: the refused record, held in memory only (nothing persisted).
    internal var withheldState: WithheldState?
    /// K held slots; `nil` = empty. `unreadableSlots` are occupied by JSON this
    /// build cannot decode — kept, ignored, never cleared (INV-9).
    internal var slots: [HeldSlotRecord?] = Array(repeating: nil, count: SendoraCloudAuth.heldGuestSlots)
    internal var unreadableSlots: Set<Int> = []
    /// Set once we have PROOF the device clock runs fast: a token the server
    /// minted SECONDS AGO already reads past its own `exp`. Releases the `exp`
    /// guard for this process. Never persisted (re-learned per process).
    internal var clockSkewConfirmed = false
    internal let lock = NSLock()
    /// Serial queue for public auth ops. All identity verbs funnel through here
    /// so concurrent invocations execute one at a time. Refresh runs as a
    /// single-flight that identity attempts AWAIT at start (§3.3 scheduling rule).
    internal let opsQueue = DispatchQueue(label: "com.sendora.sdk.auth.ops")
    internal var refreshInFlight: [(String?) -> Void] = []
    internal var isRefreshing = false
    internal let refreshSafetyMs: Int64 = 30_000
    /// Inline device-takeover listeners. UUID-keyed so callers can
    /// unsubscribe via the returned closure. Lock-protected.
    private var takeoverListeners: [UUID: (DeviceTakeoverEvent) -> Void] = [:]
    private var lastTakeover: DeviceTakeoverEvent?
    /// Inline deletion-cancelled listeners (s58.269). UUID-keyed; lock-protected.
    private var deletionCancelledListeners: [UUID: (DeletionCancelledEvent) -> Void] = [:]
    private var lastDeletionCancelled: DeletionCancelledEvent?
    private var lastAnonRetirement: AnonRetirementOutcome?
    /// Inline auth-state listeners (4.13.0). UUID-keyed; lock-protected.
    private var authStateListeners: [UUID: (SendoraCloudAuthStateChange) -> Void] = [:]
    /// True once the Keychain re-hydrate in `init` has run. Distinguishes "no
    /// session restored YET" from "genuinely signed out".
    internal var hydrated = false
    /// Observable cron state (the `Timer` itself is created only when
    /// `machineConfig.schedulesTimers`).
    internal private(set) var cronArmed = false
    private var proactiveTimer: Timer?
    private var proactiveAppActiveObserver: NSObjectProtocol?
    internal var lastSignedInCauseValue: SendoraCloudAuthSignedInCause?
    internal var lastSignedOutEndReasonValue: SendoraCloudRefreshEndReason?
    /// 5.6.0: `mfaChallengeToken` → the email its `/login` was for, so the
    /// `knownDeviceToken` an `/mfa/challenge` returns is filed under the right
    /// account. Memory only, on `opsQueue`, at most 8 entries.
    internal var pendingMfaEmails: [(challengeToken: String, email: String)] = []

    internal struct LimboRecord {
        var refreshToken: String
        var accessToken: String?
        var accessExpiresAt: Int64
    }

    internal struct WithheldState {
        var info: SendoraCloudWithheldInfo
        var refreshToken: String
        var accessToken: String
        var accessExpiresAt: Int64
        var user: SendoraCloudAuthUser?
    }

    init(
        client: APIClient,
        storage: SendoraStorage,
        config: MachineConfig = MachineConfig(),
        onIdentityChange: @escaping (String?) -> Void,
        onIdentityCleared: @escaping (ClearEffects) -> Void,
        onIdentityWithheld: @escaping () -> Void
    ) {
        self.client = client
        self.storage = storage
        self.machineConfig = config
        self.onIdentityChange = onIdentityChange
        self.onIdentityCleared = onIdentityCleared
        self.onIdentityWithheld = onIdentityWithheld
        hydrate()
    }

    // MARK: - Status

    /// The machine state (ADR-033 §3.2). Sync, lock-protected. `unknown` ≠
    /// `signedOut`, `withheld` ≠ `signedOut` — and this is the ONLY call that
    /// tells them apart (`currentUser` is nil in all three). Default-branch.
    public func status() -> SendoraCloudAuthStatus {
        lock.lock(); defer { lock.unlock() }
        return statusLocked()
    }

    internal func statusLocked() -> SendoraCloudAuthStatus {
        if !hydrated { return .unknown }
        if withheldState != nil { return .withheld }
        if let c = current { return c.user.isAnonymous ? .anonymous : .identified }
        if limbo != nil { return .unknown }
        return .signedOut
    }

    /// Resolves after the Keychain hydrate with the settled boot status — which
    /// may be `.unknown` (a refresh token with no readable user, re-judged by the
    /// single gap-fill refresh) or `.withheld`. NEVER waits on the network; on
    /// iOS the hydrate is synchronous inside `configure()`, so this completes
    /// immediately.
    public func authStateReady(completion: @escaping (SendoraCloudAuthStatus) -> Void) {
        completion(status())
    }

    public var currentUser: SendoraCloudAuthUser? {
        lock.lock(); defer { lock.unlock() }
        return current?.user
    }

    /// Synchronous read — returns whatever's cached, even if expired. `nil` in
    /// `withheld` (§3.2). Prefer `getAccessToken(completion:)` for transparent refresh.
    public var accessToken: String? {
        lock.lock(); defer { lock.unlock() }
        if withheldState != nil { return nil }
        return current?.accessToken ?? limbo?.accessToken
    }

    /// The stored refresh token, or `nil` when signed out or `withheld`. Kept
    /// for integrators that journal it; prefer the held-guest verbs.
    public func getRefreshToken() -> String? {
        lock.lock(); defer { lock.unlock() }
        if withheldState != nil { return nil }
        return current?.refreshToken ?? limbo?.refreshToken
    }

    /// Why the most recent `.signedIn` fired (`mint` / `signIn` / `restore` /
    /// `link`). Set BEFORE the event is delivered, so a listener may read it
    /// inside its `.signedIn(user:)` arm. `.restore` ⇒ re-register push.
    public func lastSignedInCause() -> SendoraCloudAuthSignedInCause? {
        lock.lock(); defer { lock.unlock() }
        return lastSignedInCauseValue
    }

    /// The server's own verdict behind the most recent `.signedOut` (5.4.1):
    /// `revoked` / `deleted` / `expired` / `reuse` / `unknown` when the session
    /// died on a rejected refresh and the server named a reason; `nil` after
    /// `signOut()` / `deleteAccount()` / `discardWithheld()` or from an older
    /// backend. Set BEFORE the event is delivered, so a listener may read it
    /// inside its `.signedOut(reason:)` arm. The `reason` itself stays
    /// `sessionExpired` for every dead verdict.
    public func lastSignedOutEndReason() -> SendoraCloudRefreshEndReason? {
        lock.lock(); defer { lock.unlock() }
        return lastSignedOutEndReasonValue
    }

    // MARK: - Hydrate (the HYDRATE rows, boot entry from `unknown`)

    /// Read-first the 5.4.0 `sendora_auth_session` record, with the four frozen
    /// keys as the authority on WHETHER a session exists (they are written by
    /// every version on every install, so after a downgrade→upgrade cycle they are
    /// at least as fresh as the record): legacy refresh absent → signed out;
    /// present and equal to the record's → the record; present and different →
    /// rebuild from the four keys and write-forward. Then the ProjectGuard.
    private func hydrate() {
        let legacyRefresh = storage.authRefreshToken
        let legacyAccess = storage.authAccessToken
        let legacyExp = storage.authAccessExpiresAt
        let legacyUserJson = storage.authUserJson
        let legacyUser = legacyUserJson.flatMap { Self.decodeUser($0) }
        var record = storage.authSessionJson.flatMap { Self.decodeSessionRecord($0) }
        var pending = record?.heldReportPending ?? []

        // Slots first (they never depend on the current session).
        var readSlots: [HeldSlotRecord?] = Array(repeating: nil, count: Self.heldGuestSlots)
        var unreadable: Set<Int> = []
        for i in 0..<Self.heldGuestSlots {
            guard let json = storage.heldSlotJson(i) else { continue }
            if let slot = HeldSlotRecord.decode(json) { readSlots[i] = slot } else { unreadable.insert(i) }
        }

        var outcome: HydrateOutcome = .signedOut
        if let refresh = legacyRefresh {
            if let r = record, r.refreshToken == refresh {
                outcome = .record(r, writeForward: false)
            } else if let user = legacyUser, !user.id.isEmpty, let access = legacyAccess, !access.isEmpty {
                let rebuilt = AuthSessionRecord(
                    user: user, accessToken: access, refreshToken: refresh, accessExpiresAt: legacyExp,
                    sid: jwtStringClaim(access, "sid"), heldReportPending: pending
                )
                record = rebuilt
                outcome = .record(rebuilt, writeForward: true)
            } else {
                // LIMBO_A: a refresh token (independently valid, the only thing
                // that can recover this account) with no readable user. `unknown`,
                // never signed out, never a mint (INV-9).
                // A record whose refresh token is not the frozen one is a
                // LEFTOVER of another session (a 5.4→5.3→sign-out/switch→5.4
                // cycle: a 5.3.0 clears only the four frozen keys) — cleared
                // silently by the commit, never trusted.
                outcome = .limbo(LimboRecord(refreshToken: refresh, accessToken: legacyAccess, accessExpiresAt: legacyExp),
                                 clearLeftoverRecord: record != nil)
            }
        } else if legacyUserJson != nil || record != nil {
            // LIMBO_B: a user blob with no refresh token — a stale blob, or a
            // 5.4.0 record with NO frozen counterpart (a downgraded 5.3.0's
            // signOut()/deleteAccount() clears only the four frozen keys, so the
            // record of the signed-out / deleted account survives the cycle).
            // Trust the record ONLY when its refresh token equals the frozen
            // one: here there is none, so it is a leftover — cleared silently
            // (no event beyond the boot `initial`, no network) and the state
            // is signed out (§3.3 row 4). NEVER reinstalled.
            outcome = .staleBlob
        }

        switch outcome {
        case .record(let r, let writeForward):
            commitHydrate(record: r, writeForward: writeForward, slots: readSlots, unreadable: unreadable)
        case .limbo(let l, let clearLeftover):
            commitHydrateLimbo(l, clearLeftoverRecord: clearLeftover, slots: readSlots, unreadable: unreadable)
        case .staleBlob:
            commitHydrateStaleBlob(slots: readSlots, unreadable: unreadable)
        case .signedOut:
            commitHydrateSignedOut(slots: readSlots, unreadable: unreadable)
        }
        pending = pending.filter { id in readSlots.contains { $0?.userId == id } }
        // `withheld` makes NO network call of any kind (§3.2) — the report
        // waits for a hydrate that is not withheld.
        if status() != .withheld { retryPendingHeldReports(pending) }
    }

    private enum HydrateOutcome {
        case record(AuthSessionRecord, writeForward: Bool)
        case limbo(LimboRecord, clearLeftoverRecord: Bool)
        case staleBlob
        case signedOut
    }

    /// B15: a `POST /guest/held` report the previous process never got an
    /// acknowledgement for. Fire-and-forget, idempotent server-side.
    private func retryPendingHeldReports(_ userIds: [String]) {
        guard !userIds.isEmpty else { return }
        lock.lock()
        let targets: [(String, String)] = userIds.compactMap { id in
            slots.compactMap { $0 }.first { $0.userId == id }.map { (id, $0.refreshToken) }
        }
        lock.unlock()
        for (id, token) in targets { reportGuestHeld(userId: id, refreshToken: token) }
    }

    internal func reportGuestHeld(userId: String, refreshToken: String) {
        client.post(path: "/auth-service/guest/held", body: ["refreshToken": refreshToken]) { [weak self] response in
            guard let self = self, (response?["success"] as? Bool) == true else { return }
            self.commitHeldReportAcknowledged(userId: userId)
        }
    }

    // MARK: - Access token (token liveness — never decides identity, INV-6)

    /// The cached-token guard, and the only place the two deadlines are
    /// combined. Both must agree before a cached token is served:
    ///
    /// 1. the locally-tracked deadline (`now + expiresIn` at mint) — immune to
    ///    a constantly-wrong clock, blind to a clock that MOVES;
    /// 2. the token's own `exp` — immune to a clock that moves, wrong by the
    ///    full offset on a constantly-wrong clock.
    ///
    /// Guard 2 is released once `clockSkewConfirmed` proves which failure mode
    /// we are in. Reported by Word Hurdle with a token 1929s past its `exp`.
    internal func canServeToken(_ token: String?, expiresAt: Int64, nowMs: Int64) -> Bool {
        guard let token = token, !token.isEmpty, expiresAt > 0 else { return false }
        if nowMs >= expiresAt - refreshSafetyMs { return false }
        lock.lock()
        let skewKnown = clockSkewConfirmed
        lock.unlock()
        if skewKnown { return true }
        return accessTokenExpIsFuture(token, nowMs: nowMs)
    }

    /// Guard 1 alone: does the locally-tracked deadline still claim life?
    private func trackedDeadlineAlive(nowMs: Int64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let c = current, !c.accessToken.isEmpty else { return false }
        return c.accessExpiresAt > 0 && nowMs < c.accessExpiresAt - refreshSafetyMs
    }

    /// True when a cached token is unusable ONLY because `exp` contradicts a
    /// tracked deadline that still claims life.
    private func deadlinesDisagree(nowMs: Int64) -> Bool {
        let snapshot = currentTokenSnapshot()
        return trackedDeadlineAlive(nowMs: nowMs)
            && !canServeToken(snapshot.token, expiresAt: snapshot.expiresAt, nowMs: nowMs)
    }

    private func learnClockSkewFrom(_ freshToken: String, nowMs: Int64) {
        guard !accessTokenExpIsFuture(freshToken, nowMs: nowMs) else { return }
        lock.lock()
        clockSkewConfirmed = true
        lock.unlock()
    }

    internal func currentTokenSnapshot() -> (token: String?, expiresAt: Int64) {
        lock.lock(); defer { lock.unlock() }
        if withheldState != nil { return (nil, 0) }
        if let c = current { return (c.accessToken, c.accessExpiresAt) }
        if let l = limbo { return (l.accessToken, l.accessExpiresAt) }
        return (nil, 0)
    }

    /// Refresh — and when the two deadlines disagree, let the token that comes
    /// back say which one was lying. Probing ONLY on a refresh performed BECAUSE
    /// `exp` contradicted a live tracked deadline separates the cases (s58.281).
    private func refreshAndReconcile(nowMs: Int64, force: Bool = false, completion: @escaping (String?) -> Void) {
        let reconciling = deadlinesDisagree(nowMs: nowMs)
        refreshAccessToken(force: force) { [weak self] token in
            if reconciling, let self = self, let token = token, !token.isEmpty {
                self.learnClockSkewFrom(token, nowMs: Int64(Date().timeIntervalSince1970 * 1000))
            }
            completion(token)
        }
    }

    /// Returns a non-expired access token, refreshing (single-flight) when the
    /// cached one is past expiry. `nil` when signed out, offline with nothing
    /// servable, or `withheld` (no refresh, no network — §3.2).
    ///
    /// Pass `forceRefresh: true` when the caller has out-of-band evidence that
    /// the tracked deadline is wrong (it decoded `exp` itself, or ate a 401).
    /// It skips the cache but NOT the single-flight or the backoff cooldown.
    public func getAccessToken(forceRefresh: Bool = false, completion: @escaping (String?) -> Void) {
        let state = status()
        if state == .withheld { completion(nil); return }
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let snapshot = currentTokenSnapshot()
        if state == .unknown {
            // LIMBO_A: drive the single gap-fill refresh so the state settles
            // (§3.2); offline, the stashed access token is the fallback.
            refreshAndReconcile(nowMs: nowMs, force: true) { token in
                if let token = token { completion(token); return }
                if let stashed = snapshot.token, self.status() == .unknown,
                   self.canServeToken(stashed, expiresAt: snapshot.expiresAt, nowMs: nowMs) {
                    completion(stashed)
                } else {
                    completion(nil)
                }
            }
            return
        }
        if !forceRefresh, let token = snapshot.token,
           canServeToken(token, expiresAt: snapshot.expiresAt, nowMs: nowMs) {
            completion(token)
            return
        }
        refreshAndReconcile(nowMs: nowMs, force: forceRefresh, completion: completion)
    }

    /// Public since 5.4.0 (the README documented it for years while it was
    /// private). Forces one refresh of the current session's tokens; `nil` when
    /// nothing could be refreshed. Prefer `getAccessToken`.
    public func refreshAccessToken(completion: @escaping (String?) -> Void) {
        refreshAccessToken(force: true, completion: completion)
    }

    /// `force` skips the stashed-token short-circuit (a caller with out-of-band
    /// evidence the tracked deadline is wrong); the cron and the sibling-join
    /// path leave it off.
    internal func refreshAccessToken(force: Bool, completion: @escaping (String?) -> Void) {
        opsQueue.async { self.performRefresh(force: force, completion) }
    }

    /// The refresh body. Runs ON `opsQueue` (an identity attempt calls it
    /// directly while it holds the queue). Single-flight: a second caller joins
    /// the in-flight request. Re-reads the stored refresh token at firing time.
    internal func performRefresh(force: Bool = false, _ completion: @escaping (String?) -> Void) {
        lock.lock()
        refreshInFlight.append(completion)
        if isRefreshing {
            lock.unlock()
            return
        }
        isRefreshing = true
        // `withheld` never refreshes (no cron, no gap-fill — §3.2).
        let sent: String? = withheldState == nil ? (current?.refreshToken ?? limbo?.refreshToken) : nil
        let stashedAccess = current?.accessToken ?? limbo?.accessToken
        let stashedExp = current?.accessExpiresAt ?? limbo?.accessExpiresAt ?? 0
        lock.unlock()

        guard let refresh = sent else {
            completeRefresh(token: nil)
            return
        }

        // Short-circuit: a sibling rotated and stashed a fresh token before we
        // acquired `isRefreshing`. Same guard as the fast path — no clock-skew
        // learning here, nothing proves this token just arrived from the server.
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        if !force, let stashedAccess = stashedAccess, !stashedAccess.isEmpty,
           canServeToken(stashedAccess, expiresAt: stashedExp, nowMs: nowMs) {
            completeRefresh(token: stashedAccess)
            return
        }

        client.requestWithDetails(method: "POST", path: "/auth-service/token/refresh",
                                  body: ["refreshToken": refresh]) { [weak self] rich in
            guard let self = self else { return }
            // The rotated trio lives under `data.tokens` (alongside `data.user`),
            // matching every other auth response. It was FLAT before s58.76, and
            // reading the wrong level does not fail loudly — it just never
            // refreshes, so the session dies at access-token expiry and the app
            // mints a fresh anonymous user, silently fragmenting the account.
            // Accept both levels.
            let data = (rich.body?["data"] as? [String: Any]) ?? [:]
            let tokenFields = (data["tokens"] as? [String: Any]) ?? data
            let token = self.routeRefreshResult(sent: refresh, rich: rich, tokenFields: tokenFields)
            self.completeRefresh(token: token)
        }
    }

    /// Route a `/token/refresh` answer for the CURRENT session or the limbo
    /// record by the token that was SENT (INV-2 token CAS): a rotation installs
    /// only while `sent` is still the stored token; a dead verdict clears only the
    /// session it was about; anything else (429, 5xx, generic 401, network) is
    /// transient and changes no identity (INV-6). Returns the access token to hand
    /// to the waiting callers, or `nil`.
    private func routeRefreshResult(sent: String, rich: APIClient.RichResponse, tokenFields: [String: Any]?) -> String? {
        let errorEnvelope = rich.body?["error"] as? [String: Any]
        if rich.statusCode == 0 { return nil } // transport failure — backoff, no identity change
        if !(200..<300).contains(rich.statusCode) {
            let code = rich.errorCode ?? (errorEnvelope?["code"] as? String) ?? ""
            if Self.isDeadRefreshError(code) {
                let endReason = Self.readEndReason(errorEnvelope)
                _ = commitRefreshDead(sent: sent, endReason: endReason)
            }
            return nil
        }
        guard let fields = tokenFields,
              let accessToken = fields["accessToken"] as? String, !accessToken.isEmpty,
              let refreshToken = fields["refreshToken"] as? String, !refreshToken.isEmpty,
              let expiresIn = fields["expiresIn"] as? Int else {
            return nil
        }
        let tokens = SendoraCloudAuthTokens(
            accessToken: accessToken, refreshToken: refreshToken, expiresIn: expiresIn,
            tokenType: fields["tokenType"] as? String ?? "Bearer"
        )
        let user = parseSuccess(rich.body)
        return commitRefreshOk(sent: sent, tokens: tokens, user: user)
    }

    internal static func readEndReason(_ error: [String: Any]?) -> SendoraCloudRefreshEndReason? {
        guard let details = error?["details"] as? [String: Any],
              let raw = details["endReason"] as? String else { return nil }
        return SendoraCloudRefreshEndReason(rawValue: raw)
    }

    /// Block the current op (on `opsQueue`) until any in-flight refresh lands —
    /// the §3.3 scheduling rule that makes the sid-CAS a backstop: an identity
    /// attempt never snapshots a token a rotation is about to replace (the "GC
    /// sheet open during refresh" interleaving).
    internal func awaitRefreshInflight() {
        lock.lock()
        guard isRefreshing else { lock.unlock(); return }
        let sem = DispatchSemaphore(value: 0)
        refreshInFlight.append { _ in sem.signal() }
        lock.unlock()
        sem.wait()
    }

    /// Refresh synchronously from within an op that holds `opsQueue`.
    internal func performRefreshSync() -> String? {
        let sem = DispatchSemaphore(value: 0)
        var out: String?
        performRefresh { token in out = token; sem.signal() }
        sem.wait()
        return out
    }

    /// A Bearer for the Bearer verbs, from within an op on `opsQueue`: the
    /// cached token when servable, else one refresh.
    internal func bearerTokenOnQueue() -> String? {
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let snapshot = currentTokenSnapshot()
        if let token = snapshot.token, canServeToken(token, expiresAt: snapshot.expiresAt, nowMs: nowMs) { return token }
        return performRefreshSync()
    }

    // MARK: - Proactive refresh (s58.73)

    /// Background timer + UIApplication.didBecomeActive observer that
    /// triggers a refresh when the access token enters the last 20%
    /// of its TTL ± 30s jitter. Armed ONLY by an install commit; stopped by a
    /// clear / withhold commit (ADR-033 INV-1). Never refreshes a held guest.
    internal func startProactiveRefreshCron() {
        lock.lock()
        let alreadyArmed = cronArmed
        cronArmed = true
        lock.unlock()
        guard !alreadyArmed, machineConfig.schedulesTimers else { return }
        let tick: () -> Void = { [weak self] in
            guard let self = self else { return }
            let snapshot = self.currentTokenSnapshot()
            guard let token = snapshot.token else { return }
            let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
            let expMs = snapshot.expiresAt
            // Repair, not just anticipate: the combined guard is the only thing
            // here that can see a deadline left stale by a backwards clock step.
            if !self.canServeToken(token, expiresAt: expMs, nowMs: nowMs) {
                self.refreshAndReconcile(nowMs: nowMs) { _ in }
                return
            }
            let remainingMs = expMs - nowMs
            if remainingMs <= 0 { return }
            let guessOriginalMs: Int64 = max(remainingMs, 5 * 60 * 1000)
            let jitter = Int64.random(in: -30_000...30_000)
            let fireWhenRemainingMs = Int64(Double(guessOriginalMs) * 0.2) + jitter
            if remainingMs <= fireWhenRemainingMs {
                self.refreshAccessToken(force: false) { _ in }
            }
        }
        tick()
        let t = Timer(timeInterval: 60.0, repeats: true) { _ in tick() }
        RunLoop.main.add(t, forMode: .common)
        self.proactiveTimer = t
        #if canImport(UIKit)
        self.proactiveAppActiveObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { _ in tick() }
        #endif
    }

    internal func stopProactiveRefreshCron() {
        lock.lock()
        cronArmed = false
        lock.unlock()
        proactiveTimer?.invalidate()
        proactiveTimer = nil
        if let obs = proactiveAppActiveObserver {
            NotificationCenter.default.removeObserver(obs)
            proactiveAppActiveObserver = nil
        }
    }

    internal func completeRefresh(token: String?) {
        let callbacks: [(String?) -> Void] = {
            lock.lock(); defer { lock.unlock() }
            let cs = refreshInFlight
            refreshInFlight.removeAll()
            isRefreshing = false
            return cs
        }()
        for cb in callbacks { cb(token) }
    }

    // MARK: - Listeners

    /// Register a callback fired when the backend retires an anon
    /// `user_id` during a signin on this device. Use it to delete
    /// the matching row from any local mirror table — Sendora's own
    /// `auth_service_users` + `push_tokens` are already cleaned up
    /// server-side. Returns an unsubscribe closure.
    ///
    /// ⚠ LEGACY after ADR-033 (5.4.0): a 5.4.0 sign-in — signIn / loginSocial /
    /// **signInWithGameCenter** / challengeMfa / verifyMagicLink / verifyEmailOtp
    /// / passkey / SSO — never presents the guest's token, so the server never
    /// retires the guest and this listener never fires for this SDK's sign-ins.
    /// The guest is HELD on-device instead: subscribe to `.guestHeld` on
    /// `onAuthStateChanged` and read `heldGuests()`. Kept callable so installed
    /// handlers compile; it still fires if an OLDER SDK on the same account
    /// triggers a server-side retirement that this device later observes in a
    /// response (`retiredAnonUserId`).
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
    /// session, or nil if none.
    public func getLastDeviceTakeover() -> DeviceTakeoverEvent? {
        lock.lock(); defer { lock.unlock() }
        return lastTakeover
    }

    /// Internal — called with the `retiredAnonUserId` parsed off a backend
    /// response. Validates UUID shape before firing (a tampered value handed to a
    /// listener that interpolates it into a path is a path-injection sink).
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
        emitAuthState(.deviceTakeover(user: currentUser, retiredAnonUserId: retiredAnonUserId))
    }

    /// Subscribe to deletion-cancelled events (s58.269): fires when a sign-in
    /// cancelled a pending self-service account deletion within its grace
    /// window (the account is restored, same user_id). Returns an unsubscribe closure.
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

    /// What the last sign-in did with this device's guest account, or nil if no
    /// sign-in has happened this session (s58.278). LEGACY after ADR-033: a 5.4.0
    /// sign-in never presents the guest, so the server states `nothingToRetire`
    /// for every one of this SDK's sign-ins — read `heldGuests()` instead.
    public func getLastAnonRetirement() -> AnonRetirementOutcome? {
        lock.lock(); defer { lock.unlock() }
        return lastAnonRetirement
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
        emitAuthState(.deletionCancelled(user: currentUser))
    }

    /// Subscribe to every auth-state transition — the single stream that answers
    /// "what happened to my session?". Firebase `addStateDidChangeListener` /
    /// Supabase `onAuthStateChange` parity.
    ///
    /// Replay on subscribe (once the Keychain hydrate has run — always, on iOS):
    /// `.initial(status:user:withheld:)` exactly once, INCLUDING `.signedOut`,
    /// `.unknown` and `.withheld`; then, when a session is installed, the
    /// pre-5.4.0 `.signedIn(user:)` replay as well (kept verbatim for installed
    /// listeners). A failed sign-in emits NOTHING: the session is unchanged.
    /// Replace emits `.guestHeld` then ONE `.signedIn` — no `.signedOut`.
    /// Listeners are best-effort. Returns an unsubscribe closure.
    @discardableResult
    public func onAuthStateChanged(_ listener: @escaping (SendoraCloudAuthStateChange) -> Void) -> () -> Void {
        let key = UUID()
        let replay: (status: SendoraCloudAuthStatus, user: SendoraCloudAuthUser?, withheld: SendoraCloudWithheldInfo?)? = {
            lock.lock(); defer { lock.unlock() }
            authStateListeners[key] = listener
            guard hydrated else { return nil }
            return (statusLocked(), current?.user, withheldState?.info)
        }()
        if let r = replay {
            listener(.initial(status: r.status, user: r.user, withheld: r.withheld))
            if let user = r.user { listener(.signedIn(user: user)) }
        }
        return { [weak self] in
            guard let self = self else { return }
            self.lock.lock(); defer { self.lock.unlock() }
            self.authStateListeners.removeValue(forKey: key)
        }
    }

    /// Internal — fan a state change out to subscribers. Snapshot-then-dispatch
    /// outside the lock so a listener can re-enter the auth surface safely.
    internal func emitAuthState(_ change: SendoraCloudAuthStateChange) {
        let snapshot: [(SendoraCloudAuthStateChange) -> Void] = {
            lock.lock(); defer { lock.unlock() }
            return Array(authStateListeners.values)
        }()
        for fn in snapshot { fn(change) }
    }

    /// Fire BOTH lifecycle listeners (device-takeover + deletion-cancelled)
    /// from a backend auth response — the single place that parses the two
    /// optional signals so every sign-in path emits them consistently (s58.269).
    func fireLifecycleSignals(from response: [String: Any]?, identifiedUserId: String) {
        let data = response?["data"] as? [String: Any]
        if let retired = data?["retiredAnonUserId"] as? String, !retired.isEmpty {
            fireDeviceTakeover(retiredAnonUserId: retired, identifiedUserId: identifiedUserId)
        }
        // s58.278 — record the guest-account outcome. Only when the server
        // states it; an older backend leaves the previous value untouched
        // rather than asserting "nothing was retired".
        if let raw = data?["anonRetirement"] as? String,
           let outcome = AnonRetirementOutcome(rawValue: raw) {
            lock.lock(); lastAnonRetirement = outcome; lock.unlock()
        }
        if let restored = data?["reactivatedFromDeletion"] as? Bool, restored {
            fireDeletionCancelled(userId: identifiedUserId)
        }
    }

    // MARK: - Parsing + error coercion

    // `internal`, not `private`: `SendoraCloudPasskeys` is a separate file and
    // needs this to surface a step-up refusal on `deletePasskey`.
    internal func parseError(_ response: [String: Any]?) -> SendoraCloudAuthError? {
        guard let response = response else {
            // No body at all — the request never produced one: offline, TLS
            // failure, request timed out, breaker open. Message kept verbatim,
            // apps match on it.
            return .network("Network request failed")
        }
        if let success = response["success"] as? Bool, success { return nil }
        let error = response["error"] as? [String: Any]
        let code = error?["code"] as? String ?? ""
        let message = error?["message"] as? String ?? "Auth request failed"
        let status = (error?["status"] as? Int) ?? 0
        return Self.asAuthError(
            code: code,
            message: message,
            status: status,
            retryAfterSeconds: Self.readRetryAfterSeconds(error)
        )
    }

    /// Error mapping for the paths that carry the HTTP status + the typed
    /// envelope. Unmapped codes become `.rejected` so the caller keeps the
    /// backend code, the status and the server's retry hint.
    internal func parseError(_ rich: APIClient.RichResponse) -> SendoraCloudAuthError? {
        if rich.statusCode == 0 { return .network("Network request failed") }
        if (200..<300).contains(rich.statusCode) {
            if let success = rich.body?["success"] as? Bool, success { return nil }
            if rich.body == nil {
                return .rejected(
                    code: "PARSE_ERROR",
                    message: "Unreadable response (HTTP \(rich.statusCode))",
                    status: rich.statusCode,
                    retryAfterSeconds: nil
                )
            }
        }
        let error = rich.body?["error"] as? [String: Any]
        let code = rich.errorCode ?? (error?["code"] as? String) ?? "HTTP_\(rich.statusCode)"
        let message = rich.errorMessage ?? (error?["message"] as? String) ?? "Auth request failed"
        return Self.asAuthError(
            code: code,
            message: message,
            status: rich.statusCode,
            retryAfterSeconds: Self.readRetryAfterSeconds(error)
        )
    }

    /// The single coercion point for a failure the SDK did not construct itself:
    /// a raw `code` + `message` (+ HTTP status, + the server's retry hint) in,
    /// a typed error whose `kind` is ALWAYS defined out.
    ///
    /// ⚠ The default MUST stay non-fatal. That is what makes the one-code
    /// `isDeadRefreshError` allow-list safe rather than merely lucky.
    static func asAuthError(
        code: String,
        message: String,
        status: Int,
        retryAfterSeconds: Int? = nil
    ) -> SendoraCloudAuthError {
        if let mapped = mapKnownErrorCode(code, message: message) { return mapped }
        return .rejected(code: code, message: message, status: status, retryAfterSeconds: retryAfterSeconds)
    }

    /// Codes with a dedicated case since before 4.13.0. Kept in one place so the
    /// two `parseError` entry points can never drift.
    private static func mapKnownErrorCode(_ code: String, message: String) -> SendoraCloudAuthError? {
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
        return nil
    }

    /// Pull the server's backoff hint out of an error envelope.
    internal static func readRetryAfterSeconds(_ error: [String: Any]?) -> Int? {
        guard let details = error?["details"] as? [String: Any] else { return nil }
        guard let seconds = details["retryAfterSeconds"] as? NSNumber else { return nil }
        let value = seconds.intValue
        return value > 0 ? value : nil
    }

    internal func parseSuccess(_ response: [String: Any]?) -> SendoraCloudAuthUser? {
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
            lastLoginMethod: userDict["lastLoginMethod"] as? String,
            project: userDict["project"] as? String                // B17
        )
    }

    internal func parseTokens(_ response: [String: Any]?) -> SendoraCloudAuthTokens? {
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

    internal static func decodeUser(_ json: String) -> SendoraCloudAuthUser? {
        guard let data = json.data(using: .utf8),
              let user = try? JSONDecoder().decode(SendoraCloudAuthUser.self, from: data),
              !user.id.isEmpty else { return nil }
        return user
    }

    internal static func encodeUser(_ user: SendoraCloudAuthUser) -> String? {
        guard let json = try? JSONEncoder().encode(user) else { return nil }
        return String(data: json, encoding: .utf8)
    }

    internal static func decodeSessionRecord(_ json: String) -> AuthSessionRecord? {
        guard let data = json.data(using: .utf8),
              let record = try? JSONDecoder().decode(AuthSessionRecord.self, from: data),
              !record.user.id.isEmpty, !record.refreshToken.isEmpty else { return nil }
        return record
    }

    internal static func encodeSessionRecord(_ record: AuthSessionRecord) -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let json = try? encoder.encode(record) else { return nil }
        return String(data: json, encoding: .utf8)
    }

    /// Canonical UUID validator. Defends against tampered
    /// `sendora_retired_anon` fragment / response values reaching
    /// host-app listeners as a path-injection sink.
    internal static func isCanonicalUuid(_ s: String) -> Bool {
        return UUID(uuidString: s) != nil
    }

    /// Backend error codes on /token/refresh that mean the stored refresh token
    /// is permanently dead (`DEAD_CODES` in `packages/shared`). ONLY the specific
    /// code: a generic 401 on this route is NOT proof the refresh token is dead
    /// (the API-key middleware returns the same 401 for a rotated `pk_` key), and
    /// a RATE_LIMIT says nothing about token validity. Failing to recognise a
    /// genuinely dead token only costs a retry loop the backoff bounds; wiping a
    /// live one is irreversible.
    internal static func isDeadRefreshError(_ code: String) -> Bool {
        return deadCodes.contains(code)
    }

    /// Fire-and-forget server-side revoke of a refresh token (signOut, the
    /// identified→identified switch hygiene, a CAS-dropped result, a fresh-mint
    /// project mismatch). Never awaited; the local state is already decided.
    internal func fireAndForgetRevoke(_ refreshToken: String) {
        client.post(path: "/auth-service/token/revoke", body: ["refreshToken": refreshToken]) { _ in }
    }

    /// Synchronous request from within an op that holds `opsQueue`.
    internal func requestSync(method: String, path: String, body: [String: Any]?, headers: [String: String]? = nil) -> APIClient.RichResponse {
        let sem = DispatchSemaphore(value: 0)
        var out = APIClient.RichResponse(statusCode: 0, body: nil, errorCode: "NETWORK", errorMessage: "No response")
        client.requestWithDetails(method: method, path: path, body: body, headers: headers) { rich in
            out = rich
            sem.signal()
        }
        sem.wait()
        return out
    }
}

// MARK: - Bearer verbs that are NOT identity transitions (SESSION_VERB row)
//
// They run on the current Bearer, outside the commit funnel, and a refusal
// surfaces through the typed `Result` (s58.335: no SDK transport throws on a
// non-2xx, so a discarded return would report every failure as success). In
// `withheld` every one of them rejects `SESSION_WITHHELD` with no network.

extension SendoraCloudAuth {
    /// The withheld refusal, when `status() == .withheld` (§3.2: every verb
    /// except `discardWithheld()` / `signOut()` rejects with no network, no write).
    internal func withheldRefusal() -> SendoraCloudAuthError? {
        lock.lock(); defer { lock.unlock() }
        guard let w = withheldState else { return nil }
        return .sessionWithheld(w.info)
    }

    /// Build the Authorization header for end-user-authenticated routes.
    /// Returns nil when no current session (or `withheld`) — callers bail.
    func bearerHeaders() -> [String: String]? {
        guard let token = accessToken else { return nil }
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

    /// Re-send the email-verification email for the currently-
    /// signed-in user. No-op when already verified.
    public func sendVerificationEmail(
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        if let refusal = withheldRefusal() { completion(.failure(refusal)); return }
        bearerCall(path: "/auth-service/email/verify/resend", body: [:]) { response in
            if let err = self.parseError(response) {
                completion(.failure(err))
            } else {
                completion(.success(()))
            }
        }
    }

    // MARK: MFA enrollment management (Bearer-authenticated)

    public struct MfaEnrollment {
        public let secret: String
        public let otpauthUrl: String
        public let recoveryCodes: [String]
    }

    /// Begin MFA enrollment. Returns the otpauth:// URL + 8 recovery
    /// codes — shown ONCE.
    public func enrollMfa(completion: @escaping (Result<MfaEnrollment, SendoraCloudAuthError>) -> Void) {
        if let refusal = withheldRefusal() { completion(.failure(refusal)); return }
        bearerCall(path: "/auth-service/mfa/enroll/start", body: [:]) { response in
            guard let data = response?["data"] as? [String: Any],
                  let secret = data["secret"] as? String,
                  let url = data["otpauthUrl"] as? String,
                  let codes = data["recoveryCodes"] as? [String] else {
                // Classify WHY there is no payload before reporting one. A nil
                // response is a dead radio or a timed-out request — `.network`,
                // retryable — not a malformed body.
                completion(.failure(self.parseError(response) ?? .unknown("Malformed enrollment response")))
                return
            }
            completion(.success(MfaEnrollment(secret: secret, otpauthUrl: url, recoveryCodes: codes)))
        }
    }

    public func confirmMfa(code: String, completion: @escaping (Result<Bool, SendoraCloudAuthError>) -> Void) {
        if let refusal = withheldRefusal() { completion(.failure(refusal)); return }
        bearerCall(path: "/auth-service/mfa/enroll/confirm", body: ["code": code]) { response in
            // A wrong code still answers `confirmed: false` — that is a verdict.
            // A request that never got an answer is NOT a verdict.
            if let confirmed = (response?["data"] as? [String: Any])?["confirmed"] as? Bool {
                completion(.success(confirmed))
                return
            }
            completion(.failure(self.parseError(response) ?? .unknown("Malformed MFA confirmation response")))
        }
    }

    public func disableMfa(completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void) {
        if let refusal = withheldRefusal() { completion(.failure(refusal)); return }
        bearerCall(path: "/auth-service/mfa/disable", body: [:]) { response in
            // Was unconditional success — a timed-out request reported MFA as
            // disabled while the second factor was still armed server-side.
            if let err = self.parseError(response) {
                completion(.failure(err))
                return
            }
            completion(.success(()))
        }
    }

    // MARK: Device sessions self-service

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

    /// Revoke one of the caller's own sessions ("sign out that device").
    ///
    /// ⚠ BREAKING in 5.0.0: the completion was `() -> Void` — no failure
    /// channel at all. A "sign out this device" button that reports success on
    /// a failure is the one place a user acts on the claim and then stops
    /// worrying about a device they no longer control.
    public func revokeSession(
        sessionId: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        if let refusal = withheldRefusal() { completion(.failure(refusal)); return }
        guard let headers = bearerHeaders() else {
            completion(.failure(.unauthorized("Sign in before revoking a session")))
            return
        }
        let escaped = sessionId.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? sessionId
        client.delete(path: "/auth-service/sessions/me/\(escaped)", headers: headers) { [weak self] response in
            guard let self = self else { return }
            if let err = self.parseError(response) { completion(.failure(err)); return }
            completion(.success(()))
        }
    }

    /// Revoke every session for the caller. Same 5.0.0 signature change and the
    /// same reason as `revokeSession`.
    public func revokeAllSessions(completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void) {
        if let refusal = withheldRefusal() { completion(.failure(refusal)); return }
        guard let headers = bearerHeaders() else {
            completion(.failure(.unauthorized("Sign in before signing out other devices")))
            return
        }
        client.delete(path: "/auth-service/sessions/me", headers: headers) { [weak self] response in
            guard let self = self else { return }
            if let err = self.parseError(response) { completion(.failure(err)); return }
            completion(.success(()))
        }
    }

    // MARK: Linked identities (ADR-030 read side + unlink)

    /// One credential linked to an account (ADR-030 read side, s58.270).
    public struct LinkedIdentity {
        public let provider: String
        public let email: String?
        public let linkedAt: String
    }

    /// Result of `listLinkedIdentities` — the full connected-account set.
    public struct LinkedIdentitiesResult {
        public let identities: [LinkedIdentity]
        public let hasPassword: Bool
    }

    /// List the auth methods/identities linked to the current account (ADR-030
    /// read side, s58.270): every social/gaming identity plus a `hasPassword`
    /// flag — the cross-device / reinstall-durable source of truth for a
    /// "Connected: Game Center · Google" UI. Bearer-authenticated network read
    /// that resolves a fresh access token first.
    public func listLinkedIdentities(
        completion: @escaping (Result<LinkedIdentitiesResult, SendoraCloudAuthError>) -> Void
    ) {
        if let refusal = withheldRefusal() { completion(.failure(refusal)); return }
        getAccessToken { [weak self] token in
            guard let self = self else { return }
            guard let token = token else {
                completion(.failure(.unauthorized("Sign in before listing linked identities")))
                return
            }
            let headers = ["Authorization": "Bearer \(token)"]
            self.client.get(path: "/auth-service/me/identities", headers: headers) { [weak self] response in
                guard let self = self else { return }
                if let err = self.parseError(response) {
                    completion(.failure(err))
                    return
                }
                guard let data = response?["data"] as? [String: Any] else {
                    completion(.failure(.unknown("Malformed identities response")))
                    return
                }
                let rows = data["identities"] as? [[String: Any]] ?? []
                let identities = rows.compactMap { row -> LinkedIdentity? in
                    guard let provider = row["provider"] as? String, !provider.isEmpty,
                          let linkedAt = row["linkedAt"] as? String else { return nil }
                    return LinkedIdentity(provider: provider, email: row["email"] as? String, linkedAt: linkedAt)
                }
                let hasPassword = data["hasPassword"] as? Bool ?? false
                completion(.success(LinkedIdentitiesResult(identities: identities, hasPassword: hasPassword)))
            }
        }
    }

    /// Result of `unlink(provider:)`. `removed` can exceed 1: an account may hold
    /// more than one row for a provider, and unlinking takes all of them.
    public struct UnlinkResult {
        public let provider: String
        public let removed: Int
        public let remaining: Int
    }

    /// Remove one linked provider from the signed-in account — what a
    /// "Disconnect" button beside each entry on a Connected Accounts screen
    /// calls. The write half of `listLinkedIdentities`.
    ///
    /// - Warning: The server REFUSES to remove the last way into the account,
    ///   with code `LAST_CREDENTIAL` / kind `.lastCredential` — permanent lockout,
    ///   not an inconvenience. Prefer preventing the tap: disable Disconnect when
    ///   `identities.count + (hasPassword ? 1 : 0) <= 1`. The error is the backstop.
    ///
    /// Fails with `.unauthorized` when signed out, and with the server's
    /// `NOT_FOUND` when the provider is not linked. On success the cached user
    /// is left as the server returned it (`userUpdated(cause: .unlink)` when it changed).
    public func unlink(
        provider: String,
        completion: @escaping (Result<UnlinkResult, SendoraCloudAuthError>) -> Void
    ) {
        if let refusal = withheldRefusal() { completion(.failure(refusal)); return }
        getAccessToken { [weak self] token in
            guard let self = self else { return }
            guard let token = token else {
                completion(.failure(.unauthorized("Sign in before unlinking an identity")))
                return
            }
            let escaped = provider.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? provider
            let headers = ["Authorization": "Bearer \(token)"]
            self.client.delete(path: "/auth-service/me/identities/\(escaped)", headers: headers) { [weak self] response in
                guard let self = self else { return }
                if let err = self.parseError(response) {
                    completion(.failure(err))
                    return
                }
                guard let data = response?["data"] as? [String: Any] else {
                    completion(.failure(.unknown("Malformed unlink response")))
                    return
                }
                completion(.success(UnlinkResult(
                    provider: data["provider"] as? String ?? provider,
                    removed: data["removed"] as? Int ?? 0,
                    remaining: data["remaining"] as? Int ?? 0
                )))
            }
        }
    }

    // MARK: Email / password utilities (no session involved)

    /// Send a magic-link email. Always resolves successfully regardless
    /// of whether the email matches a known user.
    public func sendMagicLink(
        email: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: "/auth-service/magic-link/request", body: ["email": email]) { response in
            if let err = self.parseError(response) { completion(.failure(err)) } else { completion(.success(())) }
        }
    }

    /// Send a 6-digit email OTP. Always resolves successfully
    /// regardless of whether the email matches a known user.
    public func sendEmailOtp(
        email: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: "/auth-service/email-otp/request", body: ["email": email]) { response in
            if let err = self.parseError(response) { completion(.failure(err)) } else { completion(.success(())) }
        }
    }

    /// Trigger a password-reset email. Backend always resolves
    /// successfully even when the address is unknown — prevents
    /// account enumeration.
    public func requestPasswordReset(
        email: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: "/auth-service/password/forgot", body: ["email": email]) { response in
            if let err = self.parseError(response) { completion(.failure(err)) } else { completion(.success(())) }
        }
    }

    /// Pair the reset-email token with the user's new password.
    public func resetPassword(
        token: String,
        newPassword: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: "/auth-service/password/reset", body: ["token": token, "newPassword": newPassword]) { response in
            if let err = self.parseError(response) { completion(.failure(err)) } else { completion(.success(())) }
        }
    }

    /// Verify the email-address token from the link Sendora sent on
    /// signup. Flips `emailVerified=true` on the user row.
    public func verifyEmail(
        token: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: "/auth-service/email/verify", body: ["token": token]) { response in
            if let err = self.parseError(response) { completion(.failure(err)) } else { completion(.success(())) }
        }
    }
}

// MARK: - Access-token expiry

/// True when the token's OWN `exp` claim is still in the future by the device
/// clock — or when the token carries no readable `exp` at all.
///
/// - Warning: Unreadable → `true` is deliberate, and it is what makes this safe
///   to layer UNDER the tracked-deadline check rather than in place of it.
/// - Warning: Never derive the tracked deadline FROM `exp`. The two guards fail
///   in opposite directions and that is the point (s58.281).
internal func accessTokenExpIsFuture(_ token: String, nowMs: Int64) -> Bool {
    guard let expSeconds = decodeJwtExp(token) else { return true }
    return Double(nowMs) < expSeconds * 1000.0
}

/// Read `exp` out of a JWT payload. Signature is never verified client-side —
/// the server is the only authority on validity; this is a freshness hint.
internal func decodeJwtExp(_ token: String) -> Double? {
    guard let obj = decodeJwtPayload(token),
          let exp = (obj["exp"] as? NSNumber)?.doubleValue,
          exp.isFinite else { return nil }
    return exp
}
