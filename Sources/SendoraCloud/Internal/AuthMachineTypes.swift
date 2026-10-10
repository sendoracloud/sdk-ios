import Foundation

// ADR-033 wave 1 (5.4.0) — the public vocabulary of the auth state machine and
// the two on-device records `commit()` writes. Mirrors
// `packages/shared/src/auth-machine/{states,types}.ts`; the raw values are the
// shared snake_case wire tokens so a log line reads the same on all four SDKs.
//
// ⚠ ADDITIVE ONLY (ADR-023). Every enum here is mirrored from a shared closed
// list; adding a member later is a MAJOR for this port unless opt-in gated.

// MARK: - Status

/// The five client states (ADR-033 §3.2). `unknown` ≠ `signedOut` and
/// `withheld` ≠ `signedOut` — `status()` is the ONLY call that tells them apart,
/// because `currentUser` is `nil` in all three.
///
/// NORMATIVE (§3.5): consumers MUST default-branch. `withheld` is added in
/// 5.4.0 because the type is new (free); any LATER value is a MAJOR. Write
/// `switch auth.status() { case .anonymous: … default: … }`, never an
/// exhaustive switch without `default`.
///
///  - `unknown`    not hydrated, or hydrated with a refresh token but no readable
///                 user (LIMBO_A). MINT is QUEUED here, never run.
///  - `signedOut`  no refresh token. The ONLY state in which MINT executes.
///  - `anonymous`  refresh token + `user.isAnonymous == true`.
///  - `identified` refresh token + `user.isAnonymous == false`.
///  - `withheld`   a stored session refused because its JWT `project` claim
///                 disagrees with `expectedProjectId`. A pure function of (disk
///                 record, config), never persisted. Exit: `discardWithheld()`.
public enum SendoraCloudAuthStatus: String {
    case unknown
    case signedOut = "signed_out"
    case anonymous
    case identified
    case withheld
}

/// Why a `signedIn` fired (§3.5). `restore` ⇒ re-register push (the held
/// guest's push tokens were erased if it was deleted elsewhere); `link` = the
/// legacy same-`sub` promotion the legacy-signature methods keep emitting.
public enum SendoraCloudAuthSignedInCause: String {
    case mint
    case signIn = "sign_in"
    case restore
    case link
}

/// What changed the user object WITHOUT changing the `sub` (§3.3 UserTx + CLAIM).
public enum SendoraCloudAuthUserUpdatedCause: String {
    case link
    case unlink
    case emailVerified = "email_verified"
    case refresh
    case merge
}

/// `guestReleased.reason` — every exit from a held slot names one (§3.7 P4).
/// ⚠ `dead` = the server said "unavailable" when the held token was presented.
/// It is NOT an erasure signal; UIs say "unavailable", never "progress lost".
public enum SendoraCloudGuestReleasedReason: String {
    case claimed
    case restored
    case discarded
    case dead
    case reset
}

/// `error.details.endReason` on an `INVALID_REFRESH_TOKEN` rejection (B11).
public enum SendoraCloudRefreshEndReason: String {
    case expired
    case revoked
    case evicted
    case deleted
    case reuse
    case unknown
}

/// `guestHeld` / `heldGuests()` — a held slot MINUS its tokens (§3.5: never
/// exposes tokens). `heldAt` is milliseconds since the epoch; the list is
/// ordered newest first.
public struct SendoraCloudHeldGuest {
    public let userId: String
    public let heldAt: Int64
    public let autoRestore: Bool
    public let project: String?
}

/// What `withheld()` returns while `status() == .withheld`. Never exposes
/// tokens. `userId` lets a `sub`-keyed backend record oldSub → newSub BEFORE
/// the app calls `discardWithheld()`.
public struct SendoraCloudWithheldInfo {
    public let reason: String = "project_mismatch"
    public let expectedProjectId: String
    public let actualProjectId: String?
    public let userId: String
    public let isAnonymous: Bool
}

/// What a SWITCH replaced. `held == true` ⇔ the previous slot was anonymous and
/// is now in a held slot (§3.1.1). `isAnonymous == false` ⇒ an identified →
/// identified switch: skip any guest merge and reset local save state.
public struct SendoraCloudPreviousSession {
    public let userId: String
    public let isAnonymous: Bool
    public let held: Bool
}

/// Counts off a successful claim (`POST /merge`), all `0` when the server did
/// not report one (an older backend).
public struct SendoraCloudMergeStats {
    public let mergedUserId: String
    public let deletedAnonymousId: String
    public let eventsReassigned: Int
    public let profilesReassigned: Int
    public let profilesDropped: Int
    public let entitiesReassigned: Int
    public let entitiesDropped: Int
    public let pushTokensReassigned: Int
}

public struct SendoraCloudClaimResult {
    public let user: SendoraCloudAuthUser
    public let stats: SendoraCloudMergeStats
}

// MARK: - Typed credentials + results (§3.5 "typed verbs")

/// One closed input for `link(_:)` / `signIn(with:)` instead of nine method
/// signatures. Each case carries exactly the wire fields of its sign-in / link
/// route — MINUS the guest hint (`prevAnonRefreshToken`, `linkAnonymous`,
/// `onCredentialInUse`): a wave-1 body never carries a guest credential (INV-3),
/// so there is no field to put it in. Play Games is Android-only and absent here.
public enum SendoraCloudCredential {
    case password(email: String, password: String)
    /// `provider` ∈ google · github · apple · microsoft · linkedin · facebook ·
    /// twitter · discord. Pass `code` + `redirectUri` (authorization-code flow)
    /// OR `idToken` (Apple-native flow).
    case social(provider: String, code: String? = nil, idToken: String? = nil, redirectUri: String? = nil,
                codeVerifier: String? = nil, appleFirstName: String? = nil, appleLastName: String? = nil)
    /// The `GKLocalPlayer.local.fetchItems(forIdentityVerificationSignature:)`
    /// payload + the app's bundle id. `signature`/`salt` base64, `timestamp`
    /// GameKit's millisecond value.
    case gameCenter(publicKeyURL: String, signature: String, salt: String, timestamp: UInt64, teamPlayerID: String, bundleID: String)
    case magicLink(token: String)
    case emailOtp(email: String, code: String)
    /// The WebAuthn assertion as produced by the platform authenticator; the SDK
    /// forwards it to `passkeys/authenticate/finish` unchanged.
    case passkey(assertion: [String: Any])
    case mfa(challengeToken: String, code: String)

    /// The shared `CredentialKind` wire token.
    public var kind: String {
        switch self {
        case .password: return "password"
        case .social(let provider, _, _, _, _, _, _): return provider
        case .gameCenter: return "gameCenter"
        case .magicLink: return "magicLink"
        case .emailOtp: return "emailOtp"
        case .passkey: return "passkey"
        case .mfa: return "mfa"
        }
    }

    /// Does this credential name the same identity as `other`? Used by
    /// `switchAccount()` after a re-fetch (INV-14): a Game Center payload must
    /// carry the same `teamPlayerID`, a password the same email, a social
    /// credential the same provider. Opaque single-use tokens compare by kind.
    internal func namesSameIdentity(as other: SendoraCloudCredential) -> Bool {
        switch (self, other) {
        case (.gameCenter(_, _, _, _, let a, _), .gameCenter(_, _, _, _, let b, _)): return a == b
        case (.password(let a, _), .password(let b, _)): return a.lowercased() == b.lowercased()
        case (.social(let a, _, _, _, _, _, _), .social(let b, _, _, _, _, _, _)): return a == b
        case (.emailOtp(let a, _), .emailOtp(let b, _)): return a.lowercased() == b.lowercased()
        case (.magicLink, .magicLink), (.passkey, .passkey), (.mfa, .mfa): return true
        default: return false
        }
    }
}

public enum SendoraCloudLinkCollision: String {
    case identity
    case email
}

/// The pending MFA challenge of a typed `signIn(with:)` (§3.2 `attempt.mfa`).
/// The context lives on this object, never in a nullable field cleared by hand;
/// dropping the object abandons the attempt and the current session is untouched.
public final class SendoraCloudMfaChallenge {
    public let challengeToken: String
    public let userId: String
    private let verifier: (String, @escaping (Result<SendoraCloudSignInResult, SendoraCloudAuthError>) -> Void) -> Void

    init(challengeToken: String, userId: String,
         verifier: @escaping (String, @escaping (Result<SendoraCloudSignInResult, SendoraCloudAuthError>) -> Void) -> Void) {
        self.challengeToken = challengeToken
        self.userId = userId
        self.verifier = verifier
    }

    /// Complete the challenge with a 6-digit TOTP code (or a recovery code).
    public func verify(code: String, completion: @escaping (Result<SendoraCloudSignInResult, SendoraCloudAuthError>) -> Void) {
        verifier(code, completion)
    }
}

/// `signIn(with:)` / `switchAccount()` outcome (shared `SignInResult`).
public enum SendoraCloudSignInResult {
    /// `previous` is what the switch replaced (`nil` from `signedOut`).
    /// `reactivated` surfaces a cancelled pending self-service deletion.
    case done(user: SendoraCloudAuthUser, previous: SendoraCloudPreviousSession?, reactivated: Bool)
    case mfaRequired(SendoraCloudMfaChallenge)
}

/// The `credentialInUse` outcome of `link(_:)` (409, B14 payload). Nothing was
/// mutated. The two resolvers are METHODS on this object (the Swift form of the
/// shared result's closures):
///
///  - `switchAccount()` — the ONLY path from a refused link to a sign-in, and it
///    is BOUND to the refused credential (INV-14): the same payload is reused if
///    it is under 5 minutes old; otherwise you must pass `refetch`, which asks
///    your app for a fresh native credential (GameKit `fetchItems`); the SDK then
///    compares `teamPlayerID` (or the equivalent identity field) and aborts with
///    `.credentialChanged` on a mismatch. From `anonymous` the guest is HELD;
///    from `identified` the result's `previous.held == false`.
///  - `keepCurrent()` — drops the context; nothing happens.
public final class SendoraCloudCredentialInUse {
    public let provider: String
    public let collision: SendoraCloudLinkCollision
    public let message: String
    private let credential: SendoraCloudCredential
    private let boundAt: Date
    private let performer: (SendoraCloudCredential, @escaping (Result<SendoraCloudSignInResult, SendoraCloudAuthError>) -> Void) -> Void
    private var consumed = false
    private let lock = NSLock()

    /// Payloads older than this must be re-fetched before a switch (INV-14).
    public static let maxPayloadAge: TimeInterval = 5 * 60

    init(provider: String, collision: SendoraCloudLinkCollision, message: String, credential: SendoraCloudCredential, boundAt: Date,
         performer: @escaping (SendoraCloudCredential, @escaping (Result<SendoraCloudSignInResult, SendoraCloudAuthError>) -> Void) -> Void) {
        self.provider = provider
        self.collision = collision
        self.message = message
        self.credential = credential
        self.boundAt = boundAt
        self.performer = performer
    }

    public func keepCurrent() {
        lock.lock(); consumed = true; lock.unlock()
    }

    /// Plain sign-in with the refused credential. `refetch` is consulted ONLY
    /// when the bound payload is older than `maxPayloadAge`; it must hand back a
    /// freshly obtained credential of the same kind (for Game Center: re-run
    /// `fetchItems` and rebuild `.gameCenter(...)`). Without it a stale payload
    /// fails with `.credentialChanged` rather than signing into whoever the
    /// device's identity is NOW.
    public func switchAccount(
        refetch: ((@escaping (SendoraCloudCredential?) -> Void) -> Void)? = nil,
        completion: @escaping (Result<SendoraCloudSignInResult, SendoraCloudAuthError>) -> Void
    ) {
        lock.lock()
        if consumed { lock.unlock(); completion(.failure(.credentialChanged("This credential_in_use result was already resolved"))); return }
        consumed = true
        lock.unlock()
        let age = Date().timeIntervalSince(boundAt)
        if age < Self.maxPayloadAge {
            performer(credential, completion)
            return
        }
        guard let refetch = refetch else {
            completion(.failure(.credentialChanged("The refused credential is older than 5 minutes; pass `refetch` so the device identity can be re-read and compared")))
            return
        }
        let bound = credential
        refetch { fresh in
            guard let fresh = fresh else {
                completion(.failure(.credentialChanged("Re-fetching the credential produced nothing")))
                return
            }
            guard bound.namesSameIdentity(as: fresh) else {
                completion(.failure(.credentialChanged("The device's identity changed since the link was refused; aborting the switch")))
                return
            }
            self.performer(fresh, completion)
        }
    }
}

/// `link(_:)` outcome (shared `LinkResult`). Three outcomes, nothing mutated on
/// the two refusals (INV-12, B2):
///  - `done(alreadyLinked: true)` — the same identity is already on this account:
///    a quiet 200, NO event, NO revoke of other sessions, NO step-up (B13).
///  - `done(upgraded: true)` — the caller was anonymous and was promoted in place
///    (same `sub`, rotated pair); `false` on an identified attach (no rotation).
///  - `credentialInUse` — owned by another account (409).
///  - `recentAuthRequired` — the credential is fine, the session is stale (403).
///    State unchanged. There is deliberately NO `reauthenticate(credential)`
///    resolver: re-auth must use a credential already on the current account.
public enum SendoraCloudLinkResult {
    case done(user: SendoraCloudAuthUser, upgraded: Bool, alreadyLinked: Bool)
    case credentialInUse(SendoraCloudCredentialInUse)
    case recentAuthRequired
}

// MARK: - On-device records (internal)

/// The 5.4.0 session record at `sendora_auth_session`, written on EVERY install
/// commit beside the four frozen keys (dual-write, INV-10) and read first on
/// hydrate. Held material is NEVER inside it (§3.2). `heldReportPending` is the
/// one non-secret bookkeeping field: guests whose `POST /guest/held` report has
/// not yet been acknowledged (B15), retried on hydrate.
internal struct AuthSessionRecord: Codable {
    var v: Int = 2
    var user: SendoraCloudAuthUser
    var accessToken: String
    var refreshToken: String
    var accessExpiresAt: Int64
    /// The server session family id off the access JWT — the identity CAS key.
    var sid: String?
    var heldReportPending: [String] = []
}

/// ONE held slot as persisted at `sendora_auth_held_<i>` (§3.2 `held_guests`,
/// shared `HeldGuest`). ~300 B of JSON. NO access token and NO user blob:
/// restore/claim always refresh first.
///
///  - `v` — record version; `1` is the wave-1 shape. A reader that sees a `v` it
///    does not know KEEPS the slot and ignores it (never clears — P11, INV-9).
///  - `refreshToken` — the guest's CURRENT refresh token (rotated in place by a
///    REFRESH_OK whose `sent` matches this slot).
///  - `tokenAtHold` — the refresh token at HOLD, so the deprecated
///    `merge(anonRefreshToken:)` can route an integrator-journalled token here.
///  - `project` — the JWT `project` claim read at HOLD; `nil` (encoded as JSON
///    `null`) when unreadable, judged on the refresh response instead.
///  - `autoRestore` — `false` after `deleteAccount()` of the then-current
///    account: only an explicit `restoreHeldGuest(id:)` revives it (test 9).
internal struct HeldSlotRecord {
    static let currentVersion = 1

    var v: Int = HeldSlotRecord.currentVersion
    var userId: String
    var sid: String?
    var refreshToken: String
    var tokenAtHold: String
    var heldAt: Int64
    var project: String?
    var autoRestore: Bool

    func encodeJson() -> String? {
        var dict: [String: Any] = [
            "v": v,
            "userId": userId,
            "refreshToken": refreshToken,
            "tokenAtHold": tokenAtHold,
            "heldAt": heldAt,
            // An explicit null, not an absent key — the shared shape says
            // `project: string | null`.
            "project": project.map { $0 as Any } ?? NSNull(),
            "autoRestore": autoRestore,
        ]
        if let sid = sid { dict["sid"] = sid }
        guard let data = try? JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// `nil` when the JSON is not a v1 slot. The caller KEEPS the raw value in
    /// place (never clears a slot it cannot read).
    static func decode(_ json: String) -> HeldSlotRecord? {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let v = obj["v"] as? Int, v == currentVersion,
              let userId = obj["userId"] as? String, !userId.isEmpty,
              let refreshToken = obj["refreshToken"] as? String, !refreshToken.isEmpty,
              let heldAt = (obj["heldAt"] as? NSNumber)?.int64Value else { return nil }
        return HeldSlotRecord(
            v: v,
            userId: userId,
            sid: obj["sid"] as? String,
            refreshToken: refreshToken,
            tokenAtHold: (obj["tokenAtHold"] as? String) ?? refreshToken,
            heldAt: heldAt,
            project: obj["project"] as? String,
            autoRestore: (obj["autoRestore"] as? Bool) ?? true
        )
    }
}
