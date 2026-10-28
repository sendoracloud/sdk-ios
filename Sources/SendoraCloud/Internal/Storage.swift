import Foundation
import Security
import CryptoKit

// MARK: - Store backends
//
// ADR-033 wave 1 (5.4.0): the two tiers are behind protocols so the auth
// machine's conformance suite can run on an in-memory RECORDING double and
// assert, byte for byte, which keys a transition wrote (or that it wrote
// nothing — a withheld hydrate must leave the disk identical). Production uses
// the Keychain + the `com.sendora.sdk` UserDefaults suite exactly as before.

/// The sensitive tier (Keychain in production).
///
/// ⚠⚠ DURABILITY (ADR-033 rev 3 §3.8, s58.415 — INV-16 / INV-17). A refresh token is a guest's ONLY credential.
/// `get` / `set` / `delete` are the pre-rev-3 surface and LOSE information: `get` reads every failure as "absent"
/// and `set` / `delete` swallow their `OSStatus`. The auth machine uses the status-carrying trio instead:
///  - `read` — `.absent` ONLY for `errSecItemNotFound`; every other status (−25308 `errSecInteractionNotAllowed`
///    before first unlock, −34018, an undecodable value) is `.unavailable` and must never be read as "no session";
///  - `write` — replaces IN PLACE (`SecItemUpdate`, add only when the item is absent): a write never passes
///    through "no value", and its result is KNOWN (`false` = nothing changed on disk);
///  - `remove` — `true` when the item is gone afterwards (deleted, or was never there).
protocol SendoraSecureStore: AnyObject {
    func get(_ key: String) -> String?
    func set(_ key: String, _ value: String)
    func delete(_ key: String)
    /// 5.7.0 — write ONLY if the key is absent (never delete-then-add). `.duplicate` = someone else's value is
    /// already stored; the caller must re-read and adopt it (Keychain `errSecDuplicateItem`, -25299).
    func addIfAbsent(_ key: String, _ value: String) -> SendoraSecureAddResult
    /// rev 3 (INV-17): a read that distinguishes "absent" from "could not read".
    func read(_ key: String) -> SendoraSecureRead
    /// rev 3 (INV-16): an atomic, CONFIRMED write. `false` = the old value (if any) is still what is stored.
    func write(_ key: String, _ value: String) -> Bool
    /// rev 3: a confirmed delete. `true` = the item is not on disk afterwards.
    func remove(_ key: String) -> Bool
}

/// The outcome of one secure read (ADR-033 rev 3, INV-17).
enum SendoraSecureRead: Equatable {
    case value(String)
    /// `errSecItemNotFound` — and ONLY that.
    case absent
    /// Any other status: the item may well exist. Never "signed out", never a mint.
    case unavailable(OSStatus)

    var valueOrNil: String? {
        if case .value(let v) = self { return v }
        return nil
    }

    var isUnavailable: Bool {
        if case .unavailable = self { return true }
        return false
    }
}

enum SendoraSecureAddResult: Equatable {
    case added
    case duplicate
    case failed(OSStatus)
}

extension SendoraSecureStore {
    /// Default for in-memory doubles: models the Keychain's add semantics on top of get/set.
    func addIfAbsent(_ key: String, _ value: String) -> SendoraSecureAddResult {
        if get(key) != nil { return .duplicate }
        set(key, value)
        return .added
    }

    /// Defaults for a PERFECT in-memory double (never fails a read or a write) — exactly what a plain map is.
    /// A double that models faults (FaultyStorageTests) implements all three.
    func read(_ key: String) -> SendoraSecureRead {
        if let v = get(key) { return .value(v) }
        return .absent
    }

    func write(_ key: String, _ value: String) -> Bool {
        set(key, value)
        return true
    }

    func remove(_ key: String) -> Bool {
        delete(key)
        return true
    }
}

/// The non-sensitive tier (UserDefaults in production).
protocol SendoraPlainStore: AnyObject {
    func string(forKey key: String) -> String?
    func setString(_ value: String, forKey key: String)
    func data(forKey key: String) -> Data?
    func setData(_ value: Data, forKey key: String)
    func bool(forKey key: String) -> Bool
    func setBool(_ value: Bool, forKey key: String)
    func hasValue(forKey key: String) -> Bool
    func remove(forKey key: String)
}

/// The four Security.framework calls `KeychainSecureStore` makes, behind a seam (rev 3) so `swift test` can pin
/// their ORDER and status handling without a keychain entitlement (a hostless test bundle gets −34018 on every
/// call). Production is `.system` — the real `SecItem*` functions, unchanged.
struct KeychainAPI {
    var copyMatching: ([String: Any]) -> (OSStatus, AnyObject?)
    var add: ([String: Any]) -> OSStatus
    var update: (_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus
    var delete: ([String: Any]) -> OSStatus

    static let system = KeychainAPI(
        copyMatching: { query in
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return (status, result)
        },
        add: { SecItemAdd($0 as CFDictionary, nil) },
        update: { SecItemUpdate($0 as CFDictionary, $1 as CFDictionary) },
        delete: { SecItemDelete($0 as CFDictionary) }
    )
}

final class KeychainSecureStore: SendoraSecureStore {
    private let service: String
    private let api: KeychainAPI

    init(service: String, api: KeychainAPI = .system) {
        self.service = service
        self.api = api
    }

    private func matchQuery(_ key: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: service,
        ]
    }

    /// INV-17: `errSecItemNotFound` is the ONLY "absent". −25308 (`errSecInteractionNotAllowed`, before first
    /// unlock), −34018 (no keychain entitlement), an I/O error or an undecodable value is `.unavailable`: the item
    /// may exist, and reading it as "no session" is what let a background launch mint over the account (H1).
    /// Reads never filter on accessibility, so an item written under any class stays readable.
    func read(_ key: String) -> SendoraSecureRead {
        var query = matchQuery(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, result) = api.copyMatching(query)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, let s = String(data: data, encoding: .utf8) else {
                SendoraCloudLogger.shared.error("Keychain read undecodable for key=\(key)")
                return .unavailable(errSecDecode)
            }
            return .value(s)
        case errSecItemNotFound:
            return .absent
        default:
            SendoraCloudLogger.shared.error("Keychain read failed for key=\(key) status=\(status)")
            return .unavailable(status)
        }
    }

    func get(_ key: String) -> String? {
        return read(key).valueOrNil
    }

    /// INV-16 atomic replace: `SecItemUpdate` IN PLACE, and `SecItemAdd` ONLY when the item is absent — never
    /// delete-then-add (a failed add, or a kill between the two, used to leave the key GONE; the next hydrate then
    /// cleared the record holding the rotated token as a stale blob — H2 / FS1 / FS2). The update also carries
    /// `kSecAttrAccessible`, so an item created under another class migrates on its next write (background
    /// refreshes run while the phone is locked → AfterFirstUnlock). Every OSStatus is checked: `false` = the
    /// write did not land and the OLD value is still what is stored.
    func write(_ key: String, _ value: String) -> Bool {
        let match = matchQuery(key)
        let attrs: [String: Any] = [
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: Self.accessibility(forKey: key),
        ]
        var status = api.update(match, attrs)
        if status == errSecItemNotFound {
            status = api.add(match.merging(attrs) { _, new in new })
            if status == errSecDuplicateItem {
                // A concurrent add landed between our update and our add: replace it in place.
                status = api.update(match, attrs)
            }
        }
        if status != errSecSuccess {
            SendoraCloudLogger.shared.error("Keychain write failed for key=\(key) status=\(status)")
            return false
        }
        return true
    }

    func set(_ key: String, _ value: String) {
        _ = write(key, value)
    }

    /// ⚠⚠ (s58.415, operator decision D2 — zero guest-account loss) The AUTH keys — the four frozen keys, the session
    /// record, the held + quarantine slots and the refresh marker — are `kSecAttrAccessibleAfterFirstUnlock`, NOT
    /// `…ThisDeviceOnly`: an encrypted backup / iCloud backup / Quick Start carries them to a new iPhone, so a guest
    /// moves with the player instead of being stranded on the old phone (a guest has no other way back in). A backup
    /// restored onto a SECOND phone clones the token: one of the two later gets `reuse` → quarantine / ADR-036
    /// recovery, never a destroyed account. Every write passes the class to `SecItemUpdate`, so an item created
    /// `…ThisDeviceOnly` by an earlier build migrates on its next write.
    /// Everything else — the analytics device id (`addIfAbsent`), `sendora_user_id`, the known-device tokens, the link
    /// revoke tokens — stays `AfterFirstUnlockThisDeviceOnly` exactly as before (device-bound by design).
    static func accessibility(forKey key: String) -> CFString {
        return SendoraStorage.travellingAuthKeys.contains(key)
            ? kSecAttrAccessibleAfterFirstUnlock
            : kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    }

    func remove(_ key: String) -> Bool {
        let status = api.delete(matchQuery(key))
        if status == errSecSuccess || status == errSecItemNotFound { return true }
        SendoraCloudLogger.shared.error("Keychain delete failed for key=\(key) status=\(status)")
        return false
    }

    func delete(_ key: String) {
        _ = remove(key)
    }

    func addIfAbsent(_ key: String, _ value: String) -> SendoraSecureAddResult {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: service,
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = api.add(query)
        switch status {
        case errSecSuccess: return .added
        case errSecDuplicateItem: return .duplicate
        default:
            SendoraCloudLogger.shared.error("Keychain add failed for key=\(key) status=\(status)")
            return .failed(status)
        }
    }
}

final class UserDefaultsPlainStore: SendoraPlainStore {
    private let defaults: UserDefaults

    init(defaults: UserDefaults) {
        self.defaults = defaults
    }

    func string(forKey key: String) -> String? { defaults.string(forKey: key) }
    func setString(_ value: String, forKey key: String) { defaults.set(value, forKey: key) }
    func data(forKey key: String) -> Data? { defaults.data(forKey: key) }
    func setData(_ value: Data, forKey key: String) { defaults.set(value, forKey: key) }
    func bool(forKey key: String) -> Bool { defaults.bool(forKey: key) }
    func setBool(_ value: Bool, forKey key: String) { defaults.set(value, forKey: key) }
    func hasValue(forKey key: String) -> Bool { defaults.object(forKey: key) != nil }
    func remove(forKey key: String) { defaults.removeObject(forKey: key) }
}

/// Persistent storage.
///  - `isFirstLaunch` / `sessionId` live in UserDefaults (non-sensitive).
///  - `deviceId` and `cachedUserId` live in Keychain with
///    `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — not backed up to
///    iCloud, not readable from other apps. (s58.415, D2: the AUTH keys are
///    `AfterFirstUnlock` and DO travel — `travellingAuthKeys`.)
///  - Event queue is persisted as JSON stripped of PII (userId + traits removed
///    before writing; they'll be re-injected from `currentUserId` at send time).
///
/// ⚠ ADR-023: every `sendora_*` key below is FROZEN — an installed app reads it.
/// Never rename or remove one; add new keys freely. The key NAMES live in this
/// file and nowhere else (ADR-033 INV-1 source guard: "the storage key names
/// appear in exactly one module per SDK").
final class SendoraStorage {
    private let plain: SendoraPlainStore
    private let secure: SendoraSecureStore

    /// ADR-033 wave 1 — the 5.4.0 session record, dual-written beside the four
    /// frozen auth keys (INV-10). Keychain tier.
    static let authSessionKey = "sendora_auth_session"

    /// ADR-033 §3.2 — the K = 5 FIXED held-guest slots. LITERAL names, never
    /// built from an index at the write site: a dynamically-built key is not in
    /// `secureKeys` and the conformance suite fails the write (§5 wave 1 "build a
    /// held key name dynamically → red"). Keychain tier.
    static let heldSlotKeys: [String] = [
        "sendora_auth_held_0",
        "sendora_auth_held_1",
        "sendora_auth_held_2",
        "sendora_auth_held_3",
        "sendora_auth_held_4",
    ]

    /// ADR-033 rev 3 §3.8 (s58.415) — the Q = 3 FIXED quarantine slots: the CURRENT guest whose refresh came back
    /// `reuse` is moved here instead of being cleared (operator decision D). LITERAL names for the same reason as
    /// the held slots. Keychain tier. Not counted in T, never auto-restored, never refreshed in the background.
    static let quarantineSlotKeys: [String] = [
        "sendora_auth_quarantine_0",
        "sendora_auth_quarantine_1",
        "sendora_auth_quarantine_2",
    ]

    /// ADR-033 rev 3 INV-16 — the refresh-in-flight marker `{v:1, sid, startedAt}`, written and CONFIRMED before
    /// every `/token/refresh` of the current session, removed only once the rotated pair's write confirmed. A
    /// hydrate that finds it refreshes at once.
    /// ⚠ Keychain tier (step-2 review T15, Codex F9): no token in it, but its write must be CONFIRMED DURABLE before
    /// the request goes out. A `UserDefaults.set` + same-process read-back proves only process-visible state — the
    /// defaults daemon flushes later, so a kill after the server rotated could leave R1 on disk with NO marker. A
    /// Keychain `SecItemUpdate` / `SecItemAdd` that returned `errSecSuccess` is on disk (AfterFirstUnlock).
    static let refreshInflightKey = "sendora_auth_refresh_inflight"

    /// The four pre-5.4.0 auth keys a downgraded build reads (ADR-023 frozen).
    static let frozenAuthKeys: [String] = [
        "sendora_auth_access_token",
        "sendora_auth_access_expires",
        "sendora_auth_refresh_token",
        "sendora_auth_user",
    ]

    /// 5.6.0 (F67 / backend F23) — the `knownDeviceToken` each password sign-in
    /// returns, per account, sent back on the next `/auth-service/login` for that
    /// address (it exempts this device from the account-wide guessing-attack
    /// refusal). A DEVICE credential, not a session: deliberately NOT in
    /// `clearAuthTokens()` (it survives `signOut`).
    /// Keychain tier; entries keyed by SHA-256 of the normalised email (no
    /// address at rest), newest first, at most `knownDevicesMax`. Survives the RESET
    /// row too; `deleteAccount` removes that account's entry.
    static let knownDevicesKey = "sendora_auth_known_devices"
    static let knownDevicesMax = 20
    static let knownDeviceTokenMaxLength = 2048

    /// 5.6.0 (backend F34) — shortcode → the mint's `revokeToken` (`lrt_…`), which
    /// makes a `links.revoke` FINAL. Only the device that minted a link holds it.
    /// Keychain tier (a capability), NOT an auth key; at most `linkRevokeTokensMax`.
    static let linkRevokeTokensKey = "sendora_link_revoke_tokens"
    static let linkRevokeTokensMax = 200
    static let linkRevokeTokenMaxLength = 200

    /// (s58.415, D2) The Keychain keys written `kSecAttrAccessibleAfterFirstUnlock` (they travel in an encrypted
    /// backup / Quick Start): every key that is, or holds, a session credential. See `KeychainSecureStore.accessibility`.
    static let travellingAuthKeys: Set<String> =
        Set(frozenAuthKeys + [authSessionKey] + heldSlotKeys + quarantineSlotKeys + [refreshInflightKey, mintKeyKey])

    /// The CLOSED set of Keychain keys this SDK may write. The auth machine's
    /// recording double asserts every secure write lands on one of these.
    static let secureKeys: [String] =
        ["sendora_user_id", "sendora_device_id"] + frozenAuthKeys + [authSessionKey] + heldSlotKeys
        + [knownDevicesKey, linkRevokeTokensKey] + quarantineSlotKeys + [refreshInflightKey, mintKeyKey]

    /// (step-2 review T2) Session keys whose read kept failing for the whole INV-17 window while the device was
    /// known to be unlocked: a PERMANENT failure (−34018 with no keychain entitlement, `errSecDecode` bytes). They
    /// read as ABSENT from then on — the SDK proceeds (a new session may be written OVER them) — and their bytes are
    /// NEVER deleted by the SDK (`clearAuthTokens` skips them). A successful write of a key takes it off the list.
    private var acceptedUnreadable: Set<String> = []
    private var acceptedFoundValue = false
    private let acceptedLock = NSLock()

    init() {
        let defaults = UserDefaults(suiteName: "com.sendora.sdk") ?? .standard
        self.plain = UserDefaultsPlainStore(defaults: defaults)
        self.secure = KeychainSecureStore(service: "com.sendora.sdk")
    }

    /// Test seam (ADR-033 conformance suite): inject recording doubles.
    init(secure: SendoraSecureStore, plain: SendoraPlainStore) {
        self.secure = secure
        self.plain = plain
    }

    // MARK: - UserDefaults (non-sensitive)

    var isFirstLaunch: Bool {
        get { !plain.bool(forKey: "sendora_launched") }
        set { plain.setBool(!newValue, forKey: "sendora_launched") }
    }

    var sessionId: String {
        get { plain.string(forKey: "sendora_session_id") ?? "" }
        set { plain.setString(newValue, forKey: "sendora_session_id") }
    }

    /// ADR-023 on-device schema marker. Non-sensitive → UserDefaults (NOT
    /// Keychain). `nil` = pre-marker install (treat as the implicit "0" baseline).
    /// "1" = the four flat auth keys only (4.5.0–5.3.0); "2" = the 5.4.0
    /// `sendora_auth_session` record is dual-written beside them (ADR-033 wave 1).
    /// Bumped to "2" only by an INSTALL commit — a withheld hydrate performs zero
    /// writes, so rollback and re-init see identical bytes (INV-10).
    var schemaVersion: String? {
        get { plain.string(forKey: "sendora_schema_version") }
        set {
            if let v = newValue { plain.setString(v, forKey: "sendora_schema_version") }
            else { plain.remove(forKey: "sendora_schema_version") }
        }
    }

    /// Stamp the current on-device schema version exactly once. No-op if the
    /// marker already exists, so an existing key is never overwritten (key is
    /// frozen per ADR-023 §3.4).
    func initSchemaVersionIfAbsent() {
        if !plain.hasValue(forKey: "sendora_schema_version") {
            plain.setString("1", forKey: "sendora_schema_version")
        }
    }

    /// ADR-033 B10 — the per-ATTEMPT idempotent mint key, kept until the minted session is on disk (a retried mint
    /// with the same key within 24 h returns the same guest instead of a second one).
    /// ⚠ (s58.415, C3 / Codex #7) KEYCHAIN tier since s58.415 — same literal name as the UserDefaults key it replaces
    /// (still READ as a legacy fallback, removed on the next write). While a minted session is not yet on disk this key
    /// is the device's only way back to that guest, and a UserDefaults set + same-process read-back proves nothing about
    /// the disk (the T15 lesson). A Keychain write that returned `errSecSuccess` is durable. `AfterFirstUnlock` (D2).
    static let mintKeyKey = "sendora_auth_mint_key"

    /// The stored mint key: `.value` / `.absent` / `.unavailable` (a Keychain read error — the caller does not mint).
    func readPendingMintKey() -> SendoraSecureRead {
        let r = secure.read(SendoraStorage.mintKeyKey)
        if case .absent = r, let legacy = plain.string(forKey: SendoraStorage.mintKeyKey) { return .value(legacy) }
        return r
    }

    var pendingMintKey: String? { readPendingMintKey().valueOrNil }

    /// (s58.415, G6 / C3) Write the mint key and CONFIRM it (Keychain status) — `false` = not on disk, the caller does
    /// not mint. `nil` removes it (and the legacy UserDefaults copy).
    @discardableResult
    func writePendingMintKey(_ key: String?) -> Bool {
        if let k = key {
            guard secure.write(SendoraStorage.mintKeyKey, k) else { return false }
            if plain.hasValue(forKey: SendoraStorage.mintKeyKey) { plain.remove(forKey: SendoraStorage.mintKeyKey) }
            return true
        }
        let ok = secure.remove(SendoraStorage.mintKeyKey)
        if plain.hasValue(forKey: SendoraStorage.mintKeyKey) { plain.remove(forKey: SendoraStorage.mintKeyKey) }
        return ok
    }

    // MARK: - Keychain-backed (sensitive)

    var cachedUserId: String? {
        get { secure.get("sendora_user_id") }
        set {
            if let v = newValue {
                secure.set("sendora_user_id", v)
            } else {
                secure.delete("sendora_user_id")
            }
        }
    }

    /// 5.7.0 — one lock for every `SendoraStorage` in the process (they share one Keychain), so read-then-create
    /// is atomic. Before, the first launch's concurrent callers (attribution on a background queue, `app.opened` on
    /// main, the first `trackEvent`) each minted a UUID; the loser's add failed with -25299 and it kept sending an
    /// id that was never stored — two anonymous ids in the install's first session.
    private static let deviceIdLock = NSLock()
    /// An id the Keychain refused to store (e.g. before first unlock). Reused — and retried — until a write
    /// lands, so every caller in this process still sees ONE id. A readable stored id always wins.
    private static var unsavedDeviceId: String?

    var deviceId: String {
        Self.deviceIdLock.lock(); defer { Self.deviceIdLock.unlock() }
        if let existing = secure.get("sendora_device_id") {
            Self.unsavedDeviceId = nil
            return existing
        }
        let candidate = Self.unsavedDeviceId ?? UUID().uuidString
        switch secure.addIfAbsent("sendora_device_id", candidate) {
        case .added:
            Self.unsavedDeviceId = nil
            return candidate
        case .duplicate:
            // Someone else stored one between our read and our add: adopt THEIRS.
            if let stored = secure.get("sendora_device_id") {
                Self.unsavedDeviceId = nil
                return stored
            }
            Self.unsavedDeviceId = candidate
            return candidate
        case .failed:
            Self.unsavedDeviceId = candidate
            return candidate
        }
    }

    /// Regenerate the device id. Called by `SendoraCloud.reset()` so we don't leave
    /// an un-erasable fingerprint across logout.
    func regenerateDeviceId() {
        Self.deviceIdLock.lock(); defer { Self.deviceIdLock.unlock() }
        Self.unsavedDeviceId = nil
        secure.delete("sendora_device_id")
    }

    // MARK: - Auth Service tokens (Keychain-backed, FROZEN keys)

    var authAccessToken: String? {
        get { secure.get("sendora_auth_access_token") }
        set {
            if let v = newValue { secure.set("sendora_auth_access_token", v) }
            else { secure.delete("sendora_auth_access_token") }
        }
    }

    var authRefreshToken: String? {
        get { secure.get("sendora_auth_refresh_token") }
        set {
            if let v = newValue { secure.set("sendora_auth_refresh_token", v) }
            else { secure.delete("sendora_auth_refresh_token") }
        }
    }

    /// Unix-millis when the cached access token expires.
    /// 0 = unknown / not set.
    var authAccessExpiresAt: Int64 {
        get {
            guard let s = secure.get("sendora_auth_access_expires"),
                  let ms = Int64(s) else { return 0 }
            return ms
        }
        set {
            if newValue > 0 {
                secure.set("sendora_auth_access_expires", String(newValue))
            } else {
                secure.delete("sendora_auth_access_expires")
            }
        }
    }

    /// JSON-encoded `AuthUser`. Stored as opaque string since Storage
    /// is dependency-free; SendoraCloudAuth handles encode/decode.
    var authUserJson: String? {
        get { secure.get("sendora_auth_user") }
        set {
            if let v = newValue { secure.set("sendora_auth_user", v) }
            else { secure.delete("sendora_auth_user") }
        }
    }

    /// Clear the current-session keys: the four frozen keys AND their 5.4.0
    /// mirror `sendora_auth_session` (+ the rev-3 refresh marker, which only
    /// ever describes the current session). Never touches the held or quarantine
    /// slots, the event queue or `sendora_user_id` (ADR-033 §3.3 SIGN_OUT /
    /// DISCARD_WITHHELD rows). `true` when every key is gone afterwards.
    @discardableResult
    func clearAuthTokens() -> Bool {
        var ok = true
        // (T2) A key given up as permanently unreadable is never removed by the SDK — its bytes may be a credential.
        for key in SendoraStorage.frozenAuthKeys + [SendoraStorage.authSessionKey] where !isAcceptedUnreadable(key) && !secure.remove(key) { ok = false }
        if secure.read(SendoraStorage.refreshInflightKey) != .absent, !secure.remove(SendoraStorage.refreshInflightKey) { ok = false }
        return ok
    }

    // MARK: - ADR-033 rev 3 — status-carrying auth reads / confirmed writes

    /// The five keys that together ARE the current session. Names stay in this file (INV-1 source guard).
    enum AuthField {
        case accessToken, accessExpires, refreshToken, user, session

        var key: String {
            switch self {
            case .accessToken: return "sendora_auth_access_token"
            case .accessExpires: return "sendora_auth_access_expires"
            case .refreshToken: return "sendora_auth_refresh_token"
            case .user: return "sendora_auth_user"
            case .session: return SendoraStorage.authSessionKey
            }
        }
    }

    /// INV-17: `.unavailable` is never "absent" — except for a key ACCEPTED as permanently unreadable (T2).
    func read(_ field: AuthField) -> SendoraSecureRead {
        let r = secure.read(field.key)
        if r.isUnavailable && isAcceptedUnreadable(field.key) { return .absent }
        return r
    }

    /// INV-16: a confirmed write (`nil` = remove). `false` = the disk still holds the previous value.
    /// (s58.415, iOS #10) A key given up as unreadable (T2) is RE-READ before anything is written over it: a value now
    /// means the failure was transient and those bytes may be a guest's only token — the write is refused (nothing
    /// changes on disk) and `acceptedKeyFoundValue` tells the auth machine to re-hydrate.
    @discardableResult
    func write(_ field: AuthField, _ value: String?) -> Bool {
        if let v = value {
            // (s58.415, C2) …and a key STILL unreadable is refused too: its bytes may still be the guest. Only a key that
            // now reads ABSENT may be written (nothing is there to protect).
            if isAcceptedUnreadable(field.key) {
                switch secure.read(field.key) {
                case .value:
                    acceptedLock.lock(); acceptedFoundValue = true; acceptedLock.unlock()
                    return false
                case .unavailable:
                    return false
                case .absent:
                    break
                }
            }
            let ok = secure.write(field.key, v)
            if ok { acceptedLock.lock(); acceptedUnreadable.remove(field.key); acceptedLock.unlock() }
            return ok
        }
        if isAcceptedUnreadable(field.key) { return true } // (T2) never delete bytes we gave up reading
        return secure.remove(field.key)
    }

    static let sessionFields: [AuthField] = [.accessToken, .accessExpires, .refreshToken, .user, .session]

    /// True when none of the five session keys fails to READ (absent is fine) — the INV-17 re-hydrate probe.
    func sessionKeysReadable() -> Bool {
        return !SendoraStorage.sessionFields.contains { read($0).isUnavailable }
    }

    /// (T2) Give up on the session keys whose read is STILL failing: from now on they read as absent. Nothing is
    /// deleted. Returns the keys given up.
    @discardableResult
    func acceptUnreadableSessionKeys() -> [String] {
        let failing = SendoraStorage.sessionFields.filter { secure.read($0.key).isUnavailable }.map { $0.key }
        acceptedLock.lock(); acceptedUnreadable.formUnion(failing); acceptedLock.unlock()
        return failing
    }

    /// (s58.415, C2) Re-read every key given up as unreadable: `true` when one of them holds a VALUE again.
    func acceptedKeyHoldsValue() -> Bool {
        acceptedLock.lock()
        let keys = acceptedUnreadable
        acceptedLock.unlock()
        return keys.contains { if case .value = secure.read($0) { return true }; return false }
    }

    /// (s58.415, C2 / C3) Re-read every key given up as unreadable: `true` when one of them STILL fails to read — its
    /// bytes may still be the guest, so nothing may be written over it (a mint is then never installed).
    func acceptedKeyStillUnreadable() -> Bool {
        acceptedLock.lock()
        let keys = acceptedUnreadable
        acceptedLock.unlock()
        return keys.contains { secure.read($0).isUnavailable }
    }

    /// (iOS #10) A write found a value under a key accepted as unreadable. Read-and-reset.
    func takeAcceptedKeyFoundValue() -> Bool {
        acceptedLock.lock(); defer { acceptedLock.unlock() }
        let f = acceptedFoundValue
        acceptedFoundValue = false
        return f
    }

    /// (iOS #10) The store reads again: forget every acceptance (their bytes are real values now), so the re-hydrate
    /// sees them.
    func clearAcceptedUnreadable() {
        acceptedLock.lock(); acceptedUnreadable.removeAll(); acceptedLock.unlock()
    }

    func isAcceptedUnreadable(_ key: String) -> Bool {
        acceptedLock.lock(); defer { acceptedLock.unlock() }
        return acceptedUnreadable.contains(key)
    }

    /// (T2) The session lives in memory only: its refresh key was given up as permanently unreadable and no write
    /// has landed over it since. Nothing on disk can be protected by a marker or a pending-commit retry.
    var sessionIsMemoryOnly: Bool { isAcceptedUnreadable(AuthField.refreshToken.key) }

    func readHeldSlot(_ index: Int) -> SendoraSecureRead {
        guard SendoraStorage.heldSlotKeys.indices.contains(index) else { return .absent }
        return secure.read(SendoraStorage.heldSlotKeys[index])
    }

    func readQuarantineSlot(_ index: Int) -> SendoraSecureRead {
        guard SendoraStorage.quarantineSlotKeys.indices.contains(index) else { return .absent }
        return secure.read(SendoraStorage.quarantineSlotKeys[index])
    }

    /// Confirmed write of quarantine slot `index` (`nil` = release).
    @discardableResult
    func setQuarantineSlotJson(_ index: Int, _ json: String?) -> Bool {
        guard SendoraStorage.quarantineSlotKeys.indices.contains(index) else { return false }
        let key = SendoraStorage.quarantineSlotKeys[index]
        if let v = json { return secure.write(key, v) }
        return secure.remove(key)
    }

    /// INV-16 marker (Keychain, T15). PRESENT when it reads — or when its read FAILS (a marker we cannot see may be
    /// there; refreshing once too often is harmless, skipping the immediate refresh is not).
    var refreshInflightMarkerPresent: Bool {
        switch secure.read(SendoraStorage.refreshInflightKey) {
        case .absent: return false
        case .value, .unavailable: return true
        }
    }

    /// Confirmed write (`errSecSuccess` = on disk) or confirmed removal of the marker.
    @discardableResult
    func setRefreshInflightMarker(_ value: String?) -> Bool {
        if let v = value { return secure.write(SendoraStorage.refreshInflightKey, v) }
        return secure.remove(SendoraStorage.refreshInflightKey)
    }

    // MARK: - ADR-033 session record + held slots (Keychain-backed)

    /// The 5.4.0 session record (JSON). Read FIRST on hydrate; written on every
    /// install commit beside the four frozen keys.
    var authSessionJson: String? {
        get { secure.get(SendoraStorage.authSessionKey) }
        set {
            if let v = newValue { secure.set(SendoraStorage.authSessionKey, v) }
            else { secure.delete(SendoraStorage.authSessionKey) }
        }
    }

    /// Raw JSON of held slot `index` (0..<5), or `nil` when empty.
    func heldSlotJson(_ index: Int) -> String? {
        guard SendoraStorage.heldSlotKeys.indices.contains(index) else { return nil }
        return secure.get(SendoraStorage.heldSlotKeys[index])
    }

    /// Confirmed (rev 3): `false` = the slot on disk still holds its previous bytes.
    @discardableResult
    func setHeldSlotJson(_ index: Int, _ json: String?) -> Bool {
        guard SendoraStorage.heldSlotKeys.indices.contains(index) else { return false }
        let key = SendoraStorage.heldSlotKeys[index]
        if let v = json { return secure.write(key, v) }
        return secure.remove(key)
    }

    // MARK: - Known-device tokens (5.6.0, Keychain-backed, survives signOut)

    private struct KnownDevice: Codable {
        /// SHA-256 hex of the normalised email.
        let k: String
        let t: String
        let at: Int64
    }

    /// The backend's `normalizeEmail`: trim + lowercase.
    static func normaliseEmail(_ email: String) -> String {
        return email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private static func emailKey(_ email: String) -> String {
        let digest = SHA256.hash(data: Data(normaliseEmail(email).utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func loadKnownDevices() -> [KnownDevice] {
        guard let json = secure.get(SendoraStorage.knownDevicesKey), let data = json.data(using: .utf8),
              let list = try? JSONDecoder().decode([KnownDevice].self, from: data) else { return [] }
        return list
    }

    /// The token the last password sign-in for `email` returned on this device, or nil.
    func knownDeviceToken(forEmail email: String) -> String? {
        let key = Self.emailKey(email)
        guard let t = loadKnownDevices().first(where: { $0.k == key })?.t,
              !t.isEmpty, t.count <= SendoraStorage.knownDeviceTokenMaxLength else { return nil }
        return t
    }

    /// Remember (or replace) `email`'s token, newest first, keeping at most 20 accounts.
    /// Only `SendoraCloudAuth.commitKnownDeviceToken` calls this (INV-1).
    func setKnownDeviceToken(_ token: String, forEmail email: String, atMs: Int64) {
        guard !token.isEmpty, token.count <= SendoraStorage.knownDeviceTokenMaxLength else { return }
        let key = Self.emailKey(email)
        var list = loadKnownDevices().filter { $0.k != key }
        list.insert(KnownDevice(k: key, t: token, at: atMs), at: 0)
        if list.count > SendoraStorage.knownDevicesMax { list = Array(list.prefix(SendoraStorage.knownDevicesMax)) }
        guard let data = try? JSONEncoder().encode(list), let json = String(data: data, encoding: .utf8) else { return }
        secure.set(SendoraStorage.knownDevicesKey, json)
    }

    func forgetKnownDeviceToken(forEmail email: String) {
        let key = Self.emailKey(email)
        let list = loadKnownDevices()
        let kept = list.filter { $0.k != key }
        guard kept.count != list.count else { return }
        if kept.isEmpty { secure.delete(SendoraStorage.knownDevicesKey); return }
        guard let data = try? JSONEncoder().encode(kept), let json = String(data: data, encoding: .utf8) else { return }
        secure.set(SendoraStorage.knownDevicesKey, json)
    }

    // MARK: - Link revoke tokens (5.6.0, Keychain-backed)

    private struct LinkRevokeToken: Codable {
        let s: String
        let t: String
    }

    private func loadLinkRevokeTokens() -> [LinkRevokeToken] {
        guard let json = secure.get(SendoraStorage.linkRevokeTokensKey), let data = json.data(using: .utf8),
              let list = try? JSONDecoder().decode([LinkRevokeToken].self, from: data) else { return [] }
        return list
    }

    private func saveLinkRevokeTokens(_ list: [LinkRevokeToken]) {
        if list.isEmpty { secure.delete(SendoraStorage.linkRevokeTokensKey); return }
        guard let data = try? JSONEncoder().encode(list), let json = String(data: data, encoding: .utf8) else { return }
        secure.set(SendoraStorage.linkRevokeTokensKey, json)
    }

    func linkRevokeToken(forShortcode shortcode: String) -> String? {
        return loadLinkRevokeTokens().first(where: { $0.s == shortcode })?.t
    }

    /// Newest first; the oldest is forgotten past 200 links.
    func setLinkRevokeToken(_ token: String, forShortcode shortcode: String) {
        guard !token.isEmpty, token.count <= SendoraStorage.linkRevokeTokenMaxLength, !shortcode.isEmpty else { return }
        var list = loadLinkRevokeTokens().filter { $0.s != shortcode }
        list.insert(LinkRevokeToken(s: shortcode, t: token), at: 0)
        if list.count > SendoraStorage.linkRevokeTokensMax { list = Array(list.prefix(SendoraStorage.linkRevokeTokensMax)) }
        saveLinkRevokeTokens(list)
    }

    func forgetLinkRevokeToken(forShortcode shortcode: String) {
        let list = loadLinkRevokeTokens()
        let kept = list.filter { $0.s != shortcode }
        if kept.count != list.count { saveLinkRevokeTokens(kept) }
    }

    // MARK: - Event queue

    /// Persist events to disk exactly as they will be sent (plus the queue's own
    /// `_sendoraAttempts`, stripped at send time).
    ///
    /// ⚠ s58.405: this used to strip `userId` (and a `properties.traits` key),
    /// claiming they would be "repopulated from `currentUserId` when the queue is
    /// flushed". Nothing ever did that, and it could not be right anyway — the
    /// user at flush time is not necessarily the user who produced the event. An
    /// identified event carries `userId` INSTEAD of `anonymousId`, so a restored
    /// event went out with NEITHER (unattributed) and could never get its send-time
    /// identity token (`decorateForSend` matches on `userId`). The strip never
    /// covered `identify()`'s traits either: they are the `properties` of
    /// `user.identified`, not a `traits` key. The identity token is never
    /// stored — it is attached at send time only, and removed here as a belt.
    /// Backward compatible: a file written by ≤ 5.7.0 simply has no `userId`
    /// (decodes as absent → nil), exactly what those builds sent.
    func saveEventQueue(_ events: [[String: Any]]) {
        let persisted = events.map { event -> [String: Any] in
            guard event["identityToken"] != nil else { return event }
            var e = event
            e.removeValue(forKey: "identityToken")
            return e
        }
        do {
            let data = try JSONSerialization.data(withJSONObject: persisted)
            plain.setData(data, forKey: "sendora_event_queue")
        } catch {
            SendoraCloudLogger.shared.error("Failed to save event queue: \(error)")
        }
    }

    func loadEventQueue() -> [[String: Any]] {
        guard let data = plain.data(forKey: "sendora_event_queue") else { return [] }
        do {
            let events = try JSONSerialization.jsonObject(with: data) as? [[String: Any]]
            return events ?? []
        } catch {
            return []
        }
    }

    func clearEventQueue() {
        plain.remove(forKey: "sendora_event_queue")
    }
}
