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
protocol SendoraSecureStore: AnyObject {
    func get(_ key: String) -> String?
    func set(_ key: String, _ value: String)
    func delete(_ key: String)
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

final class KeychainSecureStore: SendoraSecureStore {
    private let service: String

    init(service: String) {
        self.service = service
    }

    func get(_ key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func set(_ key: String, _ value: String) {
        let data = value.data(using: .utf8)!
        delete(key)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: service,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            // Surface OSStatus failures so the developer can diagnose
            // pre-first-unlock writes (errSecInteractionNotAllowed) or
            // duplicate-item races (errSecDuplicateItem) — previously
            // swallowed, leaving the user "logged out" with no log.
            SendoraCloudLogger.shared.error(
                "Keychain set failed for key=\(key) status=\(status)"
            )
        }
    }

    func delete(_ key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
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
///    iCloud, not readable from other apps.
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

    /// The CLOSED set of Keychain keys this SDK may write. The auth machine's
    /// recording double asserts every secure write lands on one of these.
    static let secureKeys: [String] =
        ["sendora_user_id", "sendora_device_id"] + frozenAuthKeys + [authSessionKey] + heldSlotKeys
        + [knownDevicesKey, linkRevokeTokensKey]

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

    /// ADR-033 B10 — the per-ATTEMPT idempotent mint key, persisted in the
    /// NON-secret tier until the mint commits (a retried mint with the same key
    /// within 24 h returns the same guest instead of a second one). A one-shot
    /// retry handle, never a device credential.
    var pendingMintKey: String? {
        get { plain.string(forKey: "sendora_auth_mint_key") }
        set {
            if let v = newValue { plain.setString(v, forKey: "sendora_auth_mint_key") }
            else { plain.remove(forKey: "sendora_auth_mint_key") }
        }
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

    var deviceId: String {
        if let existing = secure.get("sendora_device_id") {
            return existing
        }
        let newId = UUID().uuidString
        secure.set("sendora_device_id", newId)
        return newId
    }

    /// Regenerate the device id. Called by `SendoraCloud.reset()` so we don't leave
    /// an un-erasable fingerprint across logout.
    func regenerateDeviceId() {
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
    /// mirror `sendora_auth_session`. Never touches the held slots, the event
    /// queue or `sendora_user_id` (ADR-033 §3.3 SIGN_OUT / DISCARD_WITHHELD rows).
    func clearAuthTokens() {
        secure.delete("sendora_auth_access_token")
        secure.delete("sendora_auth_access_expires")
        secure.delete("sendora_auth_refresh_token")
        secure.delete("sendora_auth_user")
        secure.delete(SendoraStorage.authSessionKey)
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

    func setHeldSlotJson(_ index: Int, _ json: String?) {
        guard SendoraStorage.heldSlotKeys.indices.contains(index) else { return }
        let key = SendoraStorage.heldSlotKeys[index]
        if let v = json { secure.set(key, v) } else { secure.delete(key) }
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

    // MARK: - Event queue (PII-stripped)

    /// Persist events to disk. `userId` and `traits` are stripped — they'll be
    /// repopulated from `currentUserId` when the queue is flushed.
    func saveEventQueue(_ events: [[String: Any]]) {
        let stripped = events.map { event -> [String: Any] in
            var e = event
            e.removeValue(forKey: "userId")
            if var props = e["properties"] as? [String: Any] {
                props.removeValue(forKey: "traits")
                e["properties"] = props
            }
            return e
        }
        do {
            let data = try JSONSerialization.data(withJSONObject: stripped)
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
