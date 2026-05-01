import Foundation
import Security

/// Persistent storage.
///  - `isFirstLaunch` / `sessionId` live in UserDefaults (non-sensitive).
///  - `deviceId` and `cachedUserId` live in Keychain with
///    `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — not backed up to
///    iCloud, not readable from other apps.
///  - Event queue is persisted as JSON stripped of PII (userId + traits removed
///    before writing; they'll be re-injected from `currentUserId` at send time).
final class SendoraStorage {
    private let defaults: UserDefaults
    private let suiteName = "com.sendora.sdk"

    init() {
        self.defaults = UserDefaults(suiteName: suiteName) ?? .standard
    }

    // MARK: - UserDefaults (non-sensitive)

    var isFirstLaunch: Bool {
        get { !defaults.bool(forKey: "sendora_launched") }
        set { defaults.set(!newValue, forKey: "sendora_launched") }
    }

    var sessionId: String {
        get { defaults.string(forKey: "sendora_session_id") ?? "" }
        set { defaults.set(newValue, forKey: "sendora_session_id") }
    }

    // MARK: - Keychain-backed (sensitive)

    var cachedUserId: String? {
        get { keychainGet(key: "sendora_user_id") }
        set {
            if let v = newValue {
                keychainSet(key: "sendora_user_id", value: v)
            } else {
                keychainDelete(key: "sendora_user_id")
            }
        }
    }

    var deviceId: String {
        if let existing = keychainGet(key: "sendora_device_id") {
            return existing
        }
        let newId = UUID().uuidString
        keychainSet(key: "sendora_device_id", value: newId)
        return newId
    }

    /// Regenerate the device id. Called by `SendoraCloud.reset()` so we don't leave
    /// an un-erasable fingerprint across logout.
    func regenerateDeviceId() {
        keychainDelete(key: "sendora_device_id")
    }

    // MARK: - Auth Service tokens (Keychain-backed)

    var authAccessToken: String? {
        get { keychainGet(key: "sendora_auth_access_token") }
        set {
            if let v = newValue { keychainSet(key: "sendora_auth_access_token", value: v) }
            else { keychainDelete(key: "sendora_auth_access_token") }
        }
    }

    var authRefreshToken: String? {
        get { keychainGet(key: "sendora_auth_refresh_token") }
        set {
            if let v = newValue { keychainSet(key: "sendora_auth_refresh_token", value: v) }
            else { keychainDelete(key: "sendora_auth_refresh_token") }
        }
    }

    /// JSON-encoded `AuthUser`. Stored as opaque string since Storage
    /// is dependency-free; SendoraCloudAuth handles encode/decode.
    var authUserJson: String? {
        get { keychainGet(key: "sendora_auth_user") }
        set {
            if let v = newValue { keychainSet(key: "sendora_auth_user", value: v) }
            else { keychainDelete(key: "sendora_auth_user") }
        }
    }

    func clearAuthTokens() {
        keychainDelete(key: "sendora_auth_access_token")
        keychainDelete(key: "sendora_auth_refresh_token")
        keychainDelete(key: "sendora_auth_user")
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
            defaults.set(data, forKey: "sendora_event_queue")
        } catch {
            SendoraCloudLogger.shared.error("Failed to save event queue: \(error)")
        }
    }

    func loadEventQueue() -> [[String: Any]] {
        guard let data = defaults.data(forKey: "sendora_event_queue") else { return [] }
        do {
            let events = try JSONSerialization.jsonObject(with: data) as? [[String: Any]]
            return events ?? []
        } catch {
            return []
        }
    }

    func clearEventQueue() {
        defaults.removeObject(forKey: "sendora_event_queue")
    }

    // MARK: - Keychain helpers

    private func keychainGet(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: suiteName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func keychainSet(key: String, value: String) {
        let data = value.data(using: .utf8)!
        keychainDelete(key: key)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: suiteName,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    private func keychainDelete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: suiteName,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
