import Foundation
import Security
import XCTest
@testable import SendoraCloud

// ADR-033 rev 3 §3.8 (s58.415) — the REAL `KeychainSecureStore` over a fake Security.framework (`KeychainAPI` seam).
// The auth suites run on in-memory doubles, so without this file nothing would notice the production store going
// back to delete-then-add, or reading −25308 as "absent" (the two iOS defects behind FS1/FS2 and FS3, audit H1/H2).

/// A keychain that behaves like Security.framework for one service: items keyed by account, per-call status
/// overrides (−25308 before first unlock), and a log of every call in order.
final class FakeKeychain {
    private(set) var items: [String: (data: Data, accessible: String?)] = [:]
    private(set) var calls: [String] = []
    /// Status to return from the NEXT call of that kind (one-shot), or for every call while set.
    var failCopy: OSStatus?
    var failUpdate: OSStatus?
    var failAdd: OSStatus?
    var failDelete: OSStatus?

    func seed(_ account: String, _ value: String, accessible: String? = nil) { items[account] = (Data(value.utf8), accessible) }
    func seedData(_ account: String, _ data: Data) { items[account] = (data, nil) }
    func value(_ account: String) -> String? { items[account].map { String(data: $0.data, encoding: .utf8)! } }

    var api: KeychainAPI {
        KeychainAPI(
            copyMatching: { [unowned self] q in
                let account = q[kSecAttrAccount as String] as! String
                self.calls.append("copy \(account)")
                if let s = self.failCopy { return (s, nil) }
                guard let item = self.items[account] else { return (errSecItemNotFound, nil) }
                return (errSecSuccess, item.data as AnyObject)
            },
            add: { [unowned self] q in
                let account = q[kSecAttrAccount as String] as! String
                self.calls.append("add \(account)")
                if let s = self.failAdd { return s }
                if self.items[account] != nil { return errSecDuplicateItem }
                self.items[account] = (q[kSecValueData as String] as! Data, q[kSecAttrAccessible as String] as? String)
                return errSecSuccess
            },
            update: { [unowned self] q, attrs in
                let account = q[kSecAttrAccount as String] as! String
                self.calls.append("update \(account)")
                if let s = self.failUpdate { return s }
                guard self.items[account] != nil else { return errSecItemNotFound }
                self.items[account] = (attrs[kSecValueData as String] as! Data, attrs[kSecAttrAccessible as String] as? String)
                return errSecSuccess
            },
            delete: { [unowned self] q in
                let account = q[kSecAttrAccount as String] as! String
                self.calls.append("delete \(account)")
                if let s = self.failDelete { return s }
                return self.items.removeValue(forKey: account) == nil ? errSecItemNotFound : errSecSuccess
            }
        )
    }
}

final class KeychainStoreSemanticsTests: XCTestCase {
    /// ⚠ Pins converted (s58.415, operator decision D2): the AUTH keys are `AfterFirstUnlock` (they travel in an
    /// encrypted backup / Quick Start — a guest must not be stranded on the old phone); everything else, the device id
    /// first, stays `AfterFirstUnlockThisDeviceOnly`. These two tests asserted ThisDeviceOnly for `sendora_auth_session`
    /// and `sendora_auth_refresh_token`, which is exactly what D2 changed.
    private let afterFirstUnlock = kSecAttrAccessibleAfterFirstUnlock as String
    private let thisDeviceOnly = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String

    /// INV-16: a write over an existing item is an IN-PLACE update — never a delete — so a refused write leaves
    /// the OLD value (the account's token) where it was, and the caller is TOLD it failed.
    func test_writeReplacesInPlace_aRefusedWriteKeepsTheOldValueAndSaysSo() {
        let k = FakeKeychain()
        k.seed("sendora_auth_refresh_token", "R1")
        let store = KeychainSecureStore(service: "com.sendora.sdk", api: k.api)
        XCTAssertTrue(store.write("sendora_auth_refresh_token", "R2"))
        XCTAssertEqual(k.value("sendora_auth_refresh_token"), "R2")
        XCTAssertEqual(k.calls, ["update sendora_auth_refresh_token"], "one in-place update — no delete, no add")
        k.failUpdate = errSecInteractionNotAllowed
        XCTAssertFalse(store.write("sendora_auth_refresh_token", "R3"), "the failure is KNOWN")
        XCTAssertEqual(k.value("sendora_auth_refresh_token"), "R2", "the old value survives a failed write")
        XCTAssertFalse(k.calls.contains { $0.hasPrefix("delete") }, "a write never passes through 'no value'")
        // The legacy `set` is the same write.
        k.failUpdate = nil
        store.set("sendora_auth_refresh_token", "R4")
        XCTAssertEqual(k.value("sendora_auth_refresh_token"), "R4")
        XCTAssertFalse(k.calls.contains { $0.hasPrefix("delete") })
    }

    /// Add ONLY when the item is absent; a racing add that lands first is updated in place, not lost.
    func test_writeAddsOnlyWhenAbsent_andResolvesARacingAdd() {
        let k = FakeKeychain()
        let store = KeychainSecureStore(service: "com.sendora.sdk", api: k.api)
        XCTAssertTrue(store.write("sendora_auth_session", "{}"))
        XCTAssertEqual(k.calls, ["update sendora_auth_session", "add sendora_auth_session"])
        XCTAssertEqual(k.items["sendora_auth_session"]?.accessible, afterFirstUnlock, "created AfterFirstUnlock (D2)")
        // A failed add (absent item, locked device) is reported, and nothing is on disk.
        let k2 = FakeKeychain()
        k2.failAdd = errSecInteractionNotAllowed
        XCTAssertFalse(KeychainSecureStore(service: "s", api: k2.api).write("x", "v"))
        XCTAssertNil(k2.value("x"))
    }

    /// Background refreshes run while the phone is locked: every write carries AfterFirstUnlock, so an item created
    /// under another class migrates in place on its next write. Reads never filter on accessibility.
    func test_everyWriteCarriesAfterFirstUnlock_soAnOlderItemMigratesInPlace() {
        let k = FakeKeychain()
        k.seed("sendora_auth_refresh_token", "R1", accessible: kSecAttrAccessibleWhenUnlocked as String)
        let store = KeychainSecureStore(service: "com.sendora.sdk", api: k.api)
        XCTAssertEqual(store.read("sendora_auth_refresh_token"), .value("R1"), "readable whatever its class")
        XCTAssertTrue(store.write("sendora_auth_refresh_token", "R2"))
        XCTAssertEqual(k.items["sendora_auth_refresh_token"]?.accessible, afterFirstUnlock)
    }

    /// (s58.415, D2) EVERY auth key — the four frozen keys, the session record, the 5 held + 3 quarantine slots, the
    /// refresh marker — is written `kSecAttrAccessibleAfterFirstUnlock` (NOT ThisDeviceOnly), both when created and when
    /// an existing `…ThisDeviceOnly` item (every earlier build) is updated: it migrates on its next write. The device id
    /// (`addIfAbsent`) and the other non-session keys keep `…ThisDeviceOnly`. The mint key (Keychain since batch C)
    /// travels too.
    func test_D2_everyAuthKeyTravels_existingItemsMigrateOnNextWrite_theDeviceIdStaysOnThisDevice() {
        let authKeys = SendoraStorage.frozenAuthKeys + [SendoraStorage.authSessionKey] + SendoraStorage.heldSlotKeys
            + SendoraStorage.quarantineSlotKeys + [SendoraStorage.refreshInflightKey, SendoraStorage.mintKeyKey]
        // (s58.415, C3) + the mint key: a Keychain item since batch C (confirmed write), travelling like the session.
        XCTAssertEqual(authKeys.count, 4 + 1 + 5 + 3 + 1 + 1)
        XCTAssertEqual(Set(authKeys), SendoraStorage.travellingAuthKeys, "the travelling set is exactly the auth keys")
        let k = FakeKeychain()
        let store = KeychainSecureStore(service: "com.sendora.sdk", api: k.api)
        for (i, key) in authKeys.enumerated() {
            // an item an earlier build created ThisDeviceOnly → migrated by the next write (update in place)
            if i % 2 == 0 { k.seed(key, "old", accessible: thisDeviceOnly) }
            XCTAssertTrue(store.write(key, "v\(i)"))
            XCTAssertEqual(k.items[key]?.accessible, afterFirstUnlock, "\(key): AfterFirstUnlock (travels)")
            XCTAssertEqual(k.value(key), "v\(i)")
        }
        XCTAssertFalse(k.calls.contains { $0.hasPrefix("delete") }, "the migration is an in-place update, never delete-then-add")
        // the device id + the device-bound keys keep their class
        XCTAssertEqual(store.addIfAbsent("sendora_device_id", "dev-1"), .added)
        XCTAssertEqual(k.items["sendora_device_id"]?.accessible, thisDeviceOnly, "the device id stays on this device")
        for key in ["sendora_user_id", SendoraStorage.knownDevicesKey, SendoraStorage.linkRevokeTokensKey] {
            k.seed(key, "x", accessible: thisDeviceOnly)
            XCTAssertTrue(store.write(key, "y"))
            XCTAssertEqual(k.items[key]?.accessible, thisDeviceOnly, "\(key) stays ThisDeviceOnly")
        }
        // the whole storage over the real store: an install writes every session key travelling
        let k2 = FakeKeychain()
        let storage = SendoraStorage(secure: KeychainSecureStore(service: "com.sendora.sdk", api: k2.api), plain: RecordingPlainStore())
        XCTAssertTrue(storage.write(.refreshToken, "R1")); XCTAssertTrue(storage.write(.session, "{}"))
        XCTAssertTrue(storage.setHeldSlotJson(0, "{}")); XCTAssertTrue(storage.setQuarantineSlotJson(2, "{}"))
        XCTAssertTrue(storage.setRefreshInflightMarker("{}"))
        for key in ["sendora_auth_refresh_token", "sendora_auth_session", "sendora_auth_held_0", "sendora_auth_quarantine_2", "sendora_auth_refresh_inflight"] {
            XCTAssertEqual(k2.items[key]?.accessible, afterFirstUnlock, key)
        }
        _ = storage.deviceId
        XCTAssertEqual(k2.items["sendora_device_id"]?.accessible, thisDeviceOnly)
    }

    /// INV-17: ONLY errSecItemNotFound is "absent". −25308 before first unlock, −34018, an undecodable value are
    /// `.unavailable` — and `get` (the legacy surface) still returns nil for them, which is why the auth machine
    /// reads through `read`.
    func test_readDistinguishesAbsentFromUnavailable() {
        let k = FakeKeychain()
        let store = KeychainSecureStore(service: "com.sendora.sdk", api: k.api)
        XCTAssertEqual(store.read("sendora_auth_refresh_token"), .absent)
        k.seed("sendora_auth_refresh_token", "R1")
        XCTAssertEqual(store.read("sendora_auth_refresh_token"), .value("R1"))
        for status in [errSecInteractionNotAllowed, OSStatus(-34018), errSecIO] {
            k.failCopy = status
            XCTAssertEqual(store.read("sendora_auth_refresh_token"), .unavailable(status), "status \(status) is not 'absent'")
        }
        k.failCopy = nil
        k.seedData("bad", Data([0xFF, 0xFE, 0xFD])) // not UTF-8: present but unreadable
        XCTAssertEqual(store.read("bad"), .unavailable(errSecDecode))
        XCTAssertNil(store.get("bad"))
    }

    /// `remove`: true when the item is gone afterwards (incl. never there); a refused delete is reported.
    func test_removeReportsItsOutcome() {
        let k = FakeKeychain()
        k.seed("a", "1")
        let store = KeychainSecureStore(service: "com.sendora.sdk", api: k.api)
        XCTAssertTrue(store.remove("a")); XCTAssertNil(k.value("a"))
        XCTAssertTrue(store.remove("a"), "absent is removed")
        k.seed("b", "2")
        k.failDelete = errSecInteractionNotAllowed
        XCTAssertFalse(store.remove("b")); XCTAssertEqual(k.value("b"), "2")
    }

    /// The whole storage over the real store: a hydrate before first unlock sees `.unavailable`, never "no session".
    func test_storageOverTheRealStore_lockedReadIsUnavailable() {
        let k = FakeKeychain()
        k.seed("sendora_auth_refresh_token", "R1")
        let storage = SendoraStorage(secure: KeychainSecureStore(service: "com.sendora.sdk", api: k.api), plain: RecordingPlainStore())
        k.failCopy = errSecInteractionNotAllowed
        XCTAssertFalse(storage.sessionKeysReadable())
        XCTAssertEqual(storage.read(.refreshToken), .unavailable(errSecInteractionNotAllowed))
        k.failCopy = nil
        XCTAssertTrue(storage.sessionKeysReadable())
        XCTAssertEqual(storage.read(.refreshToken), .value("R1"))
    }
}
