import Foundation
import XCTest
@testable import SendoraCloud

/// 5.7.0 — the device id (the anonymous id on every pre-identify event, and the attribution key) is get-or-create
/// ATOMIC. Found on the iOS Simulator with the real Keychain: on a fresh install attribution (background queue) and
/// `app.opened` (main) both minted a UUID, the loser's add failed with -25299 and it kept sending an id that was never
/// stored — two anonymous ids in the install's first session, 4 of 4 fresh installs.
final class DeviceIdTests: XCTestCase {

    /// Models the Keychain: `addIfAbsent` is atomic and reports a duplicate, never overwrites. The sleeps widen the
    /// read → add window the way a real Keychain round trip does.
    final class KeychainModelStore: SendoraSecureStore {
        private let lock = NSLock()
        private var values: [String: String] = [:]
        /// Adds still to refuse (`errSecInteractionNotAllowed`, as before first unlock).
        var failAdds = 0
        /// Inserted by "another writer" just before the next add lands — forces the duplicate path.
        var otherWriterValue: String?
        private(set) var addCalls = 0

        func get(_ key: String) -> String? {
            usleep(300)
            lock.lock(); defer { lock.unlock() }
            return values[key]
        }
        func set(_ key: String, _ value: String) {   // the old delete-then-add: last writer wins
            usleep(300)
            lock.lock(); values[key] = value; lock.unlock()
        }
        func delete(_ key: String) { lock.lock(); values.removeValue(forKey: key); lock.unlock() }
        func addIfAbsent(_ key: String, _ value: String) -> SendoraSecureAddResult {
            usleep(300)
            lock.lock(); defer { lock.unlock() }
            addCalls += 1
            if failAdds > 0 { failAdds -= 1; return .failed(errSecInteractionNotAllowed) }
            if let other = otherWriterValue { values[key] = other; otherWriterValue = nil }
            if values[key] != nil { return .duplicate }
            values[key] = value
            return .added
        }
        func stored(_ key: String) -> String? { lock.lock(); defer { lock.unlock() }; return values[key] }
    }

    private let key = "sendora_device_id"

    override func setUp() {
        super.setUp()
        // The unsaved-id memo is process-wide (one Keychain per process): start every test without one.
        SendoraStorage(secure: KeychainModelStore(), plain: RecordingPlainStore()).regenerateDeviceId()
    }

    private func concurrentIds(_ storages: [SendoraStorage], count: Int = 50) -> [String] {
        let lock = NSLock()
        var ids: [String] = []
        DispatchQueue.concurrentPerform(iterations: count) { i in
            let id = storages[i % storages.count].deviceId
            lock.lock(); ids.append(id); lock.unlock()
        }
        return ids
    }

    func test_fiftyConcurrentFirstLaunchCallers_getOneId_andItIsTheStoredOne() {
        let store = KeychainModelStore()
        // Two storages on one Keychain (configure() twice / two SDK objects) — the lock must be process-wide.
        let storages = [SendoraStorage(secure: store, plain: RecordingPlainStore()),
                        SendoraStorage(secure: store, plain: RecordingPlainStore())]
        let ids = concurrentIds(storages)
        XCTAssertEqual(Set(ids).count, 1, "every first-session caller must get the SAME id, got \(Set(ids).count)")
        XCTAssertEqual(store.stored(key), ids.first, "the id handed out is the one persisted")
        XCTAssertEqual(storages[0].deviceId, ids.first, "and the next launch reads it back")
    }

    func test_duplicateAdd_adoptsTheStoredValue_neverKeepsItsOwnUnsavedId() {
        let store = KeychainModelStore()
        store.otherWriterValue = "THEIRS"
        let storage = SendoraStorage(secure: store, plain: RecordingPlainStore())
        XCTAssertEqual(storage.deviceId, "THEIRS", "-25299 → re-read and adopt the stored id")
        XCTAssertEqual(storage.deviceId, "THEIRS")
        XCTAssertEqual(store.stored(key), "THEIRS")
    }

    func test_keychainRefusingWrites_stillOneIdForEveryCaller_thenPersistsThatSameId() {
        let store = KeychainModelStore()
        store.failAdds = 1_000
        let storage = SendoraStorage(secure: store, plain: RecordingPlainStore())
        let ids = concurrentIds([storage])
        XCTAssertEqual(Set(ids).count, 1, "an unwritable Keychain must not hand out a fresh id per call")
        XCTAssertNil(store.stored(key))
        store.failAdds = 0
        XCTAssertEqual(storage.deviceId, ids.first, "the first write that lands stores the id already handed out")
        XCTAssertEqual(store.stored(key), ids.first)
    }

    /// The REAL Keychain (iOS only — the macOS `swift test` runner is unsigned and would write into the login
    /// keychain). Own service name, removed afterwards. ⚠ A HOSTLESS test bundle (`xcodebuild test` on this package)
    /// has no keychain entitlement: every add is -34018, so it skips there; the real-Keychain proof is the consumer-app
    /// fresh-install run (CLAUDE.md 5.7.0). It runs when the suite is hosted by an app.
    func test_realKeychain_fiftyConcurrentCallers_oneStoredId() throws {
        #if os(iOS)
        let keychain = KeychainSecureStore(service: "com.sendora.sdk.test-\(UUID().uuidString)")
        defer { keychain.delete(key); keychain.delete("probe") }
        let probe = keychain.addIfAbsent("probe", "1")
        if probe == .failed(errSecMissingEntitlement) {
            throw XCTSkip("no keychain entitlement in a hostless test bundle (-34018)")
        }
        XCTAssertEqual(probe, .added)
        XCTAssertEqual(keychain.addIfAbsent("probe", "2"), .duplicate, "a second add reports -25299, never overwrites")
        XCTAssertEqual(keychain.get("probe"), "1")
        keychain.delete("probe")
        let storages = (0..<4).map { _ in SendoraStorage(secure: keychain, plain: RecordingPlainStore()) }
        let ids = concurrentIds(storages)
        XCTAssertEqual(Set(ids).count, 1, "one id across every concurrent first-launch caller")
        XCTAssertEqual(keychain.get(key), ids.first)
        #else
        throw XCTSkip("real-Keychain test runs on the iOS Simulator only")
        #endif
    }

    func test_regenerate_startsANewId() {
        let store = KeychainModelStore()
        let storage = SendoraStorage(secure: store, plain: RecordingPlainStore())
        let first = storage.deviceId
        storage.regenerateDeviceId()
        let second = storage.deviceId
        XCTAssertNotEqual(first, second)
        XCTAssertEqual(store.stored(key), second)
    }
}
