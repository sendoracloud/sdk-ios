import XCTest
@testable import SendoraCloud

/// s58.405 — the persisted event queue keeps `userId`.
///
/// ≤ 5.7.0 stripped `userId` in `saveEventQueue`, claiming it would be "repopulated from `currentUserId` when the
/// queue is flushed" — nothing did. An identified event carries `userId` INSTEAD of `anonymousId`, so after a
/// relaunch it went out with neither (unattributed) and `decorateForSend` (which matches on `userId`) could never
/// give it the send-time identity token. These tests drive the real `SendoraStorage` + `EventQueue` over an
/// in-memory plain store (one store = one device's UserDefaults; a new `EventQueue` over it = a relaunch).
final class PersistedQueueIdentityTests: XCTestCase {

    private func device() -> (SendoraStorage, RecordingPlainStore) {
        let plain = RecordingPlainStore()
        return (SendoraStorage(secure: RecordingSecureStore(), plain: plain), plain)
    }

    private func identifiedEvent(_ name: String, userId: String) -> [String: Any] {
        SendoraCloud.buildEvent(name: name, properties: ["level": 3, "traits": ["plan": "pro"]],
                                projectId: nil, device: ["os": "iOS"], sessionId: "s1", consentGranted: true,
                                userId: userId, anonymousId: nil, timestamp: Date(timeIntervalSince1970: 1_700_000_000))
    }

    private func eventually(_ what: String, timeout: TimeInterval = 5, _ cond: () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while !cond() {
            if Date() > deadline { return XCTFail("timed out: \(what)") }
            Thread.sleep(forTimeInterval: 0.005)
        }
    }

    private final class Box<T> { var v: T; init(_ v: T) { self.v = v } }

    func test_aQueuedEventKeepsItsUserIdAcrossARelaunch_andEveryWireFieldSurvives() {
        let (storage, _) = device()
        let original = identifiedEvent("level.complete", userId: "user-42")
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.add(event: original)
        q.persistToDisk()
        _ = q.count // drain the queue's serial hop

        let relaunched = EventQueue(storage: storage, flushAt: 1000)
        let restored = relaunched.snapshot
        XCTAssertEqual(restored.count, 1)
        guard let e = restored.first else { return }
        XCTAssertEqual(e["userId"] as? String, "user-42", "the persisted queue dropped the event's user")
        XCTAssertNil(e["anonymousId"], "an identified event has no anonymousId — without userId it is unattributed")
        // Field by field: the restored event is the event that was queued.
        XCTAssertEqual(Set(e.keys), Set(original.keys), "the persisted form dropped or added a top-level field")
        let props = e["properties"] as? [String: Any]
        XCTAssertEqual((props?["level"] as? NSNumber)?.intValue, 3)
        XCTAssertEqual((props?["traits"] as? [String: Any])?["plan"] as? String, "pro", "a caller's `traits` property was stripped")
        XCTAssertEqual(e["eventType"] as? String, "level.complete")
        XCTAssertEqual(e["sessionId"] as? String, "s1")
        XCTAssertEqual(e["timestamp"] as? String, original["timestamp"] as? String)
    }

    func test_aRestoredEventGetsTheSendTimeTokenOnlyForTheIdentifiedUser() {
        let (storage, _) = device()
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.add(event: identifiedEvent("a", userId: "user-42"))
        q.add(event: identifiedEvent("b", userId: "someone-else"))
        q.persistToDisk()
        _ = q.count

        // Relaunch; identify(userId: "user-42", identityToken:) runs again, so the decorator proves user-42.
        let relaunched = EventQueue(storage: storage, flushAt: 1000)
        relaunched.jitter = { _ in 0 }
        relaunched.decorator = { SendoraCloud.decorateForSend($0, currentUserId: "user-42", identityToken: "tok-42") }
        let lock = NSLock()
        let sent = Box<[[String: Any]]>([])
        relaunched.setFlushHandler { chunk, done in lock.lock(); sent.v.append(contentsOf: chunk); lock.unlock(); done(.accepted) }
        relaunched.flush()
        eventually("drained") { relaunched.count == 0 }
        lock.lock(); defer { lock.unlock() }
        let byName = Dictionary(uniqueKeysWithValues: sent.v.map { (($0["eventType"] as? String) ?? "", $0) })
        XCTAssertEqual(byName["a"]?["userId"] as? String, "user-42")
        XCTAssertEqual(byName["a"]?["identityToken"] as? String, "tok-42", "a restored event of the identified user got no send-time token")
        XCTAssertNil(byName["b"]?["identityToken"], "another user's restored event got the token")
        // The token was attached to the outgoing copy only — never written to disk.
        let disk = String(data: (try? JSONSerialization.data(withJSONObject: storage.loadEventQueue())) ?? Data(), encoding: .utf8) ?? ""
        XCTAssertFalse(disk.contains("tok-42"))
    }

    func test_anIdentityTokenIsNeverPersisted_evenIfAnEventCarriesOne() {
        let (storage, _) = device()
        var e = identifiedEvent("x", userId: "user-42")
        e["identityToken"] = "should-not-hit-disk"
        storage.saveEventQueue([e])
        let restored = storage.loadEventQueue()
        XCTAssertEqual(restored.first?["userId"] as? String, "user-42")
        XCTAssertNil(restored.first?["identityToken"])
    }

    func test_aQueueWrittenByAnOlderVersion_withoutUserId_stillDecodes() throws {
        let (storage, plain) = device()
        // Exactly what ≤ 5.7.0 wrote: no userId (stripped), the budget field present on one event.
        let legacy = """
        [{"module":"custom","eventType":"old.one","timestamp":"2026-10-01T00:00:00.000Z","properties":{"k":"v"},
          "context":{"device":{"os":"iOS"},"sdk":{"name":"sendora-ios","version":"5.7.0"}},"sessionId":"s0","consent":["analytics"]},
         {"module":"custom","eventType":"old.two","timestamp":"2026-10-01T00:00:01.000Z","properties":{},
          "context":{},"sessionId":"s0","consent":[],"anonymousId":"dev-1","_sendoraAttempts":2}]
        """
        plain.setData(Data(legacy.utf8), forKey: "sendora_event_queue")

        let q = EventQueue(storage: storage, flushAt: 1000)
        let restored = q.snapshot
        XCTAssertEqual(restored.map { $0["eventType"] as? String }, ["old.one", "old.two"])
        XCTAssertNil(restored[0]["userId"], "a missing userId must decode as absent")
        XCTAssertEqual(restored[1]["anonymousId"] as? String, "dev-1")
        XCTAssertEqual((restored[1][EventQueue.attemptsKey] as? NSNumber)?.intValue, 2)
        // And it decorates as before: no userId, no token.
        XCTAssertNil(SendoraCloud.decorateForSend(restored[0], currentUserId: "user-42", identityToken: "tok")["identityToken"])
    }
}
