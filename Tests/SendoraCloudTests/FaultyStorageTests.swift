import Foundation
import XCTest
@testable import SendoraCloud

// Durability step 1 (s58.415) — the faulty-storage scenarios FS1–FS6.
// Spec: docs/audit/sdk-auth-s58.415/faulty-storage-scenarios.md. Audit: AUDIT-s58.415-sdk-auth-tokens.md A–D,
// sdk-auth-s58.415/ios.md H1 / H2 / H3.
//
// THE INVARIANT every scenario asserts: a storage fault never costs the device its account. After the fault and a
// cold start over the same durable storage, the account's credential (the refresh token the SERVER considers live, or
// its predecessor inside the 60 s grace) is still reachable, and the SDK never reports `signed_out` / mints a new guest
// over it.
//
// STEP 2 (ADR-033 rev 3 §3.8, s58.415): every scenario is now FIXED on iOS and runs PLAIN — no XCTExpectFailure
// left. FS1 and FS2 assert the CORRECTED spec (faulty-storage-scenarios.md): the device holds R2, or R1 with the
// INV-16 marker and refreshes at once — relaunched INSIDE the 60 s grace the server's replay recovers the session;
// relaunched PAST it (FS2) the guest is QUARANTINED, never dropped (no SDK can recover a spent R1 past the grace —
// that is ADR-036, server-side). Each scenario still runs a plain CONTROL with the fault switched off.
//
// WHAT THE DOUBLE MODELS — the NEW real `KeychainSecureStore` (rev 3), not the 5.9.0 one step 1 modelled:
//  - `read` returns `.unavailable(-25308)` for a failing read (`lockDevice()` = before first unlock; `failReads(of:)`
//    = a per-item error) and `.absent` ONLY when the item is not there. `get` = `read`'s value (the legacy surface).
//  - `write` is SecItemUpdate-in-place (add only when absent): a write that fails leaves the OLD value on disk and
//    returns `false` (known to the SDK). The step-1 `.addRefused` fault ("delete landed, add failed → key GONE")
//    cannot happen any more — there is no delete before the add — so `.addRefused` and `.locked` now leave the same
//    disk (the old value); both are still run because they fail different SETS of writes (one key vs every key).
//  - `killOnWrite(where:)` — the process dies while that write is in flight: it never lands (Keychain calls are
//    durable once they return, so "accepted but not durable" = "never returned"), and every later write of that
//    process is dropped. `processRestarted()` then a fresh `boot()` = the cold start.
//  - `corrupt(_:)` — unparseable bytes in a held slot.
// The UserDefaults tier (RecordingPlainStore) is never faulted here. Since step-2 review T15 the INV-16 marker is a
// Keychain item (this double), so a `.locked` fault starts AFTER the refresh request went out.
//
// THE FAKE SERVER (`FakeAuthServer`, its own manual clock, independent of the SDK's): rotation R1 → R2 revokes R1;
// R1 again within 60 s → the same pair (grace replay); after 60 s → 401 INVALID_REFRESH_TOKEN, details.endReason
// "reuse". `/anonymous` mints a new guest (counted), `/login` signs an identified account in.
//
// Seams: `graceRetryScale` 0.01 (the shared 2/5/15/35 s schedule runs at 20/50/150/350 ms) and a 300 ms INV-17
// queue window, so the suite stays fast while the SCHEDULE is the production one.
//
// N/A on iOS: none of FS1–FS6. Notes per id:
//  - FS1 has two faults on iOS (the refresh key's write refused; every write locked); both run, each both ways:
//    the process LIVES ON (the pending commit is re-written on the next token request) and a relaunch INSIDE the grace.
//  - FS2's only iOS form is the kill while the refresh key's write is in flight (no async write queue exists).
//  - FS4: an UNPARSEABLE slot and a slot READ ERROR are both reserved (`unreadableSlots`).

// MARK: - The faulty Keychain double

final class FaultySecureStore: SendoraSecureStore {
    enum WriteFailure { case addRefused, locked }

    private let lock = NSLock()
    private var durable: [String: String] = [:]
    private var readsFailAll = false
    private var writesLocked = false
    private var unreadableKeys: Set<String> = []
    private var writeFault: (match: (String, String) -> Bool, failure: WriteFailure)?
    private var killFault: ((String, String) -> Bool)?
    private var killed = false
    private(set) var firedFaults: [String] = []

    // MARK: SendoraSecureStore (the rev-3 KeychainSecureStore semantics)

    func read(_ key: String) -> SendoraSecureRead {
        lock.lock(); defer { lock.unlock() }
        if readsFailAll || unreadableKeys.contains(key) { return .unavailable(-25308) } // never "absent"
        return durable[key].map { .value($0) } ?? .absent
    }

    func get(_ key: String) -> String? { read(key).valueOrNil }

    func write(_ key: String, _ value: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if killed { return false }                                   // the process is gone: nothing reaches disk
        if writesLocked { firedFaults.append("locked set \(key)"); return false } // update refused → old value stays
        if let kill = killFault, kill(key, value) {
            killed = true; killFault = nil                           // died with this write in flight: never landed
            firedFaults.append("kill at set \(key)")
            return false
        }
        if let fault = writeFault, fault.match(key, value) {
            writeFault = nil                                         // SecItemUpdate in place failed → old value stays
            firedFaults.append("\(fault.failure) set \(key)")
            return false
        }
        durable[key] = value
        return true
    }

    func set(_ key: String, _ value: String) { _ = write(key, value) }

    func remove(_ key: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if killed || writesLocked { return false }
        durable.removeValue(forKey: key)
        return true
    }

    func delete(_ key: String) { _ = remove(key) }

    func addIfAbsent(_ key: String, _ value: String) -> SendoraSecureAddResult {
        lock.lock(); defer { lock.unlock() }
        if killed || writesLocked { return .failed(-25308) }
        if durable[key] != nil { return .duplicate }
        durable[key] = value
        return .added
    }

    // MARK: Fault controls

    func lockDevice() { lock.lock(); readsFailAll = true; writesLocked = true; lock.unlock() }
    /// (T2) What `isProtectedDataAvailable` would say: `false` between `lockDevice()` and `unlockDevice()`.
    var deviceUnlocked: Bool { lock.lock(); defer { lock.unlock() }; return !readsFailAll }
    func unlockDevice() { lock.lock(); readsFailAll = false; writesLocked = false; lock.unlock() }
    func failReads(of keys: Set<String>) { lock.lock(); unreadableKeys = keys; lock.unlock() }
    func failNextWrite(_ failure: WriteFailure, where match: @escaping (String, String) -> Bool) {
        lock.lock(); writeFault = (match, failure); lock.unlock()
    }
    func failAllWrites(_ on: Bool) { lock.lock(); writesLocked = on; lock.unlock() }
    func killOnWrite(where match: @escaping (String, String) -> Bool) { lock.lock(); killFault = match; lock.unlock() }
    /// A new process over the same durable bytes.
    func processRestarted() { lock.lock(); killed = false; killFault = nil; writeFault = nil; lock.unlock() }

    // MARK: Disk access for the test (bypasses every fault)

    func seed(_ key: String, _ value: String) { lock.lock(); durable[key] = value; lock.unlock() }
    func corrupt(_ key: String) { seed(key, "{corrupt") }
    func raw(_ key: String) -> String? { lock.lock(); defer { lock.unlock() }; return durable[key] }
    func anyValueContains(_ token: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return durable.values.contains { $0 == token || $0.contains("\"\(token)\"") }
    }
    func quarantineHolds(_ token: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return durable.contains { $0.key.hasPrefix("sendora_auth_quarantine_") && $0.value.contains("\"\(token)\"") }
    }
}

// MARK: - The fake server

final class FakeAuthServer {
    static let graceMs: Int64 = 60_000

    private let lock = NSLock()
    private var clockMs: Int64 = 1_760_000_000_000
    private var owner: [String: SendoraCloudAuthUser] = [:]
    private var live: Set<String> = []
    private var rotations: [String: (successor: String, access: String, at: Int64)] = [:]
    private var counter = 0
    private var mintCount = 0
    private var loseNext = false
    var loginUser: SendoraCloudAuthUser?

    var mints: Int { lock.lock(); defer { lock.unlock() }; return mintCount }
    func advance(seconds: Int64) { lock.lock(); clockMs += seconds * 1000; lock.unlock() }
    /// The next `/token/refresh` is COMMITTED server-side, then its response is lost (transport failure).
    func loseNextRefreshResponse() { lock.lock(); loseNext = true; lock.unlock() }

    func register(refresh: String, for user: SendoraCloudAuthUser) {
        lock.lock(); owner[refresh] = user; live.insert(refresh); lock.unlock()
    }

    /// Server-side rotation (also used to model a rotation whose response the device never saw).
    @discardableResult
    func rotate(_ token: String) -> (access: String, refresh: String)? {
        lock.lock(); defer { lock.unlock() }
        return rotateLocked(token)
    }

    private func rotateLocked(_ token: String) -> (access: String, refresh: String)? {
        guard live.contains(token), let user = owner[token] else { return nil }
        counter += 1
        let successor = "rt-\(user.id.prefix(4))-\(counter)"
        let access = Self.access(for: user, n: counter)
        live.remove(token)
        live.insert(successor)
        owner[successor] = user
        rotations[token] = (successor, access, clockMs)
        return (access, successor)
    }

    func isLive(_ token: String) -> Bool { lock.lock(); defer { lock.unlock() }; return live.contains(token) }

    /// Live, or a predecessor still inside the grace window (a replay would recover the pair).
    func isRecoverable(_ token: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if live.contains(token) { return true }
        if let r = rotations[token] { return clockMs - r.at <= Self.graceMs }
        return false
    }

    func recoverableTokens(of userId: String) -> [String] {
        lock.lock(); let all = owner.filter { $0.value.id == userId }.map { $0.key }; lock.unlock()
        return all.filter { isRecoverable($0) }
    }

    static func access(for user: SendoraCloudAuthUser, n: Int) -> String {
        TestJWT.make(sub: user.id, sid: "sid-\(user.id.prefix(4))-\(n)", isAnonymous: user.isAnonymous)
    }

    func install(on transport: StubTransport) {
        transport.stub("POST", "/auth-service/token/refresh") { [unowned self] req in self.handleRefresh(req) }
        transport.stub("POST", "/auth-service/anonymous") { [unowned self] _ in
            self.lock.lock()
            self.mintCount += 1
            let n = self.mintCount
            self.lock.unlock()
            let user = AuthHarness.anonymousUser(String(format: "f0000000-0000-4000-8000-%012d", n))
            let refresh = "rt-mint-\(n)"
            self.register(refresh: refresh, for: user)
            return Stub.session(user: Stub.user(from: user),
                                tokens: Stub.tokens(access: Self.access(for: user, n: 0), refresh: refresh), status: 201)
        }
        transport.stub("POST", "/auth-service/login") { [unowned self] _ in
            guard let user = self.loginUser else { return .failure(status: 401, code: "INVALID_CREDENTIALS") }
            self.lock.lock(); self.counter += 1; let n = self.counter; self.lock.unlock()
            let refresh = "rt-login-\(n)"
            self.register(refresh: refresh, for: user)
            return Stub.session(user: Stub.user(from: user), tokens: Stub.tokens(access: Self.access(for: user, n: n), refresh: refresh))
        }
    }

    private func handleRefresh(_ req: StubTransport.Recorded) -> StubResponse {
        lock.lock(); defer { lock.unlock() }
        guard let sent = req.body?["refreshToken"] as? String, let user = owner[sent] else {
            return Stub.refreshDead(endReason: "revoked")
        }
        let response: StubResponse
        if let pair = rotateLocked(sent) {
            response = Stub.session(user: Stub.user(from: user), tokens: Stub.tokens(access: pair.access, refresh: pair.refresh))
        } else if let r = rotations[sent] {
            response = clockMs - r.at <= Self.graceMs
                ? Stub.session(user: Stub.user(from: user), tokens: Stub.tokens(access: r.access, refresh: r.successor))
                : Stub.refreshDead(endReason: "reuse")
        } else {
            response = Stub.refreshDead(endReason: "revoked")
        }
        if loseNext { loseNext = false; return .offline } // committed above; the answer never arrives
        return response
    }
}

// MARK: - Harness over the faulty store (same seam / transport / config as AuthHarness)

final class FaultyHarness {
    let store = FaultySecureStore()
    let plain = RecordingPlainStore()
    let transport = StubTransport()
    let server = FakeAuthServer()
    private(set) var auth: SendoraCloudAuth!
    private(set) var processes = 0
    private let eventLock = NSLock()
    private var recorded: [SendoraCloudAuthStateChange] = []
    var autoRestoreHeldGuest: Bool

    static let refreshKey = "sendora_auth_refresh_token"

    init(autoRestoreHeldGuest: Bool = true) {
        self.autoRestoreHeldGuest = autoRestoreHeldGuest
        transport.stub("POST", "/auth-service/token/revoke", .ok([:]))
        transport.stub("POST", "/auth-service/guest/held", .ok(["reported": true]))
        server.install(on: transport)
    }

    /// A 5.4.0+ session on disk (the four frozen keys + the record), live on the server.
    func seedSession(user: SendoraCloudAuthUser, refresh: String) {
        let access = FakeAuthServer.access(for: user, n: 0)
        let expiresAt = Int64(Date().timeIntervalSince1970 * 1000) + 900_000
        store.seed("sendora_auth_access_token", access)
        store.seed(Self.refreshKey, refresh)
        store.seed("sendora_auth_access_expires", String(expiresAt))
        store.seed("sendora_auth_user", SendoraCloudAuth.encodeUser(user)!)
        let record = AuthSessionRecord(user: user, accessToken: access, refreshToken: refresh, accessExpiresAt: expiresAt,
                                       sid: jwtStringClaim(access, "sid"), heldReportPending: [])
        store.seed(SendoraStorage.authSessionKey, SendoraCloudAuth.encodeSessionRecord(record)!)
        plain.seedString("sendora_schema_version", "2")
        server.register(refresh: refresh, for: user)
    }

    func seedHeldSlot(_ index: Int, user: SendoraCloudAuthUser, refresh: String) {
        let slot = AuthHarness.slot(userId: user.id, refresh: refresh, heldAt: 1_000)
        store.seed(SendoraStorage.heldSlotKeys[index], slot.encodeJson()!)
        server.register(refresh: refresh, for: user)
    }

    /// One process: a fresh storage / client / machine over the same durable bytes.
    func boot() {
        processes += 1
        eventLock.lock(); recorded.removeAll(); eventLock.unlock()
        let storage = SendoraStorage(secure: store, plain: plain)
        let client = APIClient(baseUrl: "https://stub.sendora.test", apiKey: "pk_test_000000000000000000", transport: transport)
        client.jitter = { _ in 0 } // a transport failure must not hold the breaker over the next attempt
        let config = SendoraCloudAuth.MachineConfig(expectedProjectId: nil, configProjectId: nil,
                                                    autoRestoreHeldGuest: autoRestoreHeldGuest, schedulesTimers: false, clock: nil,
                                                    graceRetryScale: 0.01, storageUnavailableQueueMs: 300,
                                                    deviceUnlocked: { [store] in store.deviceUnlocked })
        auth = SendoraCloudAuth(client: client, storage: storage, config: config,
                                onIdentityChange: { _ in }, onIdentityCleared: { _ in }, onIdentityWithheld: {})
        auth.onAuthStateChanged { [weak self] change in
            guard let self = self else { return }
            self.eventLock.lock(); self.recorded.append(change); self.eventLock.unlock()
        }
    }

    /// Process death + relaunch over the same Keychain.
    func coldStart() {
        store.processRestarted()
        boot()
    }

    var events: [SendoraCloudAuthStateChange] { eventLock.lock(); defer { eventLock.unlock() }; return recorded }
    var eventNames: [String] { events.map { $0.eventName } }

    private func wait<T>(_ timeout: TimeInterval = 5, _ body: (@escaping (T) -> Void) -> Void) -> T? {
        let sem = DispatchSemaphore(value: 0)
        let box = NSLock()
        var out: T?
        body { v in box.lock(); out = v; box.unlock(); sem.signal() }
        if sem.wait(timeout: .now() + timeout) == .timedOut { XCTFail("timed out waiting for a completion"); return nil }
        box.lock(); defer { box.unlock() }
        return out
    }

    /// The cron / foreground refresh (forced, so the tracked deadline does not short-circuit it).
    @discardableResult
    func refresh() -> String? { wait { done in auth.getAccessToken(forceRefresh: true, completion: done) } ?? nil }

    /// The app's cold-launch `ensureSession()` (RopoLabs pattern).
    @discardableResult
    func ensureSession() -> Result<SendoraCloudAuthUser, SendoraCloudAuthError>? {
        wait { done in auth.signInAnonymously(completion: done) }
    }

    func signIn() -> Result<SendoraCloudAuthUser, SendoraCloudAuthError>? {
        wait { done in auth.signIn(email: "p@example.com", password: "pw", completion: done) }
    }

    func refreshRequests() -> [String] {
        transport.requests(to: "/auth-service/token/refresh").compactMap { $0.body?["refreshToken"] as? String }
    }

    /// The INV-16 marker on disk (Keychain tier since step-2 review T15).
    var marker: String? { store.raw(SendoraStorage.refreshInflightKey) }

    /// Poll (≤ `timeout`) for a background refresh / grace retry to land.
    @discardableResult
    func eventually(timeout: TimeInterval = 3, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            usleep(10_000)
        }
        return condition()
    }
}

// MARK: - The scenarios

final class FaultyStorageTests: XCTestCase {
    private static let guest = AuthHarness.anonymousUser("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    private static let heldGuest = AuthHarness.anonymousUser("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    private static let account = AuthHarness.identifiedUser()
    private static let r1 = "rt-aaaa-r1"
    private static let protectedDataAvailable = Notification.Name("UIApplicationProtectedDataDidBecomeAvailable")

    /// THE INVARIANT, after the fault + cold start + the next refresh + the app's `ensureSession()`.
    private func assertAccountSurvived(_ h: FaultyHarness, _ user: SendoraCloudAuthUser, _ id: String,
                                       file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNotEqual(h.auth.status(), .signedOut, "\(id): the SDK reports signed_out over a live account", file: file, line: line)
        XCTAssertFalse(h.eventNames.contains("signed_out"), "\(id): signed_out fired (\(h.eventNames))", file: file, line: line)
        XCTAssertEqual(h.server.mints, 0, "\(id): a new guest was minted over the account", file: file, line: line)
        XCTAssertEqual(h.auth.currentUser?.id, user.id, "\(id): the account is not the session", file: file, line: line)
        let held = h.auth.getRefreshToken()
        XCTAssertTrue(held.map { h.server.isRecoverable($0) } ?? false,
                      "\(id): the SDK holds \(held ?? "nil"), not a token the server considers live", file: file, line: line)
        XCTAssertTrue(h.server.recoverableTokens(of: user.id).contains { h.store.anyValueContains($0) },
                      "\(id): no live credential of the account is on disk", file: file, line: line)
    }

    // MARK: FS1 — the write of the rotated refresh token fails after the server rotated

    private enum AfterFault { case processLivesOn, relaunchInsideGrace }

    private func runFS1(faulted: Bool, failure: FaultySecureStore.WriteFailure, after: AfterFault) {
        let h = FaultyHarness()
        h.seedSession(user: Self.guest, refresh: Self.r1)
        h.boot()
        XCTAssertEqual(h.auth.status(), .anonymous, "precondition")
        if faulted {
            switch failure {
            case .addRefused:
                // Only the R2 write to the frozen refresh key fails.
                h.store.failNextWrite(.addRefused) { key, value in key == FaultyHarness.refreshKey && value != Self.r1 }
            case .locked:
                // The keychain refuses every write for the whole rotation commit (device locked mid-refresh — i.e.
                // AFTER the request went out: since T15 the marker is a Keychain item written before it, so a lock
                // switched on before the refresh would abort the refresh instead, which is FS1's control, not its fault).
                h.transport.onRequest = { req in if req.path == "/auth-service/token/refresh" { h.store.failAllWrites(true) } }
            }
        }
        let rotated = h.refresh()
        XCTAssertNotNil(rotated, "the server rotated and answered")
        if faulted {
            XCTAssertFalse(h.store.firedFaults.isEmpty, "harness: the fault must actually fire")
            XCTAssertEqual(h.store.raw(FaultyHarness.refreshKey), Self.r1, "harness: the disk still holds R1")
            XCTAssertNotNil(h.marker, "FS1: the INV-16 marker is KEPT while R2's write is unconfirmed")
            XCTAssertNotEqual(h.auth.getRefreshToken(), Self.r1, "FS1: R2 is a pending commit in memory — the session keeps working")
        }
        h.transport.onRequest = nil
        h.store.failAllWrites(false)

        switch after {
        case .processLivesOn:
            // The next token request re-writes the PENDING pair (never a second rotation), then a cold start past the grace.
            let refreshesBefore = h.refreshRequests().count
            XCTAssertNotNil(wait { done in h.auth.getAccessToken(completion: done) } ?? nil)
            XCTAssertEqual(h.refreshRequests().count, refreshesBefore, "FS1: the failed write is repaired by re-writing, never by re-rotating")
            if faulted { XCTAssertNil(h.marker, "FS1: the marker goes once the retried write confirmed") }
            h.coldStart()
            h.server.advance(seconds: 61)
        case .relaunchInsideGrace:
            // The process dies before any retry: the cold start (20 s later) finds R1 + the marker and refreshes AT ONCE.
            h.server.advance(seconds: 20)
            h.coldStart()
            if faulted {
                XCTAssertTrue(h.eventually { h.auth.getRefreshToken() != Self.r1 }, "FS1: the marker makes the relaunch refresh at once; the grace replay hands R2 back")
            }
            h.server.advance(seconds: 61)
        }
        h.refresh()
        h.ensureSession()
        assertAccountSurvived(h, Self.guest, "FS1")
    }

    private func wait<T>(_ body: (@escaping (T) -> Void) -> Void) -> T? {
        let sem = DispatchSemaphore(value: 0)
        let box = NSLock()
        var out: T?
        body { v in box.lock(); out = v; box.unlock(); sem.signal() }
        if sem.wait(timeout: .now() + 5) == .timedOut { XCTFail("timed out"); return nil }
        box.lock(); defer { box.unlock() }
        return out
    }

    func test_FS1_control_rotatedWriteLands() {
        runFS1(faulted: false, failure: .addRefused, after: .processLivesOn)
        runFS1(faulted: false, failure: .addRefused, after: .relaunchInsideGrace)
    }

    func test_FS1_rotatedRefreshWriteRefused_processKeepsRunning() { runFS1(faulted: true, failure: .addRefused, after: .processLivesOn) }
    func test_FS1_rotatedRefreshWriteRefused_relaunchInsideGrace() { runFS1(faulted: true, failure: .addRefused, after: .relaunchInsideGrace) }
    func test_FS1_rotatedWriteLocked_processKeepsRunning() { runFS1(faulted: true, failure: .locked, after: .processLivesOn) }
    func test_FS1_rotatedWriteLocked_relaunchInsideGrace() { runFS1(faulted: true, failure: .locked, after: .relaunchInsideGrace) }

    // MARK: FS2 — the write of R2 never lands: the process is killed with it in flight
    //
    // ⚠ Spec corrected in step 2: the device then holds only R1, which the server already spent. What the SDK owes:
    // (a) relaunched INSIDE the grace, the marker makes it refresh at once and the server's replay hands R2 back —
    // session kept, no mint; (b) relaunched PAST it, the guest is QUARANTINED (its token kept on disk, signed_out
    // {session_expired, endReason reuse}) — never dropped. (The step-1 text asked for (a)'s outcome at 61 s.)

    private func killDuringRotation(faulted: Bool) -> FaultyHarness {
        let h = FaultyHarness()
        h.seedSession(user: Self.guest, refresh: Self.r1)
        h.boot()
        XCTAssertEqual(h.auth.status(), .anonymous, "precondition")
        if faulted { h.store.killOnWrite { key, value in key == FaultyHarness.refreshKey && value != Self.r1 } }
        XCTAssertNotNil(h.refresh(), "the server rotated and answered")
        if faulted {
            XCTAssertEqual(h.store.firedFaults, ["kill at set \(FaultyHarness.refreshKey)"], "harness: the kill fired")
            XCTAssertEqual(h.store.raw(FaultyHarness.refreshKey), Self.r1, "harness: R2 never landed")
            XCTAssertNotNil(h.marker, "the marker written before the request survives the kill")
        }
        return h
    }

    private func runFS2InsideGrace(faulted: Bool) {
        let h = killDuringRotation(faulted: faulted)
        h.server.advance(seconds: 20)
        h.coldStart()
        if faulted { XCTAssertTrue(h.eventually { h.auth.getRefreshToken() != Self.r1 }, "FS2: the marker refreshes at once; the replay restores R2") }
        h.server.advance(seconds: 61)
        h.refresh()
        h.ensureSession()
        assertAccountSurvived(h, Self.guest, "FS2 (inside the grace)")
    }

    func test_FS2_control_noKill() { runFS2InsideGrace(faulted: false) }

    func test_FS2_killedInFlight_relaunchInsideGrace_recovered() { runFS2InsideGrace(faulted: true) }

    func test_FS2_killedInFlight_relaunchPastGrace_quarantinedNeverDropped() {
        let h = killDuringRotation(faulted: true)
        h.server.advance(seconds: 61)
        h.coldStart()
        XCTAssertTrue(h.eventually { h.auth.status() == .signedOut }, "the marker refresh lands on reuse")
        XCTAssertEqual(h.auth.getQuarantinedGuests().map { $0.userId }, [Self.guest.id], "FS2: the guest is QUARANTINED")
        XCTAssertTrue(h.store.quarantineHolds(Self.r1), "FS2: R1 is on disk in a quarantine slot — the device's only handle")
        XCTAssertEqual(h.eventNames.filter { $0 != "initial" && $0 != "signed_in" }, ["guest_quarantined", "signed_out"])
        XCTAssertEqual(h.auth.lastSignedOutEndReason(), .reuse)
        XCTAssertEqual(h.server.mints, 0)
        h.ensureSession()
        XCTAssertEqual(h.server.mints, 1, "a fresh guest — the quarantined one is never auto-restored")
        XCTAssertTrue(h.store.quarantineHolds(Self.r1), "and its slot survives the new session")
    }

    // MARK: FS3 — a read error at hydrate (before first unlock) while the stored session is intact

    private func runFS3(faulted: Bool) {
        let h = FaultyHarness()
        h.seedSession(user: Self.guest, refresh: Self.r1)
        if faulted { h.store.lockDevice() }
        h.boot()
        XCTAssertNotEqual(h.auth.status(), .signedOut, "FS3: an unreadable Keychain is reported as signed_out")
        h.ensureSession() // the app's cold-launch ensureSession() while the read is failing
        XCTAssertEqual(h.server.mints, 0, "FS3: a guest was minted while the Keychain was unreadable")
        XCTAssertEqual(h.store.raw(FaultyHarness.refreshKey), Self.r1, "FS3: the stored token was touched while unreadable")

        h.store.unlockDevice()
        NotificationCenter.default.post(name: Self.protectedDataAvailable, object: nil)
        h.ensureSession()
        h.refresh() // the first write after unlock
        assertAccountSurvived(h, Self.guest, "FS3")
    }

    func test_FS3_control_readable() { runFS3(faulted: false) }

    func test_FS3_readErrorAtHydrate() { runFS3(faulted: true) }

    // MARK: FS4 — a held-guest slot that cannot be read

    private enum SlotFault { case none, readError, unparseable }

    private func runFS4(_ fault: SlotFault) {
        let h = FaultyHarness(autoRestoreHeldGuest: false)
        h.seedSession(user: Self.guest, refresh: Self.r1)
        h.seedHeldSlot(0, user: Self.heldGuest, refresh: "rt-bbbb-held")
        let slot0 = SendoraStorage.heldSlotKeys[0]
        switch fault {
        case .none: break
        case .readError: h.store.failReads(of: [slot0])
        case .unparseable: h.store.corrupt(slot0)
        }
        let slot0Before = h.store.raw(slot0)
        h.boot()
        h.server.loginUser = Self.account
        guard case .success? = h.signIn() else { return XCTFail("sign-in from the guest must succeed") }

        XCTAssertEqual(h.store.raw(slot0), slot0Before, "FS4: the occupied slot 0 was overwritten by the new hold")
        XCTAssertTrue(h.store.anyValueContains(Self.r1), "FS4: the guest that was just held is not on disk")
        let released = h.events.compactMap { e -> String? in if case .guestReleased(let id, _, _) = e { return id }; return nil }
        XCTAssertFalse(released.contains(Self.heldGuest.id), "FS4: the held guest was released")
    }

    func test_FS4_control_readableSlot() { runFS4(.none) }

    /// Plain: an unparseable slot is reserved (`unreadableSlots`).
    func test_FS4_unparseableSlotIsNotTreatedAsFree() { runFS4(.unparseable) }

    func test_FS4_slotReadErrorIsNotTreatedAsFree() { runFS4(.readError) }

    // MARK: FS5 — the refresh response is lost after the server committed the rotation

    private static let selfRetryWindow: TimeInterval = 2

    private func runFS5(faulted: Bool) {
        let h = FaultyHarness()
        h.seedSession(user: Self.guest, refresh: Self.r1)
        h.boot()
        if faulted { h.server.loseNextRefreshResponse() }
        let first = h.refresh()
        XCTAssertEqual(first == nil, faulted, "harness: the response is lost exactly when faulted")
        XCTAssertFalse(h.server.isLive(Self.r1), "harness: the server committed the rotation (R1 revoked)")

        // The server clock is frozen inside the grace: give the SDK a window to retry R1 on its own, and wait for
        // that retry's ANSWER to land (not just its request) before the clock moves past the grace.
        if faulted {
            XCTAssertTrue(h.eventually(timeout: Self.selfRetryWindow) { h.auth.getRefreshToken() != Self.r1 },
                          "FS5: the SDK retried R1 on the grace schedule and holds the replayed pair")
            XCTAssertEqual(Array(h.refreshRequests().prefix(2)), [Self.r1, Self.r1], "FS5: the SAME token, retried")
            XCTAssertNil(h.marker, "the replayed pair confirmed → marker removed")
        }

        h.server.advance(seconds: 61) // the next cron / foreground lands past the grace
        h.refresh()
        assertAccountSurvived(h, Self.guest, "FS5")
    }

    func test_FS5_control_responseArrives() { runFS5(faulted: false) }

    func test_FS5_lostRefreshResponse() { runFS5(faulted: true) }

    // MARK: FS6 — `reuse` on the CURRENT guest session

    private func runFS6(faulted: Bool) {
        let h = FaultyHarness()
        h.seedSession(user: Self.guest, refresh: Self.r1)
        h.server.rotate(Self.r1) // a rotation this device never saw (lost response / lost write)
        h.server.advance(seconds: faulted ? 61 : 30)
        h.boot()
        h.refresh()

        XCTAssertTrue(h.store.anyValueContains(Self.r1) || h.server.recoverableTokens(of: Self.guest.id).contains { h.store.anyValueContains($0) },
                      "FS6: the guest's credential was removed from disk")
        if h.eventNames.contains("signed_out") {
            XCTAssertTrue(h.store.anyValueContains(Self.r1), "FS6: signed_out fired with the guest's credential gone")
        }
        XCTAssertEqual(h.server.mints, 0)
        if !faulted { assertAccountSurvived(h, Self.guest, "FS6 control") }
    }

    func test_FS6_control_replayInsideGrace() { runFS6(faulted: false) }

    func test_FS6_reuseOnCurrentGuest_quarantined() {
        runFS6(faulted: true)
        // …and specifically (decision D): the token sits in a quarantine slot, announced before the signed_out.
        let h = FaultyHarness()
        h.seedSession(user: Self.guest, refresh: Self.r1)
        h.server.rotate(Self.r1)
        h.server.advance(seconds: 61)
        h.boot()
        h.refresh()
        XCTAssertTrue(h.store.quarantineHolds(Self.r1))
        XCTAssertEqual(h.eventNames.filter { $0 != "initial" && $0 != "signed_in" }, ["guest_quarantined", "signed_out"])
    }

    /// Plain: for an IDENTIFIED account clearing on `reuse` is correct (it can re-authenticate). Pins the server model.
    func test_FS6_identifiedReuseClears() {
        let h = FaultyHarness()
        h.seedSession(user: Self.account, refresh: "rt-2222-r1")
        h.server.rotate("rt-2222-r1")
        h.server.advance(seconds: 61)
        h.boot()
        XCTAssertNil(h.refresh())
        XCTAssertEqual(h.auth.status(), .signedOut)
        XCTAssertEqual(h.auth.lastSignedOutEndReason(), .reuse)
        XCTAssertNil(h.store.raw(FaultyHarness.refreshKey))
    }
}
