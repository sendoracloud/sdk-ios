import Foundation
import XCTest
@testable import SendoraCloud

// ADR-033 wave 1 — the behavioural test harness for the auth machine.
//
// Three doubles, each RECORDING: an in-memory Keychain (every set/delete, in
// order), an in-memory UserDefaults, and a scripted HTTP transport (every
// request with method / path / body / headers, plus per-path GATES that hold a
// response until the test releases it — the "refresh rotates during the native
// sheet" interleaving). Nothing here reads the SDK's source text; every
// assertion in the suites is about state, events and writes.

// MARK: - Storage doubles

final class RecordingSecureStore: SendoraSecureStore {
    struct Write: Equatable { let op: String; let key: String; let value: String? }
    private let lock = NSLock()
    private var values: [String: String] = [:]
    private(set) var writes: [Write] = []

    func get(_ key: String) -> String? { lock.lock(); defer { lock.unlock() }; return values[key] }
    func set(_ key: String, _ value: String) {
        lock.lock(); defer { lock.unlock() }
        values[key] = value
        writes.append(Write(op: "set", key: key, value: value))
    }
    func delete(_ key: String) {
        lock.lock(); defer { lock.unlock() }
        values.removeValue(forKey: key)
        writes.append(Write(op: "delete", key: key, value: nil))
    }
    /// Seed without recording (the disk BEFORE boot).
    func seed(_ key: String, _ value: String) { lock.lock(); values[key] = value; lock.unlock() }
    func snapshot() -> [String: String] { lock.lock(); defer { lock.unlock() }; return values }
    func writesSince(_ mark: Int) -> [Write] { lock.lock(); defer { lock.unlock() }; return Array(writes.dropFirst(mark)) }
    var writeCount: Int { lock.lock(); defer { lock.unlock() }; return writes.count }
}

final class RecordingPlainStore: SendoraPlainStore {
    private let lock = NSLock()
    private var strings: [String: String] = [:]
    private var datas: [String: Data] = [:]
    private var bools: [String: Bool] = [:]
    private(set) var writes: [String] = []

    func string(forKey key: String) -> String? { lock.lock(); defer { lock.unlock() }; return strings[key] }
    func setString(_ value: String, forKey key: String) { lock.lock(); strings[key] = value; writes.append("set \(key)"); lock.unlock() }
    func data(forKey key: String) -> Data? { lock.lock(); defer { lock.unlock() }; return datas[key] }
    func setData(_ value: Data, forKey key: String) { lock.lock(); datas[key] = value; writes.append("set \(key)"); lock.unlock() }
    func bool(forKey key: String) -> Bool { lock.lock(); defer { lock.unlock() }; return bools[key] ?? false }
    func setBool(_ value: Bool, forKey key: String) { lock.lock(); bools[key] = value; writes.append("set \(key)"); lock.unlock() }
    func hasValue(forKey key: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return strings[key] != nil || datas[key] != nil || bools[key] != nil
    }
    func remove(forKey key: String) {
        lock.lock()
        strings.removeValue(forKey: key); datas.removeValue(forKey: key); bools.removeValue(forKey: key)
        writes.append("remove \(key)")
        lock.unlock()
    }
    func seedString(_ key: String, _ value: String) { lock.lock(); strings[key] = value; lock.unlock() }
    func snapshot() -> [String: String] { lock.lock(); defer { lock.unlock() }; return strings }
    var writeCount: Int { lock.lock(); defer { lock.unlock() }; return writes.count }
}

// MARK: - Transport double

struct StubResponse {
    let status: Int
    let json: [String: Any]?
    /// 5.6.0: extra response headers (`Retry-After`, `cf-mitigated`) and a non-JSON body (a Cloudflare page).
    var headers: [String: String] = [:]
    var rawBody: Data? = nil

    func with(headers: [String: String]) -> StubResponse { var c = self; c.headers = headers; return c }

    static func ok(_ data: [String: Any], status: Int = 200) -> StubResponse {
        return StubResponse(status: status, json: ["success": true, "data": data])
    }
    static func failure(status: Int, code: String, message: String = "refused", details: [String: Any]? = nil) -> StubResponse {
        var error: [String: Any] = ["code": code, "message": message]
        if let details = details { error["details"] = details }
        return StubResponse(status: status, json: ["success": false, "error": error])
    }
    /// A transport failure (offline): no HTTP response at all.
    static let offline = StubResponse(status: 0, json: nil)
}

final class StubTransport: SendoraHTTPTransport {
    struct Recorded {
        let method: String
        let path: String
        let body: [String: Any]?
        let headers: [String: String]
    }

    private let lock = NSLock()
    private(set) var requests: [Recorded] = []
    private var handlers: [String: (Recorded) -> StubResponse] = [:]
    private var gates: [String: DispatchSemaphore] = [:]
    /// Called synchronously on every request (BEFORE the gate) — lets a test
    /// react to "the request went out".
    var onRequest: ((Recorded) -> Void)?

    func perform(_ request: URLRequest, completion: @escaping (Data?, HTTPURLResponse?, Error?) -> Void) {
        let rawPath = request.url?.path ?? ""
        let path = rawPath.hasPrefix("/api/v1") ? String(rawPath.dropFirst("/api/v1".count)) : rawPath
        let body = request.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        let rec = Recorded(method: request.httpMethod ?? "GET", path: path, body: body, headers: request.allHTTPHeaderFields ?? [:])
        lock.lock()
        requests.append(rec)
        let handler = handlers["\(rec.method) \(path)"]
        let gate = gates[path]
        lock.unlock()
        onRequest?(rec)
        DispatchQueue.global().async {
            if let gate = gate {
                gate.wait()
                // One-shot: the next request to this path is not held.
                self.lock.lock(); if self.gates[path] === gate { self.gates.removeValue(forKey: path) }; self.lock.unlock()
            }
            let response = handler?(rec) ?? StubResponse.failure(status: 599, code: "UNSTUBBED", message: "no stub for \(rec.method) \(path)")
            if response.status == 0 {
                completion(nil, nil, URLError(.notConnectedToInternet))
                return
            }
            let data = response.rawBody ?? response.json.flatMap { try? JSONSerialization.data(withJSONObject: $0) }
            let headers = ["Content-Type": "application/json"].merging(response.headers) { _, new in new }
            let http = HTTPURLResponse(url: request.url!, statusCode: response.status, httpVersion: nil, headerFields: headers)
            completion(data, http, nil)
        }
    }

    func stub(_ method: String, _ path: String, _ handler: @escaping (Recorded) -> StubResponse) {
        lock.lock(); handlers["\(method) \(path)"] = handler; lock.unlock()
    }
    func stub(_ method: String, _ path: String, _ response: StubResponse) {
        stub(method, path) { _ in response }
    }
    /// Hold every response for `path` until the returned semaphore is signalled.
    func gate(_ path: String) -> DispatchSemaphore {
        let sem = DispatchSemaphore(value: 0)
        lock.lock(); gates[path] = sem; lock.unlock()
        return sem
    }
    func requests(to path: String) -> [Recorded] {
        lock.lock(); defer { lock.unlock() }
        return requests.filter { $0.path == path }
    }
    func lastRequest(to path: String) -> Recorded? { requests(to: path).last }
    var requestCount: Int { lock.lock(); defer { lock.unlock() }; return requests.count }
}

// MARK: - JWTs (the SDK needs only a decoder; the test needs an encoder)

enum TestJWT {
    static let projectA = "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b"
    static let projectB = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9"

    static func base64url(_ data: Data) -> String {
        return data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    /// `project`: `.some(nil)` = explicit null, `.some("…")` = string, `nil` = ABSENT key.
    static func make(sub: String = "11111111-1111-4111-8111-111111111111",
                     sid: String = "sid-1",
                     isAnonymous: Bool = true,
                     project: String?? = .some(projectA),
                     exp: Int = 4_000_000_000) -> String {
        var claims: [String: Any] = ["sub": sub, "sid": sid, "is_anonymous": isAnonymous, "iat": 1_760_000_000, "exp": exp]
        if let p = project { claims["project"] = p.map { $0 as Any } ?? NSNull() }
        // `.sortedKeys`: the same claims must make the same bytes. Unsorted, the header came out as
        // {"typ","alg"} on some iOS-Simulator runs and a test comparing two minted tokens flaked (5.7.0).
        let header = base64url(try! JSONSerialization.data(withJSONObject: ["alg": "RS256", "typ": "JWT"], options: [.sortedKeys]))
        let payload = base64url(try! JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys]))
        return "\(header).\(payload).c2ln"
    }
}

// MARK: - Response builders

enum Stub {
    static func user(id: String, isAnonymous: Bool, email: String? = nil, project: String? = TestJWT.projectA, name: String? = nil) -> [String: Any] {
        var u: [String: Any] = ["id": id, "emailVerified": false, "isAnonymous": isAnonymous]
        u["email"] = email.map { $0 as Any } ?? NSNull()
        u["name"] = name.map { $0 as Any } ?? NSNull()
        u["project"] = project.map { $0 as Any } ?? NSNull()
        return u
    }
    /// The wire shape of an existing user struct (so a refresh echoes the SAME user).
    static func user(from u: SendoraCloudAuthUser) -> [String: Any] {
        var d: [String: Any] = ["id": u.id, "emailVerified": u.emailVerified, "isAnonymous": u.isAnonymous]
        d["email"] = u.email.map { $0 as Any } ?? NSNull()
        d["name"] = u.name.map { $0 as Any } ?? NSNull()
        d["project"] = u.project.map { $0 as Any } ?? NSNull()
        if let s = u.signupMethod { d["signupMethod"] = s }
        if let l = u.lastLoginMethod { d["lastLoginMethod"] = l }
        return d
    }
    static func tokens(access: String, refresh: String, expiresIn: Int = 900) -> [String: Any] {
        return ["accessToken": access, "refreshToken": refresh, "expiresIn": expiresIn, "tokenType": "Bearer"]
    }
    /// `{ user, tokens, csrfToken }` — the sign-in / mint / signup / refresh shape.
    static func session(user: [String: Any], tokens: [String: Any], extra: [String: Any] = [:], status: Int = 200) -> StubResponse {
        var data: [String: Any] = ["user": user, "tokens": tokens, "csrfToken": "csrf"]
        for (k, v) in extra { data[k] = v }
        return .ok(data, status: status)
    }
    static func refreshDead(endReason: String?) -> StubResponse {
        var details: [String: Any] = ["retryAfterSeconds": 60]
        if let r = endReason { details["endReason"] = r }
        return .failure(status: 401, code: "INVALID_REFRESH_TOKEN", message: "Refresh token invalid or expired — re-authenticate", details: details)
    }
    static func credentialInUse(provider: String, collision: String) -> StubResponse {
        return .failure(status: 409, code: "CREDENTIAL_IN_USE", message: "already linked elsewhere", details: ["provider": provider, "collision": collision])
    }
    static let recentAuthRequired = StubResponse.failure(status: 403, code: "RECENT_AUTH_REQUIRED", message: "re-authenticate", details: ["maxAgeSeconds": 300])
    static let rateLimited = StubResponse.failure(status: 429, code: "RATE_LIMIT_EXCEEDED", message: "slow down", details: ["retryAfterSeconds": 5])
    static let serverError = StubResponse.failure(status: 503, code: "SERVICE_UNAVAILABLE", message: "down")
}

// MARK: - The harness

final class AuthHarness {
    let secure = RecordingSecureStore()
    let plain = RecordingPlainStore()
    let transport = StubTransport()
    private(set) var storage: SendoraStorage!
    private(set) var client: APIClient!
    private(set) var auth: SendoraCloudAuth!

    private let eventLock = NSLock()
    private var recordedEvents: [SendoraCloudAuthStateChange] = []
    /// How many events the subscribe-time replay delivered (`initial` + the legacy `signed_in`).
    private var replayCount = 0
    private(set) var identityChanges: [String?] = []
    private(set) var clearEffects: [SendoraCloudAuth.ClearEffects] = []
    private(set) var withheldHookCalls = 0

    var expectedProjectId: String?
    var configProjectId: String?
    var autoRestoreHeldGuest = true
    /// A frozen clock (epoch ms) for the machine; `nil` = wall clock.
    var clock: (() -> Int64)?

    static let frozenAuthKeys = ["sendora_auth_access_token", "sendora_auth_access_expires", "sendora_auth_refresh_token", "sendora_auth_user"]

    init(expectedProjectId: String? = nil, configProjectId: String? = nil, autoRestoreHeldGuest: Bool = true) {
        self.expectedProjectId = expectedProjectId
        self.configProjectId = configProjectId
        self.autoRestoreHeldGuest = autoRestoreHeldGuest
        // Fire-and-forget endpoints every row may hit.
        transport.stub("POST", "/auth-service/token/revoke", .ok([:]))
        transport.stub("POST", "/auth-service/guest/held", .ok(["reported": true]))
    }

    // MARK: Seeding (BEFORE boot — the disk a previous process left)

    /// A 5.4.0 session: the four frozen keys + the `sendora_auth_session` record.
    func seedSession(user: SendoraCloudAuthUser, access: String, refresh: String, expiresAt: Int64 = Int64(Date().timeIntervalSince1970 * 1000) + 900_000, withRecord: Bool = true) {
        secure.seed("sendora_auth_access_token", access)
        secure.seed("sendora_auth_refresh_token", refresh)
        secure.seed("sendora_auth_access_expires", String(expiresAt))
        secure.seed("sendora_auth_user", SendoraCloudAuth.encodeUser(user)!)
        if withRecord {
            let record = AuthSessionRecord(user: user, accessToken: access, refreshToken: refresh, accessExpiresAt: expiresAt,
                                           sid: jwtStringClaim(access, "sid"), heldReportPending: [])
            secure.seed(SendoraStorage.authSessionKey, SendoraCloudAuth.encodeSessionRecord(record)!)
            plain.seedString("sendora_schema_version", "2")
        } else {
            plain.seedString("sendora_schema_version", "1")
        }
    }

    /// LIMBO_A: a refresh token with no readable user blob.
    func seedLimbo(refresh: String, access: String? = nil, corruptUserBlob: Bool = true) {
        secure.seed("sendora_auth_refresh_token", refresh)
        if let access = access { secure.seed("sendora_auth_access_token", access) }
        if corruptUserBlob { secure.seed("sendora_auth_user", "{not json") }
    }

    /// LIMBO_B: a user blob with no refresh token.
    func seedStaleBlob(user: SendoraCloudAuthUser) {
        secure.seed("sendora_auth_user", SendoraCloudAuth.encodeUser(user)!)
        secure.seed("sendora_auth_access_token", TestJWT.make(sub: user.id, isAnonymous: user.isAnonymous))
    }

    func seedSlot(_ index: Int, _ slot: HeldSlotRecord) {
        secure.seed(SendoraStorage.heldSlotKeys[index], slot.encodeJson()!)
    }

    func seedRawSlot(_ index: Int, _ json: String) {
        secure.seed(SendoraStorage.heldSlotKeys[index], json)
    }

    // MARK: Boot

    func boot() {
        // A re-boot (seed → boot again) starts a fresh recording: a new process.
        eventLock.lock()
        recordedEvents.removeAll(); identityChanges.removeAll(); clearEffects.removeAll(); withheldHookCalls = 0
        eventLock.unlock()
        storage = SendoraStorage(secure: secure, plain: plain)
        client = APIClient(baseUrl: "https://stub.sendora.test", apiKey: "pk_test_000000000000000000", transport: transport)
        let config = SendoraCloudAuth.MachineConfig(expectedProjectId: expectedProjectId, configProjectId: configProjectId,
                                                    autoRestoreHeldGuest: autoRestoreHeldGuest, schedulesTimers: false,
                                                    clock: clock)
        auth = SendoraCloudAuth(
            client: client,
            storage: storage,
            config: config,
            onIdentityChange: { [weak self] id in self?.record { self?.identityChanges.append(id) } },
            onIdentityCleared: { [weak self] effects in self?.record { self?.clearEffects.append(effects) } },
            onIdentityWithheld: { [weak self] in self?.record { self?.withheldHookCalls += 1 } }
        )
        // Subscribe AFTER construction (the replay is part of what we assert).
        auth.onAuthStateChanged { [weak self] change in self?.record { self?.recordedEvents.append(change) } }
        eventLock.lock(); replayCount = recordedEvents.count; eventLock.unlock()
    }

    private func record(_ body: () -> Void) {
        eventLock.lock(); body(); eventLock.unlock()
    }

    var events: [SendoraCloudAuthStateChange] {
        eventLock.lock(); defer { eventLock.unlock() }
        return recordedEvents
    }
    var eventNames: [String] { events.map { $0.eventName } }
    /// Bounds-checked: a missing event is an assertion failure in the caller
    /// (via the event-name assertions), never an index-out-of-range crash that
    /// would abort every test after it.
    func event(at index: Int) -> SendoraCloudAuthStateChange? {
        let all = events
        return all.indices.contains(index) ? all[index] : nil
    }
    func clearEvents() { eventLock.lock(); recordedEvents.removeAll(); eventLock.unlock() }

    /// Events after the subscribe-time replay (`initial` + the legacy `signed_in`).
    var transitionEventNames: [String] {
        eventLock.lock(); defer { eventLock.unlock() }
        return Array(recordedEvents.dropFirst(replayCount).map { $0.eventName })
    }

    // MARK: Blocking helpers (every public verb is completion-based)

    func wait<T>(timeout: TimeInterval = 5, _ body: (@escaping (T) -> Void) -> Void) -> T {
        let sem = DispatchSemaphore(value: 0)
        var out: T?
        body { value in out = value; sem.signal() }
        if sem.wait(timeout: .now() + timeout) == .timedOut {
            XCTFail("timed out waiting for a completion")
        }
        return out!
    }

    func waitVoid(timeout: TimeInterval = 5, _ body: (@escaping () -> Void) -> Void) {
        let sem = DispatchSemaphore(value: 0)
        body { sem.signal() }
        if sem.wait(timeout: .now() + timeout) == .timedOut {
            XCTFail("timed out waiting for a completion")
        }
    }

    func mint(forceNew: Bool = false) -> Result<SendoraCloudAuthUser, SendoraCloudAuthError> {
        return wait { done in auth.signInAnonymously(forceNew: forceNew, completion: done) }
    }

    func signIn(email: String = "p@example.com", password: String = "pw") -> Result<SendoraCloudAuthUser, SendoraCloudAuthError> {
        return wait { done in auth.signIn(email: email, password: password, completion: done) }
    }

    func getAccessToken(forceRefresh: Bool = false) -> String? {
        return wait { done in auth.getAccessToken(forceRefresh: forceRefresh, completion: done) }
    }

    // MARK: Disk assertions

    var secureSnapshot: [String: String] { secure.snapshot() }
    func heldSlotJson(_ i: Int) -> String? { secure.get(SendoraStorage.heldSlotKeys[i]) }
    func heldSlot(_ i: Int) -> HeldSlotRecord? { heldSlotJson(i).flatMap { HeldSlotRecord.decode($0) } }
    var storedRefresh: String? { secure.get("sendora_auth_refresh_token") }
    var storedAccess: String? { secure.get("sendora_auth_access_token") }
    var storedUserJson: String? { secure.get("sendora_auth_user") }
    var storedSessionRecord: AuthSessionRecord? { secure.get(SendoraStorage.authSessionKey).flatMap { SendoraCloudAuth.decodeSessionRecord($0) } }

    /// Every Keychain key written since `mark` is one the SDK declares (the
    /// closed `secureKeys` allow-list) — a dynamically built held-slot name is
    /// not, and fails here.
    func assertSecureWritesWithinAllowList(since mark: Int, file: StaticString = #filePath, line: UInt = #line) {
        for w in secure.writesSince(mark) where !SendoraStorage.secureKeys.contains(w.key) {
            XCTFail("Keychain write to an undeclared key: \(w.op) \(w.key)", file: file, line: line)
        }
    }

    static func anonymousUser(_ id: String = "11111111-1111-4111-8111-111111111111") -> SendoraCloudAuthUser {
        return SendoraCloudAuthUser(id: id, email: nil, emailVerified: false, name: nil, isAnonymous: true, signupMethod: "anonymous", lastLoginMethod: "anonymous", project: TestJWT.projectA)
    }

    static func identifiedUser(_ id: String = "22222222-2222-4222-8222-222222222222", email: String = "p@example.com") -> SendoraCloudAuthUser {
        return SendoraCloudAuthUser(id: id, email: email, emailVerified: true, name: "Priya", isAnonymous: false, signupMethod: "password", lastLoginMethod: "password", project: TestJWT.projectA)
    }

    static func slot(userId: String, refresh: String, heldAt: Int64, project: String? = TestJWT.projectA, autoRestore: Bool = true, sid: String = "sid-held") -> HeldSlotRecord {
        return HeldSlotRecord(userId: userId, sid: sid, refreshToken: refresh, tokenAtHold: refresh, heldAt: heldAt, project: project, autoRestore: autoRestore)
    }
}
