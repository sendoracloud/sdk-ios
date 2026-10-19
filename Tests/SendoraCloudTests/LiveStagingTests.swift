import XCTest
import CryptoKit
@testable import SendoraCloud

/// 5.6.0 LIVE run against STAGING only (`https://api-dev.sendoracloud.com`). Skipped unless `SENDORA_LIVE=1`, so
/// `swift test` stays offline. The key comes from `SENDORA_PK` (a staging `pk_dev_` key) and is never printed,
/// logged or written: the recorder keeps statuses, counts, sizes and response-header VALUES only, and for
/// request headers / body fields only whether they were present.
///
/// Run: `set -a; . ../../.env.e2e.local; set +a; SENDORA_LIVE=1 swift test --filter LiveStagingTests`
final class LiveStagingTests: XCTestCase {
    static let base = "https://api-dev.sendoracloud.com"

    // MARK: - Recorder (real URLSession underneath)

    struct Rec {
        let method: String
        let path: String
        let bodyBytes: Int
        let eventCount: Int
        let status: Int
        let retryAfter: String?
        let rateLimitPolicy: String?
        let dataCount: Int?
        let errorCode: String?
        let hasBearer: Bool
        let hasKnownDeviceToken: Bool
        let hasRevokeToken: Bool
        let at: Date
    }

    final class LiveTransport: SendoraHTTPTransport {
        private let inner = URLSessionTransport(session: URLSession(configuration: APIClient.makeSessionConfiguration()))
        private let lock = NSLock()
        private(set) var recs: [Rec] = []

        func perform(_ request: URLRequest, completion: @escaping (Data?, HTTPURLResponse?, Error?) -> Void) {
            precondition(request.url?.host == "api-dev.sendoracloud.com", "live test may only reach staging")
            let body = request.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            let rawPath = request.url?.path ?? ""
            let path = rawPath.hasPrefix("/api/v1") ? String(rawPath.dropFirst(7)) : rawPath
            let events = (body?["events"] as? [Any])?.count ?? (path == "/events" ? 1 : 0)
            let bytes = request.httpBody?.count ?? 0
            let bearer = request.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Bearer ") == true
            inner.perform(request) { [weak self] data, http, error in
                let json = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                let rec = Rec(method: request.httpMethod ?? "?", path: path, bodyBytes: bytes, eventCount: events,
                              status: http?.statusCode ?? 0,
                              retryAfter: http?.value(forHTTPHeaderField: "Retry-After"),
                              rateLimitPolicy: http?.value(forHTTPHeaderField: "RateLimit-Policy"),
                              dataCount: ((json?["data"] as? [String: Any])?["count"] as? NSNumber)?.intValue,
                              errorCode: (json?["error"] as? [String: Any])?["code"] as? String,
                              hasBearer: bearer, hasKnownDeviceToken: body?["knownDeviceToken"] != nil,
                              hasRevokeToken: body?["revokeToken"] != nil, at: Date())
                self?.lock.lock(); self?.recs.append(rec); self?.lock.unlock()
                completion(data, http, error)
            }
        }

        func snapshot() -> [Rec] { lock.lock(); defer { lock.unlock() }; return recs }
        func since(_ mark: Int) -> [Rec] { Array(snapshot().dropFirst(mark)) }
        var count: Int { snapshot().count }
    }

    // MARK: - Setup

    private var apiKey = ""
    private var transport: LiveTransport!
    private var client: APIClient!
    private var results: [(String, Bool, String)] = []

    override func setUpWithError() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["SENDORA_LIVE"] == "1", "live staging test: set SENDORA_LIVE=1")
        let key = ProcessInfo.processInfo.environment["SENDORA_PK"] ?? ""
        guard key.hasPrefix("pk_dev_") else {
            throw XCTSkip("SENDORA_PK must be a staging pk_dev_ key (refusing anything else, incl. pk_prod_ / pk_live_)")
        }
        apiKey = key
        transport = LiveTransport()
        client = APIClient(baseUrl: Self.base, apiKey: apiKey, transport: transport)
    }

    private func report(_ name: String, _ ok: Bool, _ evidence: String) {
        results.append((name, ok, evidence))
        print("LIVE \(ok ? "PASS" : "FAIL") \(name) — \(evidence)")
        if !ok { XCTFail("\(name): \(evidence)") }
    }

    private func waitUntil(_ timeout: TimeInterval, poll: TimeInterval = 0.2, _ cond: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline { if cond() { return true }; Thread.sleep(forTimeInterval: poll) }
        return cond()
    }

    private func block<T>(timeout: TimeInterval = 30, _ body: (@escaping (T) -> Void) -> Void) -> T? {
        let sem = DispatchSemaphore(value: 0)
        var out: T?
        body { out = $0; sem.signal() }
        return sem.wait(timeout: .now() + timeout) == .success ? out : nil
    }

    private func event(_ name: String, _ props: [String: Any] = [:]) -> [String: Any] {
        // Exactly what `trackEvent` queues for an app configured with the key only (no projectId).
        SendoraCloud.buildEvent(name: name, properties: props, projectId: nil,
                                device: ["type": "mobile", "os": "iOS", "osVersion": "18.0", "model": "live-test"],
                                sessionId: UUID().uuidString, consentGranted: true, userId: nil,
                                anonymousId: "f67-live-ios-\(UUID().uuidString.prefix(8))", timestamp: Date())
    }

    private func queue() -> EventQueue {
        let q = EventQueue(storage: SendoraStorage(secure: RecordingSecureStore(), plain: RecordingPlainStore()), flushAt: 100_000)
        let c = client!
        q.setFlushHandler { events, done in SendoraCloud.flushEvents(events, client: c, completion: done) }
        return q
    }

    /// Flush until empty (re-flushing through shared-limiter noise), up to `timeout`.
    private func drain(_ q: EventQueue, timeout: TimeInterval = 120) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            q.flush()
            if waitUntil(3, { q.count == 0 }) { return true }
        }
        return q.count == 0
    }

    private func ingestRecs(_ recs: [Rec]) -> [Rec] { recs.filter { $0.path == "/events/batch" || $0.path == "/events" } }

    // MARK: - The run (one method: the scenarios share the ingest lane and must run in this order)

    @MainActor
    func test_live_staging() throws {
        scenarioSmallEvents()
        scenarioLargeEvents()
        scenarioBadEventAmongGood()
        scenarioAuthLinksPush()
        scenarioRateLimit()
        print("LIVE SUMMARY " + results.map { "\($0.0)=\($0.1 ? "PASS" : "FAIL")" }.joined(separator: " "))
    }

    // 1. 250 small events.
    private func scenarioSmallEvents() {
        let mark = transport.count
        let q = queue()
        q.jitter = { _ in 0.5 }
        for i in 0..<250 { q_add(q, "f67_live_ios_small", ["i": i]) }
        let drained = drain(q)
        let posts = ingestRecs(transport.since(mark))
        let ok2xx = posts.filter { (200..<300).contains($0.status) }
        let accepted = ok2xx.reduce(0) { $0 + ($1.dataCount ?? ($1.path == "/events" ? 1 : 0)) }
        let maxEvents = posts.map { $0.eventCount }.max() ?? 0
        let maxBytes = posts.map { $0.bodyBytes }.max() ?? 0
        let statuses = posts.map { "\($0.status)\($0.errorCode.map { ":" + $0 } ?? "")" }
        report("1 small×250", drained && accepted == 250 && maxEvents <= 100 && maxBytes <= 60_012,
               "posts=\(posts.count) statuses=\(statuses) accepted=\(accepted) maxEvents=\(maxEvents) maxBytes=\(maxBytes)")
    }

    private func q_add(_ q: EventQueue, _ name: String, _ props: [String: Any]) { q.add(event: event(name, props)) }

    // 2. ~12 events with ~8 KB properties.
    private func scenarioLargeEvents() {
        let mark = transport.count
        let q = queue()
        q.jitter = { _ in 0.5 }
        let blob = String(repeating: "b", count: 7_900)
        for i in 0..<12 { q_add(q, "f67_live_ios_large", ["i": i, "blob": blob]) }
        let drained = drain(q)
        let posts = ingestRecs(transport.since(mark))
        let accepted = posts.filter { (200..<300).contains($0.status) }.reduce(0) { $0 + ($1.dataCount ?? ($1.path == "/events" ? 1 : 0)) }
        let maxBytes = posts.map { $0.bodyBytes }.max() ?? 0
        report("2 large×12", drained && accepted == 12 && maxBytes <= 60_012 && posts.count >= 2,
               "posts=\(posts.count) sizes=\(posts.map { $0.bodyBytes }) statuses=\(posts.map { $0.status }) accepted=\(accepted)")
    }

    // 3. One 413 event and one 422 event among good ones.
    private func scenarioBadEventAmongGood() {
        for (label, bad) in [("413", event("f67_live_ios_huge", ["blob": String(repeating: "h", count: 70_000)])),
                             ("422", { var e = event("x"); e["eventType"] = String(repeating: "z", count: 200); return e }())] {
            let mark = transport.count
            let q = queue()
            q.jitter = { _ in 0.5 }
            for i in 0..<10 { q_add(q, "f67_live_ios_good", ["i": i]) }
            q.add(event: bad)
            for i in 10..<20 { q_add(q, "f67_live_ios_good", ["i": i]) }
            let drained = drain(q, timeout: 90)
            let posts = ingestRecs(transport.since(mark))
            let accepted = posts.filter { (200..<300).contains($0.status) }.reduce(0) { $0 + ($1.dataCount ?? ($1.path == "/events" ? 1 : 0)) }
            let refused = posts.filter { $0.status == Int(label) }
            report("3 bad-\(label)", drained && accepted == 20 && !refused.isEmpty && posts.count <= 20,
                   "posts=\(posts.count) statuses=\(posts.map { "\($0.status)/\($0.eventCount)" }) accepted=\(accepted)")
        }
    }

    // 5 / 6 / 7. Auth + known device, links, push.
    @MainActor
    private func scenarioAuthLinksPush() {
        let secure = RecordingSecureStore()
        let storage = SendoraStorage(secure: secure, plain: RecordingPlainStore())
        let auth = SendoraCloudAuth(client: client, storage: storage,
                                    config: .init(expectedProjectId: nil, configProjectId: nil, autoRestoreHeldGuest: true, schedulesTimers: false),
                                    onIdentityChange: { _ in }, onIdentityCleared: { _ in }, onIdentityWithheld: {})
        let email = "f67-live-ios-\(UUID().uuidString.prefix(10).lowercased())@example.com"
        let password = "F67-live-\(UUID().uuidString)-Aa1!"
        let mark = transport.count

        func signIn(_ e: String) -> Result<SendoraCloudAuthUser, SendoraCloudAuthError>? {
            var last: Result<SendoraCloudAuthUser, SendoraCloudAuthError>?
            for _ in 0..<4 {
                last = block { done in auth.signIn(email: e, password: password, completion: done) }
                if case .success = last { return last }
                Thread.sleep(forTimeInterval: 3)
            }
            return last
        }
        func signOut() { _ = block { (done: @escaping (()) -> Void) in auth.signOut { done(()) } } }

        var guestOK = false
        for _ in 0..<5 {
            let r: Result<SendoraCloudAuthUser, SendoraCloudAuthError>? = block { done in auth.signInAnonymously(completion: done) }
            if case .success(let u)? = r, u.isAnonymous { guestOK = true; break }
            Thread.sleep(forTimeInterval: 2.5)
        }
        var signedUp: String = "no"
        let up: Result<SendoraCloudAuthUser, SendoraCloudAuthError>? = guestOK ? block { done in auth.signUp(email: email, password: password, completion: done) } : nil
        if let r = up {
            switch r { case .success(let u): signedUp = u.isAnonymous ? "still-anon" : "ok"; case .failure(let e): signedUp = "\(e.code ?? "?")/\(e.status ?? 0)" }
        }
        signOut()
        let first = signIn(email)
        let tokenAfterFirst = storage.knownDeviceToken(forEmail: email) != nil
        signOut()
        let second = signIn(email)
        let logins = transport.since(mark).filter { $0.path == "/auth-service/login" }
        let secondSent = logins.last?.hasKnownDeviceToken == true
        let digest = SHA256.hash(data: Data(email.trimmingCharacters(in: .whitespaces).lowercased().utf8)).map { String(format: "%02x", $0) }.joined()
        let storedJson = secure.get(SendoraStorage.knownDevicesKey) ?? ""
        let keyed = storedJson.contains(digest) && !storedJson.contains("example.com")
        var firstOK = false; if case .success? = first { firstOK = true }
        var secondOK = false; if case .success? = second { secondOK = true }
        report("5a signUp→signIn kdt", guestOK && signedUp == "ok" && firstOK && tokenAfterFirst && secondOK && secondSent && keyed,
               "guest=\(guestOK) signUp=\(signedUp) login1=\(logins.first?.status ?? 0) kdtSaved=\(tokenAfterFirst) login2=\(logins.last?.status ?? 0) login2SentKdt=\(secondSent) sha256Keyed=\(keyed)")

        _ = block { (done: @escaping (()) -> Void) in auth.resetFromParent(includeHeldGuests: false) { done(()) } }
        let survivesReset = storage.knownDeviceToken(forEmail: email) != nil
        let third = signIn(email)
        let thirdSent = transport.since(mark).filter { $0.path == "/auth-service/login" }.last?.hasKnownDeviceToken == true
        var thirdOK = false; if case .success? = third { thirdOK = true }
        report("5b RESET keeps kdt", survivesReset && thirdOK && thirdSent, "kept=\(survivesReset) login3=\(thirdOK) sent=\(thirdSent)")

        // 7. Push with the Bearer (signed in now). This method runs on the main actor; the token lookup and the
        // network completion never hop to main, so blocking here is safe.
        let pushMark = transport.count
        let push = SendoraCloudPush(client: client, accessTokenProvider: { done in auth.getAccessToken(completion: done) })
        let pushSem = DispatchSemaphore(value: 0)
        push.registerToken(String(repeating: "ab", count: 32), userId: auth.currentUser?.id) { _ in pushSem.signal() }
        _ = pushSem.wait(timeout: .now() + 30)
        let pushRec = transport.since(pushMark).first { $0.path == "/push/tokens" }
        report("7 push Bearer", pushRec?.hasBearer == true && (200..<300).contains(pushRec?.status ?? 0),
               "status=\(pushRec?.status ?? 0) bearer=\(pushRec?.hasBearer ?? false) code=\(pushRec?.errorCode ?? "-")")

        // 6. Links.
        let links = SendoraCloudLinks(apiClient: client, bundleId: nil, linkHosts: [], storage: storage)
        let created: Result<SendoraCloudLinks.LinkCreateResult, Error>? = block { done in
            links.create(.init(title: "f67 live ios", fallbackUrl: "https://example.com/f67-live")) { done($0) }
        }
        var linkEvidence = "create failed"
        var linkOK = false
        if case .success(let link)? = created {
            let stored = storage.linkRevokeToken(forShortcode: link.shortcode) != nil
            let revoked: Result<SendoraCloudLinks.LinkRevokeResult, Error>? = block { done in links.revoke(shortcode: link.shortcode, revokeToken: nil) { done($0) } }
            let rec = transport.snapshot().last { $0.path.hasSuffix("/revoke") }
            var final = false; if case .success(let r)? = revoked { final = r.final }
            linkOK = link.revokeToken != nil && stored && rec?.hasRevokeToken == true && (200..<300).contains(rec?.status ?? 0) && final
                && storage.linkRevokeToken(forShortcode: link.shortcode) == nil
            linkEvidence = "revokeToken=\(link.revokeToken != nil) stored=\(stored) revokeStatus=\(rec?.status ?? 0) sentToken=\(rec?.hasRevokeToken ?? false) final=\(final)"
        } else if case .failure(let e)? = created {
            linkEvidence = "create error \(e)"
        }
        report("6 links revokeToken", linkOK, linkEvidence)

        // 5c. deleteAccount removes that account's entry and the account.
        let deleted: Result<SendoraCloudAuth.AccountDeletionResult, Error>? = block { done in auth.deleteAccount(completion: done) }
        var delStatus = "failed"; if case .success(let d)? = deleted { delStatus = d.status }
        let delRec = transport.snapshot().last { $0.path == "/auth-service/me" && $0.method == "DELETE" }
        let gone = storage.knownDeviceToken(forEmail: email) == nil
        report("5c deleteAccount", (200..<300).contains(delRec?.status ?? 0) && gone && auth.status() == .signedOut,
               "DELETE=\(delRec?.status ?? 0) status=\(delStatus) kdtRemoved=\(gone) authStatus=\(auth.status())")
    }

    // 4. Real 429 on the ingest lane.
    private func scenarioRateLimit() {
        // A guest session first, so a NON-event call (token refresh) can be timed while the lane is held.
        let auth = SendoraCloudAuth(client: client, storage: SendoraStorage(secure: RecordingSecureStore(), plain: RecordingPlainStore()),
                                    config: .init(expectedProjectId: nil, configProjectId: nil, autoRestoreHeldGuest: true, schedulesTimers: false),
                                    onIdentityChange: { _ in }, onIdentityCleared: { _ in }, onIdentityWithheld: {})
        var guest = false
        for _ in 0..<5 {
            let r: Result<SendoraCloudAuthUser, SendoraCloudAuthError>? = block { done in auth.signInAnonymously(completion: done) }
            if case .success? = r { guest = true; break }
            Thread.sleep(forTimeInterval: 2.5)
        }
        // Exhaust the lane with raw (cheap, invalid) batch posts on a SEPARATE client — the SDK client's breaker
        // must only learn of the 429 from its own request.
        let raw = APIClient(baseUrl: Self.base, apiKey: apiKey, transport: transport)
        var got429: Rec?
        let mark = transport.count
        let group = DispatchGroup()
        for _ in 0..<12 where got429 == nil {
            for _ in 0..<30 {
                group.enter()
                raw.requestWithDetails(method: "POST", path: "/events/batch", body: ["events": []]) { _ in group.leave() }
            }
            group.wait()
            got429 = transport.since(mark).first { $0.status == 429 && $0.path == "/events/batch" }
        }
        guard let first429 = got429 else {
            return report("4 rate limit", false, "no 429 after \(transport.since(mark).count) raw posts")
        }
        let policy = first429.rateLimitPolicy ?? "-"

        // The SDK queue meets the 429.
        let q = queue()
        q.add(event: event("f67_live_ios_after429"))
        let qMark = transport.count
        q.flush()
        _ = waitUntil(15) { ingestRecs(transport.since(qMark)).count >= 1 }
        let firstPost = ingestRecs(transport.since(qMark)).first
        guard let fp = firstPost, fp.status == 429, let waitSec = fp.retryAfter.flatMap({ Int($0) }) else {
            return report("4 rate limit", false, "the queue's first post was \(firstPost?.status ?? 0), not a 429 (lane recovered: \(policy))")
        }
        let held = client.breakerOpenUntil.timeIntervalSince(fp.at)
        let attempts = (q.snapshot.first?[EventQueue.attemptsKey] as? NSNumber)?.intValue ?? 0
        // Flushes inside the wait send nothing.
        for _ in 0..<5 { q.flush(); Thread.sleep(forTimeInterval: 0.3) }
        // Requests the queue sent AFTER the 429 and before its Retry-After ran out (must be none).
        let postsDuringWait = ingestRecs(transport.since(qMark)).dropFirst().filter { $0.at < fp.at.addingTimeInterval(Double(waitSec) - 0.2) }.count

        // A non-event call while the lane is held: the client must let it out within 60 s.
        var refreshAt: Date?
        if guest {
            let deadline = Date().addingTimeInterval(75)
            while Date() < deadline, refreshAt == nil {
                let m = transport.count
                _ = block(timeout: 10) { (done: @escaping (String?) -> Void) in auth.getAccessToken(forceRefresh: true, completion: done) }
                refreshAt = transport.since(m).first { $0.path == "/auth-service/token/refresh" }?.at
                if refreshAt == nil { Thread.sleep(forTimeInterval: 2) }
            }
        }
        let refreshDelay = refreshAt.map { $0.timeIntervalSince(fp.at) }

        // Delivered after the wait.
        let delivered = waitUntil(Double(waitSec) + 90, poll: 1) { q.flush(); return q.count == 0 }
        let okPost = ingestRecs(transport.since(qMark)).first { (200..<300).contains($0.status) }
        let gap = okPost.map { $0.at.timeIntervalSince(fp.at) } ?? -1
        report("4 rate limit",
               delivered && gap >= Double(waitSec) - 1 && attempts == 0 && postsDuringWait == 0 && held <= 61
                   && (refreshDelay.map { $0 <= 61 } ?? false),
               "policy=\(policy) firstQueuePost=\(fp.status) Retry-After=\(waitSec)s breakerHold=\(Int(held))s attemptsSpent=\(attempts) postsInsideWait=\(postsDuringWait) refreshAfter=\(refreshDelay.map { String(Int($0)) } ?? "none")s deliveredAfter=\(Int(gap))s")
    }
}
