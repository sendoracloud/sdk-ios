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
        var hasIdentityToken: Bool = false
        var bodyUserId: String? = nil
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
                              hasRevokeToken: body?["revokeToken"] != nil,
                              hasIdentityToken: body?["identityToken"] != nil,
                              bodyUserId: body?["userId"] as? String, at: Date())
                self?.lock.lock(); self?.recs.append(rec); self?.lock.unlock()
                completion(data, http, error)
            }
        }

        func snapshot() -> [Rec] { lock.lock(); defer { lock.unlock() }; return recs }
        func since(_ mark: Int) -> [Rec] { Array(snapshot().dropFirst(mark)) }
        var count: Int { snapshot().count }
    }

    final class Flag { private let l = NSLock(); private var v = false
        var isSet: Bool { l.lock(); defer { l.unlock() }; return v }
        func set() { l.lock(); v = true; l.unlock() } }

    // MARK: - Setup

    private var apiKey = ""
    private var base = ""
    private var transport: LiveTransport!
    private var client: APIClient!
    private var results: [(String, Bool, String)] = []

    override func setUpWithError() throws {
        let cfg = try LiveEnv.require()     // SENDORA_LIVE=1, staging host only, no prod/live key
        apiKey = cfg.apiKey
        base = cfg.base
        transport = LiveTransport()
        client = APIClient(baseUrl: cfg.base, apiKey: apiKey, transport: transport)
    }

    /// Scenario `"<n><sub> …"` reports contract step `T<n>` (a sub-case that fails fails the step).
    private func report(_ name: String, _ ok: Bool, _ evidence: String) {
        results.append((name, ok, evidence))
        let digits = name.prefix(while: { $0.isNumber })
        LiveReport.shared.record("T\(digits)", pass: ok, detail: "\(name): \(evidence)")
        if !ok { XCTFail("\(name): \(LiveReport.scrub(evidence))") }
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
        scenarioConsentAndFlags()
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

    // 8. Server consent + flags carry identify()'s token for the identified user, never for another userId.
    // (The token cannot be a VALID HMAC here — that needs the project's identity secret — so the server answers
    // "unproven"; T8 proves the four routes accept the SDK's bodies and which body carried the token.)
    private func scenarioConsentAndFlags() {
        let uid = "f67-live-ios-\(UUID().uuidString.prefix(8).lowercased())"
        let identity = SendoraIdentitySnapshot(currentUserId: uid, tokenUserId: uid,
                                               token: "hmac_v1:" + String(repeating: "0", count: 64))
        let flags = SendoraCloudFlags(client: client, identity: { identity })
        let consent = SendoraCloudConsent(initial: false)
        consent.attach(client: client, identity: { identity })
        let mark = transport.count
        var errors: [String] = []
        func run<T>(_ label: String, _ op: @escaping () async throws -> T) -> T? {
            let sem = DispatchSemaphore(value: 0)
            var out: T?
            // Detached: the test method runs on the main actor, which this semaphore blocks.
            Task.detached {
                do { out = try await op() } catch let e as SendoraCloudAPIError { errors.append("\(label) \(e.status) \(e.code)") } catch { errors.append("\(label) \(error)") }
                sem.signal()
            }
            _ = sem.wait(timeout: .now() + 30)
            return out
        }
        let rec = run("consent.record") { try await consent.record(purpose: .analytics, granted: false, userId: uid, source: "f67-live-ios") }
        let del = run("consent.requestDeletion") { try await consent.requestDeletion(userId: uid, reason: "f67 live test (no data)") }
        let one = run("flags.evaluate") { try await flags.evaluate(key: "f67_live_ios_missing_flag") }
        let all = run("flags.evaluateAll") { try await flags.evaluateAll() }
        let other = run("flags.evaluate(other user)") { try await flags.evaluate(key: "f67_live_ios_missing_flag", userId: uid + "-other") }
        let recs = transport.since(mark)
        func r(_ suffix: String) -> [Rec] { recs.filter { $0.path.hasSuffix(suffix) } }
        let carried = r("/consent/record").first?.hasIdentityToken == true && r("/consent/deletion-request").first?.hasIdentityToken == true
            && r("/feature-flags/evaluate").first?.hasIdentityToken == true && r("/feature-flags/evaluate-all").first?.hasIdentityToken == true
        let otherRec = r("/feature-flags/evaluate").last
        let notForOther = otherRec?.bodyUserId == uid + "-other" && otherRec?.hasIdentityToken == false
        let statuses = recs.map { "\($0.path.components(separatedBy: "/").suffix(2).joined(separator: "/")) \($0.status)" }
        report("8 consent+flags identityToken",
               errors.isEmpty && rec != nil && del != nil && one != nil && all != nil && other != nil && carried && notForOther
                   && recs.allSatisfy { (200..<300).contains($0.status) },
               "statuses=\(statuses) tokenOnIdentified=\(carried) tokenOnOtherUser=\(!notForOther) record.sourceVerified=\(rec?.sourceVerified.map(String.init) ?? "-") deletion.status=\(del?.status ?? "-") flag.reason=\(one?.reason ?? "-") flags=\(all?.count ?? -1) errors=\(errors)")
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
        // must only learn of the 429 from its own request. Staging's ingest lane refills in ~1 s, so the queue
        // flushes the moment a 429 is seen, and the whole round is retried if the lane refilled first.
        var policy = "-"
        var q: EventQueue!
        var qMark = 0
        var firstPost: Rec?
        for _ in 0..<4 {
            // Continuous pressure (~50 req/s against a lane that refills ~3.3/s) until the queue's own post lands.
            let stop = Flag()
            let pressure = Thread {
                while !stop.isSet {
                    // A fresh client per request: one client's own breaker would stop the pressure at the first 429.
                    APIClient(baseUrl: self.base, apiKey: self.apiKey, transport: self.transport)
                        .requestWithDetails(method: "POST", path: "/events/batch", body: ["events": []]) { _ in }
                    Thread.sleep(forTimeInterval: 0.02)
                }
            }
            let mark = transport.count
            pressure.start()
            let saw429 = waitUntil(20) { transport.since(mark).contains { $0.status == 429 && $0.eventCount == 0 } }
            if let hit = transport.since(mark).first(where: { $0.status == 429 }) { policy = hit.rateLimitPolicy ?? "-" }
            guard saw429 else { stop.set(); continue }
            q = queue()
            q.add(event: event("f67_live_ios_after429"))
            qMark = transport.count
            q.flush()
            _ = waitUntil(15) { ingestRecs(transport.since(qMark)).contains { $0.eventCount == 1 } }
            stop.set()
            firstPost = ingestRecs(transport.since(qMark)).first { $0.eventCount == 1 }
            if firstPost?.status == 429 { break }
            _ = waitUntil(5) { q.count == 0 }
        }
        guard let fp = firstPost, fp.status == 429, let waitSec = fp.retryAfter.flatMap({ Int($0) }) else {
            return report("4 rate limit", false, "the queue never met a 429 in 6 rounds (last first-post \(firstPost?.status ?? 0), \(policy))")
        }
        let held = client.breakerOpenUntil.timeIntervalSince(fp.at)
        let attempts = (q.snapshot.first?[EventQueue.attemptsKey] as? NSNumber)?.intValue ?? 0
        // Flushes inside the wait send nothing.
        for _ in 0..<5 { q.flush(); Thread.sleep(forTimeInterval: 0.3) }
        // Requests the queue sent AFTER the 429 and before its Retry-After ran out (must be none).
        let postsDuringWait = ingestRecs(transport.since(qMark)).filter { $0.eventCount == 1 }.dropFirst().filter { $0.at < fp.at.addingTimeInterval(Double(waitSec) - 0.2) }.count

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
        let okPost = ingestRecs(transport.since(qMark)).first { (200..<300).contains($0.status) && $0.eventCount == 1 }
        let gap = okPost.map { $0.at.timeIntervalSince(fp.at) } ?? -1
        report("4 rate limit",
               delivered && gap >= Double(waitSec) - 1 && attempts == 0 && postsDuringWait == 0 && held <= 61
                   && (refreshDelay.map { $0 <= 61 } ?? false),
               "policy=\(policy) firstQueuePost=\(fp.status) Retry-After=\(waitSec)s breakerHold=\(Int(held))s attemptsSpent=\(attempts) postsInsideWait=\(postsDuringWait) refreshAfter=\(refreshDelay.map { String(Int($0)) } ?? "none")s deliveredAfter=\(Int(gap))s")
    }
}
