import XCTest
@testable import SendoraCloud

/// 5.6.0 (audit F67) — the client half of the response contract: `Retry-After` holds the breaker, a
/// Cloudflare challenge is never a refusal, full-jitter backoff, and an event queue that tells a
/// permanent refusal from a transient one. Everything runs through the real `APIClient` over the
/// scripted transport (`APIClient(transport:)`) or the real `EventQueue`.
final class ResponseContractTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    private func makeClient(_ transport: StubTransport, jitter: ((TimeInterval) -> TimeInterval)? = { _ in 0 }) -> APIClient {
        let client = APIClient(baseUrl: "https://api.test", apiKey: "pk_dev_test", transport: transport)
        let now = t0
        client.clock = { now }
        if let jitter = jitter { client.jitter = jitter }
        return client
    }

    private func post(_ client: APIClient, _ path: String = "/x") -> [String: Any]? {
        let sem = DispatchSemaphore(value: 0)
        var out: [String: Any]?
        client.post(path: path, body: [:]) { out = $0; sem.signal() }
        XCTAssertEqual(sem.wait(timeout: .now() + 5), .success)
        return out
    }

    private func rich(_ client: APIClient, _ path: String = "/x") -> APIClient.RichResponse {
        let sem = DispatchSemaphore(value: 0)
        var out = APIClient.RichResponse(statusCode: -1, body: nil, errorCode: nil, errorMessage: nil)
        client.requestWithDetails(method: "POST", path: path, body: [:]) { out = $0; sem.signal() }
        XCTAssertEqual(sem.wait(timeout: .now() + 5), .success)
        return out
    }

    private static let cfPage = StubResponse(status: 403, json: nil, headers: ["cf-mitigated": "challenge", "Content-Type": "text/html"],
                                             rawBody: Data("<html>Just a moment...</html>".utf8))

    // MARK: - Retry-After holds the breaker (both request paths)

    func test_429RetryAfterHeaderHoldsTheWholeClient_onBothPaths() {
        for usePlain in [true, false] {
            let transport = StubTransport()
            let client = makeClient(transport)
            transport.stub("POST", "/x", StubResponse.failure(status: 429, code: "RATE_LIMITED").with(headers: ["Retry-After": "120"]))
            if usePlain {
                let body = post(client)
                XCTAssertEqual(((body?["error"] as? [String: Any])?["details"] as? [String: Any])?["retryAfterSeconds"] as? Int, 120,
                               "the full wait must still reach the caller")
            } else { XCTAssertEqual(rich(client).retryAfterSeconds, 120, "the full wait must still reach the caller") }
            // Review H2: a 429 is ONE lane's budget — it holds the whole client for at most 60 s.
            XCTAssertEqual(client.breakerOpenUntil, t0.addingTimeInterval(60), "plain=\(usePlain)")
            // The next call — any route — is not sent while the server's wait runs.
            transport.stub("POST", "/y", .ok([:]))
            let before = transport.requestCount
            if usePlain { XCTAssertNil(post(client, "/y")) } else { XCTAssertEqual(rich(client, "/y").statusCode, 0) }
            XCTAssertEqual(transport.requestCount, before, "a request went out inside Retry-After (plain=\(usePlain))")
        }
    }

    func test_503UsesTheBodyHintWhenTheHeaderIsMissing_andAnHttpDate() {
        let transport = StubTransport()
        let client = makeClient(transport)
        transport.stub("POST", "/x", StubResponse.failure(status: 503, code: "OVERLOADED", details: ["retryAfterSeconds": 17]))
        XCTAssertEqual(rich(client).retryAfterSeconds, 17)
        XCTAssertEqual(client.breakerOpenUntil, t0.addingTimeInterval(17))

        let http = HTTPURLResponse(url: URL(string: "https://api.test")!, statusCode: 503, httpVersion: nil,
                                   headerFields: ["Retry-After": "Fri, 15 Jan 2027 08:00:30 GMT"])!
        let now = ISO8601DateFormatter().date(from: "2027-01-15T08:00:00Z")!
        XCTAssertEqual(APIClient.retryAfterSeconds(http, body: nil, now: now), 30)
    }

    func test_serverWaitIsCappedAtOneHour() {
        let transport = StubTransport()
        let client = makeClient(transport)
        transport.stub("POST", "/x", StubResponse.failure(status: 503, code: "OVERLOADED").with(headers: ["Retry-After": "999999"]))
        _ = post(client)
        XCTAssertEqual(client.breakerOpenUntil, t0.addingTimeInterval(3600))
        // A quota 429 asking until the month resets: the client is held 60 s, the caller told ≤ 1 h.
        let t2 = StubTransport()
        let c2 = makeClient(t2)
        t2.stub("POST", "/x", StubResponse.failure(status: 429, code: "QUOTA_EXCEEDED").with(headers: ["Retry-After": "999999"]))
        XCTAssertEqual(rich(c2).retryAfterSeconds, 3600)
        XCTAssertEqual(c2.breakerOpenUntil, t0.addingTimeInterval(60))
    }

    func test_plain4xxNeverTripsTheBreaker_onBothPaths() {
        for status in [400, 401, 403, 404, 409, 410, 413, 422] {
            for usePlain in [true, false] {
                let transport = StubTransport()
                let client = makeClient(transport)
                transport.stub("POST", "/x", StubResponse.failure(status: status, code: "NOPE"))
                if usePlain { _ = post(client) } else { _ = rich(client) }
                XCTAssertEqual(client.breakerOpenUntil, .distantPast, "HTTP \(status) plain=\(usePlain) tripped the breaker")
            }
        }
    }

    // MARK: - Cloudflare challenge

    func test_challengeHoldsAtLeastSixtySeconds_andIsDeliveredAsNoResponse() {
        let transport = StubTransport()
        let client = makeClient(transport)
        transport.stub("POST", "/x", Self.cfPage)
        let r = rich(client)
        XCTAssertEqual(r.statusCode, 0, "a challenge must look like the transport class, never a 403")
        XCTAssertTrue(r.cfMitigated)
        XCTAssertEqual(r.challengeStatus, 403)
        XCTAssertNil(r.body)
        XCTAssertEqual(client.breakerOpenUntil, t0.addingTimeInterval(60))

        let t2 = StubTransport()
        let c2 = makeClient(t2)
        // A challenge whose page happens to be JSON naming a refusal is still not the API's answer.
        t2.stub("POST", "/x", StubResponse.failure(status: 503, code: "INVALID_REFRESH_TOKEN").with(headers: ["cf-mitigated": "challenge", "Retry-After": "300"]))
        XCTAssertNil(post(c2), "the plain path must not hand a challenge's body to a caller")
        XCTAssertEqual(c2.breakerOpenUntil, t0.addingTimeInterval(300), "a longer Retry-After beats the 60 s floor")
    }

    // MARK: - Full jitter

    func test_backoffIsFullJitterUnderACeilingThatDoublesToSixty() {
        let transport = StubTransport()
        let lock = NSLock()
        var ceilings: [TimeInterval] = []
        let client = makeClient(transport, jitter: { c in lock.lock(); ceilings.append(c); lock.unlock(); return 0 })
        transport.stub("POST", "/x", StubResponse.failure(status: 500, code: "BOOM"))
        for _ in 0..<7 {
            _ = post(client)
            // A draw of 0 means "retry now": a fixed doubling would still hold the window shut.
            XCTAssertEqual(client.breakerOpenUntil, t0, "the drawn delay must be the whole delay (no fixed floor)")
        }
        lock.lock(); defer { lock.unlock() }
        XCTAssertEqual(ceilings, [2, 4, 8, 16, 32, 60, 60])
    }

    func test_defaultJitterDrawsAcrossTheWholeRange() {
        let client = APIClient(baseUrl: "https://api.test", apiKey: "pk_dev_test", transport: StubTransport())
        let draws = (0..<400).map { _ in client.jitter(8) }
        XCTAssertTrue(draws.allSatisfy { $0 >= 0 && $0 <= 8 })
        XCTAssertGreaterThan(Set(draws.map { Int($0) }).count, 4, "not random(0, ceiling)")
        XCTAssertEqual(client.jitter(0), 0)
    }

    // MARK: - Delivery outcomes (the event queue's reading of an answer)

    func test_deliveryOutcomeTable() {
        func r(_ status: Int, cf: Bool = false, body: [String: Any]? = nil) -> APIClient.RichResponse {
            APIClient.RichResponse(statusCode: cf ? 0 : status, body: body, errorCode: nil, errorMessage: nil, cfMitigated: cf, challengeStatus: cf ? status : 0)
        }
        XCTAssertEqual(APIClient.deliveryOutcome(r(201, body: ["success": true])), .accepted)
        for s in [400, 401, 403, 404, 413, 422] {
            XCTAssertEqual(APIClient.deliveryOutcome(r(s)), .rejected(status: s), "\(s)")
        }
        XCTAssertEqual(APIClient.deliveryOutcome(r(429)), .retryLater(countsAttempt: false), "a 429 is NOT success and NOT the events' fault")
        XCTAssertEqual(APIClient.deliveryOutcome(r(0)), .retryLater(countsAttempt: false))
        XCTAssertEqual(APIClient.deliveryOutcome(r(403, cf: true)), .retryLater(countsAttempt: false))
        XCTAssertEqual(APIClient.deliveryOutcome(r(503, cf: true)), .retryLater(countsAttempt: false))
        for s in [408, 500, 502, 503] {
            XCTAssertEqual(APIClient.deliveryOutcome(r(s)), .retryLater(countsAttempt: true, status: s), "\(s)")
        }
        var unverified = r(401); unverified = APIClient.RichResponse(statusCode: 401, body: nil, errorCode: "IDENTITY_UNVERIFIED", errorMessage: nil)
        XCTAssertEqual(APIClient.deliveryOutcome(unverified), .retryLater(countsAttempt: true), "IDENTITY_UNVERIFIED is answered-transient, not permanent")
        let quota = APIClient.RichResponse(statusCode: 429, body: nil, errorCode: nil, errorMessage: nil, retryAfterSeconds: 3600)
        XCTAssertEqual(APIClient.deliveryOutcome(quota), .retryLater(countsAttempt: false, after: 3600), "the queue must learn the full wait")
    }

    // MARK: - Event queue

    private func eventually(_ what: String, timeout: TimeInterval = 5, _ cond: () -> Bool) {
        let deadline = Date().addingTimeInterval(timeout)
        while !cond() {
            if Date() > deadline { return XCTFail("timed out: \(what)") }
            Thread.sleep(forTimeInterval: 0.005)
        }
    }

    private func freshStorage() -> (SendoraStorage, RecordingPlainStore) {
        let plain = RecordingPlainStore()
        return (SendoraStorage(secure: RecordingSecureStore(), plain: plain), plain)
    }

    private func event(_ i: Int) -> [String: Any] { ["eventType": "e\(i)", "module": "custom", "properties": [:]] }

    /// The real wire: EventQueue → APIClient.postBatch → the scripted transport.
    func test_queueThroughTheClient_dropsPermanentRefusals_keepsTransientOnes() {
        let cases: [(StubResponse, Bool)] = [
            (StubResponse.failure(status: 400, code: "VALIDATION_ERROR"), true),
            (StubResponse.failure(status: 401, code: "UNAUTHORIZED"), true),
            (StubResponse.failure(status: 403, code: "FORBIDDEN"), true),
            (StubResponse.failure(status: 404, code: "NOT_FOUND"), true),
            (StubResponse.failure(status: 413, code: "PAYLOAD_TOO_LARGE"), true),
            (StubResponse.failure(status: 422, code: "VALIDATION_ERROR"), true),
            (StubResponse.failure(status: 429, code: "RATE_LIMITED", details: ["retryAfterSeconds": 5]), false),
            (StubResponse.failure(status: 408, code: "TIMEOUT"), false),
            (StubResponse.failure(status: 503, code: "OVERLOADED"), false),
            (Self.cfPage, false),
            (StubResponse.offline, false),
        ]
        for (response, dropped) in cases {
            let transport = StubTransport()
            let client = makeClient(transport)
            transport.stub("POST", "/events/batch", response)
            let (storage, _) = freshStorage()
            let q = EventQueue(storage: storage, flushAt: 1000)
            q.jitter = { _ in 0 } // no backoff wait in this test
            q.setFlushHandler { chunk, done in client.postBatch(path: "/events/batch", events: chunk, completion: done) }
            q.add(event: event(1)); q.add(event: event(2))
            q.flush()
            eventually("request sent (\(response.status))") { transport.requestCount >= 1 }
            if dropped {
                eventually("HTTP \(response.status) dropped") { q.count == 0 }
                XCTAssertTrue(storage.loadEventQueue().isEmpty, "the persisted queue still holds a refused chunk (\(response.status))")
            } else {
                Thread.sleep(forTimeInterval: 0.05)
                XCTAssertEqual(q.count, 2, "HTTP \(response.status) (cf=\(response.headers["cf-mitigated"] ?? "-")) must keep the chunk")
            }
        }
    }

    func test_aPoisonChunkNoLongerBlocksTheEventsBehindIt_chunksStayAtMost100() {
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.jitter = { _ in 0 } // no backoff wait in this test
        let lock = NSLock()
        var sizes: [Int] = []
        q.setFlushHandler { chunk, done in
            lock.lock(); sizes.append(chunk.count); let first = sizes.count == 1; lock.unlock()
            done(first ? .rejected(status: 404) : .accepted) // 404: permanent, never bisected
        }
        for i in 0..<150 { q.add(event: event(i)) }
        q.flush()
        eventually("drained") { q.count == 0 }
        lock.lock(); defer { lock.unlock() }
        XCTAssertEqual(sizes, [100, 50])
    }

    func test_retryBudget_serverFailuresSpendIt_offlineAnd429DoNot_andItSurvivesARelaunch() {
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.jitter = { _ in 0 } // no backoff wait in this test
        let lock = NSLock()
        var next: APIClient.DeliveryOutcome = .retryLater(countsAttempt: false)
        var sent: [[String: Any]] = []
        var calls = 0
        q.setFlushHandler { chunk, done in
            lock.lock(); calls += 1; sent = chunk; let o = next; lock.unlock()
            done(o)
        }
        q.add(event: event(1))
        func flushOnce() {
            lock.lock(); let before = calls; lock.unlock()
            q.flush()
            eventually("flush") { lock.lock(); defer { lock.unlock() }; return calls > before }
            _ = q.count; _ = q.count // drain the completion hop
        }
        // 200 offline / 429 / challenge answers: nothing is spent.
        for _ in 0..<200 { flushOnce() }
        XCTAssertEqual(q.count, 1)
        XCTAssertNil(storage.loadEventQueue().first?[EventQueue.attemptsKey], "a transport failure spent the retry budget")

        lock.lock(); next = .retryLater(countsAttempt: true); lock.unlock()
        flushOnce()
        // Persisted with its spent budget — a relaunch keeps counting.
        XCTAssertEqual((storage.loadEventQueue().first?[EventQueue.attemptsKey] as? NSNumber)?.intValue, 1)
        let relaunched = EventQueue(storage: storage, flushAt: 1000)
        relaunched.jitter = { _ in 0 } // no backoff wait in this test
        relaunched.setFlushHandler { chunk, done in
            lock.lock(); calls += 1; sent = chunk; let o = next; lock.unlock()
            done(o)
        }
        func flushRelaunched() {
            lock.lock(); let before = calls; lock.unlock()
            relaunched.flush()
            eventually("flush") { lock.lock(); defer { lock.unlock() }; return calls > before }
            _ = relaunched.count; _ = relaunched.count
        }
        lock.lock(); XCTAssertNil(sent.first?[EventQueue.attemptsKey], "the budget field must never reach the wire"); lock.unlock()
        for _ in 0..<(EventQueue.maxAttempts - 2) { flushRelaunched() }
        XCTAssertEqual(relaunched.count, 1, "dropped before its budget (\(EventQueue.maxAttempts)) was spent")
        flushRelaunched()
        XCTAssertEqual(relaunched.count, 0, "kept past its retry budget — a poison event the server 500s on holds the queue forever")
        lock.lock(); XCTAssertNil(sent.first?[EventQueue.attemptsKey]); lock.unlock()
    }

    // MARK: - Review fixes (H1 / M1 / LOW / H2)

    private final class Box<T> { var v: T; init(_ v: T) { self.v = v } }

    func test_chunksStayUnder60KB() {
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.jitter = { _ in 0 } // no backoff wait in this test
        let lock = NSLock()
        var sizes: [Int] = []
        q.setFlushHandler { chunk, done in
            let bytes = (try? JSONSerialization.data(withJSONObject: ["events": chunk]).count) ?? 0
            lock.lock(); sizes.append(bytes); lock.unlock()
            done(.accepted)
        }
        let blob = String(repeating: "x", count: 5_000)
        for i in 0..<100 { q.add(event: ["eventType": "e\(i)", "properties": ["blob": blob]]) }
        q.flush()
        eventually("drained") { q.count == 0 }
        lock.lock(); defer { lock.unlock() }
        XCTAssertGreaterThan(sizes.count, 1, "100 × 5 KB went as one chunk")
        XCTAssertTrue(sizes.allSatisfy { $0 <= 60_000 }, "a chunk over 60 KB: \(sizes)")
    }

    func test_aRefusedMultiEventChunkIsBisected_onlyTheBadEventIsDropped() {
        for status in [400, 413, 422] {
            let (storage, _) = freshStorage()
            let q = EventQueue(storage: storage, flushAt: 1000)
            q.jitter = { _ in 0 } // no backoff wait in this test
            let lock = NSLock()
            var delivered: [String] = []
            var requests = 0
            q.setFlushHandler { chunk, done in
                let names = chunk.compactMap { $0["eventType"] as? String }
                lock.lock(); requests += 1; lock.unlock()
                if names.contains("poison") { return done(.rejected(status: status)) }
                lock.lock(); delivered += names; lock.unlock()
                done(.accepted)
            }
            for i in 0..<10 { q.add(event: event(i)) }
            q.add(event: ["eventType": "poison"])
            for i in 10..<20 { q.add(event: event(i)) }
            q.flush()
            eventually("drained (\(status))") { q.count == 0 }
            lock.lock()
            XCTAssertEqual(delivered, (0..<20).map { "e\($0)" }, "HTTP \(status): a good neighbour was dropped with the bad event")
            XCTAssertLessThan(requests, 30)
            lock.unlock()
        }
    }

    func test_401AndOtherPermanentRefusalsAreNotBisected() {
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.jitter = { _ in 0 } // no backoff wait in this test
        let lock = NSLock()
        var requests = 0
        q.setFlushHandler { _, done in lock.lock(); requests += 1; lock.unlock(); done(.rejected(status: 401)) }
        for i in 0..<8 { q.add(event: event(i)) }
        q.flush()
        eventually("dropped") { q.count == 0 }
        lock.lock(); XCTAssertEqual(requests, 1); lock.unlock()
    }

    func test_sentEventsAreRemovedByIdentity_notPosition() {
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000, maxSize: 3)
        q.jitter = { _ in 0 } // no backoff wait in this test
        let release = DispatchSemaphore(value: 0)
        let sent = DispatchSemaphore(value: 0)
        let once = Box(false)
        q.setFlushHandler { _, done in
            if once.v { return done(.retryLater(countsAttempt: false)) } // keep what follows queued
            once.v = true
            sent.signal()
            DispatchQueue.global().async { release.wait(); done(.accepted) }
        }
        for i in 1...3 { q.add(event: event(i)) }
        q.flush()
        XCTAssertEqual(sent.wait(timeout: .now() + 5), .success)
        // While e1–e3 are in flight the cap trims e1, e2 to make room.
        q.add(event: event(4)); q.add(event: event(5))
        _ = q.count
        release.signal()
        eventually("in-flight chunk settled") { q.count < 3 }
        Thread.sleep(forTimeInterval: 0.05)
        // Removal by position would also have deleted the never-sent e4 and e5.
        let names = q.snapshot.compactMap { $0["eventType"] as? String }
        XCTAssertEqual(names, ["e4", "e5"], "removal by position deleted events that were never sent")
    }

    func test_theQueueHonoursTheServersFullWaitBeforeTheNextFlush() {
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.jitter = { _ in 0 } // no backoff wait in this test
        let now = Box(t0)
        q.clock = { now.v }
        let lock = NSLock()
        var calls = 0
        q.setFlushHandler { _, done in lock.lock(); calls += 1; lock.unlock(); done(.retryLater(countsAttempt: false, after: 600)) }
        q.add(event: event(1))
        q.flush()
        eventually("first flush") { lock.lock(); defer { lock.unlock() }; return calls == 1 }
        _ = q.count; _ = q.count
        now.v = t0.addingTimeInterval(599)
        q.flush(); _ = q.count; _ = q.count
        lock.lock(); XCTAssertEqual(calls, 1, "flushed inside the server's wait"); lock.unlock()
        now.v = t0.addingTimeInterval(601)
        q.flush()
        eventually("flush after the wait") { lock.lock(); defer { lock.unlock() }; return calls == 2 }
    }

    // MARK: - 201 with identity-refused rows (backend s58.402)

    func test_identityRefusedRowsOfA201StayQueued_spendOneAttempt_othersAreRemoved() {
        let transport = StubTransport()
        let client = makeClient(transport)
        let calls = Box(0)
        transport.stub("POST", "/events/batch") { _ in
            calls.v += 1
            if calls.v > 1 { return .ok(["count": 2], status: 201) }
            return .ok(["count": 1, "rejected": [
                ["index": 0, "reason": "identityToken required (strict-identity mode enabled)", "code": "IDENTITY_UNVERIFIED"],
                ["index": 1, "reason": "Identity token missing"],          // an older backend: no code
                ["index": 2, "reason": "malformed", "code": "VALIDATION"], // not identity: removed
            ]], status: 201)
        }
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.jitter = { _ in 0 } // no backoff wait in this test
        q.setFlushHandler { chunk, done in client.postBatch(path: "/events/batch", events: chunk, completion: done) }
        for i in 0..<4 { q.add(event: event(i)) }
        q.flush()
        eventually("partial settled") { q.count == 2 }
        Thread.sleep(forTimeInterval: 0.05)
        XCTAssertEqual(transport.requestCount, 1, "the kept events were resent in the same flush")
        let kept = q.snapshot
        XCTAssertEqual(kept.compactMap { $0["eventType"] as? String }, ["e0", "e1"])
        XCTAssertEqual(kept.compactMap { ($0[EventQueue.attemptsKey] as? NSNumber)?.intValue }, [1, 1], "an identity refusal is answered-transient")
        XCTAssertEqual(storage.loadEventQueue().count, 2, "not persisted")
        q.flush()
        eventually("retried on the next flush") { q.count == 0 }
        XCTAssertEqual(transport.requestCount, 2)
    }

    func test_identityRejectedIndicesParsing() {
        func body(_ rows: [[String: Any]]) -> [String: Any] { ["success": true, "data": ["rejected": rows]] }
        XCTAssertEqual(APIClient.identityRejectedIndices(body([["index": 3, "code": "IDENTITY_UNVERIFIED", "reason": "x"]])), [3])
        XCTAssertEqual(APIClient.identityRejectedIndices(body([["index": 1, "reason": "IDENTITYTOKEN invalid"]])), [1], "case-insensitive reason fallback")
        XCTAssertEqual(APIClient.identityRejectedIndices(body([["index": 1, "code": "OTHER", "reason": "identity"]])), [], "a code wins over the reason")
        XCTAssertEqual(APIClient.identityRejectedIndices(["success": true, "data": ["count": 2]]), [])
        let r = APIClient.RichResponse(statusCode: 201, body: body([["index": 0, "code": "IDENTITY_UNVERIFIED"]]), errorCode: nil, errorMessage: nil)
        XCTAssertEqual(APIClient.deliveryOutcome(r), .acceptedExcept(retry: [0]))
    }

    // MARK: - Review round 3: the queue's own backoff, bounded bisection, 5xx isolation, send-time token

    func test_theQueueBacksOffOnItsOwn_evenWhenTrackEventKeepsTriggeringFlushes() {
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1)
        let now = Box(t0)
        q.clock = { now.v }
        let lock = NSLock()
        var ceilings: [TimeInterval] = []
        q.jitter = { c in lock.lock(); ceilings.append(c); lock.unlock(); return c }
        var calls = 0
        q.setFlushHandler { _, done in lock.lock(); calls += 1; lock.unlock(); done(.retryLater(countsAttempt: true, status: 500)) }
        // A 5xx outage while the app keeps tracking: every add() past flushAt asks for a flush.
        for i in 0..<60 { q.add(event: event(i)) }
        _ = q.count; _ = q.count
        lock.lock(); XCTAssertEqual(calls, 1, "re-flushed inside the backoff: \(calls) POSTs, each spending an attempt"); lock.unlock()
        XCTAssertEqual(q.count, 60, "events were dropped by a burst of retries")
        for step in 1...10 {
            now.v = now.v.addingTimeInterval(400)
            q.flush(); _ = q.count; _ = q.count
            lock.lock(); XCTAssertEqual(calls, 1 + step); lock.unlock()
        }
        lock.lock(); XCTAssertEqual(ceilings, [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300]); lock.unlock()
    }

    func test_anAcceptedSendResetsTheBackoff() {
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000)
        let now = Box(t0)
        q.clock = { now.v }
        let lock = NSLock()
        var ceilings: [TimeInterval] = []
        q.jitter = { c in lock.lock(); ceilings.append(c); lock.unlock(); return c }
        let fail = Box(true)
        q.setFlushHandler { _, done in done(fail.v ? .retryLater(countsAttempt: false) : .accepted) }
        q.add(event: event(1)); q.flush(); _ = q.count; _ = q.count
        now.v = now.v.addingTimeInterval(400); q.flush(); _ = q.count; _ = q.count
        fail.v = false
        now.v = now.v.addingTimeInterval(400); q.flush(); _ = q.count; _ = q.count
        fail.v = true
        q.add(event: event(2)); q.flush(); _ = q.count; _ = q.count
        lock.lock(); XCTAssertEqual(ceilings, [1, 2, 1]); lock.unlock()
    }

    func test_bisectionIsBoundedPerFlush_andTheHalvedCapDoublesBackOnlyAfterSuccess() {
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.clock = { [t0] in t0 }
        q.jitter = { c in c }
        let lock = NSLock()
        var posts = 0
        q.setFlushHandler { _, done in lock.lock(); posts += 1; lock.unlock(); done(.rejected(status: 422)) }
        for i in 0..<500 { q.add(event: event(i)) }
        q.flush()
        eventually("flush stopped") { lock.lock(); defer { lock.unlock() }; return posts >= 20 }
        Thread.sleep(forTimeInterval: 0.1)
        lock.lock(); XCTAssertEqual(posts, EventQueue.maxPostsPerFlush, "500 all-bad events cost \(posts) POSTs in one flush"); lock.unlock()
        q.flush(); _ = q.count; _ = q.count
        lock.lock(); XCTAssertEqual(posts, 20, "flushed again inside the backoff"); lock.unlock()

        // 8 events, the first bad: 8 → 4 → 2 → 1 (dropped) → 1 (ok) → 2 → 4.
        let (s2, _) = freshStorage()
        let q2 = EventQueue(storage: s2, flushAt: 1000)
        q2.jitter = { _ in 0 }
        var sizes: [Int] = []
        q2.setFlushHandler { chunk, done in
            lock.lock(); sizes.append(chunk.count); lock.unlock()
            done(chunk.contains { ($0["eventType"] as? String) == "bad" } ? .rejected(status: 400) : .accepted)
        }
        q2.add(event: ["eventType": "bad"])
        for i in 1..<8 { q2.add(event: event(i)) }
        q2.flush()
        eventually("drained") { q2.count == 0 }
        lock.lock(); XCTAssertEqual(sizes, [8, 4, 2, 1, 1, 2, 4]); lock.unlock()
    }

    func test_threeAnswered5xxOnTheSameChunkHalveIt_soAPoisonEventIsIsolated() {
        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.jitter = { _ in 0 }
        let lock = NSLock()
        var delivered: [String] = []
        var sizes: [Int] = []
        q.setFlushHandler { chunk, done in
            let names = chunk.compactMap { $0["eventType"] as? String }
            lock.lock(); sizes.append(chunk.count); lock.unlock()
            if names.contains("poison") { return done(.retryLater(countsAttempt: true, status: 500)) }
            lock.lock(); delivered += names; lock.unlock()
            done(.accepted)
        }
        for i in 0..<5 { q.add(event: event(i)) }
        q.add(event: ["eventType": "poison"])
        for i in 5..<10 { q.add(event: event(i)) }
        // Isolated, the lone poison event follows the normal 50-attempt budget, then its neighbours go.
        for _ in 0..<200 where q.count > 0 {
            q.flush(); _ = q.count; _ = q.count
            Thread.sleep(forTimeInterval: 0.001)
        }
        lock.lock(); defer { lock.unlock() }
        XCTAssertEqual(Set(delivered), Set((0..<10).map { "e\($0)" }), "the good neighbours of a 5xx-poison event were never delivered")
        XCTAssertEqual(q.count, 0, "the poison event outlived its budget")
        XCTAssertEqual(Array(sizes.prefix(4)), [11, 11, 11, 5], "halved only after the 3rd answered 5xx on the same chunk")
    }

    func test_cloudflareOriginErrorsAreUnanswered() {
        for s in [520, 521, 522, 523, 524, 525, 526, 527, 530] {
            let r = APIClient.RichResponse(statusCode: s, body: nil, errorCode: nil, errorMessage: nil)
            XCTAssertEqual(APIClient.deliveryOutcome(r), .retryLater(countsAttempt: false, status: s), "\(s)")
        }
        let r = APIClient.RichResponse(statusCode: 528, body: nil, errorCode: nil, errorMessage: nil)
        XCTAssertEqual(APIClient.deliveryOutcome(r), .retryLater(countsAttempt: true, status: 528))
    }

    func test_identityTokenIsAttachedAtSendTime_neverPersisted_andCountedInTheByteCap() {
        XCTAssertEqual(SendoraCloud.decorateForSend(["userId": "u1"], currentUserId: "u1", identityToken: "tok")["identityToken"] as? String, "tok")
        XCTAssertNil(SendoraCloud.decorateForSend(["userId": "u2"], currentUserId: "u1", identityToken: "tok")["identityToken"], "another user's event got the token")
        XCTAssertNil(SendoraCloud.decorateForSend(["anonymousId": "a"], currentUserId: "u1", identityToken: "tok")["identityToken"])
        XCTAssertNil(SendoraCloud.decorateForSend(["userId": "u1"], currentUserId: "u1", identityToken: nil)["identityToken"])

        let (storage, _) = freshStorage()
        let q = EventQueue(storage: storage, flushAt: 1000)
        q.jitter = { _ in 0 }
        let token = Box<String?>(nil)
        let bigToken = String(repeating: "t", count: 4_000)
        q.decorator = { SendoraCloud.decorateForSend($0, currentUserId: "u1", identityToken: token.v) }
        let lock = NSLock()
        var sent: [[[String: Any]]] = []
        let fail = Box(true)
        q.setFlushHandler { chunk, done in lock.lock(); sent.append(chunk); lock.unlock(); done(fail.v ? .retryLater(countsAttempt: false) : .accepted) }
        for i in 0..<40 { q.add(event: ["eventType": "e\(i)", "userId": "u1", "properties": ["blob": String(repeating: "x", count: 1_000)]]) }
        q.flush(); _ = q.count; _ = q.count
        // Queued before identify() handed over a token; the token arrives later.
        token.v = bigToken
        fail.v = false
        q.flush()
        eventually("drained") { q.count == 0 }
        lock.lock(); defer { lock.unlock() }
        XCTAssertNil(sent.first?.first?["identityToken"])
        let later = sent.dropFirst()
        XCTAssertTrue(later.allSatisfy { $0.allSatisfy { ($0["identityToken"] as? String) == bigToken } }, "a later send did not carry the current token")
        for chunk in later {
            let bytes = (try? JSONSerialization.data(withJSONObject: ["events": chunk]).count) ?? 0
            XCTAssertLessThanOrEqual(bytes, 60_000, "the token's bytes were not counted")
        }
        XCTAssertFalse(String(data: (try? JSONSerialization.data(withJSONObject: storage.loadEventQueue())) ?? Data(), encoding: .utf8)?.contains("ttttt") ?? true)
    }

    // MARK: - Found live on staging: a nil projectId went out as JSON null (422 on every event)

    func test_anEventWithoutAProjectIdOmitsTheField_neverSendsNull() throws {
        let e = SendoraCloud.buildEvent(name: "x", properties: nil, projectId: nil, device: [:], sessionId: "s",
                                        consentGranted: true, userId: nil, anonymousId: "a", timestamp: Date())
        let json = String(data: try JSONSerialization.data(withJSONObject: e), encoding: .utf8) ?? ""
        XCTAssertFalse(json.contains("projectId"), "a nil projectId reached the wire: \(json)")
        XCTAssertFalse(json.contains("null"), json)
        let withId = SendoraCloud.buildEvent(name: "x", properties: nil, projectId: "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b", device: [:],
                                             sessionId: "s", consentGranted: true, userId: nil, anonymousId: nil, timestamp: Date())
        XCTAssertEqual(withId["projectId"] as? String, "6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b")
    }

    func test_noSourceBuildsABodyWithAnOptionalProjectIdDirectly() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent("Sources/SendoraCloud/SendoraCloud.swift"), encoding: .utf8)
        XCTAssertFalse(source.contains("\"projectId\": config.projectId"), "an optional projectId in a body literal serialises as null")
        XCTAssertFalse(source.contains("\"projectId\": projectId as Any"))
    }
}
