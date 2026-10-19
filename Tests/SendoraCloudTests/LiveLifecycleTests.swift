import XCTest
@testable import SendoraCloud

/// The ADR-033 auth lifecycle, LIVE against staging, driven by THIS SDK (contract 2,
/// `scripts/e2e/live-run-contract.mjs`). A port of `scripts/e2e/auth-lifecycle.mts` (phases A, B, W1) onto the iOS
/// public API: real `SendoraCloudAuth` / `EventQueue` over a real `URLSession` that KEEPS COOKIES the way a phone's
/// does (`URLSessionConfiguration.default` + its own `HTTPCookieStorage`) — the s58.360 condition: after a sign-in
/// the jar holds the ACCOUNT's `sd_rt`, and the server must still answer a held guest's refresh for the guest.
/// ("Disk" = the in-memory recording stores, shared between SDK instances, so a cold start is real; the Keychain
/// itself is not exercised in `swift test`.)
///
/// Skipped unless `SENDORA_LIVE=1`. Fail-fast like the reference: the first failing step is recorded and the run
/// stops (later steps on a broken earlier one prove nothing); cleanup of created accounts runs either way.
final class LiveLifecycleTests: XCTestCase {

    // MARK: - A phone-like wire (cookie jar ON) + a recorder

    struct Seen { let method: String; let path: String; let status: Int; let bodyKeys: Set<String> }

    final class JarTransport: SendoraHTTPTransport {
        let jar: HTTPCookieStorage
        let session: URLSession
        private let lock = NSLock()
        private var seenLog: [Seen] = []

        init() {
            jar = HTTPCookieStorage.sharedCookieStorage(forGroupContainerIdentifier: "f67-live-ios-\(UUID().uuidString)")
            jar.cookieAcceptPolicy = .always
            let config = URLSessionConfiguration.default
            config.httpCookieStorage = jar
            config.httpCookieAcceptPolicy = .always
            config.httpShouldSetCookies = true
            config.timeoutIntervalForRequest = 20
            config.urlCache = nil
            session = URLSession(configuration: config)
        }

        func perform(_ request: URLRequest, completion: @escaping (Data?, HTTPURLResponse?, Error?) -> Void) {
            precondition(request.url?.host == LiveEnv.stagingHost, "the live lifecycle may only reach staging")
            let keys = Set(((request.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }) ?? [:]).keys)
            let path = request.url?.path ?? ""
            session.dataTask(with: request) { [weak self] data, response, error in
                let http = response as? HTTPURLResponse
                self?.lock.lock()
                self?.seenLog.append(Seen(method: request.httpMethod ?? "GET", path: path, status: http?.statusCode ?? 0, bodyKeys: keys))
                self?.lock.unlock()
                completion(data, http, error)
            }.resume()
        }

        var seen: [Seen] { lock.lock(); defer { lock.unlock() }; return seenLog }
        func last(_ method: String, _ suffix: String) -> Seen? { seen.last { $0.method == method && $0.path.hasSuffix(suffix) } }
        func since(_ mark: Int) -> [Seen] { Array(seen.dropFirst(mark)) }
        func cookie(_ name: String) -> String? {
            jar.cookies(for: URL(string: "https://\(LiveEnv.stagingHost)/api/v1/auth-service/token/refresh")!)?.first { $0.name == name }?.value
        }
    }

    // MARK: - State

    private var cfg: LiveEnv.Config!
    private var wire: JarTransport!
    private var client: APIClient!
    private var failures: [String] = []
    private var evidence: [String] = []
    private var stopped = false
    private var cleanups: [() -> Void] = []

    override func setUpWithError() throws {
        cfg = try LiveEnv.require()
        wire = JarTransport()
        client = APIClient(baseUrl: cfg.base, apiKey: cfg.apiKey, transport: wire)
    }

    // MARK: - Harness

    private func ok(_ c: Bool, _ m: String) { if c { evidence.append(m) } else { failures.append(m) } }

    /// One contract step. Records pass/fail with its evidence; a failure stops the run.
    private func step(_ id: String, _ body: () throws -> Void) {
        guard !stopped else { return }
        failures = []; evidence = []
        do { try body() } catch { failures.append("threw: \(error)") }
        let pass = failures.isEmpty
        LiveReport.shared.record(id, pass: pass, detail: pass ? evidence.joined(separator: "; ") : "FAILED: " + failures.joined(separator: "; "))
        if !pass {
            stopped = true
            XCTFail("[\(id)] " + LiveReport.scrub(failures.joined(separator: "; ")))
        }
    }

    private func sync<T>(timeout: TimeInterval = 40, _ body: (@escaping (T) -> Void) -> Void) -> T? {
        let sem = DispatchSemaphore(value: 0)
        var out: T?
        let lock = NSLock()
        body { v in lock.lock(); out = v; lock.unlock(); sem.signal() }
        guard sem.wait(timeout: .now() + timeout) == .success else { return nil }
        lock.lock(); defer { lock.unlock() }
        return out
    }

    private func syncVoid(timeout: TimeInterval = 40, _ body: (@escaping () -> Void) -> Void) {
        let sem = DispatchSemaphore(value: 0)
        body { sem.signal() }
        _ = sem.wait(timeout: .now() + timeout)
    }

    private struct Raw { let status: Int; let body: [String: Any] }

    /// A raw API call through the SAME cookie-jar session (the reference's `raw()` goes through the jar too).
    private func raw(_ method: String, _ path: String, _ body: [String: Any]? = nil, bearer: String? = nil,
                     headers: [String: String] = [:], apiKey: Bool = true) -> Raw {
        var req = URLRequest(url: URL(string: "\(cfg.base)/api/v1\(path)")!)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if apiKey { req.setValue(cfg.apiKey, forHTTPHeaderField: "X-API-Key") }
        req.setValue(SendoraCloud.sdkName, forHTTPHeaderField: "X-Sendora-SDK-Name")
        req.setValue(SendoraCloud.sdkVersion, forHTTPHeaderField: "X-Sendora-SDK-Version")
        if let b = bearer { req.setValue("Bearer \(b)", forHTTPHeaderField: "Authorization") }
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        if let body = body { req.httpBody = try? JSONSerialization.data(withJSONObject: body) }
        let r: (Data?, HTTPURLResponse?)? = sync(timeout: 30) { done in
            self.wire.perform(req) { data, http, _ in done((data, http)) }
        }
        let json = r?.0.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
        return Raw(status: r?.1?.statusCode ?? 0, body: json)
    }

    private func data(_ r: Raw) -> [String: Any] { r.body["data"] as? [String: Any] ?? [:] }
    private func tokens(_ r: Raw) -> [String: Any] { data(r)["tokens"] as? [String: Any] ?? [:] }
    private func err(_ r: Raw) -> [String: Any] { r.body["error"] as? [String: Any] ?? [:] }
    private func errMessage(_ r: Raw) -> String { err(r)["message"] as? String ?? "" }

    private func claims(_ jwt: String?) -> [String: Any] {
        guard let jwt = jwt else { return [:] }
        let parts = jwt.split(separator: ".")
        guard parts.count >= 2 else { return [:] }
        var b = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        return (Data(base64Encoded: b).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }) ?? [:]
    }

    private static func rand() -> String { String(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(8)).lowercased() }
    private static func short(_ s: String) -> String { String(s.prefix(8)) }

    /// The only honest proof a server row is gone: its refresh token is refused (401). A shared-IP refresh backoff
    /// (429) is waited out and retried.
    private func assertRefreshDead(_ label: String, _ refresh: String) {
        var r = raw("POST", "/auth-service/token/refresh", ["refreshToken": refresh])
        var tries = 0
        while r.status == 429 && tries < 3 {
            Thread.sleep(forTimeInterval: Double((err(r)["details"] as? [String: Any])?["retryAfterSeconds"] as? Int ?? 10) + 1)
            r = raw("POST", "/auth-service/token/refresh", ["refreshToken": refresh]); tries += 1
        }
        ok(r.status == 401, "\(label): its refresh token is now refused (\(r.status) \(err(r)["code"] as? String ?? ""))")
    }

    private func newAuth(_ secure: RecordingSecureStore, _ plain: RecordingPlainStore, expectedProjectId: String? = nil) -> SendoraCloudAuth {
        SendoraCloudAuth(client: client, storage: SendoraStorage(secure: secure, plain: plain),
                         config: .init(expectedProjectId: expectedProjectId, configProjectId: nil, autoRestoreHeldGuest: true, schedulesTimers: false),
                         onIdentityChange: { _ in }, onIdentityCleared: { _ in }, onIdentityWithheld: {})
    }

    final class EventLog {
        private let lock = NSLock()
        private var names: [String] = []
        func add(_ n: String) { lock.lock(); names.append(n); lock.unlock() }
        var count: Int { lock.lock(); defer { lock.unlock() }; return names.count }
        func since(_ n: Int) -> String { lock.lock(); defer { lock.unlock() }; return names.dropFirst(n).joined(separator: ",") }
    }

    /// Subscribe AFTER construction; the subscribe-time replay is dropped — only real transitions are recorded.
    private func record(_ auth: SendoraCloudAuth) -> EventLog {
        let log = EventLog()
        let live = BoolBox()
        _ = auth.onAuthStateChanged { [weak auth] e in
            guard live.v else { return }
            switch e {
            case .signedIn: log.add("signed_in{\(auth?.lastSignedInCause()?.rawValue ?? "?")}")
            case .signedOut(let r): log.add("signed_out{\(r.rawValue)}")
            case .userUpdated(_, let c): log.add("user_updated{\(c.rawValue)}")
            case .guestReleased(_, let r, _): log.add("guest_released{\(r.rawValue)}")
            default: log.add(e.eventName)
            }
        }
        live.v = true
        return log
    }
    final class BoolBox { var v = false }

    private func mintSpacing() { Thread.sleep(forTimeInterval: 2.2) } // mint limiter 30/min, shared with other agents

    private func signIn(_ auth: SendoraCloudAuth, _ email: String, _ password: String) -> Result<SendoraCloudAuthUser, SendoraCloudAuthError>? {
        sync { done in auth.signIn(email: email, password: password, completion: done) }
    }

    private func mint(_ auth: SendoraCloudAuth) -> Result<SendoraCloudAuthUser, SendoraCloudAuthError>? {
        mintSpacing()
        return sync { done in auth.signInAnonymously(completion: done) }
    }

    private static let gcBogus: [String: Any] = [
        "publicKeyUrl": "https://static.gc.apple.com/public-key/gc-prod-9.cer",
        "signature": "bm90LWEtcmVhbC1zaWduYXR1cmU=", "salt": "c2FsdA==",
        "timestamp": Int(Date().timeIntervalSince1970 * 1000), "teamPlayerId": "T:_e2e_not_a_real_player",
        "bundleId": "com.sendora.e2e.invalid",
    ]
    private static let gcCredential = SendoraCloudCredential.gameCenter(
        publicKeyURL: "https://static.gc.apple.com/public-key/gc-prod-9.cer", signature: "bm90LWEtcmVhbC1zaWduYXR1cmU=",
        salt: "c2FsdA==", timestamp: UInt64(Date().timeIntervalSince1970 * 1000), teamPlayerID: "T:_e2e_not_a_real_player",
        bundleID: "com.sendora.e2e.invalid")

    // MARK: - The run

    func test_live_lifecycle() throws {
        let runStarted = Date()
        defer { for c in cleanups.reversed() { c() } }

        // ═════ PHASE A — regression probes (s58.271 / s58.272) ═════
        let aSecure = RecordingSecureStore(), aPlain = RecordingPlainStore()
        var anonId = ""

        step("A1") {
            let a = newAuth(aSecure, aPlain)
            guard case .success(let u)? = mint(a) else { return ok(false, "signInAnonymously failed") }
            anonId = u.id
            ok(!u.id.isEmpty && u.isAnonymous, "minted an anonymous user (\(Self.short(u.id))…)")
            ok(aSecure.get("sendora_auth_refresh_token") != nil, "refresh token persisted")
            ok(wire.last("POST", "/auth-service/anonymous")?.status == 201, "POST /auth-service/anonymous → \(wire.last("POST", "/auth-service/anonymous")?.status ?? 0)")
        }

        step("A2") {
            let a = newAuth(aSecure, aPlain)
            let before = aSecure.get("sendora_auth_refresh_token")
            let mark = wire.seen.count
            let r: Result<SendoraCloudAuthUser, SendoraCloudAuthError>? = sync { done in a.signInAnonymously(completion: done) }
            guard case .success(let u)? = r else { return ok(false, "signInAnonymously failed") }
            ok(u.id == anonId, "same user id returned, no new account")
            ok(aSecure.get("sendora_auth_refresh_token") == before, "refresh token untouched")
            ok(!wire.since(mark).contains { $0.path.hasSuffix("/auth-service/anonymous") }, "no mint request was sent")
        }

        step("A3") {
            // Expire the stored access token on the shared "disk", then cold-start a NEW instance.
            let expired = Int64(Date().timeIntervalSince1970 * 1000) - 60_000
            aSecure.set("sendora_auth_access_expires", String(expired))
            if let json = aSecure.get(SendoraStorage.authSessionKey), var rec = SendoraCloudAuth.decodeSessionRecord(json) {
                rec.accessExpiresAt = expired
                aSecure.set(SendoraStorage.authSessionKey, SendoraCloudAuth.encodeSessionRecord(rec)!)
            }
            let beforeRefresh = aSecure.get("sendora_auth_refresh_token")
            let a = newAuth(aSecure, aPlain)
            ok(a.currentUser?.id == anonId, "session restored from storage")
            let t: String?? = sync { done in a.getAccessToken(completion: done) }
            let token = t ?? nil
            ok(token?.split(separator: ".").count == 3, "REFRESH SUCCEEDED — a fresh access token was minted")
            ok(wire.last("POST", "/auth-service/token/refresh")?.status == 200, "POST /auth-service/token/refresh → \(wire.last("POST", "/auth-service/token/refresh")?.status ?? 0)")
            ok(aSecure.get("sendora_auth_refresh_token") != beforeRefresh, "refresh token rotated (a real round-trip)")
            ok(a.currentUser?.id == anonId, "identity preserved across the refresh")
            let c = claims(token)
            ok(c["sub"] as? String == anonId, "the new token's sub is the same account")
            ok(((c["exp"] as? NSNumber)?.doubleValue ?? 0) > Date().timeIntervalSince1970, "the new token is not already expired")
        }

        step("A4") {
            let a = newAuth(aSecure, aPlain)
            let before = aSecure.get("sendora_auth_refresh_token")
            let beforeUser = a.currentUser?.id
            let r = signIn(a, "nobody-\(Self.rand())@example.invalid", "wrong-password")
            guard case .failure(let e)? = r else { return ok(false, "a wrong password signed in") }
            ok(true, "rejected (\(e.code ?? "?") / \(e.status ?? 0)), kind \(e.kind.rawValue)")
            ok(aSecure.get("sendora_auth_refresh_token") == before, "refresh token UNCHANGED after the failure")
            ok(a.currentUser?.id == beforeUser, "user UNCHANGED after the failure")
        }

        step("A5") {
            let good = raw("POST", "/auth-service/login/game-center", Self.gcBogus.merging(["onCredentialInUse": "reject"]) { $1 })
            let goodField = ((err(good)["details"] as? [String: Any])?["fieldErrors"] as? [String: Any])?["onCredentialInUse"]
            ok(goodField == nil, "\"reject\" passes validation (\(good.status))")
            ok(errMessage(good).range(of: "not configured|signature|bundle", options: [.regularExpression, .caseInsensitive]) != nil,
               "…and reaches the credential verifier")
            let bad = raw("POST", "/auth-service/login/game-center", Self.gcBogus.merging(["onCredentialInUse": "merge"]) { $1 })
            let badField = (((err(bad)["details"] as? [String: Any])?["fieldErrors"] as? [String: Any])?["onCredentialInUse"] as? [String])?.first ?? ""
            ok(!badField.isEmpty, "a bogus policy IS rejected, by name (\(bad.status))")
            ok(badField.contains("'adopt' | 'reject'"), "…naming the exact enum")
        }

        step("A6") {
            let a = newAuth(aSecure, aPlain)
            let t: String?? = sync { done in a.getAccessToken(completion: done) }
            guard let token = t ?? nil else { return ok(false, "no access token for the guest") }
            ok(a.currentUser?.isAnonymous == true, "caller is genuinely anonymous")
            let gc = raw("POST", "/auth-service/me/link/game-center", Self.gcBogus, bearer: token)
            ok(errMessage(gc).range(of: "not configured|signature|bundle", options: [.regularExpression, .caseInsensitive]) != nil,
               "anon reached the credential verifier (\(gc.status))")
            ok(errMessage(gc).range(of: "Anonymous accounts", options: .caseInsensitive) == nil, "…the anon link guard no longer refuses it")
            let em = raw("POST", "/auth-service/me/link/email", ["email": "e2e-\(Self.rand())@example.invalid", "password": "Sup3rSecret!x"], bearer: token)
            ok(em.status == 200, "link/email promotes an anonymous caller (\(em.status))")
            ok(data(em)["upgraded"] as? Bool == true, "…returning upgraded:true")
            ok(tokens(em)["accessToken"] != nil && tokens(em)["refreshToken"] != nil, "…with a fresh token pair")
            ok((data(em)["user"] as? [String: Any])?["isAnonymous"] as? Bool == false, "…and the user is no longer anonymous")
            if let access = tokens(em)["accessToken"] as? String {
                cleanups.append { _ = self.raw("DELETE", "/auth-service/me", bearer: access) }
            }
        }

        step("A7") {
            let a = newAuth(aSecure, aPlain)
            syncVoid { done in a.signOut(completion: done) }
            ok(aSecure.get("sendora_auth_refresh_token") == nil, "local session cleared")
            ok(a.status() == .signedOut, "status() signed_out")
        }

        // ═════ PHASE B — the ADR-033 wave-1 lifecycle ═════
        let secure = RecordingSecureStore(), plain = RecordingPlainStore()
        let storage = SendoraStorage(secure: secure, plain: plain)
        let runId = "e2e-ios-\(Self.rand())"
        let email = "\(runId)@sendora-e2e.invalid"
        let emailTaken = "\(runId)-taken@sendora-e2e.invalid"
        let password = "E2e-\(Self.rand())Aa1!"
        var accountId = "", guestB = "", guestBRefresh = "", guestC = "", guestCRefresh = "", guestD = ""
        var takenAccountId = "", takenAccess = "", orgId = ProcessInfo.processInfo.environment["SENDORA_ORG_ID"] ?? ""
        let wrongProject = "00000000-0000-4000-8000-00000000dead"
        let sdk = newAuth(secure, plain)
        let ev = record(sdk)
        func heldIds() -> [String] { sdk.heldGuests().map { $0.userId } }
        func slot0() -> HeldSlotRecord? { secure.get(SendoraStorage.heldSlotKeys[0]).flatMap { HeldSlotRecord.decode($0) } }
        func accessToken(_ force: Bool = false) -> String? { (sync { done in sdk.getAccessToken(forceRefresh: force, completion: done) } as String??) ?? nil }

        step("B1") {
            ok(sdk.status() == .signedOut, "status() before any session is signed_out (\(sdk.status().rawValue))")
            let mark = wire.seen.count
            guard case .success(let u)? = mint(sdk) else { return ok(false, "mint failed") }
            accountId = u.id
            ok(u.isAnonymous, "guest A minted (\(Self.short(u.id))…)")
            let mintReq = wire.since(mark).first { $0.path.hasSuffix("/auth-service/anonymous") }
            ok(mintReq?.status == 201 && mintReq?.bodyKeys.contains("mintKey") == true, "POST /anonymous \(mintReq?.status ?? 0) carried a mintKey")
            ok(sdk.status() == .anonymous, "status() anonymous")
            ok(secure.get(SendoraStorage.authSessionKey) != nil, "auth_session record dual-written")
            ok(storage.schemaVersion == "2", "schema_version = \(storage.schemaVersion ?? "nil")")
            let c = claims(accessToken())
            ok(c["sub"] as? String == accountId && c["is_anonymous"] as? Bool == true, "JWT sub = the guest, is_anonymous=true")
            if orgId.isEmpty { orgId = c["org"] as? String ?? "" }
            ok(!orgId.isEmpty, "org resolved for the delivery-log read")
            ok(c.keys.contains("project"), "JWT carries the project claim")
            ok(ev.since(0) == "signed_in{mint}", "events: \(ev.since(0))")
        }

        step("B2") {
            let q = EventQueue(storage: SendoraStorage(secure: RecordingSecureStore(), plain: RecordingPlainStore()), flushAt: 1000)
            q.jitter = { _ in 0 }
            let c = client!
            q.setFlushHandler { events, done in SendoraCloud.flushEvents(events, client: c, completion: done) }
            q.add(event: SendoraCloud.buildEvent(name: "e2e.lifecycle", properties: ["runId": runId, "step": "B2"], projectId: nil,
                                                 device: ["os": "iOS"], sessionId: UUID().uuidString, consentGranted: true,
                                                 userId: accountId, anonymousId: nil, timestamp: Date()))
            let mark = wire.seen.count
            q.flush()
            let deadline = Date().addingTimeInterval(20)
            while Date() < deadline && q.count > 0 { Thread.sleep(forTimeInterval: 0.2) }
            let post = wire.since(mark).first { $0.path.hasSuffix("/events") || $0.path.hasSuffix("/events/batch") }
            ok((200..<300).contains(post?.status ?? 0) && q.count == 0, "POST \(post?.path.components(separatedBy: "/api/v1").last ?? "?") → \(post?.status ?? 0), queue drained")
        }

        step("B3") {
            let before = secure.get("sendora_auth_refresh_token")
            let n = ev.count
            let t = accessToken(true)
            ok(wire.last("POST", "/auth-service/token/refresh")?.status == 200, "POST /token/refresh → \(wire.last("POST", "/auth-service/token/refresh")?.status ?? 0)")
            ok(claims(t)["sub"] as? String == accountId, "sub unchanged")
            ok(secure.get("sendora_auth_refresh_token") != before, "refresh token rotated")
            ok(SendoraCloudAuth.decodeSessionRecord(secure.get(SendoraStorage.authSessionKey) ?? "")?.refreshToken == secure.get("sendora_auth_refresh_token"),
               "auth_session and the frozen key rotated together")
            ok(ev.count == n, "a rotation emits nothing")
        }

        step("B4") {
            let n = ev.count
            let r: Result<SendoraCloudAuthUser, SendoraCloudAuthError>? = sync { done in sdk.signUp(email: email, password: password, completion: done) }
            ok(wire.last("POST", "/auth-service/me/link/email")?.status == 200, "POST /me/link/email → \(wire.last("POST", "/auth-service/me/link/email")?.status ?? 0)")
            ok(wire.last("POST", "/auth-service/upgrade") == nil, "POST /upgrade never called (INV-4)")
            guard case .success(let u)? = r else { return ok(false, "signUp failed") }
            ok(u.id == accountId && !u.isAnonymous, "same sub, isAnonymous=false (upgraded in place)")
            ok(u.email?.lowercased() == email, "email set")
            ok(sdk.status() == .identified, "status() identified")
            ok(claims(accessToken())["is_anonymous"] as? Bool == false, "the new JWT says is_anonymous=false")
            ok(ev.since(n) == "signed_in{link}", "events: \(ev.since(n))")
            ok(heldIds().isEmpty, "a promotion never holds")
        }

        step("B5") {
            let n = ev.count
            syncVoid { done in sdk.signOut(completion: done) }
            ok(secure.get("sendora_auth_refresh_token") == nil && secure.get(SendoraStorage.authSessionKey) == nil, "refresh token + auth_session cleared")
            ok(sdk.currentUser == nil && sdk.status() == .signedOut, "currentUser nil, status signed_out")
            ok(ev.since(n) == "signed_out{user}", "events: \(ev.since(n))")
            ok(heldIds().isEmpty && (0..<5).allSatisfy { secure.get(SendoraStorage.heldSlotKeys[$0]) == nil }, "held slots untouched (empty)")
            let login = raw("POST", "/auth-service/login", ["email": email, "password": password])
            ok(login.status == 200 && (data(login)["user"] as? [String: Any])?["id"] as? String == accountId, "the account still signs in (\(login.status))")
            if let rt = tokens(login)["refreshToken"] as? String { _ = raw("POST", "/auth-service/token/revoke", ["refreshToken": rt]) }
        }

        step("W1-a") {
            guard case .success(let g)? = mint(sdk) else { return ok(false, "mint B failed") }
            guestB = g.id
            ok(g.isAnonymous && g.id != accountId, "guest B minted (\(Self.short(g.id))…)")
            ok(wire.last("POST", "/auth-service/anonymous")?.status == 201, "a FRESH mint")
            let n = ev.count
            let r = signIn(sdk, email, password)
            ok(wire.last("POST", "/auth-service/login")?.status == 200, "POST /login → \(wire.last("POST", "/auth-service/login")?.status ?? 0)")
            guard case .success(let u)? = r else { return ok(false, "sign-in failed") }
            ok(u.id == accountId && sdk.status() == .identified, "signed into the account")
            ok(ev.since(n) == "guest_held,signed_in{sign_in}", "events: \(ev.since(n))")
            ok(heldIds() == [guestB], "heldGuests() = [B]")
            let s0 = slot0()
            ok(s0?.userId == guestB && !(s0?.refreshToken ?? "").isEmpty, "the slot is the LITERAL key sendora_auth_held_0 with B's refresh token")
            guestBRefresh = s0?.refreshToken ?? ""
            let jarRt = wire.cookie("sd_rt")
            ok(jarRt != nil && jarRt != guestBRefresh, "the cookie jar holds the ACCOUNT's sd_rt (≠ the held guest's) — the phone condition")
            ok(sdk.getLastAnonRetirement()?.rawValue == "none", "anonRetirement = \(sdk.getLastAnonRetirement()?.rawValue ?? "nil") (no guest token presented)")
            ok(sdk.getLastDeviceTakeover() == nil, "onDeviceTakeover never fired")
            let deadline = Date().addingTimeInterval(8)
            while Date() < deadline && wire.last("POST", "/auth-service/guest/held") == nil { Thread.sleep(forTimeInterval: 0.1) }
            ok(wire.last("POST", "/auth-service/guest/held")?.status == 200, "POST /guest/held → \(wire.last("POST", "/auth-service/guest/held")?.status ?? 0) (B15 report)")
        }

        step("W1-b") {
            let n = ev.count
            let mark = wire.seen.count
            let r: Result<SendoraCloudClaimResult, SendoraCloudAuthError>? = sync { done in sdk.claimHeldGuest(id: guestB, completion: done) }
            let calls = wire.since(mark)
            ok(wire.last("POST", "/auth-service/merge")?.status == 200, "POST /merge → \(wire.last("POST", "/auth-service/merge")?.status ?? 0)")
            let refreshIdx = calls.lastIndex { $0.path.hasSuffix("/token/refresh") }
            let mergeIdx = calls.lastIndex { $0.path.hasSuffix("/merge") }
            ok(refreshIdx != nil && mergeIdx != nil && refreshIdx! < mergeIdx!, "the held token was refreshed BEFORE the merge")
            guard case .success(let c)? = r else { return ok(false, "claim failed: \(String(describing: r))") }
            ok(c.user.id == accountId, "still the account")
            ok(c.stats.mergedUserId == accountId && c.stats.deletedAnonymousId == guestB, "stats name the merge (pushTokensReassigned=\(c.stats.pushTokensReassigned))")
            ok(ev.since(n) == "user_updated{merge},guest_released{claimed}", "events: \(ev.since(n))")
            ok(heldIds().isEmpty && slot0() == nil, "the slot is released")
            ok(sdk.status() == .identified, "still identified")
            assertRefreshDead("guest B (merged)", guestBRefresh)
        }

        step("W1-c") {
            syncVoid { done in sdk.signOut(completion: done) }
            guard case .success(let g)? = mint(sdk) else { return ok(false, "mint C failed") }
            guestC = g.id
            ok(g.isAnonymous && ![accountId, guestB].contains(g.id), "guest C minted (\(Self.short(g.id))…)")
            guard case .success(let u)? = signIn(sdk, email, password), u.id == accountId else { return ok(false, "sign-in failed") }
            let accountRefresh = secure.get("sendora_auth_refresh_token")
            let n = ev.count
            let r: Result<SendoraCloudAuthUser, SendoraCloudAuthError>? = sync { done in sdk.restoreHeldGuest(id: guestC, completion: done) }
            guard case .success(let back)? = r else { return ok(false, "restore failed") }
            ok(back.id == guestC && back.isAnonymous, "restored: current user is C")
            ok(sdk.status() == .anonymous, "status() anonymous")
            ok(ev.since(n) == "signed_in{restore},guest_released{restored}", "events: \(ev.since(n))")
            ok(heldIds().isEmpty, "the slot is released")
            ok(secure.get("sendora_auth_refresh_token") != accountRefresh, "the account's local tokens are replaced by C's")
            ok(claims(accessToken())["sub"] as? String == guestC, "the live JWT sub is C")
            let login = raw("POST", "/auth-service/login", ["email": email, "password": password])
            ok(login.status == 200, "the account still signs in (\(login.status)) — nothing deleted")
            if let rt = tokens(login)["refreshToken"] as? String { _ = raw("POST", "/auth-service/token/revoke", ["refreshToken": rt]) }
        }

        step("W1-d") {
            guard case .success(let u)? = signIn(sdk, email, password), u.id == accountId else { return ok(false, "sign-in failed") }
            guestCRefresh = slot0()?.refreshToken ?? ""
            ok(!guestCRefresh.isEmpty && slot0()?.userId == guestC, "C's slot holds its refresh token")
            let accountRefresh = secure.get("sendora_auth_refresh_token") ?? ""
            let m1 = raw("POST", "/auth-service/guest/discard", ["refreshToken": accountRefresh])
            let m2 = raw("POST", "/auth-service/guest/discard", ["refreshToken": guestBRefresh])
            let m3 = raw("POST", "/auth-service/guest/discard", ["refreshToken": "bogus_\(Self.rand())\(Self.rand())"])
            ok(m1.status == 404 && m2.status == 404 && m3.status == 404, "404 matrix: account token \(m1.status), dead guest \(m2.status), bogus \(m3.status)")
            ok(heldIds().count == 1, "the refusals touched nothing on the device")
            let n = ev.count
            let r: Result<Void, SendoraCloudAuthError>? = sync { done in sdk.discardHeldGuest(id: guestC, completion: done) }
            if case .failure(let e)? = r { ok(false, "discard failed: \(e.code ?? "?")") }
            ok(wire.last("POST", "/auth-service/guest/discard")?.status == 200, "POST /guest/discard → \(wire.last("POST", "/auth-service/guest/discard")?.status ?? 0)")
            ok(ev.since(n) == "guest_released{discarded}", "events: \(ev.since(n))")
            ok(heldIds().isEmpty && slot0() == nil, "the slot is released")
            ok(sdk.status() == .identified && sdk.currentUser?.id == accountId, "the current session is untouched")
            assertRefreshDead("guest C (discarded)", guestCRefresh)
        }

        step("W1-g") {
            mintSpacing()
            let m = raw("POST", "/auth-service/anonymous", ["name": "\(runId)-taken"])
            let promoted = raw("POST", "/auth-service/me/link/email", ["email": emailTaken, "password": password], bearer: tokens(m)["accessToken"] as? String)
            takenAccountId = (data(promoted)["user"] as? [String: Any])?["id"] as? String ?? ""
            takenAccess = tokens(promoted)["accessToken"] as? String ?? ""
            ok(promoted.status == 200 && !takenAccountId.isEmpty, "a second account owns the taken email (\(Self.short(takenAccountId))…)")
            let takenAccessForCleanup = takenAccess
            cleanups.append { if !takenAccessForCleanup.isEmpty { _ = self.raw("DELETE", "/auth-service/me", bearer: takenAccessForCleanup) } }

            let userBefore = sdk.currentUser?.id
            let refreshBefore = secure.get("sendora_auth_refresh_token")
            let n = ev.count
            let mark = wire.seen.count
            let r: Result<SendoraCloudLinkResult, SendoraCloudAuthError>? = sync { done in sdk.link(.password(email: emailTaken, password: password), completion: done) }
            ok(wire.last("POST", "/auth-service/me/link/email")?.status == 409, "POST /me/link/email → \(wire.last("POST", "/auth-service/me/link/email")?.status ?? 0)")
            // iOS maps the 409 CONFLICT onto its pre-4.13 case `.emailAlreadyTaken` (frozen for compatibility; that
            // case carries no `code` / `status` by design — the wire status is asserted above).
            if case .failure(let e)? = r {
                var typed = false
                if case .emailAlreadyTaken = e { typed = true }
                ok(typed || e.code == "CONFLICT", "link() over an identified account with an email → typed \(typed ? ".emailAlreadyTaken" : (e.code ?? "?")) (kind \(e.kind.rawValue))")
            } else { ok(false, "link() over identified did not reject: \(String(describing: r))") }
            ok(!wire.since(mark).contains { $0.path.range(of: "/auth-service/(login|signup|upgrade)$", options: .regularExpression) != nil }, "never reached a sign-in / signup / upgrade route")
            ok(sdk.currentUser?.id == userBefore && secure.get("sendora_auth_refresh_token") == refreshBefore, "nothing mutated on the 409")
            let legacy: Result<SendoraCloudAuthUser, SendoraCloudAuthError>? = sync { done in sdk.linkEmailPassword(email: emailTaken, password: password, completion: done) }
            if case .failure(let e)? = legacy {
                var typed = false
                if case .emailAlreadyTaken = e { typed = true }
                ok(typed || e.code == "CONFLICT", "linkEmailPassword() rejects (\(typed ? ".emailAlreadyTaken" : (e.code ?? "?")))")
            } else { ok(false, "linkEmailPassword() did not reject") }
            ok(claims(accessToken(true))["sub"] as? String == accountId, "the session survives the refused links")
            let gcMark = wire.seen.count
            let gc: Result<SendoraCloudLinkResult, SendoraCloudAuthError>? = sync { done in sdk.link(Self.gcCredential, completion: done) }
            let gcCalls = wire.since(gcMark)
            ok(gcCalls.contains { $0.path.hasSuffix("/auth-service/me/link/game-center") }, "link(.gameCenter) went to /me/link/game-center")
            ok(!gcCalls.contains { $0.path.hasSuffix("/auth-service/login/game-center") }, "…never /login/game-center")
            if case .success(.done)? = gc { ok(false, "a bogus Game Center credential linked") }
            let soMark = wire.seen.count
            let so: Result<SendoraCloudAuthUser, SendoraCloudAuthError>? = sync { done in sdk.loginSocial(provider: "google", idToken: "not-a-real-id-token", link: true, completion: done) }
            let soCalls = wire.since(soMark)
            ok(soCalls.contains { $0.path.hasSuffix("/auth-service/me/link/social") } && !soCalls.contains { $0.path.hasSuffix("/auth-service/login/social") },
               "loginSocial(link:true) over identified went to /me/link/social, never /login/social")
            if case .success? = so { ok(false, "a bogus social credential succeeded") }
            ok(sdk.currentUser?.id == accountId, "still the account")
            ok(ev.since(n) == "", "no auth-state event from any refusal (got \"\(ev.since(n))\")")
        }

        step("W1-g2") {
            syncVoid { done in sdk.signOut(completion: done) }
            guard case .success(let g)? = mint(sdk) else { return ok(false, "mint D failed") }
            guestD = g.id
            ok(g.isAnonymous && ![accountId, guestB, guestC, takenAccountId].contains(g.id), "guest D minted (\(Self.short(g.id))…)")
            let refreshBefore = secure.get("sendora_auth_refresh_token")
            let n = ev.count
            let mark = wire.seen.count
            let r: Result<SendoraCloudLinkResult, SendoraCloudAuthError>? = sync { done in sdk.link(.password(email: emailTaken, password: password), completion: done) }
            ok(wire.last("POST", "/auth-service/me/link/email")?.status == 409, "POST /me/link/email → 409")
            guard case .success(.credentialInUse(let ctx))? = r else { return ok(false, "link() → \(String(describing: r)), not credential_in_use") }
            ok(ctx.provider == "password" && ctx.collision.rawValue == "email", "typed payload provider=\(ctx.provider) collision=\(ctx.collision.rawValue)")
            ok(sdk.currentUser?.id == guestD && secure.get("sendora_auth_refresh_token") == refreshBefore && ev.since(n) == "", "nothing mutated, no event")
            ok(!wire.since(mark).contains { $0.path.hasSuffix("/auth-service/login") }, "the refusal never reached /login")
            let sw: Result<SendoraCloudSignInResult, SendoraCloudAuthError>? = sync { done in ctx.switchAccount(completion: done) }
            ok(wire.last("POST", "/auth-service/login")?.status == 200, "switchAccount() → POST /login 200")
            guard case .success(.done(let user, let previous, _))? = sw else { return ok(false, "switchAccount → \(String(describing: sw))") }
            ok(user.id == takenAccountId, "switched into the account that owns the email")
            ok(previous?.userId == guestD && previous?.isAnonymous == true && previous?.held == true, "previous = {D, anonymous, held}")
            ok(ev.since(n) == "guest_held,signed_in{sign_in}", "events: \(ev.since(n))")
            ok(heldIds() == [guestD], "heldGuests() = [D]")
            let d: Result<Void, SendoraCloudAuthError>? = sync { done in sdk.discardHeldGuest(id: guestD, completion: done) }
            if case .failure? = d { ok(false, "discard D failed") }
            ok(heldIds().isEmpty, "D discarded (cleanup)")
            syncVoid { done in sdk.signOut(completion: done) }
            guard case .success(let back)? = signIn(sdk, email, password) else { return ok(false, "sign back in failed") }
            ok(back.id == accountId && heldIds().isEmpty, "signed back into the account, nothing held")
        }

        var accountRefreshBeforeWithheld = ""
        step("W1-e") {
            accountRefreshBeforeWithheld = secure.get("sendora_auth_refresh_token") ?? ""
            let beforeSecure = secure.snapshot(), beforePlain = plain.snapshot()
            let writesBefore = secure.writeCount + plain.writeCount
            let w = newAuth(secure, plain, expectedProjectId: wrongProject)
            ok(w.status() == .withheld, "status() \(w.status().rawValue)")
            ok(w.currentUser == nil, "currentUser nil")
            let info = w.withheld()
            let stored = secure.get("sendora_auth_access_token")
            ok(info?.userId == accountId && info?.expectedProjectId == wrongProject && info?.actualProjectId == claims(stored)["project"] as? String,
               "withheld() names the user and both projects")
            let t: String?? = sync { done in w.getAccessToken(completion: done) }
            ok((t ?? nil) == nil && w.accessToken == nil && w.getRefreshToken() == nil, "getAccessToken / accessToken / getRefreshToken all nil")
            ok(secure.snapshot() == beforeSecure && plain.snapshot() == beforePlain && secure.writeCount + plain.writeCount == writesBefore,
               "storage BYTE-IDENTICAL, zero writes after the withheld hydrate")
            let anon: Result<SendoraCloudAuthUser, SendoraCloudAuthError>? = sync { done in w.signInAnonymously(completion: done) }
            if case .failure(let e)? = anon { ok(e.code == "SESSION_WITHHELD" && e.kind == .config, "signInAnonymously() rejects \(e.code ?? "?") (kind \(e.kind.rawValue))") } else { ok(false, "a withheld instance minted") }
            let evW = record(w)
            let discarded: Bool? = sync { done in w.discardWithheld(completion: done) }
            ok(discarded == true, "discardWithheld() → true")
            ok(w.status() == .signedOut && secure.get("sendora_auth_refresh_token") == nil && secure.get(SendoraStorage.authSessionKey) == nil,
               "the frozen keys + auth_session are cleared")
            ok(evW.since(0) == "signed_out{user}", "events: \(evW.since(0))")
            Thread.sleep(forTimeInterval: 1) // the revoke is fire-and-forget
            assertRefreshDead("the account's withheld token (discardWithheld revokes)", accountRefreshBeforeWithheld)
        }

        step("B8") {
            // `sdk` still holds the account in memory (no cross-instance rehydrate on iOS); sign it in afresh.
            let fresh = newAuth(secure, plain)
            let evD = record(fresh)
            guard case .success(let u)? = signIn(fresh, email, password), u.id == accountId else { return ok(false, "sign-in failed") }
            let accountRefresh = secure.get("sendora_auth_refresh_token") ?? ""
            let n = evD.count
            let d: Result<SendoraCloudAuth.AccountDeletionResult, Error>? = sync { done in fresh.deleteAccount(completion: done) }
            ok(wire.last("DELETE", "/auth-service/me")?.status == 200, "DELETE /me → \(wire.last("DELETE", "/auth-service/me")?.status ?? 0)")
            guard case .success(let res)? = d else { return ok(false, "deleteAccount failed") }
            ok(res.status == "purged", "status=\(res.status) (needs deletionGraceDays 0 on the staging project)")
            ok(res.heldGuests == 0, "heldGuests 0")
            ok(evD.since(n) == "signed_out{account_deleted}", "events: \(evD.since(n))")
            ok(fresh.status() == .signedOut, "status() signed_out")
            assertRefreshDead("the account", accountRefresh)
            let login = raw("POST", "/auth-service/login", ["email": email, "password": password])
            ok(login.status == 401, "the credential no longer signs in (\(login.status))")
            let d2 = raw("DELETE", "/auth-service/me", bearer: takenAccess)
            ok(d2.status == 200, "the taken-email account is deleted too (\(d2.status))")
            if d2.status == 200 { takenAccess = "" }
        }

        step("B9") {
            guard let logAuth = cfg.logAuth else { return ok(false, "SENDORA_LOG_AUTH not set — cannot read the delivery log") }
            let header: [String: String] = logAuth.hasPrefix("sk_") || logAuth.hasPrefix("pk_") ? ["X-API-Key": logAuth] : ["Authorization": "Bearer \(logAuth)"]
            struct Want { let type: String; let label: String; let match: ([String: Any]) -> Bool }
            let wants = [
                Want(type: "auth.user_upgraded", label: "user_upgraded(account)") { $0["userId"] as? String == accountId },
                Want(type: "auth.guest_held", label: "guest_held(B)") { $0["guestUserId"] as? String == guestB && $0["identifiedUserId"] == nil },
                Want(type: "auth.user_merged", label: "user_merged(account←B)") { $0["mergedUserId"] as? String == accountId && $0["deletedAnonymousId"] as? String == guestB },
                Want(type: "auth.user_deleted", label: "user_deleted(C, guest_discarded)") { $0["userId"] as? String == guestC && $0["reason"] as? String == "guest_discarded" },
                Want(type: "auth.user_deleted", label: "user_deleted(account)") { $0["userId"] as? String == accountId },
            ]
            var found = Set<String>(), takeovers = 0, lastStatus = 0
            let deadline = Date().addingTimeInterval(45)
            while Date() < deadline && found.count < wants.count {
                let r = raw("GET", "/orgs/\(orgId)/webhooks/logs?eventType=auth.&pageSize=100&withTotal=0", headers: header, apiKey: false)
                lastStatus = r.status
                for row in (r.body["data"] as? [[String: Any]]) ?? [] {
                    let type = row["eventType"] as? String ?? row["event_type"] as? String ?? ""
                    let created = ISO8601DateFormatter().date(from: (row["createdAt"] as? String ?? row["created_at"] as? String ?? "").replacingOccurrences(of: #"\.\d+"#, with: "", options: .regularExpression))
                    if let c = created, c < runStarted.addingTimeInterval(-5) { continue }
                    let payload = row["payload"] as? [String: Any] ?? [:]
                    let p = payload["properties"] as? [String: Any] ?? payload
                    if type == "auth.device_takeover", [guestB, guestC, guestD].contains(p["anonUserId"] as? String ?? "") { takeovers += 1 }
                    for w in wants where !found.contains(w.label) && type == w.type && w.match(p) { found.insert(w.label) }
                }
                if found.count < wants.count { Thread.sleep(forTimeInterval: 1.5) }
            }
            ok(lastStatus == 200, "GET /orgs/…/webhooks/logs → \(lastStatus)")
            for w in wants { ok(found.contains(w.label), "\(w.type) \(w.label) \(found.contains(w.label) ? "logged" : "NOT in the log within 45 s")") }
            ok(takeovers == 0, "no auth.device_takeover for guest B, C or D (found \(takeovers))")
        }
    }
}
