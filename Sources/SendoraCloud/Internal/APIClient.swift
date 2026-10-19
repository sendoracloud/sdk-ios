import Foundation
import CommonCrypto

/// The one seam between `APIClient` and the network (ADR-033 wave 1, 5.4.0).
/// Production is `URLSessionTransport` (the pinned `URLSession` below); the auth
/// conformance suite installs a scripted stub so every row of the shared
/// transition table can be replayed without a server. Completions arrive on an
/// arbitrary thread, exactly as `URLSession`'s do.
protocol SendoraHTTPTransport: AnyObject {
    func perform(_ request: URLRequest, completion: @escaping (Data?, HTTPURLResponse?, Error?) -> Void)
}

/// HTTPS-only client with exponential backoff + circuit breaker.
/// Optionally enforces SPKI certificate pinning when `pinnedSPKIHashes`
/// is non-empty — useful against user-installed enterprise / MitM CAs
/// targeting auth tokens.
final class APIClient: NSObject, URLSessionDelegate {
    private let baseUrl: String
    private let apiKey: String
    private let pinnedSPKIHashes: Set<String>
    private var transport: SendoraHTTPTransport!
    private let lock = NSLock()
    private var consecutiveFailures = 0
    private var nextAllowedAfter: Date = .distantPast

    private let maxBackoff: TimeInterval = 60
    /// 5.6.0 (F67): the longest a server's `Retry-After` may hold the breaker open.
    internal static let maxServerWait: TimeInterval = 3600
    /// 5.6.0 (F67): a Cloudflare challenge (`cf-mitigated`) holds the breaker at least this long.
    internal static let challengeMinWait: TimeInterval = 60
    /// 5.6.0 (review H2): the longest a 429 may hold the WHOLE client. A 429 is the
    /// caller's budget on ONE lane — the events quota 429 asks until the month resets,
    /// which held `/token/refresh`, `/login` and push for an hour, all month. The full
    /// wait still reaches the caller in `RichResponse.retryAfterSeconds` (the event
    /// queue honours it, ≤ 1 h). Android clamps the same way.
    internal static let rateLimitMaxHold: TimeInterval = 60

    /// Test seams (5.6.0). `jitter(ceiling)` draws the full-jitter backoff in
    /// `0...ceiling`; `clock` is the breaker's notion of now.
    internal var jitter: (TimeInterval) -> TimeInterval = { ceiling in ceiling > 0 ? Double.random(in: 0...ceiling) : 0 }
    internal var clock: () -> Date = { Date() }

    /// `transport` is a test seam; `nil` builds the production `URLSession`
    /// (ephemeral, 10 s request / 15 s resource timeouts, pinning delegate).
    init(baseUrl: String, apiKey: String, pinnedSPKIHashes: [String] = [], transport: SendoraHTTPTransport? = nil) {
        self.baseUrl = baseUrl.hasSuffix("/") ? String(baseUrl.dropLast()) : baseUrl
        self.apiKey = apiKey
        self.pinnedSPKIHashes = Set(pinnedSPKIHashes)
        super.init()
        if let transport = transport {
            self.transport = transport
        } else {
            let config = Self.makeSessionConfiguration()
            self.transport = URLSessionTransport(session: URLSession(configuration: config, delegate: self, delegateQueue: nil))
        }
    }

    /// The default transport's session configuration (a seam so the cookie posture is testable).
    internal static func makeSessionConfiguration() -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 15
        config.waitsForConnectivity = false
        config.urlCache = nil
        // ⚠ NO COOKIES (s58.360). The SDK authenticates with x-api-key + body
        // tokens, never a cookie — but an ephemeral session still keeps an
        // in-memory jar, so every `sd_rt` the server set was replayed on the
        // next /token/refresh. After a sign-in that cookie is the ACCOUNT's,
        // and the server preferred it over a HELD GUEST's token in the body.
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false
        config.httpCookieStorage = nil
        return config
    }

    /// Circuit breaker: returns true if the caller should skip this call entirely.
    /// Purely time-based, so it is half-open by construction: each failure
    /// pushes `nextAllowedAfter` forward, and once that window elapses ONE
    /// probe is allowed through — a success resets the breaker, a failure
    /// re-arms it.
    ///
    /// It deliberately does NOT hard-trip on `consecutiveFailures` alone. A
    /// count-only block can never reset: no request is attempted, so no
    /// success is ever recorded, so the count never clears — a few minutes in
    /// airplane mode wedged the entire client for the rest of the process
    /// lifetime. (sdk-android removed the same trip for the same reason.)
    private func shouldSkip() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return clock() < nextAllowedAfter
    }

    /// When the breaker next lets a request through (`.distantPast` = closed). Tests read it.
    internal var breakerOpenUntil: Date {
        lock.lock(); defer { lock.unlock() }
        return nextAllowedAfter
    }

    private func recordSuccess() {
        lock.lock()
        consecutiveFailures = 0
        nextAllowedAfter = .distantPast
        lock.unlock()
    }

    /// 5.6.0 (F67): FULL JITTER — `random(0, min(60 s, 2^n s))` — instead of a
    /// fixed doubling (every device that failed together retried together), and
    /// never shorter than the server's own wait (`minimumWait`, capped at 1 h).
    /// The window only ever moves LATER: a concurrent in-flight failure cannot
    /// shorten a `Retry-After` another response just set.
    private func recordFailure(minimumWait: TimeInterval? = nil) {
        lock.lock()
        consecutiveFailures += 1
        let ceiling = min(maxBackoff, pow(2.0, Double(min(consecutiveFailures, 30))))
        var delay = max(0, min(ceiling, jitter(ceiling)))
        if let wait = minimumWait, wait > 0 {
            delay = max(delay, min(wait, Self.maxServerWait))
        }
        let until = clock().addingTimeInterval(delay)
        if until > nextAllowedAfter { nextAllowedAfter = until }
        lock.unlock()
    }

    // MARK: - Response classification (5.6.0, F67)

    /// What the breaker makes of one HTTP answer.
    internal enum BreakerVerdict: Equatable {
        case success
        /// 429 / 503 / a Cloudflare challenge: hold for at least `wait` seconds (nil = no hint, jitter only).
        case throttled(wait: TimeInterval?)
        /// Another 5xx (the plain path's long-standing rule).
        case serverFailure
        /// A 4xx the backend answered: never costs the caller its retry budget.
        case clientError
    }

    /// `true` when Cloudflare answered instead of Sendora (`cf-mitigated: challenge`). A challenge is never an
    /// auth verdict and never a permanent refusal: the request did not reach the API.
    internal static func isChallenge(_ http: HTTPURLResponse) -> Bool {
        guard let raw = http.value(forHTTPHeaderField: "cf-mitigated") else { return false }
        return raw.lowercased().contains("challenge")
    }

    /// The server's wait: the `Retry-After` header (delta-seconds or an HTTP-date), else
    /// `error.details.retryAfterSeconds` in the body. `nil` when neither names a positive wait.
    internal static func retryAfterSeconds(_ http: HTTPURLResponse, body: [String: Any]?, now: Date = Date()) -> Int? {
        if let raw = http.value(forHTTPHeaderField: "Retry-After")?.trimmingCharacters(in: .whitespaces), !raw.isEmpty {
            if let seconds = Double(raw), seconds.isFinite {
                if seconds > 0 { return Int(min(seconds.rounded(.up), maxServerWait)) }
            } else if let date = httpDateFormatter.date(from: raw) {
                let delta = date.timeIntervalSince(now)
                if delta > 0 { return Int(min(delta.rounded(.up), maxServerWait)) }
            }
        }
        let details = (body?["error"] as? [String: Any])?["details"] as? [String: Any]
        if let n = details?["retryAfterSeconds"] as? NSNumber, n.doubleValue > 0 {
            return Int(min(n.doubleValue.rounded(.up), maxServerWait))
        }
        return nil
    }

    private static let httpDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "GMT")
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return f
    }()

    internal static func breakerVerdict(status: Int, challenge: Bool, retryAfter: Int?) -> BreakerVerdict {
        if (200..<300).contains(status) { return .success }
        if challenge {
            return .throttled(wait: max(challengeMinWait, TimeInterval(retryAfter ?? 0)))
        }
        if status == 429 {
            return .throttled(wait: retryAfter.map { min(TimeInterval($0), rateLimitMaxHold) })
        }
        if status == 503 {
            return .throttled(wait: retryAfter.map { TimeInterval($0) })
        }
        if status >= 500 { return .serverFailure }
        return .clientError
    }

    func post(path: String, body: [String: Any], completion: @escaping ([String: Any]?) -> Void) {
        request(method: "POST", path: path, body: body, headers: nil, completion: completion)
    }

    /// POST with extra headers — used for Bearer-authenticated
    /// self-service routes (MFA enroll, passkey enroll, etc).
    func post(path: String, body: [String: Any], headers: [String: String]?, completion: @escaping ([String: Any]?) -> Void) {
        request(method: "POST", path: path, body: body, headers: headers, completion: completion)
    }

    func get(path: String, headers: [String: String]?, completion: @escaping ([String: Any]?) -> Void) {
        request(method: "GET", path: path, body: nil, headers: headers, completion: completion)
    }

    /// Convenience GET without extra headers — most read paths use this.
    func get(path: String, completion: @escaping ([String: Any]?) -> Void) {
        request(method: "GET", path: path, body: nil, headers: nil, completion: completion)
    }

    func delete(path: String, headers: [String: String]?, completion: @escaping ([String: Any]?) -> Void) {
        request(method: "DELETE", path: path, body: nil, headers: headers, completion: completion)
    }

    /// Stamp the HTTP status onto the envelope's `error` object so a caller can
    /// classify a failure the backend gave no `code` for (a bare 5xx, a gateway
    /// page). Deliberately does NOT synthesise an `error` when the body carries
    /// none — its absence is what makes a caller fall back to its own default
    /// code, and shipped apps match on those.
    private static func stampErrorStatus(_ body: [String: Any], status: Int, retryAfter: Int? = nil) -> [String: Any] {
        guard var error = body["error"] as? [String: Any] else { return body }
        error["status"] = status
        // 5.6.0: a `Retry-After` header with no body hint still reaches the caller's taxonomy.
        if let wait = retryAfter {
            var details = (error["details"] as? [String: Any]) ?? [:]
            if details["retryAfterSeconds"] == nil { details["retryAfterSeconds"] = wait }
            error["details"] = details
        }
        var out = body
        out["error"] = error
        return out
    }

    private func buildRequest(method: String, path: String, body: [String: Any]?, headers: [String: String]?) -> URLRequest? {
        guard let url = URL(string: "\(baseUrl)/api/v1\(path)"),
              url.scheme == "https" || url.host == "localhost" || url.host == "127.0.0.1" else {
            SendoraCloudLogger.shared.error("APIClient refusing non-HTTPS URL")
            return nil
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        // ADR-023: SDK-version request headers on every call. Gives the
        // backend a version signal even for non-event routes (auth/links/
        // push), which never carried one. Additive — backend ignores today.
        req.setValue(SendoraCloud.sdkName, forHTTPHeaderField: "X-Sendora-SDK-Name")
        req.setValue(SendoraCloud.sdkVersion, forHTTPHeaderField: "X-Sendora-SDK-Version")
        if let headers = headers {
            for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        }
        if let body = body {
            do {
                req.httpBody = try JSONSerialization.data(withJSONObject: body)
            } catch {
                SendoraCloudLogger.shared.error("JSON serialization failed")
                return nil
            }
        }
        return req
    }

    private func request(
        method: String,
        path: String,
        body: [String: Any]?,
        headers: [String: String]?,
        completion: @escaping ([String: Any]?) -> Void
    ) {
        if shouldSkip() {
            completion(nil)
            return
        }
        guard let req = buildRequest(method: method, path: path, body: body, headers: headers) else {
            completion(nil)
            return
        }

        transport.perform(req) { [weak self] data, http, _ in
            guard let self = self else { return }
            guard let http = http else {
                // No response at all — a genuine transport failure.
                self.recordFailure()
                completion(nil)
                return
            }
            let json = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? nil
            let challenge = !(200..<300).contains(http.statusCode) && Self.isChallenge(http)
            let retryAfter = Self.retryAfterSeconds(http, body: json, now: self.clock())
            switch Self.breakerVerdict(status: http.statusCode, challenge: challenge, retryAfter: retryAfter) {
            case .success:
                self.recordSuccess()
                completion(json)
                return
            case .throttled(let wait):
                // 5.6.0 (F67): 429 (the caller's own budget), 503 (overload) and a
                // Cloudflare challenge hold the WHOLE client for the server's wait.
                // A 429 used to record SUCCESS here — resetting the breaker on the
                // very answer that asked us to slow down.
                self.recordFailure(minimumWait: wait)
            case .serverFailure:
                self.recordFailure()
            case .clientError:
                // A non-2xx is the backend answering, not the transport failing.
                // The breaker guards the TRANSPORT; a 4xx must never cost the
                // caller its retry budget.
                self.recordSuccess()
            }
            // A challenge is Cloudflare's page, not the API's answer: deliver it as
            // "no response" so no caller can read it as an auth or permanent refusal.
            if challenge { completion(nil); return }
            // Returning nil for every non-2xx discarded `error.code` and
            // `error.details.retryAfterSeconds` (pre-4.14.0), so a wrong password, a
            // 409 and a dead radio all looked the same.
            completion(json.map { Self.stampErrorStatus($0, status: http.statusCode, retryAfter: retryAfter) })
        }
    }

    /// Rich response for callers that need HTTP status + the typed
    /// `error.code` / `error.message` envelope fields (used by the Links
    /// surface to map backend errors into typed `LinkError` cases instead
    /// of swallowing them as `nil`). Independent of the circuit breaker
    /// for HTTP-level rejections — backend 4xx is a logical error from
    /// the caller's perspective, not a transport failure, so it doesn't
    /// flip the breaker.
    struct RichResponse {
        let statusCode: Int
        let body: [String: Any]?
        let errorCode: String?
        let errorMessage: String?
        /// 5.6.0 (F67): the server's wait — `Retry-After`, else `error.details.retryAfterSeconds`.
        var retryAfterSeconds: Int? = nil
        /// 5.6.0 (F67): Cloudflare answered with a challenge (`cf-mitigated`). Delivered with
        /// `statusCode == 0` (the transport class): the request never reached the API, so no caller
        /// may read it as a dead credential or a permanent refusal. The status Cloudflare used is
        /// `challengeStatus`.
        var cfMitigated: Bool = false
        var challengeStatus: Int = 0
    }

    /// `headers` (5.4.0): the Bearer-authenticated link / claim paths of the
    /// auth machine need the typed envelope too (a 409 `CREDENTIAL_IN_USE` carries
    /// `details.collision`; a 403 `RECENT_AUTH_REQUIRED` must classify by code).
    func requestWithDetails(
        method: String,
        path: String,
        body: [String: Any]?,
        headers: [String: String]? = nil,
        completion: @escaping (RichResponse) -> Void
    ) {
        if shouldSkip() {
            completion(RichResponse(statusCode: 0, body: nil, errorCode: "NETWORK", errorMessage: "Circuit breaker open — too many recent failures"))
            return
        }
        guard let req = buildRequest(method: method, path: path, body: body, headers: headers) else {
            completion(RichResponse(statusCode: 0, body: nil, errorCode: body == nil ? "NETWORK" : "INVALID_INPUT", errorMessage: body == nil ? "Non-HTTPS URL refused" : "Body serialization failed or non-HTTPS URL refused"))
            return
        }

        transport.perform(req) { [weak self] data, http, _ in
            guard let self = self else { return }
            let status = http?.statusCode ?? 0
            var parsed: [String: Any]?
            if let data = data {
                parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            }
            guard let http = http, status != 0 else {
                self.recordFailure()
                completion(RichResponse(statusCode: 0, body: nil, errorCode: "NETWORK", errorMessage: "Network request failed"))
                return
            }
            let challenge = !(200..<300).contains(status) && Self.isChallenge(http)
            let retryAfter = Self.retryAfterSeconds(http, body: parsed, now: self.clock())
            switch Self.breakerVerdict(status: status, challenge: challenge, retryAfter: retryAfter) {
            case .success:
                self.recordSuccess()
                completion(RichResponse(statusCode: status, body: parsed, errorCode: nil, errorMessage: nil))
                return
            case .throttled(let wait):
                self.recordFailure(minimumWait: wait)
            case .serverFailure, .clientError:
                // Unchanged since 4.14.0 on this path: an HTTP-level rejection is a
                // logical answer, not a transport failure.
                break
            }
            if challenge {
                completion(RichResponse(statusCode: 0, body: nil, errorCode: "NETWORK",
                                        errorMessage: "Cloudflare challenge (cf-mitigated): the request did not reach the API",
                                        retryAfterSeconds: retryAfter.map { max($0, Int(Self.challengeMinWait)) } ?? Int(Self.challengeMinWait),
                                        cfMitigated: true, challengeStatus: status))
                return
            }
            let err = parsed?["error"] as? [String: Any]
            completion(RichResponse(
                statusCode: status,
                body: parsed,
                errorCode: err?["code"] as? String,
                errorMessage: err?["message"] as? String,
                retryAfterSeconds: retryAfter
            ))
        }
    }

    /// 5.6.0 (F67): what one event delivery's answer means for the queue.
    enum DeliveryOutcome: Equatable {
        /// 2xx — drop the chunk.
        case accepted
        /// 2xx, but the batch route refused some events for IDENTITY (`data.rejected[i].code ==
        /// "IDENTITY_UNVERIFIED"`, or a code-less row whose `reason` mentions identity): those chunk
        /// indices stay queued and spend one attempt (answered-transient, like the identity 401);
        /// every other event of the chunk is removed.
        case acceptedExcept(retry: [Int])
        /// A refusal no retry can change (400 / 401 / 403 / 404 / 413 / 422 and every other 4xx but 408 / 429)
        /// — drop the chunk, or it blocks the queue head forever.
        case rejected(status: Int)
        /// Keep the chunk. `countsAttempt` = the SERVER answered and failed (408 / 5xx / 401
        /// `IDENTITY_UNVERIFIED`): that spends the events' retry budget. Offline, the breaker, a 429 (our
        /// budget) and a Cloudflare challenge do not — they say nothing about the events. `after` = the
        /// server's wait in seconds (the queue starts no flush before it, ≤ 1 h).
        case retryLater(countsAttempt: Bool, after: Int? = nil, status: Int = 0)
    }

    internal static func deliveryOutcome(_ rich: RichResponse) -> DeliveryOutcome {
        let status = rich.statusCode
        if (200..<300).contains(status) {
            if (rich.body?["success"] as? Bool) == false { return .retryLater(countsAttempt: true) }
            let retry = identityRejectedIndices(rich.body)
            return retry.isEmpty ? .accepted : .acceptedExcept(retry: retry)
        }
        if status == 0 || rich.cfMitigated { return .retryLater(countsAttempt: false, after: rich.retryAfterSeconds) }
        if status == 429 { return .retryLater(countsAttempt: false, after: rich.retryAfterSeconds) }
        // Cloudflare's own 520–527 / 530 (origin unreachable): the API never saw the request — unanswered.
        if (520...527).contains(status) || status == 530 {
            return .retryLater(countsAttempt: false, after: rich.retryAfterSeconds, status: status)
        }
        if status == 408 || status >= 500 { return .retryLater(countsAttempt: true, after: rich.retryAfterSeconds, status: status) }
        // A strict-identity project refusing an event whose identity token has not verified YET (rotation,
        // clock) is the server answering about state that can change — spend the budget, never drop at once.
        if status == 401 && rich.errorCode == "IDENTITY_UNVERIFIED" { return .retryLater(countsAttempt: true) }
        return .rejected(status: status)
    }

    /// The indices of a 201's `data.rejected` rows that are identity refusals (s58.402 labels them with
    /// `code: "IDENTITY_UNVERIFIED"`; an older backend sends only `reason`).
    internal static func identityRejectedIndices(_ body: [String: Any]?) -> [Int] {
        guard let rows = (body?["data"] as? [String: Any])?["rejected"] as? [[String: Any]] else { return [] }
        var out: [Int] = []
        for row in rows {
            guard let index = (row["index"] as? NSNumber)?.intValue else { continue }
            if let code = row["code"] as? String {
                if code == "IDENTITY_UNVERIFIED" { out.append(index) }
            } else if let reason = row["reason"] as? String, reason.lowercased().contains("identity") {
                out.append(index)
            }
        }
        return Array(Set(out)).sorted()
    }

    func postEvents(path: String, body: [String: Any], completion: @escaping (DeliveryOutcome) -> Void) {
        requestWithDetails(method: "POST", path: path, body: body) { rich in
            completion(Self.deliveryOutcome(rich))
        }
    }

    func postBatch(path: String, events: [[String: Any]], completion: @escaping (DeliveryOutcome) -> Void) {
        postEvents(path: path, body: ["events": events], completion: completion)
    }

    // MARK: - Cert pinning

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // No pins configured → fall through to system trust evaluation.
        if pinnedSPKIHashes.isEmpty {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // Step 1 — system trust must still pass (chains to a trusted CA).
        var systemError: CFError?
        let systemValid = SecTrustEvaluateWithError(trust, &systemError)
        if !systemValid {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Step 2 — leaf SPKI must match one of our pins. Walk the chain
        // so a backup pin on an intermediate also satisfies (rotation
        // safety net).
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        for cert in chain {
            guard let hash = APIClient.spkiSHA256Base64(of: cert) else { continue }
            if pinnedSPKIHashes.contains(hash) {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
        }

        SendoraCloudLogger.shared.error("APIClient cert pin mismatch — refusing connection")
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    private static func spkiSHA256Base64(of cert: SecCertificate) -> String? {
        guard let publicKey = SecCertificateCopyKey(cert),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        publicKeyData.withUnsafeBytes { buf in
            _ = CC_SHA256(buf.baseAddress, CC_LONG(publicKeyData.count), &hash)
        }
        return Data(hash).base64EncodedString()
    }
}

/// The production transport: a plain `URLSession.dataTask`.
final class URLSessionTransport: SendoraHTTPTransport {
    private let session: URLSession

    init(session: URLSession) {
        self.session = session
    }

    func perform(_ request: URLRequest, completion: @escaping (Data?, HTTPURLResponse?, Error?) -> Void) {
        let task = session.dataTask(with: request) { data, response, error in
            completion(data, response as? HTTPURLResponse, error)
        }
        task.resume()
    }
}
