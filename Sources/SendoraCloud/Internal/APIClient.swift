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
    /// pushes `nextAllowedAfter` forward with exponential backoff, and once
    /// that window elapses ONE probe is allowed through — a success resets the
    /// breaker, a failure re-arms it.
    ///
    /// It deliberately does NOT hard-trip on `consecutiveFailures` alone. A
    /// count-only block can never reset: no request is attempted, so no
    /// success is ever recorded, so the count never clears — a few minutes in
    /// airplane mode wedged the entire client for the rest of the process
    /// lifetime. (sdk-android removed the same trip for the same reason.)
    private func shouldSkip() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return Date() < nextAllowedAfter
    }

    private func recordSuccess() {
        lock.lock()
        consecutiveFailures = 0
        nextAllowedAfter = .distantPast
        lock.unlock()
    }

    private func recordFailure() {
        lock.lock()
        consecutiveFailures += 1
        let delay = min(maxBackoff, pow(2.0, Double(consecutiveFailures)))
        nextAllowedAfter = Date().addingTimeInterval(delay)
        lock.unlock()
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
    private static func stampErrorStatus(_ body: [String: Any], status: Int) -> [String: Any] {
        guard var error = body["error"] as? [String: Any] else { return body }
        error["status"] = status
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
            if (200..<300).contains(http.statusCode) {
                self.recordSuccess()
                completion(json)
                return
            }
            // A non-2xx is the backend answering, not the transport failing.
            // Returning nil here discarded `error.code` and
            // `error.details.retryAfterSeconds`, so every 4xx/5xx reached the
            // caller as an indistinguishable generic network failure — which
            // is why a wrong password, a 409 and a dead radio all looked the
            // same, and why the dead-refresh-token branch could never fire.
            // The breaker guards the TRANSPORT, so only a 5xx counts here; a
            // 4xx must never cost the caller its retry budget.
            if http.statusCode >= 500 { self.recordFailure() } else { self.recordSuccess() }
            completion(json.map { Self.stampErrorStatus($0, status: http.statusCode) })
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
            if (200..<300).contains(status) {
                self.recordSuccess()
                completion(RichResponse(statusCode: status, body: parsed, errorCode: nil, errorMessage: nil))
                return
            }
            if status == 0 {
                self.recordFailure()
            }
            let err = parsed?["error"] as? [String: Any]
            completion(RichResponse(
                statusCode: status,
                body: parsed,
                errorCode: err?["code"] as? String,
                errorMessage: err?["message"] as? String
            ))
        }
    }

    func postBatch(path: String, events: [[String: Any]], completion: @escaping (Bool) -> Void) {
        post(path: path, body: ["events": events]) { response in
            let success = (response?["success"] as? Bool) ?? false
            completion(success)
        }
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
