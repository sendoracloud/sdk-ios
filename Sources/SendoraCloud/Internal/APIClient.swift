import Foundation
import CommonCrypto

/// HTTPS-only client with exponential backoff + circuit breaker.
/// Optionally enforces SPKI certificate pinning when `pinnedSPKIHashes`
/// is non-empty — useful against user-installed enterprise / MitM CAs
/// targeting auth tokens.
final class APIClient: NSObject, URLSessionDelegate {
    private let baseUrl: String
    private let apiKey: String
    private let pinnedSPKIHashes: Set<String>
    private var session: URLSession!
    private let lock = NSLock()
    private var consecutiveFailures = 0
    private var nextAllowedAfter: Date = .distantPast

    private let maxFailures = 10
    private let maxBackoff: TimeInterval = 60

    init(baseUrl: String, apiKey: String, pinnedSPKIHashes: [String] = []) {
        self.baseUrl = baseUrl.hasSuffix("/") ? String(baseUrl.dropLast()) : baseUrl
        self.apiKey = apiKey
        self.pinnedSPKIHashes = Set(pinnedSPKIHashes)
        super.init()
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 15
        config.waitsForConnectivity = false
        config.urlCache = nil
        self.session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }

    /// Circuit breaker: returns true if the caller should skip this call entirely.
    private func shouldSkip() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if consecutiveFailures > maxFailures { return true }
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

        guard let url = URL(string: "\(baseUrl)/api/v1\(path)"),
              url.scheme == "https" || url.host == "localhost" || url.host == "127.0.0.1" else {
            SendoraCloudLogger.shared.error("APIClient refusing non-HTTPS URL")
            completion(nil)
            return
        }

        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        if let headers = headers {
            for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        }

        if let body = body {
            do {
                req.httpBody = try JSONSerialization.data(withJSONObject: body)
            } catch {
                SendoraCloudLogger.shared.error("JSON serialization failed")
                completion(nil)
                return
            }
        }

        let task = session.dataTask(with: req) { [weak self] data, response, _ in
            guard let self = self else { return }
            if let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
               let data = data,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                self.recordSuccess()
                completion(json)
            } else {
                self.recordFailure()
                completion(nil)
            }
        }
        task.resume()
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

    func requestWithDetails(
        method: String,
        path: String,
        body: [String: Any]?,
        completion: @escaping (RichResponse) -> Void
    ) {
        if shouldSkip() {
            completion(RichResponse(statusCode: 0, body: nil, errorCode: "NETWORK", errorMessage: "Circuit breaker open — too many recent failures"))
            return
        }

        guard let url = URL(string: "\(baseUrl)/api/v1\(path)"),
              url.scheme == "https" || url.host == "localhost" || url.host == "127.0.0.1" else {
            SendoraCloudLogger.shared.error("APIClient refusing non-HTTPS URL")
            completion(RichResponse(statusCode: 0, body: nil, errorCode: "NETWORK", errorMessage: "Non-HTTPS URL refused"))
            return
        }

        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(apiKey, forHTTPHeaderField: "X-API-Key")

        if let body = body {
            do {
                req.httpBody = try JSONSerialization.data(withJSONObject: body)
            } catch {
                completion(RichResponse(statusCode: 0, body: nil, errorCode: "INVALID_INPUT", errorMessage: "Body serialization failed"))
                return
            }
        }

        let task = session.dataTask(with: req) { [weak self] data, response, _ in
            guard let self = self else { return }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
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
        task.resume()
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
