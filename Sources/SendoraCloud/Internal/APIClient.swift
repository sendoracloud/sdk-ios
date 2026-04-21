import Foundation

/// HTTPS-only client with exponential backoff + circuit breaker.
final class APIClient {
    private let baseUrl: String
    private let apiKey: String
    private let session: URLSession
    private let lock = NSLock()
    private var consecutiveFailures = 0
    private var nextAllowedAfter: Date = .distantPast

    private let maxFailures = 10
    private let maxBackoff: TimeInterval = 60

    init(baseUrl: String, apiKey: String) {
        self.baseUrl = baseUrl.hasSuffix("/") ? String(baseUrl.dropLast()) : baseUrl
        self.apiKey = apiKey
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 15
        config.waitsForConnectivity = false
        config.urlCache = nil
        self.session = URLSession(configuration: config)
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

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } catch {
            SendoraCloudLogger.shared.error("JSON serialization failed")
            completion(nil)
            return
        }

        let task = session.dataTask(with: request) { [weak self] data, response, _ in
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

    func postBatch(path: String, events: [[String: Any]], completion: @escaping (Bool) -> Void) {
        post(path: path, body: ["events": events]) { response in
            let success = (response?["success"] as? Bool) ?? false
            completion(success)
        }
    }
}
