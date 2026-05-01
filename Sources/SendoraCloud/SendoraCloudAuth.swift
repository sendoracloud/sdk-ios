import Foundation

/// Auth Service surface for the iOS SDK.
///
/// Three flows mirroring the web + RN SDKs:
///   - `signInAnonymously(...)`            — POST /auth-service/anonymous
///   - `signUp(email:password:...)`        — upgrades the same row in
///                                           place when called from an
///                                           anonymous session; otherwise
///                                           creates a fresh account.
///   - `signIn(email:password:...)`        — logs into an existing account.
///                                           Local identity is wiped FIRST
///                                           so any track() during the
///                                           round-trip can't attach to
///                                           the prior identity.
///   - `signOut(completion:)`              — wipe FIRST, fire-and-forget
///                                           revoke. User is logged out
///                                           on device even if the
///                                           network call hangs.
///
/// All public ops are serialized through a private dispatch queue so a
/// double-tap can't race two anonymous mints or interleave signIn +
/// signOut. Response payloads are validated non-empty before persisting
/// — a malformed/MitM'd response can't install an `id = ""` user.
///
/// Tokens persist in Keychain with `kSecAttrAccessibleAfterFirstUnlock-
/// ThisDeviceOnly` (no iCloud sync, sandboxed to this app's bundle id).
public struct SendoraCloudAuthUser: Codable {
    public let id: String
    public let email: String?
    public let emailVerified: Bool
    public let name: String?
    public let isAnonymous: Bool
}

public struct SendoraCloudAuthTokens: Codable {
    public let accessToken: String
    public let refreshToken: String
    public let expiresIn: Int
    public let tokenType: String
}

public enum SendoraCloudAuthError: Error {
    case emailAlreadyTaken(String)
    case unauthorized(String)
    case network(String)
    case unknown(String)
}

public final class SendoraCloudAuth {
    private let client: APIClient
    private let storage: SendoraStorage
    private let onIdentityChange: (String?) -> Void
    private let onAnonymousWipe: () -> Void
    private var cachedUser: SendoraCloudAuthUser?
    private var cachedExpiresAt: Int64 = 0
    private let lock = NSLock()
    /// Serial queue for public auth ops. All signIn/signUp/signOut/anonymous
    /// calls funnel through here so concurrent invocations execute one at
    /// a time. Refresh runs on a separate single-flight Promise.
    private let opsQueue = DispatchQueue(label: "com.sendora.sdk.auth.ops")
    private var refreshInFlight: [(String?) -> Void] = []
    private var isRefreshing = false
    private let refreshSafetyMs: Int64 = 30_000

    init(
        client: APIClient,
        storage: SendoraStorage,
        onIdentityChange: @escaping (String?) -> Void,
        onAnonymousWipe: @escaping () -> Void
    ) {
        self.client = client
        self.storage = storage
        self.onIdentityChange = onIdentityChange
        self.onAnonymousWipe = onAnonymousWipe

        // Re-hydrate session from Keychain.
        if let json = storage.authUserJson,
           let data = json.data(using: .utf8),
           let user = try? JSONDecoder().decode(SendoraCloudAuthUser.self, from: data),
           !user.id.isEmpty {
            self.cachedUser = user
            self.cachedExpiresAt = storage.authAccessExpiresAt
            self.onIdentityChange(user.id)
        } else if storage.authUserJson != nil {
            // Malformed cached user — drop it rather than carry a bad
            // identity into the session.
            storage.clearAuthTokens()
        }
    }

    public var currentUser: SendoraCloudAuthUser? {
        lock.lock(); defer { lock.unlock() }
        return cachedUser
    }

    /// Synchronous read — returns whatever's cached, even if expired.
    /// Prefer `getAccessToken(completion:)` for transparent refresh.
    public var accessToken: String? {
        return storage.authAccessToken
    }

    /// Returns a non-expired access token. Triggers a single-flight
    /// refresh if the cached token is past expiry.
    public func getAccessToken(completion: @escaping (String?) -> Void) {
        guard let token = storage.authAccessToken else {
            completion(nil)
            return
        }
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let exp = cachedExpiresAt
        if exp > 0 && nowMs < exp - refreshSafetyMs {
            completion(token)
            return
        }
        refreshAccessToken(completion: completion)
    }

    public func signInAnonymously(
        name: String? = nil,
        metadata: [String: Any]? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            var body: [String: Any] = [:]
            if let name = name { body["name"] = name }
            if let metadata = metadata { body["metadata"] = metadata }
            self.callAuthSync(path: "/auth-service/anonymous", body: body, completion: completion)
        }
    }

    public func signUp(
        email: String,
        password: String,
        name: String? = nil,
        metadata: [String: Any]? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            // Snapshot anonymity inside the serial queue so a concurrent
            // signOut/signIn can't race the read.
            let isAnonymous: Bool = {
                self.lock.lock(); defer { self.lock.unlock() }
                return self.cachedUser?.isAnonymous == true
            }()
            let refresh = self.storage.authRefreshToken

            if isAnonymous, let refresh = refresh {
                var body: [String: Any] = [
                    "refreshToken": refresh,
                    "email": email,
                    "password": password,
                ]
                if let name = name { body["name"] = name }
                self.callAuthSync(path: "/auth-service/upgrade", body: body, completion: completion)
                return
            }

            // Fresh signup from a non-anonymous identified state — wipe
            // BEFORE the network call so events fired during the round
            // trip don't cling to the old identity.
            let wasIdentified: Bool = {
                self.lock.lock(); defer { self.lock.unlock() }
                return self.cachedUser != nil && self.cachedUser?.isAnonymous == false
            }()
            if wasIdentified { self.wipeLocalIdentity() }

            var body: [String: Any] = ["email": email, "password": password]
            if let name = name { body["name"] = name }
            if let metadata = metadata { body["metadata"] = metadata }
            self.callAuthSync(path: "/auth-service/signup", body: body, completion: completion)
        }
    }

    public func signIn(
        email: String,
        password: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        opsQueue.async {
            // Wipe BEFORE the network call so any track() during the
            // auth round-trip can't attach to the prior identity.
            let hadUser: Bool = {
                self.lock.lock(); defer { self.lock.unlock() }
                return self.cachedUser != nil
            }()
            if hadUser { self.wipeLocalIdentity() }

            let body: [String: Any] = ["email": email, "password": password]
            self.callAuthSync(path: "/auth-service/login", body: body, completion: completion)
        }
    }

    public func signOut(completion: @escaping () -> Void) {
        opsQueue.async {
            // Wipe FIRST so the user is logged out on device even if
            // the revoke request hangs (airplane mode, 5xx, circuit
            // open). Refresh token still expires server-side.
            let refresh = self.storage.authRefreshToken
            self.wipeLocalIdentity()
            if let refresh = refresh {
                self.client.post(path: "/auth-service/token/revoke",
                                 body: ["refreshToken": refresh]) { _ in
                    completion()
                }
            } else {
                completion()
            }
        }
    }

    // MARK: - Internals

    /// Synchronous wrapper that blocks the opsQueue until the network
    /// call completes — keeps one auth op at a time per SDK instance.
    private func callAuthSync(
        path: String,
        body: [String: Any],
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        let semaphore = DispatchSemaphore(value: 0)
        client.post(path: path, body: body) { [weak self] response in
            guard let self = self else { semaphore.signal(); return }
            if let err = self.parseError(response) {
                completion(.failure(err))
                semaphore.signal()
                return
            }
            guard let user = self.parseSuccess(response),
                  let tokens = self.parseTokens(response) else {
                completion(.failure(.unknown("Malformed response")))
                semaphore.signal()
                return
            }
            self.persist(user: user, tokens: tokens)
            completion(.success(user))
            semaphore.signal()
        }
        semaphore.wait()
    }

    private func refreshAccessToken(completion: @escaping (String?) -> Void) {
        opsQueue.async {
            self.lock.lock()
            self.refreshInFlight.append(completion)
            if self.isRefreshing {
                self.lock.unlock()
                return
            }
            self.isRefreshing = true
            self.lock.unlock()

            guard let refresh = self.storage.authRefreshToken else {
                self.completeRefresh(token: nil)
                return
            }
            self.client.post(path: "/auth-service/token/refresh",
                             body: ["refreshToken": refresh]) { [weak self] response in
                guard let self = self else { return }
                guard let data = response?["data"] as? [String: Any],
                      let accessToken = data["accessToken"] as? String,
                      !accessToken.isEmpty,
                      let refreshToken = data["refreshToken"] as? String,
                      !refreshToken.isEmpty,
                      let expiresIn = data["expiresIn"] as? Int else {
                    self.completeRefresh(token: nil)
                    return
                }
                let expMs = Int64(Date().timeIntervalSince1970 * 1000) + Int64(expiresIn) * 1000
                self.storage.authAccessToken = accessToken
                self.storage.authRefreshToken = refreshToken
                self.storage.authAccessExpiresAt = expMs
                self.lock.lock()
                self.cachedExpiresAt = expMs
                self.lock.unlock()
                self.completeRefresh(token: accessToken)
            }
        }
    }

    private func completeRefresh(token: String?) {
        let callbacks: [(String?) -> Void] = {
            lock.lock(); defer { lock.unlock() }
            let cs = refreshInFlight
            refreshInFlight.removeAll()
            isRefreshing = false
            return cs
        }()
        for cb in callbacks { cb(token) }
    }

    private func parseError(_ response: [String: Any]?) -> SendoraCloudAuthError? {
        guard let response = response else {
            return .network("Network request failed")
        }
        if let success = response["success"] as? Bool, success { return nil }
        let error = response["error"] as? [String: Any]
        let code = error?["code"] as? String ?? ""
        let message = error?["message"] as? String ?? "Auth request failed"
        if code == "CONFLICT" || code == "EMAIL_ALREADY_TAKEN" {
            return .emailAlreadyTaken(message)
        }
        if code == "UNAUTHORIZED" || code.hasPrefix("HTTP_401") {
            return .unauthorized(message)
        }
        return .unknown("\(code): \(message)")
    }

    private func parseSuccess(_ response: [String: Any]?) -> SendoraCloudAuthUser? {
        guard let data = response?["data"] as? [String: Any],
              let userDict = data["user"] as? [String: Any],
              let id = userDict["id"] as? String,
              !id.isEmpty else { return nil }
        return SendoraCloudAuthUser(
            id: id,
            email: userDict["email"] as? String,
            emailVerified: userDict["emailVerified"] as? Bool ?? false,
            name: userDict["name"] as? String,
            isAnonymous: userDict["isAnonymous"] as? Bool ?? false
        )
    }

    private func parseTokens(_ response: [String: Any]?) -> SendoraCloudAuthTokens? {
        guard let data = response?["data"] as? [String: Any],
              let tokensDict = data["tokens"] as? [String: Any],
              let accessToken = tokensDict["accessToken"] as? String,
              !accessToken.isEmpty,
              let refreshToken = tokensDict["refreshToken"] as? String,
              !refreshToken.isEmpty,
              let expiresIn = tokensDict["expiresIn"] as? Int,
              expiresIn > 0 else { return nil }
        return SendoraCloudAuthTokens(
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresIn: expiresIn,
            tokenType: tokensDict["tokenType"] as? String ?? "Bearer"
        )
    }

    private func persist(user: SendoraCloudAuthUser, tokens: SendoraCloudAuthTokens) {
        let expMs = Int64(Date().timeIntervalSince1970 * 1000) + Int64(tokens.expiresIn) * 1000
        lock.lock()
        cachedUser = user
        cachedExpiresAt = expMs
        lock.unlock()

        storage.authAccessToken = tokens.accessToken
        storage.authRefreshToken = tokens.refreshToken
        storage.authAccessExpiresAt = expMs
        if let json = try? JSONEncoder().encode(user),
           let str = String(data: json, encoding: .utf8) {
            storage.authUserJson = str
        }
        onIdentityChange(user.id)
    }

    private func wipeLocalIdentity() {
        lock.lock()
        cachedUser = nil
        cachedExpiresAt = 0
        lock.unlock()
        storage.clearAuthTokens()
        onAnonymousWipe()
    }
}
