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
///                                           If the SDK was anonymous, the
///                                           local identity is wiped first.
///   - `signOut(completion:)`              — best-effort revoke, then wipe.
///
/// Tokens persist in Keychain via SendoraStorage. On configure() the
/// session re-hydrates so a cold launch keeps the active user.
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
    private let lock = NSLock()

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
           let user = try? JSONDecoder().decode(SendoraCloudAuthUser.self, from: data) {
            self.cachedUser = user
            self.onIdentityChange(user.id)
        }
    }

    public var currentUser: SendoraCloudAuthUser? {
        lock.lock(); defer { lock.unlock() }
        return cachedUser
    }

    public var accessToken: String? {
        return storage.authAccessToken
    }

    public func signInAnonymously(
        name: String? = nil,
        metadata: [String: Any]? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        var body: [String: Any] = [:]
        if let name = name { body["name"] = name }
        if let metadata = metadata { body["metadata"] = metadata }
        callAuth(path: "/auth-service/anonymous", body: body, completion: completion)
    }

    public func signUp(
        email: String,
        password: String,
        name: String? = nil,
        metadata: [String: Any]? = nil,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        let isAnonymous = currentUser?.isAnonymous == true
        if isAnonymous, let refresh = storage.authRefreshToken {
            var body: [String: Any] = [
                "refreshToken": refresh,
                "email": email,
                "password": password,
            ]
            if let name = name { body["name"] = name }
            callAuth(path: "/auth-service/upgrade", body: body, completion: completion)
            return
        }

        var body: [String: Any] = ["email": email, "password": password]
        if let name = name { body["name"] = name }
        if let metadata = metadata { body["metadata"] = metadata }
        callAuth(path: "/auth-service/signup", body: body, completion: completion)
    }

    public func signIn(
        email: String,
        password: String,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        let wasAnonymous = currentUser?.isAnonymous == true
        let body: [String: Any] = ["email": email, "password": password]
        client.post(path: "/auth-service/login", body: body) { [weak self] response in
            guard let self = self else { return }
            if let err = self.parseError(response) {
                completion(.failure(err))
                return
            }
            guard let user = self.parseSuccess(response) else {
                completion(.failure(.unknown("Malformed response")))
                return
            }
            if wasAnonymous { self.wipeLocalIdentity() }
            self.persist(response: response)
            completion(.success(user))
        }
    }

    public func signOut(completion: @escaping () -> Void) {
        if let refresh = storage.authRefreshToken {
            client.post(path: "/auth-service/token/revoke", body: ["refreshToken": refresh]) { [weak self] _ in
                self?.wipeLocalIdentity()
                completion()
            }
        } else {
            wipeLocalIdentity()
            completion()
        }
    }

    // MARK: - Internals

    private func callAuth(
        path: String,
        body: [String: Any],
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudAuthError>) -> Void
    ) {
        client.post(path: path, body: body) { [weak self] response in
            guard let self = self else { return }
            if let err = self.parseError(response) {
                completion(.failure(err))
                return
            }
            guard let user = self.parseSuccess(response) else {
                completion(.failure(.unknown("Malformed response")))
                return
            }
            self.persist(response: response)
            completion(.success(user))
        }
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
              let userDict = data["user"] as? [String: Any] else { return nil }
        let id = userDict["id"] as? String ?? ""
        return SendoraCloudAuthUser(
            id: id,
            email: userDict["email"] as? String,
            emailVerified: userDict["emailVerified"] as? Bool ?? false,
            name: userDict["name"] as? String,
            isAnonymous: userDict["isAnonymous"] as? Bool ?? false
        )
    }

    private func persist(response: [String: Any]?) {
        guard let data = response?["data"] as? [String: Any],
              let tokensDict = data["tokens"] as? [String: Any],
              let user = parseSuccess(response) else { return }
        let accessToken = tokensDict["accessToken"] as? String ?? ""
        let refreshToken = tokensDict["refreshToken"] as? String ?? ""

        lock.lock()
        cachedUser = user
        lock.unlock()

        storage.authAccessToken = accessToken
        storage.authRefreshToken = refreshToken
        if let json = try? JSONEncoder().encode(user),
           let str = String(data: json, encoding: .utf8) {
            storage.authUserJson = str
        }
        onIdentityChange(user.id)
    }

    private func wipeLocalIdentity() {
        lock.lock()
        cachedUser = nil
        lock.unlock()
        storage.clearAuthTokens()
        onAnonymousWipe()
    }
}
