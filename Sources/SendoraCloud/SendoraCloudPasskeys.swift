import Foundation
// Passkeys are an iOS-only feature in this SDK; the file gates on
// UIKit so it cleanly no-ops on macOS builds (Sendora's macOS surface
// doesn't expose passkey UI).
#if canImport(AuthenticationServices) && canImport(UIKit)
import AuthenticationServices
import UIKit

/// Native passkey (WebAuthn) flows backed by ASAuthorizationPlatform-
/// PublicKeyCredentialProvider — same primitive Apple uses for system
/// passkey UI in Settings → Passwords. iOS 16+; older OS versions get
/// `passkeyUnsupported` errors.
///
/// Two flows:
///   register(name:presentingWindow:completion:) — phase 1 fetches
///       options from the server, phase 2 calls
///       ASAuthorizationController.performRequests(), phase 3 posts
///       the attestation back to the server. Caller is expected to
///       have an authenticated end-user session — the start endpoint
///       reads the bearer JWT to attribute the credential.
///   signIn(userId:presentingWindow:completion:) — same three phases
///       for assertion. `userId == nil` triggers the resident-key
///       discoverable-credential flow (iOS lets the user pick from
///       saved passkeys).
///
/// Server-side implementation matches @simplewebauthn/server, so
/// COSE encoding + base64url normalisation live there. SDK side just
/// passes opaque blobs through.
public enum SendoraCloudPasskeyError: Error {
    case unsupported
    case notSignedIn
    case startFailed(String)
    case userCancelled
    case verificationFailed(String)
    case missingPresenter
    /// 5.4.0 (ADR-033): a typed refusal from the auth machine — `SESSION_WITHHELD`
    /// (the stored session's project claim disagrees with `expectedProjectId`),
    /// `PROJECT_MISMATCH`, or a dropped result. Branch on `.kind` / `.code`.
    case authError(SendoraCloudAuthError)
}

@available(iOS 16.0, *)
public final class SendoraCloudPasskeys: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private let client: APIClient
    private let auth: SendoraCloudAuth
    private weak var presentingWindow: UIWindow?
    private var registerCompletion: ((Result<RegisteredPasskey, SendoraCloudPasskeyError>) -> Void)?
    private var assertCompletion: ((Result<SendoraCloudAuthUser, SendoraCloudPasskeyError>) -> Void)?
    /// ADR-033: the identity CAS taken when the assertion ceremony started.
    private var assertStartedFrom: SendoraCloudAuth.IdentityCAS?
    private var pendingChallenge: PasskeyContext?

    /// The hostname configured as the WebAuthn RP ID in the dashboard.
    /// Set this once via `Sendora.passkeys.configure(rpId:)` before the
    /// first call. Defaults to `app.sendoracloud.com` to match the
    /// platform default — customers running their own auth subdomain
    /// override.
    public var rpId: String = "app.sendoracloud.com"

    /// Convenience metadata returned from a successful registration.
    public struct RegisteredPasskey {
        public let id: String
        public let credentialId: String
    }

    init(client: APIClient, auth: SendoraCloudAuth) {
        self.client = client
        self.auth = auth
    }

    public func configure(rpId: String) {
        self.rpId = rpId
    }

    public func register(
        name: String? = nil,
        presentingWindow: UIWindow,
        completion: @escaping (Result<RegisteredPasskey, SendoraCloudPasskeyError>) -> Void
    ) {
        guard auth.bearerHeaders() != nil else {
            completion(.failure(.notSignedIn))
            return
        }
        self.presentingWindow = presentingWindow
        self.registerCompletion = completion

        let body: [String: Any] = [:]
        client.post(path: "/auth-service/passkeys/register/start", body: body, headers: auth.bearerHeaders()) { [weak self] response in
            guard let self = self else { return }
            guard let data = response?["data"] as? [String: Any],
                  let challengeB64 = data["challenge"] as? String,
                  let userInfo = data["user"] as? [String: Any],
                  let userIdB64 = userInfo["id"] as? String else {
                self.finishRegister(.failure(.startFailed("Missing challenge or user.id in start response")))
                return
            }
            guard let challenge = Self.b64urlDecode(challengeB64),
                  let userIdData = Self.b64urlDecode(userIdB64) else {
                self.finishRegister(.failure(.startFailed("Invalid base64url in start response")))
                return
            }
            let userName = (userInfo["name"] as? String) ?? "user"

            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: self.rpId)
            let req = provider.createCredentialRegistrationRequest(
                challenge: challenge,
                name: userName,
                userID: userIdData
            )
            self.pendingChallenge = PasskeyContext(name: name, challenge: challenge)
            let controller = ASAuthorizationController(authorizationRequests: [req])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    public func signIn(
        userId: String? = nil,
        presentingWindow: UIWindow,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudPasskeyError>) -> Void
    ) {
        // ADR-033 §3.2: in `withheld` every sign-in verb rejects before any network.
        if let refusal = auth.withheldRefusal() {
            completion(.failure(.authError(refusal)))
            return
        }
        // The attempt's identity CAS is taken NOW, before the sheet: a result
        // that lands after a signOut()/switch made meanwhile is dropped.
        self.assertStartedFrom = auth.externalAttemptStart()
        self.presentingWindow = presentingWindow
        self.assertCompletion = completion

        var body: [String: Any] = [:]
        if let userId = userId { body["userId"] = userId }
        client.post(path: "/auth-service/passkeys/authenticate/start", body: body) { [weak self] response in
            guard let self = self else { return }
            guard let data = response?["data"] as? [String: Any],
                  let challengeB64 = data["challenge"] as? String else {
                self.finishAssert(.failure(.startFailed("Missing challenge in authenticate-start response")))
                return
            }
            guard let challenge = Self.b64urlDecode(challengeB64) else {
                self.finishAssert(.failure(.startFailed("Invalid base64url challenge")))
                return
            }

            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: self.rpId)
            let req = provider.createCredentialAssertionRequest(challenge: challenge)
            // allowCredentials list — when caller supplied a userId,
            // optionally restrict; otherwise let the user pick from
            // every resident credential on the device.
            if let allow = data["allowCredentials"] as? [[String: Any]] {
                req.allowedCredentials = allow.compactMap { item in
                    guard let idB64 = item["id"] as? String,
                          let id = Self.b64urlDecode(idB64) else { return nil }
                    return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: id)
                }
            }
            self.pendingChallenge = PasskeyContext(userId: userId, challenge: challenge)
            let controller = ASAuthorizationController(authorizationRequests: [req])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    // MARK: - Listing + delete

    public struct PasskeyMeta {
        public let id: String
        public let name: String?
        public let lastUsedAt: String?
        public let createdAt: String
    }

    public func listPasskeys(completion: @escaping ([PasskeyMeta]) -> Void) {
        guard let headers = auth.bearerHeaders() else { completion([]); return }
        client.get(path: "/auth-service/passkeys", headers: headers) { response in
            guard let arr = response?["data"] as? [[String: Any]] else { completion([]); return }
            completion(arr.compactMap { row in
                guard let id = row["id"] as? String, !id.isEmpty,
                      let createdAt = row["createdAt"] as? String else { return nil }
                return PasskeyMeta(
                    id: id,
                    name: row["name"] as? String,
                    lastUsedAt: row["lastUsedAt"] as? String,
                    createdAt: createdAt
                )
            })
        }
    }

    /// Delete one of the caller's passkeys.
    ///
    /// ⚠ BREAKING in 5.0.0: the completion carried no failure channel, so a 403
    /// `RECENT_AUTH_REQUIRED` (the route is step-up gated, s58.319) and a 404
    /// (the id is not the caller's) were both indistinguishable from a 200 —
    /// the app removed the row while the credential stayed live on the account.
    public func deletePasskey(
        _ passkeyId: String,
        completion: @escaping (Result<Void, SendoraCloudAuthError>) -> Void
    ) {
        if let refusal = auth.withheldRefusal() { completion(.failure(refusal)); return }
        guard let headers = auth.bearerHeaders() else {
            completion(.failure(.unauthorized("Sign in before deleting a passkey")))
            return
        }
        let escaped = passkeyId.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? passkeyId
        client.delete(path: "/auth-service/passkeys/\(escaped)", headers: headers) { [weak self] response in
            guard let self = self else { return }
            if let err = self.auth.parseError(response) { completion(.failure(err)); return }
            completion(.success(()))
        }
    }

    // MARK: - ASAuthorizationControllerDelegate

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let cred = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            // Phase 3 of register — POST attestation back.
            let body: [String: Any] = [
                "name": (pendingChallenge?.name as Any?) ?? NSNull(),
                "response": [
                    "id": Self.b64urlEncode(cred.credentialID),
                    "rawId": Self.b64urlEncode(cred.credentialID),
                    "type": "public-key",
                    "response": [
                        "clientDataJSON": Self.b64urlEncode(cred.rawClientDataJSON),
                        "attestationObject": Self.b64urlEncode(cred.rawAttestationObject ?? Data()),
                    ],
                ],
            ]
            client.post(path: "/auth-service/passkeys/register/finish", body: body, headers: auth.bearerHeaders()) { [weak self] response in
                guard let self = self else { return }
                guard let data = response?["data"] as? [String: Any],
                      let id = data["id"] as? String,
                      let credentialId = data["credentialId"] as? String else {
                    self.finishRegister(.failure(.verificationFailed("server rejected attestation")))
                    return
                }
                self.finishRegister(.success(RegisteredPasskey(id: id, credentialId: credentialId)))
            }
        } else if let cred = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            var body: [String: Any] = [
                "userId": (pendingChallenge?.userId as Any?) ?? NSNull(),
                "response": [
                    "id": Self.b64urlEncode(cred.credentialID),
                    "rawId": Self.b64urlEncode(cred.credentialID),
                    "type": "public-key",
                    "response": [
                        "clientDataJSON": Self.b64urlEncode(cred.rawClientDataJSON),
                        "authenticatorData": Self.b64urlEncode(cred.rawAuthenticatorData),
                        "signature": Self.b64urlEncode(cred.signature),
                        "userHandle": cred.userID.map(Self.b64urlEncode) as Any,
                    ],
                ],
            ]
            // ADR-033 INV-3: the body carries NO guest hint. A guest on this
            // device is HELD by the SIGN_IN commit below, never retired.
            client.post(path: "/auth-service/passkeys/authenticate/finish", body: body) { [weak self] response in
                guard let self = self else { return }
                guard response != nil, (response?["success"] as? Bool) == true else {
                    self.finishAssert(.failure(.verificationFailed("server rejected assertion")))
                    return
                }
                self.auth.completeExternalSignIn(response: response, startedFrom: self.assertStartedFrom) { [weak self] result in
                    guard let self = self else { return }
                    switch result {
                    case .success(let user): self.finishAssert(.success(user))
                    case .failure(let error): self.finishAssert(.failure(.authError(error)))
                    }
                }
            }
        } else {
            finishRegister(.failure(.unsupported))
            finishAssert(.failure(.unsupported))
        }
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        // ASAuthorizationError.canceled when the user dismisses the
        // system passkey sheet — surface as `userCancelled` so the
        // host app can offer a retry without painting it as a failure.
        let isCancel = (error as NSError).code == ASAuthorizationError.canceled.rawValue
        let failure: SendoraCloudPasskeyError = isCancel
            ? .userCancelled
            : .verificationFailed(error.localizedDescription)
        finishRegister(.failure(failure))
        finishAssert(.failure(failure))
    }

    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return presentingWindow ?? ASPresentationAnchor()
    }

    // MARK: - Helpers

    private func finishRegister(_ result: Result<RegisteredPasskey, SendoraCloudPasskeyError>) {
        guard let cb = registerCompletion else { return }
        registerCompletion = nil
        cb(result)
    }
    private func finishAssert(_ result: Result<SendoraCloudAuthUser, SendoraCloudPasskeyError>) {
        guard let cb = assertCompletion else { return }
        assertCompletion = nil
        cb(result)
    }

    private struct PasskeyContext {
        var name: String? = nil
        var userId: String? = nil
        var challenge: Data
    }

    private static func b64urlDecode(_ s: String) -> Data? {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let pad = (4 - b.count % 4) % 4
        b.append(String(repeating: "=", count: pad))
        return Data(base64Encoded: b)
    }

    private static func b64urlEncode(_ d: Data) -> String {
        return d.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
#endif
