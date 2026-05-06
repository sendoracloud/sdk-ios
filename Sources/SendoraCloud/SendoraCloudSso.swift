import Foundation
#if canImport(AuthenticationServices) && canImport(UIKit)
import AuthenticationServices
import UIKit

/// OIDC SSO via ASWebAuthenticationSession.
///
/// Flow:
///   1. signInWithOidc(returnTo:from:completion:) — calls
///      /auth-service/sso/oidc/start with the caller-supplied
///      `returnTo` (a custom URL scheme registered in the host
///      app's Info.plist, e.g. `myapp://oidc-callback`).
///   2. Backend returns `authorizationUrl`. Open it in
///      ASWebAuthenticationSession — this is Apple's
///      browser-cookie-shared SSO container; auth state from
///      Safari (already signed into Google / Okta / etc) carries
///      over without forcing a re-login.
///   3. IdP authenticates, redirects back to the Sendora callback,
///      which 302s to the customer's `returnTo` with
///      `#sendora_oidc_token=...` in the URL fragment.
///   4. ASWebAuthenticationSession captures the redirect when its
///      host (the URL scheme) matches the configured callback
///      scheme. We parse the fragment, swap the refresh token for
///      a session via /auth-service/token/refresh, and persist
///      identical to the standard signIn path.
public enum SendoraCloudSsoError: Error {
    case sessionStartFailed(String)
    case userCancelled
    case missingTokenInCallback
    case exchangeFailed(String)
    case missingPresenter
}

public final class SendoraCloudSso: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let client: APIClient
    private let auth: SendoraCloudAuth
    private weak var presentingWindow: UIWindow?
    private var activeSession: ASWebAuthenticationSession?

    init(client: APIClient, auth: SendoraCloudAuth) {
        self.client = client
        self.auth = auth
    }

    /// Begin OIDC SSO. `returnTo` MUST be one of the URL schemes
    /// registered in your app's Info.plist (CFBundleURLSchemes); if
    /// it doesn't match, ASWebAuthenticationSession will never close
    /// the browser. Sendora additionally validates the URL against
    /// the org's `allowedOrigins` list — even if the IdP redirects
    /// to a malicious URL, the backend rejects before issuing a
    /// token.
    public func signInWithOidc(
        returnTo: String,
        from window: UIWindow,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudSsoError>) -> Void
    ) {
        self.presentingWindow = window
        // Phase 1 — get the authorization URL.
        client.post(path: "/auth-service/sso/oidc/start", body: ["returnTo": returnTo]) { [weak self] response in
            guard let self = self else { return }
            guard let data = response?["data"] as? [String: Any],
                  let urlString = data["authorizationUrl"] as? String,
                  let authUrl = URL(string: urlString) else {
                completion(.failure(.sessionStartFailed("Missing authorizationUrl")))
                return
            }
            // ASWebAuthenticationSession needs the URL scheme part of
            // returnTo. Custom schemes only — universal links work too
            // but we treat them as opaque since iOS 17.
            guard let scheme = URL(string: returnTo)?.scheme else {
                completion(.failure(.sessionStartFailed("returnTo is missing a URL scheme")))
                return
            }

            DispatchQueue.main.async {
                let session = ASWebAuthenticationSession(url: authUrl, callbackURLScheme: scheme) { callback, err in
                    if let err = err {
                        let isCancel = (err as NSError).code == ASWebAuthenticationSessionError.canceledLogin.rawValue
                        completion(.failure(isCancel ? .userCancelled : .sessionStartFailed(err.localizedDescription)))
                        return
                    }
                    guard let callback = callback else {
                        completion(.failure(.sessionStartFailed("No callback URL")))
                        return
                    }
                    self.handleCallback(callback, completion: completion)
                }
                session.presentationContextProvider = self
                // ephemeralWebBrowserSession=false so the user's
                // existing browser cookies (Google / Okta sign-in
                // state) carry into the SSO session — this is the
                // whole point of using ASWebAuthenticationSession
                // over WKWebView. Setting it to true makes every SSO
                // a clean-slate login which defeats the UX.
                session.prefersEphemeralWebBrowserSession = false
                self.activeSession = session
                _ = session.start()
            }
        }
    }

    private func handleCallback(
        _ callback: URL,
        completion: @escaping (Result<SendoraCloudAuthUser, SendoraCloudSsoError>) -> Void
    ) {
        // Sendora delivers the refresh token in the fragment so it
        // doesn't end up in HTTP referrer headers / proxy logs. iOS
        // exposes the fragment via URLComponents only when we ask
        // for the raw `fragment` field.
        let fragment = callback.fragment ?? ""
        let params = parseFragment(fragment)

        if let err = params["sendora_oidc_error"] {
            completion(.failure(.exchangeFailed(err.removingPercentEncoding ?? err)))
            return
        }
        guard let refreshToken = params["sendora_oidc_token"]?.removingPercentEncoding else {
            completion(.failure(.missingTokenInCallback))
            return
        }

        // Phase 4 — swap refresh token for a session via the standard
        // refresh path. SendoraCloudAuth has the persistence + identity
        // wiring already; we delegate.
        client.post(path: "/auth-service/token/refresh", body: ["refreshToken": refreshToken]) { [weak self] response in
            guard let self = self else { return }
            guard let data = response?["data"] as? [String: Any],
                  let accessToken = data["accessToken"] as? String,
                  !accessToken.isEmpty,
                  let newRefresh = data["refreshToken"] as? String,
                  !newRefresh.isEmpty,
                  let expiresIn = data["expiresIn"] as? Int,
                  expiresIn > 0 else {
                completion(.failure(.exchangeFailed("Could not exchange OIDC token")))
                return
            }
            // We synthesise a minimal user shape from the JWT payload
            // since the refresh endpoint doesn't echo the user. Auth
            // already has the JWT-decode logic in persistFromAuth-
            // Response — we feed it a synthesised envelope.
            let synthesisedUser: [String: Any] = [
                "id": Self.subjectFromJwt(accessToken) ?? "",
                "email": NSNull(),
                "emailVerified": true,
                "name": NSNull(),
                "isAnonymous": false,
            ]
            let synthesisedEnvelope: [String: Any] = [
                "success": true,
                "data": [
                    "user": synthesisedUser,
                    "tokens": [
                        "accessToken": accessToken,
                        "refreshToken": newRefresh,
                        "expiresIn": expiresIn,
                        "tokenType": "Bearer",
                    ],
                ],
            ]
            if let user = self.auth.persistFromAuthResponse(synthesisedEnvelope) {
                completion(.success(user))
            } else {
                completion(.failure(.exchangeFailed("Persist failed")))
            }
        }
    }

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        return presentingWindow ?? ASPresentationAnchor()
    }

    // MARK: - Helpers

    private func parseFragment(_ s: String) -> [String: String] {
        var out: [String: String] = [:]
        for part in s.split(separator: "&") {
            let kv = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            if kv.count == 2 { out[kv[0]] = kv[1] }
        }
        return out
    }

    private static func subjectFromJwt(_ token: String) -> String? {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return nil }
        let payload = String(parts[1])
        // base64url → base64 (pad).
        var padded = payload.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let pad = (4 - padded.count % 4) % 4
        padded.append(String(repeating: "=", count: pad))
        guard let data = Data(base64Encoded: padded),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let sub = json["sub"] as? String else {
            return nil
        }
        return sub
    }
}
#endif
