//
// SendoraCloudSupport.swift
//
// Wave 66 — Contact widget for iOS apps. Opens the worker-hosted
// embed at `https://go.sendoracloud.com/embed/contact?widgetId=…`
// inside a WKWebView wrapped in a UIViewController, presented
// modally. The HTML form posts to `POST /widgets/:id/submit` —
// same backend the web widget.js uses.
//
// On submit success the embed page navigates to
// `sendora://close?ticketId=…&portalUrl=…`. Our WKNavigationDelegate
// catches the scheme, cancels the navigation, parses the query,
// dismisses the modal, and fires the host's completion callback.
//
// Single source of truth = the worker route. Updating contact form
// UI = redeploy worker. Zero SDK release. The native code below is
// only the bootstrap shell.
//

#if canImport(UIKit)
import UIKit
import WebKit

public struct SendoraContactResult {
    /// UUID of the ticket created server-side. Empty if the user closed
    /// without submitting.
    public let ticketId: String
    /// Operator's tracking-portal URL for the ticket (or nil when the
    /// user closed without submitting).
    public let portalUrl: URL?
    /// True if the user submitted the form; false if they just closed.
    public let submitted: Bool
}

public enum SendoraContactError: Error {
    case notConfigured
    case invalidWidgetId
    case missingPresenter
    /// Wave 69: presentTicketHistory needs an active SDK auth session.
    case notSignedIn
}

@MainActor
public final class SendoraCloudSupport {
    private let widgetEmbedHost: URL
    private let apiBaseUrl: URL

    internal init(widgetEmbedHost: URL = URL(string: "https://go.sendoracloud.com")!,
                  apiBaseUrl: URL = URL(string: "https://api.sendoracloud.com")!) {
        self.widgetEmbedHost = widgetEmbedHost
        self.apiBaseUrl = apiBaseUrl
    }

    /// Wave 73 — fetch the unread ticket count for the support tab
    /// badge. Bearer JWT auth via the SDK's current end-user session.
    /// Returns 0 when no SDK auth exists (anon or identified).
    ///
    /// Recommended polling cadence: on app foreground + every 60s
    /// while the app is active. Host app renders the resulting count
    /// as a tab badge / dot.
    public func getUnreadCount(
        widgetId: String,
        completion: @escaping (Int) -> Void
    ) {
        guard !widgetId.isEmpty, let auth = SendoraCloud.auth else {
            completion(0); return
        }
        auth.getAccessToken { token in
            guard let token = token, !token.isEmpty else {
                DispatchQueue.main.async { completion(0) }
                return
            }
            let url = self.apiBaseUrl
                .appendingPathComponent("/api/v1/widgets")
                .appendingPathComponent(widgetId)
                .appendingPathComponent("/my-tickets/unread-count")
            var req = URLRequest(url: url)
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            req.timeoutInterval = 10
            URLSession.shared.dataTask(with: req) { data, _, _ in
                var count = 0
                if let data = data,
                   let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let inner = obj["data"] as? [String: Any],
                   let n = inner["count"] as? Int {
                    count = n
                }
                DispatchQueue.main.async { completion(count) }
            }.resume()
        }
    }

    /// Open the in-app ticket history list (Wave 69).
    ///
    /// Requires an active SDK auth session (anon or identified). The
    /// SDK passes the current access token via URL hash fragment so
    /// the embed can call backend `/widgets/:widgetId/my-tickets*`
    /// endpoints as the signed-in end user.
    ///
    /// Returns `.failure(.notSignedIn)` if there's no auth row.
    public func presentTicketHistory(
        widgetId: String,
        from presenter: UIViewController,
        theme: String = "auto",
        completion: ((Result<SendoraContactResult, SendoraContactError>) -> Void)? = nil
    ) {
        guard !widgetId.isEmpty else {
            completion?(.failure(.invalidWidgetId))
            return
        }
        guard let auth = SendoraCloud.auth else {
            completion?(.failure(.notSignedIn))
            return
        }

        auth.getAccessToken { [weak presenter] token in
            Task { @MainActor in
                guard let presenter = presenter else { return }
                guard let token = token, !token.isEmpty else {
                    completion?(.failure(.notSignedIn))
                    return
                }

                var components = URLComponents(url: self.widgetEmbedHost.appendingPathComponent("/embed/tickets"),
                                               resolvingAgainstBaseURL: false)!
                components.queryItems = [
                    URLQueryItem(name: "widgetId", value: widgetId),
                    URLQueryItem(name: "theme", value: theme),
                ]
                guard var url = components.url else {
                    completion?(.failure(.invalidWidgetId))
                    return
                }
                // JWT goes in the fragment so it doesn't appear in
                // server logs / referer headers. Embed HTML scrubs
                // the hash via history.replaceState on load.
                if let escaped = token.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) {
                    url = URL(string: url.absoluteString + "#access=" + escaped)!
                }

                let vc = SendoraContactWidgetViewController(url: url, completion: completion)
                if #available(iOS 15.0, *) {
                    if let sheet = vc.sheetPresentationController {
                        sheet.detents = [.large()]
                        sheet.prefersGrabberVisible = true
                    }
                }
                presenter.present(vc, animated: true)
            }
        }
    }

    /// Open the contact widget modally over `presenter`.
    ///
    /// Identity handling (Wave 68): the widget auto-reads the SDK's
    /// current user state from `SendoraCloud.auth?.getCurrentUser()`
    /// when the caller doesn't override the prefill params:
    ///
    ///   - identified user (has verified email) → email field hidden,
    ///     read-only chip shown, `userId` posted with the ticket so it
    ///     stitches to the same profile as analytics events.
    ///   - anonymous SDK row (userId only, no email) → email field
    ///     shown for entry, anon `userId` posted.
    ///   - no SDK auth at all → standard form, no `userId`.
    ///
    /// Caller can still pass explicit `prefillName` / `prefillEmail` /
    /// `prefillUserId` to override, or `lockEmail = true` to force the
    /// hidden-email mode (use when prefillEmail is the verified value).
    ///
    /// - Parameters:
    ///   - widgetId: UUID of the widget configured in the Sendora
    ///     dashboard. Bot-check + rate-limit run server-side on submit.
    ///   - presenter: View controller used to present the modal sheet.
    ///   - theme: `"auto"`, `"light"`, or `"dark"`.
    ///   - prefillName / prefillEmail / prefillUserId: Optional overrides.
    ///     Default: read from `SendoraCloud.auth?.getCurrentUser()`.
    ///   - lockEmail: When true (and an email is prefilled), the email
    ///     field is hidden + read-only.
    ///   - completion: Fired when the user closes the sheet — either
    ///     after a successful submit (`submitted = true`) or via close
    ///     button (`submitted = false`).
    public func presentContactWidget(
        widgetId: String,
        from presenter: UIViewController,
        theme: String = "auto",
        prefillName: String? = nil,
        prefillEmail: String? = nil,
        prefillUserId: String? = nil,
        lockEmail: Bool? = nil,
        completion: ((Result<SendoraContactResult, SendoraContactError>) -> Void)? = nil
    ) {
        guard !widgetId.isEmpty else {
            completion?(.failure(.invalidWidgetId))
            return
        }

        // Auto-resolve identity from SDK auth state when caller didn't
        // override. `SendoraCloud.auth?.currentUser` returns the anon
        // or identified row that's currently signed in.
        let sdkUser = SendoraCloud.auth?.currentUser
        let resolvedName = prefillName ?? sdkUser?.name
        let resolvedEmail = prefillEmail ?? sdkUser?.email
        let resolvedUserId = prefillUserId ?? sdkUser?.id
        // Lock the email field when we have a verified email on file
        // (identified user) and the caller didn't explicitly override.
        // Anonymous rows have no email so this naturally stays false.
        let resolvedLockEmail: Bool = lockEmail ?? (
            sdkUser?.email != nil
            && sdkUser?.emailVerified == true
            && sdkUser?.isAnonymous == false
        )

        var components = URLComponents(url: widgetEmbedHost.appendingPathComponent("/embed/contact"),
                                       resolvingAgainstBaseURL: false)!
        var items: [URLQueryItem] = [
            URLQueryItem(name: "widgetId", value: widgetId),
            URLQueryItem(name: "theme", value: theme),
        ]
        if let n = resolvedName, !n.isEmpty {
            items.append(URLQueryItem(name: "prefillName", value: n))
        }
        if let e = resolvedEmail, !e.isEmpty {
            items.append(URLQueryItem(name: "prefillEmail", value: e))
        }
        if let u = resolvedUserId, !u.isEmpty {
            items.append(URLQueryItem(name: "prefillUserId", value: u))
        }
        if resolvedLockEmail, let e = resolvedEmail, !e.isEmpty {
            items.append(URLQueryItem(name: "lockEmail", value: "1"))
        }
        components.queryItems = items

        guard let url = components.url else {
            completion?(.failure(.invalidWidgetId))
            return
        }

        let vc = SendoraContactWidgetViewController(url: url, completion: completion)
        if #available(iOS 15.0, *) {
            if let sheet = vc.sheetPresentationController {
                sheet.detents = [.large()]
                sheet.prefersGrabberVisible = true
            }
        }
        presenter.present(vc, animated: true)
    }
}

// MARK: - Internal view controller

@MainActor
internal final class SendoraContactWidgetViewController: UIViewController, WKNavigationDelegate {
    private let targetUrl: URL
    private var webView: WKWebView!
    private var completion: ((Result<SendoraContactResult, SendoraContactError>) -> Void)?
    private var didFire = false

    init(url: URL,
         completion: ((Result<SendoraContactResult, SendoraContactError>) -> Void)?) {
        self.targetUrl = url
        self.completion = completion
        super.init(nibName: nil, bundle: nil)
        modalPresentationStyle = .formSheet
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) unsupported") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        let config = WKWebViewConfiguration()
        // Bridge contact form → native dismiss. We catch the
        // `sendora://close` redirect in the navigation delegate; no
        // postMessage handler needed.
        webView = WKWebView(frame: view.bounds, configuration: config)
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        webView.navigationDelegate = self
        view.addSubview(webView)
        webView.load(URLRequest(url: targetUrl))
    }

    func webView(_ webView: WKWebView,
                 decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.allow); return
        }
        if url.scheme == "sendora" && url.host == "close" {
            decisionHandler(.cancel)
            handleCloseRedirect(url: url)
            return
        }
        // First-party HTTPS only — refuse off-domain navigations
        // inside the embed (e.g. if a customer-supplied welcome
        // message somehow included a link).
        if url.scheme != "https" && url.scheme != "about" {
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    private func handleCloseRedirect(url: URL) {
        if didFire { return }
        didFire = true
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let ticketId = comps?.queryItems?.first(where: { $0.name == "ticketId" })?.value ?? ""
        let portalUrlStr = comps?.queryItems?.first(where: { $0.name == "portalUrl" })?.value ?? ""
        let portalUrl = portalUrlStr.isEmpty ? nil : URL(string: portalUrlStr)
        let submitted = !ticketId.isEmpty
        let result = SendoraContactResult(ticketId: ticketId, portalUrl: portalUrl, submitted: submitted)
        let cb = completion
        completion = nil
        dismiss(animated: true) {
            cb?(.success(result))
        }
    }
}
#endif
