import Foundation

// 5.7.0 — server consent + feature flags, with identify()'s identityToken.
//
// Until 5.7.0 iOS had neither: `SendoraCloud.consent` was only the LOCAL event gate (`grant()` / `revoke()`), and there
// was no flags API at all. The backend now honours a consent record / deletion request / audience rule only when the
// caller PROVES the userId (s58.396 F65, s58.400 F64) — a secret key, the player's own Bearer, or the project's HMAC
// `identityToken` for that userId. These calls send the token `identify(userId:options:)` was given, by the rule in
// `SendoraIdentityRequest.identityToken` (a port of RN `withInputIdentityToken`).

/// A refused SDK call: the server's `code` + HTTP `status` (or the SDK's own: `NOT_CONFIGURED`, `NETWORK`,
/// `BAD_RESPONSE`, `HTTP_<status>`). A non-2xx is ALWAYS thrown — never an empty / nil answer (s58.335 gotcha:
/// no transport throws on its own, so a discarded return hides a refusal).
public struct SendoraCloudAPIError: Error, LocalizedError, Equatable {
    public let code: String
    public let status: Int
    public let message: String
    public let retryAfterSeconds: Int?
    public var errorDescription: String? { message }
    public init(code: String, status: Int, message: String, retryAfterSeconds: Int? = nil) {
        self.code = code
        self.status = status
        self.message = message
        self.retryAfterSeconds = retryAfterSeconds
    }
}

/// A JSON value as the server sent it (a flag's `value` is any JSON).
public enum SendoraJSONValue: Equatable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([SendoraJSONValue])
    case object([String: SendoraJSONValue])

    public var boolValue: Bool? { if case .bool(let b) = self { return b }; return nil }
    public var doubleValue: Double? { if case .number(let n) = self { return n }; return nil }
    public var intValue: Int? { if case .number(let n) = self { return Int(exactly: n) }; return nil }
    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var isNull: Bool { self == .null }

    internal init(any: Any?) {
        switch any {
        case nil, is NSNull: self = .null
        case let n as NSNumber:
            if CFGetTypeID(n) == CFBooleanGetTypeID() { self = .bool(n.boolValue) } else { self = .number(n.doubleValue) }
        case let s as String: self = .string(s)
        case let a as [Any]: self = .array(a.map { SendoraJSONValue(any: $0) })
        case let o as [String: Any]: self = .object(o.mapValues { SendoraJSONValue(any: $0) })
        default: self = .null
        }
    }
}

/// One evaluated flag. `reason` = why this value (the server's `ruleMatched`: `default`, `inactive`, `not_found`,
/// `env_disabled`, a rule id…). `variant` is present only when the server names one.
public struct SendoraFlagValue: Equatable {
    public let key: String
    public let value: SendoraJSONValue
    public let variant: String?
    public let reason: String

    internal static func decode(_ o: [String: Any], fallbackKey: String? = nil) -> SendoraFlagValue? {
        guard let key = (o["key"] as? String) ?? fallbackKey else { return nil }
        return SendoraFlagValue(key: key, value: SendoraJSONValue(any: o["value"]), variant: o["variant"] as? String,
                                reason: (o["ruleMatched"] as? String) ?? (o["reason"] as? String) ?? "")
    }
}

// MARK: - The shared request + identity-token rule

/// The identity `identify(userId:options:)` established: the identified user, and the token PLUS the user it was
/// issued for (they differ once auth switches the user — a token never travels with another user's id).
internal struct SendoraIdentitySnapshot {
    var currentUserId: String?
    var tokenUserId: String?
    var token: String?
}

internal enum SendoraIdentityRequest {
    /// Route limits on `identityToken` (the backend zod schemas).
    static let flagsTokenMax = 128
    static let consentTokenMax = 256

    /// An explicit argument wins (sent as given). Otherwise identify()'s remembered token is added ONLY when the
    /// call's `userId` is the user that token was issued for AND still the identified user, and only if it fits the
    /// route's limit. Never persisted — read from memory at call time.
    static func identityToken(explicit: String?, callUserId: String?, identity: SendoraIdentitySnapshot, maxLength: Int) -> String? {
        if let explicit = explicit { return explicit }
        guard let token = identity.token, !token.isEmpty, token.count <= maxLength,
              let uid = callUserId, !uid.isEmpty, uid == identity.tokenUserId, uid == identity.currentUserId else { return nil }
        return token
    }

    /// POST `path`, unwrap `{ success, data }` or THROW the refusal.
    static func post(_ client: APIClient?, _ path: String, _ body: [String: Any], verb: String) async throws -> Any {
        guard let client = client else {
            throw SendoraCloudAPIError(code: "NOT_CONFIGURED", status: 0, message: "SendoraCloud.configure() must run before \(verb)().")
        }
        let rich: APIClient.RichResponse = await withCheckedContinuation { cont in
            client.requestWithDetails(method: "POST", path: path, body: body) { cont.resume(returning: $0) }
        }
        let status = rich.statusCode
        if (200..<300).contains(status) {
            if rich.body?["success"] as? Bool == true, let data = rich.body?["data"], !(data is NSNull) { return data }
            throw SendoraCloudAPIError(code: "BAD_RESPONSE", status: status, message: "\(verb)(): unexpected response")
        }
        if status == 0 {
            throw SendoraCloudAPIError(code: "NETWORK", status: 0, message: "\(verb)() could not reach the server.",
                                       retryAfterSeconds: rich.retryAfterSeconds)
        }
        throw SendoraCloudAPIError(code: rich.errorCode ?? "HTTP_\(status)", status: status,
                                   message: rich.errorMessage ?? "\(verb)() failed (\(status))", retryAfterSeconds: rich.retryAfterSeconds)
    }

    static func compact(_ pairs: [(String, Any?)]) -> [String: Any] {
        var out: [String: Any] = [:]
        for (k, v) in pairs { if let v = v { out[k] = v } }
        return out
    }
}

// MARK: - Flags

/// Server feature flags (5.7.0). `SendoraCloud.flags` after `configure()`.
///
/// ```swift
/// let flag = try await SendoraCloud.flags?.evaluate(key: "new_onboarding")
/// if flag?.value.boolValue == true { showNewOnboarding() }
/// ```
public final class SendoraCloudFlags: @unchecked Sendable {
    private let client: APIClient?
    private let identity: () -> SendoraIdentitySnapshot

    internal init(client: APIClient?, identity: @escaping () -> SendoraIdentitySnapshot) {
        self.client = client
        self.identity = identity
    }

    private func body(userId: String?, entityId: String?, environment: String?, identityToken: String?, extra: [(String, Any?)] = []) -> [String: Any] {
        let snapshot = identity()
        let uid = userId ?? snapshot.currentUserId   // defaults to the identified user
        let token = SendoraIdentityRequest.identityToken(explicit: identityToken, callUserId: uid, identity: snapshot,
                                                         maxLength: SendoraIdentityRequest.flagsTokenMax)
        return SendoraIdentityRequest.compact(extra + [("userId", uid), ("entityId", entityId), ("environment", environment), ("identityToken", token)])
    }

    /// Evaluate one flag for `userId` (default: the identified user). Throws `SendoraCloudAPIError` on a refusal.
    public func evaluate(key: String, userId: String? = nil, entityId: String? = nil, environment: String? = nil,
                         identityToken: String? = nil) async throws -> SendoraFlagValue {
        let data = try await SendoraIdentityRequest.post(client, "/feature-flags/evaluate",
                                                         body(userId: userId, entityId: entityId, environment: environment,
                                                              identityToken: identityToken, extra: [("key", key)]),
                                                         verb: "flags.evaluate")
        guard let o = data as? [String: Any], let flag = SendoraFlagValue.decode(o, fallbackKey: key) else {
            throw SendoraCloudAPIError(code: "BAD_RESPONSE", status: 200, message: "flags.evaluate(): unexpected response")
        }
        return flag
    }

    /// Every active flag of this app's project, keyed by flag key.
    public func evaluateAll(userId: String? = nil, entityId: String? = nil, environment: String? = nil,
                            identityToken: String? = nil) async throws -> [String: SendoraFlagValue] {
        let data = try await SendoraIdentityRequest.post(client, "/feature-flags/evaluate-all",
                                                         body(userId: userId, entityId: entityId, environment: environment, identityToken: identityToken),
                                                         verb: "flags.evaluateAll")
        var out: [String: SendoraFlagValue] = [:]
        if let rows = data as? [[String: Any]] {            // the server's shape: an array of { key, value, ruleMatched }
            for row in rows { if let f = SendoraFlagValue.decode(row) { out[f.key] = f } }
        } else if let map = data as? [String: Any] {        // tolerated: { key: { value, … } }
            for (k, v) in map { if let o = v as? [String: Any], let f = SendoraFlagValue.decode(o, fallbackKey: k) { out[k] = f } }
        } else {
            throw SendoraCloudAPIError(code: "BAD_RESPONSE", status: 200, message: "flags.evaluateAll(): unexpected response")
        }
        return out
    }
}

// MARK: - Consent (server half)

public enum SendoraConsentPurpose: String {
    case marketing, analytics, functional, necessary
}

/// What `consent.record` stored. `sourceVerified` = the server accepted the caller's proof (identity token / Bearer).
public struct SendoraConsentRecord: Equatable {
    public let id: String
    public let purpose: String
    public let granted: Bool
    public let userId: String?
    public let email: String?
    public let entityId: String?
    public let source: String?
    public let sourceVerified: Bool?
    public let createdAt: String?

    internal static func decode(_ o: [String: Any]) -> SendoraConsentRecord? {
        guard let id = o["id"] as? String else { return nil }
        return SendoraConsentRecord(id: id, purpose: o["purpose"] as? String ?? "", granted: o["granted"] as? Bool ?? false,
                                    userId: o["userId"] as? String, email: o["email"] as? String, entityId: o["entityId"] as? String,
                                    source: o["source"] as? String, sourceVerified: o["sourceVerified"] as? Bool, createdAt: o["createdAt"] as? String)
    }
}

/// What `consent.requestDeletion` filed. `status` `pending` (proven) or `unconfirmed` (an emailed confirmation is
/// required first — an unproven request names no account).
public struct SendoraDeletionRequest: Equatable {
    public let id: String
    public let status: String
    public let userId: String?
    public let email: String?
    public let reason: String?
    public let sourceVerified: Bool?
    public let createdAt: String?

    internal static func decode(_ o: [String: Any]) -> SendoraDeletionRequest? {
        guard let id = o["id"] as? String else { return nil }
        return SendoraDeletionRequest(id: id, status: o["status"] as? String ?? "", userId: o["userId"] as? String,
                                      email: o["email"] as? String, reason: o["reason"] as? String,
                                      sourceVerified: o["sourceVerified"] as? Bool, createdAt: o["createdAt"] as? String)
    }
}

public extension SendoraCloudConsent {
    /// Record a consent decision on the server (5.7.0). The local event gate (`grant()` / `revoke()`) is separate and
    /// unchanged. Pass `userId` for the identified user and identify()'s token proves it (`sourceVerified`).
    func record(purpose: SendoraConsentPurpose, granted: Bool, entityId: String? = nil, userId: String? = nil,
                email: String? = nil, source: String? = nil, identityToken: String? = nil) async throws -> SendoraConsentRecord {
        let token = SendoraIdentityRequest.identityToken(explicit: identityToken, callUserId: userId, identity: identitySnapshot(),
                                                         maxLength: SendoraIdentityRequest.consentTokenMax)
        let body = SendoraIdentityRequest.compact([("purpose", purpose.rawValue), ("granted", granted), ("entityId", entityId),
                                                   ("userId", userId), ("email", email), ("source", source), ("identityToken", token)])
        let data = try await SendoraIdentityRequest.post(attachedClient(), "/consent/record", body, verb: "consent.record")
        guard let o = data as? [String: Any], let rec = SendoraConsentRecord.decode(o) else {
            throw SendoraCloudAPIError(code: "BAD_RESPONSE", status: 201, message: "consent.record(): unexpected response")
        }
        return rec
    }

    /// File a data-deletion request (GDPR / CCPA) for the user (5.7.0).
    func requestDeletion(entityId: String? = nil, userId: String? = nil, email: String? = nil, reason: String? = nil,
                         identityToken: String? = nil) async throws -> SendoraDeletionRequest {
        let token = SendoraIdentityRequest.identityToken(explicit: identityToken, callUserId: userId, identity: identitySnapshot(),
                                                         maxLength: SendoraIdentityRequest.consentTokenMax)
        let body = SendoraIdentityRequest.compact([("entityId", entityId), ("userId", userId), ("email", email), ("reason", reason),
                                                   ("identityToken", token)])
        let data = try await SendoraIdentityRequest.post(attachedClient(), "/consent/deletion-request", body, verb: "consent.requestDeletion")
        guard let o = data as? [String: Any], let req = SendoraDeletionRequest.decode(o) else {
            throw SendoraCloudAPIError(code: "BAD_RESPONSE", status: 201, message: "consent.requestDeletion(): unexpected response")
        }
        return req
    }
}
