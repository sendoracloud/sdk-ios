import Foundation

/// Security validation helpers. All public methods throw `SendoraError`
/// on invalid input — callers are expected to treat these as programmer errors.
public enum SendoraError: Error, CustomStringConvertible {
    case invalidApiKey(String)
    case invalidApiUrl(String)
    case invalidEventName(String)
    case payloadTooLarge(Int)
    case payloadTooDeep(Int)
    case forbiddenKey(String)

    public var description: String {
        switch self {
        case .invalidApiKey(let m): return "[SendoraCloud] invalid apiKey: \(m)"
        case .invalidApiUrl(let m): return "[SendoraCloud] invalid apiUrl: \(m)"
        case .invalidEventName(let m): return "[SendoraCloud] invalid event name: \(m)"
        case .payloadTooLarge(let n): return "[SendoraCloud] payload too large: \(n) bytes"
        case .payloadTooDeep(let n): return "[SendoraCloud] payload nested too deep: \(n) levels"
        case .forbiddenKey(let k): return "[SendoraCloud] forbidden property key: \(k)"
        }
    }
}

enum SendoraCloudValidator {
    static let keyPattern = #"^pk_[A-Za-z0-9_-]{16,}$"#
    static let eventPattern = #"^[a-zA-Z][a-zA-Z0-9._:\-]{0,127}$"#
    static let maxPropsBytes = 32 * 1024
    static let maxPropsDepth = 5
    static let forbiddenKeys: Set<String> = ["__proto__", "constructor", "prototype"]

    static func validateApiKey(_ key: String) throws {
        if key.hasPrefix("sk_") || key.hasPrefix("sendora_secret_") {
            throw SendoraError.invalidApiKey(
                "secret keys cannot be used in iOS SDK — use a publishable key (pk_...)"
            )
        }
        if key.range(of: keyPattern, options: .regularExpression) == nil {
            throw SendoraError.invalidApiKey("expected pk_... (17+ chars)")
        }
    }

    static func validateApiUrl(_ url: String) throws {
        if url.hasPrefix("http://localhost") || url.hasPrefix("http://127.0.0.1") { return }
        if !url.hasPrefix("https://") {
            throw SendoraError.invalidApiUrl("must be https:// (http://localhost ok in dev)")
        }
    }

    static func validateEventName(_ name: String) throws {
        if name.range(of: eventPattern, options: .regularExpression) == nil {
            throw SendoraError.invalidEventName(name)
        }
    }

    static func validateProperties(_ props: [String: Any]?) throws {
        guard let props = props else { return }
        try assertNoForbiddenKeys(props)
        let depth = measureDepth(props)
        if depth > maxPropsDepth {
            throw SendoraError.payloadTooDeep(depth)
        }
        guard JSONSerialization.isValidJSONObject(props) else {
            throw SendoraError.payloadTooLarge(-1)
        }
        let data = try JSONSerialization.data(withJSONObject: props)
        if data.count > maxPropsBytes {
            throw SendoraError.payloadTooLarge(data.count)
        }
    }

    private static func measureDepth(_ v: Any, _ depth: Int = 0) -> Int {
        if let dict = v as? [String: Any] {
            var max = depth
            for (_, value) in dict {
                let d = measureDepth(value, depth + 1)
                if d > max { max = d }
            }
            return max
        }
        if let arr = v as? [Any] {
            var max = depth
            for value in arr {
                let d = measureDepth(value, depth + 1)
                if d > max { max = d }
            }
            return max
        }
        return depth
    }

    private static func assertNoForbiddenKeys(_ v: Any) throws {
        if let dict = v as? [String: Any] {
            for (k, value) in dict {
                if forbiddenKeys.contains(k) {
                    throw SendoraError.forbiddenKey(k)
                }
                try assertNoForbiddenKeys(value)
            }
        }
    }
}
