import Foundation
import XCTest
@testable import SendoraCloud

/// The live-run result file (contract 2, `scripts/e2e/live-run-contract.mjs`). Both live classes
/// (`LiveLifecycleTests`, `LiveStagingTests`) run in ONE xctest process and append to the same file; it is
/// rewritten after every step, so a suite that dies mid-way still leaves what it proved.
///
/// `detail` is evidence only — status codes, counts, sizes. Never a token, key or email: every detail string
/// passes `scrub` (JWT-, key- and email-shaped substrings are replaced) before it is stored or printed.
enum LiveEnv {
    static let stagingHost = "api-dev.sendoracloud.com"

    struct Config {
        let base: String
        let apiKey: String
        let logAuth: String?
    }

    /// The guard every live class calls first: SENDORA_LIVE=1, staging host only, never a prod/live credential.
    static func require() throws -> Config {
        let env = ProcessInfo.processInfo.environment
        try XCTSkipUnless(env["SENDORA_LIVE"] == "1", "live staging test: set SENDORA_LIVE=1")
        let base = (env["SENDORA_API"].flatMap { $0.isEmpty ? nil : $0 } ?? "https://\(stagingHost)")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let host = URL(string: base)?.host, host == stagingHost, base.hasPrefix("https://") else {
            throw XCTSkip("SENDORA_API must be https://\(stagingHost) (staging only)")
        }
        let key = env["SENDORA_PK"] ?? ""
        let isProd: (String) -> Bool = { $0.range(of: #"^(pk|sk)_(prod|live)_"#, options: .regularExpression) != nil }
        guard key.hasPrefix("pk_"), !isProd(key) else {
            throw XCTSkip("SENDORA_PK must be a staging publishable key (pk_prod_ / pk_live_ refused)")
        }
        let logAuth = env["SENDORA_LOG_AUTH"].flatMap { $0.isEmpty ? nil : $0 }
        if let la = logAuth, isProd(la) { throw XCTSkip("SENDORA_LOG_AUTH has a production prefix — refused") }
        return Config(base: base, apiKey: key, logAuth: logAuth)
    }
}

final class LiveReport {
    static let shared = LiveReport()
    private let lock = NSLock()
    private var steps: [(id: String, status: String, detail: String)] = []

    static func scrub(_ s: String) -> String {
        var out = s
        for pattern in [#"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"#,   // JWTs
                        #"(pk|sk|lrt|kdt1)[._][A-Za-z0-9_.\-]{6,}"#,                // keys / revoke / device tokens
                        #"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"#] {    // emails
            out = out.replacingOccurrences(of: pattern, with: "<redacted>", options: .regularExpression)
        }
        return out
    }

    /// Record one step and rewrite the result file (when `SENDORA_LIVE_RESULT` is set). A step id reported
    /// twice keeps the LAST verdict unless an earlier one failed (a fail anywhere wins, as in `judgeLiveRun`).
    func record(_ id: String, pass: Bool, detail: String) {
        let clean = Self.scrub(detail)
        lock.lock()
        if let i = steps.firstIndex(where: { $0.id == id }) {
            if steps[i].status != "fail" { steps[i] = (id, pass ? "pass" : "fail", clean) }
        } else {
            steps.append((id, pass ? "pass" : "fail", clean))
        }
        let snapshot = steps
        lock.unlock()
        print("LIVE \(pass ? "PASS" : "FAIL") [\(id)] \(clean)")
        write(snapshot)
    }

    private func write(_ snapshot: [(id: String, status: String, detail: String)]) {
        let env = ProcessInfo.processInfo.environment
        guard let path = env["SENDORA_LIVE_RESULT"], !path.isEmpty else { return }
        let host = URL(string: env["SENDORA_API"] ?? "https://\(LiveEnv.stagingHost)")?.host ?? LiveEnv.stagingHost
        let doc: [String: Any] = [
            "contract": 2,
            "nonce": env["SENDORA_LIVE_NONCE"] ?? "",
            "sdk": "ios",
            // READ FROM THE SDK at runtime — never a literal (the contract's proof that this code ran).
            "sdkReportedVersion": SendoraCloud.sdkVersion,
            "suite": "LiveLifecycleTests+LiveStagingTests",
            "apiHost": host,
            "steps": snapshot.map { ["id": $0.id, "status": $0.status, "detail": $0.detail] },
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: doc, options: [.prettyPrinted, .sortedKeys]) else { return }
        let url = URL(fileURLWithPath: path)
        let tmp = url.appendingPathExtension("tmp")
        do {
            try data.write(to: tmp, options: .atomic)
            _ = try? FileManager.default.removeItem(at: url)
            try FileManager.default.moveItem(at: tmp, to: url)
        } catch {
            try? data.write(to: url, options: .atomic)
        }
    }
}
