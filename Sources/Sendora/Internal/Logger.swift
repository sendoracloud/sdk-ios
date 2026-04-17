import Foundation
import os.log

final class SendoraLogger {
    static let shared = SendoraLogger()
    var isEnabled = false

    private let logger = os.Logger(subsystem: "com.sendora.sdk", category: "Sendora")

    func debug(_ message: String) {
        guard isEnabled else { return }
        logger.debug("[\("Sendora")] \(message)")
    }

    func error(_ message: String) {
        guard isEnabled else { return }
        logger.error("[\("Sendora")] \(message)")
    }
}
