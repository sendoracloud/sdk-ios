import Foundation
import os.log

final class SendoraCloudLogger {
    static let shared = SendoraCloudLogger()
    var isEnabled = false

    private let logger = os.Logger(subsystem: "com.sendora.sdk", category: "SendoraCloud")

    func debug(_ message: String) {
        guard isEnabled else { return }
        logger.debug("[\("SendoraCloud")] \(message)")
    }

    func error(_ message: String) {
        guard isEnabled else { return }
        logger.error("[\("SendoraCloud")] \(message)")
    }
}
