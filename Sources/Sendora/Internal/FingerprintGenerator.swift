import Foundation
import CryptoKit

/// Generates a device fingerprint hash for attribution matching.
/// Does NOT include IP — the backend resolves IP from the request.
final class FingerprintGenerator {
    static func generate(device: DeviceContext) -> String {
        let input = [
            device.model,
            device.osVersion,
            String(device.screenWidth),
            String(device.screenHeight),
            device.locale,
            device.timezone,
        ].joined(separator: "|")

        let hash = SHA256.hash(data: Data(input.utf8))
        return hash.prefix(16).map { String(format: "%02x", $0) }.joined()
    }
}
