import Foundation
#if canImport(UIKit)
import UIKit
#endif

struct DeviceContext {
    let deviceType: String
    let os: String
    let osVersion: String
    let model: String
    let screenWidth: Int
    let screenHeight: Int
    let locale: String
    let timezone: String
    let appVersion: String

    static func collect() -> DeviceContext {
        var deviceType = "desktop"
        var model = "unknown"
        var screenWidth = 0
        var screenHeight = 0

        #if canImport(UIKit) && !os(watchOS)
        let device = UIDevice.current
        switch device.userInterfaceIdiom {
        case .phone: deviceType = "mobile"
        case .pad: deviceType = "tablet"
        default: deviceType = "desktop"
        }
        model = device.model

        if let screen = UIScreen.value(forKey: "mainScreen") as? UIScreen {
            screenWidth = Int(screen.bounds.width * screen.scale)
            screenHeight = Int(screen.bounds.height * screen.scale)
        }
        #endif

        return DeviceContext(
            deviceType: deviceType,
            os: "iOS",
            osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            model: model,
            screenWidth: screenWidth,
            screenHeight: screenHeight,
            locale: Locale.current.identifier,
            timezone: TimeZone.current.identifier,
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
        )
    }

    func toDictionary() -> [String: Any] {
        return [
            "type": deviceType,
            "os": os,
            "osVersion": osVersion,
            "model": model,
        ]
    }
}
