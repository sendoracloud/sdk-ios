import Foundation
#if canImport(UserNotifications)
import UserNotifications
#endif

/// iOS Critical Alert permission helper.
///
/// Critical Alerts bypass Do Not Disturb / Focus / silent mode.
/// Requirements:
///   1. Host app must hold the Apple-issued entitlement
///      `com.apple.developer.usernotifications.critical-alerts`. Request
///      via developer.apple.com support form. Approval takes 1-3 weeks.
///   2. User must grant `criticalAlert` permission at runtime via
///      `UNUserNotificationCenter.requestAuthorization`.
///
/// Without entitlement OR permission, APNs silently downgrades the
/// payload to a regular alert (no bypass, normal sound).
///
/// Usage:
/// ```swift
/// SendoraCloudCriticalAlerts.requestPermission { granted in
///     if granted {
///         print("user granted critical-alert permission")
///     }
/// }
/// ```
public enum SendoraCloudCriticalAlerts {

    /// Request all standard notification permissions PLUS the
    /// `criticalAlert` option. Caller is responsible for invoking on
    /// a user gesture (Apple requires it for the prompt to render).
    ///
    /// Returns `granted=true` when ALL options are granted; `false`
    /// when the user denied OR the host app lacks the entitlement (the
    /// system silently strips `criticalAlert` from the request when
    /// the entitlement is absent).
    public static func requestPermission(_ completion: @escaping (Bool) -> Void) {
        #if canImport(UserNotifications)
        let options: UNAuthorizationOptions = [.alert, .badge, .sound, .criticalAlert]
        UNUserNotificationCenter.current().requestAuthorization(options: options) { granted, _ in
            completion(granted)
        }
        #else
        completion(false)
        #endif
    }

    /// Read the user's current critical-alert authorization. Useful
    /// when the host app wants to re-prompt or render an in-product
    /// upsell explaining why critical alerts matter.
    public static func currentSetting(_ completion: @escaping (Bool) -> Void) {
        #if canImport(UserNotifications)
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            completion(settings.criticalAlertSetting == .enabled)
        }
        #else
        completion(false)
        #endif
    }
}
