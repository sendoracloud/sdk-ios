import Foundation
#if canImport(CoreLocation)
import CoreLocation
#endif

/// Server-managed geofences for iOS.
///
/// Operator defines circular regions in the Sendora dashboard. SDK
/// fetches the active list at app init + on foreground, registers
/// each with `CLLocationManager.startMonitoring(for:)`, and reports
/// enter / exit / dwell transitions back to the backend.
///
/// iOS limit: **20 monitored regions per app**. SDK clamps to top-20
/// by `priority` (lower wins). Operator can manage priority in the
/// dashboard.
///
/// Permission requirements (host app must declare in Info.plist):
///   - NSLocationAlwaysAndWhenInUseUsageDescription
///   - NSLocationWhenInUseUsageDescription
///
/// And request `requestAlwaysAuthorization()` at runtime — geofences
/// only fire when in `.authorizedAlways`. Backgrounded `.authorizedWhenInUse`
/// will silently miss most transitions.
///
/// Usage:
/// ```swift
/// SendoraCloud.geofences?.start()         // pulls active list + starts monitoring
/// SendoraCloud.geofences?.refresh()        // call when foregrounded
/// ```
@available(iOS 13.0, *)
public final class SendoraCloudGeofences: NSObject {
    #if canImport(CoreLocation)
    private let locationManager = CLLocationManager()
    #endif
    private let client: APIClient
    private let configProvider: () -> SendoraCloudConfig?
    private let userIdProvider: () -> String?
    private let anonIdProvider: () -> String?

    /// Apple's hard cap. SDK trims to head-by-priority.
    private let iosRegionCap = 20

    init(
        client: APIClient,
        configProvider: @escaping () -> SendoraCloudConfig?,
        userIdProvider: @escaping () -> String?,
        anonIdProvider: @escaping () -> String?
    ) {
        self.client = client
        self.configProvider = configProvider
        self.userIdProvider = userIdProvider
        self.anonIdProvider = anonIdProvider
        super.init()
        #if canImport(CoreLocation)
        self.locationManager.delegate = self
        #endif
    }

    /// Start monitoring. Pulls active geofences + registers up to 20.
    /// Caller is responsible for prior `requestAlwaysAuthorization()`.
    public func start() {
        refresh()
    }

    /// Re-fetch the active geofence list. Call on app foreground or
    /// when the operator may have updated geofences server-side.
    /// De-registers any monitored region whose id is no longer in the
    /// active list, then registers any new ones (up to the iOS cap).
    public func refresh() {
        #if canImport(CoreLocation)
        client.get(path: "/push/geofences/list-for-device") { [weak self] response in
            guard let self = self else { return }
            let payload = response?["data"] as? [[String: Any]] ?? []
            // Trim to platform cap (server already sorts by priority asc).
            let trimmed = Array(payload.prefix(self.iosRegionCap))
            DispatchQueue.main.async {
                self.applyRegions(trimmed)
            }
        }
        #endif
    }

    /// Stop monitoring all SDK-registered regions. Use on logout / opt-out.
    public func stop() {
        #if canImport(CoreLocation)
        for region in locationManager.monitoredRegions where region.identifier.hasPrefix("sendora:") {
            locationManager.stopMonitoring(for: region)
        }
        #endif
    }

    #if canImport(CoreLocation)
    private func applyRegions(_ active: [[String: Any]]) {
        // Map of currently-monitored Sendora regions, keyed by id.
        var current: [String: CLCircularRegion] = [:]
        for region in locationManager.monitoredRegions {
            if let circ = region as? CLCircularRegion, circ.identifier.hasPrefix("sendora:") {
                current[circ.identifier] = circ
            }
        }

        var keep: Set<String> = []
        for entry in active {
            guard let id = entry["id"] as? String,
                  let lat = entry["latitude"] as? Double,
                  let lng = entry["longitude"] as? Double,
                  let radius = (entry["radiusMeters"] as? NSNumber)?.doubleValue else { continue }
            let identifier = "sendora:\(id)"
            keep.insert(identifier)
            let triggers = (entry["triggers"] as? [String]) ?? ["enter"]
            let region = CLCircularRegion(
                center: CLLocationCoordinate2D(latitude: lat, longitude: lng),
                radius: radius,
                identifier: identifier
            )
            region.notifyOnEntry = triggers.contains("enter") || triggers.contains("dwell")
            region.notifyOnExit = triggers.contains("exit")
            // CoreLocation has no native "dwell" callback — we approximate
            // via timer in didEnterRegion (NOT shipped in v1; emit as
            // standard enter for now). Documented in CLAUDE.md.

            if let existing = current[identifier] {
                // Same region already registered — only re-add if the
                // shape changed.
                if existing.center.latitude == lat &&
                   existing.center.longitude == lng &&
                   existing.radius == radius {
                    continue
                }
                locationManager.stopMonitoring(for: existing)
            }
            locationManager.startMonitoring(for: region)
        }

        // De-register Sendora regions no longer in the active list.
        for (identifier, region) in current where !keep.contains(identifier) {
            locationManager.stopMonitoring(for: region)
        }
    }

    private func reportEvent(_ event: String, region: CLCircularRegion) {
        let id = region.identifier.replacingOccurrences(of: "sendora:", with: "")
        var body: [String: Any] = [
            "geofenceId": id,
            "event": event,
            "latitude": region.center.latitude,
            "longitude": region.center.longitude,
        ]
        if let userId = userIdProvider() { body["userId"] = userId }
        if let anonId = anonIdProvider() { body["anonymousId"] = anonId }
        client.post(path: "/push/geofences/event", body: body) { _ in }
    }
    #endif
}

#if canImport(CoreLocation)
@available(iOS 13.0, *)
extension SendoraCloudGeofences: CLLocationManagerDelegate {
    public func locationManager(_ manager: CLLocationManager, didEnterRegion region: CLRegion) {
        guard let circ = region as? CLCircularRegion, circ.identifier.hasPrefix("sendora:") else { return }
        reportEvent("enter", region: circ)
    }

    public func locationManager(_ manager: CLLocationManager, didExitRegion region: CLRegion) {
        guard let circ = region as? CLCircularRegion, circ.identifier.hasPrefix("sendora:") else { return }
        reportEvent("exit", region: circ)
    }

    public func locationManager(_ manager: CLLocationManager, monitoringDidFailFor region: CLRegion?, withError error: Error) {
        // Silent — common cause is over-cap; SDK already trims, but
        // multi-SDK apps may push the device over. Operator visible
        // via APNs delivery rates dropping if expected.
    }
}
#endif
