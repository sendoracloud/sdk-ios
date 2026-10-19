import Foundation

/// Per-purpose consent state. Events are buffered until `grant()` is called.
///
/// 5.7.0: also the SERVER consent API — `record(purpose:granted:…)` and `requestDeletion(…)` (in
/// `SendoraCloudFlags.swift`). `grant()` / `revoke()` / `isGranted` are unchanged: the local event gate.
public final class SendoraCloudConsent {
    private let lock = NSLock()
    private var granted: Bool
    private var listeners: [(Bool) -> Void] = []
    private var client: APIClient?
    private var identity: () -> SendoraIdentitySnapshot = { SendoraIdentitySnapshot() }

    init(initial: Bool) {
        self.granted = initial
    }

    public var isGranted: Bool {
        lock.lock(); defer { lock.unlock() }
        return granted
    }

    public func grant() { set(true) }
    public func revoke() { set(false) }

    /// Wired by `configure()` (and the test seam): the client for the server calls + identify()'s identity.
    internal func attach(client: APIClient?, identity: @escaping () -> SendoraIdentitySnapshot) {
        lock.lock(); self.client = client; self.identity = identity; lock.unlock()
    }

    internal func attachedClient() -> APIClient? { lock.lock(); defer { lock.unlock() }; return client }

    internal func identitySnapshot() -> SendoraIdentitySnapshot {
        lock.lock(); let provider = identity; lock.unlock()
        return provider()
    }

    func subscribe(_ cb: @escaping (Bool) -> Void) {
        lock.lock()
        listeners.append(cb)
        lock.unlock()
    }

    private func set(_ value: Bool) {
        lock.lock()
        if granted == value { lock.unlock(); return }
        granted = value
        let copy = listeners
        lock.unlock()
        for cb in copy { cb(value) }
    }
}
