import Foundation

/// Per-purpose consent state. Events are buffered until `grant()` is called.
public final class SendoraConsent {
    private let lock = NSLock()
    private var granted: Bool
    private var listeners: [(Bool) -> Void] = []

    init(initial: Bool) {
        self.granted = initial
    }

    public var isGranted: Bool {
        lock.lock(); defer { lock.unlock() }
        return granted
    }

    public func grant() { set(true) }
    public func revoke() { set(false) }

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
