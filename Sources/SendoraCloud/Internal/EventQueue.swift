import Foundation

/// Thread-safe event queue with batched flushing and offline persistence.
final class EventQueue {
    private let queue = DispatchQueue(label: "com.sendora.eventqueue")
    private var events: [[String: Any]] = []
    private var flushTimer: Timer?
    private let storage: SendoraStorage
    private let flushAt: Int
    private let maxSize: Int
    private var flushHandler: (([[String: Any]]) -> Void)?

    init(storage: SendoraStorage, flushAt: Int = 20, maxSize: Int = 1000) {
        self.storage = storage
        self.flushAt = flushAt
        self.maxSize = maxSize

        // Load persisted events from previous session
        let persisted = storage.loadEventQueue()
        if !persisted.isEmpty {
            self.events = persisted
            SendoraCloudLogger.shared.debug("Loaded \(persisted.count) persisted events")
        }
    }

    func setFlushHandler(_ handler: @escaping ([[String: Any]]) -> Void) {
        self.flushHandler = handler
    }

    func startTimer(interval: TimeInterval) {
        DispatchQueue.main.async { [weak self] in
            self?.flushTimer?.invalidate()
            self?.flushTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
                self?.flush()
            }
        }
    }

    func stopTimer() {
        DispatchQueue.main.async { [weak self] in
            self?.flushTimer?.invalidate()
            self?.flushTimer = nil
        }
    }

    func add(event: [String: Any]) {
        queue.async { [weak self] in
            guard let self = self else { return }
            self.events.append(event)

            // Drop oldest if over max
            if self.events.count > self.maxSize {
                self.events.removeFirst(self.events.count - self.maxSize)
            }

            // Auto-flush if threshold reached
            if self.events.count >= self.flushAt {
                self.performFlush()
            }
        }
    }

    func flush() {
        queue.async { [weak self] in
            self?.performFlush()
        }
    }

    func persistToDisk() {
        queue.async { [weak self] in
            guard let self = self else { return }
            self.storage.saveEventQueue(self.events)
            SendoraCloudLogger.shared.debug("Persisted \(self.events.count) events to disk")
        }
    }

    private func performFlush() {
        guard !events.isEmpty else { return }
        let batch = events
        events = []
        storage.clearEventQueue()

        SendoraCloudLogger.shared.debug("Flushing \(batch.count) events")
        flushHandler?(batch)
    }

    var count: Int {
        queue.sync { events.count }
    }
}
