import Foundation

/// Thread-safe event queue with batched flushing and offline persistence.
final class EventQueue {
    private let queue = DispatchQueue(label: "com.sendora.eventqueue")
    private var events: [[String: Any]] = []
    private var flushTimer: Timer?
    private let storage: SendoraStorage
    private let flushAt: Int
    private let maxSize: Int
    /// Send a chunk of events; the SDK reports back whether the backend
    /// ACCEPTED it. On `false` the chunk stays queued for the next flush.
    private var flushHandler: (([[String: Any]], @escaping (Bool) -> Void) -> Void)?
    /// Backend `/events/batch` hard-caps at 100 events per call; bigger
    /// posts 400 and (pre-fix) silently dropped the whole buffer.
    private let maxBatchSize = 100
    /// Guards against overlapping flushes racing on the same events
    /// (timer tick + threshold auto-flush). Mutated only on `queue`.
    private var isFlushing = false

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

    func setFlushHandler(_ handler: @escaping ([[String: Any]], @escaping (Bool) -> Void) -> Void) {
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

    /// Discard every queued event without flushing. Used by Auth on
    /// cross-account signin so the prior identity's pending events
    /// don't surface under the next user.
    func dropAll() {
        queue.async { [weak self] in
            guard let self = self else { return }
            self.events = []
            self.storage.clearEventQueue()
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
        // Must run on `queue`. Sends the oldest <=100 events as one chunk and
        // ONLY removes them from the in-memory buffer + persisted snapshot once
        // the backend ACCEPTS that chunk. On failure (offline / 400 / 5xx) the
        // events stay queued for the next flush — no silent data loss. Chunks
        // are sent sequentially (recursively) so ordering is preserved and the
        // 100/call cap is never exceeded.
        guard !isFlushing else { return }
        guard let handler = flushHandler, !events.isEmpty else { return }

        isFlushing = true
        sendNextChunk(handler)
    }

    private func sendNextChunk(_ handler: @escaping ([[String: Any]], @escaping (Bool) -> Void) -> Void) {
        // Precondition: running on `queue`, isFlushing == true.
        guard !events.isEmpty else {
            isFlushing = false
            return
        }

        let chunkCount = min(maxBatchSize, events.count)
        let chunk = Array(events.prefix(chunkCount))
        SendoraCloudLogger.shared.debug("Flushing chunk of \(chunk.count) events (\(events.count) queued)")

        handler(chunk) { [weak self] accepted in
            // Backend completion may arrive on any thread — hop back onto the
            // serial queue before touching `events` / persistence.
            guard let self = self else { return }
            self.queue.async {
                guard accepted else {
                    // Keep the chunk (and everything after it) queued; persist
                    // current state and stop draining until the next flush.
                    SendoraCloudLogger.shared.debug("Flush chunk rejected — \(self.events.count) events kept for retry")
                    self.storage.saveEventQueue(self.events)
                    self.isFlushing = false
                    return
                }

                // Accepted: drop exactly the events we just sent. They sit at the
                // front of the buffer (FIFO); anything `add`ed mid-flight was
                // appended to the back, so removing the first N is correct.
                let removeCount = min(chunkCount, self.events.count)
                self.events.removeFirst(removeCount)
                self.storage.saveEventQueue(self.events)

                // Drain the next chunk, or finish.
                self.sendNextChunk(handler)
            }
        }
    }

    var count: Int {
        queue.sync { events.count }
    }
}
