import Foundation

/// Thread-safe event queue with batched flushing and offline persistence.
final class EventQueue {
    /// One queued event + an in-memory identity (5.6.0). Sent events are removed
    /// by IDENTITY, never by position: `add()` trims the oldest at `maxSize` while
    /// a chunk is in flight, so "the first N" could be events that were never sent.
    private struct Queued {
        let id: UInt64
        var event: [String: Any]
    }

    private let queue = DispatchQueue(label: "com.sendora.eventqueue")
    private var events: [Queued] = []
    private var nextId: UInt64 = 0
    private var flushTimer: Timer?
    private let storage: SendoraStorage
    private let flushAt: Int
    private let maxSize: Int
    typealias FlushHandler = ([[String: Any]], @escaping (APIClient.DeliveryOutcome) -> Void) -> Void
    /// Send a chunk of events; the SDK reports back what the backend made of it
    /// (5.6.0: accepted / permanently rejected / retry later — it was a Bool, and
    /// every `false` was retried forever, a poison chunk included).
    private var flushHandler: FlushHandler?
    /// Backend `/events/batch` hard-caps at 100 events per call; bigger
    /// posts 400 and (pre-fix) silently dropped the whole buffer.
    internal static let maxBatchSize = 100
    /// 5.6.0: …and at 64 KB of body (413). A chunk's serialized events stay under this.
    internal static let maxChunkBytes = 60_000
    /// 5.6.0 (F67): the per-event retry budget — failed deliveries the SERVER
    /// answered (408 / 5xx / 401 IDENTITY_UNVERIFIED) before an event is dropped.
    /// Offline time, the breaker, a 429 and a Cloudflare challenge never spend it.
    internal static let maxAttempts = 50
    /// The longest a server's wait may pause flushing (a quota 429 asks until the month resets).
    internal static let maxHold: TimeInterval = 3600
    /// Where an event's spent budget is kept: inside the persisted event, so it
    /// survives a relaunch. Stripped before every send (and the backend's event
    /// schema strips unknown keys, so a downgraded build sending it is harmless).
    internal static let attemptsKey = "_sendoraAttempts"
    /// Guards against overlapping flushes racing on the same events
    /// (timer tick + threshold auto-flush). Mutated only on `queue`.
    private var isFlushing = false
    /// 5.6.0: the server's wait (`Retry-After`, ≤ 1 h). No flush starts before it.
    private var holdUntil: Date = .distantPast
    /// 5.6.0: chunk-size limit while bisecting a refused chunk. Stays halved until a SUCCESS, then doubles back.
    private var bisectLimit: Int?
    /// 5.6.0 (review r3): at most this many POSTs per flush; then the normal backoff.
    internal static let maxPostsPerFlush = 20
    private var postsThisFlush = 0
    /// 5.6.0 (review r3): the queue's OWN full-jitter backoff — `random(0, min(300 s, 1 s · 2^(n-1)))` after
    /// EVERY retry-later (answered or not); a server wait raises the floor; reset by an accepted send. The
    /// client breaker does not cover it (`requestWithDetails` does not trip on a 500 / 502 / 504), and without
    /// it every `trackEvent` past `flushAt` re-sent the same head chunk and spent an attempt each time.
    internal static let backoffBase: TimeInterval = 1
    internal static let backoffMax: TimeInterval = 300
    private var consecutiveRetries = 0
    /// After this many consecutive answered 5xx on the SAME multi-event chunk, halve it (isolate a poison event).
    internal static let serverErrorBisectAfter = 3
    private var serverErrorStreak = 0
    private var serverErrorChunk: Set<UInt64> = []
    /// Test seam: the full-jitter draw in `0...ceiling`.
    internal var jitter: (TimeInterval) -> TimeInterval = { c in c > 0 ? Double.random(in: 0...c) : 0 }
    /// Applied to each event at SEND time, never stored (the identity token is attached here, so a token that
    /// arrives after enqueue is used, and none is written to the persisted queue). Counted in the byte cap.
    internal var decorator: (([String: Any]) -> [String: Any])?
    /// 5.6.0: identity-refused events kept from a 201 — skipped for the rest of THIS flush (else they would be the
    /// next chunk's head and be resent at once until their budget ran out). Reset per flush.
    private var deferredThisFlush: Set<UInt64> = []
    /// Test seam.
    internal var clock: () -> Date = { Date() }

    init(storage: SendoraStorage, flushAt: Int = 20, maxSize: Int = 1000) {
        self.storage = storage
        self.flushAt = flushAt
        self.maxSize = maxSize

        // Load persisted events from previous session
        let persisted = storage.loadEventQueue()
        if !persisted.isEmpty {
            self.events = persisted.map { makeQueued($0) }
            SendoraCloudLogger.shared.debug("Loaded \(persisted.count) persisted events")
        }
    }

    private func makeQueued(_ event: [String: Any]) -> Queued {
        nextId &+= 1
        return Queued(id: nextId, event: event)
    }

    private func persist() {
        storage.saveEventQueue(events.map { $0.event })
    }

    func setFlushHandler(_ handler: @escaping FlushHandler) {
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
            self.events.append(self.makeQueued(event))

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
            self.persist()
            SendoraCloudLogger.shared.debug("Persisted \(self.events.count) events to disk")
        }
    }

    private func performFlush() {
        // Must run on `queue`. Sends the oldest events (≤ 100, ≤ 60 KB) as one
        // chunk and removes them only when the backend ACCEPTS that chunk or
        // refuses it PERMANENTLY. On a transient failure (offline / 408 / 429 /
        // 5xx / a Cloudflare challenge) the events stay queued for the next
        // flush. Chunks are sent sequentially (recursively) so ordering is
        // preserved.
        guard !isFlushing else { return }
        guard let handler = flushHandler, !events.isEmpty else { return }
        guard clock() >= holdUntil else { return }

        isFlushing = true
        deferredThisFlush = []
        postsThisFlush = 0
        sendNextChunk(handler)
    }

    private func wire(_ event: [String: Any]) -> [String: Any] {
        var e = event
        e.removeValue(forKey: Self.attemptsKey)
        return decorator.map { $0(e) } ?? e
    }

    private static func byteSize(_ event: [String: Any]) -> Int {
        return (try? JSONSerialization.data(withJSONObject: event).count) ?? 0
    }

    /// The head of the queue as one chunk: ≤ 100 events (or the bisection limit)
    /// and ≤ 60,000 serialized bytes. Always at least one event — a single event
    /// over the byte limit is sent alone, and a 413 for it drops it.
    private func nextChunk() -> [Queued] {
        let limit = min(Self.maxBatchSize, bisectLimit ?? Self.maxBatchSize)
        var chunk: [Queued] = []
        var bytes = 12 // `{"events":[]}`
        for q in events where !deferredThisFlush.contains(q.id) {
            if chunk.count >= limit { break }
            let size = Self.byteSize(wire(q.event)) + (chunk.isEmpty ? 0 : 1)
            if !chunk.isEmpty && bytes + size > Self.maxChunkBytes { break }
            chunk.append(q)
            bytes += size
        }
        return chunk
    }

    private func sendNextChunk(_ handler: @escaping FlushHandler) {
        // Precondition: running on `queue`, isFlushing == true.
        let chunk = nextChunk()
        guard !chunk.isEmpty else {
            isFlushing = false
            return
        }
        if postsThisFlush >= Self.maxPostsPerFlush {
            // A batch of all-bad events must not cost hundreds of POSTs in a second.
            applyBackoff(after: nil)
            isFlushing = false
            return
        }
        postsThisFlush += 1

        let ids = Set(chunk.map { $0.id })
        SendoraCloudLogger.shared.debug("Flushing chunk of \(chunk.count) events (\(events.count) queued)")

        handler(chunk.map { wire($0.event) }) { [weak self] outcome in
            // Backend completion may arrive on any thread — hop back onto the
            // serial queue before touching `events` / persistence.
            guard let self = self else { return }
            self.queue.async {
                switch outcome {
                case .accepted:
                    self.remove(ids)
                    self.noteSuccess()
                    self.sendNextChunk(handler)
                case .acceptedExcept(let retry):
                    // The batch landed except the events identity refused (strict-identity: the token may
                    // arrive with the next `identify()`). Keep THOSE, spend one attempt each; remove the rest.
                    let kept = Set(retry.filter { chunk.indices.contains($0) }.map { chunk[$0].id })
                    self.remove(ids.subtracting(kept))
                    self.spendAttempt(kept)
                    self.persist()
                    self.deferredThisFlush.formUnion(kept)
                    self.noteSuccess()
                    self.sendNextChunk(handler)
                case .rejected(let status):
                    if chunk.count > 1 && [400, 413, 422].contains(status) {
                        // 5.6.0: one bad event (or a body too big) refuses the whole
                        // chunk. Halve and resend; only a SINGLE event still refused is
                        // dropped, so its neighbours are delivered.
                        self.bisectLimit = max(1, chunk.count / 2)
                        self.sendNextChunk(handler)
                        return
                    }
                    // A permanent refusal will be refused again, byte for byte. Keeping
                    // it made it the queue's head forever and nothing behind it was
                    // ever delivered.
                    SendoraCloudLogger.shared.error("Event chunk of \(chunk.count) refused permanently (HTTP \(status)) — dropped")
                    self.remove(ids)
                    self.sendNextChunk(handler)
                case .retryLater(let countsAttempt, let after, let status):
                    if countsAttempt { self.spendAttempt(ids) }
                    if countsAttempt && status >= 500 && chunk.count > 1 {
                        // The same multi-event chunk answered 5xx again: after 3 in a row, halve it.
                        if self.serverErrorChunk == ids { self.serverErrorStreak += 1 } else { self.serverErrorChunk = ids; self.serverErrorStreak = 1 }
                        if self.serverErrorStreak >= Self.serverErrorBisectAfter {
                            self.bisectLimit = max(1, chunk.count / 2)
                            self.serverErrorStreak = 0
                            self.serverErrorChunk = []
                        }
                    }
                    self.applyBackoff(after: after)
                    // Keep the chunk (and everything after it) queued; persist
                    // current state and stop draining until the next flush.
                    SendoraCloudLogger.shared.debug("Flush chunk not delivered — \(self.events.count) events kept for retry")
                    self.persist()
                    self.isFlushing = false
                }
            }
        }
    }

    private func applyBackoff(after: Int?) {
        consecutiveRetries += 1
        let ceiling = min(Self.backoffMax, Self.backoffBase * pow(2.0, Double(min(consecutiveRetries - 1, 30))))
        var delay = max(0, min(ceiling, jitter(ceiling)))
        if let after = after, after > 0 { delay = max(delay, min(TimeInterval(after), Self.maxHold)) }
        let until = clock().addingTimeInterval(delay)
        if until > holdUntil { holdUntil = until }
    }

    /// A delivered send: the backoff resets and a halved chunk cap doubles back toward 100.
    private func noteSuccess() {
        consecutiveRetries = 0
        serverErrorStreak = 0
        serverErrorChunk = []
        if let limit = bisectLimit {
            let doubled = limit * 2
            bisectLimit = doubled >= Self.maxBatchSize ? nil : doubled
        }
    }

    private func remove(_ ids: Set<UInt64>) {
        events.removeAll { ids.contains($0.id) }
        persist()
    }

    /// One server-answered failure for each sent event still queued; an event
    /// whose budget is spent is dropped (a poison event the server 500s on
    /// forever must not hold the queue).
    private func spendAttempt(_ ids: Set<UInt64>) {
        var dropped = 0
        events = events.compactMap { q in
            guard ids.contains(q.id) else { return q }
            var q = q
            let spent = ((q.event[Self.attemptsKey] as? NSNumber)?.intValue ?? 0) + 1
            if spent >= Self.maxAttempts {
                dropped += 1
                return nil
            }
            q.event[Self.attemptsKey] = spent
            return q
        }
        if dropped > 0 {
            SendoraCloudLogger.shared.error("\(dropped) events dropped after \(Self.maxAttempts) failed deliveries")
        }
    }

    var count: Int {
        queue.sync { events.count }
    }

    /// Test seam: the queued events in order (as persisted).
    internal var snapshot: [[String: Any]] {
        queue.sync { events.map { $0.event } }
    }
}
