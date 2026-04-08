//
//  Security.swift
//  ACE SDK
//
//  Timestamp freshness check + replay detection.
//

import Foundation

// MARK: - Constants

public let maxDriftSeconds = 300 // 5 minutes
private let messageIdV4Pattern = try! NSRegularExpression(
    pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

// MARK: - Message ID Validation

/// Validate that a message ID is a valid UUID v4.
public func validateMessageId(_ messageId: String) throws {
    let range = NSRange(messageId.startIndex..., in: messageId)
    guard messageIdV4Pattern.firstMatch(in: messageId, range: range) != nil else {
        throw ACEError.invalidMessage("Invalid messageId: expected UUID v4, got '\(String(messageId.prefix(50)))'")
    }
}

// MARK: - Timestamp Freshness

/// Check that a timestamp is within the 5-minute freshness window.
/// Rejects messages with |now - timestamp| > 5 minutes.
public func checkTimestampFreshness(_ timestamp: Int, now: Int? = nil) throws {
    guard timestamp >= 0 else {
        throw ACEError.timestampNotFresh(Int.max)
    }
    let now = now ?? Int(Date().timeIntervalSince1970)
    let (lowerBound, lowerOverflow) = now.subtractingReportingOverflow(maxDriftSeconds)
    let (upperBound, upperOverflow) = now.addingReportingOverflow(maxDriftSeconds)

    let isTooOld = !lowerOverflow && timestamp < lowerBound
    let isTooNew = !upperOverflow && timestamp > upperBound
    if isTooOld || isTooNew {
        let drift: Int
        if timestamp < now {
            let (distance, overflow) = now.subtractingReportingOverflow(timestamp)
            drift = overflow ? Int.max : distance
        } else {
            let (distance, overflow) = timestamp.subtractingReportingOverflow(now)
            drift = overflow ? Int.max : distance
        }
        throw ACEError.timestampNotFresh(drift)
    }
}

// MARK: - Replay Detector

/// In-memory replay detector with TTL-based eviction.
///
/// Messages are evicted after `ttlSeconds` (default: matches the freshness
/// window of 300 s).  A hard `capacity` cap prevents unbounded memory growth
/// under burst traffic — when reached, the oldest entry is evicted regardless
/// of TTL.
///
/// Thread-safe via NSLock (matches Python SDK's threading.Lock).
///
/// Callers SHOULD persist state via `export()` / `fromExport()` across
/// restarts to avoid a replay window during the freshness period after restart.
public final class ReplayDetector: @unchecked Sendable {
    private var seen: TimedOrderedSet
    private let capacity: Int
    private let ttlSeconds: TimeInterval
    private let lock = NSLock()

    public init(capacity: Int = 100_000, ttlSeconds: Int = maxDriftSeconds) {
        self.capacity = capacity
        self.ttlSeconds = TimeInterval(ttlSeconds)
        self.seen = TimedOrderedSet(capacity: capacity)
    }

    /// Remove entries older than TTL. Caller must hold lock.
    private func evictExpired() {
        let cutoff = ProcessInfo.processInfo.systemUptime - ttlSeconds
        seen.evictBefore(cutoff)
    }

    /// Atomically check if a messageId has been seen and reserve it.
    /// Returns true if new (accepted), false if duplicate (rejected).
    public func checkAndReserve(_ messageId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        evictExpired()

        if seen.contains(messageId) {
            return false
        }

        // Hard capacity cap — evict oldest regardless of TTL
        if seen.count >= capacity {
            seen.removeFirst()
        }

        seen.insert(messageId, at: ProcessInfo.processInfo.systemUptime)
        return true
    }

    /// Check if a messageId has been seen (without reserving).
    public func hasSeen(_ messageId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        evictExpired()
        return seen.contains(messageId)
    }

    /// Release a previously reserved message ID after processing failure.
    public func release(_ messageId: String) {
        lock.lock()
        defer { lock.unlock() }
        seen.remove(messageId)
    }

    /// Export seen message IDs for persistence.
    public func export() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        evictExpired()
        return seen.elements
    }

    /// Import previously persisted seen message IDs.
    public static func fromExport(_ messageIds: [String], capacity: Int = 100_000, ttlSeconds: Int = maxDriftSeconds) -> ReplayDetector {
        let detector = ReplayDetector(capacity: capacity, ttlSeconds: ttlSeconds)
        // Truncate to capacity — keep the most recent entries
        let trimmed = messageIds.count > capacity
            ? Array(messageIds.suffix(capacity))
            : messageIds
        let now = ProcessInfo.processInfo.systemUptime
        for id in trimmed {
            detector.seen.insert(id, at: now)
        }
        return detector
    }
}

// MARK: - TimedOrderedSet (insertion-ordered with timestamps, O(1) lookup, TTL eviction)

/// Ordered set with timestamps — supports both TTL-based and FIFO eviction.
/// Uses Set for O(1) lookup + ring buffer for insertion order + timestamps.
private struct TimedOrderedSet {
    private var lookup: Set<String>
    private var buffer: [(id: String, timestamp: TimeInterval)]
    private var head: Int = 0

    init(capacity: Int) {
        lookup = Set(minimumCapacity: capacity)
        buffer = []
        buffer.reserveCapacity(capacity)
    }

    var count: Int { lookup.count }

    var elements: [String] {
        buffer[head...].compactMap { lookup.contains($0.id) ? $0.id : nil }
    }

    func contains(_ element: String) -> Bool {
        lookup.contains(element)
    }

    mutating func insert(_ element: String, at timestamp: TimeInterval) {
        if lookup.insert(element).inserted {
            buffer.append((id: element, timestamp: timestamp))
        }
    }

    mutating func remove(_ element: String) {
        lookup.remove(element)
        compactIfNeeded()
    }

    mutating func removeFirst() {
        while head < buffer.count {
            let element = buffer[head].id
            head += 1
            if lookup.remove(element) != nil {
                break
            }
        }
        compactIfNeeded()
    }

    /// Evict all entries with timestamp <= cutoff.
    mutating func evictBefore(_ cutoff: TimeInterval) {
        while head < buffer.count {
            let entry = buffer[head]
            if entry.timestamp <= cutoff {
                head += 1
                lookup.remove(entry.id)
            } else {
                break
            }
        }
        compactIfNeeded()
    }

    private mutating func compactIfNeeded() {
        if head > 1024 && head > buffer.count / 2 {
            buffer = Array(buffer[head...])
            head = 0
        }
    }
}
