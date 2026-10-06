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
public func checkTimestampFreshness(_ timestamp: Int, now: Int? = nil, oldestTimestamp: Int? = nil) throws {
    guard timestamp >= 0 else {
        throw ACEError.timestampNotFresh(Int.max)
    }
    let now = now ?? Int(Date().timeIntervalSince1970)
    let (lowerBound, lowerOverflow) = now.subtractingReportingOverflow(maxDriftSeconds)
    let (upperBound, upperOverflow) = now.addingReportingOverflow(maxDriftSeconds)

    if let oldestTimestamp, oldestTimestamp < 0 || oldestTimestamp > now {
        throw ACEError.invalidMessage("Invalid offline timestamp floor")
    }
    let isTooOld = oldestTimestamp.map { timestamp < $0 } ?? (!lowerOverflow && timestamp < lowerBound)
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

/// Persisted state of a ``ReplayDetector``.
public struct ReplayDetectorExport: Codable, Equatable, Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public let messageId: String
        /// Signed envelope timestamp.
        public let timestamp: Int

        public init(messageId: String, timestamp: Int) {
            self.messageId = messageId
            self.timestamp = timestamp
        }
    }

    /// Messages with `timestamp <= horizon` are rejected.
    public let horizon: Int
    public let entries: [Entry]

    public init(horizon: Int, entries: [Entry]) {
        self.horizon = horizon
        self.entries = entries
    }
}

/// Seen store with a replay horizon (06-security § Replay Protection).
///
/// Holds `(messageId, timestamp)` for every message whose signature verified.
/// Rejects any message with `timestamp <= horizon`, so an entry can be removed
/// once the horizon covers it: only the smallest-timestamp entry is removed,
/// and the horizon moves up to its timestamp. Removal happens when the entry
/// falls below the acceptance floor or the store exceeds `capacity`.
///
/// Thread-safe via NSLock. Callers MUST persist state via `export()` /
/// `fromExport()` across restarts.
public final class ReplayDetector: @unchecked Sendable {
    private let capacity: Int
    private var ids: Set<String> = []
    /// Min-heap ordered by timestamp.
    private var heap: [ReplayDetectorExport.Entry] = []
    private var _horizon: Int
    private let lock = NSLock()

    public convenience init(capacity: Int = 100_000) {
        self.init(capacity: capacity, horizon: Int(Date().timeIntervalSince1970) - maxDriftSeconds)
    }

    init(capacity: Int, horizon: Int) {
        precondition(capacity > 0, "ReplayDetector capacity must be positive")
        self.capacity = capacity
        self._horizon = horizon
    }

    public var horizon: Int {
        lock.lock()
        defer { lock.unlock() }
        return _horizon
    }

    /// Pipeline steps 2–3: true if `timestamp` is above the horizon and `messageId` is unseen.
    public func accepts(_ messageId: String, timestamp: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return acceptsLocked(messageId, timestamp: timestamp)
    }

    /// Pipeline step 4: record a message whose signature has verified.
    /// Returns false if it is a duplicate or at/below the horizon.
    /// `floor` is the acceptance floor (default `now - 5 min`).
    public func commit(_ messageId: String, timestamp: Int, floor: Int? = nil) -> Bool {
        let floor = floor ?? Int(Date().timeIntervalSince1970) - maxDriftSeconds
        lock.lock()
        defer { lock.unlock() }
        guard acceptsLocked(messageId, timestamp: timestamp) else { return false }
        ids.insert(messageId)
        push(.init(messageId: messageId, timestamp: timestamp))
        evict(below: floor)
        return true
    }

    public func export() -> ReplayDetectorExport {
        lock.lock()
        defer { lock.unlock() }
        return ReplayDetectorExport(horizon: _horizon, entries: heap)
    }

    public static func fromExport(_ data: ReplayDetectorExport, capacity: Int = 100_000) throws -> ReplayDetector {
        guard data.horizon >= 0 else {
            throw ACEError.invalidMessage("fromExport: invalid replay state")
        }
        let detector = ReplayDetector(capacity: capacity, horizon: data.horizon)
        for entry in data.entries {
            try validateMessageId(entry.messageId)
            guard entry.timestamp > data.horizon, detector.ids.insert(entry.messageId).inserted else {
                throw ACEError.invalidMessage("fromExport: invalid entry")
            }
            detector.push(entry)
        }
        detector.evict(below: 0)
        return detector
    }

    private func acceptsLocked(_ messageId: String, timestamp: Int) -> Bool {
        timestamp > _horizon && !ids.contains(messageId)
    }

    /// Remove smallest-timestamp entries while below `floor` or over capacity.
    private func evict(below floor: Int) {
        while let top = heap.first, top.timestamp < floor || heap.count > capacity {
            pop()
            ids.remove(top.messageId)
            _horizon = top.timestamp
        }
    }

    private func push(_ entry: ReplayDetectorExport.Entry) {
        heap.append(entry)
        var i = heap.count - 1
        while i > 0 {
            let parent = (i - 1) / 2
            if heap[parent].timestamp <= heap[i].timestamp { break }
            heap.swapAt(parent, i)
            i = parent
        }
    }

    private func pop() {
        let last = heap.removeLast()
        guard !heap.isEmpty else { return }
        heap[0] = last
        var i = 0
        while true {
            let l = 2 * i + 1, r = l + 1
            var min = i
            if l < heap.count && heap[l].timestamp < heap[min].timestamp { min = l }
            if r < heap.count && heap[r].timestamp < heap[min].timestamp { min = r }
            if min == i { break }
            heap.swapAt(min, i)
            i = min
        }
    }
}
