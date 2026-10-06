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
    pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    options: [.caseInsensitive]
)

// MARK: - Message ID Validation

/// Validate that a message ID is a valid UUID v4.
public func validateMessageId(_ messageId: String) throws {
    guard messageIdV4Pattern.fullMatch(messageId) else {
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
        /// Sender ACE ID (`from`), bound by the signature.
        public let sender: String
        /// Signed envelope timestamp.
        public let timestamp: Int

        public init(messageId: String, sender: String, timestamp: Int) {
            self.messageId = messageId
            self.sender = sender
            self.timestamp = timestamp
        }

        /// Encoded as the JSON array `[messageId, sender, timestamp]` (same format as Py/TS).
        public init(from decoder: any Decoder) throws {
            var container = try decoder.unkeyedContainer()
            messageId = try container.decode(String.self)
            sender = try container.decode(String.self)
            timestamp = try container.decode(Int.self)
            guard container.isAtEnd else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "Replay entry must have exactly 3 elements")
            }
        }

        public func encode(to encoder: any Encoder) throws {
            var container = encoder.unkeyedContainer()
            try container.encode(messageId)
            try container.encode(sender)
            try container.encode(timestamp)
        }
    }

    /// Messages with `timestamp <= horizon` are rejected.
    public let horizon: Int
    /// Messages from `sender` with `timestamp <= senderHorizons[sender]` are rejected.
    public let senderHorizons: [String: Int]
    public let entries: [Entry]

    public init(horizon: Int, senderHorizons: [String: Int] = [:], entries: [Entry]) {
        self.horizon = horizon
        self.senderHorizons = senderHorizons
        self.entries = entries
    }
}

/// Seen store with a replay horizon (06-security § Replay Protection).
///
/// Holds `(messageId, sender, timestamp)` for every message whose signature
/// verified. Rejects any message with `timestamp <= horizon`, or `<=` its
/// sender's horizon, so an entry can be removed once a horizon covers it: only
/// the smallest-timestamp entry is removed. Below the acceptance floor it raises
/// the horizon; over `capacity` it raises only its sender's horizon, so a sender
/// flooding the store cannot block anyone else.
///
/// Thread-safe via NSLock. Callers MUST persist state via `export()` /
/// `fromExport()` across restarts.
public final class ReplayDetector: @unchecked Sendable {
    private let capacity: Int
    private struct ReplayKey: Hashable {
        let sender: String
        let messageId: String
    }
    private var ids: Set<ReplayKey> = []
    /// Min-heap ordered by timestamp.
    private var heap: [ReplayDetectorExport.Entry] = []
    private var _horizon: Int
    private var senderHorizons: [String: Int] = [:]
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

    /// Pipeline steps 2–3: true if `timestamp` is above both horizons and `messageId` is unseen.
    public func accepts(_ messageId: String, from sender: String, timestamp: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return acceptsLocked(messageId, from: sender, timestamp: timestamp)
    }

    /// Pipeline step 4: record a message whose signature has verified.
    /// Returns false if it is a duplicate or at/below a horizon.
    /// `floor` is the acceptance floor (default `now - 5 min`).
    public func commit(_ messageId: String, from sender: String, timestamp: Int, floor: Int? = nil) -> Bool {
        let floor = floor ?? Int(Date().timeIntervalSince1970) - maxDriftSeconds
        lock.lock()
        defer { lock.unlock() }
        guard acceptsLocked(messageId, from: sender, timestamp: timestamp) else { return false }
        ids.insert(ReplayKey(sender: sender, messageId: messageId))
        push(.init(messageId: messageId, sender: sender, timestamp: timestamp))
        evict(below: floor)
        return true
    }

    public func export() -> ReplayDetectorExport {
        lock.lock()
        defer { lock.unlock() }
        // Serialization already traverses the heap; discard horizon-covered
        // entries here so the result always passes fromExport validation.
        let live = heap.filter { $0.timestamp > _horizon && $0.timestamp > senderHorizons[$0.sender, default: _horizon] }
        heap.removeAll(keepingCapacity: true)
        ids.removeAll(keepingCapacity: true)
        for entry in live {
            push(entry)
            ids.insert(ReplayKey(sender: entry.sender, messageId: entry.messageId))
        }
        return ReplayDetectorExport(horizon: _horizon, senderHorizons: senderHorizons, entries: heap)
    }

    public static func fromExport(_ data: ReplayDetectorExport, capacity: Int = 100_000) throws -> ReplayDetector {
        guard data.horizon >= 0, data.senderHorizons.allSatisfy({ !$0.key.isEmpty && $0.value >= 0 }) else {
            throw ACEError.invalidMessage("fromExport: invalid replay state")
        }
        let detector = ReplayDetector(capacity: capacity, horizon: data.horizon)
        detector.senderHorizons = data.senderHorizons
        for entry in data.entries {
            try validateMessageId(entry.messageId)
            guard !entry.sender.isEmpty,
                  detector.acceptsLocked(entry.messageId, from: entry.sender, timestamp: entry.timestamp),
                  detector.ids.insert(ReplayKey(sender: entry.sender, messageId: entry.messageId)).inserted else {
                throw ACEError.invalidMessage("fromExport: invalid entry")
            }
            detector.push(entry)
        }
        detector.evict(below: 0)
        return detector
    }

    private func acceptsLocked(_ messageId: String, from sender: String, timestamp: Int) -> Bool {
        timestamp > _horizon && timestamp > senderHorizons[sender, default: _horizon] && !ids.contains(ReplayKey(sender: sender, messageId: messageId))
    }

    /// Remove smallest-timestamp entries: below `floor` they raise the horizon,
    /// over capacity they raise only their sender's horizon.
    private func evict(below floor: Int) {
        while let top = heap.first, top.timestamp < floor {
            pop()
            ids.remove(ReplayKey(sender: top.sender, messageId: top.messageId))
            _horizon = max(_horizon, top.timestamp)
        }
        while heap.count > capacity, let top = heap.first {
            pop()
            ids.remove(ReplayKey(sender: top.sender, messageId: top.messageId))
            senderHorizons[top.sender] = max(senderHorizons[top.sender, default: top.timestamp], top.timestamp)
        }
        compactSenderHorizons()
    }

    /// Keep at most `capacity` sender horizons: drop those the horizon already
    /// covers, then fold the lowest half into the horizon (amortized O(log n)).
    private func compactSenderHorizons() {
        guard senderHorizons.count > capacity else { return }
        senderHorizons = senderHorizons.filter { $0.value > _horizon }
        let excess = senderHorizons.count - capacity / 2
        guard excess > 0 else { return }
        for (sender, h) in senderHorizons.sorted(by: { $0.value < $1.value }).prefix(excess) {
            senderHorizons[sender] = nil
            _horizon = max(_horizon, h)
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
