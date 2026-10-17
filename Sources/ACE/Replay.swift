//
//  Replay.swift
//  ACE SDK
//
//  Seen store with replay horizons and a per-sender quota (06 § Deduplication).
//

import Foundation

/// The seen store's persisted state (06 § Deduplication): entries sorted by (timestamp, sender, messageId).
public struct ReplayState: Sendable, Equatable {
    public struct Entry: Sendable, Equatable {
        public let messageId: String
        public let sender: String
        public let timestamp: Int

        public init(messageId: String, sender: String, timestamp: Int) {
            self.messageId = messageId
            self.sender = sender
            self.timestamp = timestamp
        }
    }

    public var entries: [Entry]
    public var horizon: Int
    public var senderHorizons: [String: Int]
    public var version: Int

    public init(entries: [Entry], horizon: Int, senderHorizons: [String: Int], version: Int = 1) {
        self.entries = entries
        self.horizon = horizon
        self.senderHorizons = senderHorizons
        self.version = version
    }

    /// Parse `replay.json`. Structural errors are `invalid_argument`. Integers follow the
    /// wire-integer rule (`11.0` is accepted); unknown keys are ignored.
    public init(json: Data) throws {
        func bad(_ msg: String) -> ACEError { ACEError(.invalidArgument, "fromState: \(msg)") }
        let v: JSONValue
        do { v = try JSONParser.parse(json) } catch { throw bad("not JSON") }
        guard let o = v.objectValue else { throw bad("state must be an object") }
        guard o["version"]?.wireInt == 1 else { throw bad("version must be 1") }
        guard let horizon = o["horizon"]?.wireInt, let sh = o["senderHorizons"]?.objectValue,
              let entries = o["entries"]?.arrayValue else {
            throw bad("horizon, senderHorizons and entries are required")
        }
        var horizons: [String: Int] = [:]
        for (s, h) in sh {
            guard let hv = h.wireInt else { throw bad("invalid sender horizon") }
            horizons[s] = hv
        }
        var out: [Entry] = []
        for e in entries {
            guard let a = e.arrayValue, a.count == 3 else { throw bad("entries must be [messageId, sender, timestamp]") }
            guard let mid = a[0].stringValue, let s = a[1].stringValue, let ts = a[2].wireInt else { throw bad("invalid entry") }
            out.append(Entry(messageId: mid, sender: s, timestamp: ts))
        }
        self.init(entries: out, horizon: horizon, senderHorizons: horizons, version: 1)
    }

    /// Canonical bytes: compact, keys sorted, ASCII only (byte-identical across SDKs).
    public func jsonData() -> Data {
        let v: JSONValue = .object([
            "entries": .array(entries.map { [.string($0.messageId), .string($0.sender), .number(Double($0.timestamp))] }),
            "horizon": .number(Double(horizon)),
            "senderHorizons": .object(senderHorizons.mapValues { .number(Double($0)) }),
            "version": .number(Double(version)),
        ])
        return try! v.jsonData()  // integers only
    }
}

// MARK: - Heap

package struct MinHeap<T: Comparable> {
    private(set) var items: [T] = []

    package var first: T? { items.first }

    package mutating func push(_ x: T) {
        items.append(x)
        var i = items.count - 1
        while i > 0 {
            let p = (i - 1) / 2
            if items[p] <= items[i] { break }
            items.swapAt(p, i)
            i = p
        }
    }

    @discardableResult
    package mutating func pop() -> T? {
        guard !items.isEmpty else { return nil }
        let top = items[0]
        let last = items.removeLast()
        if !items.isEmpty {
            items[0] = last
            var i = 0
            while true {
                let l = 2 * i + 1, r = l + 1
                var m = i
                if l < items.count, items[l] < items[m] { m = l }
                if r < items.count, items[r] < items[m] { m = r }
                if m == i { break }
                items.swapAt(m, i)
                i = m
            }
        }
        return top
    }

    package init() {}
    package init(_ items: [T]) {
        self.items = items.sorted()
    }
}

private struct GEntry: Comparable {
    package let ts: Int
    package let sender: String
    package let id: String
    package static func < (a: GEntry, b: GEntry) -> Bool { (a.ts, a.sender, a.id) < (b.ts, b.sender, b.id) }
}

private struct SEntry: Comparable {
    package let ts: Int
    package let id: String
    package static func < (a: SEntry, b: SEntry) -> Bool { (a.ts, a.id) < (b.ts, b.id) }
}

private struct HEntry: Comparable {
    package let h: Int
    package let sender: String
    package static func < (a: HEntry, b: HEntry) -> Bool { (a.h, a.sender) < (b.h, b.sender) }
}

private struct LiveKey: Hashable {
    package let sender: String
    package let id: String
}

/// Thread-safe seen store.
///
/// A message `(id, sender, ts)` is accepted iff `ts > H`, `ts > SH[sender]` and the pair
/// is unseen. Entries are removed only once a horizon covers them:
/// 1. entries below the acceptance floor raise `H`;
/// 2. a sender holding more than `Q = max(1, capacity / 16)` entries loses its smallest
///    ones and raises only its own `SH[sender]`;
/// 3. over capacity, the global smallest is removed and raises its sender's `SH`;
/// 4. sender horizons covered by `H` are dropped; more than `capacity` of them fold the
///    lowest into `H`.
///
/// Persist with `exportState()` / `init(state:capacity:)`.
public final class ReplayDetector: @unchecked Sendable {
    public let capacity: Int
    private let quota: Int
    private let clock: @Sendable () -> Int
    private var _horizon: Int
    private var sh: [String: Int] = [:]
    private var shHeap = MinHeap<HEntry>()
    private var live: [LiveKey: Int] = [:]
    private var global = MinHeap<GEntry>()
    private var perSender: [String: MinHeap<SEntry>] = [:]
    private var counts: [String: Int] = [:]
    private let lock = NSLock()

    /// `horizon` defaults to `F − 1` with `F = now − 2·OFFLINE_WINDOW_SECONDS`. `capacity` must be ≥ 1 (`invalid_argument`). Every clock reading (the
    /// default horizon, `commit`'s default floor) is `invalid_argument` outside [0, 2^53 − 1] (Python `unix_now`).
    public init(capacity: Int = ACELimits.defaultReplayCapacity, horizon: Int? = nil,
                clock: @escaping @Sendable () -> Int = systemClock) throws {
        guard capacity >= 1 else { throw ACEError(.invalidArgument, "capacity must be an integer >= 1") }
        if let horizon, !isWireInt(horizon) {
            throw ACEError(.invalidArgument, "horizon must be an integer in [0, 2^53-1]")
        }
        self.capacity = capacity
        self.quota = max(1, capacity / 16)
        self.clock = clock
        self._horizon = try horizon ?? max(0, Self.floor(unixNow(clock)) - 1)
    }

    /// Validate (`invalid_argument`) and normalize a persisted state.
    public convenience init(state: ReplayState, capacity: Int = ACELimits.defaultReplayCapacity,
                            clock: @escaping @Sendable () -> Int = systemClock) throws {
        func bad(_ msg: String) -> ACEError { ACEError(.invalidArgument, "fromState: \(msg)") }
        guard state.version == 1 else { throw bad("version must be 1") }
        guard isWireInt(state.horizon) else { throw bad("invalid horizon") }
        try self.init(capacity: capacity, horizon: state.horizon, clock: clock)
        for (s, h) in state.senderHorizons {
            guard !s.isEmpty, isWireInt(h) else { throw bad("invalid sender horizon") }
            setSH(s, h)
        }
        for e in state.entries {
            guard isMessageId(e.messageId), !e.sender.isEmpty, isWireInt(e.timestamp) else {
                throw bad("invalid entry")
            }
            guard acceptsLocked(e.messageId, e.sender, e.timestamp) else {
                throw bad("entry is covered by a horizon or duplicated")
            }
            insert(e.timestamp, e.sender, e.messageId)
        }
        for s in counts.keys.sorted() { enforceQuota(s) }
        enforceCapacity()
        compact()
    }

    /// The retention floor `F = max(0, now − 2·OFFLINE_WINDOW_SECONDS)`.
    package static func floor(_ now: Int) -> Int { max(0, now - 2 * ACELimits.offlineWindowSeconds) }

    /// True when `(sender, messageId)` is in the store.
    package func contains(_ messageId: String, from sender: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return live[LiveKey(sender: sender, id: messageId)] != nil
    }

    /// True when `ts` is at or below `max(H, SH[sender])`.
    package func covers(sender: String, timestamp ts: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return ts <= max(_horizon, sh[sender] ?? _horizon)
    }

    private static func checkArgs(_ messageId: String, _ sender: String, _ ts: Int) throws {
        guard !messageId.isEmpty, !sender.isEmpty else {
            throw ACEError(.invalidArgument, "messageId and sender must be non-empty strings")
        }
        guard isWireInt(ts) else { throw ACEError(.invalidArgument, "timestamp must be an integer in [0, 2^53-1]") }
    }

    public func accepts(_ messageId: String, from sender: String, timestamp: Int) throws -> Bool {
        try Self.checkArgs(messageId, sender, timestamp)
        lock.lock()
        defer { lock.unlock() }
        return acceptsLocked(messageId, sender, timestamp)
    }

    /// Record a verified message. False if it is a duplicate or covered by a horizon.
    /// `floor` defaults to `now − 2·OFFLINE_WINDOW_SECONDS`.
    @discardableResult
    public func commit(_ messageId: String, from sender: String, timestamp: Int, floor: Int? = nil) throws -> Bool {
        try Self.checkArgs(messageId, sender, timestamp)
        if let floor, !isWireInt(floor) {
            throw ACEError(.invalidArgument, "floor must be an integer in [0, 2^53-1]")
        }
        let floor = try floor ?? Self.floor(unixNow(clock))
        lock.lock()
        defer { lock.unlock() }
        guard acceptsLocked(messageId, sender, timestamp) else { return false }
        insert(timestamp, sender, messageId)
        while let m = peekGlobal(), m.ts < floor {
            remove(m.sender, m.id)
            _horizon = max(_horizon, m.ts)
        }
        purgeGlobal()
        enforceQuota(sender)
        enforceCapacity()
        compact()
        return true
    }

    /// Canonical state: entries sorted by (timestamp, sender, messageId); only horizons above `H`.
    public func exportState() -> ReplayState {
        lock.lock()
        defer { lock.unlock() }
        let entries = live.map { GEntry(ts: $0.value, sender: $0.key.sender, id: $0.key.id) }.sorted()
        return ReplayState(
            entries: entries.map { ReplayState.Entry(messageId: $0.id, sender: $0.sender, timestamp: $0.ts) },
            horizon: _horizon,
            senderHorizons: sh.filter { $0.value > _horizon },
            version: 1
        )
    }

    // MARK: Internals (caller holds the lock)

    private func acceptsLocked(_ id: String, _ s: String, _ ts: Int) -> Bool {
        ts > _horizon && ts > (sh[s] ?? _horizon) && live[LiveKey(sender: s, id: id)] == nil
    }

    private func insert(_ ts: Int, _ s: String, _ id: String) {
        live[LiveKey(sender: s, id: id)] = ts
        global.push(GEntry(ts: ts, sender: s, id: id))
        perSender[s, default: MinHeap()].push(SEntry(ts: ts, id: id))
        counts[s, default: 0] += 1
    }

    private func remove(_ s: String, _ id: String) {
        live[LiveKey(sender: s, id: id)] = nil
        let c = counts[s, default: 0] - 1
        if c > 0 {
            counts[s] = c
        } else {
            counts[s] = nil
            perSender[s] = nil
        }
    }

    private func peekGlobal() -> GEntry? {
        while let g = global.first, live[LiveKey(sender: g.sender, id: g.id)] != g.ts {
            global.pop()
        }
        return global.first
    }

    private func peekSender(_ s: String) -> SEntry? {
        guard var h = perSender[s] else { return nil }
        var changed = false
        while let top = h.first, live[LiveKey(sender: s, id: top.id)] != top.ts {
            h.pop()
            changed = true
        }
        if changed { perSender[s] = h }
        return h.first
    }

    private func setSH(_ s: String, _ h: Int) {
        sh[s] = h
        shHeap.push(HEntry(h: h, sender: s))
    }

    private func raiseSH(_ s: String, _ ts: Int) {
        setSH(s, max(sh[s] ?? _horizon, ts))
        let limit = sh[s]!
        while let m = peekSender(s), m.ts <= limit {
            remove(s, m.id)
        }
    }

    private func purgeGlobal() {
        while let m = peekGlobal(), m.ts <= _horizon {
            remove(m.sender, m.id)
        }
    }

    private func enforceQuota(_ s: String) {
        while counts[s, default: 0] > quota, let m = peekSender(s) {
            remove(s, m.id)
            raiseSH(s, m.ts)
        }
    }

    private func enforceCapacity() {
        while live.count > capacity, let m = peekGlobal() {
            remove(m.sender, m.id)
            raiseSH(m.sender, m.ts)
        }
    }

    private func dropCoveredSH() {
        while let top = shHeap.first, top.h <= _horizon {
            shHeap.pop()
            if sh[top.sender] == top.h { sh[top.sender] = nil }
        }
    }

    private func compact() {
        dropCoveredSH()
        guard sh.count > capacity else { return }
        let excess = sh.count - capacity / 2
        let sorted = sh.map { HEntry(h: $0.value, sender: $0.key) }.sorted()
        for e in sorted.prefix(excess) {
            sh[e.sender] = nil
            _horizon = max(_horizon, e.h)
        }
        purgeGlobal()
        dropCoveredSH()
        shHeap = MinHeap(sh.map { HEntry(h: $0.value, sender: $0.key) })
    }
}
