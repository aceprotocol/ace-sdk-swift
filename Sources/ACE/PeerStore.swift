//
//  PeerStore.swift
//  ACE SDK
//
//  Peer pins: the verified KEL per ACE ID, extended under the fork rules, plus the newest signed descriptor adopted for
//  it (lock `peers`). When the pin advances past the descriptor's KEL, the descriptor is kept as stale, with the KEL it
//  was bound to: never used, only its relays asked when refreshing. Rows are re-verified on every read (cached by their
//  exact bytes).
//

import Foundation

/// How `PeerStore.adopt` changed a pin.
public struct PeerAdoption: Sendable {
    public let state: KelState
    public let outcome: ExtendOutcome
}

/// Durable pins. `adopt` applies `ACEKel.extend` (rollback and fork protection) and keeps the newest descriptor per
/// identity: one under an advanced pin always replaces the held one; under the same pin an older `issuedAt`, or a
/// descriptor whose KEL is a strict prefix of the pin, or the same `issuedAt` with other content, is `stale_peer_binding`.
public actor PeerStore {
    private static let cacheSize = 256
    private let store: any ACEStore
    private let clock: @Sendable () -> Int
    private var cache: [String: (raw: Data, pin: Pin)] = [:]

    private struct Pin {
        let state: KelState
        /// The descriptor bound to `state`.
        let agent: VerifiedAgent?
        /// The last descriptor bound to an earlier state of the pin (nil while `agent` is held): routes only.
        let stale: VerifiedAgent?
        let fetchedAt: Int
        /// A live descriptor served by a relay vouched for `state` (see `adopt(_:live:)`).
        let kelLive: Bool
    }

    public init(store: any ACEStore, clock: @escaping @Sendable () -> Int = systemClock) {
        self.store = store
        self.clock = clock
    }

    private static func key(_ aceId: String) -> String { "peers/\(sha256Hex(Data(aceId.utf8))).json" }

    private static func checkId(_ aceId: String) throws {
        guard isACEId(aceId) else { throw ACEError(.invalidArgument, "aceId must be an ACE ID") }
    }

    private func load(_ aceId: String) throws -> Pin? {
        let key = Self.key(aceId)
        guard let raw = try store.checkedRead(key) else { return nil }
        if let hit = cache[key], hit.raw == raw { return hit.pin }
        let pin = try Self.decode(raw, aceId: aceId, key: key)
        if cache.count >= Self.cacheSize { cache.removeAll() }
        cache[key] = (raw, pin)
        return pin
    }

    /// A stored row, verified (`storage_failed` for anything malformed).
    private static func decode(_ raw: Data, aceId: String, key: String) throws -> Pin {
        do {
            guard let o = JSONValue(stored: raw)?.objectValue, o["version"] == 1, o["aceId"]?.stringValue == aceId,
                  let at = o["fetchedAt"]?.wireInt, let list = o["kel"]?.arrayValue, let source = o["agent"],
                  o["kelLive"].map({ $0.boolValue != nil }) ?? true else {
                throw ACEError(.storageFailed, "\(key) is malformed")
            }
            let events = try list.map { e -> KelEvent in
                guard let ev = e.objectValue else { throw ACEError(.storageFailed, "\(key) holds a malformed event") }
                return ev
            }
            let state = try ACEKel.verify(events, now: at)
            guard state.aceId == aceId else { throw ACEError(.storageFailed, "\(key) does not match its aceId") }
            var agent: VerifiedAgent?, stale: VerifiedAgent?
            if !source.isNull {
                guard let issued = source["descriptor"]?["issuedAt"]?.wireInt else { throw ACEError(.storageFailed, "\(key) holds a malformed descriptor") }
                agent = try Self.reverify(source, issuedAt: issued, state: state)
            }
            if let old = o["stale"], !old.isNull {
                // `{kel, descriptor}`: the descriptor verified under the KEL state it was bound to.
                guard agent == nil, let issued = old["descriptor"]?["issuedAt"]?.wireInt, let kel = old["kel"]?.arrayValue else {
                    throw ACEError(.storageFailed, "\(key) holds a malformed stale descriptor")
                }
                let bound = try ACEKel.verify(try kel.map { e -> KelEvent in
                    guard let ev = e.objectValue else { throw ACEError(.storageFailed, "\(key) holds a malformed event") }
                    return ev
                }, now: at)
                guard bound.aceId == aceId else { throw ACEError(.storageFailed, "\(key) does not match its aceId") }
                stale = try Self.reverify(old, issuedAt: issued, state: bound)
            }
            // A row written before `kelLive` existed was pinned through a descriptor: live.
            return Pin(state: state, agent: agent, stale: stale, fetchedAt: at, kelLive: o["kelLive"]?.boolValue ?? true)
        } catch let e as ACEError {
            throw ACEError(.storageFailed, "\(key): \(e.message)")
        }
    }

    /// A stored descriptor, verified as adopted: its claims at `issuedAt`, its signature under the pinned `state`.
    private static func reverify(_ source: JSONValue, issuedAt: Int, state: KelState) throws -> VerifiedAgent {
        let carried = try verifyPublishedAgent(["kel": ExportJSON.kelValue(state.events), "descriptor": source["descriptor"] ?? .null],
                                               now: issuedAt, allowLoopback: true, pinned: nil, kelNow: state.events.last.flatMap { wireInt($0["ts"]) })
        return VerifiedAgent(state: state, descriptor: carried.descriptor, source: source)
    }

    /// The pinned KEL state, or nil.
    public func pinned(_ aceId: String) throws -> KelState? {
        try Self.checkId(aceId)
        return try load(aceId)?.state
    }

    /// `pinned(_:)` read synchronously, without the actor's cache: for profile rules, whose `check` is synchronous
    /// (`delegationRules`).
    package nonisolated func pinnedState(_ aceId: String) throws -> KelState? {
        try Self.checkId(aceId)
        let key = Self.key(aceId)
        guard let raw = try store.checkedRead(key) else { return nil }
        return try Self.decode(raw, aceId: aceId, key: key).state
    }

    /// The store clock (`invalid_argument` for a reading outside [0, 2^53 − 1]).
    package nonisolated func clockNow() throws -> Int { try unixNow(clock) }

    /// Whether a live descriptor served by a relay vouched for the pinned KEL (`adopt(_:live:)`); false without a pin.
    public func kelLive(_ aceId: String) throws -> Bool {
        try Self.checkId(aceId)
        return try load(aceId)?.kelLive ?? false
    }

    /// The newest adopted descriptor bound to the pinned KEL (possibly expired: check `descriptor.expiresAt`), or nil. Its
    /// `state` is the pinned (newest) KEL state.
    public func agent(_ aceId: String) throws -> VerifiedAgent? {
        try Self.checkId(aceId)
        return try load(aceId)?.agent
    }

    /// The relays of the held descriptor, bound to the current pin or not (one the pin advanced past), nil when none:
    /// routes to try when refreshing, never a descriptor to use.
    package func heldRelays(_ aceId: String) throws -> [String]? {
        try Self.checkId(aceId)
        guard let pin = try load(aceId) else { return nil }
        return (pin.agent ?? pin.stale)?.descriptor.relays
    }

    /// `agent(aceId)` while its descriptor is unexpired at the store clock and the pinned identity is usable (01 § Verifier
    /// rules 5: never send to an identity whose signing delegation has passed its `notAfter`), else nil: the descriptor that
    /// may be used (04 § Caching).
    public func usableAgent(_ aceId: String) throws -> VerifiedAgent? {
        let now = try unixNow(clock)
        guard let a = try agent(aceId), now < a.descriptor.expiresAt, ACEKel.isUsable(a.state, now: now) else { return nil }
        return a
    }

    /// Pin (or extend the pin to) a KEL under the fork rules, without a descriptor. A held descriptor is bound to the KEL
    /// state it was verified under: when the pin advances it is no longer `agent` or `usableAgent` (refreshed on next use)
    /// and is kept as stale, its relays only routes (`heldRelays`). A KEL alone vouches for nothing: a pin it moves is not
    /// `kelLive`; an unchanged one keeps its flag.
    @discardableResult
    public func pin(kel: [KelEvent]) throws -> PeerAdoption {
        try store.withLock("peers") {
            let now = try unixNow(clock)
            let candidate = try ACEKel.verify(kel, now: now)
            let old = try load(candidate.aceId)
            let (state, outcome) = try ACEKel.extend(pinned: old?.state, verified: candidate)
            // An advanced pin unbinds the held descriptor: it is kept as stale (its relays still routes), never used.
            let same = old?.state.lastHash == state.lastHash
            let stale = same ? old?.stale : old?.agent ?? old?.stale
            try write(state.aceId, state: state, agent: same ? old?.agent?.source : nil, stale: stale,
                      fetchedAt: max(now, old?.fetchedAt ?? 0), kelLive: same && old?.kelLive == true)
            return PeerAdoption(state: state, outcome: outcome)
        }
    }

    /// Verify a PublishedAgent against the pin (`verifyPublishedAgent(pinned:)` at the store clock) and adopt it. An older
    /// revision refused under the same KEL never stands in for the held one: that one is returned only while usable
    /// (unexpired and bound to the current pin), else `stale_peer_binding`.
    @discardableResult
    public func adopt(source: JSONValue, allowLoopback: Bool = false) throws -> VerifiedAgent {
        guard let aceId = source["descriptor"]?["aceId"]?.stringValue, isACEId(aceId) else {
            throw ACEError(.invalidAuthorization, "published agent must be {kel, descriptor}")
        }
        let now = try unixNow(clock)
        let pinned = try load(aceId)?.state
        let agent = try verifyPublishedAgent(source, now: now, allowLoopback: allowLoopback, pinned: pinned)
        if let kept = try adoptOrUsable(agent) { return kept }
        return try load(aceId)?.agent ?? agent
    }

    /// `adopt(_:live:)`, except that a refused older revision (`stale_peer_binding`) falls back to the held descriptor
    /// while it is usable (unexpired and bound to the current pin), returned; nil when `agent` was adopted (04 § Caching).
    /// Without a usable held descriptor the refusal stands.
    @discardableResult
    package func adoptOrUsable(_ agent: VerifiedAgent, live: Bool = false) throws -> VerifiedAgent? {
        do {
            try adopt(agent, live: live)
            return nil
        } catch let e as ACEError where e.code == .stalePeerBinding {
            guard let kept = try usableAgent(agent.aceId) else { throw e }
            return kept
        }
    }

    /// Adopt a verified agent's KEL and descriptor under lock `peers`. The KEL is reconciled with the pin (fork rules) and
    /// the descriptor must verify under the resulting newest state: one signed by a delegation the pin has superseded is
    /// `stale_peer_binding` (no prekey substitution by a replaced signing key). A descriptor under an advanced pin replaces
    /// the held one unconditionally; under the same pin, an older `issuedAt`, or the same `issuedAt` with other content, is
    /// `stale_peer_binding`. `live`: a relay served the descriptor, so it vouches for the KEL it is bound to and the
    /// pin becomes `kelLive`. Anything else (an imported or contact source, which a holder of a superseded key can sign)
    /// confirms nothing: a pin it moves is not live, an unchanged one keeps its flag (04 § Card record).
    @discardableResult
    public func adopt(_ agent: VerifiedAgent, live: Bool = false) throws -> PeerAdoption {
        try store.withLock("peers") {
            let now = try unixNow(clock)
            let old = try load(agent.aceId)
            let (state, outcome) = try ACEKel.extend(pinned: old?.state, events: agent.state.events, now: max(now, agent.descriptor.issuedAt))
            try verifyDescriptorSignature(agent.source, state: state, now: now)
            var kept = agent.source
            if let previous = old?.agent, old?.state.lastHash == state.lastHash {
                // An older revision, or the same `issuedAt` with other claims, never replaces the held one (04 § Caching).
                if previous.descriptor.issuedAt > agent.descriptor.issuedAt {
                    throw ACEError(.stalePeerBinding, "descriptor revision rolled back")
                }
                if previous.descriptor.issuedAt == agent.descriptor.issuedAt {
                    // identical claims: the signatures may differ (ML-DSA signing is randomized)
                    guard try documentDigest(previous.source["descriptor"] ?? .null) == documentDigest(agent.source["descriptor"] ?? .null) else {
                        throw ACEError(.stalePeerBinding, "conflicting descriptor revision")
                    }
                    kept = previous.source
                }
            }
            let same = old?.state.lastHash == state.lastHash
            let kelLive = (live && state.lastHash == agent.state.lastHash) || (same && old?.kelLive == true)
            try write(agent.aceId, state: state, agent: kept, fetchedAt: max(now, agent.descriptor.issuedAt, old?.fetchedAt ?? 0),
                      kelLive: kelLive)
            return PeerAdoption(state: state, outcome: outcome)
        }
    }

    /// `stale`: kept with the KEL state it was bound to.
    private func write(_ aceId: String, state: KelState, agent: JSONValue?, stale: VerifiedAgent? = nil, fetchedAt: Int,
                       kelLive: Bool) throws {
        var row: [String: JSONValue] = ["version": 1, "aceId": .string(aceId), "fetchedAt": .number(Double(fetchedAt)),
                                        "kel": ExportJSON.kelValue(state.events), "agent": agent ?? .null, "kelLive": .bool(kelLive)]
        if let stale { row["stale"] = ["kel": ExportJSON.kelValue(stale.state.events), "descriptor": stale.source["descriptor"] ?? .null] }
        try store.checkedWrite(Self.key(aceId), try JSONValue.object(row).jsonData())
    }
}
