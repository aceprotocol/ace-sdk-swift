//
//  PrekeyVault.swift
//  ACE SDK
//
//  Prekey lifecycle: the current X-Wing prekey published in the descriptor, superseded prekeys kept for
//  `OFFLINE_WINDOW_SECONDS` after they were superseded (at most `ACELimits.maxPrekeys` in all), then deleted.
//  The forward-secrecy window equals that retention.
//

import Foundation

/// A prekey the vault holds: its public half and when it was created / superseded.
public struct PrekeyRecord: Sendable, Equatable {
    public let prekey: Prekey
    public let createdAt: Int
    /// Nil for the current prekey.
    public let supersededAt: Int?
}

/// Storage of prekey seeds. Seeds are secrets with the protection level of identity seeds.
///
/// Besides the published prekeys, the vault keeps per peer (04 § Peer prekeys): the peer prekey offered to it (`offer`), the
/// one it used last (`used`), each opening only that peer's packets for `OFFLINE_WINDOW_SECONDS` after it was last offered;
/// and the newest key that peer offered us (`hold` / `held`), bound to the pin it was authenticated under.
public protocol PrekeyVault: Sendable {
    /// The current prekey, or nil before the first `rotate`.
    func current() throws -> PrekeyRecord?
    /// Generate a new current prekey; the previous one is superseded at `now`. Prunes.
    @discardableResult func rotate(now: Int) throws -> PrekeyRecord
    /// The 32-byte seed for `prekeyId` at `now`: the published current or a retained prekey (a superseded one only while its
    /// retention, `OFFLINE_WINDOW_SECONDS` after supersession, lasts, even before it is deleted), else, when `sender` is
    /// given, the peer prekey offered to `sender` or in use by it while its window lasts; nil otherwise. Implementations
    /// prune expired seeds here (04 § Prekey, § Peer prekeys).
    func open(_ prekeyId: String, sender: String?, now: Int) throws -> Data?
    /// Delete prekeys superseded more than `OFFLINE_WINDOW_SECONDS` before `now` (and the oldest beyond the cap), and peer
    /// seeds and held keys whose window ended; a peer left with nothing is removed.
    func prune(now: Int) throws
    /// The peer prekey offered to `peer` in a packet sent at `now`: the offered one while its window lasts (the window
    /// restarts at `now`), else a fresh one.
    func offer(peer: String, now: Int) throws -> Prekey
    /// A packet from `peer` opened under `prekeyId`: when that is the offered key it becomes the in-use key (the previous
    /// in-use seed is deleted) and the next `offer` generates a new one. Any other ID changes nothing.
    func used(peer: String, prekeyId: String) throws
    /// Hold the key `peer` offered in a packet dated `timestamp`, authenticated under pin `pin` (the last pinned KEL event
    /// digest), unless the held key came from a packet at least as new.
    func hold(peer: String, prekey: Prekey, timestamp: Int, pin: String) throws
    /// The key held for `peer` while `pin` is the pin it is bound to and its window (`timestamp + OFFLINE_WINDOW_SECONDS`)
    /// lasts; otherwise it is deleted and the answer is nil.
    func held(peer: String, pin: String, now: Int) throws -> Prekey?
    /// Delete the key held for `peer` (a block, or a `rejected:unknown_prekey` naming it).
    func dropHeld(peer: String) throws
}

extension PrekeyVault {
    /// A published (current or retained) prekey's seed; never a peer prekey.
    public func open(_ prekeyId: String, now: Int) throws -> Data? { try open(prekeyId, sender: nil, now: now) }
}

/// How `StorePrekeyVault` protects seeds at rest.
public enum PrekeyProtection: Sendable {
    /// The seed is stored as is (a `FileStore` writes files 0600; a `MemoryStore` keeps it in process memory).
    case software
    /// The seed is sealed to a fresh Secure Enclave ML-KEM-768 key per prekey (the same KEM/DEM seal the SDK uses for
    /// every Secure Enclave secret) and opened per packet; never kept in clear.
    case secureEnclave
}

/// A `PrekeyVault` over an `ACEStore` (`prekeys.json` under lock `prekeys`): `MemoryStore` for in-memory, `FileStore` for
/// a keystore file, `protection: .secureEnclave` for Secure Enclave–sealed seeds (published and peer seeds alike).
///
/// The document, version 2 (version 1 is read as version 2 with no peers; any other is `storage_failed`):
/// `{version: 2, current: Entry|null, retained: Entry[], peers: {<aceId>: {offered: Seed|null, inUse: Seed|null,
/// held: {publicKey, timestamp, pin}|null}}}`, where `Entry` is `{prekey, createdAt, supersededAt (retained only), secret}`,
/// `Seed` is `{prekey, offeredAt, secret}` and `secret` is `{seed}` (software) or `{seal}` (Secure Enclave). The public
/// half is stored beside each secret so lookups by ID never unseal.
public final class StorePrekeyVault: PrekeyVault, @unchecked Sendable {
    private static let key = "prekeys.json"
    private static let version = 2
    private static let sealInfo = "ace.secure-enclave.mlkem768.prekey-seed"
    private let store: any ACEStore
    private let protection: PrekeyProtection

    public init(store: any ACEStore, protection: PrekeyProtection = .software) {
        self.store = store
        self.protection = protection
    }

    /// A published prekey.
    private struct Entry {
        var record: PrekeyRecord
        var secret: JSONValue
    }

    /// A peer prekey seed we offered.
    private struct Seed: Equatable {
        var prekey: Prekey
        var offeredAt: Int
        var secret: JSONValue

        func live(_ now: Int) -> Bool { now < offeredAt + ACELimits.offlineWindowSeconds }
    }

    /// A key a peer offered us, from its packet dated `timestamp` authenticated under pin `pin`.
    private struct Held: Equatable {
        var prekey: Prekey
        var timestamp: Int
        var pin: String

        func live(_ now: Int) -> Bool { now < timestamp + ACELimits.offlineWindowSeconds }
    }

    private struct Peer: Equatable {
        var offered: Seed?
        var inUse: Seed?
        var held: Held?

        var isEmpty: Bool { offered == nil && inUse == nil && held == nil }

        /// Without the seeds and held key whose window ended at `now`.
        func pruned(_ now: Int) -> Peer {
            Peer(offered: offered.flatMap { $0.live(now) ? $0 : nil }, inUse: inUse.flatMap { $0.live(now) ? $0 : nil },
                 held: held.flatMap { $0.live(now) ? $0 : nil })
        }
    }

    private struct Document {
        var entries: [Entry] = []
        var peers: [String: Peer] = [:]
    }

    // MARK: Persistence

    private var malformed: ACEError { ACEError(.storageFailed, "\(Self.key) is malformed") }

    private func load() throws -> Document {
        guard let raw = try store.checkedRead(Self.key) else { return Document() }
        if let o = JSONValue(stored: raw)?.objectValue, o["version"] == 1 { return try upgrade(o) }
        guard let o = JSONValue(stored: raw)?.objectValue, o["version"] == .number(Double(Self.version)),
              Set(o.keys) == ["version", "current", "retained", "peers"], let current = o["current"], let retained = o["retained"]?.arrayValue,
              let peers = o["peers"]?.objectValue else {
            throw malformed
        }
        var doc = Document()
        if current != .null { doc.entries.append(try entry(current, retained: false)) }
        for r in retained { doc.entries.append(try entry(r, retained: true)) }
        for (peer, v) in peers {
            guard isACEId(peer), let p = v.objectValue, Set(p.keys) == ["offered", "inUse", "held"] else { throw malformed }
            doc.peers[peer] = Peer(offered: try seed(p["offered"]!), inUse: try seed(p["inUse"]!), held: try held(p["held"]!))
        }
        return doc
    }

    /// Version 1 (0.6.0 and earlier): `{version: 1, keys: [{prekey, createdAt, supersededAt?, secret}]}`, published
    /// prekeys only. Read as version 2 with no peers; the next save writes version 2. Refusing it would cut every agent
    /// upgraded with a vault off its own published prekey.
    private func upgrade(_ o: [String: JSONValue]) throws -> Document {
        guard Set(o.keys) == ["version", "keys"], let keys = o["keys"]?.arrayValue else { throw malformed }
        var doc = Document()
        for k in keys {
            guard let e = k.objectValue else { throw malformed }
            doc.entries.append(try entry(k, retained: e["supersededAt"] != nil))
        }
        guard doc.entries.filter({ $0.record.supersededAt == nil }).count <= 1 else { throw malformed }
        return doc
    }

    private func secret(_ v: JSONValue?) throws -> JSONValue {
        guard let v, let o = v.objectValue, o.count == 1, o["seed"]?.stringValue != nil || o["seal"]?.objectValue != nil else { throw malformed }
        return v
    }

    private func entry(_ v: JSONValue, retained: Bool) throws -> Entry {
        guard let o = v.objectValue, Set(o.keys) == (retained ? ["prekey", "createdAt", "supersededAt", "secret"] : ["prekey", "createdAt", "secret"]),
              let prekey = Prekey(o["prekey"]), let created = o["createdAt"]?.wireInt else { throw malformed }
        var superseded: Int?
        if retained {
            guard let n = o["supersededAt"]?.wireInt else { throw malformed }
            superseded = n
        }
        return Entry(record: PrekeyRecord(prekey: prekey, createdAt: created, supersededAt: superseded), secret: try secret(o["secret"]))
    }

    private func seed(_ v: JSONValue) throws -> Seed? {
        if v == .null { return nil }
        guard let o = v.objectValue, Set(o.keys) == ["prekey", "offeredAt", "secret"], let prekey = Prekey(o["prekey"]),
              let at = o["offeredAt"]?.wireInt else { throw malformed }
        return Seed(prekey: prekey, offeredAt: at, secret: try secret(o["secret"]))
    }

    private func held(_ v: JSONValue) throws -> Held? {
        if v == .null { return nil }
        guard let o = v.objectValue, Set(o.keys) == ["publicKey", "timestamp", "pin"], let text = o["publicKey"]?.stringValue,
              let ts = o["timestamp"]?.wireInt, let pin = o["pin"]?.stringValue, isSHA256Hex(pin),
              let raw = try? decodeB64(text, code: .storageFailed, what: "held prekey", maxBytes: ACELimits.kemPublicKeySize),
              let prekey = try? Prekey(publicKey: raw) else { throw malformed }
        return Held(prekey: prekey, timestamp: ts, pin: pin)
    }

    private func save(_ doc: Document) throws {
        func entry(_ e: Entry) -> JSONValue {
            var o: [String: JSONValue] = ["prekey": e.record.prekey.jsonValue, "createdAt": .number(Double(e.record.createdAt)), "secret": e.secret]
            if let s = e.record.supersededAt { o["supersededAt"] = .number(Double(s)) }
            return .object(o)
        }
        func seed(_ s: Seed?) -> JSONValue {
            s.map { ["prekey": $0.prekey.jsonValue, "offeredAt": .number(Double($0.offeredAt)), "secret": $0.secret] } ?? .null
        }
        var peers: [String: JSONValue] = [:]
        for (peer, p) in doc.peers where !p.isEmpty {
            let held: JSONValue = p.held.map {
                ["publicKey": .string(ACEBase64.encode($0.prekey.publicKey)), "timestamp": .number(Double($0.timestamp)), "pin": .string($0.pin)]
            } ?? .null
            peers[peer] = ["offered": seed(p.offered), "inUse": seed(p.inUse), "held": held]
        }
        let current = doc.entries.first { $0.record.supersededAt == nil }
        let value: JSONValue = .object([
            "version": .number(Double(Self.version)), "current": current.map(entry) ?? .null,
            "retained": .array(doc.entries.filter { $0.record.supersededAt != nil }.map(entry)), "peers": .object(peers),
        ])
        try store.checkedWrite(Self.key, try value.jsonData())
    }

    /// Load, apply `body` to the document, save when it changed it (`body` returns whether it did).
    private func update<T>(_ body: (inout Document) throws -> (T, changed: Bool)) throws -> T {
        try store.withLock("prekeys") {
            var doc = try load()
            let (result, changed) = try body(&doc)
            if changed { try save(doc) }
            return result
        }
    }

    private static func pruned(_ entries: [Entry], now: Int) -> [Entry] {
        var kept = entries.filter { e in e.record.supersededAt.map { now < $0 + ACELimits.offlineWindowSeconds } ?? true }
        // Newest first beyond the current one; the cap counts the current prekey.
        kept.sort { ($0.record.supersededAt ?? .max) > ($1.record.supersededAt ?? .max) }
        return Array(kept.prefix(ACELimits.maxPrekeys))
    }

    /// A fresh seed's public half and its stored secret (sealed under `.secureEnclave`).
    private func generate() throws -> (Prekey, JSONValue) {
        var seed = XWing.generateSeed()
        defer { seed.resetBytes(in: 0..<seed.count) }
        let prekey = try Prekey(publicKey: XWing.publicKey(fromSeed: seed))
        switch protection {
        case .software: return (prekey, ["seed": .string(ACEBase64.encode(seed))])
        case .secureEnclave: return (prekey, ["seal": try SecureEnclaveSeal.seal(seed, info: Self.sealInfo).jsonValue])
        }
    }

    private func unseal(_ secret: JSONValue) throws -> Data {
        if secret["seed"] != nil, protection == .secureEnclave {
            // Fail closed: a Secure Enclave vault never holds a seed in clear, so one here was planted or downgraded.
            throw ACEError(.storageFailed, "\(Self.key) holds a plaintext seed in a Secure Enclave vault")
        }
        if let text = secret["seed"]?.stringValue {
            return try decodeB64(text, code: .storageFailed, what: "prekey seed", maxBytes: ACELimits.kemSeedSize)
        }
        do {
            return try SecureEnclaveSeal(secret["seal"]).open(info: Self.sealInfo)
        } catch let e as ACEError {
            throw ACEError(.identityUnavailable, "prekey seal unavailable: \(e.message)")
        }
    }

    private static func check(peer: String, now: Int) throws {
        guard isACEId(peer) else { throw ACEError(.invalidArgument, "peer must be an ACE ID") }
        guard isWireInt(now) else { throw ACEError(.invalidArgument, "now must be an integer in [0, 2^53-1]") }
    }

    /// The stored document as is (tests).
    package func document() throws -> JSONValue? {
        try store.withLock("prekeys") { try store.checkedRead(Self.key).flatMap { JSONValue(stored: $0) } }
    }

    // MARK: Published prekeys

    public func current() throws -> PrekeyRecord? {
        try store.withLock("prekeys") { try load().entries.first { $0.record.supersededAt == nil }?.record }
    }

    @discardableResult
    public func rotate(now: Int) throws -> PrekeyRecord {
        guard isWireInt(now) else { throw ACEError(.invalidArgument, "now must be an integer in [0, 2^53-1]") }
        let (prekey, secret) = try generate()
        let record = PrekeyRecord(prekey: prekey, createdAt: now, supersededAt: nil)
        try update { doc in
            var entries = doc.entries.map { e -> Entry in
                guard e.record.supersededAt == nil else { return e }
                return Entry(record: PrekeyRecord(prekey: e.record.prekey, createdAt: e.record.createdAt, supersededAt: now), secret: e.secret)
            }
            entries.append(Entry(record: record, secret: secret))
            doc.entries = Self.pruned(entries, now: now)
            return ((), true)
        }
        return record
    }

    public func open(_ prekeyId: String, sender: String?, now: Int) throws -> Data? {
        let secret = try store.withLock("prekeys") { () -> JSONValue? in
            var doc = try load()
            let kept = Self.pruned(doc.entries, now: now)
            if kept.count != doc.entries.count {
                doc.entries = kept
                try? save(doc)  // opportunistic; the expired seed is refused regardless
            }
            if let e = kept.first(where: { $0.record.prekey.id == prekeyId }) { return e.secret }
            guard let sender, let p = doc.peers[sender] else { return nil }
            guard let s = [p.offered, p.inUse].compactMap({ $0 }).first(where: { $0.prekey.id == prekeyId }) else { return nil }
            if s.live(now) { return s.secret }
            doc.peers[sender] = p.pruned(now)  // its window ended: deleted (best effort, refused either way)
            try? save(doc)
            return nil
        }
        return try secret.map(unseal)
    }

    public func prune(now: Int) throws {
        try update { doc in
            let entries = Self.pruned(doc.entries, now: now)
            var peers: [String: Peer] = [:]
            for (peer, p) in doc.peers {
                let kept = p.pruned(now)
                if !kept.isEmpty { peers[peer] = kept }
            }
            let changed = entries.count != doc.entries.count || peers != doc.peers
            doc.entries = entries
            doc.peers = peers
            return ((), changed)
        }
    }

    // MARK: Peer prekeys (04 § Peer prekeys)

    public func offer(peer: String, now: Int) throws -> Prekey {
        try Self.check(peer: peer, now: now)
        return try update { doc in
            var p = doc.peers[peer] ?? Peer()
            if var o = p.offered, o.live(now) {
                guard o.offeredAt != now else { return (o.prekey, false) }
                o.offeredAt = now  // its window restarts
                p.offered = o
            } else {
                let (prekey, secret) = try generate()
                p.offered = Seed(prekey: prekey, offeredAt: now, secret: secret)
            }
            doc.peers[peer] = p
            return (p.offered!.prekey, true)
        }
    }

    public func used(peer: String, prekeyId: String) throws {
        guard isACEId(peer) else { throw ACEError(.invalidArgument, "peer must be an ACE ID") }
        try update { doc in
            guard var p = doc.peers[peer], let o = p.offered, o.prekey.id == prekeyId else { return ((), false) }
            p.inUse = o  // the previous in-use seed is deleted
            p.offered = nil
            doc.peers[peer] = p
            return ((), true)
        }
    }

    public func hold(peer: String, prekey: Prekey, timestamp: Int, pin: String) throws {
        try Self.check(peer: peer, now: timestamp)
        guard isSHA256Hex(pin) else { throw ACEError(.invalidArgument, "pin must be 64 lowercase hex") }
        try update { doc in
            var p = doc.peers[peer] ?? Peer()
            if let h = p.held, timestamp <= h.timestamp { return ((), false) }
            p.held = Held(prekey: prekey, timestamp: timestamp, pin: pin)
            doc.peers[peer] = p
            return ((), true)
        }
    }

    public func held(peer: String, pin: String, now: Int) throws -> Prekey? {
        try Self.check(peer: peer, now: now)
        return try update { doc in
            guard var p = doc.peers[peer], let h = p.held else { return (nil, false) }
            if h.pin == pin, h.live(now) { return (h.prekey, false) }
            p.held = nil
            doc.peers[peer] = p
            return (nil, true)
        }
    }

    public func dropHeld(peer: String) throws {
        guard isACEId(peer) else { throw ACEError(.invalidArgument, "peer must be an ACE ID") }
        try update { doc in
            guard var p = doc.peers[peer], p.held != nil else { return ((), false) }
            p.held = nil
            doc.peers[peer] = p
            return ((), true)
        }
    }
}
