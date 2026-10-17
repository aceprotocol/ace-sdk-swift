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
public protocol PrekeyVault: Sendable {
    /// The current prekey, or nil before the first `rotate`.
    func current() throws -> PrekeyRecord?
    /// Generate a new current prekey; the previous one is superseded at `now`. Prunes.
    @discardableResult func rotate(now: Int) throws -> PrekeyRecord
    /// The 32-byte seed of a held prekey at `now`; nil when it is unknown, deleted, or superseded with its retention
    /// (`OFFLINE_WINDOW_SECONDS` after supersession) ended, even before it is deleted. Implementations prune expired seeds
    /// here (04 § Prekey).
    func open(_ prekeyId: String, now: Int) throws -> Data?
    /// Delete prekeys superseded more than `OFFLINE_WINDOW_SECONDS` before `now`, and the oldest beyond the cap.
    func prune(now: Int) throws
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
/// a keystore file, `protection: .secureEnclave` for Secure Enclave–sealed seeds.
public final class StorePrekeyVault: PrekeyVault, @unchecked Sendable {
    private static let key = "prekeys.json"
    private static let sealInfo = "ace.secure-enclave.mlkem768.prekey-seed"
    private let store: any ACEStore
    private let protection: PrekeyProtection

    public init(store: any ACEStore, protection: PrekeyProtection = .software) {
        self.store = store
        self.protection = protection
    }

    private struct Entry {
        var record: PrekeyRecord
        var secret: JSONValue
    }

    private func load() throws -> [Entry] {
        guard let raw = try store.checkedRead(Self.key) else { return [] }
        guard let o = JSONValue(stored: raw)?.objectValue, o["version"] == 1, let items = o["keys"]?.arrayValue else {
            throw ACEError(.storageFailed, "\(Self.key) is malformed")
        }
        return try items.map { item in
            guard let prekey = Prekey(item["prekey"]), let created = item["createdAt"]?.wireInt, let secret = item["secret"] else {
                throw ACEError(.storageFailed, "\(Self.key) holds a malformed prekey")
            }
            var superseded: Int?
            if let s = item["supersededAt"] {
                guard let n = s.wireInt else { throw ACEError(.storageFailed, "\(Self.key) holds a malformed prekey") }
                superseded = n
            }
            return Entry(record: PrekeyRecord(prekey: prekey, createdAt: created, supersededAt: superseded), secret: secret)
        }
    }

    private func save(_ entries: [Entry]) throws {
        let items: [JSONValue] = entries.map { e in
            var o: [String: JSONValue] = ["prekey": e.record.prekey.jsonValue, "createdAt": .number(Double(e.record.createdAt)), "secret": e.secret]
            if let s = e.record.supersededAt { o["supersededAt"] = .number(Double(s)) }
            return .object(o)
        }
        try store.checkedWrite(Self.key, try JSONValue.object(["version": 1, "keys": .array(items)]).jsonData())
    }

    private static func pruned(_ entries: [Entry], now: Int) -> [Entry] {
        var kept = entries.filter { e in e.record.supersededAt.map { now < $0 + ACELimits.offlineWindowSeconds } ?? true }
        // Newest first beyond the current one; the cap counts the current prekey.
        kept.sort { ($0.record.supersededAt ?? .max) > ($1.record.supersededAt ?? .max) }
        return Array(kept.prefix(ACELimits.maxPrekeys))
    }

    public func current() throws -> PrekeyRecord? {
        try store.withLock("prekeys") { try load().first { $0.record.supersededAt == nil }?.record }
    }

    @discardableResult
    public func rotate(now: Int) throws -> PrekeyRecord {
        guard isWireInt(now) else { throw ACEError(.invalidArgument, "now must be an integer in [0, 2^53-1]") }
        var seed = XWing.generateSeed()
        defer { seed.resetBytes(in: 0..<seed.count) }
        let prekey = try Prekey(publicKey: XWing.publicKey(fromSeed: seed))
        let secret: JSONValue
        switch protection {
        case .software: secret = ["seed": .string(ACEBase64.encode(seed))]
        case .secureEnclave: secret = ["seal": try SecureEnclaveSeal.seal(seed, info: Self.sealInfo).jsonValue]
        }
        let record = PrekeyRecord(prekey: prekey, createdAt: now, supersededAt: nil)
        try store.withLock("prekeys") {
            var entries = try load().map { e -> Entry in
                guard e.record.supersededAt == nil else { return e }
                return Entry(record: PrekeyRecord(prekey: e.record.prekey, createdAt: e.record.createdAt, supersededAt: now), secret: e.secret)
            }
            entries.append(Entry(record: record, secret: secret))
            try save(Self.pruned(entries, now: now))
        }
        return record
    }

    public func open(_ prekeyId: String, now: Int) throws -> Data? {
        let entry = try store.withLock("prekeys") { () -> Entry? in
            let entries = try load()
            let kept = Self.pruned(entries, now: now)
            if kept.count != entries.count { try? save(kept) }  // opportunistic; the expired seed is refused regardless
            return kept.first { $0.record.prekey.id == prekeyId }
        }
        guard let secret = entry?.secret else { return nil }
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

    public func prune(now: Int) throws {
        try store.withLock("prekeys") {
            let entries = try load()
            let kept = Self.pruned(entries, now: now)
            if kept.count != entries.count { try save(kept) }
        }
    }
}
