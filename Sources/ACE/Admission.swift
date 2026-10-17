//
//  Admission.swift
//  ACE SDK
//
//  The durable admission table (05): per peer `pending` / `admitted` / `blocked` and the newest permit we issued to it;
//  the one held permit per issuer (issued to us: used to send to it and to resolve its descriptor), kept apart from
//  admission; the block records registered at our relays; and the held incoming contact requests awaiting a local
//  decision. Lock `admission`.
//

import Foundation

public enum AdmissionState: String, Sendable {
    case pending, admitted, blocked
}

/// One row of the admission table. A peer without a row is a stranger; so is one whose `pending` entry has expired
/// (`OFFLINE_WINDOW_SECONDS` after the request was sent, 05 § Flow step 4).
public struct AdmissionRecord: Sendable, Equatable {
    public var aceId: String
    public var state: AdmissionState
    /// The profile the contact is about.
    public var profile: String?
    /// The newest permit we issued to the peer, recorded once the packet carrying it was sent.
    public var issuedPermit: JSONValue?
    /// When `state` was last set.
    public var updatedAt: Int

    public init(aceId: String, state: AdmissionState, profile: String? = nil, issuedPermit: JSONValue? = nil, updatedAt: Int) {
        self.aceId = aceId
        self.state = state
        self.profile = profile
        self.issuedPermit = issuedPermit
        self.updatedAt = updatedAt
    }

    /// A contact reply about `profile` is expected: an answer to our pending request for it, or (admitted) to a permit refresh.
    package func acceptsReply(profile: String) -> Bool { state == .admitted || (state == .pending && self.profile == profile) }

    var jsonValue: JSONValue {
        var o: [String: JSONValue] = ["version": 1, "aceId": .string(aceId), "state": .string(state.rawValue), "updatedAt": .number(Double(updatedAt))]
        if let profile { o["profile"] = .string(profile) }
        if let issuedPermit { o["issuedPermit"] = issuedPermit }
        return .object(o)
    }

    /// Strict: anything malformed is `storage_failed`, never read as absent or admitted.
    init(_ v: JSONValue, key: String, aceId expected: String? = nil) throws {
        guard let o = v.objectValue, o["version"] == 1, let id = o["aceId"]?.stringValue, isACEId(id), expected.map({ $0 == id }) ?? true,
              let state = o["state"]?.stringValue.flatMap(AdmissionState.init), let at = o["updatedAt"]?.wireInt,
              o["profile"].map({ $0.stringValue != nil }) ?? true, o["issuedPermit"].map({ $0["expiresAt"]?.wireInt != nil }) ?? true,
              Set(o.keys).isSubset(of: ["version", "aceId", "state", "updatedAt", "profile", "issuedPermit"]) else {
            throw ACEError(.storageFailed, "\(key) is malformed")
        }
        self.init(aceId: id, state: state, profile: o["profile"]?.stringValue, issuedPermit: o["issuedPermit"], updatedAt: at)
    }

    /// An outgoing `pending` entry lives `OFFLINE_WINDOW_SECONDS` after its request was sent (05 § Flow step 4): a reply
    /// can wait that long on the relay.
    func expired(now: Int) -> Bool { state == .pending && now >= updatedAt + ACELimits.offlineWindowSeconds }
}

/// A pending incoming contact request (05 § Flow step 2), held until a local decision. It changes no admission state by
/// itself.
public struct ContactRequest: Sendable, Equatable {
    public let from: String
    public let profile: String
    public let note: String
    /// The requester's verified PublishedAgent as received.
    public let source: JSONValue
    /// The reply permit the requester issued to us.
    public let permit: JSONValue
    public let receivedAt: Int

    var jsonValue: JSONValue {
        ["version": 1, "from": .string(from), "profile": .string(profile), "note": .string(note), "source": source, "permit": permit,
         "receivedAt": .number(Double(receivedAt))]
    }

    init(from: String, profile: String, note: String, source: JSONValue, permit: JSONValue, receivedAt: Int) {
        self.from = from
        self.profile = profile
        self.note = note
        self.source = source
        self.permit = permit
        self.receivedAt = receivedAt
    }

    init(_ v: JSONValue, key: String) throws {
        guard v["version"] == 1, let from = v["from"]?.stringValue, isACEId(from), let profile = v["profile"]?.stringValue,
              let note = v["note"]?.stringValue, let source = v["source"], source.objectValue != nil, let permit = v["permit"],
              permit.objectValue != nil, let at = v["receivedAt"]?.wireInt else {
            throw ACEError(.storageFailed, "\(key) is malformed")
        }
        self.init(from: from, profile: profile, note: note, source: source, permit: permit, receivedAt: at)
    }
}

/// `{peer, blocked, revision}` as last decided locally (07 § Blocks). `unsyncedRevision` is that revision until every
/// relay accepted it: the first send and every `maintain` retry use exactly that value, so a late retry can never
/// outrank a later decision (an unblock allocates a strictly higher revision). Kept after an unblock, so the revision
/// keeps increasing.
package struct BlockRecord: Sendable, Equatable {
    package let peer: String
    package let blocked: Bool
    package let revision: Int
    package let unsyncedRevision: Int?
}

/// The admission table, held permits, block records and pending contact requests over an `ACEStore`.
public struct AdmissionTable: Sendable {
    let store: any ACEStore
    let clock: @Sendable () -> Int

    public init(store: any ACEStore, clock: @escaping @Sendable () -> Int = systemClock) {
        self.store = store
        self.clock = clock
    }

    private static func digest(_ aceId: String) -> String { sha256Hex(Data(aceId.utf8)) }
    private static func key(_ aceId: String) -> String { "admission/\(digest(aceId)).json" }
    private static func requestKey(_ aceId: String) -> String { "requests/\(digest(aceId)).json" }
    private static func heldKey(_ aceId: String) -> String { "admission-permits/\(digest(aceId)).json" }
    private static func blockKey(_ aceId: String) -> String { "blocks/\(digest(aceId)).json" }

    private func now() throws -> Int { try unixNow(clock) }

    /// The peer's row, nil for a stranger. An expired `pending` entry is deleted (05 § Flow step 4) under lock
    /// `admission`, after reading it again there: another process may have replaced it (with a block, or a fresh
    /// request) since the first read.
    public func get(_ aceId: String) throws -> AdmissionRecord? {
        guard let r = try row(aceId) else { return nil }
        guard r.expired(now: try now()) else { return r }
        return try store.withLock("admission") {
            guard let current = try row(aceId) else { return nil }
            guard current.expired(now: try now()) else { return current }
            try store.checkedDelete(Self.key(aceId))
            return nil
        }
    }

    /// The row as stored, without expiry: for callers already holding lock `admission`.
    private func row(_ aceId: String) throws -> AdmissionRecord? {
        let key = Self.key(aceId)
        return try store.readJSON(key).map { try AdmissionRecord($0, key: key, aceId: aceId) }
    }

    /// `row`, nil when it is an expired `pending` entry (left for `get` or the next write to remove).
    private func live(_ aceId: String) throws -> AdmissionRecord? {
        guard let r = try row(aceId), !r.expired(now: try now()) else { return nil }
        return r
    }

    public func all() throws -> [AdmissionRecord] {
        let now = try now()
        return try store.checkedList("admission/").compactMap { key in
            try store.readJSON(key).flatMap { v in
                let r = try AdmissionRecord(v, key: key)
                guard Self.key(r.aceId) == key else { throw ACEError(.storageFailed, "\(key) does not match its aceId") }
                return r.expired(now: now) ? nil : r
            }
        }
    }

    /// Read-modify-write one row under lock `admission`; `body` returns the new row (nil deletes it). `updatedAt` is set
    /// whenever the state changes (a caller renewing a `pending` row sets it itself).
    @discardableResult
    public func update(_ aceId: String, _ body: (AdmissionRecord?) throws -> AdmissionRecord?) throws -> AdmissionRecord? {
        try store.withLock("admission") { try updateLocked(aceId, body) }
    }

    @discardableResult
    private func updateLocked(_ aceId: String, _ body: (AdmissionRecord?) throws -> AdmissionRecord?) throws -> AdmissionRecord? {
        let old = try live(aceId)
        guard var next = try body(old) else {
            try store.checkedDelete(Self.key(aceId))
            return nil
        }
        if next.state != old?.state { next.updatedAt = try now() }
        try store.checkedWrite(Self.key(aceId), try next.jsonValue.jsonData())
        return next
    }

    /// Record a permit we issued to `peer` once the packet carrying it was sent (05 § Delivery permits): it becomes the
    /// newest issued permit of the peer's row, if it still has one.
    package func noteIssued(_ peer: String, permit: JSONValue) throws {
        try update(peer) { r in
            guard var r else { return nil }
            r.issuedPermit = permit
            return r
        }
    }

    /// Hold a verified permit its issuer issued to us: the one slot per issuer, written by every path (accept, `accepted`,
    /// receipt renewal, invitation). Holding a permit only lets us reach the issuer; whether the issuer may deliver to us
    /// stays a local decision. Under lock `admission`: `when` makes it conditional on the issuer's row, and `keep`
    /// (default: the held one is newer by `issuedAt`) keeps the held permit instead.
    public func holdPermit(_ permit: VerifiedPermit, when: ((AdmissionRecord?) -> Bool)? = nil, keep: ((JSONValue) -> Bool)? = nil) throws {
        let keep = keep ?? { ($0["issuedAt"]?.wireInt ?? 0) > permit.issuedAt }
        try store.withLock("admission") {
            if let when, !when(try live(permit.issuer)) { return }
            if let old = try heldPermit(permit.issuer), keep(old) { return }
            try store.checkedWrite(Self.heldKey(permit.issuer), try permit.value.jsonData())
        }
    }

    /// The permit `aceId` issued to us (see `holdPermit`), if any; unverified (verify it under the issuer's current pin).
    public func heldPermit(_ aceId: String) throws -> JSONValue? {
        let key = Self.heldKey(aceId)
        guard let v = try store.readJSON(key) else { return nil }
        guard v["issuer"]?.stringValue == aceId, v["issuedAt"]?.wireInt != nil, v["expiresAt"]?.wireInt != nil else {
            throw ACEError(.storageFailed, "\(key) is malformed")
        }
        return v
    }

    // MARK: Blocks

    package func blockRecord(_ peer: String) throws -> BlockRecord? {
        let key = Self.blockKey(peer)
        guard let v = try store.readJSON(key) else { return nil }
        guard v["peer"]?.stringValue == peer, let blocked = v["blocked"]?.boolValue, let revision = v["revision"]?.wireInt,
              v["unsyncedRevision"].map({ $0.wireInt != nil }) ?? true else { throw ACEError(.storageFailed, "\(key) is malformed") }
        return BlockRecord(peer: peer, blocked: blocked, revision: revision, unsyncedRevision: v["unsyncedRevision"]?.wireInt)
    }

    /// One local block decision under lock `admission`: the row (`body`, as `update`) and the block record with the next
    /// revision, unsynced, written together; a block also discards the peer's held request (05 § Blocks), so an accept
    /// (which admits under the same lock) never lands between the two. Returns the record to register at the relays.
    package func decideBlock(_ peer: String, blocked: Bool, _ body: (AdmissionRecord?) throws -> AdmissionRecord?) throws -> BlockRecord {
        try store.withLock("admission") {
            try updateLocked(peer, body)
            if blocked { try store.checkedDelete(Self.requestKey(peer)) }
            let revision = (try blockRecord(peer)?.revision ?? 0) + 1
            let record = BlockRecord(peer: peer, blocked: blocked, revision: revision, unsyncedRevision: revision)
            try writeBlock(record)
            return record
        }
    }

    /// The relays accepted (or already hold a higher revision than) `revision`: clear `unsyncedRevision`, unless a newer
    /// decision replaced it meanwhile.
    package func blockSynced(_ peer: String, revision: Int) throws {
        try store.withLock("admission") {
            guard let r = try blockRecord(peer), r.unsyncedRevision == revision else { return }
            try writeBlock(BlockRecord(peer: peer, blocked: r.blocked, revision: r.revision, unsyncedRevision: nil))
        }
    }

    package func unsyncedBlocks() throws -> [BlockRecord] {
        try store.checkedList("blocks/").compactMap { key in
            guard let peer = try store.readJSON(key)?["peer"]?.stringValue, Self.blockKey(peer) == key else {
                throw ACEError(.storageFailed, "\(key) is malformed")
            }
            return try blockRecord(peer).flatMap { $0.unsyncedRevision == nil ? nil : $0 }
        }
    }

    private func writeBlock(_ r: BlockRecord) throws {
        var o: [String: JSONValue] = ["peer": .string(r.peer), "blocked": .bool(r.blocked), "revision": .number(Double(r.revision))]
        if let u = r.unsyncedRevision { o["unsyncedRevision"] = .number(Double(u)) }
        try store.checkedWrite(Self.blockKey(r.peer), try JSONValue.object(o).jsonData())
    }

    // MARK: Pending contact requests (05 § Flow step 2)

    private static func expired(_ r: ContactRequest, now: Int) -> Bool { now >= r.receivedAt + ACELimits.contactRequestTTLSeconds }

    /// Unexpired pending requests, oldest first; expired ones are deleted.
    public func requests() throws -> [ContactRequest] { try requests(now: try now()) }

    private func requests(now: Int) throws -> [ContactRequest] {
        var out: [ContactRequest] = []
        for key in try store.checkedList("requests/") {
            guard let v = try store.readJSON(key) else { continue }
            let r = try ContactRequest(v, key: key)
            if Self.expired(r, now: now) { try store.checkedDelete(key); continue }
            out.append(r)
        }
        return out.sorted { ($0.receivedAt, $0.from) < ($1.receivedAt, $1.from) }
    }

    /// `aceId`'s pending request, nil when absent or expired.
    public func request(_ aceId: String) throws -> ContactRequest? {
        let key = Self.requestKey(aceId)
        guard let r = try store.readJSON(key).map({ try ContactRequest($0, key: key) }) else { return nil }
        if Self.expired(r, now: try now()) { try store.checkedDelete(key); return nil }
        return r
    }

    /// Hold `r` (dated `receivedAt`): one slot per sender (replaced), expired ones dropped, the oldest evicted when full.
    func putRequest(_ r: ContactRequest) throws {
        try store.withLock("admission") {
            var held = try requests(now: r.receivedAt).filter { $0.from != r.from }
            while held.count >= ACELimits.maxPendingContactRequests {
                try store.checkedDelete(Self.requestKey(held.removeFirst().from))
            }
            try store.checkedWrite(Self.requestKey(r.from), try r.jsonValue.jsonData())
        }
    }

    func removeRequest(_ aceId: String) throws {
        try store.withLock("admission") { try store.checkedDelete(Self.requestKey(aceId)) }
    }
}
