//
//  Outbox.swift
//  ACE SDK
//
//  Sender durability (06 § Outbox). Each message is stored as `{messageId, to, privateContent, createdAt}` plus its
//  attempt state. Every attempt re-encrypts to the peer's current prekey and re-signs at the current time; `messageId`
//  never changes. Retries back off `min(60·2^(n-1), 3600)` s until a receipt arrives or `OFFLINE_WINDOW_SECONDS` have
//  passed since the first attempt (`expired`). A relay `{ok: true}` is not delivery. `expired` (or abandoned) means the
//  sender stopped retrying, the outcome is unknown: a late receipt still settles the entry.
//

import Foundation

/// What the Outbox needs from the network for one attempt (`NetworkClient`).
package protocol PacketTransport: Sendable {
    /// The peer's current prekey from a valid descriptor; `refresh` forces a descriptor refresh first.
    func prekey(for aceId: String, refresh: Bool) async throws -> Prekey
    /// Encrypt `content` to `prekey`, sign it now and post it to the peer's relays (one attempt). `retry`: an attempt after
    /// the first, which carries `admission` (05 § Admission recovery).
    func post(to aceId: String, content: PrivateContent, messageId: String, prekey: Prekey, retry: Bool) async throws
}

public enum OutboxStatus: String, Sendable {
    case pending, delivered, rejected, expired
}

/// One staged message and its attempt state.
public struct OutboxEntry: Sendable, Equatable {
    public let messageId: String
    public let to: String
    public let content: PrivateContent
    public let createdAt: Int
    public internal(set) var status: OutboxStatus
    /// The `rejected` receipt's code (or `unknown_prekey` when the current prekey was refused).
    public internal(set) var code: String?
    public internal(set) var attempts: Int
    public internal(set) var firstAttemptAt: Int?
    public internal(set) var nextAttemptAt: Int
    /// The prekey of the last attempt.
    public internal(set) var lastPrekey: String?
    /// A `rejected:unknown_prekey` receipt asked for a descriptor refresh before the next attempt.
    public internal(set) var refreshPrekey: Bool
    public internal(set) var lastError: String?
    /// When the entry became `expired` (retries stopped or abandoned).
    public internal(set) var expiredAt: Int?
    /// When a receipt (or a final attempt error) settled it as `delivered` or `rejected`.
    public internal(set) var settledAt: Int?
    /// An attempt holds the entry until then (a lease, so two processes never attempt it at once).
    public internal(set) var inFlightUntil: Int?

    var jsonValue: JSONValue {
        var o: [String: JSONValue] = [
            "version": 1, "messageId": .string(messageId), "to": .string(to), "content": content.jsonValue, "createdAt": .number(Double(createdAt)),
            "status": .string(status.rawValue), "attempts": .number(Double(attempts)), "nextAttemptAt": .number(Double(nextAttemptAt)),
            "refreshPrekey": .bool(refreshPrekey),
        ]
        if let code { o["code"] = .string(code) }
        if let firstAttemptAt { o["firstAttemptAt"] = .number(Double(firstAttemptAt)) }
        if let lastPrekey { o["lastPrekey"] = .string(lastPrekey) }
        if let lastError { o["lastError"] = .string(String(lastError.prefix(500))) }
        if let expiredAt { o["expiredAt"] = .number(Double(expiredAt)) }
        if let settledAt { o["settledAt"] = .number(Double(settledAt)) }
        if let inFlightUntil { o["inFlightUntil"] = .number(Double(inFlightUntil)) }
        return .object(o)
    }

    init(messageId: String, to: String, content: PrivateContent, createdAt: Int) {
        self.messageId = messageId
        self.to = to
        self.content = content
        self.createdAt = createdAt
        status = .pending
        attempts = 0
        nextAttemptAt = createdAt
        refreshPrekey = false
    }

    /// Strict: a corrupt entry is `storage_failed`, never skipped or read as absent.
    init(_ v: JSONValue, key: String) throws {
        func opt<T>(_ k: String, _ get: (JSONValue) -> T?) throws -> T? {
            guard let x = v[k] else { return nil }
            guard let t = get(x) else { throw ACEError(.storageFailed, "\(key) is malformed") }
            return t
        }
        guard v["version"] == 1, let id = v["messageId"]?.stringValue, isMessageId(id), key == "outbox/\(id).json",
              let to = v["to"]?.stringValue, isACEId(to), let c = v["content"]?.objectValue,
              let created = v["createdAt"]?.wireInt, let status = v["status"]?.stringValue.flatMap(OutboxStatus.init),
              let attempts = v["attempts"]?.wireInt, let next = v["nextAttemptAt"]?.wireInt, let refresh = v["refreshPrekey"]?.boolValue,
              let content = PrivateContent(stored: c) else {
            throw ACEError(.storageFailed, "\(key) is malformed")
        }
        self.init(messageId: id, to: to, content: content, createdAt: created)
        self.status = status
        self.attempts = attempts
        self.nextAttemptAt = next
        self.refreshPrekey = refresh
        self.code = try opt("code") { $0.stringValue }
        self.firstAttemptAt = try opt("firstAttemptAt") { $0.wireInt }
        self.lastPrekey = try opt("lastPrekey") { $0.stringValue }
        self.lastError = try opt("lastError") { $0.stringValue }
        self.expiredAt = try opt("expiredAt") { $0.wireInt }
        self.settledAt = try opt("settledAt") { $0.wireInt }
        self.inFlightUntil = try opt("inFlightUntil") { $0.wireInt }
    }

    mutating func settle(_ status: OutboxStatus, code: String?, at now: Int) {
        self.status = status
        self.code = code
        settledAt = now
    }
}

/// The durable Outbox (lock `outbox`). Concurrent attempts of one message never send twice, in this process or another
/// over the same store: an attempt takes a persisted lease (`inFlightUntil`, `inFlightSeconds`) under the lock before its
/// first suspension, and another attempt meanwhile returns the stored entry.
public actor Outbox {
    /// How long an attempt holds its entry (sdk-ts `IN_FLIGHT_SECONDS`); a crashed attempt's lease expires after it.
    public static let inFlightSeconds = 120
    /// Attempt errors that fail again on every retry: the entry ends as `rejected` with that code.
    private static let finalCodes: Set<ACEError.Code> = [.unknownPrekey, .invalidArgument, .invalidBody]

    private let identity: any ACEIdentity
    private let store: any ACEStore
    private let profiles: InstalledProfiles
    private let rules: [any ProfileRules]
    private let clock: @Sendable () -> Int

    public init(identity: any ACEIdentity, store: any ACEStore, profiles: InstalledProfiles, rules: [any ProfileRules] = [],
                clock: @escaping @Sendable () -> Int = systemClock) {
        self.identity = identity
        self.store = store
        self.profiles = profiles
        self.rules = rules
        self.clock = clock
    }

    private static func key(_ messageId: String) -> String { "outbox/\(messageId).json" }

    /// The delay after attempt `n` (1-based): `min(60 · 2^(n-1), 3600)`.
    public static func backoff(afterAttempt n: Int) -> Int { n >= 7 ? 3600 : min(60 << max(0, n - 1), 3600) }

    public func entry(_ messageId: String) throws -> OutboxEntry? {
        guard isMessageId(messageId) else { return nil }
        let key = Self.key(messageId)
        return try store.readJSON(key).map { try OutboxEntry($0, key: key) }
    }

    public func entries() throws -> [OutboxEntry] {
        // A corrupt entry is `storage_failed` (as in `entry`), never silently skipped.
        try store.checkedList("outbox/").compactMap { key in try store.readJSON(key).map { try OutboxEntry($0, key: key) } }
            .sorted { ($0.createdAt, $0.messageId) < ($1.createdAt, $1.messageId) }
    }

    private func save(_ e: OutboxEntry) throws { try store.checkedWrite(Self.key(e.messageId), try e.jsonValue.jsonData()) }

    /// The thread index of profile-ruled messages: the last such message staged to `to` on `threadId`.
    private static func threadKey(_ to: String, _ threadId: String) -> String {
        "outbox-threads/\(pairDigest(to, threadId)).json"
    }

    private func busyLocked(to peer: String, threadId: String) throws -> String? {
        let key = Self.threadKey(peer, threadId)
        guard let raw = try store.checkedRead(key) else { return nil }
        guard let id = JSONValue(stored: raw)?["messageId"]?.stringValue else { throw ACEError(.storageFailed, "\(key) is malformed") }
        guard let previous = try entry(id), previous.status == .pending, previous.to == peer else { return nil }
        return id
    }

    /// The thread `(peer, threadId)` is busy (08 § Sender state and busy threads): the ID of the governed message from this
    /// identity on it that is still pending (no receipt yet, not expired or abandoned), or nil.
    public func busy(to peer: String, threadId: String) throws -> String? {
        try store.withLock("outbox") { try busyLocked(to: peer, threadId: threadId) }
    }

    /// True when some installed rule governs `type`.
    public nonisolated func governs(_ type: String) -> Bool { rules.contains { $0.types.contains(type) } }

    private func event(_ e: OutboxEntry) -> ProfileEvent {
        ProfileEvent(direction: .send, from: identity.getACEId(), to: e.to, messageId: e.messageId, timestamp: e.createdAt, type: e.content.type,
                     threadId: e.content.threadId)
    }

    /// Stage a message of an installed `type` to `to`: schema (`unsupported_schema`, `invalid_body`), `thread_busy` while an
    /// earlier profile-ruled message to `to` on the same thread awaits its receipt, then the profile rules' `check` and the
    /// entry under lock `outbox`. The rules' `commit` runs when the `delivered` receipt arrives (a `rejected` or expired
    /// message changes no profile state). Receipts and contacts never enter the Outbox.
    /// `messageId` defaults to a fresh UUIDv4 (an existing entry's ID is `invalid_argument`).
    package func enqueue(to: String, type: String, body: [String: JSONValue], threadId: String? = nil,
                         messageId: String? = nil) throws -> OutboxEntry {
        guard isACEId(to), to != identity.getACEId() else { throw ACEError(.invalidArgument, "to must be another ACE ID") }
        if let messageId, !isMessageId(messageId) { throw ACEError(.invalidArgument, "messageId must be a lowercase UUIDv4") }
        guard type != CoreTypes.receipt, type != CoreTypes.contact else {
            throw ACEError(.invalidArgument, "receipts and contacts never enter the Outbox")
        }
        let content = try profiles.content(type: type, body: body, threadId: threadId)
        _ = try content.jsonData()
        let now = try unixNow(clock)
        let entry = OutboxEntry(messageId: messageId ?? UUID().uuidString.lowercased(), to: to, content: content, createdAt: now)
        let ev = event(entry)
        try store.withLock("outbox") {
            if messageId != nil, try self.entry(entry.messageId) != nil { throw ACEError(.invalidArgument, "messageId is already in the Outbox") }
            let indexed = governs(type) ? threadId : nil
            if let indexed, try busyLocked(to: to, threadId: indexed) != nil {
                throw ACEError(.threadBusy, "a message on this thread awaits its receipt")
            }
            try rules.check(ev, body: body)
            // The thread index first: a crash before the entry is written leaves an index that `busy` reads as free.
            if let indexed {
                try store.checkedWrite(Self.threadKey(to, indexed), try JSONValue.object(["messageId": .string(entry.messageId)]).jsonData())
            }
            try save(entry)
        }
        return entry
    }

    /// One attempt now, unless the message is final or another attempt holds its lease. Attempt failures are recorded on
    /// the entry and never thrown (a permanent one ends it as `rejected`); storage failures are.
    @discardableResult
    package func deliver(_ messageId: String, via transport: any PacketTransport) async throws -> OutboxEntry {
        let start = try unixNow(clock)
        let claimed: OutboxEntry? = try store.withLock("outbox") {
            guard var e = try entry(messageId) else { throw ACEError(.invalidArgument, "unknown Outbox message") }
            guard e.status == .pending, (e.inFlightUntil ?? 0) <= start else { return nil }
            if let first = e.firstAttemptAt, start - first > ACELimits.offlineWindowSeconds {
                e.status = .expired
                e.expiredAt = start
                try save(e)
                return nil
            }
            e.inFlightUntil = start + Self.inFlightSeconds
            try save(e)
            return e
        }
        guard var e = claimed else {
            guard let current = try entry(messageId) else { throw ACEError(.storageFailed, "Outbox entry vanished") }
            return current
        }
        let refreshAtStart = e.refreshPrekey
        var failure: ACEError?, posted: Prekey?
        do {
            // Every retry refreshes the descriptor (the peer may have lost its prekeys with its state); if that fails, a
            // cached one still unexpired and bound to the pins is used (06 § Outbox step 1).
            let retry = e.attempts > 0
            let prekey: Prekey
            if retry, !e.refreshPrekey, let fresh = try? await transport.prekey(for: e.to, refresh: true) {
                prekey = fresh
            } else {
                prekey = try await transport.prekey(for: e.to, refresh: e.refreshPrekey)
            }
            // The peer refused the prekey that is still its current one: final.
            if e.refreshPrekey, prekey.id == e.lastPrekey { throw ACEError(.unknownPrekey, "the peer refused its current prekey") }
            try await transport.post(to: e.to, content: e.content, messageId: e.messageId, prekey: prekey, retry: retry)
            posted = prekey
        } catch let err as ACEError {
            failure = err
        } catch {
            failure = ACEError(.relayUnavailable, "\(error)")
        }
        // A cancellation that stopped the post is not an attempt: release the lease and leave the entry as it was. One
        // after the post returned is recorded, since a receipt for it names that prekey.
        if posted == nil, Task.isCancelled {
            try store.withLock("outbox") {
                guard var current = try entry(messageId) else { return }
                current.inFlightUntil = nil
                try save(current)
            }
            throw CancellationError()
        }
        // The entry may have been changed by a receipt while this attempt was suspended: finished, or asked for a prekey
        // refresh (`rejected:unknown_prekey`), which must survive this save. Merged under lock `outbox`.
        let at = try unixNow(clock)
        return try store.withLock("outbox") {
            guard var current = try entry(messageId) else { return e }
            current.inFlightUntil = nil
            guard current.status == .pending else {
                try save(current)
                return current
            }
            e.inFlightUntil = nil
            e.attempts = current.attempts + 1
            e.firstAttemptAt = current.firstAttemptAt ?? start
            if let posted {
                // Recorded only once posted: a receipt for this attempt names this prekey (06 § Outbox).
                e.refreshPrekey = false
                e.lastPrekey = posted.id
                e.lastError = nil
            } else if let failure {
                e.lastError = "\(failure)"
            }
            if current.refreshPrekey && !refreshAtStart {
                // Keep the refused prekey, its code and the immediate retry.
                e.refreshPrekey = true
                e.lastPrekey = current.lastPrekey
                e.code = current.code
                e.nextAttemptAt = current.nextAttemptAt
            } else if let failure, Self.finalCodes.contains(failure.code) {
                e.settle(.rejected, code: failure.code.rawValue, at: at)
            } else {
                // A relay's Retry-After lengthens the wait, capped at the longest backoff.
                e.nextAttemptAt = at + min(max(Self.backoff(afterAttempt: e.attempts), failure?.retryAfterSeconds ?? 0), 3600)
            }
            try save(e)
            return e
        }
    }

    /// Attempt every pending message that is due (and expire those past the offline window).
    @discardableResult
    package func flush(via transport: any PacketTransport) async throws -> [OutboxEntry] {
        let now = try unixNow(clock)
        var out: [OutboxEntry] = []
        for e in try entries() where e.status == .pending && e.nextAttemptAt <= now {
            out.append(try await deliver(e.messageId, via: transport))
        }
        return out
    }

    /// Apply a receipt body from `from`. `delivered` / `rejected` finish a pending or expired entry (a late receipt settles
    /// an expired one: the recipient may have processed it), except `rejected:unknown_prekey`, which schedules an immediate
    /// attempt with a refreshed descriptor when its `prekey` is the latest attempt's (once, pending entries only). A receipt
    /// matching no pending or expired entry is ignored. Returns the updated entry.
    @discardableResult
    package func handleReceipt(from: String, body: [String: JSONValue]) throws -> OutboxEntry? {
        guard let id = body["messageId"]?.stringValue else { return nil }
        let now = try unixNow(clock)
        return try store.withLock("outbox") {
            guard var e = try entry(id), e.to == from, e.status == .pending || e.status == .expired else { return nil }
            let code = body["code"]?.stringValue
            switch body["outcome"]?.stringValue {
            case "delivered":
                e.settle(.delivered, code: nil, at: now)
                // The sender's profile state advances only now (06 § Outbox; 08 § Profile rules). A rule refusing the
                // commit (the thread moved on meanwhile) leaves the state; the message itself was delivered.
                do { try rules.commit(event(e), body: e.content.body) } catch let err as ACEError where err.category == .permanent {
                    e.lastError = "profile commit refused: \(err)"
                }
            case "rejected" where code == ACEError.Code.unknownPrekey.rawValue:
                // Counted only for the latest attempt's prekey, and once: a late or replayed receipt is ignored (L1).
                guard e.status == .pending, let prekey = body["prekey"]?.stringValue, prekey == e.lastPrekey, !e.refreshPrekey else { return nil }
                e.refreshPrekey = true
                e.code = code
                e.nextAttemptAt = now
            case "rejected":
                e.settle(.rejected, code: code, at: now)
            default:
                return nil
            }
            try save(e)
            return e
        }
    }

    /// Stop attempting a pending message locally: it becomes `expired` (outcome unknown; a late receipt still settles it).
    public func abandon(_ messageId: String) throws {
        let now = try unixNow(clock)
        try store.withLock("outbox") {
            guard var e = try entry(messageId), e.status == .pending else { return }
            e.status = .expired
            e.expiredAt = now
            try save(e)
        }
    }

    /// Delete entries settled (`delivered`, `rejected`) at least `OFFLINE_WINDOW_SECONDS` ago, and `expired` ones whose
    /// receipt can no longer arrive (expired at least `OFFLINE_WINDOW_SECONDS`, the relay's retention, ago). Returns the
    /// number deleted.
    @discardableResult
    public func prune() throws -> Int {
        let now = try unixNow(clock), window = ACELimits.offlineWindowSeconds
        return try store.withLock("outbox") {
            var n = 0
            for e in try entries() {
                let since: Int?
                switch e.status {
                case .delivered, .rejected: since = e.settledAt ?? 0
                case .expired: since = e.expiredAt ?? 0
                case .pending: since = nil
                }
                guard let since, now - since >= window else { continue }
                try store.checkedDelete(Self.key(e.messageId))
                n += 1
            }
            return n
        }
    }
}

/// The core message types (always installed, `ace:core:1`).
public enum CoreTypes {
    public static let receipt = "ace:receipt:1"
    public static let contact = "ace:contact:1"
}
