//
//  Kel.swift
//  ACE SDK
//
//  Key event log: inception, rotation, signing delegation. ACE ID = SHA-256 of the inception bytes. The KEL carries
//  control and signing only; encryption keys are prekeys published in the descriptor.
//

import Foundation

/// One KEL event in its wire shape (integers are `JSONValue.number`).
public typealias KelEvent = [String: JSONValue]

/// The ML-DSA-65 signing key delegated by a `dlg` event at `seq`.
public struct DelegatedKey: Sendable, Equatable, Hashable {
    public let publicKey: Data
    public let seq: Int
    public let notAfter: Int?
}

/// The verified state of a key event log.
public struct KelState: Sendable, Equatable, Hashable {
    public let aceId: String
    public let seq: Int
    public let lastHash: String
    public let rootPublicKey: Data
    public let next: String
    public let signing: DelegatedKey?
    /// The verified events, owned by the state. Excluded from `==` / `hash` (`lastHash` already commits to them).
    public let events: [KelEvent]

    public static func == (a: KelState, b: KelState) -> Bool {
        a.aceId == b.aceId && a.seq == b.seq && a.lastHash == b.lastHash && a.rootPublicKey == b.rootPublicKey && a.next == b.next && a.signing == b.signing
    }

    public func hash(into h: inout Hasher) {
        h.combine(aceId); h.combine(seq); h.combine(lastHash); h.combine(rootPublicKey); h.combine(next); h.combine(signing)
    }

    /// The pre-rotation commitment: `next` is `hex(keyDigest(publicKey))`.
    package func commits(to publicKey: Data) -> Bool { hexEncode(keyDigest(publicKey: publicKey)) == next }

    /// The number of `rot` events: the index n of the current root key(n) (key(0) incepts).
    public var rotationCount: Int { events.filter { $0["t"] == .string("rot") }.count }
}

/// How `ACEKel.extend` treated a candidate log against the pinned one.
public enum ExtendOutcome: String, Sendable {
    case adopted, unchanged, extended, recovered
}

public enum ACEKel {
    package static let keys: [String: Set<String>] = [
        "icp": ["t", "seq", "ts", "root", "next", "sig"],
        "rot": ["t", "seq", "ts", "prev", "root", "next", "sig"],
        "dlg": ["t", "seq", "ts", "prev", "key", "sig"],
    ]

    package static func bad(_ msg: String) -> ACEError { ACEError(.invalidKel, msg) }

    package static func keyBytes(_ obj: JSONValue?, _ what: String) throws -> (scheme: String, publicKey: Data) {
        guard case .object(let o)? = obj, Set(o.keys) == ["scheme", "publicKey"] else {
            throw bad("\(what) must be {scheme, publicKey}")
        }
        guard case .string(let scheme)? = o["scheme"] else { throw bad("\(what).scheme must be a string") }
        guard case .string(let text)? = o["publicKey"] else { throw bad("\(what).publicKey must be a Base64 string") }
        return (scheme, try decodeB64(text, code: .invalidKel, what: "\(what).publicKey"))
    }

    /// `{scheme: ml-dsa-65, publicKey}`: the inverse of `keyBytes`.
    package static func keyValue(_ publicKey: Data) -> JSONValue {
        ["scheme": .string(SigningScheme.mlDsa65.rawValue), "publicKey": .string(ACEBase64.encode(publicKey))]
    }

    /// The bytes of a 64-lowercase-hex member, or `invalid_kel`.
    package static func sha256HexBytes(_ v: JSONValue?, _ what: String) throws -> Data {
        guard case .string(let s)? = v, isSHA256Hex(s), let d = hexDecode(s) else { throw bad("\(what) must be 64 lowercase hex") }
        return d
    }

    /// Canonical bytes (signatures excluded). Shape errors are `invalid_kel`.
    public static func eventBytes(_ event: KelEvent) throws -> Data {
        guard case .string(let t)? = event["t"], let members = keys[t] else { throw bad("event must be icp, rot or dlg") }
        let allowed = t == "dlg" ? members.union(["notAfter"]) : members
        let required = members.subtracting(["sig"])  // signatures are not part of the canonical bytes
        let present = Set(event.keys)
        guard present.isSubset(of: allowed), required.isSubset(of: present) else { throw bad("\(t) has unknown or missing members") }
        guard let seq = wireInt(event["seq"]), let ts = wireInt(event["ts"]) else { throw bad("seq and ts must be wire integers") }
        if t == "icp" {
            let (scheme, pk) = try keyBytes(event["root"], "root")
            let next = try sha256HexBytes(event["next"], "next")
            return ACESigning.encodePayload([
                .string("icp"), .string(decimal(seq)), .string(decimal(ts)), .string(scheme), .data(pk), .data(next),
            ])
        }
        guard case .string(let prev)? = event["prev"], isSHA256Hex(prev) else { throw bad("prev must be 64 lowercase hex") }
        if t == "rot" {
            let (scheme, pk) = try keyBytes(event["root"], "root")
            let next = try sha256HexBytes(event["next"], "next")
            return ACESigning.encodePayload([
                .string("rot"), .string(decimal(seq)), .string(decimal(ts)), .string(prev), .string(scheme), .data(pk), .data(next),
            ])
        }
        let (scheme, pk) = try keyBytes(event["key"], "key")
        var na = ""
        if let v = event["notAfter"] {
            guard let n = wireInt(v) else { throw bad("notAfter must be a wire integer") }
            na = decimal(n)
        }
        return ACESigning.encodePayload([
            .string("dlg"), .string(decimal(seq)), .string(decimal(ts)), .string(prev), .string(scheme), .data(pk),
            .string(na),
        ])
    }

    /// `ace:sha256:` + hex(SHA-256(inception event bytes)).
    public static func computeACEId(inceptionBytes: Data) -> String { "ace:sha256:" + sha256Hex(inceptionBytes) }

    /// `{scheme, value}`: action `kel` over `M(aceId, ts, "", eventBytes)`.
    package static func sig(_ provider: any ACEKeyProvider, _ aceId: String, _ ts: Int, _ eb: Data) throws -> JSONValue {
        let s = try provider.sign(try ACESigning.message(aceId: aceId, timestamp: ts, seq: nil, payload: eb), action: "kel")
        return ["scheme": .string(SigningScheme.mlDsa65.rawValue), "value": .string(ACEBase64.encode(s))]
    }

    package static func checkSig(
        _ sig: JSONValue?, _ aceId: String, _ ts: Int, _ eb: Data, _ pk: Data, _ who: String
    ) throws {
        guard case .object(let o)? = sig, Set(o.keys) == ["scheme", "value"], o["scheme"] == .string(SigningScheme.mlDsa65.rawValue) else {
            throw bad("\(who) signature must be {scheme: ml-dsa-65, value}")
        }
        guard case .string(let text)? = o["value"] else {
            throw ACEError(.invalidSignature, "\(who) signature must be a Base64 string")
        }
        let raw = try decodeB64(text, code: .invalidSignature, what: "\(who) signature")
        let m = try ACESigning.message(aceId: aceId, timestamp: ts, seq: nil, payload: eb)
        guard ACESigning.verifySignature(message: m, action: "kel", signature: raw, publicKey: pk) else {
            throw ACEError(.invalidSignature, "\(who) signature does not verify")
        }
    }

    public static func createInception(root: any ACEKeyProvider, nextDigest: Data, ts: Int) throws -> KelEvent {
        var ev: KelEvent = [
            "t": "icp",
            "seq": 0,
            "ts": .number(Double(ts)),
            "root": keyValue(root.publicKey()),
            "next": .string(hexEncode(nextDigest)),
        ]
        let eb = try eventBytes(ev)
        ev["sig"] = try sig(root, computeACEId(inceptionBytes: eb), ts, eb)
        return ev
    }

    /// `rot` revealing the committed `newRoot`, signed by it alone (pre-rotation).
    public static func createRotation(state: KelState, newRoot: any ACEKeyProvider, nextDigest: Data, ts: Int) throws -> KelEvent {
        guard state.commits(to: newRoot.publicKey()) else {
            throw bad("new root does not match the committed next digest")
        }
        var ev: KelEvent = [
            "t": "rot",
            "seq": .number(Double(state.seq + 1)),
            "ts": .number(Double(ts)),
            "prev": .string(state.lastHash),
            "root": keyValue(newRoot.publicKey()),
            "next": .string(hexEncode(nextDigest)),
        ]
        let eb = try eventBytes(ev)
        ev["sig"] = try sig(newRoot, state.aceId, ts, eb)
        return ev
    }

    /// `dlg` delegating the ML-DSA-65 signing key `keyPublic`, signed by the current root.
    public static func createDelegation(
        state: KelState, root: any ACEKeyProvider, keyPublic: Data, ts: Int, notAfter: Int? = nil
    ) throws -> KelEvent {
        if let notAfter {
            let (span, overflow) = notAfter.subtractingReportingOverflow(ts)
            guard notAfter > ts, !overflow, span <= ACELimits.maxSigningKeyLifetime else { throw bad("notAfter must be in (ts, ts + MAX_SIGNING_KEY_LIFETIME]") }
        }
        var ev: KelEvent = [
            "t": "dlg",
            "seq": .number(Double(state.seq + 1)),
            "ts": .number(Double(ts)),
            "prev": .string(state.lastHash),
            "key": keyValue(keyPublic),
        ]
        if let notAfter { ev["notAfter"] = .number(Double(notAfter)) }
        let eb = try eventBytes(ev)
        ev["sig"] = try sig(root, state.aceId, ts, eb)
        return ev
    }

    /// Verify a KEL at `now` (01 § Verifier rules). Verified states are cached by their prefix key (05 § Receiver
    /// admission): verification is a pure function of the log and `now`, and only the future bound
    /// `ts <= now + TIMESTAMP_WINDOW_SECONDS` depends on `now`, so a hit re-checks that bound alone and costs no signature
    /// verification. A log extending a cached one (a pin plus new events) re-checks the whole structure but verifies only
    /// the new events' signatures. Only a log usable at `now` is cached: an unusable one can authenticate nothing, so
    /// caching it would only let a sender fill the cache.
    public static func verify(_ events: [KelEvent], now: Int) throws -> KelState {
        let prefixes = prefixKeys(events)
        var resume: KelState?
        if let keys = prefixes?.keys {
            if let hit = VerifiedKelCache.shared.get(keys[keys.count - 1]), hit.lastTs <= now + ACELimits.timestampWindowSeconds { return hit.state }
            for k in keys.dropLast().reversed() {
                if let hit = VerifiedKelCache.shared.get(k) { resume = hit.state; break }
            }
        }
        let state = try verifyUncached(events, now: now, resume: resume)
        if let (keys, bytes) = prefixes, isUsable(state, now: now) {
            VerifiedKelCache.shared.put(keys[keys.count - 1], state: state, lastTs: events.last.flatMap { wireInt($0["ts"]) } ?? 0, bytes: bytes)
        }
        return state
    }

    /// Chained content keys: `keys[i]` is the SHA-256 over `keys[i-1]` and the canonical JSON of event `i` (its `sig`
    /// included), so it identifies the exact prefix `events[0...i]`; `bytes` is the size of that canonical JSON. Nil for
    /// an empty or oversized log.
    static func prefixKeys(_ events: [KelEvent]) -> (keys: [String], bytes: Int)? {
        guard (1...ACELimits.maxKelEvents).contains(events.count) else { return nil }
        var keys: [String] = [], bytes = 0
        keys.reserveCapacity(events.count)
        for ev in events {
            guard let d = try? JSONValue.object(ev).jsonData() else { return nil }
            keys.append(sha256Hex(Data((keys.last ?? "").utf8) + d))
            bytes += d.count
        }
        return (keys, bytes)
    }

    /// `resume`: a verified state of a prefix of `events` (same content, signatures included); its signatures are not
    /// checked again.
    private static func verifyUncached(_ events: [KelEvent], now: Int, resume: KelState? = nil) throws -> KelState {
        guard !events.isEmpty else { throw bad("kel must be a non-empty array") }
        guard events.count <= ACELimits.maxKelEvents else { throw bad("kel exceeds \(ACELimits.maxKelEvents) events") }
        guard events[0]["t"] == .string("icp") else { throw bad("kel must start with icp") }
        var eb = try eventBytes(events[0])
        let aceId = computeACEId(inceptionBytes: eb)
        let (rootSchemeName, rootPk) = try keyBytes(events[0]["root"], "root")
        guard ACESigning.isValidSigningPublicKey(rootSchemeName, rootPk) else { throw bad("root key must be ml-dsa-65") }
        let icpNext = events[0]["next"]?.stringValue ?? ""  // validated by eventBytes
        var state = resume ?? KelState(aceId: aceId, seq: 0, lastHash: sha256Hex(eb), rootPublicKey: rootPk,
                                       next: icpNext, signing: nil, events: [])
        let first = resume?.events.count ?? 0
        // Rule 1: the whole log's structure before any signature.
        var bytes: [Data] = []
        var prevTs = -1, prevHash = ""
        for (i, ev) in events.enumerated() {
            eb = try eventBytes(ev)
            let t = ev["t"]?.stringValue ?? ""  // validated by eventBytes
            guard let members = keys[t], members.isSubset(of: Set(ev.keys)) else { throw bad("event \(i): missing signature") }
            guard case .object(let sg)? = ev["sig"], Set(sg.keys) == ["scheme", "value"], sg["scheme"]?.stringValue != nil,
                  case .string(let sv)? = sg["value"] else { throw bad("event \(i): sig must be {scheme, value}") }
            _ = try decodeB64(sv, code: .invalidKel, what: "event \(i) sig.value")
            guard let seq = wireInt(ev["seq"]), let ts = wireInt(ev["ts"]),
                  seq == i, ts >= prevTs, ts - ACELimits.timestampWindowSeconds <= now else {
                throw bad("event \(i): bad seq or ts")
            }
            if i > 0 && t == "icp" { throw bad("event \(i): icp only at seq 0") }
            if i > 0 && ev["prev"] != .string(prevHash) { throw bad("event \(i): prev does not match") }
            prevTs = ts
            prevHash = sha256Hex(eb)
            bytes.append(eb)
        }
        for (i, ev) in events.enumerated() where i >= first {
            eb = bytes[i]
            let t = ev["t"]?.stringValue ?? ""
            let ts = wireInt(ev["ts"]) ?? 0
            var signing = state.signing
            let newRoot: (publicKey: Data, next: String)
            if t == "icp" {
                try checkSig(ev["sig"], aceId, ts, eb, rootPk, "icp")
                newRoot = (rootPk, ev["next"]?.stringValue ?? "")
            } else if t == "rot" {
                let (scheme, pk) = try keyBytes(ev["root"], "root")
                guard ACESigning.isValidSigningPublicKey(scheme, pk) else { throw bad("event \(i): root key must be ml-dsa-65") }
                guard state.commits(to: pk) else {
                    throw bad("event \(i): revealed root does not match commitment")
                }
                try checkSig(ev["sig"], aceId, ts, eb, pk, "rot")  // the revealed root alone
                newRoot = (pk, ev["next"]?.stringValue ?? "")
                signing = nil
            } else {
                try checkSig(ev["sig"], aceId, ts, eb, state.rootPublicKey, "dlg")
                let (scheme, pk) = try keyBytes(ev["key"], "key")
                let na = ev["notAfter"].flatMap(wireInt)  // present means a wire integer (eventBytes)
                if let na, !(ts < na && na <= ts + ACELimits.maxSigningKeyLifetime) { throw bad("event \(i): notAfter out of range") }
                guard ACESigning.isValidSigningPublicKey(scheme, pk) else {
                    throw bad("event \(i): signing key must be ml-dsa-65")
                }
                signing = DelegatedKey(publicKey: pk, seq: i, notAfter: na)
                newRoot = (state.rootPublicKey, state.next)
            }
            state = KelState(aceId: aceId, seq: i, lastHash: sha256Hex(eb), rootPublicKey: newRoot.publicKey,
                             next: newRoot.next, signing: signing, events: [])
        }
        return KelState(aceId: aceId, seq: state.seq, lastHash: state.lastHash, rootPublicKey: state.rootPublicKey, next: state.next, signing: state.signing, events: events)
    }

    /// A signing key is delegated and, when it has a `notAfter`, `now < notAfter`.
    public static func isUsable(_ state: KelState, now: Int) -> Bool {
        guard let k = state.signing else { return false }
        return k.notAfter.map { now < $0 } ?? true
    }

    /// Adopt, keep or advance a pinned log (01 § Verifier rules, rule 6).
    public static func extend(pinned: KelState?, events: [KelEvent], now: Int) throws -> (state: KelState, outcome: ExtendOutcome) {
        try extend(pinned: pinned, verified: try verify(events, now: now))
    }

    /// `extend` of a candidate already returned by `verify`.
    package static func extend(pinned: KelState?, verified cand: KelState) throws -> (state: KelState, outcome: ExtendOutcome) {
        guard let pinned else { return (cand, .adopted) }
        guard cand.aceId == pinned.aceId else { throw ACEError(.kelConflict, "candidate names a different identity") }
        let ph = try pinned.events.map { sha256Hex(try eventBytes($0)) }
        let ch = try cand.events.map { sha256Hex(try eventBytes($0)) }
        for k in 0..<min(ph.count, ch.count) where ph[k] != ch[k] {
            // a rot supersedes the pinned events from the fork point only when none of them is a rot:
            // otherwise a holder of a revealed root could re-reveal it (01 rule 6)
            if cand.events[k]["t"] == .string("rot") && !pinned.events[k...].contains(where: { $0["t"] == .string("rot") }) {
                return (cand, .recovered)
            }
            throw ACEError(.kelConflict, "conflicting event at seq \(k)")
        }
        if ch.count > ph.count { return (cand, .extended) }
        return (pinned, .unchanged)
    }
}

/// A bounded, process-wide memo of verified KELs (see `ACEKel.verify`): at most `capacity` logs and `budget` bytes of
/// their canonical JSON, the oldest evicted first.
package final class VerifiedKelCache: @unchecked Sendable {
    static let shared = VerifiedKelCache(capacity: 256, budget: 16 << 20)
    private let capacity: Int, budget: Int
    private let lock = NSLock()
    private var entries: [String: (state: KelState, lastTs: Int, bytes: Int)] = [:]
    private var order: [String] = []
    private var total = 0

    package init(capacity: Int, budget: Int) {
        self.capacity = capacity
        self.budget = budget
    }

    /// The number of cached logs and their bytes.
    package var usage: (count: Int, bytes: Int) { lock.withLock { (entries.count, total) } }

    func get(_ key: String) -> (state: KelState, lastTs: Int)? {
        lock.lock(); defer { lock.unlock() }
        return entries[key].map { ($0.state, $0.lastTs) }
    }

    /// A log larger than the whole budget is not cached.
    package func put(_ key: String, state: KelState, lastTs: Int, bytes: Int) {
        lock.lock(); defer { lock.unlock() }
        guard bytes <= budget else { return }
        if let old = entries[key] { total -= old.bytes } else { order.append(key) }
        entries[key] = (state, lastTs, bytes)
        total += bytes
        while order.count > capacity || total > budget {
            total -= entries.removeValue(forKey: order.removeFirst())?.bytes ?? 0
        }
    }
}
