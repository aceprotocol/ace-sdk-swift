//
//  Identity.swift
//  ACE SDK
//
//  ACEIdentity on the key event log: a root (and pre-committed next root) that delegates an ml-dsa-65 signing key.
//  The KEL carries control and signing only. `KelIdentityCore` is the state machine shared by `SoftwareIdentity`
//  (seeds in memory) and `SecureEnclaveIdentity` (SecureEnclaveIdentity.swift). `checkUsable` is the
//  construct-time guard of every signing site.
//

import Foundation

/// What the SDK needs from an identity (software, Secure Enclave, HSM, ...).
///
/// `getKel()` and `getSigningSeq()` may throw (a Keychain-backed host identity can fail to read); `checkUsable`
/// reports any such throw as `identity_unavailable`.
public protocol ACEIdentity: Sendable {
    func getACEId() -> String
    /// The ML-DSA-65 public key of the delegated signing key.
    func getSigningPublicKey() -> Data
    /// The `seq` of the `dlg` event that delegated the signing key.
    func getSigningSeq() throws -> Int
    func getKel() throws -> [KelEvent]
    /// ML-DSA-65 with the current signing key over `message(seq)` (the complete `M` of 02 § Signatures), ctx =
    /// UTF-8(action), where `seq` is that key's delegation, read together with the key: a concurrent `delegate` can
    /// never pair one key's signature with another delegation's `seq`. Returns `(seq, signature)`.
    func sign(_ message: (Int) throws -> Data, action: String) throws -> (seq: Int, signature: Data)
}

/// An identity that holds its root and can extend its own log. Rotation is per key store (`SoftwareIdentity.rotate`,
/// `SecureEnclaveIdentity.rotate`): only a software identity can reveal a next root held outside it.
public protocol ACEManagedIdentity: ACEIdentity {
    func getState() -> KelState
    /// Delegate a fresh signing key, optionally expiring at `notAfter`.
    func delegate(now: Int?, notAfter: Int?) throws
}

/// An SDK identity whose log was verified in full when it was set (`KelIdentityCore`): `checkUsable` reads it instead of
/// verifying the log again. Verifying the same events at `t = max(now, ts of the last event)` gives the same state (only
/// the future bound `ts - window <= t` depends on the time, and every `ts <= t`).
package protocol HeldKelIdentity: ACEIdentity {
    var heldState: KelState { get }
}

package func checkNextDigest(_ nextRootDigest: Data?) throws -> Data? {
    if let d = nextRootDigest, d.count != 32 { throw ACEError(.invalidArgument, "nextRootDigest must be 32 bytes") }
    return nextRootDigest
}

/// `now` (wire-integer Unix seconds) or the system clock; anything else is `invalid_argument`.
package func identityNow(_ now: Int?) throws -> Int {
    guard let now else { return systemClock() }
    guard isWireInt(now) else { throw ACEError(.invalidArgument, "now must be an integer in [0, 2^53-1]") }
    return now
}

/// `key` is the next root `state` commits to, or `invalid_argument`.
package func checkCommitted(_ key: any ACEKeyProvider, _ state: KelState) throws {
    guard state.commits(to: key.publicKey()) else {
        throw ACEError(.invalidArgument, "nextRoot does not match the committed next root")
    }
}

/// The identity's verified log state, or `identity_unavailable` when it must not sign now.
///
/// The log is verified at `t = max(now, ts of its last event)`; the signing key must be live at `t` and be the one the
/// log delegates (key and `seq`). Any failure, including a provider throw, is `identity_unavailable`. A `now`
/// outside `[0, 2^53-1]` is `invalid_argument`.
public func checkUsable(_ identity: any ACEIdentity, now: Int) throws -> KelState {
    guard isWireInt(now) else { throw ACEError(.invalidArgument, "now must be an integer in [0, 2^53-1]") }
    let state: KelState, t: Int, pk: Data, seq: Int
    do {
        let held = (identity as? any HeldKelIdentity)?.heldState
        let kel = try held?.events ?? identity.getKel()
        let last = kel.last.flatMap { wireInt($0["ts"]) }
        t = last.map { max(now, $0) } ?? now
        state = try held ?? ACEKel.verify(kel, now: t)
        pk = identity.getSigningPublicKey()
        seq = try identity.getSigningSeq()
    } catch let e as ACEError {
        throw ACEError(.identityUnavailable, "identity kel does not verify: \(e.message)")
    } catch {
        throw ACEError(.identityUnavailable, "identity unavailable: \(type(of: error))")
    }
    guard ACEKel.isUsable(state, now: t) else {
        throw ACEError(.identityUnavailable, "signing delegation missing or expired")
    }
    guard let s = state.signing, s.publicKey == pk, s.seq == seq else {
        throw ACEError(.identityUnavailable, "identity signing key or seq does not match its kel")
    }
    return state
}

/// The KEL state machine of an identity, generic over where its keys live. Every extension of the log is built and
/// verified in full before any field changes (all-or-nothing).
package final class KelIdentityCore<Key: ACEKeyProvider>: @unchecked Sendable {
    package typealias MakeKey = () throws -> Key

    private let lock = NSLock()
    package var root: Key
    package var nextRoot: Key?
    package var signing: Key
    /// The verified log; `state.events` is the KEL.
    package var state: KelState
    private let makeKey: MakeKey

    package init(root: Key, nextRoot: Key?, signing: Key, kel: [KelEvent], now: Int, makeKey: @escaping MakeKey) throws {
        let state = try ACEKel.verify(kel, now: now)
        guard state.rootPublicKey == root.publicKey() else { throw ACEError(.invalidArgument, "root key does not match the kel") }
        if let nextRoot, !state.commits(to: nextRoot.publicKey()) {
            throw ACEError(.invalidArgument, "next root key does not match the commitment")
        }
        guard let s = state.signing else { throw ACEError(.invalidKel, "kel has no signing delegation") }
        guard s.publicKey == signing.publicKey() else { throw ACEError(.invalidArgument, "signing key does not match the kel") }
        self.root = root
        self.nextRoot = nextRoot
        self.signing = signing
        self.state = state
        self.makeKey = makeKey
    }

    /// Inception, then the signing delegation, both at `now`.
    package static func generate(nextRootDigest: Data?, now: Int?, makeKey: @escaping MakeKey) throws -> KelIdentityCore {
        let digestIn = try checkNextDigest(nextRootDigest)
        let ts = try identityNow(now)
        let root = try makeKey(), signing = try makeKey()
        let (nextRoot, digest) = try newNextRoot(digestIn, current: root, events: [], makeKey: makeKey)
        let icp = try ACEKel.createInception(root: root, nextDigest: digest, ts: ts)
        let st = try ACEKel.verify([icp], now: ts)
        let d1 = try ACEKel.createDelegation(state: st, root: root, keyPublic: signing.publicKey(), ts: ts)
        return try KelIdentityCore(root: root, nextRoot: nextRoot, signing: signing, kel: [icp, d1], now: ts, makeKey: makeKey)
    }

    /// From a verified log and its committed next root (held outside the lost device), fork the log at the start of
    /// the current root epoch (its last `icp`/`rot`; later events, possibly a thief's, are dropped) and append `rot`
    /// (signed by `nextRoot` alone), then `dlg` of a fresh signing key, all dated `max(now, ts of the epoch start)`.
    package static func recover(kel: [KelEvent], nextRoot: Key, now: Int?, nextRootDigest: Data?,
                                makeKey: @escaping MakeKey) throws -> KelIdentityCore {
        let digestIn = try checkNextDigest(nextRootDigest)
        let nowTs = try identityNow(now)
        let full = try ACEKel.verify(kel, now: nowTs)
        let start = full.events.lastIndex { $0["t"] == .string("icp") || $0["t"] == .string("rot") } ?? 0
        let events = Array(full.events[...start])
        let ts = max(nowTs, events[start]["ts"]?.intValue ?? nowTs)
        let state = try ACEKel.verify(events, now: ts)
        try checkCommitted(nextRoot, state)
        let (newNext, digest) = try newNextRoot(digestIn, current: nextRoot, events: events, makeKey: makeKey)
        let signing = try makeKey()
        var st = try appended(state, try ACEKel.createRotation(state: state, newRoot: nextRoot, nextDigest: digest, ts: ts), ts)
        st = try appended(st, try ACEKel.createDelegation(state: st, root: nextRoot, keyPublic: signing.publicKey(), ts: ts), ts)
        return try KelIdentityCore(root: nextRoot, nextRoot: newNext, signing: signing, kel: st.events, now: ts, makeKey: makeKey)
    }

    /// The next root to commit (generated, none held when `digestIn` is given) and its digest. Committing any current
    /// or past root, each possibly exposed, is refused (pre-rotation).
    package static func newNextRoot(_ digestIn: Data?, current: Key, events: [KelEvent], makeKey: MakeKey) throws -> (key: Key?, digest: Data) {
        let next: Key?, digest: Data
        if let digestIn {
            (next, digest) = (nil, digestIn)
        } else {
            let k = try makeKey()
            (next, digest) = (k, keyDigest(publicKey: k.publicKey()))
        }
        var roots: Set<Data> = [keyDigest(publicKey: current.publicKey())]
        for ev in events where ev["t"] == "icp" || ev["t"] == "rot" {
            roots.insert(keyDigest(publicKey: try ACEKel.keyBytes(ev["root"], "root").publicKey))
        }
        guard !roots.contains(digest) else {
            throw ACEError(.invalidArgument, "the next root must differ from every current or past root")
        }
        return (next, digest)
    }

    package func withLock<T>(_ body: (KelIdentityCore) throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body(self)
    }

    package var aceId: String { withLock { $0.state.aceId } }
    package var signingPublicKey: Data { withLock { $0.signing.publicKey() } }
    package var currentKel: [KelEvent] { withLock { $0.state.events } }
    package var currentState: KelState { withLock { $0.state } }

    package func signingSeq() throws -> Int {
        guard let s = currentState.signing else { throw ACEError(.identityUnavailable, "no signing delegation") }
        return s.seq
    }

    /// The signing key and its `seq` are read in one lock section; the signature is made outside the lock (a Secure
    /// Enclave signature takes milliseconds).
    package func sign(_ message: (Int) throws -> Data, action: String) throws -> (seq: Int, signature: Data) {
        let (key, seq) = try withLock { c -> (Key, Int) in
            guard let seq = c.state.signing?.seq else { throw ACEError(.identityUnavailable, "no signing delegation") }
            return (c.signing, seq)
        }
        return (seq, try key.sign(try message(seq), action: action))
    }

    /// `state.events + [event]` verified at `now`, or the error; nothing changes here.
    private static func appended(_ state: KelState, _ event: KelEvent, _ now: Int) throws -> KelState {
        try ACEKel.verify(state.events + [event], now: now)
    }

    /// rot, then dlg of the same signing key. `revealed` is a committed next root held outside the identity; only
    /// `SoftwareIdentity` passes one.
    package func rotate(now: Int?, nextRootDigest: Data?, revealed: Key? = nil) throws {
        try withLock { c in
            let next: Key
            if let revealed {
                guard c.nextRoot == nil else { throw ACEError(.invalidArgument, "the next root key is held by this identity") }
                try checkCommitted(revealed, c.state)
                next = revealed
            } else if let held = c.nextRoot {
                next = held
            } else {
                throw ACEError(.invalidArgument, "the next root key is not held by this identity")
            }
            let digestIn = try checkNextDigest(nextRootDigest)
            let ts = try identityNow(now)
            let (newNext, digest) = try Self.newNextRoot(digestIn, current: next, events: c.state.events, makeKey: c.makeKey)
            var st = try Self.appended(c.state, try ACEKel.createRotation(state: c.state, newRoot: next, nextDigest: digest, ts: ts), ts)
            st = try Self.appended(st, try ACEKel.createDelegation(state: st, root: next, keyPublic: c.signing.publicKey(), ts: ts), ts)
            c.state = st
            c.root = next
            c.nextRoot = newNext
        }
    }

    /// A fresh signing key delegated by the root.
    package func delegate(now: Int?, notAfter: Int?) throws {
        try withLock { c in
            let ts = try identityNow(now)
            let key = try c.makeKey()
            let ev = try ACEKel.createDelegation(state: c.state, root: c.root, keyPublic: key.publicKey(), ts: ts, notAfter: notAfter)
            c.state = try Self.appended(c.state, ev, ts)
            c.signing = key
        }
    }
}

// MARK: - Export JSON

/// Strict member readers for identity exports (never a raw parse error).
package enum ExportJSON {
    package static func object(_ data: Data) throws -> [String: JSONValue] {
        guard let o = (try? JSONValue(json: data))?.objectValue else { throw ACEError(.invalidArgument, "export must be a JSON object") }
        return o
    }

    package static func kel(_ o: [String: JSONValue]) throws -> [KelEvent] {
        guard let items = o["kel"]?.arrayValue, !items.isEmpty else { throw ACEError(.invalidKel, "export.kel must be a non-empty array") }
        return try items.map {
            guard let e = $0.objectValue else { throw ACEError(.invalidKel, "export.kel must hold event objects") }
            return e
        }
    }

    package static func string(_ o: [String: JSONValue], _ key: String) throws -> String {
        guard let s = o[key]?.stringValue else { throw ACEError(.invalidArgument, "\(key) must be a string") }
        return s
    }

    /// Absent → nil; present → must be a string.
    package static func optionalString(_ o: [String: JSONValue], _ key: String) throws -> String? {
        o[key] == nil ? nil : try string(o, key)
    }

    package static func kelValue(_ kel: [KelEvent]) -> JSONValue { .array(kel.map { .object($0) }) }
}

// MARK: - SoftwareIdentity

/// Exported key material of a `SoftwareIdentity`: root, next root and signing seeds (Base64) and the KEL.
/// `nextRootSeed` is absent when the next root is held elsewhere. Handle with extreme care.
public struct SoftwareIdentityExport: Sendable, Equatable {
    public var rootSeed: String
    public var nextRootSeed: String?
    public var signingSeed: String
    public var kel: [KelEvent]

    public init(rootSeed: String, nextRootSeed: String? = nil, signingSeed: String, kel: [KelEvent]) {
        self.rootSeed = rootSeed
        self.nextRootSeed = nextRootSeed
        self.signingSeed = signingSeed
        self.kel = kel
    }

    /// Not an object, or a missing or non-string seed → `invalid_argument`; a bad `kel` → `invalid_kel`. Unknown members
    /// are ignored.
    public init(json: Data) throws {
        let o = try ExportJSON.object(json)
        kel = try ExportJSON.kel(o)
        rootSeed = try ExportJSON.string(o, "rootSeed")
        nextRootSeed = try ExportJSON.optionalString(o, "nextRootSeed")
        signingSeed = try ExportJSON.string(o, "signingSeed")
    }

    /// Canonical JSON.
    public func jsonData() throws -> Data {
        var o: [String: JSONValue] = ["rootSeed": .string(rootSeed), "signingSeed": .string(signingSeed), "kel": ExportJSON.kelValue(kel)]
        if let nextRootSeed { o["nextRootSeed"] = .string(nextRootSeed) }
        return try JSONValue.object(o).jsonData()
    }
}

/// Root, next root and signing key in process memory, plus the KEL. Use a `SecureEnclaveIdentity` or another
/// hardware-backed `ACEIdentity` for high-value deployments.
public final class SoftwareIdentity: ACEManagedIdentity, HeldKelIdentity, @unchecked Sendable {
    package let core: KelIdentityCore<SoftwareKey>

    private init(core: KelIdentityCore<SoftwareKey>) { self.core = core }

    package init(root: SoftwareKey, nextRoot: SoftwareKey?, signing: SoftwareKey, kel: [KelEvent], now: Int) throws {
        core = try KelIdentityCore(root: root, nextRoot: nextRoot, signing: signing, kel: kel, now: now, makeKey: SoftwareKey.generate)
    }

    /// A new identity: root, next root (generated, unless `nextRootDigest` commits to a root held elsewhere) and signing
    /// key, delegated at `now`.
    public static func generate(nextRootDigest: Data? = nil, now: Int? = nil) throws -> SoftwareIdentity {
        SoftwareIdentity(core: try .generate(nextRootDigest: nextRootDigest, now: now, makeKey: SoftwareKey.generate))
    }

    /// Recover an identity whose keys are lost or stolen from its log and the committed next root held outside the lost
    /// device. Appends `rot` (signed by `nextRoot` alone) and `dlg` of a fresh signing key.
    public static func recover(kel: [KelEvent], nextRoot: SoftwareKey, now: Int? = nil, nextRootDigest: Data? = nil) throws -> SoftwareIdentity {
        SoftwareIdentity(core: try .recover(kel: kel, nextRoot: nextRoot, now: now, nextRootDigest: nextRootDigest, makeKey: SoftwareKey.generate))
    }

    /// Import an export (`invalid_kel` when the log does not verify at `now`, `invalid_argument` when a seed is
    /// malformed or does not match the log).
    public convenience init(export: SoftwareIdentityExport, now: Int? = nil) throws {
        func key(_ text: String, _ what: String) throws -> SoftwareKey {
            try SoftwareKey(seed: decodeB64(text, code: .invalidArgument, what: what))
        }
        try self.init(root: key(export.rootSeed, "rootSeed"), nextRoot: export.nextRootSeed.map { try key($0, "nextRootSeed") },
                      signing: key(export.signingSeed, "signingSeed"), kel: export.kel, now: try identityNow(now))
    }

    /// Export private key material. Handle with extreme care.
    public func exportPrivateKey() -> SoftwareIdentityExport {
        core.withLock { c in
            SoftwareIdentityExport(rootSeed: ACEBase64.encode(c.root.seed), nextRootSeed: c.nextRoot.map { ACEBase64.encode($0.seed) },
                                   signingSeed: ACEBase64.encode(c.signing.seed), kel: c.state.events)
        }
    }

    // MARK: ACEIdentity

    public func getACEId() -> String { core.aceId }
    public func getSigningPublicKey() -> Data { core.signingPublicKey }
    public func getSigningSeq() throws -> Int { try core.signingSeq() }
    public func getKel() throws -> [KelEvent] { core.currentKel }
    public func sign(_ message: (Int) throws -> Data, action: String) throws -> (seq: Int, signature: Data) {
        try core.sign(message, action: action)
    }
    package var heldState: KelState { core.currentState }

    // MARK: ACEManagedIdentity

    public func getState() -> KelState { core.currentState }

    /// Reveal the committed next root (the held one, or `nextRoot` when it is held outside this identity) and commit a
    /// new one (`nextRootDigest` of a root held elsewhere, or a generated one; any current or past root is
    /// `invalid_argument`), then re-delegate the signing key. The `rot` is signed by the revealed root alone.
    public func rotate(now: Int? = nil, nextRootDigest: Data? = nil, nextRoot: SoftwareKey? = nil) throws {
        try core.rotate(now: now, nextRootDigest: nextRootDigest, revealed: nextRoot)
    }

    public func delegate(now: Int? = nil, notAfter: Int? = nil) throws {
        try core.delegate(now: now, notAfter: notAfter)
    }
}

/// `print`, `dump` and string interpolation never show the seeds.
extension SoftwareIdentity: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "SoftwareIdentity(\(getACEId()))" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["aceId": getACEId()], displayStyle: .class) }
}

/// `print`, `dump` and string interpolation never show the seeds.
extension SoftwareIdentityExport: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "SoftwareIdentityExport(seeds: <redacted>, kel: \(kel.count) events)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["kelEvents": kel.count], displayStyle: .struct) }
}
