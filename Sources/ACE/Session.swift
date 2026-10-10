import Foundation
import Darwin

/// Trusted local binding to the common Rust MLS engine. Enrollment authentication is the host's job.
public protocol MLSEngine: Sendable {
    func execute(_ command: Data) throws -> Data
}

/// An engine that owns native resources. `openSecureMailbox` frees it at the mailbox's `close()`.
public protocol ClosableMLSEngine: MLSEngine {
    /// Idempotent; close every context first.
    func close()
}

public struct MLSError: Error, Equatable, Sendable {
    public let code: String
    public init(_ code: String) { self.code = code }
    /// Expected stale/invalid handshakes that can be skipped; any other code (engine/storage corruption) blocks.
    var isPermanent: Bool { Self.permanentCodes.contains(code) }
    private static let permanentCodes: Set<String> = [
        "invalid_delivery_frame", "invalid_session_input", "invalid_session_message", "invalid_session_members",
        "secure_delivery_required", "delivery_expired", "delivery_peer_disabled", "session_closed", "session_limit"]
}

public struct MLSState: Codable, Equatable, Sendable {
    public let handle: UInt64
    public let generation: UInt64
    public let local: String
    public let peer: String
    public let keyPackage: String
    public let signatureKey: String
    public let groupId: String?
    public let epoch: UInt64?
    public let ready: Bool
}

public struct MLSEvent: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable { case welcome, joined, application, commit }
    public let kind: Kind
    public let message: String?
    public let plaintext: String?

    public func plaintextData() throws -> Data {
        guard kind == .application, let plaintext else { throw MLSError("invalid_session_event") }
        return try decodeB64(plaintext, code: .invalidBody, what: "MLS plaintext", maxBytes: PairwiseMLS.maxPlaintextBytes)
    }
}

/// Pairwise MLS primitives with a durable generation barrier before every transition.
///
/// The host MUST authenticate enrollment inputs through a fresh ACE handshake. This type
/// does not enroll peers or implement transport. Persist returned ciphertext in your delivery
/// journal before transmission. Secret state has no export/import/resume API; restarting
/// requires fresh enrollment. MemoryStore/FileStore cannot prevent whole-host rollback;
/// use a trusted external monotonic store for that threat model.
public final class PairwiseMLS: @unchecked Sendable {
    static let maxPlaintextBytes = 40_000
    static let maxMessageBytes = 64_000
    static let maxKeyPackageBytes = 10_924
    /// One engine command or response, serialized.
    static let maxEngineIOBytes = 140_000
    private struct Gate: Codable {
        let version: Int
        let context: String
        let local: String
        let peer: String
        let signatureKey: String
        var generation: UInt64
        var closed: Bool
    }
    private struct Response<T: Decodable>: Decodable {
        let ok: Bool
        let result: T?
        let error: String?
        func value() throws -> T {
            guard ok, let result else { throw MLSError(error ?? "session_failed") }
            return result
        }
    }
    private struct Transition: Decodable { let event: MLSEvent; let state: MLSState }
    private struct Closed: Decodable { let kind: String }
    private let engine: any MLSEngine
    private let store: any ACECoordinatedStore
    private let mutex = NSLock()
    private let processID = getpid()
    private let key: String
    private let lockName: String
    private var current: MLSState
    private var gate: Gate
    private var closed = false

    public init(engine: any MLSEngine, store: any ACECoordinatedStore, local: String, peer: String) throws {
        guard isACEId(local), isACEId(peer), local != peer else { throw MLSError("invalid_session_input") }
        self.engine = engine
        self.store = store
        let response: Response<MLSState> = try Self.call(engine, ["op": "new", "local": local, "peer": peer])
        current = try response.value()
        let context = randomHex(32)
        gate = Gate(version: 1, context: context, local: local, peer: peer,
                    signatureKey: current.signatureKey, generation: 0, closed: false)
        key = "mls/gates/\(context).json"
        lockName = "mls-\(context.prefix(48))"
        do {
            try checkState(current, generation: 0)
            guard !current.ready else { throw MLSError("invalid_engine_state") }
            try store.coordinate(lockName) { data in
                guard try data.read(key) == nil else { throw MLSError("session_context_conflict") }
                try data.write(key, encodeGate(gate))
            }
        } catch { destroy(); throw error }
    }

    public var state: MLSState {
        // Diagnostics only. Never wait on a mutex inherited across fork.
        guard processID == getpid() else { return current }
        mutex.lock(); defer { mutex.unlock() }
        return current
    }

    /// The peer package must come from a fresh, authenticated ACE handshake.
    public func create(keyPackage: String) throws -> MLSEvent {
        try wireStep("create", field: "key_package", value: keyPackage, limit: Self.maxKeyPackageBytes)
    }

    /// The Welcome must be bound to the same authenticated handshake.
    public func join(welcome: String) throws -> MLSEvent { try wireStep("join", field: "welcome", value: welcome, limit: Self.maxMessageBytes) }

    public func send(_ plaintext: Data) throws -> MLSEvent {
        guard plaintext.count <= Self.maxPlaintextBytes else { throw MLSError("session_limit") }
        return try step(["op": "send", "plaintext": plaintext.base64EncodedString()])
    }

    public func receive(_ message: String) throws -> MLSEvent { try wireStep("receive", field: "message", value: message, limit: Self.maxMessageBytes) }

    /// Past epochs are erased immediately. Coordinate updates with delivery.
    public func update() throws -> MLSEvent { try step(["op": "update"]) }

    public func close() throws {
        guard processID == getpid() else { throw MLSError("session_closed") }
        mutex.lock(); defer { mutex.unlock() }
        guard !closed else { return }
        defer { destroy() }
        try store.coordinate(lockName) { data in
            try checkGate(data)
            try data.delete(key)
        }
    }

    deinit { destroy() }

    private func step(_ command: [String: Any]) throws -> MLSEvent {
        guard processID == getpid() else { throw MLSError("session_closed") }
        mutex.lock(); defer { mutex.unlock() }
        guard !closed else { throw MLSError("session_closed") }
        let response: Response<Transition>
        do {
            response = try store.coordinate(lockName) { data in
                try checkGate(data)
                let info: Response<MLSState> = try Self.call(engine, ["op": "info", "handle": current.handle])
                try checkState(info.value(), generation: gate.generation)
                let generation = gate.generation
                guard generation < maxSafeInteger else { throw MLSError("session_limit") }
                var next = gate
                next.generation += 1
                try data.write(key, encodeGate(next))
                gate = next
                var input = command
                input["handle"] = current.handle
                input["generation"] = generation
                let result: Response<Transition> = try Self.call(engine, input)
                if !result.ok, let error = result.error,
                   ["session_failed", "session_closed", "session_generation_mismatch"].contains(error) {
                    throw MLSError(error)
                }
                let after: Response<MLSState> = try Self.call(engine, ["op": "info", "handle": current.handle])
                let state = try after.value()
                try checkState(state, generation: generation + 1)
                current = state
                return result
            }
        } catch { destroy(); throw error }
        // Invalid ciphertext consumed the generation, but not the ratchet. Surface the
        // rejection only after coordinate returns and its release/fence has succeeded.
        return try response.value().event
    }

    private func wireStep(_ op: String, field: String, value: String, limit: Int) throws -> MLSEvent {
        guard value.utf8.count <= limit else { throw MLSError("session_limit") }
        return try step(["op": op, field: value])
    }

    private func checkGate(_ data: any ACEStoreData) throws {
        guard try data.read(key) == encodeGate(gate) else { throw MLSError("session_generation_mismatch") }
    }

    private func checkState(_ state: MLSState, generation: UInt64) throws {
        guard state.handle > 0, state.handle == current.handle, state.generation == generation,
              state.local == gate.local, state.peer == gate.peer, state.signatureKey == gate.signatureKey else {
            throw MLSError("invalid_engine_state")
        }
    }

    private func encodeGate(_ gate: Gate) throws -> Data { try encodeSortedJSON(gate) }

    private func destroy() {
        closed = true
        let _: Response<Closed>? = try? Self.call(engine, ["op": "close", "handle": current.handle])
    }

    private static func call<T: Decodable>(_ engine: any MLSEngine, _ command: [String: Any]) throws -> Response<T> {
        let input = try JSONSerialization.data(withJSONObject: command)
        guard input.count <= maxEngineIOBytes else { throw MLSError("session_limit") }
        let raw = try engine.execute(input)
        guard raw.count <= maxEngineIOBytes else { throw MLSError("invalid_engine_response") }
        return try JSONDecoder().decode(Response<T>.self, from: raw)
    }
}
