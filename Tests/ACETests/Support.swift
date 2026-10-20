import Foundation
import Testing
@testable import ACE

/// The shared fixed clock of the identity-layer tests.
let NOW = 1_800_000_000

/// Software by default; `ACE_KEY_PROVIDER=secure-enclave` runs the suite on Secure Enclave keys.
let testKeyProvider = ProcessInfo.processInfo.environment["ACE_KEY_PROVIDER"] ?? "software"

/// The bound of every "wait for an event" in the tests: a hang guard only.
let hangGuardSeconds = testKeyProvider == "secure-enclave" ? 600 : 30

func makeIdentity(nextRootDigest: Data? = nil, now: Int = NOW) throws -> any ACEManagedIdentity {
    switch testKeyProvider {
    case "software": return try SoftwareIdentity.generate(nextRootDigest: nextRootDigest, now: now)
    case "secure-enclave": return try SecureEnclaveIdentity.generate(nextRootDigest: nextRootDigest, now: now)
    default: fatalError("ACE_KEY_PROVIDER must be software or secure-enclave")
    }
}

/// Reveal the held next root (either provider).
func rotate(_ identity: any ACEManagedIdentity, now: Int? = nil, nextRootDigest: Data? = nil) throws {
    if let s = identity as? SoftwareIdentity { return try s.rotate(now: now, nextRootDigest: nextRootDigest) }
    try (identity as! SecureEnclaveIdentity).rotate(now: now, nextRootDigest: nextRootDigest)
}

/// A fresh process's view of `identity`: export, then import (both providers).
func reload(_ identity: any ACEManagedIdentity, now: Int = NOW) throws -> any ACEManagedIdentity {
    if let s = identity as? SoftwareIdentity { return try SoftwareIdentity(export: s.exportPrivateKey(), now: now) }
    return try SecureEnclaveIdentity(export: (identity as! SecureEnclaveIdentity).exportKeyReferences(), now: now)
}

/// 06 steps 1 (recipient), 4, 5 and 6 of one packet, as the vectors' `packet.open` (the SDK has no public `openPacket`:
/// the Inbox runs the whole pipeline).
func openPacket(_ packet: Packet, sender: KelState, recipient: String, vault: any PrekeyVault, now: Int = NOW) throws -> PrivateContent {
    guard packet.to == recipient else { throw ACEError(.wrongRecipient) }
    try verifyPacketSignature(packet, sender: sender, now: now)
    try checkPacketTime(packet, now: now)
    guard let seed = try vault.open(packet.encryption.prekey, now: now) else { throw ACEError(.unknownPrekey) }
    return try decryptPacket(packet, seed: seed)
}

func json(_ object: Any) -> Data {
    try! JSONSerialization.data(withJSONObject: object, options: [.fragmentsAllowed])
}

/// A Foundation JSON object as a body.
func jsonBody(_ object: Any) -> [String: JSONValue] {
    try! JSONValue(json: json(object)).objectValue!
}

func hex(_ s: String) -> Data { hexDecode(s)! }

/// Expect an `ACEError` with `code` (and, when given, a message containing `messageContains`); `label` names the case.
func expectCode<T>(_ code: ACEError.Code, _ label: String = "", messageContains: String? = nil,
                   sourceLocation: SourceLocation = #_sourceLocation, _ body: () throws -> T) {
    let prefix = label.isEmpty ? "" : "\(label): "
    do {
        _ = try body()
        Issue.record("\(prefix)expected \(code.rawValue), got success", sourceLocation: sourceLocation)
    } catch let e as ACEError {
        #expect(e.code == code, "\(prefix)expected \(code.rawValue), got \(e)", sourceLocation: sourceLocation)
        if let messageContains {
            #expect(e.message.contains(messageContains), "\(prefix)message \(e.message)", sourceLocation: sourceLocation)
        }
    } catch {
        Issue.record("\(prefix)expected ACEError \(code.rawValue), got \(error)", sourceLocation: sourceLocation)
    }
}

func expectCodeAsync<T>(_ code: ACEError.Code, sourceLocation: SourceLocation = #_sourceLocation, _ body: () async throws -> T) async {
    do {
        _ = try await body()
        Issue.record("expected \(code.rawValue), got success", sourceLocation: sourceLocation)
    } catch let e as ACEError {
        #expect(e.code == code, "expected \(code.rawValue), got \(e)", sourceLocation: sourceLocation)
    } catch {
        Issue.record("expected ACEError \(code.rawValue), got \(error)", sourceLocation: sourceLocation)
    }
}

/// A mutable clock for tests.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int
    init(_ value: Int) { self.value = value }
    var now: Int {
        get { lock.lock(); defer { lock.unlock() }; return value }
        set { lock.lock(); value = newValue; lock.unlock() }
    }
    var fn: @Sendable () -> Int { { [self] in self.now } }
}

/// A value shared with a `@Sendable` closure.
final class LockedValue<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value
    init(_ value: Value) { stored = value }
    var value: Value {
        get { lock.withLock { stored } }
        set { lock.withLock { stored = newValue } }
    }
}

/// An identity with a prekey vault and a published agent, for packet-level tests.
struct TestAgent {
    let identity: any ACEManagedIdentity
    let vault: StorePrekeyVault
    let agent: VerifiedAgent

    init(now: Int = NOW, profiles: [ProfileManifest] = [.text], relay: String = "https://relay.example") throws {
        identity = try makeIdentity(now: now)
        vault = StorePrekeyVault(store: MemoryStore())
        let prekey = try vault.rotate(now: now).prekey
        agent = try createPublishedAgent(identity: identity, claims: DescriptorClaims(
            relays: [relay], prekey: prekey, profiles: profiles.map(\.ref)), now: now)
    }

    var aceId: String { identity.getACEId() }
    var state: KelState { agent.state }
}

/// A full networking peer on a `FakeRelay`.
struct NetPeer {
    let identity: any ACEManagedIdentity
    let store: MemoryStore
    let network: NetworkClient
    let received: LockedValue<[ReceivedMessage]>

    static func make(_ relay: FakeRelay, clock: TestClock, configuration: NetworkConfiguration = NetworkConfiguration(contact: .open, listed: true),
                     capacity: Int = ACELimits.defaultReplayCapacity,
                     rules: (String, MemoryStore) -> [any ProfileRules] = { _, _ in [] }) async throws -> NetPeer {
        let identity = try makeIdentity(now: clock.now)
        let store = MemoryStore()
        let received = LockedValue<[ReceivedMessage]>([])
        var config = configuration
        config.rules = rules(identity.getACEId(), store)
        let host = config.onMessage
        config.onMessage = { m in
            try await host?(m)
            received.value.append(m)
        }
        let network = try await NetworkClient.open(identity: identity, store: store, relay: try relay.client(clock: clock.fn),
                                                   prekeys: StorePrekeyVault(store: store), configuration: config,
                                                   foreignRelay: { _ in throw ACEError(.blockedAddress) }, clock: clock.fn, capacity: capacity)
        try await network.publish()  // registers on demand
        return NetPeer(identity: identity, store: store, network: network, received: received)
    }

    var aceId: String { identity.getACEId() }
}
