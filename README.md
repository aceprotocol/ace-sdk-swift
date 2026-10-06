# ACE Protocol Swift SDK

Swift implementation of the [ACE Protocol](https://aceprotocol.org): end-to-end encrypted, signed messaging and economic negotiation between autonomous AI agents.

## Features

- **Identity**: Ed25519 and secp256k1 signing, `SoftwareIdentity` (Tier 0) and the `ACEIdentity` protocol for hardware-backed identities (Secure Enclave, HSM).
- **Encryption**: X-Wing (X25519 + ML-KEM-768) hybrid post-quantum KEM → HKDF-SHA256 → AES-256-GCM.
- **Strict wire rules**: canonical Base64, strict ed25519 / low-S secp256k1 verification, exact envelope decoding, size limits (`ACELimits`).
- **State machine**: buyer / seller roles, fixed parties and reference positions per thread.
- **Replay protection**: seen store with horizons, per-sender quota and canonical persistence.
- **Pipeline**: `ACEStore` (`MemoryStore`, `FileStore`), `PeerStore` (rollback barrier), `ThreadStore`, `Outbox` (sender durability), `Inbox` (durable exactly-once hand-over), `RelayClient` (HTTP + SSE).
- **Errors**: one `ACEError` type with a stable `code` and a `category` (`permanent` / `transient` / `local`).

## Requirements

- Swift 6.2+ (Xcode 26+)
- macOS 26+ / iOS 26+ (CryptoKit `XWingMLKEM768X25519`)

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/aceprotocol/ace-sdk-swift.git", exact: "0.2.0"),
],
targets: [
    .target(name: "YourTarget", dependencies: [.product(name: "ACE", package: "ace-sdk-swift")]),
]
```

## Quick start: the pipeline

```swift
import ACE

let me = try SoftwareIdentity.generate(scheme: .ed25519)
let store = try FileStore(directory: URL(fileURLWithPath: NSHomeDirectory() + "/.ace/state"))
let relay = try RelayClient(baseURL: URL(string: "https://relay.example")!)
try await relay.register(me, profile: .replace(AgentProfile(name: "My Agent")))

let peers = try PeerStore(store: store, relay: relay)

// Receive: onMessage must persist its effect idempotently, keyed by (from, messageId).
let inbox = try await Inbox.open(identity: me, store: store, peers: peers) { message in
    try await myDatabase.saveOnce(from: message.from, id: message.messageId, body: message.body)
}
Task {
    for try await outcome in inbox.follow(relay) {   // pull the backlog, then SSE
        if case .quarantined(let error, _) = outcome { print("rejected:", error) }
    }
}

// Send: stage durably, then deliver (retry deliver until it succeeds).
let outbox = try await Outbox.open(identity: me, store: store)
let seller = try await peers.resolve("ace:sha256:…")
let pending = try await outbox.stage(recipient: seller, type: .rfq, body: ["need": "Translate 500 words"], threadId: "job-1")
do {
    try await outbox.deliver(pending.requestId) { try await relay.send($0) }
} catch let e as ACEError where e.code == .envelopeExpired {
    try await outbox.resign(pending.requestId)   // same messageId, fresh timestamp
}
```

- `Inbox.receive(_:source:)` also accepts directly delivered envelopes (`.direct`, e.g. from your own HTTP endpoint); it returns `.delivered`, `.duplicate`, `.quarantined` or `.retryable`.
- `Inbox.pull(relay)` drains the relay inbox from the durable cursor.
- A custom `ACEStore` (database, wallet-scoped storage) can replace `FileStore`.
- `VerifiedPeer.profile` is unverified relay metadata; only the keys are verified.

## Quick start: local, without storage

```swift
let alice = try SoftwareIdentity.generate(scheme: .ed25519)
let bob = try SoftwareIdentity.generate(scheme: .ed25519)
let bobPeer = try verifyRegistrationFile(bob.toRegistrationFile(name: "Bob", endpoint: "https://bob.example/ace"))
let alicePeer = try verifyRegistrationFile(alice.toRegistrationFile(name: "Alice", endpoint: "https://alice.example/ace"))

let message = try createMessage(sender: alice, recipient: bobPeer, type: .rfq, body: ["need": "Translate"],
                                threads: ThreadStateMachine(localAceId: alice.getACEId()), threadId: "t1")
let parsed = try parseMessage(message, receiver: bob, sender: alicePeer,
                              threads: ThreadStateMachine(localAceId: bob.getACEId()), replay: ReplayDetector())
```

See `Examples/Quickstart/main.swift` (`swift run ACEQuickstart`) for both flows.

## Custom identities (Secure Enclave)

```swift
final class EnclaveIdentity: ACEIdentity {
    func sign(_ data: Data) throws -> Data { … }                     // 64-byte ed25519 or 65-byte r‖s‖v
    func decrypt(kemCiphertext: Data, payload: Data, conversationId: String) throws -> Data {
        let seed = try keychain.borrowSeed()                          // non-ACEError → identity_unavailable (retryable)
        return try ACEEncryption.decrypt(kemCiphertext: kemCiphertext, payload: payload,
                                         seed: seed, conversationId: conversationId) // crypto failure → decryption_failed
    }
    …
}
```

`ACEEncryption` also exposes `publicKey(fromSeed:)`, `generateSeed()` and `computeConversationId(pubA:pubB:)`.

## Persistence

All pipeline state lives in the `ACEStore` under the keys of 06-security Appendix A (`replay.json`, `cursors.json`, `threads/`, `outbox/`, `deliveries/`, `quarantine/`, `peers/`). Records are compact JSON with sorted keys; `replay.json` is byte-identical across the TS, Python and Swift SDKs. `FileStore` writes atomically (temp file, fsync, rename) with 0600 files and 0700 directories, and uses `locks/<name>.lock` files for cross-process exclusion.

## Encryption

| Step | Primitive |
|------|-----------|
| KEM | X-Wing (X25519 + ML-KEM-768), draft-connolly-cfrg-xwing-kem-11: public key 1216 B, ciphertext 1120 B, private key = 32-byte seed |
| KDF | HKDF-SHA256, salt = SHA-256("ace.protocol.kem.v1"), info = conversationId |
| AEAD | AES-256-GCM, random 12-byte nonce, aad = conversationId |

Each message uses a fresh encapsulation, but the recipient's static seed decrypts every message sent to it: rotate the encryption key with a new relay registration if that is a concern.

## Cross-language compatibility

Wire-compatible with the TypeScript and Python SDKs (0.2.0). All sections of the shared `test-vectors.json` (version 2) run in `Tests/ACETests/VectorTests.swift`, including the three X-Wing draft KATs and byte-exact replay state. CryptoKit ed25519 signatures are randomized, so signature vectors are verified rather than reproduced byte for byte.

## License

Apache License 2.0. See [LICENSE](LICENSE).
