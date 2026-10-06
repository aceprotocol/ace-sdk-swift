# ACE Protocol Swift SDK

Swift implementation of the [ACE Protocol](https://aceprotocol.org) — a secure, end-to-end encrypted communication protocol for autonomous AI agents.

## Features

- **Identity** — Ed25519 and secp256k1 signing schemes, tiered identity (key-only / chain-registered), hardware backing (Secure Enclave, TPM, HSM, TEE)
- **Encryption** — X-Wing (X25519 + ML-KEM-768) hybrid post-quantum KEM → HKDF-SHA256 → AES-256-GCM, per-message KEM encapsulation
- **Messages** — Full economic message lifecycle (RFQ → Offer → Accept → Invoice → Receipt → Deliver → Confirm), plus system and social messages
- **Security** — Timestamp freshness, replay detection, signature-before-decryption pipeline, payload size limits
- **State Machine** — Thread-level state tracking for economic message flows
- **Discovery** — Agent registration file validation and well-known URL discovery

## Requirements

- Swift 6.2+ (Xcode 26+)
- macOS 26+ / iOS 26+ (CryptoKit `XWingMLKEM768X25519`)

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/aceprotocol/ace-sdk-swift.git", exact: "0.2.0"),
]
```

Then add `"ACE"` to your target's dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "ACE", package: "ace-sdk-swift"),
    ]
)
```

### Xcode

File → Add Package Dependencies → Enter:

```
https://github.com/aceprotocol/ace-sdk-swift.git
```

## Quick Start

### Create an Identity

```swift
import ACE

// Create a software identity (Tier 0): Ed25519 signing key + 32-byte X-Wing seed
let identity = try SoftwareIdentity.generate(scheme: .ed25519)

print(identity.getACEId())                       // ace:sha256:...
print(identity.getEncryptionPublicKey().count)   // 1216 (X-Wing public key)

// Export / import — `encryptionPrivateKey` is the Base64 32-byte X-Wing seed
let export = identity.exportPrivateKey()
let restored = try SoftwareIdentity.fromExport(export)
```

### Encrypt & Decrypt

```swift
let plaintext = Data("Hello, Agent!".utf8)

// Both keys are 1216-byte X-Wing public keys
let conversationId = try ACEEncryption.computeConversationId(
    pubA: senderEncPub,
    pubB: recipientEncPub
)

// Encrypt: X-Wing encapsulate → HKDF-SHA256 → AES-256-GCM
let (kemCiphertext, payload) = try ACEEncryption.encrypt(
    plaintext,
    recipientPublicKey: recipientEncPub,
    conversationId: conversationId
)
// kemCiphertext: 1120 bytes; payload: nonce[12] || ciphertext || tag[16]

// Decrypt with the recipient's 32-byte X-Wing seed
let decrypted = try ACEEncryption.decrypt(
    kemCiphertext: kemCiphertext,
    payload: payload,
    seed: recipientSeed,
    conversationId: conversationId
)
```

#### Encryption scheme

| Step | Primitive |
|------|-----------|
| KEM | X-Wing (X25519 + ML-KEM-768), draft-connolly-cfrg-xwing-kem-11 — public key 1216 B, ciphertext 1120 B, private key = 32-byte seed |
| KDF | HKDF-SHA256, `ikm` = X-Wing shared secret, `salt` = SHA-256("ace.protocol.kem.v1"), `info` = conversationId, 32 B |
| AEAD | AES-256-GCM, random 12-byte nonce, `aad` = conversationId |
| Wire | `encryption: { kemCiphertext: Base64(1120 B), payload: Base64(nonce ‖ ciphertext ‖ tag) }` |

The hybrid KEM protects message confidentiality against harvest-now-decrypt-later
attacks by a future quantum adversary as long as *either* X25519 or ML-KEM-768 holds.
Signatures (Ed25519 / secp256k1) remain classical by design.

**Forward secrecy — honest statement.** Each message uses a fresh KEM encapsulation,
so compromising the *sender* reveals nothing about past messages. However, the
*recipient's* static X-Wing seed decrypts every message ever sent to it: compromise
of that seed reveals all past and future messages to that recipient. Rotate the
encryption key via a new registration file if that is a concern.

### Send & Receive Messages

```swift
let stateMachine = ThreadStateMachine()
let replayDetector = ReplayDetector()

// Create an encrypted, signed message
let message = try createMessage(CreateMessageOptions(
    sender: identity,
    recipientPubKey: recipientEncPub,
    recipientACEId: recipientACEId,
    type: .rfq,
    body: ["need": "Translate 500 words EN→JP"],
    stateMachine: stateMachine,
    threadId: UUID().uuidString.lowercased()
))

// Parse and verify an incoming message
let parsed = try parseMessage(
    message,
    receiver: recipientIdentity,
    senderSigningPubKey: senderSigningPub,
    opts: ParseMessageOptions(stateMachine: stateMachine, replayDetector: replayDetector)
)
```

`replayDetector` is the seen store with a replay horizon; persist it across restarts with
`export()` / `ReplayDetector.fromExport(_:)`.

### Verify Signatures

```swift
let signData = ACESigning.buildSignData(
    action: "message",
    aceId: aceId,
    timestamp: timestamp,
    payload: payload
)

let valid = ACESigning.verifySignature(
    signData: signData,
    signature: signatureBytes,
    scheme: .ed25519,
    signingPublicKey: publicKey
)
```

## Architecture

| Module | Description |
|--------|-------------|
| `Types.swift` | Core protocol types, enums, and error definitions |
| `Identity.swift` | ACE identity management and ACE ID derivation |
| `Signing.swift` | Domain-tagged sign data construction and signature verification |
| `Encryption.swift` | X-Wing (X25519 + ML-KEM-768) + HKDF-SHA256 + AES-256-GCM encryption/decryption |
| `Messages.swift` | Message creation and parsing pipeline |
| `StateMachine.swift` | Thread-level economic state machine |
| `Discovery.swift` | Registration file validation and agent discovery |
| `Security.swift` | Replay detection, timestamp checks, security utilities |
| `Keccak256.swift` | Keccak-256 hash for secp256k1 address derivation |
| `Utils.swift` | Base64, hex encoding, and common helpers |

## Cross-Language Compatibility

This SDK produces wire-compatible output with the [TypeScript](https://github.com/aceprotocol/ace-sdk-ts) and [Python](https://github.com/aceprotocol/ace-sdk-python) implementations (all at 0.2.0). Interoperability is verified through the shared canonical test vectors (`ace-spec/test-vectors.json`), which include the X-Wing draft-11 KEM vector and a Python-encrypted message that this SDK decrypts.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
