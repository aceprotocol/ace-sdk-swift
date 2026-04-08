# ACE Protocol Swift SDK

Swift implementation of the [ACE Protocol](https://aceprotocol.org) — a secure, end-to-end encrypted communication protocol for autonomous AI agents.

## Features

- **Identity** — Ed25519 and secp256k1 signing schemes, tiered identity (key-only / chain-registered), hardware backing (Secure Enclave, TPM, HSM, TEE)
- **Encryption** — X25519 ECDH + HKDF-SHA256 + AES-256-GCM with per-message ephemeral keys (forward secrecy)
- **Messages** — Full economic message lifecycle (RFQ → Offer → Accept → Invoice → Receipt → Deliver → Confirm), plus system and social messages
- **Security** — Timestamp freshness, replay detection, signature-before-decryption pipeline, payload size limits
- **State Machine** — Thread-level state tracking for economic message flows
- **Discovery** — Agent registration file validation and well-known URL discovery

## Requirements

- Swift 6.0+
- macOS 14+ / iOS 17+

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/aceprotocol/ace-sdk-swift.git", from: "0.1.0"),
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
import CryptoKit

// Generate key pairs
let signingKey = Curve25519.Signing.PrivateKey()
let encryptionKey = Curve25519.KeyAgreement.PrivateKey()

// Create a software identity (Tier 0)
let identity = SoftwareIdentity(
    signingPrivateKey: signingKey,
    encryptionPrivateKey: encryptionKey,
    scheme: .ed25519
)

print(identity.getACEId())  // ace:sha256:...
```

### Encrypt & Decrypt

```swift
let plaintext = Data("Hello, Agent!".utf8)

// Encrypt (creates ephemeral key pair automatically)
let conversationId = try ACEEncryption.computeConversationId(
    pubA: senderEncPub,
    pubB: recipientEncPub
)

let (ephemeralPubKey, payload) = try ACEEncryption.encrypt(
    plaintext: plaintext,
    recipientPublicKey: recipientEncPub,
    conversationId: conversationId
)

// Decrypt
let decrypted = try ACEEncryption.decrypt(
    ephemeralPubKey: ephemeralPubKey,
    payload: payload,
    recipientPrivateKey: recipientEncPriv,
    conversationId: conversationId
)
```

### Send & Receive Messages

```swift
let stateMachine = ThreadStateMachine()

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
    opts: ParseMessageOptions(stateMachine: stateMachine)
)
```

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
| `Encryption.swift` | X25519 + AES-256-GCM encryption/decryption |
| `Messages.swift` | Message creation and parsing pipeline |
| `StateMachine.swift` | Thread-level economic state machine |
| `Discovery.swift` | Registration file validation and agent discovery |
| `Security.swift` | Replay detection, timestamp checks, security utilities |
| `Keccak256.swift` | Keccak-256 hash for secp256k1 address derivation |
| `Utils.swift` | Base64, hex encoding, and common helpers |

## Cross-Language Compatibility

This SDK produces wire-compatible output with the [TypeScript](https://github.com/aceprotocol/ace-sdk-ts) and [Python](https://github.com/aceprotocol/ace-sdk-python) implementations. Interoperability is verified through shared protocol test vectors.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
