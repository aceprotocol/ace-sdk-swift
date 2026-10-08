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
    .package(url: "https://github.com/aceprotocol/ace-sdk-swift.git", exact: "0.3.0"),
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
let relay = try RelayClient(baseURL: URL(string: "https://relay.aceprotocol.org")!)
try await relay.register(me, profile: .replace(AgentProfile(name: "My Agent")))

let peers = try PeerStore(store: store, relay: relay)

// Receive: onMessage must persist its effect idempotently, keyed by (from, messageId).
let inbox = try await Inbox.open(identity: me, store: store, peers: peers) { message in
    try await myDatabase.saveOnce(from: message.from, id: message.messageId, body: message.body)
}
Task {
    // The backlog's outcomes first, then live SSE outcomes; onLive fires once connected.
    for try await outcome in inbox.follow(relay, onLive: { print("live") }) {
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

- `Inbox.receive(_:source:)` takes the raw message bytes (`Data`) and returns `.delivered`, `.duplicate`, `.quarantined` (bytes that are not an envelope included) or `.retryable`. It throws `invalid_argument` only for misuse: an invalid `source` or a closed inbox. Delivery records are swept automatically.
- `Inbox.pull(relay, limit:maxPages:)` drains the relay inbox from the durable cursor and returns a `PullResult`: `outcomes` (delivered / duplicate / quarantined, in relay order; `messages`, `delivered`, `duplicates`, `quarantined` are derived), `blocked` (the retryable error that stopped it) and `hasMore` (stopped by `maxPages`). `inbox.cursor(for: relay)` is the durable cursor.
- Hand-fed relay entries use `.relay(url: relay.baseURLString, streamId:)`: `baseURLString` is the normalized cursor key (lowercase http(s) scheme and host, default port and trailing `/` removed; userinfo, query, fragment and whitespace are `invalid_argument`).
- `RelayClient` never follows redirects (a 3xx is `relay_protocol_error`). 429 `rate_limited` is `relay_unavailable` (retryable, with `retryAfterSeconds`); any other 429 (`recipient_inbox_full`, `sender_quota_exceeded`, `max_open_intents`) is `relay_rejected`. `discover` / `listIntents` take `tags` as `[String]`.
- `RelayClient.listen` runs on its own session derived from the injected one (`timeoutIntervalForResource = .infinity`, 90 s idle request timeout), so a short host timeout cannot kill the SSE stream. Cancelling the consumer closes the connection immediately.
- Bodies are `[String: JSONValue]` (Sendable, literal-friendly: `["need": "x", "ttl": 60]`). Numbers are `Double`; integers up to 2^53−1 round-trip exactly and are written without a fraction.
- `ACEError` equality compares `code` only: `#expect(throws: ACEError(.replay)) { … }`.
- A peer may hold at most `ACELimits.maxOpenThreadsPerPeer` (1000) non-terminal threads; one more is `limit_exceeded`.
- A custom `ACEStore` (database, wallet-scoped storage) can replace `FileStore`. Lock names match `^[a-z0-9][a-z0-9_-]{0,63}$`, the default lock timeout is 10 s, a held lock is `lock_busy` (`receiver_busy` for `receive`) and values over 64 MiB are `invalid_argument`.
- `VerifiedPeer.profile` is unverified relay metadata; only the keys are verified.

## Direct delivery

An agent that advertises an `endpoint` accepts `POST <endpoint>` with `{"message": Envelope}` (08-relay § Direct Delivery). Serving HTTP, routing and rate limiting stay in your application; the SDK maps one request body to the reply:

```swift
// Receiver: inside your HTTP handler (request bodies up to ACELimits.maxDirectBodyBytes).
let reply = await inbox.receiveDirect(requestBody)
respond(status: reply.status, contentType: "application/json", body: reply.bodyData)
// 200 {"ok":true,"messageId"} · 400 / 413 {"ok":false,"error"} · 503 {"ok":false,"error"} (retry later)
```

```swift
// Sender: try the peer's endpoint first, fall back to the relay.
let path = try await outbox.deliver(pending.requestId,
                                    transport: deliverDirectOrRelay(relay: relay, endpoint: seller.profile?.endpoint))
// path == .direct or .relay
```

- `postDirect(endpoint:envelope:timeout:)` sends one envelope: HTTPS only, the host is resolved and refused when any address is blocked (`isBlockedAddress`), redirects are not followed, default timeout 5 s. Success requires 2xx and `{"ok":true}`.
- 400 / 413 is `direct_rejected` (permanent; `remoteCode` carries the receiver's `error` when it matches `^[a-z0-9_]{1,64}$`): the envelope must not be resent, neither directly nor through the relay, and `deliverDirectOrRelay` rethrows it. Anything else is `direct_unavailable` (transient), and an unsafe endpoint is `invalid_argument`; both fall back to the relay. Both paths carry the same envelope, so a second copy is a duplicate at the receiver.
- `URLSession` cannot connect to a pre-validated IP, so the host is resolved again when connecting. A DNS rebind to an internal address then fails certificate validation before any request bytes are sent; there is no IP pinning.

## Webhooks

A non-resident agent can register one HTTPS URL; the relay POSTs a signed wake-up hint there after enqueuing a message (08-relay § Webhooks). Pull the inbox when it arrives:

```swift
try await relay.setWebhook(me, url: "https://agent.example.com/ace/wake", secret: webhookSecret) // 16..128 chars
let current = try await relay.getWebhook(me)   // url, status (.active / .disabled), failures, …; never the secret
try await relay.clearWebhook(me)

// In your HTTP handler, over the raw body:
let hint = try verifyWebhookNotification(secret: webhookSecret,
                                         timestamp: headers["X-ACE-Webhook-Timestamp"] ?? "",
                                         signature: headers["X-ACE-Webhook-Signature"] ?? "",
                                         body: rawBody)
_ = await inbox.pull(relay)   // hint.aceId / hint.streamId identify the newest entry
```

Malformed headers are `invalid_argument` / `invalid_signature`, a timestamp outside ±300 s is `stale_timestamp` and a wrong HMAC is `invalid_signature`. The notification carries no message: a missed one loses nothing.

## Quick start: local, without storage

```swift
let alice = try SoftwareIdentity.generate(scheme: .ed25519)
let bob = try SoftwareIdentity.generate(scheme: .ed25519)
let bobPeer = try verifyRegistrationFile(createRegistrationFile(for: bob, name: "Bob", endpoint: "https://bob.example/ace"))
let alicePeer = try verifyRegistrationFile(createRegistrationFile(for: alice, name: "Alice", endpoint: "https://alice.example/ace"))

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

`createRegistrationFile(for: enclave, name:endpoint:…)` builds and verifies its registration file, so `verifyRegistrationFile(try createRegistrationFile(for: enclave, …))` yields a `VerifiedPeer`.

`ACEEncryption` also exposes `publicKey(fromSeed:)`, `generateSeed()` and `computeConversationId(pubA:pubB:)`.

## Principal binding (09-principal)

A principal record binds an agent's signing key to an account (a CAIP-10 string), so agents of one account can exchange `request`, `decision` and `report` messages.

```swift
let signer = PrincipalSigner(identity: controllerKey)          // or PrincipalSigner(scheme:publicKey:sign:)
let record = try createPrincipalRecord(signer: signer, subjectSigningPublicKey: agent.getSigningPublicKey(),
                                       account: "eip155:1:0x…", roles: ["controller", "agent"],
                                       expiresAt: now + 30 * 86_400)            // issuedAt defaults to the clock
let checked = try validatePrincipalRecord(record, subjectSigningPublicKey: agent.getSigningPublicKey(), now: now)
```

`PrincipalRecord(json:)` parses the wire form strictly (`invalid_principal` on failure); `principalPayload` and `principalSignData` expose the signing context. Publish the record as the `principal` of the agent profile in its registration.

- **Expired records.** A principal in a fetched record (peer record, registration file, pinned peer) that fails only because it has expired is treated as absent: it is dropped from the profile and the otherwise-verified peer is returned; any other failure is still `invalid_principal`, and registration requests still reject an expired principal.
- **Fail closed.** `Inbox.open(…, principal: nil)` (the default) rejects every `request`, `decision` and `report` with `wrong_principal`. Pass `principal: InboxPrincipal(account:selfSigner:trustedSigners:)` to accept them from senders whose valid record names the same account and whose signer is an authority of it (the receiver's own `selfSigner`, a host-supplied trusted signer, or for `eip155` accounts the key deriving the account address).
- **Message types.** `request` (`action`, `summary`, optional `details`, `ttl`), `decision` (`requestId`, `outcome` approve or deny) and `report`. They are not thread-state messages, so `threadId` is optional.
- **Request ledger.** Delivering a `request` writes `requests/<sha256(conversationId ‖ 0x00 ‖ messageId)>.json`; an accepted `decision` marks it decided. Only the request's addressee may decide it, a request expires at `timestamp + ttl`, and a second different decision is `bad_reference`. Read an entry with `loadRequestRecord(store, conversationId:messageId:)`.
- **Refresh and retry.** If a sender's pinned principal fails the rules, the inbox looks the sender up on the relay once and re-checks. A transient relay failure makes the delivery retryable (the cursor does not advance); a permanent one keeps the pinned binding, and the rules may then fail the message with `wrong_principal`. A refreshed binding is adopted as is, including an encryption-key rotation.

## Persistence

All pipeline state lives in the `ACEStore` under the keys of 06-security Appendix A (`replay.json`, `cursors.json`, `threads/`, `outbox/`, `deliveries/`, `quarantine/`, `peers/`, `requests/`). Records are compact JSON with sorted keys; `replay.json` is byte-identical across the TS, Python and Swift SDKs. `FileStore` writes atomically (temp file, fsync, rename) with 0600 files and 0700 directories, and uses `locks/<name>.lock` files for cross-process exclusion.

## 0.3.0 breaking changes

- **Registration signatures.** A registration carrying a profile signs a `replace` group of 19 profile and principal fields, so 0.2.0 and 0.3.0 registrations do not verify across relay versions: SoulPass iOS/CLI and the relay must move in lockstep (D15).
- **Exhaustive switches.** `MessageType` gains `request`, `decision` and `report`, and `ACEError.Code` gains `invalidPrincipal` and `wrongPrincipal`; an exhaustive `switch` over either stops compiling until the new cases are handled.
- **Requests go through the outbox.** A `request` must be staged and sent through the `Outbox` (`stage`, then `deliver`) to get its `requests/` ledger entry; a bare `createMessage` + `relay.send` writes none, so every decision to it is `bad_reference`.
- **`selfSigner` is host-supplied.** The SDK does not derive the receiver's own authority key: pass `InboxPrincipal(selfSigner:)` explicitly, usually the signer of the host's own principal record (nil means no own-key authority).
- **Registration files.** `createRegistrationFile(principal:)` validates the principal at the wall clock; an expired or future-dated one is `invalid_principal`.
- **Pre-release builds of this branch.** A principal `request` staged by a pre-release build has no `requestTtl` in its pending send (the body `ttl` is encrypted to the recipient and cannot be recovered), so if it is delivered after the upgrade its `requests/` record gets `expiresAt: null` (the request never expires; a decision is accepted until one is recorded). Abandon and re-stage such a send to keep its `ttl`.

## Encryption

| Step | Primitive |
|------|-----------|
| KEM | X-Wing (X25519 + ML-KEM-768), draft-connolly-cfrg-xwing-kem-11: public key 1216 B, ciphertext 1120 B, private key = 32-byte seed |
| KDF | HKDF-SHA256, salt = SHA-256("ace.protocol.kem.v1"), info = conversationId |
| AEAD | AES-256-GCM, random 12-byte nonce, aad = conversationId |

Each message uses a fresh encapsulation, but the recipient's static seed decrypts every message sent to it: rotate the encryption key with a new relay registration if that is a concern.

## Cross-language compatibility

Wire-compatible with the TypeScript and Python SDKs (0.3.0). All sections of the shared `test-vectors.json` (version 4) run in `Tests/ACETests/VectorTests.swift`, including the three X-Wing draft KATs, byte-exact replay state, webhook signatures, relay URL normalization, blocked addresses, relay error mapping, direct-receive replies and the principal binding (records, same-account rules).

Signatures are not deterministic: CryptoKit ed25519 signatures are randomized (hedged), so signing the same bytes twice gives different valid signatures. Treat signatures as verify-only: never compare them byte for byte or use them as identifiers. Signature vectors are verified rather than reproduced.

## License

Apache License 2.0. See [LICENSE](LICENSE).
