# ACE Protocol Swift SDK

Network ingress must use `SecureMailbox`, and Outbox transport must use `SecureTransport`.
The `Inbox`/`createMessage` examples also expose lower-level application codecs; those
alone are not the authenticated secure network boundary. See “Authenticated secure delivery”.

Message packet **2.0** carries `{type,schemaDigest,threadId?,body}` entirely inside the ciphertext. Custom namespaced types require an immutable `schemaDigest`; unknown schemas are data and never execute. Durable Inbox/Outbox defaults do not install commerce state transitions. Set `commerce: true` (Python `commerce=True`) for the bundled commerce profile. The optional `principal` policy validates account coordination; receiving without it grants no execution rights.


Swift implementation of the [ACE Protocol](https://aceprotocol.org): end-to-end encrypted, signed messaging and economic negotiation between autonomous AI agents.

## Features

- **Identity**: Ed25519 and secp256k1 signing, `SoftwareIdentity` (Tier 0) and the `ACEIdentity` protocol for hardware-backed identities (Secure Enclave, HSM).
- **Encryption**: X-Wing (X25519 + ML-KEM-768) hybrid post-quantum KEM → HKDF-SHA256 → AES-256-GCM.
- **Strict wire rules**: canonical Base64, strict ed25519 / low-S secp256k1 verification, exact envelope decoding, size limits (`ACELimits`).
- **State machine**: buyer / seller roles, fixed parties and reference positions per thread.
- **Replay protection**: seen store with horizons, per-sender quota and canonical persistence.
- **Pipeline**: `ACEStore` (`MemoryStore`, `FileStore`), `PeerStore` (rollback barrier), `ThreadStore`, `Outbox` (sender durability), `Inbox` (durable exactly-once hand-over), `RelayClient` (HTTP + SSE), `SecureTransport` + `SecureMailbox` (the authenticated network boundary).
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

## Build

`ACE` links the MLS engine through the `ace-session-core` package (`session-core/bindings/swift`
in the source workspace: `SessionCoreEngine`, a thin wrapper over
`session-core/pkg/ACESessionCore.xcframework`). From a source checkout, build that XCFramework
once before `swift build` / `swift test`; a release pins
`https://github.com/aceprotocol/ace-session-core.git` by exact version instead of the path.

```sh
(cd ../session-core && python3 build.py --apple)   # Rust 1.95.0 + Xcode; see session-core/README.md
swift build
swift test            # includes the native engine tests (Tests/ACETests/Engine)
```

`swift run SecureInterop` / `swift run MLSInterop` are the local interop drivers that
`session-core/tests/*.mjs` build and run; they are never network endpoints.

## Quick start: the pipeline (recommended)

```swift
import ACE   // NativeMLSEngine, the source-built MLS engine, is part of the module

let me = try SoftwareIdentity.generate(scheme: .ed25519)
let store = try FileStore(directory: URL(fileURLWithPath: NSHomeDirectory() + "/.ace/state"))
let relay = try RelayClient(baseURL: URL(string: "https://relay.aceprotocol.org")!)
try await relay.register(me, profile: .replace(AgentProfile(name: "My Agent")))
let peers = try PeerStore(store: store, relay: relay)

// Receive: one call opens the application Inbox (it only ever sees authenticated MLS
// plaintext), the SecureTransport and the SecureMailbox, the only network boundary; one
// close() releases the receive lock, the transport and the engine. onMessage must persist
// its effect idempotently, keyed by (from, messageId).
let mailbox = try await openSecureMailbox(
    identity: me, store: store, peers: peers, relay: relay, engine: try NativeMLSEngine(),
    inbox: InboxSetup(onMessage: { message in
        try await myDatabase.saveOnce(from: message.from, id: message.messageId, body: message.body)
    }, commerce: true),
    send: { frame, peer in try await deliverDirectOrRelay(relay: relay, endpoint: peer.profile?.endpoint)(frame) })
Task {
    // The backlog's outcomes first, then a pull after every SSE wake-up; onLive fires once connected.
    for try await outcome in mailbox.follow(onLive: { print("live") }) {
        if case .quarantined(let error, _) = outcome { print("rejected:", error) }
    }
}

// Send: stage durably, then deliver through the authenticated handshake (retry deliver until it succeeds).
let outbox = try await Outbox.open(identity: me, store: store)
let seller = try await peers.resolve("ace:sha256:…")
try SecureTransport.setPeerAllowed(store: store, peer: seller.aceId, allowed: true)   // local policy; the peer enables you too
let pending = try await outbox.stage(recipient: seller, type: .rfq, body: ["need": "Translate 500 words"], threadId: "job-1")
do {
    try await outbox.deliver(pending.requestId) { try await mailbox.deliver($0, peer: seller) }
} catch let e as ACEError where e.code == .envelopeExpired {
    try await outbox.resign(pending.requestId)   // same messageId, fresh timestamp
}
```

- `openSecureMailbox(identity:store:peers:relay:engine:inbox:send:clock:)` is `Inbox.open` (with the `InboxSetup` options: `onMessage`, `commerce`, `principal`, `schemas`, `offlineWindowSeconds`, `clock`, …) → `SecureTransport` → `SecureMailbox.open`; `send` defaults to `relay.send`. A failure after the Inbox opened closes it (no leaked `receive` lock) and rethrows; the engine is then still yours to close. `SecureMailbox.open(identity:store:peers:relay:secure:inbox:send:)` is the manual form: you then own the Inbox and the engine, and `close()` closes only the transport.
- A sending process that does not own the mailbox (another process holds `receive`) delivers with `deliverSecure(outbox, requestId, identity:secure:relay:peer:send:)` = `outbox.deliver(requestId, transport: secureTransportFor(…))`: every handshake frame goes out through `send` and its signed reply is read back on a non-destructive relay cursor (`SecureRelayReplies`). It returns once the peer's Inbox durably committed the envelope; on failure the operation stays pending under `requestId` — retry that ID, never stage a new one.
- `SecureMailbox` is the only network receive path. `pull(limit:maxPages:)` drains the relay inbox from its durable cursor and returns a `PullResult`: `outcomes` (delivered / duplicate / quarantined, in relay order; `messages`, `delivered`, `duplicates`, `quarantined` are derived), `blocked` (the retryable error that stopped it) and `hasMore` (stopped by `maxPages`). `follow(onLive:)` streams the backlog and then pulls again after every SSE wake-up (an SSE event is never authority or a cursor commit). `receiveDirect(_:)` serves the direct endpoint (below) and `cursor` is the durable cursor. A static application packet is refused as `invalid_body` (`secure_delivery_required`): there is no downgrade.
- `Inbox.receive(_:)` is the in-process application codec: it takes raw envelope bytes (`Data`) and returns `.delivered`, `.duplicate`, `.quarantined` (bytes that are not an envelope included; permanent rejections are persisted under `quarantine/`) or `.retryable`. It throws `invalid_argument` only for a closed inbox. It is fed by `SecureMailbox`, or directly by in-process code and tests; never expose it to the network. Delivery records are swept automatically.
- `RelayClient` never follows redirects (a 3xx is `relay_protocol_error`). 429 `rate_limited` is `relay_unavailable` (retryable, with `retryAfterSeconds`); any other 429 (`recipient_inbox_full`, `sender_quota_exceeded`, `max_open_intents`) is `relay_rejected`. `discover` / `listIntents` take `tags` as `[String]`.
- **Product-neutral discovery.** `AgentProfile` is `name, description, image, tags, capabilities, endpoint, ext?, principal?`; a `RegistrationFile` carries `ext?` too, and an intent is `postIntent(need:tags:ext:ttl:)`. `ext` (`ExtMap`, `[String: JSONValue]`) holds namespaced extensions: each key a namespaced identifier (04 grammar, ≤ 256 bytes), each value an object, ≤ 8 keys, canonical JSON ≤ 4096 bytes, depth ≤ 8 (`validateExt(_:carrier:)`; `invalid_profile` for profiles and registration files, `invalid_argument` for intents); an empty `ext` is absent. Commerce data lives under `commerceExt` (`urn:ace:commerce:1`): `profile.commerce` / `file.commerce` give a `CommerceProfileExt` (`chains`, `pricing`, `settlement`, `accounts`) and `intent.commerce` a `CommerceIntentExt` (`maxPrice`, `currency`); build one with `CommerceProfileExt(...).jsonValue`. The relay stores and serves `ext` in canonical form and never indexes it.
- `RelayClient.listen` runs on its own session derived from the injected one (`timeoutIntervalForResource = .infinity`, 90 s idle request timeout), so a short host timeout cannot kill the SSE stream. Cancelling the consumer closes the connection immediately.
- Bodies are `[String: JSONValue]` (Sendable, literal-friendly: `["need": "x", "ttl": 60]`). Numbers are `Double`; integers up to 2^53−1 round-trip exactly and are written without a fraction.
- `ACEError` equality compares `code` only: `#expect(throws: ACEError(.replay)) { … }`.
- A peer may hold at most `ACELimits.maxOpenThreadsPerPeer` (1000) non-terminal threads; one more is `limit_exceeded`.
- A custom `ACEStore` (database, wallet-scoped storage) can replace `FileStore`. Lock names match `^[a-z0-9][a-z0-9_-]{0,63}$`, the default lock timeout is 10 s, a held lock is `lock_busy` (`receiver_busy` for `receive`) and values over 64 MiB are `invalid_argument`. `checkKey(_:)` / `checkLockName(_:)` are the public key and lock-name validators (they return the value or throw `invalid_argument`).
- `VerifiedPeer.profile` is unverified relay metadata; only the keys are verified.

## Direct delivery

An agent that advertises an `endpoint` accepts `POST <endpoint>` with `{"message": Envelope}` (08-relay § Direct Delivery), where the envelope is a secure delivery frame of the handshake. Serving HTTP, routing and rate limiting stay in your application; the mailbox maps one request body to the reply:

```swift
// Receiver: inside your HTTP handler (request bodies up to ACELimits.maxDirectBodyBytes).
let reply = await mailbox.receiveDirect(requestBody)
respond(status: reply.status, contentType: "application/json", body: reply.bodyData)
// 200 {"ok":true,"messageId"} · 400 / 413 {"ok":false,"error"} · 503 {"ok":false,"error"} (retry later)
```

```swift
// Sender: the mailbox's `send` tries the peer's endpoint first and falls back to the relay.
let mailbox = try SecureMailbox.open(…, send: { frame, peer in
    try await deliverDirectOrRelay(relay: relay, endpoint: peer.profile?.endpoint)(frame)   // .direct or .relay
})
```

- `postDirect(endpoint:envelope:timeout:)` posts one frame: HTTPS only, the host is resolved and refused when any address is blocked (`isBlockedAddress`), redirects are not followed, default timeout 5 s. Success requires 2xx and `{"ok":true}`.
- 400 / 413 is `direct_rejected` (permanent; `remoteCode` carries the receiver's `error` when it matches `^[a-z0-9_]{1,64}$`): the frame must not be resent, neither directly nor through the relay, and `deliverDirectOrRelay` rethrows it. Anything else is `direct_unavailable` (transient), and an unsafe endpoint is `invalid_argument`; both fall back to the relay. Both paths carry the same frame, so a second copy is idempotent at the receiver.
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
_ = await mailbox.pull()   // hint.aceId / hint.streamId identify the newest entry
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

A principal record binds an agent's signing key to an account (a CAIP-10 string), so agents of one account can exchange `request`, `decision` and `report` messages. Roles are `controller` (approves) and `delegate` (acts); `principalRoles` lists them in canonical order.

```swift
let signer = PrincipalSigner(identity: controllerKey)          // or PrincipalSigner(scheme:publicKey:sign:)
let record = try createPrincipalRecord(signer: signer, subjectSigningPublicKey: agent.getSigningPublicKey(),
                                       account: "eip155:1:0x…", roles: ["controller", "delegate"],
                                       expiresAt: now + 30 * 86_400)            // issuedAt defaults to the clock
let checked = try validatePrincipalRecord(record, subjectSigningPublicKey: agent.getSigningPublicKey(), now: now)
```

`PrincipalRecord(json:)` parses the wire form strictly (`invalid_principal` on failure); `principalPayload` and `principalSignData` expose the signing context. Publish the record as the `principal` of the agent profile in its registration. `inboxPrincipalFromOwnRecord(record, identity: me, now:trustedSigners:)` turns the host's own saved record into the Inbox `principal` option as `(principal, warning)`: no record is `(nil, nil)`, a valid one binds its account with the record's signer as `selfSigner`, and an expired or foreign one never throws but is `(nil, "<code>: <detail>")`.

- **Expired records.** A principal in a fetched record (peer record, registration file, pinned peer) that fails only because it has expired is treated as absent: it is dropped from the profile and the otherwise-verified peer is returned; any other failure is still `invalid_principal`, and registration requests still reject an expired principal.
- **Explicit policy.** `Inbox.open(…, principal: nil)` receives authenticated data without account authorization. Pass `principal: InboxPrincipal(account:selfSigner:trustedSigners:)` to accept them from senders whose valid record names the same account and whose signer is an authority of it (the receiver's own `selfSigner`, a host-supplied trusted signer, or for `eip155` accounts the key deriving the account address).
- **Message types.** `request` (`action`, `summary`, optional `details`, `ttl`), `decision` (`requestId`, `outcome` approve or deny) and `report`. They are not thread-state messages, so `threadId` is optional.
- **Request ledger.** Delivering a `request` writes `requests/<sha256(conversationId ‖ 0x00 ‖ messageId)>.json`; an accepted `decision` marks it decided. Only the request's addressee may decide it, a request expires at `timestamp + ttl`, and a second different decision is `bad_reference`. Read an entry with `loadRequestRecord(store, conversationId:messageId:)`.
- **Refresh and retry.** If a sender's pinned principal fails the rules, the inbox looks the sender up on the relay once and re-checks. A transient relay failure makes the delivery retryable (the cursor does not advance); a permanent one keeps the pinned binding, and the rules may then fail the message with `wrong_principal`. A refreshed binding is adopted as is, including an encryption-key rotation.

## Installed schemas

Custom namespaced types are authenticated data until a validator is installed for their `schemaDigest`. `Inbox.open(…, schemas:)` and `Outbox.open(…, schemas:)` take a `[String: SchemaValidator]` keyed by the 64-hex digest (anything else is `invalid_argument` at open); a validator is `@Sendable (SchemaMessage) throws -> Void` over `{ type, schemaDigest, threadId, body }` and must be deterministic. The Inbox runs it at the body-validation step, after decryption and before thread/principal checks: a thrown `ACEError` with a permanent code quarantines the message with that code, anything else quarantines it as `invalid_body`. `Outbox.stage` runs it before anything is persisted and throws the same way. Bundled types keep their built-in rules; a validator installed for a bundled digest runs in addition.

```swift
let schemas: [String: SchemaValidator] = [taskDigest: { m in
    guard m.body["task"]?.stringValue != nil else { throw ACEError(.invalidBody, "task required") }
}]
let inbox = try await Inbox.open(identity: me, store: store, peers: peers, onMessage: handle, schemas: schemas)
```

## Persistence

All pipeline state lives in the `ACEStore` under the keys of 06-security Appendix A (`replay.json`, `threads/`, `outbox/`, `deliveries/`, `quarantine/`, `peers/`, `requests/`) and 13-session-core (`secure/cursors/<sha256(normalized relay URL)>.json`, `secure/peers/<sha256(aceId)>.json`, `secure/in/<attempt>.json`, `mls/gates/…`; the sender keeps no attempt journal). Records are compact JSON with sorted keys; `replay.json` is byte-identical across the TS, Python and Swift SDKs. `FileStore` writes atomically (temp file, fsync, rename) with 0600 files and 0700 directories, and uses permanent `locks/<name>.lock` files with POSIX kernel locks for cross-process exclusion. Process exit releases ownership; never delete lock files or use a network mount.

## 0.3.0 breaking changes

- **Registration signatures.** A registration carrying a profile signs a `replace` group of 15 profile (including the canonical `ext`) and principal fields, so earlier registrations do not verify across relay versions: SoulPass iOS/CLI and the relay must move in lockstep (D15).
- **Vocabulary.** The principal role `agent` is now `delegate`; `AgentProfile.chains` / `.pricing`, `RegistrationFile.settlement` / `.chains`, capability `pricing`, intent `maxPrice` / `currency` and `DiscoverQuery.chain` are gone — commerce data moves into `ext[commerceExt]`.
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

## Resource execution and audit

Exact-intent grants bind a resource, executor, immutable effect digest, absolute deadline and policy epoch. Verification starts from a locally trusted authority and validates every ancestor; message labels confer no rights. See [resource grants](https://github.com/aceprotocol/ace-spec/blob/main/10-resource-grants.md). The TypeScript and Swift `ExecutionAuthority` coordinators reserve all profile-derived budgets atomically and consume one authorization release under current policy. `hasReservation` reads a permanent binding after expiry/revocation; it never permits another effect. All three SDKs expose the closed `urn:ace:execute:1` request schema. SoulPass has an opt-in Solana/EVM execution service with explicit local or replicated authority storage; generic applications must install their own deterministic effect validators and durable executors.

Optional audit APIs create private salted commitments, Merkle inclusion/consistency proofs and signed checkpoints. They do not publish records automatically. See [private audit](https://github.com/aceprotocol/ace-spec/blob/main/11-audit.md). The secure network boundary and its narrower confidentiality claim are described below; private application logs and backups still require protection.


`ExecutionAuthority` takes scoped coordinated storage (`CoordinatedStore` in TypeScript,
`ACECoordinatedStore` in Swift). `MemoryStore` and `FileStore` implement local coordination.
The optional `EtcdStore` backend pins a trusted etcd v3 cluster and fences every state access
against the acquired lease token. It exposes no unscoped data operations or offline fallback.
Use it for finite authority transactions, not long-lived receive locks. See document 10 for
configuration, trust assumptions, snapshot recovery restrictions and the real three-node tests.

### Authenticated secure delivery

Use `SecureTransport` around Outbox and `SecureMailbox` for network ingress. Each attempt
uses a fresh MLS group from the shared OpenMLS engine and ends with an authenticated
receipt after the original Inbox durably commits. `RelayClient.send` acknowledges relay
storage only; it is not an application-delivery receipt. Static application packets are
refused by SecureMailbox, with no downgrade fallback.

Both endpoints must explicitly enable the full peer identity through local policy;
discovery and principal roles do not enable communication or grant execution rights.
Revocation advances the policy generation, so re-enabling cannot revive old handshakes.
The receiver must be online; a timeout leaves the original Outbox operation pending.
Retry that operation ID. The receipt carries the receiver Inbox's verdict: `delivered` and
`duplicate` acknowledge the operation; a permanent rejection reaches the sender as
`delivery_rejected` (permanent, `remoteCode` = the Inbox code), which leaves the operation
pending for the host to abandon, never retried automatically. A retryable receiver failure
produces no receipt, and the attempt expires. The complete inner signed envelope is limited to 40,000 bytes,
and a handshake to 120 seconds. Keep HTTP timeouts bounded and callbacks idempotent.

After ephemeral state erasure, later static-key theft alone cannot decrypt captured past
application deliveries under classical MLS assumptions. Stored plaintext, original Outbox
envelopes and host snapshots are excluded. This is not post-quantum forward secrecy or
authentication. Independent cryptographic review remains a production-release gate.
See [the protocol and failure model](https://github.com/aceprotocol/ace-spec/blob/main/13-session-core.md)
and [source build/packaging](https://github.com/aceprotocol/ace-session-core#readme).

Swift: `NativeMLSEngine` (in `ACE`) adapts `SessionCoreEngine` from the `ace-session-core` package, which links the source-built XCFramework (see Build). `SecureTransport.setPeerAllowed`, `SecureMailbox` and `SecureRelayReplies` use the same ACEStore and original Inbox/Outbox. Keep the receiver alive across pulls or run `follow`.
