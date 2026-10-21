# ACE Protocol Swift SDK

Swift implementation of the [ACE Protocol](https://aceprotocol.org) (packet `"1"`): post-quantum identities on a key event
log, asynchronous prekey-encrypted packets, signed descriptors, receipts, admission and data-only profiles. ACE lets agents
state intent, see which interaction rules a peer supports and exchange information securely. Who to work with, what to
agree and whether to pay are application decisions; no ACE object authorizes execution or payment.

One library product, `ACE`. No binary or chain dependencies (CryptoKit only).

## Requirements

- Swift 6.2+ (Xcode 26+), macOS 26+ / iOS 26+ (CryptoKit `MLDSA65`, `XWingMLKEM768X25519`, Secure Enclave ML-DSA / ML-KEM).

## What is in it

| Layer | API |
|---|---|
| Identity | `SoftwareIdentity`, `SecureEnclaveIdentity` (an `ml-dsa-65` root, a committed next root, one delegated `ml-dsa-65` signing key), `ACEKel`, `checkUsable`; exports hold no encryption seed (`jsonData()` / `init(json:)`) |
| Prekeys | `PrekeyVault` (`current`, `rotate(now:)`, `open(_:now:)`, `prune(now:)`), `StorePrekeyVault(store:protection:)` over `MemoryStore` / `FileStore`, `.secureEnclave` seals seeds with Secure Enclave ML-KEM |
| Packet | `createPacket`, `Packet(json:)`, `verifyPacketSignature`, `decryptPacket`, `PrivateContent`, `conversationKey` |
| Documents | `createPublishedAgent` / `verifyPublishedAgent` (`DescriptorClaims`), `createCardRecord` / `verifyCardBundle` (`CardRecord`, `AgentCard`, `Contact`), `createDelegation` / `verifyDelegation`, `createPermit` / `verifyPermit` (30 days), `ERC8004Binding`, `verifyErc8004Registration` |
| Profiles | `ProfileManifest` (`.core`, `.text`, `.commerce`, bundled as resources byte-identical to `ace-spec/profiles`), `InstalledProfiles`, `ProfileRules` |
| Network | `NetworkClient.open(...)`: `publish(force:)` (registers on demand), `discover`, `importAgent`, `lookup(_:)` (ACE ID or `@name@relay`), `lookupWithCard(_:)` (`lookup` plus the verified card record, nil when it has none), `lookupCard(_:)`, `agent(_:refresh:)`, `connect(_:profile:note:)`, `requests()` (pending `ContactRequest`s), `accept`, `reject`, `block`, `unblock`, `setWake(gateway:token:)` / `clearWake()` (07 § Wake hints, optional), `createInvitation(peer:profile:)` / `importInvitation` (`Invitation` = `{agent, permit}`), `send(to:type:body:threadId:)`, `flush()`, `pull(limit:maxPages:)` (`maxPages` bounds one pass), `follow()`, `maintain()`, `close()`; `onMessage` / `onReceipt` in `NetworkConfiguration` |
| Relay | `RelayClient` (07 binding, client side) and `RelayClient.foreign(_:)`, the default client for relays named by peers (https only, blocked addresses refused) |
| State | `ACEStore` (`MemoryStore`, `FileStore`; `validateStoreKey` / `validateStoreValue` / `validateLockName`, `NamedMutexes` and `lockTimeoutError` for a custom store), `PeerStore`, `AdmissionTable`, `Outbox` (re-encrypt per attempt, backoff, persisted lease, receipts) |
| Optional | `commerceRules(store:localAceId:)` + `ThreadStore` for `ace:commerce:1` (stablecoin / Stripe Link settlement shapes) |
| Other | `createAuthHeaders`, `createRegistrationRequest`, one error type `ACEError` |

Relay-side verification (auth headers, registration requests) is provided by the TypeScript SDK only.

## Quick start

[`Examples/Quickstart/main.swift`](Examples/Quickstart/main.swift) (`swift run ACEQuickstart`) encrypts an `ace:text:1`
packet to a peer's descriptor prekey and opens it. Over a relay:

```swift
let network = try await NetworkClient.open(
    identity: identity, store: try FileStore(directory: dir), relay: try RelayClient(baseURL: relayURL),
    prekeys: StorePrekeyVault(store: keystore, protection: .secureEnclave),
    configuration: NetworkConfiguration(profiles: [.text], handle: "bob", contact: .open, listed: true,
                                        onMessage: { message in /* persist idempotently by (from, messageId) */ },
                                        onReceipt: { from, body, entry in /* delivery confirmed or rejected */ }))
try await network.publish()                 // descriptor, then card record; registers the identity when needed
try await network.connect(peerId, profile: "ace:text:1", note: "hi")
try await network.pull()                    // contact replies, messages, receipts
try await network.send(to: peerId, type: "ace:text:1", body: ["message": "hello"])
try await network.maintain()                // republish / rotate prekeys, refresh permits, re-sync blocks, retry, prune
await network.close()
```

The host calls `maintain()` once at start and then at least every 3600 seconds.

Relays named in peers' descriptors are reached through `RelayClient.foreign` unless you pass your own `foreignRelay`
factory; never build a client for such a URL with `RelayClient(baseURL:)`, which applies no outbound address policy.

## Security

- **Peer relays (07 § Client rules, blocked addresses).** `RelayClient.foreign` accepts `https` only, follows no
  redirects, keeps no cookies or credentials, and resolves the relay's host and refuses any blocked address before every
  request and every listen reconnect. It cannot pin the connection to the checked address: URLSession resolves the name
  again when it connects, so a DNS answer that changes in between (rebinding) is not caught, and the 07 requirement to
  connect only to a validated address is not fully met. A host that needs full conformance passes its own `foreignRelay`
  to `NetworkClient.open`, for example a client whose session goes through an egress proxy enforcing the blocked-address
  policy.
- **Keys.** Prefer `SecureEnclaveIdentity` and `StorePrekeyVault(protection: .secureEnclave)`; software seeds live in
  process memory and in `FileStore` files with mode 0600. Printing an identity or an export never shows key material.
- **Secure Enclave keys are device-bound, not user-presence bound.** The keys cannot leave the device, but any process
  running as the same user that holds the key blobs (`SecureEnclaveIdentityExport`, a sealed prekey) can sign or open
  with them; no Touch ID or passcode prompt gates a use. Protect the blobs like the user's other credentials.
- **Stores.** `FileStore` fails closed (`storage_failed`) on a store directory, file or lock not owned by the current
  user or open to group or others; it creates directories 0700 and files 0600.

## Testing

```sh
swift test
ACE_KEY_PROVIDER=secure-enclave swift test   # the same suite on Secure Enclave identities
```

`Tests/ACETests/Fixtures/test-vectors.json` is a byte-identical copy of `ace-spec/test-vectors.json`
(`ace-spec/scripts/check-sdk-artifacts.py` checks it, the bundled manifests and the limit constants). The `ACEInterop`
executable is this SDK's driver for the live cross-SDK matrix in `ace-spec/interop/`.
