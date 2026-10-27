import ACE
import Foundation

// Two identities. `SecureEnclaveIdentity.generate()` keeps the roots and the signing key in the Secure Enclave.
let alice = try SoftwareIdentity.generate()
let bob = try SoftwareIdentity.generate()

// Bob's prekeys (use `FileStore` and `.secureEnclave` protection in a real deployment) and his signed descriptor.
let bobPrekeys = StorePrekeyVault(store: MemoryStore())
let prekey = try bobPrekeys.rotate(now: systemClock()).prekey
let text = try InstalledProfiles([.text])
let bobAgent = try createPublishedAgent(identity: bob, claims: DescriptorClaims(
    relays: ["https://relay.aceprotocol.org"], prekey: prekey, profiles: text.refs))

// Alice verifies Bob's PublishedAgent (its keys come only from the verified KEL and descriptor) and sends a text packet.
let verifiedBob = try verifyPublishedAgent(bobAgent.source, now: systemClock())
let content = try text.content(type: "ace:text:1", body: ["message": "Hello, Bob"])
let packet = try createPacket(sender: alice, to: verifiedBob.aceId, prekey: verifiedBob.descriptor.prekey, content: content)

// On the wire the packet is canonical JSON; Bob decodes it strictly, checks Alice's signature against her KEL and
// decrypts it with his prekey.
let received = try Packet(json: packet.jsonData())
let aliceKel = try ACEKel.verify(alice.getKel(), now: systemClock())
try verifyPacketSignature(received, sender: aliceKel, now: systemClock())
let opened = try PrivateContent(json: try decryptPacket(received, vault: bobPrekeys, now: systemClock()))
try text.validate(opened)
print(opened.type, opened.body["message"]?.stringValue ?? "")

// Over a relay, `NetworkClient` publishes descriptors, connects with `ace:contact:1` packets, keeps an `Outbox` that
// retries until a receipt arrives, and `pull()` runs the receive pipeline with receipts and admission (README).
