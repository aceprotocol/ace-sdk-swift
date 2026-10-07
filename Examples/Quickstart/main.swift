import ACE
import Foundation

// MARK: 1. Pure local: create and parse one message

let alice = try SoftwareIdentity.generate(scheme: .ed25519)
let bob = try SoftwareIdentity.generate(scheme: .ed25519)

// Keys are trusted here because both identities were created locally; in production a
// VerifiedPeer comes from PeerStore / RelayClient / verifyRegistrationFile.
let bobPeer = try verifyRegistrationFile(createRegistrationFile(for: bob, name: "Bob", endpoint: "https://bob.example/ace"))
let alicePeer = try verifyRegistrationFile(createRegistrationFile(for: alice, name: "Alice", endpoint: "https://alice.example/ace"))

let rfq = try createMessage(
    sender: alice, recipient: bobPeer, type: .rfq,
    body: ["need": "Translate 500 words EN→FR", "maxPrice": "10", "currency": "USDC"],
    threads: ThreadStateMachine(localAceId: alice.getACEId()),
    threadId: "translation-1"
)
let parsed = try parseMessage(
    rfq, receiver: bob, sender: alicePeer,
    threads: ThreadStateMachine(localAceId: bob.getACEId()),
    replay: ReplayDetector()
)
precondition(parsed.body["need"]?.stringValue == "Translate 500 words EN→FR")
print("local:", parsed.type, parsed.body)

// MARK: 2. Pipeline: Outbox → transport → Inbox, with durable state

// Each agent keeps its state in an ACEStore (FileStore(directory:) on disk).
let aliceStore = MemoryStore()
let bobStore = MemoryStore()
// With a relay: `let relay = try RelayClient(baseURL: URL(string: "https://relay.aceprotocol.org")!)`
// and `PeerStore(store:relay:)`; peers are then resolved and pinned from the relay.
let alicePeers = try PeerStore(store: aliceStore)
let bobPeers = try PeerStore(store: bobStore)
let bobPinned = try await alicePeers.pinRegistrationFile(createRegistrationFile(for: bob, name: "Bob", endpoint: "https://bob.example/ace"))
try await bobPeers.pinRegistrationFile(createRegistrationFile(for: alice, name: "Alice", endpoint: "https://alice.example/ace"))

// onMessage must persist the host effect idempotently, keyed by (from, messageId).
let inbox = try await Inbox.open(identity: bob, store: bobStore, peers: bobPeers) { message in
    print("bob received:", message.type, message.body)
}
let outbox = try await Outbox.open(identity: alice, store: aliceStore)

let staged = try await outbox.stage(recipient: bobPinned, type: .rfq, body: ["need": "Summarize a PDF"], threadId: "job-42")
// With a relay: `try await outbox.deliver(staged.requestId) { try await relay.send($0) }`
// and on the receiving side `await inbox.pull(relay).messages` or `for try await o in inbox.follow(relay)`.
try await outbox.deliver(staged.requestId) { envelope in
    let outcome = try await inbox.receive(envelope.jsonData(), source: .direct)
    guard case .delivered = outcome else { throw outcome.error ?? ACEError(.relayRejected) }
}
let threads = try ThreadStore(store: bobStore, localAceId: bob.getACEId())
let state = try threads.get(conversationId: staged.message.conversationId, threadId: "job-42")?.state
print("bob's thread state:", state?.rawValue ?? "none")
await inbox.close()
