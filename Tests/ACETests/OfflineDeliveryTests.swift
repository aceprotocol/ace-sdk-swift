import Foundation
import Testing
@testable import ACE

struct OfflineDeliveryTests {
    @Test func boundedOfflineDelivery() throws {
        let alice = try SoftwareIdentity.generate(scheme: .ed25519)
        let bob = try SoftwareIdentity.generate(scheme: .ed25519)
        let now = Int(Date().timeIntervalSince1970)
        func message(_ timestamp: Int) throws -> ACEMessage {
            try createMessage(CreateMessageOptions(sender: alice, recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(), type: .text, body: ["message": "offline"],
                stateMachine: ThreadStateMachine(), timestamp: timestamp))
        }
        let old = try message(now - 3600)
        var opts = ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: ReplayDetector(ttlSeconds: 7200 + maxDriftSeconds),
                                      senderEncryptionPubKey: alice.getEncryptionPublicKey())
        #expect(throws: (any Error).self) { try parseMessage(old, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(), opts: opts) }
        opts.oldestTimestamp = now - 7200
        let parsed = try parseMessage(old, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(), opts: opts)
        #expect(parsed.body["message"] as? String == "offline")
        #expect(throws: (any Error).self) { try parseMessage(old, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(), opts: opts) }
        for timestamp in [now + 3600, now - 7201] {
            #expect(throws: (any Error).self) { try parseMessage(message(timestamp), receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(), opts: opts) }
        }
        // Default 300 s TTL would evict the id while it is still above the floor.
        opts.replayDetector = ReplayDetector()
        #expect(throws: (any Error).self) { try parseMessage(message(now - 60), receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(), opts: opts) }
        opts.replayDetector = nil
        #expect(throws: (any Error).self) { try parseMessage(old, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(), opts: opts) }
    }
}
