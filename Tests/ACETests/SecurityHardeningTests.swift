//
//  SecurityHardeningTests.swift
//  ACE SDK
//
//  Security hardening tests: thread safety, edge cases, tampering detection.
//

import Testing
import Foundation
@testable import ACE

@Suite("Security Hardening")
struct SecurityHardeningTests {

    // ============================================================
    // ReplayDetector thread safety
    // ============================================================

    @Suite("ReplayDetector thread safety")
    struct ReplayDetectorConcurrency {
        static let t = 1_800_000_000

        @Test("handles multiple concurrent commits without crash")
        func concurrentAccess() {
            let detector = ReplayDetector(capacity: 10_000, horizon: Self.t - maxDriftSeconds)
            let iterations = 1000

            DispatchQueue.concurrentPerform(iterations: iterations) { i in
                _ = detector.commit("msg-\(i)", from: "ace:sha256:alice", timestamp: Self.t, floor: Self.t - maxDriftSeconds)
            }

            // All should have been committed (no crash, no data corruption)
            let committed = (0..<iterations).filter { !detector.accepts("msg-\($0)", from: "ace:sha256:alice", timestamp: Self.t) }
            #expect(committed.count == iterations)
        }

        @Test("concurrent commit returns true exactly once per id")
        func concurrentUniqueCommit() {
            let detector = ReplayDetector(capacity: 10_000, horizon: Self.t - maxDriftSeconds)
            let id = "contested-msg"
            let iterations = 100
            var successCount = 0
            let lock = NSLock()

            DispatchQueue.concurrentPerform(iterations: iterations) { _ in
                if detector.commit(id, from: "ace:sha256:alice", timestamp: Self.t, floor: Self.t - maxDriftSeconds) {
                    lock.lock()
                    successCount += 1
                    lock.unlock()
                }
            }

            #expect(successCount == 1, "Only one thread should succeed in committing")
        }
    }

    // ============================================================
    // Timestamp edge cases
    // ============================================================

    @Suite("timestamp edge cases")
    struct TimestampEdgeCases {

        @Test("accepts timestamp exactly at 300s boundary")
        func exactlyAtBoundary() throws {
            let nowTs = 1_000_000
            // 300s in the past
            try checkTimestampFreshness(nowTs - 300, now: nowTs)
            // 300s in the future
            try checkTimestampFreshness(nowTs + 300, now: nowTs)
        }

        @Test("rejects timestamp just over 300s boundary")
        func justOverBoundary() {
            let nowTs = 1_000_000
            #expect(throws: ACEError.self) {
                try checkTimestampFreshness(nowTs - 301, now: nowTs)
            }
            #expect(throws: ACEError.self) {
                try checkTimestampFreshness(nowTs + 301, now: nowTs)
            }
        }

        @Test("handles zero timestamp")
        func zeroTimestamp() {
            // With a reasonable "now", 0 is far in the past
            #expect(throws: ACEError.self) {
                try checkTimestampFreshness(0, now: 1_000_000)
            }
        }

        @Test("handles negative timestamp")
        func negativeTimestamp() {
            #expect(throws: ACEError.self) {
                try checkTimestampFreshness(-1, now: 1_000_000)
            }
        }
    }

    // ============================================================
    // Message tampering detection
    // ============================================================

    @Suite("message tampering")
    struct MessageTampering {

        @Test("parse message with wrong sender key is rejected")
        func wrongSenderKey() throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)
            let mallory = try SoftwareIdentity.generate(scheme: .ed25519)
            let smCreate = ThreadStateMachine()

            let msg = try createMessage(CreateMessageOptions(
                sender: alice,
                recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(),
                type: .text,
                body: ["message": "hello"],
                stateMachine: smCreate
            ))

            // Parse with wrong signing key — should be rejected
            #expect(throws: ACEError.self) {
                try parseMessage(
                    msg,
                    receiver: bob,
                    senderSigningPubKey: mallory.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: ReplayDetector())
                )
            }
        }

        @Test("message with tampered type field rejected by signature verification")
        func tamperedTypeField() throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)
            let smCreate = ThreadStateMachine()

            let msg = try createMessage(CreateMessageOptions(
                sender: alice,
                recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(),
                type: .text,
                body: ["message": "hello"],
                stateMachine: smCreate
            ))

            // Tamper with the type field (text -> info)
            let tampered = ACEMessage(
                ace: msg.ace,
                messageId: msg.messageId,
                from: msg.from,
                to: msg.to,
                conversationId: msg.conversationId,
                type: .info,  // tampered!
                threadId: msg.threadId,
                timestamp: msg.timestamp,
                encryption: msg.encryption,
                signature: msg.signature
            )

            // Signature was computed with "text" type, so this should fail
            #expect(throws: ACEError.self) {
                try parseMessage(
                    tampered,
                    receiver: bob,
                    senderSigningPubKey: alice.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: ReplayDetector())
                )
            }
        }

        @Test("message addressed to wrong recipient is rejected")
        func wrongRecipient() throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)
            let charlie = try SoftwareIdentity.generate(scheme: .ed25519)
            let smCreate = ThreadStateMachine()

            let msg = try createMessage(CreateMessageOptions(
                sender: alice,
                recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(),
                type: .text,
                body: ["message": "hello"],
                stateMachine: smCreate
            ))

            // Try to parse as charlie — msg.to won't match charlie's ACE ID
            #expect(throws: ACEError.self) {
                try parseMessage(
                    msg,
                    receiver: charlie,
                    senderSigningPubKey: alice.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: ReplayDetector())
                )
            }
        }
    }

    // ============================================================
    // Empty payload handling
    // ============================================================

    @Suite("empty payload handling")
    struct EmptyPayloadHandling {

        @Test("rejects message with empty payload string")
        func emptyPayloadString() throws {
            let sender = try SoftwareIdentity.generate(scheme: .ed25519)
            let receiver = try SoftwareIdentity.generate(scheme: .ed25519)

            let msg = ACEMessage(
                messageId: UUID().uuidString.lowercased(),
                from: sender.getACEId(),
                to: receiver.getACEId(),
                conversationId: String(repeating: "a", count: 64),
                type: .text,
                timestamp: Int(Date().timeIntervalSince1970),
                encryption: EncryptionEnvelope(
                    kemCiphertext: ACEBase64.encode(Data(repeating: 1, count: 1120)),
                    payload: ""
                ),
                signature: SignatureEnvelope(
                    scheme: .ed25519,
                    value: ACEBase64.encode(Data(repeating: 0, count: 64))
                )
            )

            #expect(throws: Error.self) {
                try parseMessage(
                    msg,
                    receiver: receiver,
                    senderSigningPubKey: sender.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: ReplayDetector())
                )
            }
        }
    }

    // ============================================================
    // StateMachine thread safety
    // ============================================================

    @Suite("StateMachine thread safety")
    struct StateMachineThreadSafety {

        @Test("concurrent transitions to different threads don't corrupt state")
        func concurrentDifferentThreads() throws {
            let sm = ThreadStateMachine()
            let convId = String(repeating: "c", count: 64)
            let iterations = 100

            DispatchQueue.concurrentPerform(iterations: iterations) { i in
                let threadId = "thread-\(i)"
                do {
                    try sm.transition(conversationId: convId, threadId: threadId, messageType: .rfq, messageId: UUID().uuidString.lowercased(), timestamp: Int(Date().timeIntervalSince1970))
                } catch {
                    // Some may fail due to timing — that's fine for this test
                }
            }

            // Verify state consistency: each thread that was transitioned should be in .rfq
            var rfqCount = 0
            for i in 0..<iterations {
                let state = sm.getState(conversationId: convId, threadId: "thread-\(i)")
                if state == .rfq {
                    rfqCount += 1
                } else {
                    #expect(state == .idle, "State should be idle or rfq, not \(state)")
                }
            }
            #expect(rfqCount == iterations, "All threads should have transitioned to rfq")
        }
    }
}
