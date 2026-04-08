//
//  MessageValidationTests.swift
//  ACE SDK
//

import Testing
import Foundation
@testable import ACE

@Suite("Message Validation")
struct MessageValidationTests {

    // ============================================================
    // Body Schema Validation
    // ============================================================

    @Suite("body schema validation")
    struct BodySchemaValidation {

        @Test("validates rfq body - need is required")
        func rfqBody() throws {
            try validateBody(.rfq, ["need": "code review"])
            #expect(throws: ACEError.self) {
                try validateBody(.rfq, [:])
            }
        }

        @Test("validates offer body - price and currency required")
        func offerBody() throws {
            try validateBody(.offer, ["price": "3.50", "currency": "USD"])
            #expect(throws: ACEError.self) {
                try validateBody(.offer, ["price": "3.50"])
            }
            #expect(throws: ACEError.self) {
                try validateBody(.offer, ["currency": "USD"])
            }
            #expect(throws: ACEError.self) {
                try validateBody(.offer, [:])
            }
        }

        @Test("validates accept body - offerId required")
        func acceptBody() throws {
            try validateBody(.accept, ["offerId": "some-offer-id"])
            #expect(throws: ACEError.self) {
                try validateBody(.accept, [:])
            }
        }

        @Test("validates invoice body - offerId, amount, currency, settlementMethod required")
        func invoiceBody() throws {
            try validateBody(.invoice, [
                "offerId": "offer-1",
                "amount": "3.50",
                "currency": "USD",
                "settlementMethod": "crypto/instant",
            ])
            #expect(throws: ACEError.self) {
                try validateBody(.invoice, ["offerId": "offer-1"])
            }
            #expect(throws: ACEError.self) {
                try validateBody(.invoice, [:])
            }
        }

        @Test("validates receipt body - invoiceId, amount, currency, settlementMethod, proof required")
        func receiptBody() throws {
            try validateBody(.receipt, [
                "invoiceId": "inv-1",
                "amount": "3.50",
                "currency": "USD",
                "settlementMethod": "crypto/instant",
                "proof": ["txHash": "0xabc"] as [String: Any],
            ])
            #expect(throws: ACEError.self) {
                try validateBody(.receipt, [
                    "invoiceId": "inv-1",
                    "amount": "3.50",
                    "currency": "USD",
                    "settlementMethod": "crypto/instant",
                ])
            }
            #expect(throws: ACEError.self) {
                try validateBody(.receipt, [:])
            }
        }

        @Test("validates deliver body inline - content required")
        func deliverInlineBody() throws {
            try validateBody(.deliver, ["type": "inline", "content": "hello"])
            #expect(throws: ACEError.self) {
                try validateBody(.deliver, ["type": "inline"])
            }
        }

        @Test("validates deliver body reference - uri required")
        func deliverReferenceBody() throws {
            try validateBody(.deliver, ["type": "reference", "uri": "https://example.com/file"])
            #expect(throws: ACEError.self) {
                try validateBody(.deliver, ["type": "reference"])
            }
        }

        @Test("rejects invalid deliver.type")
        func deliverInvalidType() {
            #expect(throws: ACEError.self) {
                try validateBody(.deliver, ["type": "streaming", "content": "x"])
            }
        }

        @Test("validates confirm body - deliverId required")
        func confirmBody() throws {
            try validateBody(.confirm, ["deliverId": "del-1"])
            #expect(throws: ACEError.self) {
                try validateBody(.confirm, [:])
            }
        }

        @Test("validates text body - message required")
        func textBody() throws {
            try validateBody(.text, ["message": "hello"])
            #expect(throws: ACEError.self) {
                try validateBody(.text, [:])
            }
        }

        @Test("validates info body - message required")
        func infoBody() throws {
            try validateBody(.info, ["message": "system info"])
            #expect(throws: ACEError.self) {
                try validateBody(.info, [:])
            }
        }

        @Test("validates reject body - no required fields")
        func rejectBody() throws {
            try validateBody(.reject, [:])
            try validateBody(.reject, ["reason": "too expensive"])
        }

        @Test("rejects wrong required field types")
        func rejectsWrongRequiredFieldTypes() {
            #expect(throws: ACEError.self) {
                try validateBody(.invoice, [
                    "offerId": "550e8400-e29b-41d4-a716-446655440000",
                    "amount": ["3.50"],
                    "currency": "USD",
                    "settlementMethod": "crypto/instant",
                ])
            }
        }

        @Test("rejects wrong optional field types")
        func rejectsWrongOptionalFieldTypes() {
            #expect(throws: ACEError.self) {
                try validateBody(.offer, [
                    "price": "3.50",
                    "currency": "USD",
                    "ttl": true,
                ])
            }
        }

        @Test("rejects wrong system message type")
        func rejectsWrongSystemMessageType() {
            #expect(throws: ACEError.self) {
                try validateBody(.text, [
                    "message": ["hello": "world"],
                ])
            }
        }
    }

    // ============================================================
    // createMessage validation
    // ============================================================

    @Suite("createMessage validation")
    struct CreateMessageValidation {

        @Test("economic message requires threadId in createMessage")
        func economicRequiresThreadId() throws {
            let sender = try SoftwareIdentity.generate(scheme: .ed25519)
            let receiver = try SoftwareIdentity.generate(scheme: .ed25519)
            let sm = ThreadStateMachine()

            #expect(throws: ACEError.self) {
                try createMessage(CreateMessageOptions(
                    sender: sender,
                    recipientPubKey: receiver.getEncryptionPublicKey(),
                    recipientACEId: receiver.getACEId(),
                    type: .rfq,
                    body: ["need": "test"],
                    stateMachine: sm
                ))
            }
        }

        @Test("non-economic message allows no threadId")
        func nonEconomicAllowsNoThreadId() throws {
            let sender = try SoftwareIdentity.generate(scheme: .ed25519)
            let receiver = try SoftwareIdentity.generate(scheme: .ed25519)
            let sm = ThreadStateMachine()

            let msg = try createMessage(CreateMessageOptions(
                sender: sender,
                recipientPubKey: receiver.getEncryptionPublicKey(),
                recipientACEId: receiver.getACEId(),
                type: .text,
                body: ["message": "hi"],
                stateMachine: sm
            ))
            #expect(msg.type == .text)
            #expect(msg.threadId == nil)
        }

        @Test("state machine enforced on createMessage - can't send offer without rfq")
        func stateMachineEnforcedOnCreate() throws {
            let sender = try SoftwareIdentity.generate(scheme: .ed25519)
            let receiver = try SoftwareIdentity.generate(scheme: .ed25519)
            let sm = ThreadStateMachine()

            #expect(throws: Error.self) {
                try createMessage(CreateMessageOptions(
                    sender: sender,
                    recipientPubKey: receiver.getEncryptionPublicKey(),
                    recipientACEId: receiver.getACEId(),
                    type: .offer,
                    body: ["price": "10.00", "currency": "USD"],
                    stateMachine: sm,
                    threadId: "thread-1"
                ))
            }
        }
    }

    // ============================================================
    // parseMessage validation
    // ============================================================

    @Suite("parseMessage validation")
    struct ParseMessageValidation {

        @Test("state machine enforced on parseMessage")
        func stateMachineEnforcedOnParse() throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)
            let smCreate = ThreadStateMachine()
            let smParse = ThreadStateMachine()
            let detector = ReplayDetector()

            // Create a valid rfq message
            let rfqMsg = try createMessage(CreateMessageOptions(
                sender: alice,
                recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(),
                type: .rfq,
                body: ["need": "test"],
                stateMachine: smCreate,
                threadId: "t1"
            ))

            // Parse it once (should succeed)
            _ = try parseMessage(
                rfqMsg,
                receiver: bob,
                senderSigningPubKey: alice.getSigningPublicKey(),
                opts: ParseMessageOptions(stateMachine: smParse, replayDetector: detector)
            )

            // Parse the same rfq again should fail (replay or double rfq)
            #expect(throws: Error.self) {
                try parseMessage(
                    rfqMsg,
                    receiver: bob,
                    senderSigningPubKey: alice.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: smParse, replayDetector: detector)
                )
            }
        }

        @Test("rejects message with wrong sender key")
        func wrongSenderKey() throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)
            let mallory = try SoftwareIdentity.generate(scheme: .ed25519)
            let sm = ThreadStateMachine()

            let msg = try createMessage(CreateMessageOptions(
                sender: alice,
                recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(),
                type: .text,
                body: ["message": "hello"],
                stateMachine: sm
            ))

            // Try to parse with mallory's signing key instead of alice's
            #expect(throws: ACEError.self) {
                try parseMessage(
                    msg,
                    receiver: bob,
                    senderSigningPubKey: mallory.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine())
                )
            }
        }

        @Test("rejects tampered threadId because it is signed")
        func tamperedThreadIdRejected() throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)

            let msg = try createMessage(CreateMessageOptions(
                sender: alice,
                recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(),
                type: .rfq,
                body: ["need": "gpu rental"],
                stateMachine: ThreadStateMachine(),
                threadId: "deal-a"
            ))

            let tampered = ACEMessage(
                ace: msg.ace,
                messageId: msg.messageId,
                from: msg.from,
                to: msg.to,
                conversationId: msg.conversationId,
                type: msg.type,
                threadId: "deal-b",
                timestamp: msg.timestamp,
                encryption: msg.encryption,
                signature: msg.signature
            )

            #expect(throws: ACEError.self) {
                try parseMessage(
                    tampered,
                    receiver: bob,
                    senderSigningPubKey: alice.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: ReplayDetector())
                )
            }
        }

        @Test("rejects cross-thread references on create")
        func crossThreadReferenceRejectedOnCreate() throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)
            let sm = ThreadStateMachine()

            _ = try createMessage(CreateMessageOptions(
                sender: alice,
                recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(),
                type: .rfq,
                body: ["need": "gpu rental"],
                stateMachine: sm,
                threadId: "deal-a"
            ))
            let offerA = try createMessage(CreateMessageOptions(
                sender: bob,
                recipientPubKey: alice.getEncryptionPublicKey(),
                recipientACEId: alice.getACEId(),
                type: .offer,
                body: ["price": "10", "currency": "USD"],
                stateMachine: sm,
                threadId: "deal-a"
            ))
            _ = try createMessage(CreateMessageOptions(
                sender: alice,
                recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(),
                type: .accept,
                body: ["offerId": offerA.messageId],
                stateMachine: sm,
                threadId: "deal-a"
            ))
            _ = try createMessage(CreateMessageOptions(
                sender: alice,
                recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(),
                type: .rfq,
                body: ["need": "design review"],
                stateMachine: sm,
                threadId: "deal-b"
            ))
            let offerB = try createMessage(CreateMessageOptions(
                sender: bob,
                recipientPubKey: alice.getEncryptionPublicKey(),
                recipientACEId: alice.getACEId(),
                type: .offer,
                body: ["price": "20", "currency": "USD"],
                stateMachine: sm,
                threadId: "deal-b"
            ))
            _ = try createMessage(CreateMessageOptions(
                sender: alice,
                recipientPubKey: bob.getEncryptionPublicKey(),
                recipientACEId: bob.getACEId(),
                type: .accept,
                body: ["offerId": offerB.messageId],
                stateMachine: sm,
                threadId: "deal-b"
            ))

            #expect(throws: Error.self) {
                try createMessage(CreateMessageOptions(
                    sender: bob,
                    recipientPubKey: alice.getEncryptionPublicKey(),
                    recipientACEId: alice.getACEId(),
                    type: .invoice,
                    body: [
                        "offerId": offerA.messageId,
                        "amount": "20",
                        "currency": "USD",
                        "settlementMethod": "crypto/instant",
                    ],
                    stateMachine: sm,
                    threadId: "deal-b"
                ))
            }
        }
    }
}
