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

    // ============================================================
    // Replay reservation lifecycle
    // ============================================================

    @Suite("replay reservation")
    struct ReplayReservation {

        @Test("a validly signed message whose decryption fails still consumes the messageId")
        func decryptionFailureAfterValidSignatureConsumesMessageId() throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)
            // Same signing key as bob (so `to` matches), different X-Wing seed: the
            // signature verifies, decryption fails.
            let bobExport = bob.exportPrivateKey()
            let bobWrongSeed = try SoftwareIdentity.fromExport(SoftwareIdentityExport(
                scheme: bobExport.scheme,
                signingPrivateKey: bobExport.signingPrivateKey,
                encryptionPrivateKey: ACEBase64.encode(ACEEncryption.generateSeed())
            ))
            #expect(bobWrongSeed.getACEId() == bob.getACEId())

            let msg = try createMessage(CreateMessageOptions(
                sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(),
                type: .text, body: ["message": "hi"], stateMachine: ThreadStateMachine()
            ))
            let detector = ReplayDetector()

            #expect(throws: (any Error).self) {
                try parseMessage(
                    msg, receiver: bobWrongSeed, senderSigningPubKey: alice.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: detector)
                )
            }

            // The signature verified, so the messageId is one-shot: the genuine
            // message with the same id is now rejected as a replay.
            let err = #expect(throws: ACEError.self) {
                try parseMessage(
                    msg, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: detector)
                )
            }
            if case .replayDetected? = err {} else {
                Issue.record("expected replayDetected, got \(String(describing: err))")
            }
        }

        @Test("a failure before signature verification releases the reservation")
        func preSignatureFailureReleasesReservation() throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)
            let msg = try createMessage(CreateMessageOptions(
                sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(),
                type: .text, body: ["message": "hi"], stateMachine: ThreadStateMachine()
            ))
            // Same messageId, malformed kemCiphertext: rejected before the signature check.
            let bad = ACEMessage(
                ace: msg.ace, messageId: msg.messageId, from: msg.from, to: msg.to,
                conversationId: msg.conversationId, type: msg.type, threadId: msg.threadId, timestamp: msg.timestamp,
                encryption: EncryptionEnvelope(
                    kemCiphertext: ACEBase64.encode(Data(repeating: 0xAA, count: 1119)),
                    payload: msg.encryption.payload
                ),
                signature: msg.signature
            )
            let detector = ReplayDetector()

            #expect(throws: ACEError.self) {
                try parseMessage(
                    bad, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: detector)
                )
            }

            // Reservation released: the genuine message parses with the same detector.
            let parsed = try parseMessage(
                msg, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(),
                opts: ParseMessageOptions(stateMachine: ThreadStateMachine(), replayDetector: detector)
            )
            #expect(parsed.body["message"] as? String == "hi")
        }
    }

    // ============================================================
    // kemCiphertext length validation
    // ============================================================

    @Suite("kemCiphertext length validation")
    struct KEMCiphertextLength {

        @Test("message envelope carries a 1120-byte kemCiphertext")
        func envelopeLength() throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)
            let msg = try createMessage(CreateMessageOptions(
                sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(),
                type: .text, body: ["message": "hi"], stateMachine: ThreadStateMachine()
            ))
            #expect(try ACEBase64.decode(msg.encryption.kemCiphertext).count == 1120)
        }

        @Test("rejects an off-by-one kemCiphertext before signature check and decapsulation",
              arguments: [1119, 1121])
        func rejectsWrongLength(count: Int) throws {
            let alice = try SoftwareIdentity.generate(scheme: .ed25519)
            let bob = try SoftwareIdentity.generate(scheme: .ed25519)
            let msg = try createMessage(CreateMessageOptions(
                sender: alice, recipientPubKey: bob.getEncryptionPublicKey(), recipientACEId: bob.getACEId(),
                type: .text, body: ["message": "hi"], stateMachine: ThreadStateMachine()
            ))
            let bad = ACEMessage(
                ace: msg.ace, messageId: msg.messageId, from: msg.from, to: msg.to,
                conversationId: msg.conversationId, type: msg.type, threadId: msg.threadId, timestamp: msg.timestamp,
                encryption: EncryptionEnvelope(
                    kemCiphertext: ACEBase64.encode(Data(repeating: 0xAA, count: count)),
                    payload: msg.encryption.payload
                ),
                // Garbage signature: if length validation did not run first we would see
                // signatureVerificationFailed instead of the invalidMessage length error.
                signature: SignatureEnvelope(scheme: .ed25519, value: ACEBase64.encode(Data(repeating: 0, count: 64)))
            )
            let err = #expect(throws: ACEError.self) {
                try parseMessage(
                    bad, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(),
                    opts: ParseMessageOptions(stateMachine: ThreadStateMachine())
                )
            }
            if case .invalidMessage(let text)? = err {
                #expect(text.contains("kemCiphertext"))
                #expect(text.contains("1120"))
            } else {
                Issue.record("expected invalidMessage length error for count=\(count), got \(String(describing: err))")
            }
        }
    }
}
