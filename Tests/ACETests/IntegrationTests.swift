//
//  IntegrationTests.swift
//  ACE SDK
//
//  End-to-end message flow tests: RFQ -> Offer -> Accept
//

import Testing
import Foundation
@testable import ACE

@Suite("Integration")
struct IntegrationTests {

    @Test("ed25519 <-> ed25519 message roundtrip")
    func ed25519Roundtrip() throws {
        let alice = try SoftwareIdentity.generate(scheme: .ed25519)
        let bob = try SoftwareIdentity.generate(scheme: .ed25519)
        let sm = ThreadStateMachine()

        // Alice -> Bob: text message
        let msg = try createMessage(CreateMessageOptions(
            sender: alice,
            recipientPubKey: bob.getEncryptionPublicKey(),
            recipientACEId: bob.getACEId(),
            type: .text,
            body: ["message": "hello from alice"],
            stateMachine: sm
        ))

        #expect(msg.ace == "1.0")
        #expect(msg.from == alice.getACEId())
        #expect(msg.to == bob.getACEId())
        #expect(msg.type == .text)

        let parsed = try parseMessage(
            msg,
            receiver: bob,
            senderSigningPubKey: alice.getSigningPublicKey(),
            opts: ParseMessageOptions(
                stateMachine: sm,
                expectedScheme: .ed25519,
                senderEncryptionPubKey: alice.getEncryptionPublicKey()
            )
        )

        #expect(parsed.body["message"] as? String == "hello from alice")
    }

    @Test("secp256k1 <-> secp256k1 message roundtrip")
    func secp256k1Roundtrip() throws {
        let alice = try SoftwareIdentity.generate(scheme: .secp256k1)
        let bob = try SoftwareIdentity.generate(scheme: .secp256k1)
        let smCreate = ThreadStateMachine()
        let smParse = ThreadStateMachine()

        let msg = try createMessage(CreateMessageOptions(
            sender: alice,
            recipientPubKey: bob.getEncryptionPublicKey(),
            recipientACEId: bob.getACEId(),
            type: .rfq,
            body: ["need": "code review"],
            stateMachine: smCreate,
            threadId: "thread-1"
        ))

        let parsed = try parseMessage(
            msg,
            receiver: bob,
            senderSigningPubKey: alice.getSigningPublicKey(),
            opts: ParseMessageOptions(stateMachine: smParse, expectedScheme: .secp256k1, replayDetector: ReplayDetector())
        )

        #expect(parsed.body["need"] as? String == "code review")
    }

    @Test("cross-scheme: ed25519 -> secp256k1")
    func crossScheme() throws {
        let alice = try SoftwareIdentity.generate(scheme: .ed25519)
        let bob = try SoftwareIdentity.generate(scheme: .secp256k1)
        let smCreate = ThreadStateMachine()
        let smParse = ThreadStateMachine()

        // Send RFQ first to advance state machine
        let rfq = try createMessage(CreateMessageOptions(
            sender: alice,
            recipientPubKey: bob.getEncryptionPublicKey(),
            recipientACEId: bob.getACEId(),
            type: .rfq,
            body: ["need": "cross-scheme test"],
            stateMachine: smCreate,
            threadId: "thread-1"
        ))
        _ = try parseMessage(
            rfq,
            receiver: bob,
            senderSigningPubKey: alice.getSigningPublicKey(),
            opts: ParseMessageOptions(stateMachine: smParse, expectedScheme: .ed25519, replayDetector: ReplayDetector())
        )

        // Now send offer
        let msg = try createMessage(CreateMessageOptions(
            sender: alice,
            recipientPubKey: bob.getEncryptionPublicKey(),
            recipientACEId: bob.getACEId(),
            type: .offer,
            body: ["price": "100", "currency": "USDC"],
            stateMachine: smCreate,
            threadId: "thread-1"
        ))

        let parsed = try parseMessage(
            msg,
            receiver: bob,
            senderSigningPubKey: alice.getSigningPublicKey(),
            opts: ParseMessageOptions(stateMachine: smParse, expectedScheme: .ed25519, replayDetector: ReplayDetector())
        )

        #expect(parsed.body["price"] as? String == "100")
        #expect(parsed.body["currency"] as? String == "USDC")
    }

    @Test("RFQ -> Offer -> Accept flow")
    func rfqOfferAcceptFlow() throws {
        let buyer = try SoftwareIdentity.generate(scheme: .ed25519)
        let seller = try SoftwareIdentity.generate(scheme: .secp256k1)
        let detector = ReplayDetector(capacity: 100)
        let smCreate = ThreadStateMachine()
        let smParse = ThreadStateMachine()

        // 1. Buyer -> Seller: RFQ
        let rfq = try createMessage(CreateMessageOptions(
            sender: buyer,
            recipientPubKey: seller.getEncryptionPublicKey(),
            recipientACEId: seller.getACEId(),
            type: .rfq,
            body: ["need": "translate document"],
            stateMachine: smCreate,
            threadId: "deal-1"
        ))
        let parsedRfq = try parseMessage(
            rfq, receiver: seller, senderSigningPubKey: buyer.getSigningPublicKey(),
            opts: ParseMessageOptions(stateMachine: smParse, replayDetector: detector)
        )
        #expect(parsedRfq.type == .rfq)

        // 2. Seller -> Buyer: Offer
        let offer = try createMessage(CreateMessageOptions(
            sender: seller,
            recipientPubKey: buyer.getEncryptionPublicKey(),
            recipientACEId: buyer.getACEId(),
            type: .offer,
            body: ["price": "50", "currency": "USDC"],
            stateMachine: smCreate,
            threadId: "deal-1"
        ))
        let parsedOffer = try parseMessage(
            offer, receiver: buyer, senderSigningPubKey: seller.getSigningPublicKey(),
            opts: ParseMessageOptions(stateMachine: smParse, replayDetector: detector)
        )
        #expect(parsedOffer.type == .offer)
        #expect(parsedOffer.threadId == "deal-1")

        // 3. Buyer -> Seller: Accept
        let accept = try createMessage(CreateMessageOptions(
            sender: buyer,
            recipientPubKey: seller.getEncryptionPublicKey(),
            recipientACEId: seller.getACEId(),
            type: .accept,
            body: ["offerId": offer.messageId],
            stateMachine: smCreate,
            threadId: "deal-1"
        ))
        let parsedAccept = try parseMessage(
            accept, receiver: seller, senderSigningPubKey: buyer.getSigningPublicKey(),
            opts: ParseMessageOptions(stateMachine: smParse, replayDetector: detector)
        )
        #expect(parsedAccept.type == .accept)
    }

    @Test("replay is detected")
    func replayDetection() throws {
        let alice = try SoftwareIdentity.generate(scheme: .ed25519)
        let bob = try SoftwareIdentity.generate(scheme: .ed25519)
        let detector = ReplayDetector(capacity: 100)
        let sm = ThreadStateMachine()

        let msg = try createMessage(CreateMessageOptions(
            sender: alice,
            recipientPubKey: bob.getEncryptionPublicKey(),
            recipientACEId: bob.getACEId(),
            type: .text,
            body: ["message": "test"],
            stateMachine: sm
        ))

        // First parse succeeds
        _ = try parseMessage(
            msg, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(),
            opts: ParseMessageOptions(stateMachine: sm, replayDetector: detector)
        )

        // Second parse fails (replay)
        #expect(throws: ACEError.self) {
            _ = try parseMessage(
                msg, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(),
                opts: ParseMessageOptions(stateMachine: sm, replayDetector: detector)
            )
        }
    }

    @Test("wrong recipient rejects message")
    func wrongRecipient() throws {
        let alice = try SoftwareIdentity.generate(scheme: .ed25519)
        let bob = try SoftwareIdentity.generate(scheme: .ed25519)
        let eve = try SoftwareIdentity.generate(scheme: .ed25519)
        let sm = ThreadStateMachine()

        let msg = try createMessage(CreateMessageOptions(
            sender: alice,
            recipientPubKey: bob.getEncryptionPublicKey(),
            recipientACEId: bob.getACEId(),
            type: .text,
            body: ["message": "for bob only"],
            stateMachine: sm
        ))

        // Eve tries to parse
        #expect(throws: ACEError.self) {
            _ = try parseMessage(
                msg, receiver: eve, senderSigningPubKey: alice.getSigningPublicKey(),
                opts: ParseMessageOptions(stateMachine: sm)
            )
        }
    }

    @Test("parse from registration file")
    func parseFromRegistration() throws {
        let sender = try SoftwareIdentity.generate(scheme: .secp256k1)
        let receiver = try SoftwareIdentity.generate(scheme: .ed25519)
        let sm = ThreadStateMachine()

        let reg = sender.toRegistrationFile(
            name: "TestSender",
            endpoint: "https://test.example.com/ace"
        )

        let msg = try createMessage(CreateMessageOptions(
            sender: sender,
            recipientPubKey: receiver.getEncryptionPublicKey(),
            recipientACEId: receiver.getACEId(),
            type: .info,
            body: ["message": "via registration"],
            stateMachine: sm
        ))

        let parsed = try parseMessageFromRegistration(
            msg,
            receiver: receiver,
            senderRegistration: reg,
            stateMachine: sm
        )

        #expect(parsed.body["message"] as? String == "via registration")
    }
}
