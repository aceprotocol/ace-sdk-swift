//
//  PeerBindingTests.swift
//  ACE SDK
//
//  Encryption-key binding: a relay must not be able to substitute an X25519 key.
//

import Testing
import Foundation
@testable import ACE

@Suite("Encryption-key binding (relay MITM defense)")
struct PeerBindingTests {

    /// Reproduce exactly what the relay stores/serves for GET /v1/peer.
    func relayPeerResponse(_ identity: any ACEIdentity, registeredAt: Int = 1741000000) throws -> RelayPeerResponse {
        let encB64 = ACEBase64.encode(identity.getEncryptionPublicKey())
        let signB64 = ACEBase64.encode(identity.getSigningPublicKey())
        let payload = ACESigning.encodePayload([.string(encB64), .string(signB64)])
        let signData = ACESigning.buildSignData(action: "register", aceId: identity.getACEId(), timestamp: registeredAt, payload: payload)
        let (sig, scheme) = try identity.sign(signData)
        return RelayPeerResponse(
            aceId: identity.getACEId(),
            scheme: scheme,
            encryptionPublicKey: encB64,
            signingPublicKey: signB64,
            registrationSignature: ACESigning.encodeSignature(sig, scheme: scheme),
            registeredAt: registeredAt
        )
    }

    @Test("accepts a genuine binding", arguments: [SigningScheme.ed25519, SigningScheme.secp256k1])
    func acceptsGenuine(scheme: SigningScheme) throws {
        let identity = try SoftwareIdentity.generate(scheme: scheme)
        let peer = try verifyPeerResponse(try relayPeerResponse(identity))
        #expect(peer.aceId == identity.getACEId())
        #expect(peer.encryptionPublicKey == identity.getEncryptionPublicKey())
        #expect(peer.signingPublicKey == identity.getSigningPublicKey())
    }

    @Test("rejects a substituted encryption key", arguments: [SigningScheme.ed25519, SigningScheme.secp256k1])
    func rejectsSubstitutedKey(scheme: SigningScheme) throws {
        let victim = try SoftwareIdentity.generate(scheme: scheme)
        let attacker = try SoftwareIdentity.generate(scheme: scheme)
        let genuine = try relayPeerResponse(victim)

        // Relay keeps the real signing key/aceId but swaps the X25519 key.
        let poisoned = RelayPeerResponse(
            aceId: genuine.aceId,
            scheme: genuine.scheme,
            encryptionPublicKey: ACEBase64.encode(attacker.getEncryptionPublicKey()),
            signingPublicKey: genuine.signingPublicKey,
            registrationSignature: genuine.registrationSignature,
            registeredAt: genuine.registeredAt
        )

        #expect(verifyEncryptionKeyBinding(
            aceId: poisoned.aceId, scheme: poisoned.scheme,
            encryptionPublicKey: poisoned.encryptionPublicKey, signingPublicKey: poisoned.signingPublicKey,
            timestamp: poisoned.registeredAt!, signature: poisoned.registrationSignature!
        ) == false)

        #expect(throws: ACEError.self) { try verifyPeerResponse(poisoned) }
    }

    @Test("rejects a missing binding signature")
    func rejectsMissingBinding() throws {
        let identity = try SoftwareIdentity.generate(scheme: .secp256k1)
        let genuine = try relayPeerResponse(identity)
        let noBinding = RelayPeerResponse(
            aceId: genuine.aceId, scheme: genuine.scheme,
            encryptionPublicKey: genuine.encryptionPublicKey, signingPublicKey: genuine.signingPublicKey,
            registrationSignature: nil, registeredAt: nil
        )
        #expect(throws: ACEError.self) { try verifyPeerResponse(noBinding) }
    }

    @Test("rejects a tampered registeredAt (timestamp is signed)")
    func rejectsTamperedTimestamp() throws {
        let identity = try SoftwareIdentity.generate(scheme: .secp256k1)
        let resp = try relayPeerResponse(identity, registeredAt: 1741000000)
        #expect(verifyEncryptionKeyBinding(
            aceId: resp.aceId, scheme: resp.scheme,
            encryptionPublicKey: resp.encryptionPublicKey, signingPublicKey: resp.signingPublicKey,
            timestamp: 1741000001, signature: resp.registrationSignature!
        ) == false)
    }

    @Test("parseMessageFromPeer round-trips", arguments: [SigningScheme.ed25519, SigningScheme.secp256k1])
    func parseFromPeerRoundtrip(scheme: SigningScheme) throws {
        let sender = try SoftwareIdentity.generate(scheme: scheme)
        let receiver = try SoftwareIdentity.generate(scheme: .ed25519)

        let msg = try createMessage(CreateMessageOptions(
            sender: sender,
            recipientPubKey: receiver.getEncryptionPublicKey(),
            recipientACEId: receiver.getACEId(),
            type: .text,
            body: ["message": "hello"],
            stateMachine: ThreadStateMachine()
        ))

        let senderPeer = try verifyPeerResponse(try relayPeerResponse(sender))
        let parsed = try parseMessageFromPeer(msg, receiver: receiver, sender: senderPeer, stateMachine: ThreadStateMachine(), replayDetector: ReplayDetector())

        #expect(parsed.body["message"] as? String == "hello")
        #expect(parsed.from == sender.getACEId())
    }
}
