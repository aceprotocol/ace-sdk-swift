import ACE
import Foundation

let alice = try SoftwareIdentity.generate(scheme: .ed25519)
let bob = try SoftwareIdentity.generate(scheme: .ed25519)
let message = try createMessage(CreateMessageOptions(
    sender: alice,
    recipientPubKey: bob.getEncryptionPublicKey(),
    recipientACEId: bob.getACEId(),
    type: .rfq,
    body: ["need": "Translate 500 words EN→FR", "maxPrice": "10", "currency": "USDC"],
    stateMachine: ThreadStateMachine(),
    threadId: "translation-1"
))

// The keys are trusted here because both identities were created locally.
let parsed = try parseMessage(
    message, receiver: bob, senderSigningPubKey: alice.getSigningPublicKey(),
    opts: ParseMessageOptions(
        stateMachine: ThreadStateMachine(),
        expectedScheme: alice.getSigningScheme(),
        replayDetector: ReplayDetector(),
        senderEncryptionPubKey: alice.getEncryptionPublicKey()
    )
)
precondition(parsed.body["need"] as? String == "Translate 500 words EN→FR")
print(parsed.body)
