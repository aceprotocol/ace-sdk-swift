//
//  Messages.swift
//  ACE SDK
//
//  Message construction and the receive pipeline (06-security).
//

import Foundation

// MARK: - Body schema

private enum FieldKind { case str, optStr, obj, optObj, optTTL }

private let bodySchemas: [MessageType: [(String, FieldKind)]] = [
    .rfq: [("need", .str), ("maxPrice", .optStr), ("currency", .optStr), ("ttl", .optTTL)],
    .offer: [("price", .str), ("currency", .str), ("terms", .optStr), ("ttl", .optTTL)],
    .accept: [("offerId", .str)],
    .reject: [("reason", .optStr)],
    .invoice: [("offerId", .str), ("amount", .str), ("currency", .str), ("settlementMethod", .str), ("settlementDetails", .optObj)],
    .receipt: [("referenceId", .str), ("amount", .str), ("currency", .str), ("settlementMethod", .str), ("proof", .obj)],
    .deliver: [("type", .str), ("content", .optStr), ("contentType", .optStr), ("uri", .optStr), ("metadata", .optObj)],
    .confirm: [("deliverId", .str), ("message", .optStr)],
    .info: [("message", .str)],
    .text: [("message", .str)],
]

/// Validate a body against its type's schema; failures are `invalid_body`.
/// Optional fields set to `null` are absent; unknown fields are ignored.
public func validateBody(_ type: MessageType, _ body: [String: JSONValue]) throws {
    for (name, kind) in bodySchemas[type]! {
        guard let v = body[name], !v.isNull else {
            if kind == .str || kind == .obj { throw ACEError(.invalidBody, "\(type.rawValue).\(name) is required") }
            continue
        }
        let ok: Bool
        switch kind {
        case .str, .optStr: ok = v.stringValue != nil
        case .obj, .optObj: ok = v.objectValue != nil
        case .optTTL: ok = v.wireInt != nil
        }
        guard ok else { throw ACEError(.invalidBody, "\(type.rawValue).\(name) has the wrong type") }
    }
    if type == .deliver {
        let kind = body["type"]?.stringValue
        let required = kind == "inline" ? "content" : kind == "reference" ? "uri" : nil
        guard let required else { throw ACEError(.invalidBody, "deliver.type must be 'inline' or 'reference'") }
        guard body[required]?.stringValue != nil else { throw ACEError(.invalidBody, "deliver (\(kind!)) requires \(required)") }
    }
}

/// Decrypted bytes → validated body (`invalid_body`): fatal UTF-8, no non-finite numbers,
/// depth ≤ 32, a JSON object.
func decodeBody(_ type: MessageType, _ raw: Data) throws -> [String: JSONValue] {
    let v: JValue
    do { v = try JSONParser.parse(raw, maxDepth: ACELimits.maxJSONDepth) } catch {
        throw ACEError(.invalidBody, "body is not valid JSON: \(error.reason)")
    }
    guard case .object = v else { throw ACEError(.invalidBody, "body must be a JSON object") }
    guard let body = JSONValue(v)?.objectValue else { throw ACEError(.invalidBody, "non-finite number") }
    try validateBody(type, body)
    return body
}

/// Sender-side JSON-value rules: finite numbers, depth ≤ 32 (the body object is depth 0).
private func checkJSONValue(_ value: JSONValue, depth: Int) throws {
    switch value {
    case .null, .bool, .string:
        return
    case .number(let d):
        guard d.isFinite else { throw ACEError(.invalidBody, "non-finite number") }
    case .object(let o):
        guard depth <= ACELimits.maxJSONDepth else { throw ACEError(.invalidBody, "JSON nesting exceeds depth \(ACELimits.maxJSONDepth)") }
        for v in o.values { try checkJSONValue(v, depth: depth + 1) }
    case .array(let a):
        guard depth <= ACELimits.maxJSONDepth else { throw ACEError(.invalidBody, "JSON nesting exceeds depth \(ACELimits.maxJSONDepth)") }
        for v in a { try checkJSONValue(v, depth: depth + 1) }
    }
}

/// Compact UTF-8 JSON (keys sorted) of a checked body.
func serializeBody(_ body: [String: JSONValue]) throws -> Data {
    guard let v = JSONValue.object(body).jvalue else { throw ACEError(.invalidBody, "non-finite number") }
    return JSONWriter.serialize(v)
}

private func event(_ env: ACEMessage) -> ThreadEvent {
    ThreadEvent(conversationId: env.conversationId, threadId: env.threadId, type: env.type, messageId: env.messageId,
                timestamp: env.timestamp, from: env.from, to: env.to)
}

// MARK: - Create

/// Encrypt, sign and record an outbound message (design §2.5 order):
/// type / threadId / local identity (`invalid_argument`) → JSON values and schema
/// (`invalid_body`) → conversationId → state-machine pre-check → serialize
/// (`limit_exceeded` over 65508 bytes) → encrypt → sign → `threads.apply`.
public func createMessage(
    sender: any ACEIdentity,
    recipient: VerifiedPeer,
    type: MessageType,
    body: [String: JSONValue],
    threads: ThreadStateMachine,
    threadId: String? = nil,
    timestamp: Int? = nil
) throws -> ACEMessage {
    try createMessage(sender: sender, recipient: recipient, type: type, body: body, threads: threads,
                      threadId: threadId, timestamp: timestamp, messageId: UUID().uuidString.lowercased())
}

func createMessage(
    sender: any ACEIdentity, recipient: VerifiedPeer, type: MessageType, body: [String: JSONValue], threads: ThreadStateMachine,
    threadId: String?, timestamp: Int?, messageId: String
) throws -> ACEMessage {
    // 1. type, threadId, local identity
    if let threadId, !isThreadId(threadId) {
        throw ACEError(.invalidArgument, "threadId must be 1..256 code points without control characters")
    }
    if threadId == nil && type.isEconomic { throw ACEError(.invalidArgument, "economic messages require threadId") }
    let from = sender.getACEId()
    guard threads.localAceId == from else { throw ACEError(.invalidArgument, "threads.localAceId must be the sender") }
    let ts = timestamp ?? systemClock()
    guard isWireInt(ts) else { throw ACEError(.invalidArgument, "timestamp must be an integer in [0, 2^53-1]") }
    // 2. JSON values, then schema
    try checkJSONValue(.object(body), depth: 0)
    try validateBody(type, body)
    // 3. conversation
    let conversationId = try ACEEncryption.computeConversationId(pubA: sender.getEncryptionPublicKey(), pubB: recipient.encryptionPublicKey)
    let e = ThreadEvent(conversationId: conversationId, threadId: threadId, type: type, messageId: messageId,
                        timestamp: ts, from: from, to: recipient.aceId)
    // 4. state machine pre-check
    try threads.check(e, body: body)
    // 5. serialize
    let plaintext = try serializeBody(body)
    guard plaintext.count <= ACELimits.maxPlaintextBytes else {
        throw ACEError(.limitExceeded, "body exceeds \(ACELimits.maxPlaintextBytes) bytes")
    }
    // 6. encrypt
    let (kem, payload) = try ACEEncryption.encrypt(plaintext, recipientPublicKey: recipient.encryptionPublicKey, conversationId: conversationId)
    // 7. sign
    let scheme = sender.getSigningScheme()
    let unsigned = ACEMessage(
        messageId: messageId, from: from, to: recipient.aceId, conversationId: conversationId, type: type,
        threadId: threadId, timestamp: ts,
        encryption: EncryptionEnvelope(kemCiphertext: ACEBase64.encode(kem), payload: ACEBase64.encode(payload)),
        signature: SignatureEnvelope(scheme: scheme, value: "")
    )
    let env = try resign(unsigned, sender: sender, timestamp: ts)
    // 8. commit
    try threads.apply(e, body: body)
    return env
}

/// Sign `env` (same ciphertext) with `timestamp`.
func resign(_ env: ACEMessage, sender: any ACEIdentity, timestamp: Int) throws -> ACEMessage {
    let scheme = sender.getSigningScheme()
    let draft = ACEMessage(
        messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId, type: env.type,
        threadId: env.threadId, timestamp: timestamp, encryption: env.encryption,
        signature: SignatureEnvelope(scheme: scheme, value: "")
    )
    let sig = try sender.sign(try messageSignData(draft))
    return ACEMessage(
        messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId, type: env.type,
        threadId: env.threadId, timestamp: timestamp, encryption: env.encryption,
        signature: SignatureEnvelope(scheme: scheme, value: encodeSignature(sig, scheme: scheme))
    )
}

// MARK: - Parse

/// Verify, decrypt and validate an inbound message. The first failure wins:
///
/// decode → `wrong_recipient` → from (`invalid_envelope`) → `scheme_mismatch` →
/// conversationId (`invalid_envelope`) → floor / timestamp (`stale_timestamp`) → `replay` →
/// `invalid_signature` → replay commit → decrypt → `invalid_body` → state machine.
///
/// `floor` defaults to `max(0, now − 300)` and must lie in `[0, now]` (`invalid_argument`).
/// A non-`ACEError` thrown by `receiver.decrypt` is `identity_unavailable`.
public func parseMessage(
    _ env: ACEMessage,
    receiver: any ACEIdentity,
    sender: VerifiedPeer,
    threads: ThreadStateMachine,
    replay: ReplayDetector,
    floor: Int? = nil,
    clock: @Sendable () -> Int = systemClock
) throws -> ParsedMessage {
    let receiverId = receiver.getACEId()
    guard threads.localAceId == receiverId else { throw ACEError(.invalidArgument, "threads.localAceId must be the receiver") }
    // 1
    let env = try revalidate(env)
    // 2-5
    guard env.to == receiverId else { throw ACEError(.wrongRecipient, "message is not addressed to this identity") }
    guard env.from == sender.aceId else { throw ACEError(.invalidEnvelope, "from does not match the sender") }
    guard env.signature.scheme == sender.scheme else {
        throw ACEError(.schemeMismatch, "signature scheme differs from the sender's scheme")
    }
    let expected = try ACEEncryption.computeConversationId(pubA: sender.encryptionPublicKey, pubB: receiver.getEncryptionPublicKey())
    guard env.conversationId == expected else {
        throw ACEError(.invalidEnvelope, "conversationId does not match the verified keys")
    }
    // 6
    let now = wireNow(clock)
    let floor = floor ?? windowFloor(now: now)
    guard floor >= 0, floor <= now else { throw ACEError(.invalidArgument, "floor must be an integer in [0, now]") }
    guard env.timestamp >= floor, env.timestamp <= now + ACELimits.timestampWindowSeconds else {
        throw ACEError(.staleTimestamp, "timestamp is outside the acceptance window")
    }
    // 7
    guard try replay.accepts(env.messageId, from: env.from, timestamp: env.timestamp) else {
        throw ACEError(.replay, "message already seen or below the replay horizon")
    }
    // 8
    let sig = try decodeSignature(env.signature.value, scheme: env.signature.scheme, code: .invalidEnvelope)
    guard ACESigning.verify(signData: try messageSignData(env), signature: sig, scheme: sender.scheme, publicKey: sender.signingPublicKey) else {
        throw ACEError(.invalidSignature, "message signature does not verify")
    }
    // 9
    guard try replay.commit(env.messageId, from: env.from, timestamp: env.timestamp, floor: floor) else {
        throw ACEError(.replay, "message already seen or below the replay horizon")
    }
    // 10
    let plaintext: Data
    do {
        plaintext = try receiver.decrypt(
            kemCiphertext: try ACEEncryption.decodeKemCiphertext(env.encryption.kemCiphertext),
            payload: try decodePayload(env.encryption.payload),
            conversationId: env.conversationId
        )
    } catch let e as ACEError {
        throw e
    } catch {
        throw ACEError(.identityUnavailable, "identity decrypt failed: \(Swift.type(of: error))")
    }
    // 11-12
    let body = try decodeBody(env.type, plaintext)
    // 13
    if env.type.isEconomic {
        try threads.apply(event(env), body: body)
    }
    return ParsedMessage(messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId,
                         type: env.type, threadId: env.threadId, timestamp: env.timestamp, body: body)
}
