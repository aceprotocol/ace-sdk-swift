//
//  Messages.swift
//  ACE SDK
//
//  Message creation (encrypt + sign) and parsing (verify + decrypt) pipeline.
//
//  Security pipeline order (parseMessage):
//    1. Envelope validation (cheap)
//    2. Timestamp freshness and replay horizon (cheap, before expensive ops)
//    3. Replay check (messageId not in the seen store)
//    4. Signature verification BEFORE decryption (prevents decryption oracle attacks),
//       then atomic replay commit — kept on any later failure: an authentic
//       message is one-shot regardless of outcome
//    5. Decryption
//    6. Body schema validation
//

import Foundation

// MARK: - Body Schema Validation

/// Validate message body has required fields for its type.
public func validateBody(_ type: MessageType, _ body: [String: Any]) throws {
    switch type {
    case .rfq:
        try requireString(body, "need", "rfq")
        try validateOptionalString(body, "maxPrice", "rfq")
        try validateOptionalString(body, "currency", "rfq")
        try validateOptionalNumber(body, "ttl", "rfq")
    case .offer:
        try requireString(body, "price", "offer")
        try requireString(body, "currency", "offer")
        try validateOptionalString(body, "terms", "offer")
        try validateOptionalNumber(body, "ttl", "offer")
    case .accept:
        try requireString(body, "offerId", "accept")
    case .reject:
        try validateOptionalString(body, "reason", "reject")
    case .invoice:
        try requireString(body, "offerId", "invoice")
        try requireString(body, "amount", "invoice")
        try requireString(body, "currency", "invoice")
        try requireString(body, "settlementMethod", "invoice")
        try validateOptionalObject(body, "settlementDetails", "invoice")
    case .receipt:
        try requireString(body, "referenceId", "receipt")
        try requireString(body, "amount", "receipt")
        try requireString(body, "currency", "receipt")
        try requireString(body, "settlementMethod", "receipt")
        try requireObject(body, "proof", "receipt")
    case .deliver:
        let deliverType = try requireString(body, "type", "deliver")
        try validateOptionalString(body, "content", "deliver")
        try validateOptionalString(body, "contentType", "deliver")
        try validateOptionalString(body, "uri", "deliver")
        try validateOptionalObject(body, "metadata", "deliver")
        if deliverType == "inline" {
            try requireString(body, "content", "deliver (inline)")
        } else if deliverType == "reference" {
            try requireString(body, "uri", "deliver (reference)")
        } else {
            throw ACEError.invalidMessage("deliver.type must be 'inline' or 'reference', got '\(String(deliverType.prefix(50)))'")
        }
    case .confirm:
        try requireString(body, "deliverId", "confirm")
        try validateOptionalString(body, "message", "confirm")
    case .info:
        try requireString(body, "message", "info")
    case .text:
        try requireString(body, "message", "text")
    }
}

/// JSON `null` is treated as absent: missing for `require*`, skipped by `validateOptional*`.
private func presentValue(_ body: [String: Any], _ field: String) -> Any? {
    guard let value = body[field], !(value is NSNull) else { return nil }
    return value
}

@discardableResult
private func requireString(_ body: [String: Any], _ field: String, _ typeName: String) throws -> String {
    guard let value = presentValue(body, field) else {
        throw ACEError.invalidMessage("\(typeName) body requires '\(field)' field")
    }
    guard let string = value as? String else {
        throw ACEError.invalidMessage("\(typeName).\(field) must be a string")
    }
    return string
}

private func requireObject(_ body: [String: Any], _ field: String, _ typeName: String) throws {
    guard let value = presentValue(body, field) else {
        throw ACEError.invalidMessage("\(typeName) body requires '\(field)' field")
    }
    try validateObject(value, field, typeName)
}

private func validateOptionalString(_ body: [String: Any], _ field: String, _ typeName: String) throws {
    guard let value = presentValue(body, field) else { return }
    guard value is String else {
        throw ACEError.invalidMessage("\(typeName).\(field) must be a string")
    }
}

private func validateOptionalNumber(_ body: [String: Any], _ field: String, _ typeName: String) throws {
    guard let value = presentValue(body, field) else { return }
    guard isJSONNumber(value) else {
        throw ACEError.invalidMessage("\(typeName).\(field) must be a number")
    }
}

private func validateOptionalObject(_ body: [String: Any], _ field: String, _ typeName: String) throws {
    guard let value = presentValue(body, field) else { return }
    try validateObject(value, field, typeName)
}

private func validateObject(_ value: Any, _ field: String, _ typeName: String) throws {
    guard value is [String: Any] || value is NSDictionary else {
        throw ACEError.invalidMessage("\(typeName).\(field) must be an object")
    }
}

private func isJSONNumber(_ value: Any) -> Bool {
    // NSNumber first: JSONSerialization's 0/1 also bridge to Bool, so `is Bool`
    // would reject them. Only a real CFBoolean is a JSON boolean.
    switch value {
    case let n as NSNumber:
        if CFGetTypeID(n as CFTypeRef) == CFBooleanGetTypeID() { return false }
        return n.doubleValue.isFinite
    case is Bool:
        return false
    case is Int, is Int8, is Int16, is Int32, is Int64,
         is UInt, is UInt8, is UInt16, is UInt32, is UInt64,
         is Decimal:
        return true
    case let f as Float:
        return f.isFinite
    case let d as Double:
        return d.isFinite
    default:
        return false
    }
}

private let conversationIdPattern = try! NSRegularExpression(pattern: "^[0-9a-f]{64}$")
private let maxJSONDepth = 32

/// Iterative nesting-depth check (top-level object is depth 0); same semantics as TS/Py.
private func assertMaxDepth(_ value: Any, _ maxDepth: Int) throws {
    var stack: [(value: Any, depth: Int)] = [(value, 0)]
    while let (val, depth) = stack.popLast() {
        if depth > maxDepth {
            throw ACEError.invalidMessage("Decrypted body exceeds maximum nesting depth of \(maxDepth)")
        }
        let children: [Any]
        if let dict = val as? [String: Any] {
            children = Array(dict.values)
        } else if let array = val as? [Any] {
            children = array
        } else {
            continue
        }
        for child in children where child is [String: Any] || child is [Any] {
            stack.append((child, depth + 1))
        }
    }
}

private func normalizeThreadId(_ threadId: String?) -> String {
    threadId ?? ""
}

private func buildSignedMessagePayload(
    type: MessageType,
    to: String,
    conversationId: String,
    messageId: String,
    threadId: String?,
    kemCiphertext: Data,
    payload: Data
) -> Data {
    // kemCiphertext is signed too: it is what the recipient uses to derive the
    // decryption key, so it is part of the sender's commitment. Omitting it would
    // let a relay swap the KEM ciphertext (garbling the message) without breaking
    // the signature.
    ACESigning.encodePayload([
        .string(type.rawValue), .string(to), .string(conversationId), .string(messageId),
        .string(normalizeThreadId(threadId)), .data(kemCiphertext), .data(payload),
    ])
}

private func threadContainsMessage(
    stateMachine: ThreadStateMachine,
    conversationId: String,
    threadId: String,
    messageType: MessageType,
    messageId: String
) -> Bool {
    stateMachine.getSnapshot(conversationId: conversationId, threadId: threadId)
        .history
        .contains { $0.type == messageType.rawValue && $0.messageId == messageId }
}

private func validateThreadReferences(
    type: MessageType,
    body: [String: Any],
    stateMachine: ThreadStateMachine,
    conversationId: String,
    threadId: String
) throws {
    guard isEconomicType(type), !threadId.isEmpty else { return }

    switch type {
    case .accept:
        let offerId = try requireString(body, "offerId", "accept")
        guard threadContainsMessage(stateMachine: stateMachine, conversationId: conversationId, threadId: threadId, messageType: .offer, messageId: offerId) else {
            throw ACEError.invalidMessage("accept.offerId must reference an offer in the same thread")
        }
    case .invoice:
        let offerId = try requireString(body, "offerId", "invoice")
        guard threadContainsMessage(stateMachine: stateMachine, conversationId: conversationId, threadId: threadId, messageType: .offer, messageId: offerId) else {
            throw ACEError.invalidMessage("invoice.offerId must reference an offer in the same thread")
        }
    case .receipt:
        // Pre-paid path (accepted→receipt) references the accept; otherwise the invoice.
        let referenceId = try requireString(body, "referenceId", "receipt")
        let isPrePaid = stateMachine.getState(conversationId: conversationId, threadId: threadId) == .accepted
        guard threadContainsMessage(stateMachine: stateMachine, conversationId: conversationId, threadId: threadId, messageType: isPrePaid ? .accept : .invoice, messageId: referenceId) else {
            throw ACEError.invalidMessage("receipt.referenceId must reference the invoice (or, when pre-paid, the accept) in the same thread")
        }
    case .confirm:
        let deliverId = try requireString(body, "deliverId", "confirm")
        guard threadContainsMessage(stateMachine: stateMachine, conversationId: conversationId, threadId: threadId, messageType: .deliver, messageId: deliverId) else {
            throw ACEError.invalidMessage("confirm.deliverId must reference a deliver message in the same thread")
        }
    default:
        break
    }
}

// MARK: - Parsed Message

/// @unchecked Sendable safety: body is constructed exclusively from JSONSerialization output,
/// which produces only immutable Foundation types (NSString, NSNumber, NSArray, NSDictionary, NSNull).
public struct ParsedMessage: @unchecked Sendable {
    public let messageId: String
    public let from: String
    public let to: String
    public let conversationId: String
    public let type: MessageType
    public let threadId: String?
    public let timestamp: Int
    public let body: [String: Any]

    public init(messageId: String, from: String, to: String, conversationId: String, type: MessageType, threadId: String?, timestamp: Int, body: [String: Any]) {
        self.messageId = messageId
        self.from = from
        self.to = to
        self.conversationId = conversationId
        self.type = type
        self.threadId = threadId
        self.timestamp = timestamp
        self.body = body
    }
}

// MARK: - Create Message Options

public struct CreateMessageOptions {
    public let sender: any ACEIdentity
    public let recipientPubKey: Data // X-Wing encryption public key (1216 bytes)
    public let recipientACEId: String
    public let type: MessageType
    public let body: [String: Any]
    public let stateMachine: ThreadStateMachine
    public var threadId: String?
    public var timestamp: Int?

    public init(
        sender: any ACEIdentity,
        recipientPubKey: Data,
        recipientACEId: String,
        type: MessageType,
        body: [String: Any],
        stateMachine: ThreadStateMachine,
        threadId: String? = nil,
        timestamp: Int? = nil
    ) {
        self.sender = sender
        self.recipientPubKey = recipientPubKey
        self.recipientACEId = recipientACEId
        self.type = type
        self.body = body
        self.stateMachine = stateMachine
        self.threadId = threadId
        self.timestamp = timestamp
    }
}

// MARK: - Create Message

/// Create an encrypted and signed ACE message.
public func createMessage(_ opts: CreateMessageOptions) throws -> ACEMessage {
    // Economic messages require threadId
    let isEconomic = isEconomicType(opts.type)
    if isEconomic && (opts.threadId == nil || opts.threadId!.isEmpty) {
        throw ACEError.invalidMessage("Economic message type '\(opts.type.rawValue)' requires a threadId")
    }

    // Validate threadId format if provided
    if let threadId = opts.threadId {
        try validateThreadId(threadId)
    }

    // 1. Validate body schema
    try validateBody(opts.type, opts.body)

    let messageId = UUID().uuidString.lowercased()
    let timestamp = opts.timestamp ?? Int(Date().timeIntervalSince1970)
    let fromId = opts.sender.getACEId()
    let toId = opts.recipientACEId
    let conversationId = try ACEEncryption.computeConversationId(
        pubA: opts.sender.getEncryptionPublicKey(),
        pubB: opts.recipientPubKey
    )
    let threadKey = normalizeThreadId(opts.threadId)
    // Pre-check: fail fast before expensive crypto operations
    if !opts.stateMachine.canTransition(conversationId: conversationId, threadId: threadKey, messageType: opts.type) {
        let current = opts.stateMachine.getState(conversationId: conversationId, threadId: threadKey)
        throw ACEError.invalidTransition("cannot process '\(opts.type.rawValue)' in state '\(current)'")
    }
    try validateThreadReferences(
        type: opts.type,
        body: opts.body,
        stateMachine: opts.stateMachine,
        conversationId: conversationId,
        threadId: threadKey
    )

    // 2. Encrypt body (compact JSON, no spaces — cross-language consistency)
    let bodyData = try JSONSerialization.data(
        withJSONObject: opts.body,
        options: [.withoutEscapingSlashes]
    )
    let (kemCiphertext, payload) = try ACEEncryption.encrypt(
        bodyData,
        recipientPublicKey: opts.recipientPubKey,
        conversationId: conversationId
    )

    // 3. Build sign data and sign
    let messagePayload = buildSignedMessagePayload(
        type: opts.type,
        to: toId,
        conversationId: conversationId,
        messageId: messageId,
        threadId: opts.threadId,
        kemCiphertext: kemCiphertext,
        payload: payload
    )
    let signData = ACESigning.buildSignData(action: "message", aceId: fromId, timestamp: timestamp, payload: messagePayload)
    let (signature, scheme) = try opts.sender.sign(signData)

    // 4. Commit state transition (only after all crypto succeeded)
    try opts.stateMachine.transition(
        conversationId: conversationId,
        threadId: threadKey,
        messageType: opts.type,
        messageId: messageId,
        timestamp: timestamp
    )

    // 5. Assemble envelope
    return ACEMessage(
        ace: "1.0",
        messageId: messageId,
        from: fromId,
        to: toId,
        conversationId: conversationId,
        type: opts.type,
        threadId: opts.threadId,
        timestamp: timestamp,
        encryption: EncryptionEnvelope(
            kemCiphertext: ACEBase64.encode(kemCiphertext),
            payload: ACEBase64.encode(payload)
        ),
        signature: SignatureEnvelope(
            scheme: scheme,
            value: ACESigning.encodeSignature(signature, scheme: scheme)
        )
    )
}

// MARK: - Parse Message Options

public struct ParseMessageOptions {
    public var stateMachine: ThreadStateMachine
    public var expectedScheme: SigningScheme?
    public var replayDetector: ReplayDetector
    public var senderEncryptionPubKey: Data?
    var currentTimestamp: Int?
    /// Offline acceptance floor; use it for every message, live ones included, until the backlog is done.
    public var oldestTimestamp: Int?

    public init(stateMachine: ThreadStateMachine, expectedScheme: SigningScheme? = nil, replayDetector: ReplayDetector, senderEncryptionPubKey: Data? = nil, oldestTimestamp: Int? = nil) {
        self.stateMachine = stateMachine
        self.expectedScheme = expectedScheme
        self.replayDetector = replayDetector
        self.senderEncryptionPubKey = senderEncryptionPubKey
        self.currentTimestamp = nil
        self.oldestTimestamp = oldestTimestamp
    }
}

// MARK: - Parse Message

/// Parse, verify, and decrypt an ACE message.
///
/// Security pipeline:
/// 1. Envelope validation
/// 2. Timestamp freshness and replay horizon
/// 3. Replay check
/// 4. Signature verification (BEFORE decryption), then replay commit
/// 5. Decryption
/// 6. Body schema validation
public func parseMessage(
    _ msg: ACEMessage,
    receiver: any ACEIdentity,
    senderSigningPubKey: Data,
    opts: ParseMessageOptions
) throws -> ParsedMessage {
    // 1. Envelope validation
    guard msg.ace == "1.0" else {
        throw ACEError.invalidMessage("Unsupported ACE version: '\(msg.ace)'")
    }
    guard msg.to == receiver.getACEId() else {
        throw ACEError.invalidMessage("Message not addressed to this recipient")
    }
    guard !msg.messageId.isEmpty, !msg.from.isEmpty, !msg.conversationId.isEmpty else {
        throw ACEError.invalidMessage("Missing required envelope fields")
    }
    guard conversationIdPattern.fullMatch(msg.conversationId) else {
        throw ACEError.invalidMessage("Invalid conversationId: expected 64 lowercase hex characters")
    }
    try validateMessageId(msg.messageId)

    // Validate from matches sender's signing public key
    let expectedFromId = computeACEId(senderSigningPubKey)
    guard msg.from == expectedFromId else {
        throw ACEError.invalidMessage("msg.from does not match sender signing public key")
    }

    // Validate conversationId if sender encryption key provided
    if let senderEncPubKey = opts.senderEncryptionPubKey {
        let expectedConvId = try ACEEncryption.computeConversationId(
            pubA: senderEncPubKey,
            pubB: receiver.getEncryptionPublicKey()
        )
        guard msg.conversationId == expectedConvId else {
            throw ACEError.invalidMessage("msg.conversationId does not match sender/recipient encryption keys")
        }
    }

    // Validate signature scheme
    if let expected = opts.expectedScheme, msg.signature.scheme != expected {
        throw ACEError.invalidMessage("Signature scheme mismatch: expected '\(expected.rawValue)', got '\(msg.signature.scheme.rawValue)'")
    }

    // Economic messages require threadId
    let isEconomic = isEconomicType(msg.type)
    if isEconomic && (msg.threadId == nil || msg.threadId!.isEmpty) {
        throw ACEError.invalidMessage("Economic message type '\(msg.type.rawValue)' requires a threadId")
    }

    // Validate threadId format if present.
    // Empty string threadId is rejected — use nil for no thread.
    if let threadId = msg.threadId {
        try validateThreadId(threadId)
    }

    // 2–3. Timestamp freshness, replay horizon and seen check
    let now = opts.currentTimestamp ?? Int(Date().timeIntervalSince1970)
    try checkTimestampFreshness(msg.timestamp, now: now, oldestTimestamp: opts.oldestTimestamp)
    guard opts.replayDetector.accepts(msg.messageId, from: msg.from, timestamp: msg.timestamp) else {
        throw ACEError.replayDetected(msg.messageId)
    }

    // 4. Signature verification BEFORE decryption
    let payloadBytes = try ACEBase64.decode(msg.encryption.payload, maxLength: ACEEncryption.maxPayloadSize, what: "Payload")

    // kemCiphertext length is enforced here, BEFORE signature verification and
    // long before any decapsulation runs.
    let kemCiphertext = try ACEEncryption.decodeKEMCiphertext(base64: msg.encryption.kemCiphertext)
    let messagePayload = buildSignedMessagePayload(
        type: msg.type,
        to: msg.to,
        conversationId: msg.conversationId,
        messageId: msg.messageId,
        threadId: msg.threadId,
        kemCiphertext: kemCiphertext,
        payload: payloadBytes
    )
    let signData = ACESigning.buildSignData(action: "message", aceId: msg.from, timestamp: msg.timestamp, payload: messagePayload)

    let sigBytes: Data
    do {
        sigBytes = try ACESigning.decodeSignature(msg.signature.value, scheme: msg.signature.scheme)
    } catch {
        throw ACEError.signatureVerificationFailed("Failed to decode signature")
    }

    let valid = ACESigning.verifySignature(
        signData: signData,
        signature: sigBytes,
        scheme: msg.signature.scheme,
        signingPublicKey: senderSigningPubKey
    )

    guard valid else {
        throw ACEError.signatureVerificationFailed("Signature verification failed")
    }

    // Commit now: an authentic message is one-shot, even if a later step fails.
    let floor = opts.oldestTimestamp ?? now - maxDriftSeconds
    guard opts.replayDetector.commit(msg.messageId, from: msg.from, timestamp: msg.timestamp, floor: floor) else {
        throw ACEError.replayDetected(msg.messageId)
    }

    // 5. Decrypt body — kemCiphertext was decoded, length-checked and signature-verified above.
    let decrypted = try receiver.decrypt(
        kemCiphertext: kemCiphertext,
        payload: payloadBytes,
        conversationId: msg.conversationId
    )

    // 6. Parse and validate body
    let decoded: Any
    do { decoded = try JSONSerialization.jsonObject(with: decrypted) }
    catch { throw ACEError.invalidMessage("Decrypted body is not valid JSON") }
    guard let body = decoded as? [String: Any] else {
        throw ACEError.invalidMessage("Decrypted body must be a JSON object")
    }
    try assertMaxDepth(body, maxJSONDepth)
    try validateBody(msg.type, body)
    try validateThreadReferences(
        type: msg.type,
        body: body,
        stateMachine: opts.stateMachine,
        conversationId: msg.conversationId,
        threadId: normalizeThreadId(msg.threadId)
    )

    // 7. State machine validation (after all security checks)
    try opts.stateMachine.transition(
        conversationId: msg.conversationId,
        threadId: normalizeThreadId(msg.threadId),
        messageType: msg.type,
        messageId: msg.messageId,
        timestamp: msg.timestamp
    )

    return ParsedMessage(
        messageId: msg.messageId,
        from: msg.from,
        to: msg.to,
        conversationId: msg.conversationId,
        type: msg.type,
        threadId: msg.threadId,
        timestamp: msg.timestamp,
        body: body
    )
}

// MARK: - Parse Message from Registration

/// Parse a message using sender's registration file for full validation.
public func parseMessageFromRegistration(
    _ msg: ACEMessage,
    receiver: any ACEIdentity,
    senderRegistration: RegistrationFile,
    stateMachine: ThreadStateMachine,
    replayDetector: ReplayDetector,
    oldestTimestamp: Int? = nil
) throws -> ParsedMessage {
    try parseMessageFromRegistrationInternal(
        msg,
        receiver: receiver,
        senderRegistration: senderRegistration,
        stateMachine: stateMachine,
        replayDetector: replayDetector,
        currentTimestamp: nil,
        oldestTimestamp: oldestTimestamp
    )
}

/// Safe path for messages whose sender keys came from a relay.
///
/// `sender` must be a ``VerifiedPeer`` — obtainable only after its encryption-key
/// binding was verified — so the recipient never trusts a relay-substituted X-Wing
/// key. `conversationId` is recomputed from the verified keys and must match.
public func parseMessageFromPeer(
    _ msg: ACEMessage,
    receiver: any ACEIdentity,
    sender: VerifiedPeer,
    stateMachine: ThreadStateMachine,
    replayDetector: ReplayDetector,
    oldestTimestamp: Int? = nil
) throws -> ParsedMessage {
    let opts = ParseMessageOptions(
        stateMachine: stateMachine,
        expectedScheme: sender.scheme,
        replayDetector: replayDetector,
        senderEncryptionPubKey: sender.encryptionPublicKey,
        oldestTimestamp: oldestTimestamp
    )
    return try parseMessage(msg, receiver: receiver, senderSigningPubKey: sender.signingPublicKey, opts: opts)
}

func parseMessageFromRegistrationInternal(
    _ msg: ACEMessage,
    receiver: any ACEIdentity,
    senderRegistration: RegistrationFile,
    stateMachine: ThreadStateMachine,
    replayDetector: ReplayDetector,
    currentTimestamp: Int? = nil,
    oldestTimestamp: Int? = nil
) throws -> ParsedMessage {
    // validateRegistrationFile already checks the secp256k1 address against the
    // signing key, so the only remaining verifyRegistrationId check is the id.
    let keys = try validateRegistrationFile(senderRegistration)
    guard computeACEId(keys.signingPublicKey) == senderRegistration.id else {
        throw ACEError.invalidRegistration("Sender registration file failed cryptographic verification")
    }
    let signingPubKey = keys.signingPublicKey
    let encryptionPubKey = keys.encryptionPublicKey

    var opts = ParseMessageOptions(
        stateMachine: stateMachine,
        expectedScheme: senderRegistration.signing.scheme,
        replayDetector: replayDetector,
        senderEncryptionPubKey: encryptionPubKey,
        oldestTimestamp: oldestTimestamp
    )
    opts.currentTimestamp = currentTimestamp

    return try parseMessage(
        msg,
        receiver: receiver,
        senderSigningPubKey: signingPubKey,
        opts: opts
    )
}
