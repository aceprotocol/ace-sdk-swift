//
//  Messages.swift
//  ACE SDK
//
//  Message construction and the receive pipeline (06-security).
//

import Foundation

// MARK: - Body schema

private enum FieldKind: String { case str, optStr, obj, optObj; case optTTL = "optTtl" }

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
    .request: [("action", .str), ("summary", .str), ("ref", .optObj), ("amount", .optStr), ("currency", .optStr), ("details", .optObj), ("ttl", .optTTL)],
    .decision: [("requestId", .str), ("outcome", .str), ("reason", .optStr), ("result", .optObj)],
    .report: [("action", .str), ("summary", .str), ("outcome", .str), ("ref", .optObj), ("requestId", .optStr), ("proof", .optObj)],
]

/// Digest of the immutable bundled profile descriptor. Custom schemas are pinned by callers.
public func knownSchemaDigest(_ type: MessageType) -> String? {
    guard let fields = bodySchemas[type] else { return nil }
    let outcomes = type == .decision ? ["approve", "deny"] : type == .report ? ["ok", "failed", "skipped"] : []
    let v: JValue = .object(["type": .string(type.rawValue), "version": .number("1"),
        "fields": .array(fields.map { .array([.string($0.0), .string($0.1.rawValue)]) }),
        "outcomes": .array(outcomes.map(JValue.string))])
    return sha256Hex(JSONWriter.serialize(v))
}

// MARK: - Installed schemas

/// What an installed validator sees: the decoded private content of one message.
public struct SchemaMessage: Sendable {
    public let type: MessageType
    public let schemaDigest: String
    public let threadId: String?
    public let body: [String: JSONValue]
    public init(type: MessageType, schemaDigest: String, threadId: String?, body: [String: JSONValue]) {
        self.type = type; self.schemaDigest = schemaDigest; self.threadId = threadId; self.body = body
    }
}

/// Deterministic validator installed per `schemaDigest` (`Inbox.open(schemas:)`,
/// `Outbox.open(schemas:)`). Throw an `ACEError` with a permanent code to reject with that
/// code; any other thrown value is `invalid_body`.
public typealias SchemaValidator = @Sendable (SchemaMessage) throws -> Void

/// `invalid_argument` unless every key is a 64-hex schema digest.
func checkSchemas(_ schemas: [String: SchemaValidator]) throws {
    for key in schemas.keys where !isSha256Hex(key) {
        throw ACEError(.invalidArgument, "schemas keys must be 64 lowercase hex schema digests")
    }
}

/// Run the installed validator for `message.schemaDigest`, if any, with the error mapping above.
func validateInstalledSchema(_ schemas: [String: SchemaValidator], _ message: SchemaMessage) throws {
    guard let validator = schemas[message.schemaDigest] else { return }
    do { try validator(message) }
    catch let e as ACEError where e.category == .permanent { throw e }
    catch { throw ACEError(.invalidBody, "schema validator rejected the body: \(error)") }
}

/// The schema digest a message of `type` carries: `schemaDigest`, else the bundled one. A custom
/// type must pin one, and a bundled type only its own (`invalid_body`).
func resolveSchemaDigest(_ type: MessageType, _ schemaDigest: String?) throws -> String {
    let known = knownSchemaDigest(type)
    guard let digest = schemaDigest ?? known, isSha256Hex(digest), known == nil || known == digest else {
        throw ACEError(.invalidBody, "schemaDigest must pin the message schema")
    }
    return digest
}

func privateContent(_ type: MessageType, body: [String: JSONValue], threadId: String?, schemaDigest: String?) throws -> [String: JSONValue] {
    let digest = try resolveSchemaDigest(type, schemaDigest)
    var content: [String: JSONValue] = ["type": .string(type.rawValue), "body": .object(body), "schemaDigest": .string(digest)]
    if let threadId { content["threadId"] = .string(threadId) }
    try checkJSONValue(.object(content))
    return content
}

func decodePrivateContent(_ raw: Data) throws -> (MessageType, [String: JSONValue], String?, String) {
    let v: JValue
    do { v = try JSONParser.parse(raw, maxDepth: ACELimits.maxJSONDepth) } catch {
        throw ACEError(.invalidBody, "content is not valid JSON")
    }
    guard let content = JSONValue(v)?.objectValue,
          Set(content.keys).isSubset(of: ["type", "body", "schemaDigest", "threadId"]),
          let t = content["type"]?.stringValue, let type = MessageType(rawValue: t),
          let body = content["body"]?.objectValue, let digest = content["schemaDigest"]?.stringValue else {
        throw ACEError(.invalidBody, "invalid private content")
    }
    var threadId: String?
    if let rawThread = content["threadId"] {
        guard let t = rawThread.stringValue, isThreadId(t) else { throw ACEError(.invalidBody, "invalid threadId") }
        threadId = t
    }
    _ = try privateContent(type, body: body, threadId: threadId, schemaDigest: digest)
    try validateBody(type, body)
    return (type, body, threadId, digest)
}

/// Validate a body against its type's schema; failures are `invalid_body`.
/// Optional fields set to `null` are absent; unknown fields are ignored.
public func validateBody(_ type: MessageType, _ body: [String: JSONValue]) throws {
    for (name, kind) in bodySchemas[type] ?? [] {
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
    let outcomes: [MessageType: [String]] = [.decision: ["approve", "deny"], .report: ["ok", "failed", "skipped"]]
    if let allowed = outcomes[type], !allowed.contains(body["outcome"]?.stringValue ?? "") {
        throw ACEError(.invalidBody, "\(type.rawValue).outcome must be one of \(allowed.joined(separator: ", "))")
    }
    if type == .request || type == .report, let ref = body["ref"], !ref.isNull {
        let r = ref.objectValue!
        guard let c = r["conversationId"]?.stringValue, isConversationId(c) else {
            throw ACEError(.invalidBody, "\(type.rawValue).ref.conversationId must be 64 lowercase hex")
        }
        guard let m = r["messageId"]?.stringValue, isMessageId(m) else {
            throw ACEError(.invalidBody, "\(type.rawValue).ref.messageId must be a lowercase UUID v4")
        }
        if let t = r["threadId"], !t.isNull {
            guard let s = t.stringValue, isThreadId(s) else {
                throw ACEError(.invalidBody, "\(type.rawValue).ref.threadId must be a valid thread ID")
            }
        }
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

/// Sender-side JSON-value rules: finite numbers, depth ≤ `maxDepth` (the top-level object is
/// depth 0). Bodies use 32 / `invalid_body`; `ext` objects use 8 and their carrier's code.
func checkJSONValue(_ value: JSONValue, depth: Int = 0, maxDepth: Int = ACELimits.maxJSONDepth, code: ACEError.Code = .invalidBody) throws {
    switch value {
    case .null, .bool, .string:
        return
    case .number(let d):
        guard d.isFinite else { throw ACEError(code, "non-finite number") }
    case .object(let o):
        guard depth <= maxDepth else { throw ACEError(code, "JSON nesting exceeds depth \(maxDepth)") }
        for v in o.values { try checkJSONValue(v, depth: depth + 1, maxDepth: maxDepth, code: code) }
    case .array(let a):
        guard depth <= maxDepth else { throw ACEError(code, "JSON nesting exceeds depth \(maxDepth)") }
        for v in a { try checkJSONValue(v, depth: depth + 1, maxDepth: maxDepth, code: code) }
    }
}

/// Compact UTF-8 JSON (keys sorted) of a checked body.
func serializeBody(_ body: [String: JSONValue]) throws -> Data {
    guard let v = JSONValue.object(body).jvalue else { throw ACEError(.invalidBody, "non-finite number") }
    return JSONWriter.serialize(v)
}

func event(_ env: ParsedMessage) -> ThreadEvent {
    ThreadEvent(conversationId: env.conversationId, threadId: env.threadId, type: env.type, messageId: env.messageId,
                timestamp: env.timestamp, from: env.from, to: env.to)
}

// MARK: - Create

/// Encrypt, sign and record an outbound message, in this order:
/// type / threadId / local identity (`invalid_argument`) → JSON values and schema
/// (`invalid_body`) → conversationId → state-machine pre-check → serialize
/// (`limit_exceeded` over 65508 bytes) → encrypt → sign → `threads.apply`.
public func createMessage(
    sender: any ACEIdentity,
    recipient: VerifiedPeer,
    type: MessageType,
    body: [String: JSONValue],
    threads: ThreadStateMachine? = nil,
    threadId: String? = nil,
    timestamp: Int? = nil,
    schemaDigest: String? = nil
) throws -> ACEMessage {
    try createMessage(sender: sender, recipient: recipient, type: type, body: body, threads: threads,
                      threadId: threadId, timestamp: timestamp, schemaDigest: schemaDigest, messageId: UUID().uuidString.lowercased())
}

func createMessage(
    sender: any ACEIdentity, recipient: VerifiedPeer, type: MessageType, body: [String: JSONValue], threads: ThreadStateMachine? = nil,
    threadId: String?, timestamp: Int?, schemaDigest: String? = nil, messageId: String
) throws -> ACEMessage {
    // 1. type, threadId, local identity
    if let threadId, !isThreadId(threadId) {
        throw ACEError(.invalidArgument, "threadId must be 1..256 code points without control characters")
    }
    if threads != nil && threadId == nil && type.isEconomic { throw ACEError(.invalidArgument, "economic messages require threadId") }
    let from = sender.getACEId()
    guard threads == nil || threads?.localAceId == from else { throw ACEError(.invalidArgument, "threads.localAceId must be the sender") }
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
    try threads?.check(e, body: body)
    // 5. serialize
    let plaintext = try serializeBody(privateContent(type, body: body, threadId: threadId, schemaDigest: schemaDigest))
    guard plaintext.count <= ACELimits.maxPlaintextBytes else {
        throw ACEError(.limitExceeded, "body exceeds \(ACELimits.maxPlaintextBytes) bytes")
    }
    // 6. encrypt
    let (kem, payload) = try ACEEncryption.encrypt(plaintext, recipientPublicKey: recipient.encryptionPublicKey, conversationId: conversationId)
    // 7. sign
    let scheme = sender.getSigningScheme()
    let unsigned = ACEMessage(
        messageId: messageId, from: from, to: recipient.aceId, conversationId: conversationId, timestamp: ts,
        encryption: EncryptionEnvelope(kemCiphertext: ACEBase64.encode(kem), payload: ACEBase64.encode(payload)),
        signature: SignatureEnvelope(scheme: scheme, value: "")
    )
    let env = try resign(unsigned, sender: sender, timestamp: ts)
    // 8. commit
    try threads?.apply(e, body: body)
    return env
}

/// Sign `env` (same ciphertext) with `timestamp`.
func resign(_ env: ACEMessage, sender: any ACEIdentity, timestamp: Int) throws -> ACEMessage {
    let scheme = sender.getSigningScheme()
    let draft = ACEMessage(
        messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId, timestamp: timestamp, encryption: env.encryption,
        signature: SignatureEnvelope(scheme: scheme, value: "")
    )
    let sig = try sender.sign(try messageSignData(draft))
    return ACEMessage(
        messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId, timestamp: timestamp, encryption: env.encryption,
        signature: SignatureEnvelope(scheme: scheme, value: encodeSignature(sig, scheme: scheme))
    )
}

// MARK: - Parse

/// Verify, decrypt and validate an inbound message. The first failure wins:
///
/// decode → `wrong_recipient` → from (`invalid_envelope`) → `scheme_mismatch` →
/// conversationId (`invalid_envelope`) → floor / timestamp (`stale_timestamp`) → `replay` →
/// `invalid_signature` → replay commit → decrypt → `invalid_body` → state machine /
/// principal rules.
///
/// `floor` defaults to `max(0, now − 300)` and must lie in `[0, now]` (`invalid_argument`).
/// A non-`ACEError` thrown by `receiver.decrypt` is `identity_unavailable`.
///
/// `principal` explicitly installs the account coordination policy. Its absence permits
/// data reception only; it grants no execution rights. Commerce is also opt-in.
public func parseMessage(
    _ env: ACEMessage,
    receiver: any ACEIdentity,
    sender: VerifiedPeer,
    threads: ThreadStateMachine? = nil,
    replay: ReplayDetector,
    floor: Int? = nil,
    clock: @Sendable () -> Int = systemClock,
    principal: PrincipalContext? = nil
) throws -> ParsedMessage {
    try parseMessage(env, receiver: receiver, sender: sender, threads: threads, gate: replay, floor: floor, clock: clock, principal: principal)
}

/// The seen store as the pipeline reads it (step 7) and records into it (step 9).
protocol ReplayGate {
    func accepts(_ messageId: String, from sender: String, timestamp: Int) throws -> Bool
    func commit(_ messageId: String, from sender: String, timestamp: Int, floor: Int?) throws -> Bool
}
extension ReplayDetector: ReplayGate {}

func parseMessage(
    _ env: ACEMessage, receiver: any ACEIdentity, sender: VerifiedPeer, threads: ThreadStateMachine? = nil,
    gate replay: any ReplayGate, floor: Int?, clock: @Sendable () -> Int, principal: PrincipalContext? = nil
) throws -> ParsedMessage {
    let receiverId = receiver.getACEId()
    guard threads == nil || threads?.localAceId == receiverId else { throw ACEError(.invalidArgument, "threads.localAceId must be the receiver") }
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
    let (type, body, threadId, digest) = try decodePrivateContent(plaintext)
    let parsed = ParsedMessage(messageId: env.messageId, from: env.from, to: env.to, conversationId: env.conversationId,
                               type: type, threadId: threadId, timestamp: env.timestamp, body: body, schemaDigest: digest)
    try applyMessageRules(parsed, threads: threads, principal: principal, sender: sender, now: now)
    return parsed
}

/// 06 step 13 on a decoded message: the state machine for economic types, the account rules for
/// principal types. A nil `threads` / `principal` skips that rule.
func applyMessageRules(_ parsed: ParsedMessage, threads: ThreadStateMachine?, principal: PrincipalContext?,
                       sender: VerifiedPeer, now: Int) throws {
    if parsed.type.isEconomic { try threads?.apply(event(parsed), body: parsed.body) }
    if parsed.type.isPrincipal, let principal { try checkPrincipal(parsed, body: parsed.body, sender: sender, context: principal, now: now) }
}

/// 06 step 7 for principal types (09 § Same-Account Rules), against the sender binding as given.
/// The `Inbox` refreshes a stale sender once before parsing (R-P20, outside any store lock).
private func checkPrincipal(_ env: ParsedMessage, body: [String: JSONValue], sender: VerifiedPeer,
                            context: PrincipalContext?, now: Int) throws {
    try checkPrincipalRules(
        type: env.type, body: body, conversationId: env.conversationId, senderPrincipal: sender.principal,
        senderSigningPublicKey: sender.signingPublicKey, selfAccount: context?.account,
        openRequestTo: context?.openRequestTo, now: now,
        selfSigner: context?.selfSigner, trustedSigners: context?.trustedSigners ?? [])
}
