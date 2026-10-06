//
//  Envelope.swift
//  ACE SDK
//
//  Envelope decoding (04 "Envelope decoding"), signature check and fingerprint.
//

import Foundation

/// Decode an envelope from its JSON bytes, applying the 04 decoding rules exactly.
///
/// Errors: `unsupported_version` for an `ace` string other than `"1.0"`, otherwise
/// `invalid_envelope`. Unknown fields at any level are ignored.
public func decodeEnvelope(_ json: Data) throws -> ACEMessage {
    let v: JValue
    do { v = try JSONParser.parse(json) } catch {
        throw ACEError(.invalidEnvelope, "envelope is not JSON: \(error.reason)")
    }
    return try decodeEnvelope(value: v)
}

private func bad(_ msg: String) -> ACEError { ACEError(.invalidEnvelope, msg) }

func decodePayload(_ text: String) throws -> Data {
    let raw = try decodeB64(text, code: .invalidEnvelope, what: "encryption.payload", maxBytes: ACELimits.maxPayloadBytes)
    guard (ACEEncryption.minPayloadBytes...ACELimits.maxPayloadBytes).contains(raw.count) else {
        throw bad("encryption.payload must be \(ACEEncryption.minPayloadBytes)..\(ACELimits.maxPayloadBytes) bytes")
    }
    return raw
}

func decodeEnvelope(value v: JValue) throws -> ACEMessage {
    guard let o = v.objectValue else { throw bad("envelope must be a JSON object") }
    guard let ace = o["ace"]?.stringValue else { throw bad("ace must be a string") }
    guard ace == "1.0" else {
        throw ACEError(.unsupportedVersion, "unsupported ACE version '\(String(ace.prefix(16)))'")
    }
    guard let messageId = o["messageId"]?.stringValue, isMessageId(messageId) else {
        throw bad("messageId must be a lowercase UUIDv4")
    }
    guard let from = o["from"]?.stringValue, isACEId(from), let to = o["to"]?.stringValue, isACEId(to) else {
        throw bad("from/to must be ACE IDs")
    }
    guard let conversationId = o["conversationId"]?.stringValue, isConversationId(conversationId) else {
        throw bad("conversationId must be 64 lowercase hex characters")
    }
    guard let typeText = o["type"]?.stringValue, let type = MessageType(rawValue: typeText) else {
        throw bad("unknown message type")
    }
    var threadId: String?
    if let t = o["threadId"] {
        guard let s = t.stringValue, isThreadId(s) else {
            throw bad("threadId must be 1..256 code points without control characters")
        }
        threadId = s
    }
    if threadId == nil && type.isEconomic { throw bad("economic messages require threadId") }
    guard let timestamp = o["timestamp"]?.wireInt else { throw bad("timestamp must be an integer in [0, 2^53-1]") }
    guard let enc = o["encryption"]?.objectValue else { throw bad("encryption must be an object") }
    guard let kem = enc["kemCiphertext"]?.stringValue else { throw bad("encryption.kemCiphertext must be a Base64 string") }
    _ = try ACEEncryption.decodeKemCiphertext(kem)
    guard let payload = enc["payload"]?.stringValue else { throw bad("encryption.payload must be a Base64 string") }
    _ = try decodePayload(payload)
    guard let sig = o["signature"]?.objectValue else { throw bad("signature must be an object") }
    guard let schemeText = sig["scheme"]?.stringValue, let scheme = SigningScheme(rawValue: schemeText) else {
        throw bad("unsupported signature scheme")
    }
    guard let value = sig["value"]?.stringValue else { throw bad("signature.value must be a string") }
    _ = try decodeSignature(value, scheme: scheme, code: .invalidEnvelope)
    return ACEMessage(
        ace: ace, messageId: messageId, from: from, to: to, conversationId: conversationId, type: type,
        threadId: threadId, timestamp: timestamp,
        encryption: EncryptionEnvelope(kemCiphertext: kem, payload: payload),
        signature: SignatureEnvelope(scheme: scheme, value: value)
    )
}

/// Re-run the decoding rules on an `ACEMessage` built by the caller.
func revalidate(_ env: ACEMessage) throws -> ACEMessage {
    try decodeEnvelope(value: env.jvalue)
}

func messageSignData(_ env: ACEMessage) throws -> Data {
    let payload = ACESigning.encodePayload([
        .string(env.type.rawValue), .string(env.to), .string(env.conversationId), .string(env.messageId),
        .string(env.threadId ?? ""),
        .data(try ACEEncryption.decodeKemCiphertext(env.encryption.kemCiphertext)),
        .data(try decodePayload(env.encryption.payload)),
    ])
    return try ACESigning.buildSignData(action: "message", aceId: env.from, timestamp: env.timestamp, payload: payload)
}

/// Signature-only check against a known signer.
///
/// `scheme_mismatch` if the envelope scheme differs; `invalid_signature` if it does not verify.
public func verifyEnvelopeSignature(_ env: ACEMessage, scheme: SigningScheme, signingPublicKey: Data) throws {
    let env = try revalidate(env)
    guard env.signature.scheme == scheme else {
        throw ACEError(.schemeMismatch, "envelope signature scheme differs from the signer's")
    }
    let sig = try decodeSignature(env.signature.value, scheme: scheme, code: .invalidEnvelope)
    guard ACESigning.verify(signData: try messageSignData(env), signature: sig, scheme: scheme, publicKey: signingPublicKey) else {
        throw ACEError(.invalidSignature, "message signature does not verify")
    }
}

/// Lowercase hex SHA-256 of the RFC 8785 JSON of the 10 known envelope fields.
public func envelopeFingerprint(_ env: ACEMessage) -> String {
    sha256Hex(JSONWriter.serialize(env.jvalue))
}
