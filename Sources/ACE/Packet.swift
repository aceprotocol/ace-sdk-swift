//
//  Packet.swift
//  ACE SDK
//
//  The packet: the only wire object. Prekey encryption (X-Wing → HKDF-SHA256 → AES-256-GCM) plus an ML-DSA-65 signature.
//
//    header  = encodePayload("ace.v1.packet", from, to, messageId, decimal(timestamp), prekeyId, kemCiphertextBytes)
//    (ss, kemCiphertext) = XWing.Encapsulate(prekey.publicKey)
//    key     = HKDF-SHA256(ikm = ss, salt = "", info = header, L = 32)
//    plaintext = u32be(len(content)) ‖ content ‖ zeros to a bucket (03 § Encryption)
//    payload = nonce[12] ‖ AES-256-GCM(key, nonce, plaintext, aad = header)
//    signature (action "packet") over M(from, timestamp, seq, encodePayload(to, messageId, prekeyId, kemCiphertextBytes, payloadBytes))
//
//  The header binds from / to / messageId: re-signing a stripped packet under another identity changes `from`, so the
//  AEAD no longer opens.
//

import CryptoKit
import Foundation

private func bad(_ msg: String) -> ACEError { ACEError(.invalidPacket, msg) }

// MARK: - Prekey

/// A published X-Wing prekey: `id` = lowercase hex SHA-256 of the 1216-byte public key.
public struct Prekey: Sendable, Equatable, Hashable {
    public let id: String
    public let publicKey: Data

    /// `invalid_argument` unless `publicKey` is 1216 bytes that decode as an X-Wing public key (`XWing.isPublicKey`).
    public init(publicKey: Data) throws {
        guard XWing.isPublicKey(publicKey) else {
            throw ACEError(.invalidArgument, "prekey must be a \(ACELimits.kemPublicKeySize)-byte X-Wing public key")
        }
        self.init(validated: publicKey)
    }

    /// A key already known to be an X-Wing public key (derived from a seed we hold, or checked when its content was
    /// decoded): no trial encapsulation again.
    package init(validated publicKey: Data) {
        self.publicKey = publicKey
        self.id = sha256Hex(publicKey)
    }

    /// `{id, publicKey}`.
    public var jsonValue: JSONValue { ["id": .string(id), "publicKey": .string(ACEBase64.encode(publicKey))] }

    /// Exactly `{id, publicKey}` with a canonical 1216-byte X-Wing public key whose SHA-256 is `id`; nil otherwise.
    /// `ownSeed`: the public half stored beside a seed we hold (the vault), checked for its length and ID only.
    package init?(_ v: JSONValue?, ownSeed: Bool = false) {
        guard let o = v?.objectValue, Set(o.keys) == ["id", "publicKey"], let id = o["id"]?.stringValue, let text = o["publicKey"]?.stringValue,
              let raw = try? decodeB64(text, code: .invalidArgument, what: "prekey", maxBytes: ACELimits.kemPublicKeySize),
              raw.count == ACELimits.kemPublicKeySize else { return nil }
        let key: Prekey
        if ownSeed { key = Prekey(validated: raw) } else {
            guard let checked = try? Prekey(publicKey: raw) else { return nil }
            key = checked
        }
        guard key.id == id else { return nil }
        self = key
    }
}

/// X-Wing (draft-connolly-cfrg-xwing-kem, CryptoKit `XWingMLKEM768X25519`) seed helpers.
public enum XWing {
    /// A fresh random 32-byte X-Wing seed.
    public static func generateSeed() -> Data { Data(randomBytes(ACELimits.kemSeedSize)) }

    /// The 1216-byte public key of a 32-byte seed; `invalid_argument` for a malformed seed.
    public static func publicKey(fromSeed seed: Data) throws -> Data {
        Data(try privateKey(seed).publicKey.rawRepresentation)
    }

    /// True when `raw` is 1216 bytes whose ML-KEM-768 half (the first 1184 bytes) is a valid FIPS 203 encapsulation key.
    /// CryptoKit accepts out-of-range coefficients at construction, so a trial encapsulation with that ML-KEM key alone
    /// (its result discarded) checks the modulus. Any 32 bytes are an X25519 half: no small-order or all-zero check
    /// (03 § X-Wing).
    public static func isPublicKey(_ raw: Data) -> Bool {
        guard raw.count == ACELimits.kemPublicKeySize,
              let key = try? MLKEM768.PublicKey(rawRepresentation: raw.prefix(mlkemPublicKeySize)) else { return false }
        return (try? key.encapsulate()) != nil
    }

    /// The ML-KEM-768 half of an X-Wing public key (`pk_M ‖ pk_X`).
    private static let mlkemPublicKeySize = 1184

    package static func privateKey(_ seed: Data) throws -> XWingMLKEM768X25519.PrivateKey {
        guard seed.count == ACELimits.kemSeedSize else { throw ACEError(.invalidArgument, "X-Wing seed must be 32 bytes") }
        do { return try XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: nil) } catch {
            throw ACEError(.invalidArgument, "X-Wing seed expansion failed")
        }
    }
}

// MARK: - Private content

/// The `admission` member of an Outbox retry (05 § Admission recovery): `proof`, the permit the receiver issued to the
/// sender; `permit`, a reply permit the sender issued to the receiver; `source`, the sender's PublishedAgent. Only their
/// shape is checked on decoding.
package struct Admission: Sendable, Equatable {
    package let proof: JSONValue
    package let permit: JSONValue
    package let source: JSONValue

    package init(proof: JSONValue, permit: JSONValue, source: JSONValue) {
        self.proof = proof
        self.permit = permit
        self.source = source
    }

    var jsonValue: JSONValue { ["proof": proof, "permit": permit, "source": source] }
}

/// The private content of a packet, `{type, schemaDigest, threadId?, body, prekey, admission?}`, carried entirely inside
/// the ciphertext. `prekey` is the 1216-byte X-Wing public key the sender offers the receiver for its replies (04 § Peer
/// prekeys), required on the wire. `prekey` and `admission` never reach the host: `ReceivedMessage.content` and stored
/// records carry neither.
public struct PrivateContent: Sendable, Equatable {
    public let type: String
    public let schemaDigest: String
    public let threadId: String?
    public let body: [String: JSONValue]
    package var prekey: Data?
    package var admission: Admission?

    /// `invalid_body` for a type that is not a namespaced identifier, a digest that is not 64 lowercase hex, a bad
    /// `threadId`, or a body with a non-finite number or nesting deeper than 32.
    public init(type: String, schemaDigest: String, threadId: String? = nil, body: [String: JSONValue]) throws {
        guard isNamespacedIdentifier(type) else { throw ACEError(.invalidBody, "type must be a namespaced identifier") }
        guard isSHA256Hex(schemaDigest) else { throw ACEError(.invalidBody, "schemaDigest must be 64 lowercase hex") }
        if let threadId, !isThreadId(threadId) { throw ACEError(.invalidBody, "invalid threadId") }
        try checkJSONValue(.object(body), depth: 1)  // depth counts from the private content object (02 § JSON values)
        self.type = type
        self.schemaDigest = schemaDigest
        self.threadId = threadId
        self.body = body
        self.prekey = nil
        self.admission = nil
    }

    /// This content carrying `prekey`, the public key offered to the receiver.
    package func with(prekey: Data) -> PrivateContent {
        var c = self
        c.prekey = prekey
        return c
    }

    /// This content carrying `admission` (nil: none).
    package func with(admission: Admission?) -> PrivateContent {
        var c = self
        c.admission = admission
        return c
    }

    /// The `jsonValue` shape read back from a local store record (members beyond it are ignored), or nil.
    package init?(stored c: [String: JSONValue]) {
        guard let type = c["type"]?.stringValue, let digest = c["schemaDigest"]?.stringValue, let body = c["body"]?.objectValue,
              c["threadId"].map({ $0.stringValue != nil }) ?? true,
              let content = try? PrivateContent(type: type, schemaDigest: digest, threadId: c["threadId"]?.stringValue, body: body) else {
            return nil
        }
        self = content
    }

    package var jsonValue: JSONValue {
        var o: [String: JSONValue] = ["type": .string(type), "schemaDigest": .string(schemaDigest), "body": .object(body)]
        if let threadId { o["threadId"] = .string(threadId) }
        if let prekey { o["prekey"] = .string(ACEBase64.encode(prekey)) }
        if let admission { o["admission"] = admission.jsonValue }
        return .object(o)
    }

    /// Canonical JSON; `invalid_argument` without a 1216-byte `prekey`, `limit_exceeded` over `ACELimits.maxPlaintextBytes`.
    public func jsonData() throws -> Data {
        guard prekey?.count == ACELimits.kemPublicKeySize else {
            throw ACEError(.invalidArgument, "private content must carry a \(ACELimits.kemPublicKeySize)-byte prekey")
        }
        let data = try jsonValue.jsonData()
        guard data.count <= ACELimits.maxPlaintextBytes else {
            throw ACEError(.limitExceeded, "private content exceeds \(ACELimits.maxPlaintextBytes) bytes")
        }
        return data
    }

    /// Strict decoding (`invalid_body`): a closed object `{type, schemaDigest, threadId?, body, prekey, admission?}`, depth
    /// ≤ 32; `prekey` the canonical Base64 of a 1216-byte X-Wing public key, kept in `prekey`; `admission` the closed `{proof, permit, source}`
    /// of three objects.
    public init(json: Data) throws {
        guard json.count <= ACELimits.maxPlaintextBytes else { throw ACEError(.invalidBody, "private content is too large") }
        let v: JSONValue
        do { v = try JSONParser.parse(json) } catch {
            throw ACEError(.invalidBody, "private content is not valid JSON")
        }
        guard let o = v.objectValue, Set(o.keys).isSubset(of: ["type", "schemaDigest", "threadId", "body", "prekey", "admission"]),
              let type = o["type"]?.stringValue, let digest = o["schemaDigest"]?.stringValue, let body = o["body"]?.objectValue else {
            throw ACEError(.invalidBody, "private content must be {type, schemaDigest, threadId?, body, prekey}")
        }
        guard let prekeyText = o["prekey"]?.stringValue,
              let prekey = try? decodeB64(prekeyText, code: .invalidBody, what: "prekey", maxBytes: ACELimits.kemPublicKeySize),
              prekey.count == ACELimits.kemPublicKeySize else {
            throw ACEError(.invalidBody, "prekey must be \(ACELimits.kemPublicKeySize) bytes of canonical Base64")
        }
        // A key that does not decode as an X-Wing public key is malformed: never held, never encrypted to.
        guard XWing.isPublicKey(prekey) else { throw ACEError(.invalidBody, "prekey is not an X-Wing public key") }
        var threadId: String?
        if let t = o["threadId"] {
            guard let s = t.stringValue else { throw ACEError(.invalidBody, "invalid threadId") }
            threadId = s
        }
        try self.init(type: type, schemaDigest: digest, threadId: threadId, body: body)
        self.prekey = prekey
        if let a = o["admission"] {
            guard let m = a.objectValue, Set(m.keys) == ["proof", "permit", "source"], let proof = m["proof"], proof.objectValue != nil,
                  let permit = m["permit"], permit.objectValue != nil, let source = m["source"], source.objectValue != nil else {
                throw ACEError(.invalidBody, "admission must be {proof, permit, source}")
            }
            guard type != CoreTypes.receipt, type != CoreTypes.contact else { throw ACEError(.invalidBody, "receipts and contacts carry no admission") }
            try checkJSONValue(a, depth: 1)
            self.admission = Admission(proof: proof, permit: permit, source: source)
        }
    }
}

/// Finite numbers and depth ≤ `maxDepth` (the top-level object is depth 0); `code` otherwise.
package func checkJSONValue(_ value: JSONValue, depth: Int = 0, maxDepth: Int = ACELimits.maxJSONDepth, code: ACEError.Code = .invalidBody) throws {
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

// MARK: - Packet

/// `encryption`: the prekey it was sealed to and the Base64 KEM ciphertext and payload.
public struct PacketEncryption: Sendable, Equatable {
    public let prekey: String
    public let kemCiphertext: String
    public let payload: String
}

/// A decoded packet. Obtain from `Packet(json:)` or `createPacket`.
public struct Packet: Sendable, Equatable {
    public static let version = "1"
    /// Decoded `encryption.payload`: `nonce[12] ‖ ciphertext ‖ tag[16]`, its ciphertext length a plaintext bucket.
    package static let minPayloadBytes = 28
    package static let maxPayloadBytes = largestPlaintextBucket + minPayloadBytes

    /// `u32be` length prefix of a padded plaintext.
    private static let lengthPrefixBytes = 4
    /// The bucket of every content over 2^20 − 4 bytes: `MAX_PLAINTEXT_BYTES + 4`.
    private static let largestPlaintextBucket = ACELimits.maxPlaintextBytes + lengthPrefixBytes

    /// Every padded plaintext length: the powers of two from `MIN_PLAINTEXT_BUCKET` to 2^20, and `MAX_PLAINTEXT_BYTES + 4`.
    package static let plaintextBuckets: Set<Int> = Set(
        sequence(first: ACELimits.minPlaintextBucket) { $0 < 1 << 20 ? $0 * 2 : nil } + [largestPlaintextBucket])

    /// The padded length of `contentLength` content bytes: the smallest power of two ≥ `MIN_PLAINTEXT_BUCKET` holding
    /// `contentLength + 4`; above 2^20, `MAX_PLAINTEXT_BYTES + 4`.
    package static func plaintextBucket(_ contentLength: Int) -> Int {
        let n = contentLength + lengthPrefixBytes
        if n > 1 << 20 { return largestPlaintextBucket }
        var b = ACELimits.minPlaintextBucket
        while b < n { b *= 2 }
        return b
    }

    /// `u32be(len(content)) ‖ content ‖ zeros` to `plaintextBucket(len(content))`; `content` must be at most
    /// `MAX_PLAINTEXT_BYTES` (`sealPacket` checks it: `limit_exceeded`).
    package static func pad(_ content: Data) -> Data {
        let n = content.count
        precondition(n <= ACELimits.maxPlaintextBytes, "Packet.pad: content exceeds MAX_PLAINTEXT_BYTES")
        let bucket = plaintextBucket(n)
        var out = Data(capacity: bucket)
        out.append(contentsOf: [UInt8(truncatingIfNeeded: n >> 24), UInt8(truncatingIfNeeded: n >> 16), UInt8(truncatingIfNeeded: n >> 8),
                                UInt8(truncatingIfNeeded: n)])
        out.append(content)
        out.append(Data(count: bucket - out.count))
        return out
    }

    /// The content inside a padded plaintext; `invalid_body` unless its length is a bucket, the prefix is at most
    /// `MAX_PLAINTEXT_BYTES` and fits, the bucket is the one the prefix implies and the padding is all zero.
    package static func unpad(_ p: Data) throws -> Data {
        guard plaintextBuckets.contains(p.count) else { throw ACEError(.invalidBody, "plaintext padding is invalid") }
        let n = p.prefix(lengthPrefixBytes).reduce(0) { $0 << 8 | Int($1) }
        let start = p.startIndex + lengthPrefixBytes  // a slice keeps its parent's indices
        guard n <= ACELimits.maxPlaintextBytes, lengthPrefixBytes + n <= p.count, plaintextBucket(n) == p.count,
              p[(start + n)...].allSatisfy({ $0 == 0 }) else {
            throw ACEError(.invalidBody, "plaintext padding is invalid")
        }
        return p.subdata(in: start..<(start + n))
    }

    public let messageId: String
    public let from: String
    public let to: String
    public let timestamp: Int
    public let encryption: PacketEncryption
    public let signature: SignatureEnvelope
    /// Decoded `encryption.kemCiphertext` / `encryption.payload`.
    package let kemCiphertext: Data
    package let payload: Data

    package init(messageId: String, from: String, to: String, timestamp: Int, prekey: String, kemCiphertext: Data, payload: Data,
                 signature: SignatureEnvelope) {
        self.messageId = messageId
        self.from = from
        self.to = to
        self.timestamp = timestamp
        self.encryption = PacketEncryption(prekey: prekey, kemCiphertext: ACEBase64.encode(kemCiphertext), payload: ACEBase64.encode(payload))
        self.signature = signature
        self.kemCiphertext = kemCiphertext
        self.payload = payload
    }

    /// Strict decoding. A closed object at every level; `unsupported_version` for an `ace` other than `"1"` (checked before
    /// the member set); everything else `invalid_packet`.
    public init(json: Data) throws {
        guard json.count <= ACELimits.maxPacketBytes else { throw bad("packet exceeds \(ACELimits.maxPacketBytes) bytes") }
        let v: JSONValue
        do { v = try JSONParser.parse(json, maxDepth: 4) } catch { throw bad("packet is not JSON: \(error.reason)") }
        guard let o = v.objectValue else { throw bad("packet must be a JSON object") }
        guard let ace = o["ace"]?.stringValue else { throw bad("ace must be a string") }
        guard ace == Self.version else { throw ACEError(.unsupportedVersion, "unsupported ACE version '\(String(ace.prefix(16)))'") }
        guard Set(o.keys) == ["ace", "messageId", "from", "to", "timestamp", "encryption", "signature"] else {
            throw bad("packet has unknown or missing members")
        }
        guard let messageId = o["messageId"]?.stringValue, isMessageId(messageId) else { throw bad("messageId must be a lowercase UUIDv4") }
        guard let from = o["from"]?.stringValue, isACEId(from), let to = o["to"]?.stringValue, isACEId(to), from != to else {
            throw bad("from/to must be distinct ACE IDs")
        }
        guard let timestamp = o["timestamp"]?.wireInt else { throw bad("timestamp must be an integer in [0, 2^53-1]") }
        guard let enc = o["encryption"]?.objectValue, Set(enc.keys) == ["prekey", "kemCiphertext", "payload"] else {
            throw bad("encryption must be {prekey, kemCiphertext, payload}")
        }
        guard let prekey = enc["prekey"]?.stringValue, isSHA256Hex(prekey) else { throw bad("encryption.prekey must be 64 lowercase hex") }
        guard let kemText = enc["kemCiphertext"]?.stringValue,
              let kem = try? decodeB64(kemText, code: .invalidPacket, what: "kemCiphertext", maxBytes: ACELimits.kemCiphertextSize),
              kem.count == ACELimits.kemCiphertextSize else { throw bad("encryption.kemCiphertext must be 1120 bytes of canonical Base64") }
        guard let payloadText = enc["payload"]?.stringValue,
              let payload = try? decodeB64(payloadText, code: .invalidPacket, what: "payload", maxBytes: Self.maxPayloadBytes),
              Self.plaintextBuckets.contains(payload.count - Self.minPayloadBytes) else {
            throw bad("encryption.payload is not a padded bucket")
        }
        guard let signature = SignatureEnvelope(operational: o["signature"]) else {
            throw bad("signature must be {scheme: ml-dsa-65, seq, value}")
        }
        self.init(messageId: messageId, from: from, to: to, timestamp: timestamp, prekey: prekey, kemCiphertext: kem, payload: payload,
                  signature: signature)
    }

    package var jsonValue: JSONValue {
        .object([
            "ace": .string(Self.version), "messageId": .string(messageId), "from": .string(from), "to": .string(to),
            "timestamp": .number(Double(timestamp)),
            "encryption": .object(["prekey": .string(encryption.prekey), "kemCiphertext": .string(encryption.kemCiphertext),
                                   "payload": .string(encryption.payload)]),
            "signature": signature.jsonValue,
        ])
    }

    /// Canonical JSON.
    public func jsonData() -> Data { try! jsonValue.jsonData() }  // every member is a string or a wire integer

    /// Lowercase hex SHA-256 of the canonical JSON.
    public var fingerprint: String { sha256Hex(jsonData()) }

    /// `encodePayload("ace.v1.packet", from, to, messageId, decimal(timestamp), prekeyId, kemCiphertextBytes)`.
    package static func header(from: String, to: String, messageId: String, timestamp: Int, prekey: String, kemCiphertext: Data) -> Data {
        ACESigning.encodePayload([.string("ace.v1.packet"), .string(from), .string(to), .string(messageId), .string(decimal(timestamp)),
                                  .string(prekey), .data(kemCiphertext)])
    }

    package var header: Data {
        Self.header(from: from, to: to, messageId: messageId, timestamp: timestamp, prekey: encryption.prekey, kemCiphertext: kemCiphertext)
    }

    /// `encodePayload(to, messageId, prekeyId, kemCiphertextBytes, payloadBytes)`: the packet signature payload.
    package static func signPayload(to: String, messageId: String, prekey: String, kemCiphertext: Data, payload: Data) -> Data {
        ACESigning.encodePayload([.string(to), .string(messageId), .string(prekey), .data(kemCiphertext), .data(payload)])
    }

    package static func aeadKey(_ sharedSecret: SymmetricKey, header: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: sharedSecret, salt: Data(), info: header, outputByteCount: 32)
    }

    /// `nonce ‖ AES-256-GCM(key, nonce, plaintext, aad = header)` (deterministic given `nonce`: vectors); `plaintext` is
    /// already padded.
    package static func seal(_ plaintext: Data, sharedSecret: SymmetricKey, header: Data, nonce: AES.GCM.Nonce = AES.GCM.Nonce()) throws -> Data {
        do {
            let box = try AES.GCM.seal(plaintext, using: aeadKey(sharedSecret, header: header), nonce: nonce, authenticating: header)
            return Data(nonce) + box.ciphertext + box.tag
        } catch {
            throw ACEError(.invalidArgument, "AES-GCM seal failed")
        }
    }
}

/// Encrypt `content` to `prekey` and sign it as `sender` (the packet's `from`). Order: arguments (`invalid_argument`) →
/// content size (`limit_exceeded`) → `checkUsable(sender, timestamp)` (`identity_unavailable`, before any crypto) →
/// encapsulate → seal → sign.
public func createPacket(sender: any ACEIdentity, to: String, prekey: Prekey, content: PrivateContent,
                         messageId: String = UUID().uuidString.lowercased(), timestamp: Int? = nil) throws -> Packet {
    guard isACEId(to), to != sender.getACEId() else { throw ACEError(.invalidArgument, "to must be another ACE ID") }
    guard isMessageId(messageId) else { throw ACEError(.invalidArgument, "messageId must be a lowercase UUIDv4") }
    let ts = timestamp ?? systemClock()
    guard isWireInt(ts) else { throw ACEError(.invalidArgument, "timestamp must be an integer in [0, 2^53-1]") }
    let plaintext = try content.jsonData()
    let from = sender.getACEId()
    _ = try usableSigningSeq(sender, now: ts)
    let encapsulated: (sharedSecret: SymmetricKey, encapsulated: Data)
    do {
        let r = try XWingMLKEM768X25519.PublicKey(rawRepresentation: prekey.publicKey).encapsulate()
        encapsulated = (r.sharedSecret, Data(r.encapsulated))
    } catch {
        throw ACEError(.invalidArgument, "X-Wing encapsulation failed")
    }
    return try sealPacket(sender: sender, from: from, to: to, messageId: messageId, timestamp: ts, prekey: prekey.id, plaintext: plaintext,
                          sharedSecret: encapsulated.sharedSecret, kemCiphertext: encapsulated.encapsulated)
}

/// The deterministic core of `createPacket` (vectors inject `sharedSecret`, `kemCiphertext` and `nonce`): seals
/// `Packet.pad(plaintext)`, `plaintext` being the content's canonical JSON.
package func sealPacket(sender: any ACEIdentity, from: String, to: String, messageId: String, timestamp: Int, prekey: String, plaintext: Data,
                        sharedSecret: SymmetricKey, kemCiphertext: Data, nonce: AES.GCM.Nonce = AES.GCM.Nonce()) throws -> Packet {
    guard plaintext.count <= ACELimits.maxPlaintextBytes else {
        throw ACEError(.limitExceeded, "private content exceeds \(ACELimits.maxPlaintextBytes) bytes")
    }
    let header = Packet.header(from: from, to: to, messageId: messageId, timestamp: timestamp, prekey: prekey, kemCiphertext: kemCiphertext)
    let payload = try Packet.seal(Packet.pad(plaintext), sharedSecret: sharedSecret, header: header, nonce: nonce)
    let signature = try operationalSign(sender, action: "packet", timestamp: timestamp,
                                        payload: Packet.signPayload(to: to, messageId: messageId, prekey: prekey, kemCiphertext: kemCiphertext,
                                                                    payload: payload))
    return Packet(messageId: messageId, from: from, to: to, timestamp: timestamp, prekey: prekey, kemCiphertext: kemCiphertext,
                  payload: payload, signature: signature)
}

/// The packet signature by `sender` (the verified KEL of `packet.from`) at `now`: `invalid_signature` when `sender` is
/// another identity, otherwise 01 § Operational signatures (`stale_peer_binding`, `invalid_signature`).
public func verifyPacketSignature(_ packet: Packet, sender: KelState, now: Int) throws {
    guard sender.aceId == packet.from else { throw ACEError(.invalidSignature, "from does not match the sender's KEL") }
    try verifyOperational(packet.signature, state: sender, action: "packet", timestamp: packet.timestamp,
                          payload: Packet.signPayload(to: packet.to, messageId: packet.messageId, prekey: packet.encryption.prekey,
                                                      kemCiphertext: packet.kemCiphertext, payload: packet.payload), now: now)
}

/// Decrypt with the prekey seed (`decryption_failed` for every crypto failure), then unpad and decode the private content
/// (`invalid_body`).
public func decryptPacket(_ packet: Packet, seed: Data) throws -> PrivateContent {
    try PrivateContent(json: try decryptPlaintext(packet, seed: seed))
}

/// 06 step 6: decrypt with the prekey seed (`decryption_failed` for every crypto failure) and unpad (`invalid_body`); the
/// content bytes, not yet decoded.
package func decryptPlaintext(_ packet: Packet, seed: Data) throws -> Data {
    let key = try XWing.privateKey(seed)
    guard sha256Hex(Data(key.publicKey.rawRepresentation)) == packet.encryption.prekey else {
        throw ACEError(.decryptionFailed, "seed is not the packet's prekey")
    }
    let shared: SymmetricKey
    do { shared = try key.decapsulate(packet.kemCiphertext) } catch { throw ACEError(.decryptionFailed, "X-Wing decapsulation failed") }
    let header = packet.header, p = packet.payload
    let plaintext: Data
    do {
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: p.prefix(12)), ciphertext: p.dropFirst(12).dropLast(16), tag: p.suffix(16))
        plaintext = try AES.GCM.open(box, using: Packet.aeadKey(shared, header: header), authenticating: header)
    } catch {
        throw ACEError(.decryptionFailed, "AEAD authentication failed")
    }
    return try Packet.unpad(plaintext)
}

/// `now - OFFLINE_WINDOW_SECONDS <= timestamp <= now + TIMESTAMP_WINDOW_SECONDS` (06 step 5), or `stale_timestamp`.
package func checkPacketTime(_ packet: Packet, now: Int) throws {
    guard packet.timestamp >= now - ACELimits.offlineWindowSeconds, packet.timestamp <= now + ACELimits.timestampWindowSeconds else {
        throw ACEError(.staleTimestamp, "packet timestamp is outside the window")
    }
}
