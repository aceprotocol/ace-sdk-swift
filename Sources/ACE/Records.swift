//
//  Records.swift
//  ACE SDK
//
//  Persisted JSON formats (06-security Appendix A). Writers emit compact
//  UTF-8 with keys sorted and `/` unescaped; readers accept any valid JSON. An unknown
//  `version` or a malformed record is `storage_failed`.
//

import Foundation

func storageError(_ key: String, _ msg: String) -> ACEError {
    ACEError(.storageFailed, "\(key): \(msg)")
}

func num(_ i: Int) -> JValue { .number(String(i)) }

/// Status of a staged outbound message.
public enum PendingStatus: String, Sendable, Codable {
    case pending
    /// The relay rejected the envelope as expired; `Outbox.resign` re-signs it.
    case expired
}

/// A signed envelope staged by the `Outbox` and not yet acknowledged.
public struct PendingSend: Sendable, Equatable {
    public let requestId: String
    public let status: PendingStatus
    public let stagedAt: Int
    public let message: ACEMessage
    /// The body `ttl` of a principal `request` (the body is encrypted to the recipient, so the
    /// Outbox keeps it to write the `requests/` record before transport). Persisted as
    /// `requestTtl` only when present (06 Appendix A).
    public let intentDigest: String
    public let type: MessageType
    public let schemaDigest: String
    public let threadId: String?
    public let requestTtl: Int?

    public init(requestId: String, status: PendingStatus, stagedAt: Int, message: ACEMessage, intentDigest: String, type: MessageType, schemaDigest: String, threadId: String? = nil, requestTtl: Int? = nil) {
        self.requestId = requestId
        self.status = status
        self.stagedAt = stagedAt
        self.message = message
        self.intentDigest = intentDigest
        self.type = type
        self.schemaDigest = schemaDigest
        self.threadId = threadId
        self.requestTtl = requestTtl
    }

    /// The same send with another status / message (keeps `requestId`, `stagedAt`, `requestTtl`).
    func with(status: PendingStatus, message: ACEMessage? = nil) -> PendingSend {
        PendingSend(requestId: requestId, status: status, stagedAt: stagedAt, message: message ?? self.message, intentDigest: intentDigest, type: type, schemaDigest: schemaDigest, threadId: threadId, requestTtl: requestTtl)
    }

    func jvalue(version: Bool) -> JValue {
        var o: [String: JValue] = [
            "message": message.jvalue, "requestId": .string(requestId),
            "stagedAt": num(stagedAt), "status": .string(status.rawValue), "intentDigest": .string(intentDigest),
        ]
        o["type"] = .string(type.rawValue)
        o["schemaDigest"] = .string(schemaDigest)
        if let threadId { o["threadId"] = .string(threadId) }
        if let requestTtl { o["requestTtl"] = num(requestTtl) }
        if version { o["version"] = num(1) }
        return .object(o)
    }

    static func parse(_ v: JValue, key: String, versioned: Bool) throws -> PendingSend {
        guard let o = v.objectValue else { throw storageError(key, "pending send must be an object") }
        if versioned { try checkVersion(o, key) }
        guard let requestId = o["requestId"]?.stringValue, let statusText = o["status"]?.stringValue,
              let status = PendingStatus(rawValue: statusText), let stagedAt = o["stagedAt"]?.wireInt,
              let intentDigest = o["intentDigest"]?.stringValue, isSha256Hex(intentDigest),
              let typeText = o["type"]?.stringValue, let type = MessageType(rawValue: typeText),
              let schemaDigest = o["schemaDigest"]?.stringValue, isSha256Hex(schemaDigest),
              let m = o["message"] else {
            throw storageError(key, "malformed pending send")
        }
        let threadId = o["threadId"]?.stringValue
        if let t = o["threadId"], t.stringValue == nil || !isThreadId(t.stringValue!) { throw storageError(key, "invalid threadId") }
        let message: ACEMessage
        do { message = try decodeEnvelope(value: m) } catch { throw storageError(key, "pending envelope is invalid") }
        var requestTtl: Int?
        if let t = o["requestTtl"], !t.isNull {
            guard let n = t.wireInt else { throw storageError(key, "requestTtl must be an integer in [0, 2^53-1]") }
            guard type == .request else { throw storageError(key, "requestTtl belongs to a request only") }
            requestTtl = n
        }
        return PendingSend(requestId: requestId, status: status, stagedAt: stagedAt, message: message, intentDigest: intentDigest, type: type, schemaDigest: schemaDigest, threadId: threadId, requestTtl: requestTtl)
    }
}

func checkVersion(_ o: [String: JValue], _ key: String) throws {
    guard case .number(let lex)? = o["version"], wireIntFromLexeme(lex) == 1 else {
        throw storageError(key, "unknown version")
    }
}

// MARK: - Thread snapshots

extension ThreadSnapshot {
    func jfields() -> [String: JValue] {
        [
            "conversationId": .string(conversationId),
            "history": .array(history.map {
                .object(["from": .string($0.from), "messageId": .string($0.messageId),
                         "timestamp": num($0.timestamp), "type": .string($0.type.rawValue)])
            }),
            "localAceId": .string(localAceId),
            "peerAceId": .string(peerAceId),
            "state": .string(state.rawValue),
            "threadId": .string(threadId),
        ]
    }

    var jvalue: JValue { .object(jfields()) }

    /// Structural parse; semantic checks are done by replaying with `ThreadStateMachine`.
    static func parse(_ v: JValue, key: String) throws -> ThreadSnapshot {
        guard let o = v.objectValue, let c = o["conversationId"]?.stringValue, let t = o["threadId"]?.stringValue,
              let local = o["localAceId"]?.stringValue, let peer = o["peerAceId"]?.stringValue,
              let stateText = o["state"]?.stringValue, let state = ThreadState(rawValue: stateText),
              let history = o["history"]?.arrayValue else {
            throw storageError(key, "malformed thread snapshot")
        }
        let entries: [ThreadHistoryEntry] = try history.map { h in
            guard let typeText = h["type"]?.stringValue, let type = MessageType(rawValue: typeText),
                  let mid = h["messageId"]?.stringValue, let ts = h["timestamp"]?.wireInt, let from = h["from"]?.stringValue else {
                throw storageError(key, "malformed thread history entry")
            }
            return ThreadHistoryEntry(type: type, messageId: mid, timestamp: ts, from: from)
        }
        return ThreadSnapshot(conversationId: c, threadId: t, localAceId: local, peerAceId: peer, state: state, history: entries)
    }
}

// MARK: - Delivery records

enum DeliveryStatus: String { case pending, acked }

struct DeliveryRecord {
    let fingerprint: String
    let message: ParsedMessage
    let receivedAt: Int
    var status: DeliveryStatus
    let thread: ThreadSnapshot?

    static func key(from: String, messageId: String) -> String {
        "deliveries/" + sha256Hex(from, messageId) + ".json"
    }

    func data() throws -> Data {
        let m = message
        guard let body = JSONValue.object(m.body).jvalue else { throw ACEError(.storageFailed, "delivery body is not finite JSON") }
        let messageObject: JValue = .object([
            "body": body, "conversationId": .string(m.conversationId), "from": .string(m.from),
            "messageId": .string(m.messageId), "threadId": m.threadId.map { .string($0) } ?? .null,
            "timestamp": num(m.timestamp), "to": .string(m.to), "type": .string(m.type.rawValue), "schemaDigest": .string(m.schemaDigest),
        ])
        return JSONWriter.serialize(.object([
            "fingerprint": .string(fingerprint), "message": messageObject, "receivedAt": num(receivedAt),
            "status": .string(status.rawValue), "thread": thread?.jvalue ?? .null,
            "version": num(1),
        ]))
    }

    static func parse(_ v: JValue, key: String) throws -> DeliveryRecord {
        guard let o = v.objectValue else { throw storageError(key, "delivery record must be an object") }
        try checkVersion(o, key)
        guard let fingerprint = o["fingerprint"]?.stringValue, let receivedAt = o["receivedAt"]?.wireInt,
              let statusText = o["status"]?.stringValue, let status = DeliveryStatus(rawValue: statusText),
              let m = o["message"]?.objectValue, let rawBody = m["body"], let body = JSONValue(rawBody)?.objectValue,
              let c = m["conversationId"]?.stringValue, let from = m["from"]?.stringValue,
              let mid = m["messageId"]?.stringValue, let ts = m["timestamp"]?.wireInt, let to = m["to"]?.stringValue,
              let schemaDigest = m["schemaDigest"]?.stringValue, isSha256Hex(schemaDigest),
              let typeText = m["type"]?.stringValue, let type = MessageType(rawValue: typeText) else {
            throw storageError(key, "malformed delivery record")
        }
        var threadId: String?
        if let t = m["threadId"], !t.isNull {
            guard let s = t.stringValue else { throw storageError(key, "malformed delivery threadId") }
            threadId = s
        }
        var thread: ThreadSnapshot?
        if let t = o["thread"], !t.isNull { thread = try ThreadSnapshot.parse(t, key: key) }
        let message = ParsedMessage(messageId: mid, from: from, to: to, conversationId: c, type: type, threadId: threadId,
                                    timestamp: ts, body: body, schemaDigest: schemaDigest)
        return DeliveryRecord(fingerprint: fingerprint, message: message, receivedAt: receivedAt,
                              status: status, thread: thread)
    }
}

// MARK: - Quarantine

func quarantineData(_ env: ACEMessage, error: ACEError, fingerprint: String, at: Int) -> Data {
    JSONWriter.serialize(.object([
        "code": .string(error.code.rawValue),
        "envelope": env.jvalue,
        "fingerprint": .string(fingerprint),
        "quarantinedAt": num(at),
        "reason": .string(String(error.message.prefix(1000))),
        "version": num(1),
    ]))
}

// MARK: - Peers

struct PinnedPeer {
    let peer: VerifiedPeer
    let fetchedAt: Int

    static func key(_ aceId: String) -> String { "peers/" + sha256Hex(Data(aceId.utf8)) + ".json" }

    func data() -> Data {
        let p = peer
        return JSONWriter.serialize(.object([
            "aceId": .string(p.aceId),
            "encryptionPublicKey": .string(ACEBase64.encode(p.encryptionPublicKey)),
            "fetchedAt": num(fetchedAt),
            "profile": p.profile?.jvalue ?? .null,
            "registeredAt": num(p.registeredAt),
            "registrationSignature": .string(p.registrationSignature),
            "scheme": .string(p.scheme.rawValue),
            "signingPublicKey": .string(ACEBase64.encode(p.signingPublicKey)),
            "source": .string(p.source.rawValue),
            "version": num(1),
        ]))
    }

    /// Parse and re-verify (binding for relay; ID hash and key lengths for registration).
    static func parse(_ v: JValue, key: String, aceId: String) throws -> PinnedPeer {
        guard let o = v.objectValue else { throw storageError(key, "peer record must be an object") }
        try checkVersion(o, key)
        guard let id = o["aceId"]?.stringValue, id == aceId, let schemeText = o["scheme"]?.stringValue,
              let scheme = SigningScheme(rawValue: schemeText), let enc = o["encryptionPublicKey"]?.stringValue,
              let spk = o["signingPublicKey"]?.stringValue, let registeredAt = o["registeredAt"]?.wireInt,
              let fetchedAt = o["fetchedAt"]?.wireInt, let sourceText = o["source"]?.stringValue,
              let source = PeerSource(rawValue: sourceText) else {
            throw storageError(key, "malformed peer record")
        }
        var profile: AgentProfile?
        if let p = o["profile"], !p.isNull {
            do { profile = try AgentProfile.parse(p) } catch { throw storageError(key, "malformed profile") }
        }
        var signature: String?
        if let s = o["registrationSignature"], !s.isNull {
            guard let text = s.stringValue else { throw storageError(key, "malformed registrationSignature") }
            signature = text
        }
        do {
            guard let signature else { throw storageError(key, "binding without signature") }
            let verified = try verifyPeerRecord(PeerRecord(aceId: id, scheme: schemeText, encryptionPublicKey: enc,
                                                           signingPublicKey: spk, registrationSignature: signature,
                                                           registeredAt: registeredAt, profile: profile), clock: { fetchedAt })
            let peer = VerifiedPeer(aceId: id, scheme: scheme, signingPublicKey: verified.signingPublicKey,
                                    encryptionPublicKey: verified.encryptionPublicKey, registeredAt: registeredAt,
                                    registrationSignature: signature, source: source, profile: verified.profile)
            return PinnedPeer(peer: peer, fetchedAt: fetchedAt)
        } catch let e as ACEError where e.code != .storageFailed {
            throw storageError(key, "re-verification failed: \(e.message)")
        }
    }
}
