//
//  Principal.swift
//  ACE SDK
//
//  Principal binding (09-principal): records, the `principal` signing context,
//  the same-account rules and the `requests/` ledger. Mirrors sdk-py `ace/principal.py`.
//

import Foundation

// MARK: - Record

/// A `(scheme, publicKey)` pair as it appears in a principal record (`signer`), in
/// `InboxPrincipal.selfSigner` and in the trusted-signer set.
public struct PrincipalKey: Codable, Sendable, Hashable {
    /// Kept as a string so an unsupported scheme is reported as `invalid_principal`.
    public var scheme: String
    /// Canonical Base64 of the raw key, used exactly as it appears in the record.
    public var publicKey: String

    public init(scheme: String, publicKey: String) {
        self.scheme = scheme
        self.publicKey = publicKey
    }
}

/// 09-principal § Principal Record (wire shape). Semantic checks: `validatePrincipalRecord`.
public struct PrincipalRecord: Codable, Sendable, Equatable {
    public var account: String
    public var roles: [String]
    public var signer: PrincipalKey
    public var issuedAt: Int
    /// Required (R-P24): `issuedAt < expiresAt <= issuedAt + 31622400`.
    public var expiresAt: Int
    public var scope: String?
    public var signature: String

    /// A new valid signature of the same statement is not a conflicting grant.
    func sameClaims(as other: PrincipalRecord) -> Bool {
        var a = self, b = other
        a.signature = ""
        b.signature = ""
        return a == b
    }

    /// R-P36 monotonicity within one (subject, account, signer) authority domain: this record
    /// may replace `old` only with a strictly newer `issuedAt`, or the same signed claims at the
    /// same `issuedAt`.
    func supersedes(_ old: PrincipalRecord) -> Bool {
        issuedAt > old.issuedAt || (issuedAt == old.issuedAt && sameClaims(as: old))
    }

    public init(account: String, roles: [String], signer: PrincipalKey, issuedAt: Int, expiresAt: Int,
                scope: String? = nil, signature: String) {
        self.account = account
        self.roles = roles
        self.signer = signer
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.scope = scope
        self.signature = signature
    }

    /// Strict wire parse (09 § Validation rule 1): failures are `invalid_principal`; a `null`
    /// optional member is absent; unknown members are ignored.
    public init(json: Data) throws {
        let v: JValue
        do { v = try JSONParser.parse(json) } catch { throw ACEError(.invalidPrincipal, "principal is not JSON") }
        self = try PrincipalRecord.parse(v)
    }

    /// The wire JSON (compact, keys sorted; `scope` omitted when absent).
    public func jsonData() -> Data {
        JSONWriter.serialize(jvalue)
    }

    static func parse(_ v: JValue) throws -> PrincipalRecord {
        guard let o = v.objectValue else { throw principalError("principal must be a JSON object") }
        guard let s = o["signer"]?.objectValue else { throw principalError("principal.signer must be an object") }
        guard let scheme = s["scheme"]?.stringValue, let pk = s["publicKey"]?.stringValue else {
            throw principalError("principal.signer must be {scheme, publicKey} strings")
        }
        guard let rolesV = o["roles"]?.arrayValue else { throw principalError("principal.roles must be an array of strings") }
        var roles: [String] = []
        for r in rolesV {
            guard let t = r.stringValue else { throw principalError("principal.roles must be an array of strings") }
            roles.append(t)
        }
        guard let issuedAt = o["issuedAt"]?.wireInt else { throw principalError("principal.issuedAt must be a wire integer") }
        guard let expiresAt = o["expiresAt"]?.wireInt else { throw principalError("principal.expiresAt must be a wire integer") }
        guard let account = o["account"]?.stringValue else { throw principalError("principal.account must be a string") }
        guard let signature = o["signature"]?.stringValue else { throw principalError("principal.signature must be a string") }
        var scope: String?
        if let sc = o["scope"], !sc.isNull {
            guard let t = sc.stringValue else { throw principalError("principal.scope must be a string") }
            scope = t
        }
        return PrincipalRecord(account: account, roles: roles, signer: PrincipalKey(scheme: scheme, publicKey: pk),
                               issuedAt: issuedAt, expiresAt: expiresAt, scope: scope, signature: signature)
    }

    var jvalue: JValue {
        var o: [String: JValue] = [
            "account": .string(account),
            "roles": .array(roles.map { .string($0) }),
            "signer": .object(["scheme": .string(signer.scheme), "publicKey": .string(signer.publicKey)]),
            "issuedAt": num(issuedAt),
            "expiresAt": num(expiresAt),
            "signature": .string(signature),
        ]
        if let scope { o["scope"] = .string(scope) }
        return .object(o)
    }
}

/// The key that signs a principal record. Any key source works (passkey PRF, Secure Enclave, HSM).
public struct PrincipalSigner: Sendable {
    public let scheme: SigningScheme
    /// Raw signing public key (32 bytes ed25519, 33-byte compressed secp256k1).
    public let publicKey: Data
    /// Sign the 32-byte digest (ed25519: 64 bytes; secp256k1: r‖s‖v, low-S).
    public let sign: @Sendable (Data) throws -> Data

    public init(scheme: SigningScheme, publicKey: Data, sign: @escaping @Sendable (Data) throws -> Data) {
        self.scheme = scheme
        self.publicKey = publicKey
        self.sign = sign
    }

    /// Sign with an ACE identity's signing key.
    public init(identity: any ACEIdentity) {
        self.init(scheme: identity.getSigningScheme(), publicKey: identity.getSigningPublicKey(),
                  sign: { try identity.sign($0) })
    }
}

/// The roles in canonical order: `controller` approves, `delegate` acts.
public let principalRoles: [String] = ["controller", "delegate"]
private let allowedRoles: Set<[String]> = [["controller"], ["delegate"], ["controller", "delegate"]]
private let caip10Regex = try! NSRegularExpression(pattern: #"\A[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}\z"#)
private let eip155AddressRegex = try! NSRegularExpression(pattern: #"\A0x[0-9a-fA-F]{40}\z"#)
private let wrongDecider = "decision from a different controller than the request was sent to"

private func principalError(_ m: String) -> ACEError { ACEError(.invalidPrincipal, m) }

/// A CAIP-10 account ID (`^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$`).
public func isCAIP10(_ value: String) -> Bool { regexFullMatch(caip10Regex, value) }

// MARK: - Signing context

/// `encodePayload(account, join(roles), signer.scheme, signer.publicKey, subjectKeyB64,
/// scopeOrEmpty, decimal(expiresAtOr0))` (09 § Signing Context).
public func principalPayload(_ r: PrincipalRecord, subjectSigningPublicKey: Data) -> Data {
    ACESigning.encodePayload(r.account, r.roles.joined(separator: ","), r.signer.scheme, r.signer.publicKey,
                             ACEBase64.encode(subjectSigningPublicKey), r.scope ?? "", String(r.expiresAt))
}

/// The 32-byte digest the signer signs (no validation).
public func principalSignData(_ r: PrincipalRecord, subjectSigningPublicKey: Data) throws -> Data {
    try ACESigning.buildSignData(action: "principal", aceId: computeACEId(subjectSigningPublicKey), timestamp: r.issuedAt,
                                 payload: principalPayload(r, subjectSigningPublicKey: subjectSigningPublicKey))
}

// MARK: - Validation

/// 09 § Validation rules 1 (typed form) to 7; returns the scheme and decoded signer key.
private func checkFields(_ r: PrincipalRecord, now: Int) throws -> (SigningScheme, Data) {
    guard isWireInt(r.issuedAt) else { throw principalError("principal.issuedAt must be a wire integer") }  // 1
    guard isWireInt(r.expiresAt) else { throw principalError("principal.expiresAt must be a wire integer") }
    guard isCAIP10(r.account) else { throw principalError("principal.account must be a CAIP-10 account") }  // 2
    guard allowedRoles.contains(r.roles) else {  // 3
        throw principalError(#"principal.roles must be ["controller"], ["delegate"] or ["controller","delegate"]"#)
    }
    guard let scheme = SigningScheme(rawValue: r.signer.scheme) else {  // 4
        throw principalError("principal.signer.scheme is unsupported")
    }
    let signerKey = try decodeB64(r.signer.publicKey, code: .invalidPrincipal, what: "principal.signer.publicKey", maxBytes: 64)
    guard ACESigning.isValidSigningPublicKey(scheme, signerKey) else {
        throw principalError("principal.signer.publicKey is not a valid key for its scheme")
    }
    guard r.issuedAt <= now + ACELimits.timestampWindowSeconds else {  // 5
        throw principalError("principal.issuedAt is in the future")
    }
    guard r.issuedAt < r.expiresAt, r.expiresAt - r.issuedAt <= ACELimits.principalMaxLifetimeSeconds else {  // 6
        throw principalError("principal.expiresAt must be after issuedAt and at most 366 days later")
    }
    if let s = r.scope {  // 7
        let n = s.unicodeScalars.count
        guard n >= 1, n <= 256, !hasControlCharacter(s) else {
            throw principalError("principal.scope must be 1-256 characters without control characters")
        }
    }
    return (scheme, signerKey)
}

/// 09 § Validation, rules 1-10 in order; every failure is `invalid_principal`.
/// `subjectSigningPublicKey` is the key the caller has verified, never anything from the record.
@discardableResult
public func validatePrincipalRecord(_ r: PrincipalRecord, subjectSigningPublicKey: Data, now: Int) throws -> PrincipalRecord {
    try validatePrincipalSignature(r, subjectSigningPublicKey: subjectSigningPublicKey, now: now)  // 1-9
    guard r.expiresAt > now else { throw principalError("principal record has expired") }  // 10
    return r
}

/// 09 § Validation rules 1-9: every rule except expiry (rule 10).
private func validatePrincipalSignature(_ r: PrincipalRecord, subjectSigningPublicKey: Data, now: Int) throws {
    let (scheme, signerKey) = try checkFields(r, now: now)  // 1-7
    let sig = try decodeSignature(r.signature, scheme: scheme, code: .invalidPrincipal)  // 8
    guard ACESigning.verify(signData: try principalSignData(r, subjectSigningPublicKey: subjectSigningPublicKey),
                            signature: sig, scheme: scheme, publicKey: signerKey) else {  // 9
        throw principalError("principal.signature does not verify for this subject")
    }
}

/// R-P40: true when `r` fails `validatePrincipalRecord` at `now` only at the expiry step (rule 10):
/// rules 1-9 pass and `expiresAt <= now`. Any other outcome is false.
func isExpiredOnly(_ r: PrincipalRecord, subjectSigningPublicKey: Data, now: Int) -> Bool {
    guard r.expiresAt <= now else { return false }
    return (try? validatePrincipalSignature(r, subjectSigningPublicKey: subjectSigningPublicKey, now: now)) != nil
}

/// R-P40, fetched records: validate `profile.principal`; one that fails only because it has expired is
/// dropped (nil when nothing else remains). Any other failure throws `invalid_principal`.
func dropExpiredPrincipal(_ profile: AgentProfile?, subjectSigningPublicKey: Data, now: Int) throws -> AgentProfile? {
    guard var p = profile, let pr = p.principal else { return profile }
    if isExpiredOnly(pr, subjectSigningPublicKey: subjectSigningPublicKey, now: now) {
        p.principal = nil
        return p == AgentProfile() ? nil : p
    }
    try validatePrincipalRecord(pr, subjectSigningPublicKey: subjectSigningPublicKey, now: now)
    return p
}

/// Sign a principal record for a subject key. Roles are canonicalized (deduplicated, `controller`
/// first); an unknown role is `invalid_argument`. Rules 1-7 run before the (possibly hardware)
/// signer is asked to sign; the result is validated at `issuedAt` (`invalid_principal`).
public func createPrincipalRecord(
    signer: PrincipalSigner, subjectSigningPublicKey: Data, account: String, roles: [String],
    expiresAt: Int, scope: String? = nil, issuedAt: Int? = nil
) throws -> PrincipalRecord {
    guard roles.allSatisfy(principalRoles.contains) else {
        throw ACEError(.invalidArgument, "roles must contain only 'controller' and 'delegate'")
    }
    let ts = issuedAt ?? systemClock()
    var r = PrincipalRecord(account: account, roles: principalRoles.filter(roles.contains),
                            signer: PrincipalKey(scheme: signer.scheme.rawValue, publicKey: ACEBase64.encode(signer.publicKey)),
                            issuedAt: ts, expiresAt: expiresAt, scope: scope, signature: "")
    _ = try checkFields(r, now: ts)
    let sig = try signer.sign(try principalSignData(r, subjectSigningPublicKey: subjectSigningPublicKey))
    r.signature = encodeSignature(sig, scheme: signer.scheme)
    return try validatePrincipalRecord(r, subjectSigningPublicKey: subjectSigningPublicKey, now: ts)
}

// MARK: - Same-account rules

/// Inbox option: the receiver's own principal `account`, and the keys accepted as authorities of
/// it (09 § Same-Account Rules step 4): `selfSigner` (normally the signer of the receiver's own
/// record; nil = none) and host-supplied `trustedSigners` (for example the account's on-chain
/// keys). With neither, only `eip155` accounts whose address derives from the signer pass.
public struct InboxPrincipal: Sendable, Equatable {
    public let account: String
    public let selfSigner: PrincipalKey?
    public let trustedSigners: Set<PrincipalKey>

    public init(account: String, selfSigner: PrincipalKey? = nil, trustedSigners: Set<PrincipalKey> = []) {
        self.account = account
        self.selfSigner = selfSigner
        self.trustedSigners = trustedSigners
    }

    /// `Inbox.open` check: `account` is CAIP-10 and every signer key is well-formed (a supported
    /// scheme and a valid public key for it, base64); else `invalid_argument`.
    func validate() throws {
        guard isCAIP10(account) else { throw ACEError(.invalidArgument, "principal.account must be a CAIP-10 account") }
        for (k, what) in (selfSigner.map { [($0, "principal.selfSigner")] } ?? []) + trustedSigners.map({ ($0, "principal.trustedSigners[]") }) {
            guard let scheme = SigningScheme(rawValue: k.scheme),
                  let key = try? decodeB64(k.publicKey, code: .invalidArgument, what: what, maxBytes: 64),
                  ACESigning.isValidSigningPublicKey(scheme, key) else {
                throw ACEError(.invalidArgument, "\(what) must be {scheme, publicKey} with a valid key for a supported scheme")
            }
        }
    }
}

/// The receiver's context for 06 step 7 (`parseMessage(principal:)`): its principal `account`,
/// the step-4 authorities (`selfSigner`, `trustedSigners`, see `InboxPrincipal`), the open-request
/// lookup for step 7 (`openRequestTo(conversationId, requestId, now)` → the request's `to`, or nil;
/// the `Inbox` binds it to its store's `requests/` ledger). The sender binding is used as given:
/// refreshing a stale sender is the `Inbox`'s job (R-P20, R-P43).
public struct PrincipalContext: Sendable {
    public let account: String
    public let openRequestTo: (@Sendable (String, String, Int) throws -> String?)?
    public let selfSigner: PrincipalKey?
    public let trustedSigners: Set<PrincipalKey>

    public init(account: String, openRequestTo: (@Sendable (String, String, Int) throws -> String?)? = nil,
                selfSigner: PrincipalKey? = nil, trustedSigners: Set<PrincipalKey> = []) {
        self.account = account
        self.openRequestTo = openRequestTo
        self.selfSigner = selfSigner
        self.trustedSigners = trustedSigners
    }
}

/// 09 step 4 (R-P21): `p.signer` is an authority of `p.account` when it is the receiver's own
/// attesting key, a host-trusted key, or (`eip155`) the secp256k1 key whose address is the
/// account address (case-insensitive). `p` has passed `validatePrincipalRecord`.
func isAccountAuthority(_ p: PrincipalRecord, selfSigner: PrincipalKey?, trustedSigners: Set<PrincipalKey>) -> Bool {
    if p.signer == selfSigner || trustedSigners.contains(p.signer) { return true }
    let parts = p.account.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: false)
    guard parts.count == 3, parts[0] == "eip155", p.signer.scheme == SigningScheme.secp256k1.rawValue else { return false }
    let address = String(parts[2])
    guard regexFullMatch(eip155AddressRegex, address),
          let key = try? decodeB64(p.signer.publicKey, code: .invalidPrincipal, what: "principal.signer.publicKey", maxBytes: 64),
          let derived = try? secp256k1Address(key) else { return false }
    return derived.lowercased() == address.lowercased()
}

/// 09 § Same-Account Rules, steps 1-7 in order (first failure wins). Pure: no side effects beyond
/// `openRequestTo`, so a caller may refresh the sender's peer binding and call it again (R-P20).
/// `body` has already passed `validateBody`. `openRequestTo(conversationId, requestId, now)`
/// returns the ACE ID an open request (sent in that conversation, undecided, unexpired) went to,
/// else nil.
public func checkPrincipalRules(
    type: MessageType, body: [String: JSONValue], conversationId: String, senderPrincipal: PrincipalRecord?,
    senderSigningPublicKey: Data, selfAccount: String?, openRequestTo: ((String, String, Int) throws -> String?)?,
    now: Int, selfSigner: PrincipalKey? = nil, trustedSigners: Set<PrincipalKey> = []
) throws {
    guard type.isPrincipal else { throw ACEError(.invalidArgument, "not a principal message type") }
    guard let selfAccount else { throw ACEError(.wrongPrincipal, "the receiver has no principal") }  // 1
    let p = try checkSenderPrincipal(senderPrincipal, senderSigningPublicKey: senderSigningPublicKey, account: selfAccount,
                                selfSigner: selfSigner, trustedSigners: trustedSigners, now: now)  // 2-5
    if type == .decision {
        guard p.roles.contains("controller") else {  // 6
            throw ACEError(.wrongPrincipal, "only a controller may send a decision")
        }
        var recipient: String?
        if let openRequestTo, let rid = body["requestId"]?.stringValue {
            recipient = try openRequestTo(conversationId, rid, now)
        }
        guard let recipient else {  // 7 (unknown, decided or expired request)
            throw ACEError(.badReference, "decision.requestId names no open request in this conversation")
        }
        guard recipient == computeACEId(senderSigningPublicKey) else {  // 7 (decider, R-P22)
            throw ACEError(.wrongPrincipal, wrongDecider)
        }
    }
}

/// 09 § Same-Account Rules steps 2-5 (present, valid, signed by an authority of the account, same
/// account, no scope); returns the validated record, else throws `wrong_principal`.
private func checkSenderPrincipal(_ senderPrincipal: PrincipalRecord?, senderSigningPublicKey: Data, account: String,
                             selfSigner: PrincipalKey?, trustedSigners: Set<PrincipalKey>, now: Int) throws -> PrincipalRecord {
    guard let senderPrincipal else { throw ACEError(.wrongPrincipal, "the sender has no principal") }  // 2
    let p: PrincipalRecord
    do {  // 3
        p = try validatePrincipalRecord(senderPrincipal, subjectSigningPublicKey: senderSigningPublicKey, now: now)
    } catch let e as ACEError where e.code == .invalidPrincipal {
        throw ACEError(.wrongPrincipal, "the sender's principal is invalid: \(e.message)")
    }
    guard isAccountAuthority(p, selfSigner: selfSigner, trustedSigners: trustedSigners) else {  // 4
        throw ACEError(.wrongPrincipal, "signer is not an authority of the account")
    }
    guard p.account == account else { throw ACEError(.wrongPrincipal, "the sender belongs to another account") }  // 5
    guard p.scope == nil else { throw ACEError(.wrongPrincipal, "unsupported principal scope") }
    return p
}

/// True when the pinned sender principal passes 09 steps 2-5 (present, valid, signed by an
/// authority of the account, same account). False means a peer refresh may help (R-P20).
/// Only a `wrong_principal` failure is false; any other error throws.
func senderPrincipalUsable(_ senderPrincipal: PrincipalRecord?, senderSigningPublicKey: Data,
                           principal: PrincipalContext, now: Int) throws -> Bool {
    do {
        _ = try checkSenderPrincipal(senderPrincipal, senderSigningPublicKey: senderSigningPublicKey, account: principal.account,
                                     selfSigner: principal.selfSigner, trustedSigners: principal.trustedSigners, now: now)
        return true
    } catch let e as ACEError where e.code == .wrongPrincipal { return false }
}

// MARK: - requests/ ledger (09 § Persistence, 06 Appendix A)

/// The accepted decision recorded on a sent request.
public struct RequestDecision: Sendable, Equatable {
    public let messageId: String
    public let outcome: String
    public let timestamp: Int

    public init(messageId: String, outcome: String, timestamp: Int) {
        self.messageId = messageId
        self.outcome = outcome
        self.timestamp = timestamp
    }
}

/// A `requests/` ledger entry: one per sent `request`.
public struct RequestRecord: Sendable, Equatable {
    public let conversationId: String
    public let messageId: String
    /// The ACE ID the request was sent to; only it may decide the request.
    public let to: String
    public let sentAt: Int
    /// Request `timestamp + ttl`; nil when the request had no `ttl` (never expires).
    public let expiresAt: Int?
    public let decision: RequestDecision?
}

/// `requests/<sha256(conversationId ‖ 0x00 ‖ messageId)>.json`.
func requestKey(_ conversationId: String, _ messageId: String) -> String {
    "requests/\(sha256Hex(conversationId, messageId)).json"
}

private func loadRequestObject(_ store: any ACEStore, _ conversationId: String,
                               _ messageId: String) throws -> ([String: JValue], RequestRecord)? {
    let key = requestKey(conversationId, messageId)
    guard let v = try store.readJSON(key) else { return nil }
    guard let o = v.objectValue else { throw storageError(key, "not a JSON object") }
    try checkVersion(o, key)
    func bad() -> ACEError { storageError(key, "invalid request record") }
    guard o["conversationId"]?.stringValue == conversationId, o["messageId"]?.stringValue == messageId,
          let to = o["to"]?.stringValue, isACEId(to), let sentAt = o["sentAt"]?.wireInt else { throw bad() }
    var expiresAt: Int?
    if let e = o["expiresAt"], !e.isNull {
        guard let n = e.wireInt else { throw bad() }
        expiresAt = n
    }
    var decision: RequestDecision?
    if let d = o["decision"], !d.isNull {
        guard let dm = d.objectValue, let mid = dm["messageId"]?.stringValue, isMessageId(mid),
              let outcome = dm["outcome"]?.stringValue, outcome == "approve" || outcome == "deny",
              let ts = dm["timestamp"]?.wireInt else { throw bad() }
        decision = RequestDecision(messageId: mid, outcome: outcome, timestamp: ts)
    }
    return (o, RequestRecord(conversationId: conversationId, messageId: messageId, to: to, sentAt: sentAt,
                             expiresAt: expiresAt, decision: decision))
}

/// The ledger entry of a sent `request`, or nil; a malformed entry is `storage_failed`.
public func loadRequestRecord(_ store: any ACEStore, conversationId: String, messageId: String) throws -> RequestRecord? {
    try loadRequestObject(store, conversationId, messageId)?.1
}

/// The `to` of a sent, undecided, unexpired request (expired when `timestamp + ttl < now`), else
/// nil (09 § Same-Account Rules step 7). Internal (R-P46): the `Inbox` binds it to its store.
func openRequestTo(_ store: any ACEStore, conversationId: String, messageId: String, now: Int) throws -> String? {
    guard let r = try loadRequestRecord(store, conversationId: conversationId, messageId: messageId),
          r.decision == nil else { return nil }
    if let e = r.expiresAt, now > e { return nil }
    return r.to
}

/// Write the ledger entry of a delivered `request` (idempotent: an existing entry is never
/// overwritten). `ttl` is the request body's `ttl`. Caller holds lock `requests`.
func recordRequest(_ store: any ACEStore, message: ACEMessage, sentAt: Int, ttl: Int? = nil) throws {
    guard isConversationId(message.conversationId) else { throw ACEError(.invalidArgument, "invalid conversationId") }
    guard isMessageId(message.messageId) else { throw ACEError(.invalidArgument, "invalid messageId") }
    guard isACEId(message.to) else { throw ACEError(.invalidArgument, "invalid to") }
    guard isWireInt(sentAt) else { throw ACEError(.invalidArgument, "sentAt must be an integer in [0, 2^53-1]") }
    var expiresAt: JValue = .null
    if let ttl {
        guard isWireInt(ttl) else { throw ACEError(.invalidArgument, "ttl must be an integer in [0, 2^53-1]") }
        guard isWireInt(message.timestamp) else {
            throw ACEError(.invalidArgument, "timestamp must be an integer in [0, 2^53-1]")
        }
        expiresAt = num(min(message.timestamp + ttl, maxSafeInteger))
    }
    if try loadRequestObject(store, message.conversationId, message.messageId) != nil { return }
    try store.checkedWrite(requestKey(message.conversationId, message.messageId), JSONWriter.serialize(.object([
        "conversationId": .string(message.conversationId),
        "decision": .null,
        "expiresAt": expiresAt,
        "messageId": .string(message.messageId),
        "sentAt": num(sentAt),
        "to": .string(message.to),
        "version": num(1),
    ])))
}

/// Mark the request of an accepted `decision` decided. Replaying the recorded decision (same
/// `messageId`) and an unknown request are no-ops; a second, different decision is
/// `bad_reference` (R-P25); a decision from anyone but the request's `to` is `wrong_principal`
/// (09 step 7, R-P22). The record is unchanged on failure; unknown members are kept.
/// Caller holds lock `requests`.
func fillDecision(_ store: any ACEStore, _ m: ParsedMessage) throws {
    guard m.type == .decision, let requestId = m.body["requestId"]?.stringValue, !requestId.isEmpty,
          let outcome = m.body["outcome"]?.stringValue, outcome == "approve" || outcome == "deny" else {
        throw ACEError(.invalidArgument, "fillDecision needs a decision with requestId and outcome approve|deny")
    }
    guard let (raw, rec) = try loadRequestObject(store, m.conversationId, requestId) else { return }
    if let d = rec.decision {
        if d.messageId == m.messageId { return }
        throw ACEError(.badReference, "the request already has an accepted decision")
    }
    guard m.from == rec.to else { throw ACEError(.wrongPrincipal, wrongDecider) }
    var out = raw
    out["decision"] = .object([
        "messageId": .string(m.messageId), "outcome": .string(outcome), "timestamp": num(m.timestamp),
    ])
    out["version"] = num(1)
    try store.checkedWrite(requestKey(m.conversationId, requestId), JSONWriter.serialize(.object(out)))
}
