import Foundation

/// Locally trusted, current resource policy. Never construct it from a requesting agent's claims.
public struct ResourcePolicy: Sendable {
    public let resource: String
    public let authority: VerifiedPeer
    public let epoch: Int
    public let revoked: [String]
    public init(resource: String, authority: VerifiedPeer, epoch: Int, revoked: [String] = []) {
        self.resource = resource; self.authority = authority; self.epoch = epoch; self.revoked = revoked
    }
}

/// Exact-intent capabilities; message labels and account roles confer no execution rights.
public enum ACEGrants {
    static func bad() -> ACEError { ACEError(.invalidAuthorization, "invalid execution intent or resource grant") }
    static func keys(_ o: [String: JSONValue], _ names: String) -> Bool { Set(o.keys) == Set(names.split(separator: ",").map(String.init)) }
    static func name(_ v: JSONValue?) -> Bool { v?.stringValue.map(isNamespacedIdentifier) == true }
    public static func isExecutionUnits(_ s: String) -> Bool {
        let b = Array(s.utf8)
        return s == "0" || !b.isEmpty && b.count <= 78 && b[0] >= 49 && b[0] <= 57 && b.dropFirst().allSatisfy { $0 >= 48 && $0 <= 57 }
    }
    public static func executionIntentDigest(_ intent: [String: JSONValue]) throws -> String {
        guard keys(intent, "operationId,audience,resource,action,schemaDigest,details,expiresAt"),
              let operation = intent["operationId"]?.stringValue, isMessageId(operation),
              let audience = intent["audience"]?.stringValue, isACEId(audience), name(intent["resource"]), name(intent["action"]),
              let schema = intent["schemaDigest"]?.stringValue, isSha256Hex(schema), intent["details"]?.objectValue != nil,
              intent["expiresAt"]?.wireInt != nil else { throw bad() }
        func depth(_ v: JSONValue, _ n: Int) throws {
            guard n <= ACELimits.maxJSONDepth else { throw bad() }
            switch v {
            case .array(let a): for child in a { try depth(child, n + 1) }
            case .object(let o):
                for (key, child) in o {
                    guard key.utf8.elementsEqual(key.precomposedStringWithCanonicalMapping.utf8) else { throw bad() }
                    try depth(child, n + 1)
                }
            default: break
            }
        }
        try depth(.object(intent), 0)
        guard try JSONValue.object(intent).jsonData().count <= ACELimits.maxExecutionJSONBytes else { throw bad() }
        return try intentDigest(.object(intent))
    }
    /// Validated grant claims and their digest.
    struct Claims {
        let grantId: String, issuer: String, subject: String, audience: String, resource: String, intentDigest: String
        let issuedAt: Int, expiresAt: Int, epoch: Int, parent: String?, delegationDepth: Int
        let digest: String
        init(_ c: [String: JSONValue]) throws {
            guard keys(c, "grantId,issuer,subject,audience,resource,intentDigest,issuedAt,expiresAt,epoch,parent,delegationDepth"),
                  let grantId = c["grantId"]?.stringValue, isMessageId(grantId),
                  let issuer = c["issuer"]?.stringValue, isACEId(issuer), let subject = c["subject"]?.stringValue, isACEId(subject),
                  let audience = c["audience"]?.stringValue, isACEId(audience), name(c["resource"]), let resource = c["resource"]?.stringValue,
                  let intentDigest = c["intentDigest"]?.stringValue, isSha256Hex(intentDigest),
                  let issuedAt = c["issuedAt"]?.wireInt, let expiresAt = c["expiresAt"]?.wireInt, issuedAt < expiresAt,
                  let epoch = c["epoch"]?.wireInt, let delegationDepth = c["delegationDepth"]?.wireInt, delegationDepth <= 7,
                  c["parent"] == .null || c["parent"]?.stringValue.map(isSha256Hex) == true else { throw bad() }
            self.grantId = grantId; self.issuer = issuer; self.subject = subject; self.audience = audience; self.resource = resource
            self.intentDigest = intentDigest; self.issuedAt = issuedAt; self.expiresAt = expiresAt; self.epoch = epoch
            self.parent = c["parent"]?.stringValue; self.delegationDepth = delegationDepth
            digest = try ACE.intentDigest(.object(c))
        }
        var signData: Data {
            get throws {
                try ACESigning.buildSignData(action: "grant", aceId: issuer, timestamp: issuedAt, payload: ACESigning.encodePayload([.string(digest)]))
            }
        }
    }
    /// Parent references bind claims independently of randomized signature bytes.
    public static func executionGrantDigest(_ grant: [String: JSONValue]) throws -> String {
        guard let c = grant["claims"]?.objectValue else { throw bad() }
        return try Claims(c).digest
    }
    public static func createExecutionGrant(signer: any ACEIdentity, claims: [String: JSONValue]) throws -> [String: JSONValue] {
        guard claims["issuer"]?.stringValue == signer.getACEId() else { throw bad() }
        let scheme = signer.getSigningScheme(), value = try encodeSignature(signer.sign(Claims(claims).signData), scheme: scheme)
        return ["claims": .object(claims), "signingPublicKey": .string(signer.getSigningPublicKey().base64EncodedString()),
                "signature": SignatureEnvelope(scheme: scheme, value: value).jsonValue]
    }
    /// Pure proof verification. Invoke inside the authoritative reservation transaction with current policy.
    public static func verifyExecutionGrantChain(_ chain: [[String: JSONValue]], intent: [String: JSONValue], sender: String,
                                                 executor: String, policy: ResourcePolicy, now: Int) throws -> String {
        do {
            let digest = try executionIntentDigest(intent)
            guard (1...8).contains(chain.count), isACEId(sender), isACEId(executor), isWireInt(now), isWireInt(policy.epoch),
                  policy.revoked.allSatisfy(isMessageId), intent["audience"]?.stringValue == executor,
                  intent["resource"]?.stringValue == policy.resource,
                  let intentExpires = intent["expiresAt"]?.wireInt, now < intentExpires else { throw bad() }
            var previous: Claims?, ids = Set<String>()
            for g in chain {
                guard keys(g, "claims,signingPublicKey,signature"), let raw = g["claims"]?.objectValue,
                      let sig = g["signature"]?.objectValue.flatMap(SignatureEnvelope.init(exactly:)),
                      let pk = g["signingPublicKey"]?.stringValue else { throw bad() }
                let scheme = sig.scheme, value = sig.value
                let c = try Claims(raw)
                let key = try decodeB64(pk, code: .invalidAuthorization, what: "signingPublicKey", maxBytes: 64)
                guard ACESigning.isValidSigningPublicKey(scheme, key), computeACEId(key) == c.issuer,
                      try ACESigning.verify(signData: c.signData, signature: decodeSignature(value, scheme: scheme, code: .invalidAuthorization), scheme: scheme, publicKey: key),
                      c.audience == executor, c.resource == policy.resource, c.intentDigest == digest,
                      c.epoch == policy.epoch, now >= c.issuedAt, now < c.expiresAt,
                      intentExpires <= c.expiresAt, !policy.revoked.contains(c.grantId), !ids.contains(c.grantId) else { throw bad() }
                if let p = previous {
                    guard c.parent == p.digest, c.issuer == p.subject, c.delegationDepth < p.delegationDepth,
                          c.issuedAt >= p.issuedAt, c.expiresAt <= p.expiresAt else { throw bad() }
                } else {
                    guard c.parent == nil, c.issuer == policy.authority.aceId,
                          scheme == policy.authority.scheme, key == policy.authority.signingPublicKey else { throw bad() }
                }
                ids.insert(c.grantId); previous = c
            }
            guard previous?.subject == sender else { throw bad() }
            return digest
        } catch { throw bad() }
    }
}
