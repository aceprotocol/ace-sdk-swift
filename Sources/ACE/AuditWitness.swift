import Foundation

public struct AuditWitnessReceipt: Codable, Sendable, Equatable {
    public let logId: String
    public let `operator`: String
    public let checkpointDigest: String
    public let timestamp: Int
    public let witness: String
    public let signature: SignatureEnvelope

    public init(logId: String, operator: String, checkpointDigest: String, timestamp: Int, witness: String, signature: SignatureEnvelope) {
        self.logId = logId; self.operator = `operator`; self.checkpointDigest = checkpointDigest
        self.timestamp = timestamp; self.witness = witness; self.signature = signature
    }
    public init(json: Data) throws {
        guard let o = try JSONValue(json: json).objectValue,
              Set(o.keys) == ["logId", "operator", "checkpointDigest", "timestamp", "witness", "signature"],
              let logId = o["logId"]?.stringValue, let op = o["operator"]?.stringValue,
              let digest = o["checkpointDigest"]?.stringValue, let timestamp = o["timestamp"]?.wireInt,
              let witness = o["witness"]?.stringValue, let s = o["signature"]?.objectValue,
              let signature = SignatureEnvelope(exactly: s) else { throw ACEAudit.bad() }
        self.init(logId: logId, operator: op, checkpointDigest: digest, timestamp: timestamp, witness: witness, signature: signature)
        _ = try ACEAudit.witnessData(self)
    }
    public init(from decoder: any Decoder) throws { self = try AuditWitnessReceipt(json: JSONValue(from: decoder).jsonData()) }
}

public struct AuditWitnessPolicy: Sendable {
    public let witnesses: [VerifiedPeer]
    public let threshold: Int
    public let maxFaulty: Int
    public let maxAgeSeconds: Int
    public let maxFutureSkewSeconds: Int
    public init(witnesses: [VerifiedPeer], threshold: Int, maxFaulty: Int, maxAgeSeconds: Int, maxFutureSkewSeconds: Int) {
        self.witnesses = witnesses; self.threshold = threshold; self.maxFaulty = maxFaulty
        self.maxAgeSeconds = maxAgeSeconds; self.maxFutureSkewSeconds = maxFutureSkewSeconds
    }
}

extension ACEAudit {
    /// Stable digest of checkpoint claims, independent of signature randomness/encoding.
    public static func checkpointDigest(_ c: AuditCheckpoint) throws -> String {
        hexEncode(try checkpointData(c))
    }
    static func witnessData(_ r: AuditWitnessReceipt) throws -> Data {
        guard isMessageId(r.logId), isACEId(r.operator), isACEId(r.witness), r.operator != r.witness,
              isSha256Hex(r.checkpointDigest), isWireInt(r.timestamp) else { throw bad() }
        return try ACESigning.buildSignData(action: "audit-witness", aceId: r.witness, timestamp: r.timestamp,
            payload: ACESigning.encodePayload([.string(r.logId), .string(r.operator), .data(bytes(r.checkpointDigest))]))
    }
    /// A witness service MUST persist its accepted checkpoint before releasing this signature.
    public static func createWitnessReceipt(_ c: AuditCheckpoint, operator: VerifiedPeer, witness: any ACEIdentity, timestamp: Int) throws -> AuditWitnessReceipt {
        try verifyCheckpoint(c, operator: `operator`)
        guard isWireInt(timestamp), timestamp >= c.timestamp else { throw bad() }
        let r = AuditWitnessReceipt(logId: c.logId, operator: c.signer, checkpointDigest: try checkpointDigest(c), timestamp: timestamp,
            witness: witness.getACEId(), signature: .init(scheme: witness.getSigningScheme(), value: ""))
        let value = try encodeSignature(witness.sign(witnessData(r)), scheme: witness.getSigningScheme())
        return AuditWitnessReceipt(logId: r.logId, operator: r.operator, checkpointDigest: r.checkpointDigest, timestamp: r.timestamp,
            witness: r.witness, signature: .init(scheme: witness.getSigningScheme(), value: value))
    }
    public static func verifyWitnessReceipt(_ r: AuditWitnessReceipt, checkpoint c: AuditCheckpoint, operator: VerifiedPeer, witness: VerifiedPeer) throws {
        do {
            try verifyCheckpoint(c, operator: `operator`)
            try verifyReceipt(r, verified: c, digest: checkpointDigest(c), witness: witness)
        } catch { throw ACEError(.invalidSignature, "invalid audit witness receipt") }
    }
    /// The receipt checks for an already verified checkpoint `c` whose digest is `digest`.
    private static func verifyReceipt(_ r: AuditWitnessReceipt, verified c: AuditCheckpoint, digest: String, witness: VerifiedPeer) throws {
        guard r.logId == c.logId, r.operator == c.signer, r.checkpointDigest == digest, r.timestamp >= c.timestamp,
              r.witness == witness.aceId, r.signature.scheme == witness.scheme,
              try ACESigning.verify(signData: witnessData(r), signature: decodeSignature(r.signature.value, scheme: witness.scheme, code: .invalidSignature),
                  scheme: witness.scheme, publicKey: witness.signingPublicKey) else { throw bad() }
    }
    /// Quorums must intersect in an honest witness: 2*threshold > N+maxFaulty. Time is local policy.
    public static func verifyWitnessQuorum(_ c: AuditCheckpoint, receipts: [AuditWitnessReceipt], operator: VerifiedPeer, policy p: AuditWitnessPolicy, now: Int) throws {
        do {
            try verifyCheckpoint(c, operator: `operator`)
            let n = p.witnesses.count, q = p.threshold, f = p.maxFaulty
            guard (1...32).contains(n), Set(p.witnesses.map(\.aceId)).count == n, !p.witnesses.contains(where: { $0.aceId == `operator`.aceId }),
                  isWireInt(q), isWireInt(f), q <= n - f, 2*q > n + f,
                  isWireInt(p.maxAgeSeconds), isWireInt(p.maxFutureSkewSeconds), isWireInt(now), receipts.count <= n,
                  c.timestamp - now <= p.maxFutureSkewSeconds, now - c.timestamp <= p.maxAgeSeconds else { throw bad() }
            let digest = try checkpointDigest(c)
            var seen = Set<String>()
            for r in receipts {
                guard let w = p.witnesses.first(where: { $0.aceId == r.witness }), !seen.contains(r.witness),
                      isWireInt(r.timestamp), r.timestamp - now <= p.maxFutureSkewSeconds, now - r.timestamp <= p.maxAgeSeconds else { throw bad() }
                try verifyReceipt(r, verified: c, digest: digest, witness: w)
                seen.insert(r.witness)
            }
            guard seen.count >= q else { throw bad() }
        } catch { throw ACEError(.invalidSignature, "audit witness quorum or freshness policy not satisfied") }
    }
}
