//
//  Signing.swift
//  ACE SDK
//
//  The signed message and ML-DSA-65 verification (02 § Signatures):
//
//    M   = encodePayload("ace.v1", aceId, decimal(timestamp), seqOrEmpty, payload)
//    sig = ML-DSA.Sign(sk, M, ctx = UTF-8(action))
//
//  `seqOrEmpty` is "" for a KEL event signature and decimal(seq) of the signing delegation for every other signature.
//

import CryptoKit
import Foundation

/// One field of `encodePayload`.
public enum PayloadField: Sendable {
    case string(String)
    case data(Data)
}

public enum ACESigning {
    public static let seedSize = 32
    public static let publicKeySize = 1952
    public static let signatureSize = 3309

    /// `len(4 BE) || bytes` per field; strings are UTF-8.
    public static func encodePayload(_ fields: [PayloadField]) -> Data {
        var out = Data()
        for f in fields {
            let d: Data
            switch f {
            case .string(let s): d = Data(s.utf8)
            case .data(let raw): d = raw
            }
            var len = UInt32(d.count).bigEndian
            withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
            out.append(d)
        }
        return out
    }

    public static func encodePayload(_ strings: String...) -> Data { encodePayload(strings.map { .string($0) }) }

    /// `M = encodePayload("ace.v1", aceId, decimal(timestamp), seqOrEmpty, payload)`; `seq` nil for a KEL event signature.
    /// `invalid_argument` for a timestamp or `seq` outside [0, 2^53-1].
    public static func message(aceId: String, timestamp: Int, seq: Int?, payload: Data) throws -> Data {
        guard isWireInt(timestamp), seq.map(isWireInt) ?? true else {
            throw ACEError(.invalidArgument, "timestamp and seq must be integers in [0, 2^53-1]")
        }
        return encodePayload([.string("ace.v1"), .string(aceId), .string(decimal(timestamp)), .string(seq.map(decimal) ?? ""), .data(payload)])
    }

    /// True when `key` is an `ml-dsa-65` public key.
    public static func isValidSigningPublicKey(_ scheme: String, _ key: Data) -> Bool {
        scheme == SigningScheme.mlDsa65.rawValue && key.count == publicKeySize
    }

    /// ML-DSA-65 verify of `message`, ctx = UTF-8(action). Malformed input is `false`, never a throw.
    public static func verifySignature(message: Data, action: String, signature: Data, publicKey: Data) -> Bool {
        guard publicKey.count == publicKeySize, signature.count == signatureSize,
              let pk = try? MLDSA65.PublicKey(rawRepresentation: publicKey) else { return false }
        return pk.isValidSignature(signature, for: message, context: Data(action.utf8))
    }
}

// MARK: - Operational signatures (01 § Operational signatures)

/// `checkUsable(identity, now)`, then the `seq` of the signing delegation the verified log names.
package func usableSigningSeq(_ identity: any ACEIdentity, now: Int) throws -> Int {
    guard let seq = try checkUsable(identity, now: now).signing?.seq else {
        throw ACEError(.identityUnavailable, "identity has no signing delegation")
    }
    return seq
}

/// ML-DSA-65 over `M(identity, timestamp, seq, payload)` with ctx = `action`, under the identity's current signing
/// delegation (`identity_unavailable` when it cannot sign at `timestamp`, or when the delegation changed between the
/// check and the signature).
package func operationalSign(_ identity: any ACEIdentity, action: String, timestamp: Int, payload: Data) throws -> SignatureEnvelope {
    let checked = try usableSigningSeq(identity, now: timestamp), aceId = identity.getACEId()
    let (seq, sig) = try identity.sign({ try ACESigning.message(aceId: aceId, timestamp: timestamp, seq: $0, payload: payload) }, action: action)
    guard seq == checked else { throw ACEError(.identityUnavailable, "the signing delegation changed while signing") }
    return SignatureEnvelope(value: ACEBase64.encode(sig), seq: seq)
}

/// 01 § Operational signatures, in order: (1) the scheme is `ml-dsa-65` (`SignatureEnvelope` only holds that one);
/// (2) `signature.seq` names the current signing delegation and (3) the signed `timestamp` is at or after the `ts` of its
/// `dlg` and before its `notAfter` (`stale_peer_binding`); (4) the signature verifies (`invalid_signature`); (5) the
/// signer is usable at `now` (`stale_peer_binding`).
package func verifyOperational(_ sig: SignatureEnvelope, state: KelState, action: String, timestamp: Int, payload: Data, now: Int) throws {
    guard let key = state.signing, sig.seq == key.seq else {
        throw ACEError(.stalePeerBinding, "signature.seq is not the current signing delegation")
    }
    if state.events.indices.contains(key.seq), let dlgTs = wireInt(state.events[key.seq]["ts"]), timestamp < dlgTs {
        throw ACEError(.stalePeerBinding, "signed before the delegating dlg's ts")
    }
    if let notAfter = key.notAfter, timestamp >= notAfter {
        throw ACEError(.stalePeerBinding, "signed at or after the signing delegation's notAfter")
    }
    let raw = try decodeSignature(sig.value, code: .invalidSignature)
    let m = try ACESigning.message(aceId: state.aceId, timestamp: timestamp, seq: sig.seq, payload: payload)
    guard ACESigning.verifySignature(message: m, action: action, signature: raw, publicKey: key.publicKey) else {
        throw ACEError(.invalidSignature, "\(action) signature does not verify")
    }
    guard ACEKel.isUsable(state, now: now) else { throw ACEError(.stalePeerBinding, "the signer is not usable now") }
}
