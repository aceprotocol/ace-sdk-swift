//
//  Signing.swift
//  ACE SDK
//
//  Sign data construction + Ed25519/secp256k1 signature verification.
//
//  Unified domain prefix "ace.v1" for all signature contexts.
//  Format: SHA-256("ace.v1" || len(action) || action || len(aceId) || aceId || timestamp[8 BE] || len(payload) || payload)
//

import Foundation
import CryptoKit
import P256K

// MARK: - Domain Prefix

private let domainPrefix = Data("ace.v1".utf8)

// MARK: - secp256k1 order (canonical low-S enforcement)

// N and N/2 as 32-byte big-endian. A signature is canonical (non-malleable) only
// when s ∈ [1, N/2]; accepting high-S lets (r, s) and (r, N - s) both verify.
private let secp256k1OrderBE = Data([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
])
private let secp256k1HalfOrderBE = Data([
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
])

/// Compare two equal-length big-endian byte strings numerically (-1 / 0 / 1).
private func compareBE(_ a: Data, _ b: Data) -> Int {
    let ab = [UInt8](a), bb = [UInt8](b)
    for i in 0..<Swift.min(ab.count, bb.count) where ab[i] != bb[i] {
        return ab[i] < bb[i] ? -1 : 1
    }
    return ab.count == bb.count ? 0 : (ab.count < bb.count ? -1 : 1)
}
private func isZeroBytes(_ d: Data) -> Bool { d.allSatisfy { $0 == 0 } }

// MARK: - Sign Data Builder

public enum ACESigning {

    /// A field that can be included in a signed payload.
    public enum SignField {
        case string(String)
        case data(Data)
    }

    /// Encode multiple fields into a single payload blob.
    /// Each field is length-prefixed: [len(4 BE)] || data
    public static func encodePayload(_ fields: [SignField]) -> Data {
        var buffer = Data()
        for field in fields {
            switch field {
            case .string(let str):
                appendLengthPrefixed(str, to: &buffer)
            case .data(let data):
                appendLengthPrefixedBytes(data, to: &buffer)
            }
        }
        return buffer
    }

    /// Build signData hash per ACE Protocol V1 spec:
    ///
    /// SHA-256(
    ///   "ace.v1" ||
    ///   len(action)[4 BE] || UTF-8(action) ||
    ///   len(aceId)[4 BE] || UTF-8(aceId) ||
    ///   timestamp[8 big-endian] ||
    ///   len(payload)[4 BE] || payload
    /// )
    public static func buildSignData(action: String, aceId: String, timestamp: Int, payload: Data = Data()) -> Data {
        var buffer = Data()
        buffer.append(domainPrefix)
        appendLengthPrefixed(action, to: &buffer)
        appendLengthPrefixed(aceId, to: &buffer)
        appendTimestamp(timestamp, to: &buffer)
        appendLengthPrefixedBytes(payload, to: &buffer)
        return Data(SHA256.hash(data: buffer))
    }

    // MARK: - Signature Verification

    /// Verify a signature against signData.
    /// - For ed25519: direct verification with public key (CryptoKit)
    /// - For secp256k1: recover public key from signature and compare (constant-time)
    public static func verifySignature(
        signData: Data,
        signature: Data,
        scheme: SigningScheme,
        signingPublicKey: Data
    ) -> Bool {
        switch scheme {
        case .ed25519:
            return verifyEd25519(signData: signData, signature: signature, publicKey: signingPublicKey)
        case .secp256k1:
            return verifySecp256k1(signData: signData, signature: signature, expectedPublicKey: signingPublicKey)
        }
    }

    // MARK: - Signature Encoding

    /// Encode a signature to its wire format.
    /// ed25519: Base64(64 bytes)
    /// secp256k1: 0x + hex(r[32] || s[32] || v[1])
    public static func encodeSignature(_ signature: Data, scheme: SigningScheme) -> String {
        switch scheme {
        case .ed25519:
            return ACEBase64.encode(signature)
        case .secp256k1:
            return "0x" + ACEHex.encode(signature)
        }
    }

    /// Decode a signature from its wire format.
    public static func decodeSignature(_ encoded: String, scheme: SigningScheme) throws -> Data {
        switch scheme {
        case .ed25519:
            return try ACEBase64.decode(encoded)
        case .secp256k1:
            return try ACEHex.decode(encoded)
        }
    }

    // MARK: - Private: Ed25519 Verification

    private static func verifyEd25519(signData: Data, signature: Data, publicKey: Data) -> Bool {
        guard signature.count == 64, publicKey.count == 32 else { return false }
        do {
            let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
            return pubKey.isValidSignature(signature, for: signData)
        } catch {
            return false
        }
    }

    // MARK: - Private: secp256k1 Verification (recover-and-compare)

    private static func verifySecp256k1(signData: Data, signature: Data, expectedPublicKey: Data) -> Bool {
        guard signature.count == 65 else { return false }

        let r = signature.prefix(32)
        let s = signature.dropFirst(32).prefix(32)
        let vByte = signature[signature.startIndex + 64]
        // Recovery ID must be 0 or 1 (2/3 are theoretically valid but
        // practically impossible for secp256k1 and not used in ACE)
        guard vByte <= 1 else { return false }
        let v = Int32(vByte)

        // Reject out-of-range and non-canonical (high-S) signatures. ECDSA is
        // malleable: (r, s) and (r, N - s) recover the same key, so accepting
        // high-S lets an observer re-mint a valid signature with different bytes
        // and slip past signature-keyed replay protection. All ACE SDKs sign low-S.
        let rData = Data(r), sData = Data(s)
        guard !isZeroBytes(rData), compareBE(rData, secp256k1OrderBE) < 0 else { return false }
        guard !isZeroBytes(sData), compareBE(sData, secp256k1HalfOrderBE) <= 0 else { return false }

        do {
            // Build recoverable signature: compact(r||s) + recoveryId
            let compactSig = r + s
            let recoverableSig = try P256K.Recovery.ECDSASignature(
                compactRepresentation: [UInt8](compactSig),
                recoveryId: v
            )

            // Recover public key from signature + signData hash
            let digest = HashDigest([UInt8](signData))
            let recoveredPub = try P256K.Recovery.PublicKey(
                digest,
                signature: recoverableSig
            )

            // Compare compressed public keys (constant-time)
            let recoveredCompressed = Data(recoveredPub.dataRepresentation)
            return constantTimeEqual(recoveredCompressed, expectedPublicKey)
        } catch {
            return false
        }
    }

    // MARK: - Private: Encoding Helpers

    /// Encode a string as length-prefixed: [len(4 BE)] || UTF-8(str)
    private static func appendLengthPrefixed(_ field: String, to buffer: inout Data) {
        appendLengthPrefixedBytes(Data(field.utf8), to: &buffer)
    }

    /// Encode binary data as length-prefixed: [len(4 BE)] || data
    private static func appendLengthPrefixedBytes(_ data: Data, to buffer: inout Data) {
        var len = UInt32(data.count).bigEndian
        buffer.append(Data(bytes: &len, count: 4))
        buffer.append(data)
    }

    /// Encode timestamp as 8-byte big-endian uint64.
    /// Precondition: ts must be non-negative (enforced by checkTimestampFreshness).
    private static func appendTimestamp(_ ts: Int, to buffer: inout Data) {
        precondition(ts >= 0, "Timestamp must be non-negative")
        var val = UInt64(ts).bigEndian
        buffer.append(Data(bytes: &val, count: 8))
    }
}
