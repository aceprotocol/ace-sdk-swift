//
//  Discovery.swift
//  ACE SDK
//
//  Registration file validation and well-known URL fetching.
//

import Foundation

// MARK: - ACE ID Validation

private let aceIdPattern = try! NSRegularExpression(
    pattern: "^ace:sha256:[a-f0-9]{64}$"
)

/// Validate ACE ID format: ace:sha256:<64 hex chars>
public func validateACEId(_ id: String) -> Bool {
    aceIdPattern.fullMatch(id)
}

// MARK: - Registration File Validation

/// Decoded public keys of a validated registration file.
public struct RegistrationKeys: Sendable {
    public let signingPublicKey: Data
    public let encryptionPublicKey: Data
}

/// Validate a registration file has all required fields and correct format.
/// Returns the decoded keys so callers need not decode them a second time.
@discardableResult
public func validateRegistrationFile(_ reg: RegistrationFile) throws -> RegistrationKeys {
    guard reg.ace == "1.0" else {
        throw ACEError.invalidRegistration("Invalid ace version: expected '1.0', got '\(reg.ace)'")
    }
    guard validateACEId(reg.id) else {
        throw ACEError.invalidRegistration("Invalid or missing ACE id: '\(reg.id)'")
    }
    guard !reg.name.isEmpty else {
        throw ACEError.invalidRegistration("Missing required field: name")
    }
    guard isHTTPSURL(reg.endpoint) else {
        throw ACEError.invalidRegistration("endpoint must be a valid HTTPS URL")
    }
    // IdentityTier enum enforces valid values (0, 1) at decode time
    guard !reg.signing.address.isEmpty else {
        throw ACEError.invalidRegistration("Missing required field: signing.address")
    }
    guard !reg.signing.encryptionPublicKey.isEmpty else {
        throw ACEError.invalidRegistration("Missing required field: signing.encryptionPublicKey")
    }
    let encryptionPublicKey = try getRegistrationEncryptionPublicKey(reg)
    let signingPublicKey = try getRegistrationSigningPublicKey(reg)
    if reg.signing.scheme == .secp256k1, try reg.signing.address != secp256k1Address(signingPublicKey) {
        throw ACEError.invalidRegistration("signing.address does not match signing.signingPublicKey")
    }
    return RegistrationKeys(signingPublicKey: signingPublicKey, encryptionPublicKey: encryptionPublicKey)
}

/// Verify that a registration file's ACE ID matches its signing key.
public func verifyRegistrationId(_ reg: RegistrationFile) throws -> Bool {
    let signingPubKeyBytes = try getRegistrationSigningPublicKey(reg)
    let expectedId = computeACEId(signingPubKeyBytes)
    guard reg.id == expectedId else { return false }

    if reg.signing.scheme == .secp256k1 {
        let derivedAddress = try secp256k1Address(signingPubKeyBytes)
        return reg.signing.address == derivedAddress
    }
    return true
}

/// Extract the signing public key from a validated registration file.
public func getRegistrationSigningPublicKey(_ reg: RegistrationFile) throws -> Data {
    if reg.signing.scheme == .ed25519 {
        let addressPubKey = try Base58.decode(reg.signing.address)
        guard addressPubKey.count == 32 else {
            throw ACEError.invalidRegistration("ed25519 signing.address must decode to 32 bytes")
        }
        if let sigPubB64 = reg.signing.signingPublicKey, !sigPubB64.isEmpty {
            let signingPubKeyBytes = try ACEBase64.decode(sigPubB64)
            guard constantTimeEqual(addressPubKey, signingPubKeyBytes) else {
                throw ACEError.invalidRegistration("ed25519 signing.signingPublicKey does not match signing.address")
            }
        }
        return addressPubKey
    }
    if let sigPubB64 = reg.signing.signingPublicKey, !sigPubB64.isEmpty {
        return try ACEBase64.decode(sigPubB64)
    }
    throw ACEError.invalidRegistration("\(reg.signing.scheme.rawValue) scheme requires signing.signingPublicKey")
}

/// Extract the X-Wing encryption public key (1216 bytes) from a validated registration file.
public func getRegistrationEncryptionPublicKey(_ reg: RegistrationFile) throws -> Data {
    // `ACEEncryption` owns the length rule; re-label its error for this field.
    do {
        return try ACEEncryption.decodePublicKey(base64: reg.signing.encryptionPublicKey)
    } catch ACEError.invalidKey(let reason) {
        throw ACEError.invalidRegistration("signing.encryptionPublicKey: \(reason)")
    }
}

// MARK: - Encryption-Key Binding (relay-sourced peer keys)
//
// `aceId` self-certifies only the SIGNING key (aceId == sha256(signingKey)). The
// X-Wing ENCRYPTION key is separate — on its own an unauthenticated claim. A relay
// routes ciphertext and is untrusted by design, so it could hand a client its own
// X-Wing key and read messages the client believes are end-to-end encrypted. The
// binding below is the proof that closes that gap: the exact signature the relay
// already requires at registration, verifiable with the identity's signing key alone.

/// A `GET /v1/peer` response or a `/v1/discover` agent entry.
public struct RelayPeerResponse: Codable, Sendable {
    public let aceId: String
    public let scheme: SigningScheme
    public let encryptionPublicKey: String
    public let signingPublicKey: String
    public let registrationSignature: String?
    public let registeredAt: Int?

    public init(
        aceId: String, scheme: SigningScheme,
        encryptionPublicKey: String, signingPublicKey: String,
        registrationSignature: String?, registeredAt: Int?
    ) {
        self.aceId = aceId
        self.scheme = scheme
        self.encryptionPublicKey = encryptionPublicKey
        self.signingPublicKey = signingPublicKey
        self.registrationSignature = registrationSignature
        self.registeredAt = registeredAt
    }
}

/// A peer's public keys AFTER the identity + encryption-key binding are verified.
/// Obtain ONLY via `verifyPeerResponse`; the memberwise initializer bypasses checks.
public struct VerifiedPeer: Sendable {
    public let aceId: String
    public let scheme: SigningScheme
    public let signingPublicKey: Data
    public let encryptionPublicKey: Data
}

/// Verify that `encryptionPublicKey` was authorized by `aceId`.
///
/// The binding is identical to what `POST /v1/register` signs:
///   buildSignData("register", aceId, timestamp,
///                 encodePayload(encryptionPublicKey, signingPublicKey))
/// signed by the identity's signing key. This also re-checks
/// `aceId == sha256(signingPublicKey)`, so `true` means this exact X-Wing key was
/// signed by the key that defines this identity. Inputs MUST be the Base64 wire
/// strings (the signature commits to those strings). Returns `false` on bad input.
public func verifyEncryptionKeyBinding(
    aceId: String,
    scheme: SigningScheme,
    encryptionPublicKey: String,
    signingPublicKey: String,
    timestamp: Int,
    signature: String
) -> Bool {
    verifyBinding(
        aceId: aceId, scheme: scheme,
        encryptionPublicKey: encryptionPublicKey, signingPublicKey: signingPublicKey,
        timestamp: timestamp, signature: signature
    ) != nil
}

/// `verifyEncryptionKeyBinding`, returning the decoded keys on success.
private func verifyBinding(
    aceId: String,
    scheme: SigningScheme,
    encryptionPublicKey: String,
    signingPublicKey: String,
    timestamp: Int,
    signature: String
) -> RegistrationKeys? {
    guard timestamp >= 0 else { return nil }
    // The bound key must be a well-formed X-Wing public key.
    guard let encryptionPubBytes = try? ACEEncryption.decodePublicKey(base64: encryptionPublicKey) else { return nil }
    guard let signingPubBytes = try? ACEBase64.decode(signingPublicKey) else { return nil }
    // The signing key must be the one that defines this identity.
    guard computeACEId(signingPubBytes) == aceId else { return nil }
    let payload = ACESigning.encodePayload([.string(encryptionPublicKey), .string(signingPublicKey)])
    let signData = ACESigning.buildSignData(action: "register", aceId: aceId, timestamp: timestamp, payload: payload)
    guard let sigBytes = try? ACESigning.decodeSignature(signature, scheme: scheme),
          ACESigning.verifySignature(signData: signData, signature: sigBytes, scheme: scheme, signingPublicKey: signingPubBytes)
    else { return nil }
    return RegistrationKeys(signingPublicKey: signingPubBytes, encryptionPublicKey: encryptionPubBytes)
}

/// Build a ``VerifiedPeer`` from a relay `GET /v1/peer` or `/v1/discover` entry.
///
/// Throws if the binding signature is absent or fails — a relay that substitutes an
/// X-Wing key cannot produce a passing binding, and neither can a key that is not a
/// well-formed 1216-byte X-Wing public key. Use the keys with `parseMessageFromPeer`.
public func verifyPeerResponse(_ data: RelayPeerResponse) throws -> VerifiedPeer {
    guard validateACEId(data.aceId) else {
        throw ACEError.invalidRegistration("Invalid peer aceId: '\(String(data.aceId.prefix(80)))'")
    }
    guard let signature = data.registrationSignature, let registeredAt = data.registeredAt else {
        throw ACEError.invalidRegistration(
            "Peer response is missing the encryption-key binding (registrationSignature/registeredAt); " +
            "its encryptionPublicKey cannot be trusted. Without the binding a relay could substitute " +
            "its own X-Wing key and read messages meant to be end-to-end encrypted."
        )
    }
    guard let keys = verifyBinding(
        aceId: data.aceId, scheme: data.scheme,
        encryptionPublicKey: data.encryptionPublicKey, signingPublicKey: data.signingPublicKey,
        timestamp: registeredAt, signature: signature
    ) else {
        throw ACEError.signatureVerificationFailed(
            "Peer encryption-key binding failed verification: the encryptionPublicKey is not a well-formed " +
            "X-Wing key signed by this identity's signing key (possible key substitution / relay MITM)."
        )
    }
    return VerifiedPeer(
        aceId: data.aceId,
        scheme: data.scheme,
        signingPublicKey: keys.signingPublicKey,
        encryptionPublicKey: keys.encryptionPublicKey
    )
}

// MARK: - URL Validation

/// Absolute URL with scheme `https` (case-insensitive) and a non-empty host.
/// SSRF host checks belong to the fetcher (`fetchRegistrationFile`), not here.
private func isHTTPSURL(_ string: String) -> Bool {
    guard let url = URL(string: string), url.scheme?.lowercased() == "https",
          let host = url.host, !host.isEmpty else { return false }
    return true
}

// MARK: - URL Host Validation

/// Reject URL hosts that resolve to private/reserved addresses.
/// Prevents SSRF via literal IPs (127.0.0.1, ::1, 169.254.x.x, 10.x.x.x, etc).
private let ipv4Pattern = try! NSRegularExpression(pattern: #"^\d{1,3}(\.\d{1,3}){3}$"#)
private let blockedDomainSuffixes = [".local", ".localhost", ".internal", ".intranet", ".lan", ".home.arpa"]
private let blockedDomainExact = ["localhost"]

func validateURLHost(_ host: String) throws {
    let lower = host.lowercased()

    // Block IPv6 literals (bracketed or bare)
    if lower.contains(":") || lower.hasPrefix("[") {
        throw ACEError.invalidRegistration("URL host must not be an IPv6 literal: '\(String(host.prefix(100)))'")
    }

    // Block IPv4 literals (any dotted decimal)
    if ipv4Pattern.fullMatch(host) {
        throw ACEError.invalidRegistration("URL host must not be an IP address: '\(String(host.prefix(100)))'")
    }

    // Block numeric-only hosts (hex/decimal IP forms like 0x7f000001, 2130706433)
    if lower.allSatisfy({ $0.isHexDigit || $0 == "x" }) && !lower.isEmpty {
        throw ACEError.invalidRegistration("URL host must not be a numeric address: '\(String(host.prefix(100)))'")
    }

    // Block reserved domain suffixes
    if blockedDomainExact.contains(lower) || blockedDomainSuffixes.contains(where: { lower.hasSuffix($0) }) {
        throw ACEError.invalidRegistration("URL host is a reserved/private domain: '\(String(host.prefix(100)))'")
    }
}

// MARK: - Domain Validation

private let validDomainPattern = try! NSRegularExpression(
    pattern: #"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"#
)

public let defaultRegistrationFetchTimeout: TimeInterval = 10.0
public let defaultMaxRegistrationBytes = 1_048_576

/// Fetch and validate a registration file from a well-known URL.
public func fetchRegistrationFile(
    _ domain: String,
    timeout: TimeInterval = defaultRegistrationFetchTimeout,
    maxBytes: Int = defaultMaxRegistrationBytes
) async throws -> RegistrationFile {
    guard validDomainPattern.fullMatch(domain) else {
        throw ACEError.invalidRegistration("Invalid domain: '\(String(domain.prefix(100)))'")
    }
    // Block reserved/private domains to prevent SSRF via DNS rebinding
    try validateURLHost(domain)
    guard timeout > 0 else {
        throw ACEError.invalidRegistration("Invalid timeout: expected positive seconds, got \(timeout)")
    }
    guard maxBytes > 0 else {
        throw ACEError.invalidRegistration("Invalid maxBytes: expected positive integer, got \(maxBytes)")
    }

    guard let url = URL(string: "https://\(domain)/.well-known/ace.json") else {
        throw ACEError.invalidRegistration("Failed to construct URL for domain: '\(String(domain.prefix(100)))'")
    }
    var request = URLRequest(url: url)
    request.timeoutInterval = timeout
    request.setValue("application/json", forHTTPHeaderField: "Accept")

    // Use a custom URLSession that rejects redirects to prevent SSRF via
    // server-controlled redirects to private IPs (DNS rebinding mitigation).
    let sessionDelegate = SSRFSafeDelegate()
    let session = URLSession(configuration: .default, delegate: sessionDelegate, delegateQueue: nil)
    defer { session.finishTasksAndInvalidate() }

    let (data, response): (Data, URLResponse)
    do {
        (data, response) = try await session.data(for: request)
    } catch let error as URLError where error.code == .timedOut {
        throw ACEError.invalidRegistration("Timed out fetching registration file from https://\(domain)/.well-known/ace.json after \(timeout)s")
    }

    guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        throw ACEError.invalidRegistration("Failed to fetch registration file: HTTP \(status)")
    }

    guard let contentType = httpResponse.value(forHTTPHeaderField: "Content-Type"),
          contentType.contains("application/json") else {
        let ct = httpResponse.value(forHTTPHeaderField: "Content-Type") ?? "missing"
        throw ACEError.invalidRegistration("Invalid content-type: expected application/json, got '\(ct)'")
    }

    let declaredLength = httpResponse.expectedContentLength
    if declaredLength > Int64(maxBytes) {
        throw ACEError.invalidRegistration("Registration file too large: \(declaredLength) bytes exceeds max \(maxBytes)")
    }
    guard data.count <= maxBytes else {
        throw ACEError.invalidRegistration("Registration file too large: \(data.count) bytes exceeds max \(maxBytes)")
    }

    let reg: RegistrationFile
    do {
        reg = try JSONDecoder().decode(RegistrationFile.self, from: data)
    } catch {
        throw ACEError.invalidRegistration("Failed to parse registration JSON: \(error)")
    }

    let keys = try validateRegistrationFile(reg)
    guard computeACEId(keys.signingPublicKey) == reg.id else {
        throw ACEError.invalidRegistration("Registration ACE ID does not match signing key")
    }

    return reg
}

// MARK: - Profile Validation

private let tagPattern = try! NSRegularExpression(pattern: "^[a-z0-9][a-z0-9-]*$")
private let caip2Pattern = try! NSRegularExpression(pattern: "^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")
private let controlCharPattern = try! NSRegularExpression(pattern: "[\\x00-\\x1f\\x7f]")

private func validateTagLikeArray(_ items: [String], fieldName: String, maxCount: Int) throws {
    guard items.count <= maxCount else {
        throw ACEError.invalidRegistration("Invalid profile: \(fieldName) must have at most \(maxCount) items")
    }
    for item in items {
        guard item.unicodeScalars.count <= 32, tagPattern.fullMatch(item) else {
            throw ACEError.invalidRegistration("Invalid profile: each \(fieldName.dropLast(1)) must be 1-32 lowercase alphanumeric chars or hyphens (\(fieldName))")
        }
    }
}

public func validateProfile(_ profile: AgentProfile) throws {
    if let name = profile.name {
        guard !name.isEmpty, name.unicodeScalars.count <= 64 else {
            throw ACEError.invalidRegistration("Invalid profile: name must be 1-64 characters")
        }
        let nameRange = NSRange(name.startIndex..., in: name)
        if controlCharPattern.firstMatch(in: name, range: nameRange) != nil {
            throw ACEError.invalidRegistration("Invalid profile: name must not contain control characters")
        }
    }

    if let description = profile.description {
        guard description.unicodeScalars.count <= 256 else {
            throw ACEError.invalidRegistration("Invalid profile: description must be at most 256 characters")
        }
        let range = NSRange(description.startIndex..., in: description)
        if controlCharPattern.firstMatch(in: description, range: range) != nil {
            throw ACEError.invalidRegistration("Invalid profile: description must not contain control characters")
        }
    }

    if let image = profile.image {
        guard image.unicodeScalars.count <= 512 else {
            throw ACEError.invalidRegistration("Invalid profile: image must be at most 512 characters")
        }
        guard isHTTPSURL(image) else {
            throw ACEError.invalidRegistration("Invalid profile: image must be a valid HTTPS URL (image)")
        }
    }

    if let tags = profile.tags {
        try validateTagLikeArray(tags, fieldName: "tags", maxCount: 10)
    }

    if let capabilities = profile.capabilities {
        try validateTagLikeArray(capabilities, fieldName: "capabilities", maxCount: 20)
    }

    if let chains = profile.chains {
        guard chains.count <= 10 else {
            throw ACEError.invalidRegistration("Invalid profile: chains must have at most 10 items")
        }
        for chain in chains {
            guard caip2Pattern.fullMatch(chain) else {
                throw ACEError.invalidRegistration("Invalid profile: each chain must be a CAIP-2 identifier (chains)")
            }
        }
    }

    if let endpoint = profile.endpoint {
        guard isHTTPSURL(endpoint) else {
            throw ACEError.invalidRegistration("Invalid profile: endpoint must be a valid HTTPS URL (endpoint)")
        }
    }

    if let pricing = profile.pricing {
        guard !pricing.currency.isEmpty else {
            throw ACEError.invalidRegistration("Invalid profile: pricing.currency is required (pricing)")
        }
    }
}

// MARK: - SSRF-Safe URL Session Delegate

/// Rejects HTTP redirects to prevent SSRF via server-controlled redirects
/// to private/reserved IP addresses. Used by `fetchRegistrationFile`.
private final class SSRFSafeDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // Reject all redirects — the well-known URL should respond directly.
        // This prevents DNS rebinding and open-redirect SSRF attacks.
        completionHandler(nil)
    }
}
