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
    let range = NSRange(id.startIndex..., in: id)
    return aceIdPattern.firstMatch(in: id, range: range) != nil
}

// MARK: - Registration File Validation

/// Validate a registration file has all required fields and correct format.
public func validateRegistrationFile(_ reg: RegistrationFile) throws {
    guard reg.ace == "1.0" else {
        throw ACEError.invalidRegistration("Invalid ace version: expected '1.0', got '\(reg.ace)'")
    }
    guard validateACEId(reg.id) else {
        throw ACEError.invalidRegistration("Invalid or missing ACE id: '\(reg.id)'")
    }
    guard !reg.name.isEmpty else {
        throw ACEError.invalidRegistration("Missing required field: name")
    }
    guard let endpointURL = URL(string: reg.endpoint),
          endpointURL.scheme == "https",
          let host = endpointURL.host,
          !host.isEmpty else {
        throw ACEError.invalidRegistration("endpoint must be a valid HTTPS URL")
    }
    try validateURLHost(host)
    // IdentityTier enum enforces valid values (0, 1) at decode time
    guard !reg.signing.address.isEmpty else {
        throw ACEError.invalidRegistration("Missing required field: signing.address")
    }
    guard !reg.signing.encryptionPublicKey.isEmpty else {
        throw ACEError.invalidRegistration("Missing required field: signing.encryptionPublicKey")
    }

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
    } else if reg.signing.scheme == .secp256k1 {
        // secp256k1 requires signingPublicKey (address is a hash, can't recover pubkey from it)
        guard let sigPubB64 = reg.signing.signingPublicKey, !sigPubB64.isEmpty else {
            throw ACEError.invalidRegistration("secp256k1 scheme requires signing.signingPublicKey")
        }
        // Verify address matches signingPublicKey
        let signingPubKeyBytes = try ACEBase64.decode(sigPubB64)
        let derivedAddress = try secp256k1Address(signingPubKeyBytes)
        guard reg.signing.address == derivedAddress else {
            throw ACEError.invalidRegistration("signing.address does not match signing.signingPublicKey")
        }
    }
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
    throw ACEError.invalidRegistration("Cannot derive signing public key from registration file")
}

/// Extract the X25519 encryption public key from a validated registration file.
public func getRegistrationEncryptionPublicKey(_ reg: RegistrationFile) throws -> Data {
    return try ACEBase64.decode(reg.signing.encryptionPublicKey)
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
    let range = NSRange(host.startIndex..., in: host)
    if ipv4Pattern.firstMatch(in: host, range: range) != nil {
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
    let range = NSRange(domain.startIndex..., in: domain)
    guard validDomainPattern.firstMatch(in: domain, range: range) != nil else {
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

    try validateRegistrationFile(reg)
    guard try verifyRegistrationId(reg) else {
        throw ACEError.invalidRegistration("Registration ACE ID does not match signing key")
    }

    return reg
}

// MARK: - Profile Validation

private let tagPattern = try! NSRegularExpression(pattern: "^[a-z0-9][a-z0-9-]*$")
private let controlCharPattern = try! NSRegularExpression(pattern: "[\\x00-\\x1f\\x7f]")

private func validateTagLikeArray(_ items: [String], fieldName: String, maxCount: Int) throws {
    guard items.count <= maxCount else {
        throw ACEError.invalidRegistration("Invalid profile: \(fieldName) must have at most \(maxCount) items")
    }
    for item in items {
        let range = NSRange(item.startIndex..., in: item)
        guard item.count <= 32, tagPattern.firstMatch(in: item, range: range) != nil else {
            throw ACEError.invalidRegistration("Invalid profile: each \(fieldName.dropLast(1)) must be 1-32 lowercase alphanumeric chars or hyphens (\(fieldName))")
        }
    }
}

public func validateProfile(_ profile: AgentProfile) throws {
    if let name = profile.name {
        guard !name.isEmpty, name.count <= 64 else {
            throw ACEError.invalidRegistration("Invalid profile: name must be 1-64 characters")
        }
        let nameRange = NSRange(name.startIndex..., in: name)
        if controlCharPattern.firstMatch(in: name, range: nameRange) != nil {
            throw ACEError.invalidRegistration("Invalid profile: name must not contain control characters")
        }
    }

    if let description = profile.description {
        guard description.count <= 256 else {
            throw ACEError.invalidRegistration("Invalid profile: description must be at most 256 characters")
        }
        let range = NSRange(description.startIndex..., in: description)
        if controlCharPattern.firstMatch(in: description, range: range) != nil {
            throw ACEError.invalidRegistration("Invalid profile: description must not contain control characters")
        }
    }

    if let image = profile.image {
        guard image.count <= 512 else {
            throw ACEError.invalidRegistration("Invalid profile: image must be at most 512 characters")
        }
        guard
            let url = URL(string: image),
            url.scheme == "https",
            let host = url.host,
            !host.isEmpty
        else {
            throw ACEError.invalidRegistration("Invalid profile: image must be a valid HTTPS URL (image)")
        }
        try validateURLHost(host)
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
            guard chain.contains(":") else {
                throw ACEError.invalidRegistration("Invalid profile: each chain must be a CAIP-2 identifier (chains)")
            }
            let parts = chain.split(separator: ":", maxSplits: 1)
            guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else {
                throw ACEError.invalidRegistration("Invalid profile: each chain must have non-empty namespace and reference (chains)")
            }
        }
    }

    if let endpoint = profile.endpoint {
        guard
            let url = URL(string: endpoint),
            url.scheme == "https",
            let host = url.host,
            !host.isEmpty
        else {
            throw ACEError.invalidRegistration("Invalid profile: endpoint must be a valid HTTPS URL (endpoint)")
        }
        try validateURLHost(host)
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
