//
//  Types.swift
//  ACE SDK
//
//  ACE Protocol v1.0 type definitions.
//

import Foundation

// MARK: - Identity Types

public enum SigningScheme: String, Codable, Sendable {
    case ed25519
    case secp256k1
}

public enum IdentityTier: Int, Codable, Sendable {
    case keyOnly = 0
    case chainRegistered = 1
}

public enum HardwareBacking: String, Codable, Sendable {
    case secureEnclave = "secure-enclave"
    case tpm
    case hsm
    case tee
}

// MARK: - ACEIdentity Protocol

/// Interface that all ACE identity implementations must satisfy.
/// Software keys (Tier 0), HSM (Tier 1), and TEE/SE (Tier 2) all conform to this protocol.
public protocol ACEIdentity: Sendable {
    func getEncryptionPublicKey() -> Data
    func getSigningPublicKey() -> Data
    func sign(_ data: Data) throws -> (signature: Data, scheme: SigningScheme)
    func decrypt(ephemeralPubKey: Data, payload: Data, conversationId: String) throws -> Data
    func getAddress() -> String
    func getSigningScheme() -> SigningScheme
    func getTier() -> IdentityTier
    func getACEId() -> String
}

// MARK: - Registration File Types

public struct PricingInfo: Codable, Sendable {
    public let model: String // "per-call" | "per-token" | "per-hour" | "flat"
    public let amount: String
    public let currency: String

    public init(model: String, amount: String, currency: String) {
        self.model = model
        self.amount = amount
        self.currency = currency
    }
}

public struct Capability: Codable, Sendable {
    public let id: String
    public let description: String
    public let input: String?
    public let output: String?
    public let pricing: PricingInfo?

    public init(id: String, description: String, input: String? = nil, output: String? = nil, pricing: PricingInfo? = nil) {
        self.id = id
        self.description = description
        self.input = input
        self.output = output
        self.pricing = pricing
    }
}

public struct ChainInfo: Codable, Sendable {
    public let network: String // CAIP-2 format
    public let address: String

    public init(network: String, address: String) {
        self.network = network
        self.address = address
    }
}

// MARK: - Discovery Profile

public struct ProfilePricing: Codable, Sendable {
    public let currency: String
    public let maxAmount: String?

    public init(currency: String, maxAmount: String? = nil) {
        self.currency = currency
        self.maxAmount = maxAmount
    }
}

public struct AgentProfile: Codable, Sendable {
    public var name: String?
    public var description: String?
    public var image: String?
    public var tags: [String]?
    public var capabilities: [String]?
    public var chains: [String]?
    public var endpoint: String?
    public var pricing: ProfilePricing?

    public init(
        name: String? = nil,
        description: String? = nil,
        image: String? = nil,
        tags: [String]? = nil,
        capabilities: [String]? = nil,
        chains: [String]? = nil,
        endpoint: String? = nil,
        pricing: ProfilePricing? = nil
    ) {
        self.name = name
        self.description = description
        self.image = image
        self.tags = tags
        self.capabilities = capabilities
        self.chains = chains
        self.endpoint = endpoint
        self.pricing = pricing
    }
}

public struct DiscoverQuery: Codable, Sendable {
    public var q: String?
    public var tags: String?
    public var chain: String?
    public var scheme: String?
    public var online: Bool?
    public var limit: Int?
    public var cursor: String?

    public init(
        q: String? = nil, tags: String? = nil, chain: String? = nil,
        scheme: String? = nil, online: Bool? = nil, limit: Int? = nil, cursor: String? = nil
    ) {
        self.q = q
        self.tags = tags
        self.chain = chain
        self.scheme = scheme
        self.online = online
        self.limit = limit
        self.cursor = cursor
    }
}

public struct DiscoverAgent: Codable, Sendable {
    public let aceId: String
    public let encryptionPublicKey: String
    public let signingPublicKey: String
    public let scheme: SigningScheme
    public let profile: AgentProfile
}

public struct DiscoverResult: Codable, Sendable {
    public let agents: [DiscoverAgent]
    public let cursor: String?
}

public struct SigningConfig: Codable, Sendable {
    public let scheme: SigningScheme
    public let address: String
    public var signingPublicKey: String? // Base64, required for secp256k1
    public let encryptionPublicKey: String // Base64, always required

    public init(scheme: SigningScheme, address: String, signingPublicKey: String? = nil, encryptionPublicKey: String) {
        self.scheme = scheme
        self.address = address
        self.signingPublicKey = signingPublicKey
        self.encryptionPublicKey = encryptionPublicKey
    }
}

public struct RegistrationFile: Codable, Sendable {
    public let ace: String // "1.0"
    public let id: String // ace:sha256:<fingerprint>
    public let name: String
    public var description: String?
    public let endpoint: String
    public let tier: IdentityTier
    public var hardwareBacking: HardwareBacking?
    public var signing: SigningConfig
    public var capabilities: [Capability]?
    public var settlement: [String]?
    public var chains: [ChainInfo]?

    public init(
        ace: String = "1.0",
        id: String,
        name: String,
        description: String? = nil,
        endpoint: String,
        tier: IdentityTier,
        hardwareBacking: HardwareBacking? = nil,
        signing: SigningConfig,
        capabilities: [Capability]? = nil,
        settlement: [String]? = nil,
        chains: [ChainInfo]? = nil
    ) {
        self.ace = ace
        self.id = id
        self.name = name
        self.description = description
        self.endpoint = endpoint
        self.tier = tier
        self.hardwareBacking = hardwareBacking
        self.signing = signing
        self.capabilities = capabilities
        self.settlement = settlement
        self.chains = chains
    }
}

// MARK: - Message Types

public enum MessageType: String, Codable, Sendable {
    // Economic
    case rfq, offer, accept, reject
    case invoice, receipt
    case deliver, confirm
    // System
    case info
    // Social
    case text
}

public let economicTypes: Set<MessageType> = [
    .rfq, .offer, .accept, .reject,
    .invoice, .receipt,
    .deliver, .confirm,
]

public let systemTypes: Set<MessageType> = [.info]
public let socialTypes: Set<MessageType> = [.text]

public func isEconomicType(_ type: MessageType) -> Bool { economicTypes.contains(type) }
public func isSystemType(_ type: MessageType) -> Bool { systemTypes.contains(type) }
public func isSocialType(_ type: MessageType) -> Bool { socialTypes.contains(type) }

// MARK: - Message Envelope

public struct EncryptionEnvelope: Codable, Sendable {
    public let ephemeralPubKey: String // Base64
    public let payload: String // Base64(nonce || ciphertext || tag)

    public init(ephemeralPubKey: String, payload: String) {
        self.ephemeralPubKey = ephemeralPubKey
        self.payload = payload
    }
}

public struct SignatureEnvelope: Codable, Sendable {
    public let scheme: SigningScheme
    public let value: String // Base64 (ed25519) or 0x-hex (secp256k1)

    public init(scheme: SigningScheme, value: String) {
        self.scheme = scheme
        self.value = value
    }
}

public struct ACEMessage: Codable, Sendable {
    public let ace: String // "1.0"
    public let messageId: String
    public let from: String // ACE ID
    public let to: String // ACE ID
    public let conversationId: String
    public let type: MessageType
    public var threadId: String?
    public let timestamp: Int
    public let encryption: EncryptionEnvelope
    public let signature: SignatureEnvelope

    public init(
        ace: String = "1.0",
        messageId: String,
        from: String,
        to: String,
        conversationId: String,
        type: MessageType,
        threadId: String? = nil,
        timestamp: Int,
        encryption: EncryptionEnvelope,
        signature: SignatureEnvelope
    ) {
        self.ace = ace
        self.messageId = messageId
        self.from = from
        self.to = to
        self.conversationId = conversationId
        self.type = type
        self.threadId = threadId
        self.timestamp = timestamp
        self.encryption = encryption
        self.signature = signature
    }
}

// MARK: - ACE Errors

public enum ACEError: Error, CustomStringConvertible {
    case invalidKey(String)
    case encryptionFailed(String)
    case decryptionFailed(String)
    case signatureVerificationFailed(String)
    case invalidMessage(String)
    case invalidRegistration(String)
    case timestampNotFresh(Int)
    case replayDetected(String)
    case payloadTooLarge(Int)
    case invalidACEId(String)
    case invalidTransition(String)

    public var description: String {
        switch self {
        case .invalidKey(let msg): return "Invalid key: \(msg)"
        case .encryptionFailed(let msg): return "Encryption failed: \(msg)"
        case .decryptionFailed(let msg): return "Decryption failed: \(msg)"
        case .signatureVerificationFailed(let msg): return "Signature verification failed: \(msg)"
        case .invalidMessage(let msg): return "Invalid message: \(msg)"
        case .invalidRegistration(let msg): return "Invalid registration: \(msg)"
        case .timestampNotFresh(let drift): return "Timestamp not fresh: drift \(drift)s exceeds max 300s"
        case .replayDetected(let id): return "Replay detected: messageId '\(id)' already processed"
        case .payloadTooLarge(let size): return "Payload too large: \(size) bytes exceeds max \(ACEEncryption.maxPayloadSize)"
        case .invalidACEId(let id): return "Invalid ACE ID: '\(id)'"
        case .invalidTransition(let msg): return "Invalid transition: \(msg)"
        }
    }
}
