//
//  ProfileTests.swift
//  ACE SDK
//
//  Tests for AgentProfile validation.
//

import Testing
import Foundation
@testable import ACE

@Suite("Profile Validation")
struct ProfileValidationTests {

    @Test("accepts valid full profile")
    func validFullProfile() throws {
        let profile = AgentProfile(
            name: "TestBot",
            description: "A test bot",
            image: "https://example.com/avatar.png",
            tags: ["test", "bot"],
            capabilities: ["translation"],
            chains: ["eip155:8453"],
            endpoint: "https://example.com/ace",
            pricing: ProfilePricing(currency: "USD", maxAmount: "1.00")
        )
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    @Test("accepts valid empty profile")
    func validEmptyProfile() throws {
        let profile = AgentProfile()
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    // MARK: - Name Validation

    @Test("rejects empty name")
    func emptyName() {
        let profile = AgentProfile(name: "")
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("rejects name longer than 64 characters")
    func nameTooLong() {
        let profile = AgentProfile(name: String(repeating: "a", count: 65))
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("accepts name at exactly 64 characters")
    func nameAtLimit() throws {
        let profile = AgentProfile(name: String(repeating: "a", count: 64))
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    // MARK: - Description Validation

    @Test("rejects description longer than 256 characters")
    func descriptionTooLong() {
        let profile = AgentProfile(description: String(repeating: "a", count: 257))
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("accepts description at exactly 256 characters")
    func descriptionAtLimit() throws {
        let profile = AgentProfile(description: String(repeating: "a", count: 256))
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    @Test("rejects description with control characters")
    func descriptionWithControlChars() {
        let profile = AgentProfile(description: "hello\u{0000}world")
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("rejects description with newline control character")
    func descriptionWithNewline() {
        let profile = AgentProfile(description: "hello\nworld")
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    // MARK: - Image Validation

    @Test("accepts valid HTTPS image URL")
    func validImageUrl() throws {
        let profile = AgentProfile(image: "https://example.com/avatar.png")
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    @Test("accepts image URL at exactly 512 characters")
    func imageAtLimit() throws {
        let profile = AgentProfile(image: "https://example.com/" + String(repeating: "a", count: 491))
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    @Test("rejects image URL longer than 512 characters")
    func imageTooLong() {
        let profile = AgentProfile(image: "https://example.com/" + String(repeating: "a", count: 493))
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("rejects non-HTTPS image URL")
    func imageHttpRejected() {
        let profile = AgentProfile(image: "http://example.com/avatar.png")
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("rejects image URL without scheme")
    func imageNoScheme() {
        let profile = AgentProfile(image: "example.com/avatar.png")
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    // MARK: - Tags Validation

    @Test("rejects more than 10 tags")
    func tooManyTags() {
        let tags = (0..<11).map { "tag\($0)" }
        let profile = AgentProfile(tags: tags)
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("accepts exactly 10 tags")
    func tagsAtLimit() throws {
        let tags = (0..<10).map { "tag\($0)" }
        let profile = AgentProfile(tags: tags)
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    @Test("rejects tag longer than 32 characters")
    func tagTooLong() {
        let profile = AgentProfile(tags: [String(repeating: "a", count: 33)])
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("rejects tag with uppercase letters")
    func tagUppercase() {
        let profile = AgentProfile(tags: ["InvalidTag"])
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("rejects tag with spaces")
    func tagWithSpaces() {
        let profile = AgentProfile(tags: ["not valid"])
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("accepts valid hyphenated tag")
    func tagWithHyphens() throws {
        let profile = AgentProfile(tags: ["my-cool-tag"])
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    // MARK: - Capabilities Validation

    @Test("rejects more than 20 capabilities")
    func tooManyCapabilities() {
        let caps = (0..<21).map { "cap\($0)" }
        let profile = AgentProfile(capabilities: caps)
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("accepts exactly 20 capabilities")
    func capabilitiesAtLimit() throws {
        let caps = (0..<20).map { "cap\($0)" }
        let profile = AgentProfile(capabilities: caps)
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    @Test("rejects capability with invalid format")
    func capabilityInvalidFormat() {
        let profile = AgentProfile(capabilities: ["INVALID"])
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    // MARK: - Chains Validation

    @Test("rejects more than 10 chains")
    func tooManyChains() {
        let chains = (0..<11).map { "eip155:\($0)" }
        let profile = AgentProfile(chains: chains)
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("rejects chain without CAIP-2 colon separator")
    func chainMissingColon() {
        let profile = AgentProfile(chains: ["eip155"])
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("accepts valid CAIP-2 chain")
    func validChain() throws {
        let profile = AgentProfile(chains: ["eip155:1", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"])
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    // MARK: - Endpoint Validation

    @Test("rejects non-HTTPS endpoint")
    func httpEndpoint() {
        let profile = AgentProfile(endpoint: "http://example.com")
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("rejects invalid URL endpoint")
    func invalidEndpoint() {
        let profile = AgentProfile(endpoint: "not a url")
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("rejects HTTPS endpoint without host")
    func httpsEndpointWithoutHost() {
        let profile = AgentProfile(endpoint: "https:///nohost")
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("rejects empty HTTPS host")
    func emptyHttpsHost() {
        let profile = AgentProfile(endpoint: "https://")
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("accepts valid HTTPS endpoint")
    func validEndpoint() throws {
        let profile = AgentProfile(endpoint: "https://example.com/ace")
        #expect(throws: Never.self) { try validateProfile(profile) }
    }

    // MARK: - Pricing Validation

    @Test("rejects pricing with empty currency")
    func pricingEmptyCurrency() {
        let profile = AgentProfile(pricing: ProfilePricing(currency: ""))
        #expect(throws: ACEError.self) { try validateProfile(profile) }
    }

    @Test("accepts pricing with valid currency")
    func pricingValidCurrency() throws {
        let profile = AgentProfile(pricing: ProfilePricing(currency: "USD", maxAmount: "10.00"))
        #expect(throws: Never.self) { try validateProfile(profile) }
    }
}
