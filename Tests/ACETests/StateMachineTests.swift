//
//  StateMachineTests.swift
//  ACE SDK
//
//  Tests for the thread state machine (V1 simplified).
//

import Testing
import Foundation
@testable import ACE

private func uuid() -> String {
    UUID().uuidString.lowercased()
}

private let now = Int(Date().timeIntervalSince1970)
private let CONV_A = String(repeating: "a", count: 64)
private let CONV_B = String(repeating: "b", count: 64)

@Suite("ThreadStateMachine")
struct StateMachineTests {

    // ============================================================
    // Standard Flow
    // ============================================================

    @Suite("standard flow")
    struct StandardFlow {
        @Test("completes full rfq -> offer -> accept -> invoice -> receipt -> deliver -> confirm")
        func fullFlow() throws {
            let sm = ThreadStateMachine()

            #expect(try sm.transition(conversationId: CONV_A, threadId: "deal-001", messageType: .rfq, messageId: uuid(), timestamp: now) == .rfq)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "deal-001", messageType: .offer, messageId: uuid(), timestamp: now) == .offered)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "deal-001", messageType: .accept, messageId: uuid(), timestamp: now) == .accepted)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "deal-001", messageType: .invoice, messageId: uuid(), timestamp: now) == .invoiced)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "deal-001", messageType: .receipt, messageId: uuid(), timestamp: now) == .paid)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "deal-001", messageType: .deliver, messageId: uuid(), timestamp: now) == .delivered)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "deal-001", messageType: .confirm, messageId: uuid(), timestamp: now) == .confirmed)
        }
    }

    // ============================================================
    // Valid Variations
    // ============================================================

    @Suite("valid variations")
    struct ValidVariations {
        @Test("counter-offer: multiple offers before accept")
        func counterOffer() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now) == .offered)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now) == .offered)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now) == .accepted)
        }

        @Test("reject after offer")
        func rejectAfterOffer() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .reject, messageId: uuid(), timestamp: now) == .rejected)
            #expect(sm.isTerminal(conversationId: CONV_A, threadId: "t"))
        }

        @Test("deliver-first (trust-based, skip invoice/receipt)")
        func deliverFirst() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .deliver, messageId: uuid(), timestamp: now) == .delivered)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .confirm, messageId: uuid(), timestamp: now) == .confirmed)
        }

        @Test("pre-paid: receipt directly after accept (no invoice)")
        func prePaid() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .receipt, messageId: uuid(), timestamp: now) == .paid)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .deliver, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .confirm, messageId: uuid(), timestamp: now)
        }
    }

    // ============================================================
    // Real-World Commerce Scenarios
    // ============================================================

    @Suite("real-world scenarios")
    struct RealWorldScenarios {
        @Test("SCENARIO: pre-paid API service")
        func prePaidAPI() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .receipt, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .deliver, messageId: uuid(), timestamp: now)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .confirm, messageId: uuid(), timestamp: now) == .confirmed)
        }

        @Test("SCENARIO: free service (no payment involved)")
        func freeService() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .deliver, messageId: uuid(), timestamp: now)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .confirm, messageId: uuid(), timestamp: now) == .confirmed)
        }

        @Test("SCENARIO: counter-offer negotiation before deal")
        func counterOfferNegotiation() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now) // $100
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now) // $80 counter
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now) // $90 counter
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now) // deal at $90
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .invoice, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .receipt, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .deliver, messageId: uuid(), timestamp: now)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .confirm, messageId: uuid(), timestamp: now) == .confirmed)
        }
    }

    // ============================================================
    // Invalid Transitions
    // ============================================================

    @Suite("invalid transitions")
    struct InvalidTransitions {
        @Test("rejects offer before rfq")
        func offerBeforeRfq() {
            let sm = ThreadStateMachine()
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects accept before offer")
        func acceptBeforeOffer() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects reject before offer")
        func rejectBeforeOffer() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .reject, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects invoice before accept")
        func invoiceBeforeAccept() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .invoice, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects deliver before accept")
        func deliverBeforeAccept() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .deliver, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects confirm before deliver")
        func confirmBeforeDeliver() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .confirm, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects rfq after rfq (no double-rfq)")
        func doubleRfq() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects accept after accept")
        func doubleAccept() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects receipt before invoice or accept")
        func receiptBeforeInvoice() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .receipt, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects going backwards: offer after accept")
        func offerAfterAccept() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects going backwards: rfq after offer")
        func rfqAfterOffer() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects re-negotiation after accept")
        func reNegotiationAfterAccept() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)

            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            }
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            }
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            }
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .reject, messageId: uuid(), timestamp: now)
            }
        }
    }

    // ============================================================
    // Terminal State Enforcement
    // ============================================================

    @Suite("terminal state enforcement")
    struct TerminalStateEnforcement {
        @Test("rejected is terminal - all economic messages blocked")
        func rejectedIsTerminal() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .reject, messageId: uuid(), timestamp: now)

            let economicTypes: [MessageType] = [.rfq, .offer, .accept, .reject, .invoice, .receipt, .deliver, .confirm]
            for type in economicTypes {
                #expect(throws: InvalidTransitionError.self) {
                    try sm.transition(conversationId: CONV_A, threadId: "t", messageType: type, messageId: uuid(), timestamp: now)
                }
            }
        }

        @Test("confirmed IS terminal - no outgoing economic transitions")
        func confirmedIsTerminal() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .deliver, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .confirm, messageId: uuid(), timestamp: now)

            #expect(sm.isTerminal(conversationId: CONV_A, threadId: "t"))
            #expect(!sm.canTransition(conversationId: CONV_A, threadId: "t", messageType: .invoice))
            #expect(!sm.canTransition(conversationId: CONV_A, threadId: "t", messageType: .deliver))

            let economicTypes: [MessageType] = [.rfq, .offer, .accept, .reject, .invoice, .receipt, .deliver, .confirm]
            for type in economicTypes {
                #expect(throws: InvalidTransitionError.self) {
                    try sm.transition(conversationId: CONV_A, threadId: "t", messageType: type, messageId: uuid(), timestamp: now)
                }
            }
        }

        @Test("allows text/info after rejected")
        func textInfoAfterRejected() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .reject, messageId: uuid(), timestamp: now)

            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .text, messageId: uuid(), timestamp: now) == .rejected)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .info, messageId: uuid(), timestamp: now) == .rejected)
        }

        @Test("allows text/info after confirmed")
        func textInfoAfterConfirmed() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .accept, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .deliver, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .confirm, messageId: uuid(), timestamp: now)

            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .text, messageId: uuid(), timestamp: now) == .confirmed)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .info, messageId: uuid(), timestamp: now) == .confirmed)
        }
    }

    // ============================================================
    // Non-Economic Messages
    // ============================================================

    @Suite("non-economic messages")
    struct NonEconomicMessages {
        @Test("text messages always allowed, never change state")
        func textAlwaysAllowed() throws {
            let sm = ThreadStateMachine()

            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .text, messageId: uuid(), timestamp: now) == .idle)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .text, messageId: uuid(), timestamp: now) == .rfq)
            #expect(sm.getState(conversationId: CONV_A, threadId: "t") == .rfq)
        }

        @Test("info messages always allowed, never change state")
        func infoAlwaysAllowed() throws {
            let sm = ThreadStateMachine()

            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            #expect(try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .info, messageId: uuid(), timestamp: now) == .offered)
        }

        @Test("text/info do not require valid threadId")
        func textNoThreadIdRequired() throws {
            let sm = ThreadStateMachine()
            #expect(try sm.transition(conversationId: CONV_A, threadId: "", messageType: .text, messageId: uuid(), timestamp: now) == .idle)
        }
    }

    // ============================================================
    // Conversation Isolation
    // ============================================================

    @Suite("conversation isolation")
    struct ConversationIsolation {
        @Test("same threadId in different conversations are independent")
        func sameThreadDifferentConv() throws {
            let sm = ThreadStateMachine()
            let threadId = "deal-001"

            try sm.transition(conversationId: CONV_A, threadId: threadId, messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: threadId, messageType: .offer, messageId: uuid(), timestamp: now)

            #expect(sm.getState(conversationId: CONV_B, threadId: threadId) == .idle)
            try sm.transition(conversationId: CONV_B, threadId: threadId, messageType: .rfq, messageId: uuid(), timestamp: now)

            #expect(sm.getState(conversationId: CONV_A, threadId: threadId) == .offered)
            #expect(sm.getState(conversationId: CONV_B, threadId: threadId) == .rfq)
        }

        @Test("different threadIds in same conversation are independent")
        func differentThreadsSameConv() throws {
            let sm = ThreadStateMachine()

            try sm.transition(conversationId: CONV_A, threadId: "deal-a", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "deal-a", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "deal-b", messageType: .rfq, messageId: uuid(), timestamp: now)

            #expect(sm.getState(conversationId: CONV_A, threadId: "deal-a") == .offered)
            #expect(sm.getState(conversationId: CONV_A, threadId: "deal-b") == .rfq)
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "deal-b", messageType: .accept, messageId: uuid(), timestamp: now)
            }
        }
    }

    // ============================================================
    // ThreadId Validation
    // ============================================================

    @Suite("threadId validation")
    struct ThreadIdValidation {
        @Test("rejects empty threadId for economic messages")
        func emptyThreadId() {
            let sm = ThreadStateMachine()
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "", messageType: .rfq, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects threadId exceeding max length")
        func tooLongThreadId() {
            let sm = ThreadStateMachine()
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: String(repeating: "x", count: 257), messageType: .rfq, messageId: uuid(), timestamp: now)
            }
        }

        @Test("rejects threadId with control characters")
        func controlCharsInThreadId() {
            let sm = ThreadStateMachine()
            #expect(throws: InvalidTransitionError.self) {
                try sm.transition(conversationId: CONV_A, threadId: "thread\u{0000}id", messageType: .rfq, messageId: uuid(), timestamp: now)
            }
        }

        @Test("accepts threadId at max length")
        func threadIdAtMaxLength() throws {
            let sm = ThreadStateMachine()
            let longId = String(repeating: "x", count: 256)
            #expect(try sm.transition(conversationId: CONV_A, threadId: longId, messageType: .rfq, messageId: uuid(), timestamp: now) == .rfq)
        }
    }

    // ============================================================
    // canTransition
    // ============================================================

    @Suite("canTransition")
    struct CanTransition {
        @Test("reports valid transitions correctly")
        func validTransitions() {
            let sm = ThreadStateMachine()
            #expect(sm.canTransition(conversationId: CONV_A, threadId: "t", messageType: .rfq))
            #expect(!sm.canTransition(conversationId: CONV_A, threadId: "t", messageType: .offer))
        }

        @Test("text/info always return true")
        func textInfoAlwaysTrue() {
            let sm = ThreadStateMachine()
            #expect(sm.canTransition(conversationId: CONV_A, threadId: "t", messageType: .text))
            #expect(sm.canTransition(conversationId: CONV_A, threadId: "t", messageType: .info))
        }
    }

    // ============================================================
    // Snapshot / Export / Import
    // ============================================================

    @Suite("snapshot and export")
    struct SnapshotAndExport {
        @Test("getSnapshot returns correct state and history")
        func snapshot() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: "mid-1", timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: "mid-2", timestamp: now + 1)

            let snap = sm.getSnapshot(conversationId: CONV_A, threadId: "t")
            #expect(snap.state == .offered)
            #expect(snap.history.count == 2)
            #expect(snap.history[0].type == "rfq")
            #expect(snap.history[1].type == "offer")
        }

        @Test("export and fromExport roundtrip")
        func exportImport() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t1", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t1", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t2", messageType: .rfq, messageId: uuid(), timestamp: now)

            let exported = sm.export()
            let restored = try ThreadStateMachine.fromExport(exported)

            #expect(restored.getState(conversationId: CONV_A, threadId: "t1") == .offered)
            #expect(restored.getState(conversationId: CONV_A, threadId: "t2") == .rfq)
        }

        @Test("remove clears thread state")
        func remove() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            #expect(sm.getState(conversationId: CONV_A, threadId: "t") == .rfq)
            #expect(sm.remove(conversationId: CONV_A, threadId: "t"))
            #expect(sm.getState(conversationId: CONV_A, threadId: "t") == .idle)
        }

        @Test("allowedTypes returns correct types for state")
        func allowedTypes() throws {
            let sm = ThreadStateMachine()
            let idleAllowed = sm.allowedTypes(conversationId: CONV_A, threadId: "t")
            #expect(idleAllowed.contains(.rfq))
            #expect(!idleAllowed.contains(.offer))

            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            let rfqAllowed = sm.allowedTypes(conversationId: CONV_A, threadId: "t")
            #expect(rfqAllowed.contains(.offer))
            #expect(!rfqAllowed.contains(.rfq))
        }

        @Test("terminal state returns empty allowedTypes")
        func terminalAllowedTypes() throws {
            let sm = ThreadStateMachine()
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .rfq, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .offer, messageId: uuid(), timestamp: now)
            try sm.transition(conversationId: CONV_A, threadId: "t", messageType: .reject, messageId: uuid(), timestamp: now)

            let allowed = sm.allowedTypes(conversationId: CONV_A, threadId: "t")
            #expect(allowed.isEmpty)
        }
    }

    // ============================================================
    // Composite Key Safety
    // ============================================================

    @Suite("composite key safety")
    struct CompositeKeySafety {
        @Test("length-prefixed key prevents ambiguity")
        func keyAmbiguity() throws {
            let sm = ThreadStateMachine()

            try sm.transition(conversationId: "ab", threadId: "cd", messageType: .rfq, messageId: uuid(), timestamp: now)

            #expect(sm.getState(conversationId: "ab", threadId: "cd") == .rfq)
            #expect(sm.getState(conversationId: "a", threadId: "bcd") == .idle)
            #expect(sm.getState(conversationId: "abc", threadId: "d") == .idle)
        }
    }
}
