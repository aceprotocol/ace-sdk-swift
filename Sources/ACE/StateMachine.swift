//
//  StateMachine.swift
//  ACE SDK
//
//  Thread state machine tracking economic message flow per (conversationId, threadId) pair.
//  Logic mirrors the TypeScript implementation exactly.
//

import Foundation

// MARK: - Thread States

public enum ThreadState: String, Codable, Sendable {
    case idle
    case rfq
    case offered
    case accepted
    case rejected
    case invoiced
    case paid
    case delivered
    case confirmed
}

// MARK: - Transition Table

private let TRANSITIONS: [String: ThreadState] = [
    // Phase 1: Negotiation
    "idle:rfq": .rfq,
    "rfq:offer": .offered,
    "offered:accept": .accepted,
    "offered:reject": .rejected,
    "offered:offer": .offered,       // Counter-offer

    // Phase 2: Execution
    "accepted:invoice": .invoiced,
    "accepted:receipt": .paid,       // Pre-paid (no invoice needed)
    "invoiced:receipt": .paid,

    "accepted:deliver": .delivered,  // Deliver-first (trust-based)
    "paid:deliver": .delivered,      // Standard: deliver after payment
    "delivered:confirm": .confirmed,
]

// Rejected and confirmed are terminal — no outgoing economic transitions.
private let TERMINAL_STATES: Set<ThreadState> = [.rejected, .confirmed]

// MARK: - Validation

private let MAX_THREAD_ID_LENGTH = 256

/// Validate that a threadId is non-empty, not too long, and contains no control characters.
public func validateThreadId(_ threadId: String) throws {
    if threadId.isEmpty {
        throw InvalidTransitionError.validationError("threadId must not be empty")
    }
    if threadId.count > MAX_THREAD_ID_LENGTH {
        throw InvalidTransitionError.validationError("threadId exceeds max length of \(MAX_THREAD_ID_LENGTH) characters")
    }
    for scalar in threadId.unicodeScalars {
        let v = scalar.value
        if (v >= 0x00 && v <= 0x1f) || v == 0x7f {
            throw InvalidTransitionError.validationError("threadId must not contain control characters")
        }
    }
}

// MARK: - Error

public enum InvalidTransitionError: Error, Sendable, CustomStringConvertible {
    case invalidTransition(threadId: String, currentState: ThreadState, messageType: String)
    case validationError(String)

    public var description: String {
        switch self {
        case .invalidTransition(let tid, let state, let type):
            return "Invalid transition: cannot process '\(type)' in state '\(state.rawValue)' (thread: \(tid))"
        case .validationError(let msg):
            return msg
        }
    }
}

// MARK: - Thread Entry & Snapshot

public struct ThreadHistoryEntry: Codable, Sendable {
    public let type: String  // MessageType raw value
    public let messageId: String
    public let timestamp: Int

    public init(type: String, messageId: String, timestamp: Int) {
        self.type = type
        self.messageId = messageId
        self.timestamp = timestamp
    }
}

public struct ThreadSnapshot: Codable, Sendable {
    public let conversationId: String
    public let threadId: String
    public let state: ThreadState
    public let history: [ThreadHistoryEntry]

    public init(conversationId: String, threadId: String, state: ThreadState, history: [ThreadHistoryEntry]) {
        self.conversationId = conversationId
        self.threadId = threadId
        self.state = state
        self.history = history
    }
}

private struct ThreadEntry {
    var conversationId: String
    var threadId: String
    var state: ThreadState
    var history: [ThreadHistoryEntry]
}

// MARK: - Thread State Machine

public final class ThreadStateMachine: @unchecked Sendable {
    private var threads: [String: ThreadEntry] = [:]
    private let lock = NSLock()
    private let maxThreads: Int
    private let maxHistoryPerThread: Int

    public init(maxThreads: Int = 100_000, maxHistoryPerThread: Int = 1_000) {
        self.maxThreads = maxThreads
        self.maxHistoryPerThread = maxHistoryPerThread
    }

    /// Length-prefixed composite key prevents collision between
    /// conversationId="a:b" threadId="c" vs conversationId="a" threadId="b:c"
    private func compositeKey(_ conversationId: String, _ threadId: String) -> String {
        return "\(conversationId.count):\(conversationId):\(threadId)"
    }

    /// Validate and apply a state transition for a thread.
    /// Non-economic messages (text, info) are always allowed and do not change state.
    /// Returns the new state after transition.
    @discardableResult
    public func transition(
        conversationId: String,
        threadId: String,
        messageType: MessageType,
        messageId: String,
        timestamp: Int
    ) throws -> ThreadState {
        if !isEconomicType(messageType) {
            return getState(conversationId: conversationId, threadId: threadId)
        }

        try validateThreadId(threadId)

        lock.lock()
        defer { lock.unlock() }

        let key = compositeKey(conversationId, threadId)
        let currentState: ThreadState = threads[key]?.state ?? .idle

        if TERMINAL_STATES.contains(currentState) {
            throw InvalidTransitionError.invalidTransition(
                threadId: threadId, currentState: currentState, messageType: messageType.rawValue
            )
        }

        let transitionKey = "\(currentState.rawValue):\(messageType.rawValue)"
        guard let nextState = TRANSITIONS[transitionKey] else {
            throw InvalidTransitionError.invalidTransition(
                threadId: threadId, currentState: currentState, messageType: messageType.rawValue
            )
        }

        let entry = ThreadHistoryEntry(type: messageType.rawValue, messageId: messageId, timestamp: timestamp)

        if threads[key] != nil {
            guard threads[key]!.history.count < maxHistoryPerThread else {
                throw InvalidTransitionError.validationError("Thread history exceeds maximum of \(maxHistoryPerThread) entries")
            }
            threads[key]!.state = nextState
            threads[key]!.history.append(entry)
        } else {
            guard threads.count < maxThreads else {
                throw InvalidTransitionError.validationError("Thread limit reached (\(maxThreads))")
            }
            threads[key] = ThreadEntry(
                conversationId: conversationId,
                threadId: threadId,
                state: nextState,
                history: [entry]
            )
        }

        return nextState
    }

    /// Check if a transition would be valid without applying it.
    public func canTransition(conversationId: String, threadId: String, messageType: MessageType) -> Bool {
        if !isEconomicType(messageType) {
            return true
        }

        do {
            try validateThreadId(threadId)
        } catch {
            return false
        }

        lock.lock()
        defer { lock.unlock() }

        let currentState = threads[compositeKey(conversationId, threadId)]?.state ?? .idle

        if TERMINAL_STATES.contains(currentState) {
            return false
        }

        let transitionKey = "\(currentState.rawValue):\(messageType.rawValue)"
        return TRANSITIONS[transitionKey] != nil
    }

    public func getState(conversationId: String, threadId: String) -> ThreadState {
        lock.lock()
        defer { lock.unlock() }
        return threads[compositeKey(conversationId, threadId)]?.state ?? .idle
    }

    public func getSnapshot(conversationId: String, threadId: String) -> ThreadSnapshot {
        lock.lock()
        defer { lock.unlock() }
        let thread = threads[compositeKey(conversationId, threadId)]
        return ThreadSnapshot(
            conversationId: conversationId,
            threadId: threadId,
            state: thread?.state ?? .idle,
            history: thread?.history ?? []
        )
    }

    public func allowedTypes(conversationId: String, threadId: String) -> [MessageType] {
        lock.lock()
        defer { lock.unlock() }

        let currentState = threads[compositeKey(conversationId, threadId)]?.state ?? .idle

        if TERMINAL_STATES.contains(currentState) {
            return []
        }

        var allowed: [MessageType] = []
        let prefix = "\(currentState.rawValue):"
        for (transKey, _) in TRANSITIONS {
            if transKey.hasPrefix(prefix) {
                let typeStr = String(transKey.dropFirst(prefix.count))
                if let msgType = MessageType(rawValue: typeStr) {
                    allowed.append(msgType)
                }
            }
        }
        return allowed
    }

    public func isTerminal(conversationId: String, threadId: String) -> Bool {
        return TERMINAL_STATES.contains(getState(conversationId: conversationId, threadId: threadId))
    }

    @discardableResult
    public func remove(conversationId: String, threadId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return threads.removeValue(forKey: compositeKey(conversationId, threadId)) != nil
    }

    public func export() -> [ThreadSnapshot] {
        lock.lock()
        defer { lock.unlock() }
        return threads.values.map { thread in
            ThreadSnapshot(
                conversationId: thread.conversationId,
                threadId: thread.threadId,
                state: thread.state,
                history: thread.history
            )
        }
    }

    /// Import previously exported state. Validates that each snapshot's history
    /// represents a legal walk through the transition table from .idle.
    /// Rejects snapshots with invalid transition sequences to prevent state injection.
    public static func fromExport(_ snapshots: [ThreadSnapshot]) throws -> ThreadStateMachine {
        let sm = ThreadStateMachine()
        sm.lock.lock()
        defer { sm.lock.unlock() }

        for snap in snapshots {
            // Validate threadId and conversationId format (same rules as live messages)
            try validateThreadId(snap.threadId)
            guard !snap.conversationId.isEmpty, snap.conversationId.count <= 256 else {
                throw ACEError.invalidTransition("fromExport: invalid conversationId")
            }

            // Validate the history represents a valid transition sequence
            var replayState: ThreadState = .idle
            for entry in snap.history {
                guard let msgType = MessageType(rawValue: entry.type) else {
                    throw ACEError.invalidMessage("fromExport: unknown message type '\(entry.type)' in thread history")
                }
                let transitionKey = "\(replayState.rawValue):\(msgType.rawValue)"
                guard let nextState = TRANSITIONS[transitionKey] else {
                    throw ACEError.invalidTransition("fromExport: invalid transition '\(msgType.rawValue)' from state '\(replayState.rawValue)'")
                }
                replayState = nextState
            }
            // Final replayed state must match the declared state
            guard replayState == snap.state else {
                throw ACEError.invalidTransition("fromExport: declared state '\(snap.state.rawValue)' does not match history replay '\(replayState.rawValue)'")
            }

            let key = sm.compositeKey(snap.conversationId, snap.threadId)
            sm.threads[key] = ThreadEntry(
                conversationId: snap.conversationId,
                threadId: snap.threadId,
                state: snap.state,
                history: snap.history
            )
        }
        return sm
    }
}
