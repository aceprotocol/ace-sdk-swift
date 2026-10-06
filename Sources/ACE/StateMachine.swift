//
//  StateMachine.swift
//  ACE SDK
//
//  Thread state machine with parties, roles and fixed reference positions (04).
//

import Foundation

public enum ThreadState: String, Codable, Sendable, CaseIterable {
    case idle, rfq, offered, accepted, rejected, invoiced, paid, delivered, confirmed

    public var isTerminal: Bool { self == .rejected || self == .confirmed }
}

enum ThreadRole: Sendable { case buyer, seller }

/// (from, type) → (to, required sender role), in table order.
private let transitions: [(from: ThreadState, type: MessageType, to: ThreadState, role: ThreadRole)] = [
    (.idle, .rfq, .rfq, .buyer),
    (.rfq, .offer, .offered, .seller),
    (.rfq, .reject, .rejected, .seller),
    (.offered, .offer, .offered, .seller),
    (.offered, .accept, .accepted, .buyer),
    (.offered, .reject, .rejected, .buyer),
    (.accepted, .invoice, .invoiced, .seller),
    (.accepted, .receipt, .paid, .buyer),
    (.accepted, .deliver, .delivered, .seller),
    (.invoiced, .receipt, .paid, .buyer),
    (.paid, .deliver, .delivered, .seller),
    (.delivered, .confirm, .confirmed, .buyer),
]

/// type → body field holding the reference.
private let referenceFields: [MessageType: String] = [
    .accept: "offerId", .invoice: "offerId", .receipt: "referenceId", .confirm: "deliverId",
]

/// One economic message as seen by the state machine.
public struct ThreadEvent: Sendable, Equatable {
    public let conversationId: String
    public let threadId: String?
    public let type: MessageType
    public let messageId: String
    public let timestamp: Int
    public let from: String
    public let to: String

    public init(conversationId: String, threadId: String?, type: MessageType, messageId: String, timestamp: Int, from: String, to: String) {
        self.conversationId = conversationId
        self.threadId = threadId
        self.type = type
        self.messageId = messageId
        self.timestamp = timestamp
        self.from = from
        self.to = to
    }
}

public struct ThreadHistoryEntry: Codable, Sendable, Equatable {
    public let type: MessageType
    public let messageId: String
    public let timestamp: Int
    public let from: String

    public init(type: MessageType, messageId: String, timestamp: Int, from: String) {
        self.type = type
        self.messageId = messageId
        self.timestamp = timestamp
        self.from = from
    }
}

public struct ThreadSnapshot: Codable, Sendable, Equatable {
    public let conversationId: String
    public let threadId: String
    public let localAceId: String
    public let peerAceId: String
    public let state: ThreadState
    public let history: [ThreadHistoryEntry]

    public init(conversationId: String, threadId: String, localAceId: String, peerAceId: String, state: ThreadState, history: [ThreadHistoryEntry]) {
        self.conversationId = conversationId
        self.threadId = threadId
        self.localAceId = localAceId
        self.peerAceId = peerAceId
        self.state = state
        self.history = history
    }
}

private struct ThreadKey: Hashable, Comparable {
    let conversationId: String
    let threadId: String
    static func < (a: ThreadKey, b: ThreadKey) -> Bool {
        (a.conversationId, a.threadId) < (b.conversationId, b.threadId)
    }
}

private struct ThreadRecord {
    var peer: String
    var state: ThreadState
    var history: [ThreadHistoryEntry]
}

/// Per-(conversationId, threadId) economic flow seen from `localAceId`.
///
/// Bounds reject new work and never evict; `remove` drops a thread explicitly. Thread-safe.
public final class ThreadStateMachine: @unchecked Sendable {
    public let localAceId: String
    private let maxThreads: Int
    private let maxHistory: Int
    private var threads: [ThreadKey: ThreadRecord] = [:]
    private let lock = NSLock()

    public init(localAceId: String, maxThreads: Int = 100_000, maxHistoryPerThread: Int = 1_000) throws {
        guard isACEId(localAceId) else { throw ACEError(.invalidArgument, "localAceId must be an ACE ID") }
        guard maxThreads >= 1 else { throw ACEError(.invalidArgument, "maxThreads must be a positive integer") }
        guard maxHistoryPerThread >= 1 else { throw ACEError(.invalidArgument, "maxHistoryPerThread must be a positive integer") }
        self.localAceId = localAceId
        self.maxThreads = maxThreads
        self.maxHistory = maxHistoryPerThread
    }

    /// Replay every snapshot's history under the party / role rules; any violation is
    /// `invalid_argument`. Reference positions are not re-checked (bodies are not stored).
    public convenience init(state snapshots: [ThreadSnapshot], localAceId: String, maxThreads: Int = 100_000, maxHistoryPerThread: Int = 1_000) throws {
        try self.init(localAceId: localAceId, maxThreads: maxThreads, maxHistoryPerThread: maxHistoryPerThread)
        func bad(_ msg: String) -> ACEError { ACEError(.invalidArgument, "fromState: \(msg)") }
        for snap in snapshots {
            guard isConversationId(snap.conversationId), isThreadId(snap.threadId) else {
                throw bad("invalid conversationId or threadId")
            }
            guard snap.localAceId == localAceId else { throw bad("snapshot belongs to another local identity") }
            guard isACEId(snap.peerAceId), snap.peerAceId != localAceId else { throw bad("invalid peerAceId") }
            let key = ThreadKey(conversationId: snap.conversationId, threadId: snap.threadId)
            guard threads[key] == nil else { throw bad("duplicate thread") }
            guard !snap.history.isEmpty else { throw bad("history must not be empty") }
            for h in snap.history {
                guard h.type.isEconomic, isMessageId(h.messageId), h.timestamp >= 0, h.timestamp <= maxSafeInteger,
                      h.from == localAceId || h.from == snap.peerAceId else {
                    throw bad("invalid history entry")
                }
                let to = h.from == localAceId ? snap.peerAceId : localAceId
                let e = ThreadEvent(conversationId: snap.conversationId, threadId: snap.threadId, type: h.type,
                                    messageId: h.messageId, timestamp: h.timestamp, from: h.from, to: to)
                do {
                    let next = try decide(e, body: nil, checkRefs: false)
                    commit(e, next: next)
                } catch let error as ACEError {
                    throw bad(error.message)
                }
            }
            guard threads[key]?.state == snap.state else { throw bad("declared state does not match the replayed history") }
        }
    }

    // MARK: Core rules (caller holds the lock or is the initializer)

    private func decide(_ e: ThreadEvent, body: JSONObject?, checkRefs: Bool) throws -> ThreadState {
        guard let threadId = e.threadId, isThreadId(threadId) else {
            throw ACEError(.invalidEnvelope, "economic messages require a valid threadId")
        }
        guard e.from == localAceId || e.to == localAceId, e.from != e.to else {
            throw ACEError(.wrongParty, "the local identity is not exactly one party of this message")
        }
        let thread = threads[ThreadKey(conversationId: e.conversationId, threadId: threadId)]
        if let thread, Set([localAceId, thread.peer]) != Set([e.from, e.to]) {
            throw ACEError(.wrongParty, "message is not between the thread's two parties")
        }
        let state = thread?.state ?? .idle
        guard !state.isTerminal, let rule = transitions.first(where: { $0.from == state && $0.type == e.type }) else {
            throw ACEError(.transitionNotAllowed, "'\(e.type.rawValue)' is not allowed in state '\(state.rawValue)'")
        }
        if let thread {
            let senderRole: ThreadRole = e.from == thread.history[0].from ? .buyer : .seller
            guard senderRole == rule.role else {
                throw ACEError(.wrongRole, "'\(e.type.rawValue)' in state '\(state.rawValue)' must come from the \(rule.role)")
            }
        }
        if checkRefs, let field = referenceFields[e.type] {
            guard let ref = body?[field] as? String, !isJSONBool(body?[field] as Any) else {
                throw ACEError(.invalidBody, "\(e.type.rawValue).\(field) is required")
            }
            let history = thread?.history ?? []
            let idx = e.type == .invoice ? history.count - 2 : history.count - 1
            guard idx >= 0, ref == history[idx].messageId else {
                throw ACEError(.badReference, "\(e.type.rawValue).\(field) does not reference the required message")
            }
        }
        if let thread {
            guard thread.history.count < maxHistory else {
                throw ACEError(.limitExceeded, "thread history limit \(maxHistory) reached")
            }
        } else if threads.count >= maxThreads {
            throw ACEError(.limitExceeded, "thread limit \(maxThreads) reached")
        }
        return rule.to
    }

    private func commit(_ e: ThreadEvent, next: ThreadState) {
        let key = ThreadKey(conversationId: e.conversationId, threadId: e.threadId!)
        let entry = ThreadHistoryEntry(type: e.type, messageId: e.messageId, timestamp: e.timestamp, from: e.from)
        if var thread = threads[key] {
            thread.state = next
            thread.history.append(entry)
            threads[key] = thread
        } else {
            let peer = e.from == localAceId ? e.to : e.from
            threads[key] = ThreadRecord(peer: peer, state: next, history: [entry])
        }
    }

    // MARK: Public API

    /// Throw the deterministic error `apply` would throw; never mutates. Non-economic: no-op.
    public func check(_ e: ThreadEvent, body: JSONObject) throws {
        guard e.type.isEconomic else { return }
        lock.lock()
        defer { lock.unlock() }
        _ = try decide(e, body: body, checkRefs: true)
    }

    /// Check and apply; returns the resulting state (non-economic: the current state, or
    /// `idle` without a threadId).
    @discardableResult
    public func apply(_ e: ThreadEvent, body: JSONObject) throws -> ThreadState {
        lock.lock()
        defer { lock.unlock() }
        guard e.type.isEconomic else {
            guard let t = e.threadId else { return .idle }
            return threads[ThreadKey(conversationId: e.conversationId, threadId: t)]?.state ?? .idle
        }
        let next = try decide(e, body: body, checkRefs: true)
        commit(e, next: next)
        return next
    }

    /// Apply without reference checks (rebuilding a re-signed head entry). Internal.
    func applyWithoutReferences(_ e: ThreadEvent) throws {
        lock.lock()
        defer { lock.unlock() }
        let next = try decide(e, body: nil, checkRefs: false)
        commit(e, next: next)
    }

    public func getState(conversationId: String, threadId: String) -> ThreadState {
        lock.lock()
        defer { lock.unlock() }
        return threads[ThreadKey(conversationId: conversationId, threadId: threadId)]?.state ?? .idle
    }

    public func getSnapshot(conversationId: String, threadId: String) -> ThreadSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        guard let t = threads[ThreadKey(conversationId: conversationId, threadId: threadId)] else { return nil }
        return ThreadSnapshot(conversationId: conversationId, threadId: threadId, localAceId: localAceId,
                              peerAceId: t.peer, state: t.state, history: t.history)
    }

    /// Economic types `senderAceId` may send next, in table order. Unknown thread: `[.rfq]`.
    public func allowedTypes(conversationId: String, threadId: String, senderAceId: String) -> [MessageType] {
        lock.lock()
        defer { lock.unlock() }
        guard let t = threads[ThreadKey(conversationId: conversationId, threadId: threadId)] else { return [.rfq] }
        guard senderAceId == localAceId || senderAceId == t.peer, !t.state.isTerminal else { return [] }
        let role: ThreadRole = senderAceId == t.history[0].from ? .buyer : .seller
        return transitions.filter { $0.from == t.state && $0.role == role }.map(\.type)
    }

    public func isTerminal(conversationId: String, threadId: String) -> Bool {
        getState(conversationId: conversationId, threadId: threadId).isTerminal
    }

    @discardableResult
    public func remove(conversationId: String, threadId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return threads.removeValue(forKey: ThreadKey(conversationId: conversationId, threadId: threadId)) != nil
    }

    /// All threads, sorted by (conversationId, threadId).
    public func exportState() -> [ThreadSnapshot] {
        lock.lock()
        defer { lock.unlock() }
        return threads.keys.sorted().map { k in
            let t = threads[k]!
            return ThreadSnapshot(conversationId: k.conversationId, threadId: k.threadId, localAceId: localAceId,
                                  peerAceId: t.peer, state: t.state, history: t.history)
        }
    }
}
