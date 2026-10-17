//
//  Commerce.swift
//  ACE SDK
//
//  The optional commerce profile module (profiles/commerce.md): `commerceRules()` (rule-level body constraints and the
//  thread state machine) over a durable `ThreadStore`. Outside every core path. A received commerce message never
//  authorizes a payment: whether to pay, deliver or accept an amount is the application's decision.
//

import Foundation

public enum CommerceType {
    public static let rfq = "ace:commerce:rfq:1"
    public static let offer = "ace:commerce:offer:1"
    public static let accept = "ace:commerce:accept:1"
    public static let reject = "ace:commerce:reject:1"
    public static let invoice = "ace:commerce:invoice:1"
    public static let payment = "ace:commerce:payment:1"
    public static let deliver = "ace:commerce:deliver:1"
    public static let confirm = "ace:commerce:confirm:1"
    public static let all: Set<String> = [rfq, offer, accept, reject, invoice, payment, deliver, confirm]
}

public enum ThreadState: String, Sendable, CaseIterable {
    case idle, requested, offered, accepted, rejected, invoiced, paid, delivered, confirmed

    public var isTerminal: Bool { self == .rejected || self == .confirmed }
}

private enum Role { case buyer, seller }

/// (from, type) → (to, required sender role), in table order.
private let transitions: [(from: ThreadState, type: String, to: ThreadState, role: Role)] = [
    (.idle, CommerceType.rfq, .requested, .buyer),
    (.requested, CommerceType.offer, .offered, .seller),
    (.requested, CommerceType.reject, .rejected, .seller),
    (.offered, CommerceType.offer, .offered, .seller),
    (.offered, CommerceType.accept, .accepted, .buyer),
    (.offered, CommerceType.reject, .rejected, .buyer),
    (.accepted, CommerceType.invoice, .invoiced, .seller),
    (.accepted, CommerceType.payment, .paid, .buyer),
    (.accepted, CommerceType.deliver, .delivered, .seller),
    (.invoiced, CommerceType.payment, .paid, .buyer),
    (.paid, CommerceType.deliver, .delivered, .seller),
    (.delivered, CommerceType.confirm, .confirmed, .buyer),
]

private let referenceFields: [String: String] = [
    CommerceType.accept: "offerId", CommerceType.invoice: "offerId", CommerceType.payment: "referenceId", CommerceType.confirm: "deliverId",
]

public struct ThreadHistoryEntry: Sendable, Equatable {
    public let type: String
    public let messageId: String
    public let timestamp: Int
    public let from: String
}

/// One commerce thread, keyed by `(local pair key, threadId)`. The first entry's sender is the buyer.
public struct CommerceThread: Sendable, Equatable {
    public let pair: String
    public let threadId: String
    /// `[buyer, seller]`.
    public let parties: [String]
    public let state: ThreadState
    public let history: [ThreadHistoryEntry]

    var jsonValue: JSONValue {
        ["version": 1, "pair": .string(pair), "threadId": .string(threadId), "parties": .array(parties.map { .string($0) }),
         "state": .string(state.rawValue),
         "history": .array(history.map { ["type": .string($0.type), "messageId": .string($0.messageId), "timestamp": .number(Double($0.timestamp)),
                                          "from": .string($0.from)] })]
    }

    init(pair: String, threadId: String, parties: [String], state: ThreadState, history: [ThreadHistoryEntry]) {
        self.pair = pair
        self.threadId = threadId
        self.parties = parties
        self.state = state
        self.history = history
    }

    init(_ v: JSONValue, key: String) throws {
        guard v["version"] == 1, let pair = v["pair"]?.stringValue, let t = v["threadId"]?.stringValue,
              let parties = v["parties"]?.arrayValue?.compactMap(\.stringValue), parties.count == 2,
              let state = v["state"]?.stringValue.flatMap(ThreadState.init), let list = v["history"]?.arrayValue else {
            throw ACEError(.storageFailed, "\(key) is malformed")
        }
        let history = try list.map { h -> ThreadHistoryEntry in
            guard let type = h["type"]?.stringValue, let id = h["messageId"]?.stringValue, let ts = h["timestamp"]?.wireInt,
                  let from = h["from"]?.stringValue else { throw ACEError(.storageFailed, "\(key) history is malformed") }
            return ThreadHistoryEntry(type: type, messageId: id, timestamp: ts, from: from)
        }
        self.init(pair: pair, threadId: t, parties: parties, state: state, history: history)
    }
}

/// Durable commerce threads (`commerce/threads/…`, lock `threads`).
public struct ThreadStore: Sendable {
    public static let maxOpenThreadsPerPeer = 1000
    public static let maxHistory = 1000
    let store: any ACEStore

    public init(store: any ACEStore) { self.store = store }

    private static func key(_ pair: String, _ threadId: String) -> String {
        "commerce/threads/\(pairDigest(pair, threadId)).json"
    }

    private static func openKey(_ peer: String) -> String { "commerce/open/\(sha256Hex(Data(peer.utf8))).json" }

    /// The thread between `a` and `b` named `threadId`, or nil.
    public func thread(between a: String, and b: String, threadId: String) throws -> CommerceThread? {
        let key = Self.key(conversationKey(a, b), threadId)
        return try store.readJSON(key).map { try CommerceThread($0, key: key) }
    }

    func openThreads(_ peer: String) throws -> [String] {
        guard let raw = try store.checkedRead(Self.openKey(peer)) else { return [] }
        return JSONValue(stored: raw)?["open"]?.arrayValue?.compactMap(\.stringValue) ?? []
    }

    func write(_ t: CommerceThread, peer: String) throws {
        let key = Self.key(t.pair, t.threadId)
        try store.checkedWrite(key, try t.jsonValue.jsonData())
        var open = Set(try openThreads(peer))
        if t.state.isTerminal { open.remove(key) } else { open.insert(key) }
        try store.checkedWrite(Self.openKey(peer), try JSONValue.object(["open": .array(open.sorted().map { .string($0) })]).jsonData())
    }
}

/// The commerce profile rules (`ace:commerce:1`).
public struct CommerceRules: ProfileRules {
    public let types = CommerceType.all
    public let localAceId: String
    public let threads: ThreadStore

    public init(store: any ACEStore, localAceId: String) {
        self.localAceId = localAceId
        self.threads = ThreadStore(store: store)
    }

    private func bad(_ m: String) -> ACEError { ACEError(.invalidBody, m) }

    /// Rule-level body constraints (`invalid_body`).
    private func checkBody(_ type: String, _ body: [String: JSONValue]) throws {
        func nonEmpty(_ v: JSONValue?) -> Bool { (v?.stringValue).map { !$0.isEmpty } ?? false }
        switch type {
        case CommerceType.invoice:
            guard let s = body["settlement"]?.objectValue else { throw bad("invoice.settlement is required") }
            switch s["method"]?.stringValue {
            case "stablecoin":
                guard Set(s.keys).isSubset(of: ["method", "asset", "recipient", "memo"]), (s["asset"]?.stringValue).map(isCAIP19) == true,
                      nonEmpty(s["recipient"]) else { throw bad("stablecoin settlement is {method, asset: CAIP-19, recipient, memo?}") }
            case "stripe-link":
                guard Set(s.keys) == ["method", "url"], (s["url"]?.stringValue).map(isHTTPSURL) == true else {
                    throw bad("stripe-link settlement is {method, url: HTTPS}")
                }
            default: throw bad("unknown settlement method")
            }
        case CommerceType.payment:
            guard let s = body["settlement"]?.objectValue, Set(s.keys) == ["method", "proof"], let proof = s["proof"]?.objectValue else {
                throw bad("payment.settlement is {method, proof}")
            }
            switch s["method"]?.stringValue {
            case "stablecoin": guard Set(proof.keys) == ["txHash"], nonEmpty(proof["txHash"]) else { throw bad("stablecoin proof is {txHash}") }
            case "stripe-link": guard Set(proof.keys) == ["paymentId"], nonEmpty(proof["paymentId"]) else { throw bad("stripe-link proof is {paymentId}") }
            default: throw bad("unknown settlement method")
            }
        case CommerceType.deliver:
            switch body["type"]?.stringValue {
            case "inline": guard body["content"]?.stringValue != nil else { throw bad("deliver (inline) requires content") }
            case "reference": guard body["uri"]?.stringValue != nil else { throw bad("deliver (reference) requires uri") }
            default: throw bad("deliver.type must be inline or reference")
            }
        default:
            break
        }
    }

    /// The next state, or nil when the message is already in the thread (idempotent). The check order of
    /// profiles/commerce.md § Check order.
    private func decide(_ e: ProfileEvent, _ body: [String: JSONValue]) throws -> (CommerceThread?, ThreadState)? {
        guard let threadId = e.threadId else { throw bad("commerce messages require threadId") }
        try checkBody(e.type, body)
        guard (e.from == localAceId) != (e.to == localAceId) else { throw ACEError(.wrongParty, "the local agent is not exactly one party") }
        let thread = try threads.thread(between: e.from, and: e.to, threadId: threadId)
        if let thread {
            if thread.history.contains(where: { $0.messageId == e.messageId && $0.from == e.from }) { return nil }
            guard Set(thread.parties) == Set([e.from, e.to]) else { throw ACEError(.wrongParty, "message is not between the thread's parties") }
        }
        let state = thread?.state ?? .idle
        guard !state.isTerminal, let rule = transitions.first(where: { $0.from == state && $0.type == e.type }) else {
            throw ACEError(.transitionNotAllowed, "'\(e.type)' is not allowed in state '\(state.rawValue)'")
        }
        if let thread {
            let role: Role = e.from == thread.parties[0] ? .buyer : .seller
            guard role == rule.role else { throw ACEError(.wrongRole, "'\(e.type)' must come from the \(rule.role)") }
        }
        if let field = referenceFields[e.type] {
            let history = thread?.history ?? []
            let idx = e.type == CommerceType.invoice ? history.count - 2 : history.count - 1
            guard let ref = body[field]?.stringValue, idx >= 0, ref == history[idx].messageId else {
                throw ACEError(.badReference, "\(e.type).\(field) does not reference the required message")
            }
        }
        if let thread {
            guard thread.history.count < ThreadStore.maxHistory else { throw ACEError(.limitExceeded, "thread history limit reached") }
        } else {
            let peer = e.from == localAceId ? e.to : e.from
            guard try threads.openThreads(peer).count < ThreadStore.maxOpenThreadsPerPeer else {
                throw ACEError(.limitExceeded, "open thread limit reached for this peer")
            }
        }
        return (thread, rule.to)
    }

    public func check(_ event: ProfileEvent, body: [String: JSONValue]) throws {
        _ = try decide(event, body)
    }

    public func commit(_ event: ProfileEvent, body: [String: JSONValue]) throws {
        try threads.store.withLock("threads") {
            guard let (thread, next) = try decide(event, body) else { return }
            let entry = ThreadHistoryEntry(type: event.type, messageId: event.messageId, timestamp: event.timestamp, from: event.from)
            let updated = CommerceThread(pair: conversationKey(event.from, event.to), threadId: event.threadId!,
                                         parties: thread?.parties ?? [event.from, event.to], state: next, history: (thread?.history ?? []) + [entry])
            try threads.write(updated, peer: event.from == localAceId ? event.to : event.from)
        }
    }
}

/// The commerce profile rules for `localAceId`, persisting threads in `store`.
public func commerceRules(store: any ACEStore, localAceId: String) -> CommerceRules {
    CommerceRules(store: store, localAceId: localAceId)
}
