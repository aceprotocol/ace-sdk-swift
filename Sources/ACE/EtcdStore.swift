import Foundation

/// Private replicated authority state. The operator must pin a trusted etcd v3 quorum's identity.
/// There is no offline fallback, automatic re-pin, or retry of an uncertain effect.
public final class EtcdStore: ACECoordinatedStore, @unchecked Sendable {
    public struct Configuration: Sendable {
        public let endpoint: String
        public let namespace: String
        public let clusterId: String
        public let token: String?
        public let timeout: TimeInterval
        public let leaseSeconds: Int
        public init(endpoint: String, namespace: String, clusterId: String, token: String? = nil,
                    timeout: TimeInterval = 5, leaseSeconds: Int = 60) {
            self.endpoint = endpoint; self.namespace = namespace; self.clusterId = clusterId
            self.token = token; self.timeout = timeout; self.leaseSeconds = leaseSeconds
        }
    }
    private struct Held: Sendable { let key: String; let value: String }
    private let config: Configuration
    private let origin: String
    private let prefix: String
    private let mutexes = NamedMutexes()
    /// One session for the store's lifetime, so RPCs reuse their TCP/TLS connection.
    private let session: URLSession
    private let health = NSLock()
    private var broken = false
    private static func failed() -> ACEError {
        ACEError(.storageFailed, "replicated store unavailable, changed or lock ownership lost")
    }
    private static func decimal(_ value: Any?) -> String? {
        guard let s = value as? String, s.first != "0", !s.isEmpty,
              s.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }), UInt64(s) != nil else { return nil }
        return s
    }
    public init(configuration: Configuration) throws {
        let c = configuration
        guard let url = URLComponents(string: c.endpoint), let host = url.host,
              url.scheme == "https" || url.scheme == "http" && ["127.0.0.1", "[::1]", "::1"].contains(host),
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path.isEmpty || url.path == "/", let endpoint = url.url,
              Self.decimal(c.clusterId) != nil, c.timeout.isFinite, c.timeout > 0, c.timeout <= 30,
              (1...300).contains(c.leaseSeconds),
              c.token == nil || (!c.token!.isEmpty && c.token!.utf8.count <= 4096 && c.token!.utf8.allSatisfy({ $0 >= 33 && $0 <= 126 })) else {
            throw ACEError(.invalidArgument, "invalid replicated store configuration")
        }
        try validateLockName(c.namespace)
        config = c; origin = endpoint.absoluteString.hasSuffix("/") ? String(endpoint.absoluteString.dropLast()) : endpoint.absoluteString
        prefix = "/ace/\(c.namespace)/data/"
        session = EtcdHTTPExchange.session(timeout: c.timeout)
    }
    deinit { session.invalidateAndCancel() }
    private func assertHealthy() throws {
        health.lock(); defer { health.unlock() }
        if broken { throw Self.failed() }
    }
    private func poison() { health.lock(); broken = true; health.unlock() }
    private static func b64(_ s: String) -> String { Data(s.utf8).base64EncodedString() }
    private static func bytes(_ value: Any?) throws -> Data {
        if value == nil { return Data() } // protobuf omits empty bytes
        guard let s = value as? String,
              let d = try? decodeB64(s, code: .storageFailed, what: "etcd value", maxBytes: ACELimits.maxStoreValueBytes),
              d.count <= ACELimits.maxStoreValueBytes else { throw failed() }
        return d
    }
    private func rpc(_ path: String, _ body: [String: Any]) throws -> [String: Any] {
        try assertHealthy()
        do {
            var request = URLRequest(url: URL(string: origin + path)!)
            request.httpMethod = "POST"; request.timeoutInterval = config.timeout
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            if let token = config.token { request.setValue(token, forHTTPHeaderField: "Authorization") }
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
            let bytes = try EtcdHTTPExchange.perform(request, session: session, timeout: config.timeout)
            guard let result = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
                  let header = result["header"] as? [String: Any], header["cluster_id"] as? String == config.clusterId,
                  Self.decimal(header["revision"]) != nil else { throw Self.failed() }
            try assertHealthy()
            return result
        } catch { poison(); throw Self.failed() }
    }
    private func comparisons(_ held: Held) -> [[String: String]] {
        [["key": held.key, "target": "VALUE", "result": "EQUAL", "value": held.value]]
    }
    private func txn(_ held: Held, _ op: [String: Any]) throws -> [String: Any] {
        let r = try rpc("/v3/kv/txn", ["compare": comparisons(held), "success": [op]])
        guard r["succeeded"] as? Bool == true, let responses = r["responses"] as? [[String: Any]], responses.count == 1 else {
            poison(); throw Self.failed()
        }
        return responses[0]
    }
    private func read(_ held: Held, _ key: String) throws -> Data? {
        try validateStoreKey(key)
        let encoded = Self.b64(prefix + key), r = try txn(held, ["request_range": ["key": encoded, "serializable": false]])
        guard let range = r["response_range"] as? [String: Any], range["kvs"] == nil || range["kvs"] is [[String: Any]] else { throw Self.failed() }
        let rows = range["kvs"] as? [[String: Any]] ?? []
        if rows.isEmpty { return nil }
        guard rows.count == 1, rows[0]["key"] as? String == encoded else { throw Self.failed() }
        return try Self.bytes(rows[0]["value"])
    }
    private func write(_ held: Held, _ key: String, _ value: Data) throws {
        try validateStoreKey(key); try validateStoreValue(value)
        _ = try txn(held, ["request_put": ["key": Self.b64(prefix + key), "value": value.base64EncodedString()]])
    }
    private func delete(_ held: Held, _ key: String) throws {
        try validateStoreKey(key)
        _ = try txn(held, ["request_delete_range": ["key": Self.b64(prefix + key)]])
    }
    private func list(_ held: Held, _ p: String) throws -> [String] {
        guard p.utf8.count <= 200, p.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || [46, 95, 47, 45].contains($0) }) else {
            throw ACEError(.invalidArgument, "invalid store prefix")
        }
        let first = Data((prefix + p).utf8)
        var end = first; end[end.count - 1] += 1
        var start = first, revision: String?, result: [String] = []
        while true {
            var query: [String: Any] = ["key": start.base64EncodedString(), "range_end": end.base64EncodedString(),
                "keys_only": true, "limit": "1024", "sort_order": "ASCEND", "sort_target": "KEY", "serializable": false]
            if let revision { query["revision"] = revision }
            let response = try txn(held, ["request_range": query])
            guard let range = response["response_range"] as? [String: Any], let header = range["header"] as? [String: Any],
                  let current = Self.decimal(header["revision"]), range["kvs"] == nil || range["kvs"] is [[String: Any]] else { throw Self.failed() }
            if revision == nil { revision = current }
            let rows = range["kvs"] as? [[String: Any]] ?? [], more = range["more"] as? Bool == true
            guard rows.count <= 1024, !more || !rows.isEmpty else { throw Self.failed() }
            var last: Data?
            for row in rows {
                let raw = try Self.bytes(row["key"])
                guard let key = String(data: raw, encoding: .utf8), key.hasPrefix(prefix + p), !raw.lexicographicallyPrecedes(start),
                      last == nil || last!.lexicographicallyPrecedes(raw) else { throw Self.failed() }
                let name = String(key.dropFirst(prefix.count)); try validateStoreKey(name)
                result.append(name); last = raw
            }
            guard result.count <= 100_000 else { throw Self.failed() }
            if !more { return result }
            start = last!; start.append(0)
        }
    }
    /// Finite state transactions only; long-lived receive locks must use a pipeline store.
    public func coordinate<T>(_ name: String, _ body: (any ACEStoreData) throws -> T) throws -> T {
        try validateLockName(name); try assertHealthy()
        let deadline = ContinuousClock.now.advanced(by: .seconds(ACELimits.defaultLockTimeoutSeconds))
        guard mutexes.acquire(name, timeout: ACELimits.defaultLockTimeoutSeconds) else { throw lockTimeoutError(name) }
        defer { mutexes.release(name) }
        let lease = try rpc("/v3/lease/grant", ["TTL": String(config.leaseSeconds)])
        guard let id = Self.decimal(lease["ID"]) else { poison(); throw Self.failed() }
        let held = Held(key: Self.b64("/ace/\(config.namespace)/locks/\(name)"), value: Data(randomBytes(32)).base64EncodedString())
        while true {
            let r = try rpc("/v3/kv/txn", ["compare": [["key": held.key, "target": "VERSION", "result": "EQUAL", "version": "0"]],
                "success": [["request_put": ["key": held.key, "value": held.value, "lease": id]]]])
            if r["succeeded"] as? Bool == true { break }
            guard ContinuousClock.now < deadline else { throw lockTimeoutError(name) }
            Thread.sleep(forTimeInterval: 0.05)
        }
        let view = View(owner: self, held: held)
        let result: Result<T, Error>
        do { result = .success(try body(view)) } catch { result = .failure(error) }
        view.invalidate()
        // Even an empty callback cannot succeed after losing its lease. An old owner must never
        // remove a successor's lock. A failed response poisons this instance, including lost ACKs.
        let r = try rpc("/v3/kv/txn", ["compare": comparisons(held), "success": [["request_delete_range": ["key": held.key]]]])
        guard r["succeeded"] as? Bool == true else { poison(); throw Self.failed() }
        return try result.get()
    }
    private final class View: ACEStoreData, @unchecked Sendable {
        let owner: EtcdStore
        let held: Held
        let mutex = NSLock()
        var active = true
        init(owner: EtcdStore, held: Held) { self.owner = owner; self.held = held }
        func invalidate() { mutex.lock(); active = false; mutex.unlock() }
        func use<T>(_ body: () throws -> T) throws -> T {
            mutex.lock(); defer { mutex.unlock() }
            guard active else { throw EtcdStore.failed() }
            do { return try body() } catch {
                if (error as? ACEError)?.code == .storageFailed { owner.poison() }
                throw error
            }
        }
        func read(_ key: String) throws -> Data? { try use { try owner.read(held, key) } }
        func write(_ key: String, _ value: Data) throws { try use { try owner.write(held, key, value) } }
        func delete(_ key: String) throws { try use { try owner.delete(held, key) } }
        func list(prefix: String) throws -> [String] { try use { try owner.list(held, prefix) } }
    }
}

/// Synchronous bridge for ACEStoreData; callbacks run on a URLSession delegate queue, never a
/// blocked Swift cooperative executor. No redirects, cookies, credentials, caches or unbounded body.
/// Each request's exchange is its task's own delegate on the store's shared session.
private final class EtcdHTTPExchange: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let condition = NSCondition()
    private var data = Data()
    private var done = false
    private var valid = false
    private static let cap = ACELimits.maxStoreValueBytes * 4 / 3 + 1_048_576
    static func session(timeout: TimeInterval) -> URLSession {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieStorage = nil; c.httpShouldSetCookies = false; c.urlCredentialStorage = nil; c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData; c.timeoutIntervalForRequest = timeout; c.timeoutIntervalForResource = timeout
        return URLSession(configuration: c, delegate: nil, delegateQueue: nil)
    }
    static func perform(_ request: URLRequest, session: URLSession, timeout: TimeInterval) throws -> Data {
        let exchange = EtcdHTTPExchange(), task = session.dataTask(with: request)
        task.delegate = exchange
        defer { task.cancel() }  // no-op once complete; stops a timed-out request
        let deadline = Date(timeIntervalSinceNow: timeout)
        exchange.condition.lock(); defer { exchange.condition.unlock() }
        task.resume()
        while !exchange.done {
            if !exchange.condition.wait(until: deadline) && !exchange.done { throw ACEError(.storageFailed, "replicated store request timed out") }
        }
        guard exchange.valid else { throw ACEError(.storageFailed, "replicated store request failed") }
        return exchange.data
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void) {
        let accept = (response as? HTTPURLResponse).map { (200...299).contains($0.statusCode) } == true && response.expectedContentLength <= Self.cap
        condition.lock(); valid = accept; condition.unlock(); completionHandler(accept ? .allow : .cancel)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive bytes: Data) {
        condition.lock()
        let overflow = data.count + bytes.count > Self.cap
        if overflow { valid = false } else { data.append(bytes) }
        condition.unlock()
        if overflow { dataTask.cancel() }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        condition.lock(); if error != nil { valid = false }; done = true; condition.broadcast(); condition.unlock()
    }
}
