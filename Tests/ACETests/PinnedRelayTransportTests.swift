import Foundation
import Network
import Security
import Testing
@testable import ACE

/// A real loopback socket, so these tests exercise the connection destination rather than URLProtocol mocks.
private final class PinnedTestServer: @unchecked Sendable {
    let listener: NWListener
    let queue = DispatchQueue(label: "ace.pinned-test-server")
    let requests = LockedValue<[Data]>([])
    let connections = LockedValue<[NWConnection]>([])
    let handler: @Sendable (NWConnection, Data) -> Void
    let raw: Bool

    init(raw: Bool = false, tls: NWProtocolTLS.Options? = nil,
         handler: @escaping @Sendable (NWConnection, Data) -> Void) throws {
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        listener = try NWListener(using: parameters)
        self.handler = handler
        self.raw = raw
    }

    func start() async throws -> Int {
        let ready = RelayIOResult<Int>()
        listener.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready: ready.finish(.success(Int(self!.listener.port!.rawValue)))
            case .failed(let error): ready.finish(.failure(error))
            case .cancelled: ready.finish(.failure(CancellationError()))
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            connections.value.append(connection)
            connection.start(queue: queue)
            receive(connection, accumulated: Data())
        }
        listener.start(queue: queue)
        return try await withCheckedThrowingContinuation { ready.install($0) }
    }

    private func receive(_ connection: NWConnection, accumulated: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, complete, error in
            guard let self, let data, error == nil else { return }
            let total = accumulated + data
            if raw || total.range(of: Data("\r\n\r\n".utf8)) != nil {
                requests.value.append(total)
                handler(connection, total)
            } else if !complete, total.count < 65536 { receive(connection, accumulated: total) }
        }
    }

    func stop() { listener.cancel(); for connection in connections.value { connection.cancel() } }
    deinit { stop() }
}

private func respond(_ connection: NWConnection, _ text: String, close: Bool = true) {
    connection.send(content: Data(text.utf8), contentContext: close ? .finalMessage : .defaultMessage,
                    isComplete: true, completion: .contentProcessed { _ in })
}

private func pinnedRequest(port: Int, path: String = "/v1/test", tls: Bool = false) -> URLRequest {
    URLRequest(url: URL(string: "\(tls ? "https" : "http")://relay.invalid:\(port)\(path)")!)
}

private func readPinned(_ bytes: RelayResponseBytes) async throws -> Data {
    defer { bytes.cancel() }
    var out = Data()
    for try await byte in bytes { out.append(byte) }
    return out
}

@Suite struct PinnedRelayTransportTests {
    @Test func connectsOnlyToValidatedIPAndRetainsAuthority() async throws {
        let server = try PinnedTestServer { connection, _ in respond(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}") }
        let port = try await server.start()
        defer { server.stop() }
        let resolutions = LockedValue(0)
        let resolver: PinnedRelayTransport.Resolver = { host in
            #expect(host == "relay.invalid")
            resolutions.value += 1
            // A second lookup, whether during connection or a later request, would be unsafe.
            return resolutions.value == 1 ? ["127.0.0.1"] : ["10.0.0.1"]
        }
        let (bytes, response) = try await PinnedRelayTransport.open(pinnedRequest(port: port, path: "/v1/test?q=a%20b"),
            allowLoopback: true, timeout: 10, streaming: false, resolver: resolver)
        #expect(response.statusCode == 200)
        #expect(try await readPinned(bytes) == Data("{}".utf8))
        #expect(resolutions.value == 1)
        let request = String(decoding: try #require(server.requests.value.first), as: UTF8.self)
        #expect(request.hasPrefix("GET /v1/test?q=a%20b HTTP/1.1\r\n"))
        #expect(request.contains("\r\nHost: relay.invalid:\(port)\r\n"))
        await expectCodeAsync(.blockedAddress) {
            _ = try await PinnedRelayTransport.open(pinnedRequest(port: port), allowLoopback: true,
                timeout: 10, streaming: false, resolver: resolver)
        }
        #expect(resolutions.value == 2)
        #expect(server.requests.value.count == 1)
    }

    @Test func rejectsEveryBlockedDNSAnswerBeforeConnecting() async throws {
        let server = try PinnedTestServer { _, _ in Issue.record("blocked destination was contacted") }
        let port = try await server.start()
        defer { server.stop() }
        for addresses in [["127.0.0.1", "10.0.0.1"], ["127.0.0.1", "::ffff:169.254.169.254"], ["not-an-ip"]] {
            await expectCodeAsync(.blockedAddress) {
                _ = try await PinnedRelayTransport.open(pinnedRequest(port: port), allowLoopback: true,
                    timeout: 1, streaming: false, resolver: { _ in addresses })
            }
        }
        #expect(server.connections.value.isEmpty)
        await expectCodeAsync(.blockedAddress) {
            _ = try await PinnedRelayTransport.open(pinnedRequest(port: port, tls: true), allowLoopback: false,
                timeout: 1, streaming: false, resolver: { _ in ["127.0.0.1"] })
        }
    }

    @Test(arguments: [
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=x\r\nhe\r\n3\r\nllo\r\n0\r\nX-Test: end\r\n\r\n",
        "HTTP/1.0 200 OK\r\n\r\nhello"
    ]) func supportsBoundedHTTPFraming(_ response: String) async throws {
        let server = try PinnedTestServer { connection, _ in
            // Deliberately split CRLF and chunk boundaries across writes.
            let chunks = Array(response.utf8).chunkedForTest(3)
            for (index, chunk) in chunks.enumerated() {
                connection.send(content: Data(chunk), contentContext: index == chunks.count - 1 ? .finalMessage : .defaultMessage,
                                isComplete: true, completion: .contentProcessed { _ in })
            }
        }
        let port = try await server.start()
        defer { server.stop() }
        let (bytes, _) = try await PinnedRelayTransport.open(pinnedRequest(port: port), allowLoopback: true,
            timeout: 10, streaming: false, resolver: { _ in ["127.0.0.1"] })
        #expect(try await readPinned(bytes) == Data("hello".utf8))
    }

    @Test(arguments: [
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999999\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\nx\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx!\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 1\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
        "HTTP/1.1 200 OK\nContent-Length: 0\n\n",
        "oversized-header"
    ]) func rejectsMalformedOrUnboundedFraming(_ response: String) async throws {
        let payload = response == "oversized-header"
            ? "HTTP/1.1 200 OK\r\nX-Large: " + String(repeating: "a", count: 65536) + "\r\n\r\n" : response
        let server = try PinnedTestServer { connection, _ in respond(connection, payload) }
        let port = try await server.start()
        defer { server.stop() }
        await expectCodeAsync(.relayProtocolError) {
            let (bytes, _) = try await PinnedRelayTransport.open(pinnedRequest(port: port), allowLoopback: true,
                timeout: 10, streaming: false, resolver: { _ in ["127.0.0.1"] })
            _ = try await readPinned(bytes)
        }
    }

    @Test func dnsAndStreamHeadersHaveDeadlines() async throws {
        let start = ContinuousClock.now
        await expectCodeAsync(.relayUnavailable) {
            _ = try await PinnedRelayTransport.open(pinnedRequest(port: 1), allowLoopback: true,
                timeout: 0.1, streaming: false, resolver: { _ in
                    try await Task.sleep(for: .seconds(10)); return ["127.0.0.1"]
                })
        }
        #expect(start.duration(to: .now) < .seconds(5))
        let server = try PinnedTestServer { connection, _ in respond(connection, "HTTP/1.1 200 OK\r\n", close: false) }
        let port = try await server.start()
        defer { server.stop() }
        await expectCodeAsync(.relayUnavailable) {
            _ = try await PinnedRelayTransport.open(pinnedRequest(port: port), allowLoopback: true,
                timeout: 5, streaming: true, resolver: { _ in ["127.0.0.1"] })
        }
    }

    @Test func wholeBodyDeadlineAndCancellationTearDownSocket() async throws {
        let server = try PinnedTestServer { connection, _ in
            respond(connection, "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nx", close: false)
        }
        let port = try await server.start()
        defer { server.stop() }
        let (bytes, _) = try await PinnedRelayTransport.open(pinnedRequest(port: port), allowLoopback: true,
            timeout: 5, streaming: false, resolver: { _ in ["127.0.0.1"] })
        await expectCodeAsync(.relayUnavailable) { _ = try await readPinned(bytes) }
        let task = Task {
            let (bytes, _) = try await PinnedRelayTransport.open(pinnedRequest(port: port), allowLoopback: true,
                timeout: 10, streaming: true, resolver: { _ in ["127.0.0.1"] })
            _ = try await readPinned(bytes)
        }
        #expect(await settles { server.requests.value.count == 2 })
        let cancelledAt = ContinuousClock.now
        task.cancel()
        do { try await task.value; Issue.record("cancelled read succeeded") }
        catch { #expect(error is CancellationError) }
        #expect(cancelledAt.duration(to: .now) < .seconds(1))
    }

    @Test func fallbackUsesOnlyAlreadyValidatedAddresses() async throws {
        let server = try PinnedTestServer { connection, _ in respond(connection, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") }
        let port = try await server.start()
        defer { server.stop() }
        let resolutions = LockedValue(0)
        let (bytes, _) = try await PinnedRelayTransport.open(pinnedRequest(port: port), allowLoopback: true,
            timeout: 10, streaming: false, resolver: { _ in
                resolutions.value += 1
                return ["127.0.0.2", "127.0.0.1"]
            })
        #expect(try await readPinned(bytes).isEmpty)
        #expect(resolutions.value == 1)
        #expect(server.requests.value.count == 1)
    }

    @Test func failedStreamHandshakeKeepsWholeResponseDeadline() async throws {
        let server = try PinnedTestServer { connection, _ in
            respond(connection, "HTTP/1.1 503 Unavailable\r\nContent-Length: 20\r\nContent-Type: text/event-stream\r\n\r\nx", close: false)
        }
        let port = try await server.start()
        defer { server.stop() }
        let (bytes, response) = try await PinnedRelayTransport.open(pinnedRequest(port: port), allowLoopback: true,
            timeout: 5, streaming: true, resolver: { _ in ["127.0.0.1"] })
        #expect(response.statusCode == 503)
        await expectCodeAsync(.relayUnavailable) { _ = try await readPinned(bytes) }
    }

    @Test func successfulSSEHandshakeSwitchesToIdleTimeout() async throws {
        let server = try PinnedTestServer { connection, _ in
            respond(connection, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nContent-Length: 5\r\n\r\n", close: false)
            DispatchQueue.global().asyncAfter(deadline: .now() + 6) { respond(connection, "hello") }
        }
        let port = try await server.start()
        defer { server.stop() }
        let (bytes, _) = try await PinnedRelayTransport.open(pinnedRequest(port: port), allowLoopback: true,
            timeout: 5, streaming: true, resolver: { _ in ["127.0.0.1"] })
        // Both server idle time and consumer backpressure may exceed the short request timeout.
        try await Task.sleep(for: .seconds(6.1))
        #expect(try await readPinned(bytes) == Data("hello".utf8))
    }

    @Test func tlsUsesOriginalSNIAndRejectsAnUntrustedCertificate() async throws {
        // Capture a real ClientHello sent to a numeric IP. The DNS name must still appear as SNI.
        let helloServer = try PinnedTestServer(raw: true) { connection, _ in connection.cancel() }
        let helloPort = try await helloServer.start()
        defer { helloServer.stop() }
        await expectCodeAsync(.relayUnavailable) {
            _ = try await PinnedRelayTransport.open(pinnedRequest(port: helloPort, tls: true), allowLoopback: true,
                timeout: 10, streaming: false, resolver: { _ in ["127.0.0.1"] })
        }
        let hello = try #require(helloServer.requests.value.first)
        let sni = Array("relay.invalid".utf8)
        // extension 0 (server_name), extension length, list length, host_name 0, hostname length.
        let sniExtension = Data([0, 0, 0, UInt8(sni.count + 5), 0, UInt8(sni.count + 3), 0, 0, UInt8(sni.count)] + sni)
        #expect(hello.range(of: sniExtension) != nil)

        // Test-only self-signed identity. Import to process memory, never the user's keychain.
        let fixture = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/untrusted-relay.p12")
        var imported: CFArray?
        let options = [kSecImportExportPassphrase as String: "ace-test-only", kSecImportToMemoryOnly as String: true] as CFDictionary
        #expect(SecPKCS12Import(try Data(contentsOf: fixture) as CFData, options, &imported) == errSecSuccess)
        let items = try #require(imported as? [[String: Any]])
        let identity = try #require(items.first?[kSecImportItemIdentity as String]) as! SecIdentity
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, sec_identity_create(identity)!)
        let secureServer = try PinnedTestServer(tls: tls) { _, _ in Issue.record("untrusted TLS reached HTTP") }
        let securePort = try await secureServer.start()
        defer { secureServer.stop() }
        await expectCodeAsync(.relayUnavailable) {
            _ = try await PinnedRelayTransport.open(pinnedRequest(port: securePort, tls: true), allowLoopback: true,
                timeout: 10, streaming: false, resolver: { _ in ["127.0.0.1"] })
        }
        #expect(secureServer.connections.value.count == 1)
        #expect(secureServer.requests.value.isEmpty)
    }

    @Test func foreignClientUsesPinnedTransportAndNeverFollowsRedirects() async throws {
        let destination = try PinnedTestServer { _, _ in Issue.record("redirect followed") }
        let targetPort = try await destination.start()
        defer { destination.stop() }
        let source = try PinnedTestServer { connection, _ in
            respond(connection, "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:\(targetPort)/\r\nContent-Length: 2\r\n\r\n{}")
        }
        let port = try await source.start()
        defer { source.stop() }
        let relay = try RelayClient.foreign("http://127.0.0.1:\(port)", allowLoopbackRelays: true)
        let identity = try makeIdentity()
        await expectCodeAsync(.relayProtocolError) { _ = try await relay.descriptor(identity.getACEId()) }
        #expect(source.requests.value.count == 1)
        #expect(destination.connections.value.isEmpty)
    }
}

private extension Array where Element == UInt8 {
    func chunkedForTest(_ count: Int) -> [[UInt8]] {
        stride(from: 0, to: self.count, by: count).map { Array(self[$0..<Swift.min($0 + count, self.count)]) }
    }
}
