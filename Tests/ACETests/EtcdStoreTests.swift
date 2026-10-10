import Foundation
import Testing
@testable import ACE

@Suite("Replicated authority configuration")
struct EtcdStoreConfigurationTests {
    @Test func strictConfiguration() throws {
        for endpoint in ["http://example.com", "https://user:secret@example.com", "https://example.com/path", "https://example.com/?token=secret", "https://example.com/#fragment"] {
            expectCode(.invalidArgument) { try EtcdStore(configuration: .init(endpoint: endpoint, namespace: "state", clusterId: "1")) }
        }
        for id in ["", "0", "01", "auto", "-1", "18446744073709551616", "1\n"] {
            expectCode(.invalidArgument) { try EtcdStore(configuration: .init(endpoint: "https://example.com", namespace: "state", clusterId: id)) }
        }
        expectCode(.invalidArgument) { try EtcdStore(configuration: .init(endpoint: "https://example.com", namespace: "../other", clusterId: "1")) }
        expectCode(.invalidArgument) { try EtcdStore(configuration: .init(endpoint: "https://example.com", namespace: "state", clusterId: "1", token: "secret\nheader")) }
    }
}

// sdk-ts/tests/etcd-store.integration.test.ts owns the real three-node cluster and runs this suite
// with ACE_SWIFT_INTEROP=1. No payment, signing service, or deployed environment is contacted.
@Suite("Live TS / Swift replicated authority", .enabled(if: ProcessInfo.processInfo.environment["ACE_ETCD_ENDPOINT"] != nil))
struct EtcdStoreIntegrationTests {
    private func store(_ suffix: String = "", pin: String? = nil, lease: Int = 60) throws -> EtcdStore {
        let env = ProcessInfo.processInfo.environment
        return try EtcdStore(configuration: .init(endpoint: try #require(env["ACE_ETCD_ENDPOINT"]),
            namespace: try #require(env["ACE_ETCD_NAMESPACE"]) + suffix,
            clusterId: try #require(pin ?? env["ACE_ETCD_CLUSTER_ID"]), timeout: 2, leaseSeconds: lease))
    }
    @Test func releaseTypeScriptReservation() throws {
        let s = try store()
        let request = try s.coordinate("bridge") { data in
            #expect(try data.read("empty") == Data())
            #expect(try data.list(prefix: "items/").count == 1030)
            let raw = try #require(try data.read("request"))
            let value = try JSONValue(json: raw)
            return try ExecutionRequest(body: #require(value.objectValue))
        }
        let i = request.intent
        let a = try ExecutionAuthority(configuration: .init(resource: i["resource"]!.stringValue!, authority: peerOf(Fixtures.agent("alice")),
            executor: Fixtures.agent("bob").getACEId(), schemaDigest: i["schemaDigest"]!.stringValue!, actions: [i["action"]!.stringValue!], clock: { 150 }) { i in
                ["asset:token": i["details"]!["amount"]!.stringValue!]
            }, store: s)
        #expect(try a.inspect().remaining == ["asset:token": "4"])
        #expect(try a.reserve(chain: request.grants, intent: i, authenticatedSender: Fixtures.agent("bob").getACEId()) == .existing)
        try a.release(chain: request.grants, intent: i, authenticatedSender: Fixtures.agent("bob").getACEId())
        expectCode(.invalidAuthorization) { try a.release(chain: request.grants, intent: i, authenticatedSender: Fixtures.agent("bob").getACEId()) }
        try s.coordinate("bridge") { try $0.write("swift", Data("released".utf8)) }
    }
    @Test func expiredLeaseAndEscapedHandleFailClosed() throws {
        let s = try store("-expire", lease: 1)
        expectCode(.storageFailed) {
            try s.coordinate("state") { data in
                try data.write("value", Data("original".utf8))
                Thread.sleep(forTimeInterval: 3)
                try data.write("value", Data("stale".utf8))
            }
        }
        expectCode(.storageFailed) { try s.coordinate("state") { _ in } }
        var escaped: (any ACEStoreData)?
        try store("-expire").coordinate("state") { data throws -> Void in
            escaped = data
            #expect(try data.read("value") == Data("original".utf8))
        }
        expectCode(.storageFailed) { try escaped!.write("value", Data()) }
    }
    @Test func wrongClusterNeverRunsCallback() throws {
        let s = try store("-pin", pin: "1")
        var ran = false
        expectCode(.storageFailed) { try s.coordinate("state") { _ in ran = true } }
        #expect(!ran)
    }
}
