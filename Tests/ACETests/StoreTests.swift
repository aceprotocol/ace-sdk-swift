import Foundation
import Testing
import Darwin
@testable import ACE

func tempDirectory() -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("ace-store-\(UUID().uuidString)")
    return url
}

@Suite("Stores")
struct StoreTests {
    @Test func keyGrammar() {
        for good in ["replay.json", "threads/abc.json", "a", "a/b/c-d_e.f", String(repeating: "a", count: 200)] {
            #expect(isValidStoreKey(good), "\(good)")
        }
        for bad in ["", "/a", "a/", "a//b", ".tmp", "A", "a/.b", "a b", "../x", String(repeating: "a", count: 201)] {
            #expect(!isValidStoreKey(bad), "\(bad)")
        }
    }

    private func exercise(_ store: any ACEStore) throws {
        #expect(try store.read("x.json") == nil)
        try store.write("x.json", Data("1".utf8))
        try store.write("dir/b.json", Data("2".utf8))
        try store.write("dir/a.json", Data("3".utf8))
        try store.write("dir/a.json", Data("4".utf8))
        #expect(try store.read("dir/a.json") == Data("4".utf8))
        #expect(try store.list(prefix: "dir/") == ["dir/a.json", "dir/b.json"])
        #expect(try store.list(prefix: "") == ["dir/a.json", "dir/b.json", "x.json"])
        try store.delete("dir/a.json")
        try store.delete("dir/a.json")
        #expect(try store.list(prefix: "dir/") == ["dir/b.json"])
        expectCode(.invalidArgument) { try store.write("Bad", Data()) }

        let held = try store.lock("receive", timeout: 0)
        expectCode(.lockBusy) { try store.lock("receive", timeout: 0) }
        expectCode(.lockBusy) {
            let other = try store.lock("threads", timeout: 1)
            defer { other.release() }
            return try store.lock("threads", timeout: 0.1)
        }
        held.release()
        held.release()
        try store.lock("receive", timeout: 0).release()

        // Lock names have their own grammar (no '/', no '.', at most 64 characters).
        for bad in ["", "a/b", "a.b", "A", "-a", String(repeating: "a", count: 65)] {
            expectCode(.invalidArgument) { try store.lock(bad, timeout: 0) }
        }
        try store.lock("a_b-" + String(repeating: "c", count: 60), timeout: 0).release()

        // Nothing is written that could not be read back.
        expectCode(.invalidArgument) { try store.write("big.json", Data(count: ACELimits.maxStoreValueBytes + 1)) }
        #expect(try store.read("big.json") == nil)
    }

    @Test func memoryStore() throws { try exercise(MemoryStore()) }

    @Test func fileStore() throws {
        let dir = tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try FileStore(directory: dir)
        try exercise(store)
        // Permissions and layout.
        var st = stat()
        #expect(stat(dir.appendingPathComponent("x.json").path, &st) == 0 && st.st_mode & 0o777 == 0o600)
        #expect(stat(dir.appendingPathComponent("dir").path, &st) == 0 && st.st_mode & 0o777 == 0o700)
        // Locks live under locks/ and are not listed.
        let l = try store.lock("peers", timeout: 1)
        #expect(try !store.list(prefix: "").contains { $0.hasPrefix("locks") })
        l.release()
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("locks/peers.lock").path))
    }

    @Test func fileStoreRefusesSymlinksAndUsesKernelLocks() throws {
        let dir = tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try FileStore(directory: dir)
        try store.write("real.json", Data("x".utf8))
        symlink(dir.appendingPathComponent("real.json").path, dir.appendingPathComponent("link.json").path)
        expectCode(.storageFailed) { try store.read("link.json") }

        try store.lock("receive", timeout: 0).release()
        let path = dir.appendingPathComponent("locks/receive.lock").path
        let fd = open(path, O_RDWR)
        defer { close(fd) }
        #expect(flock(fd, LOCK_EX | LOCK_NB) == 0)
        expectCode(.lockBusy) { try store.lock("receive", timeout: 0) }
        #expect(flock(fd, LOCK_UN) == 0)
        try store.lock("receive", timeout: 0).release()
        expectCode(.invalidArgument) { try store.write("locks/receive.lock", Data()) }
        expectCode(.invalidArgument) { try store.delete("locks/receive.lock") }
    }

    @Test func fileStoreSerializesInProcessAcrossInstances() throws {
        let dir = tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let a = try FileStore(directory: dir), b = try FileStore(directory: dir)
        let l = try a.lock("receive", timeout: 0)
        expectCode(.lockBusy) { try b.lock("receive", timeout: 0) }
        l.release()
        try b.lock("receive", timeout: 0).release()
    }
}


func makePeerTestStore(_ kind: String) throws -> any ACEStore {
    kind == "memory" ? MemoryStore() : try FileStore(directory: tempDirectory())
}
