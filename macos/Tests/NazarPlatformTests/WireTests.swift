import CNazarBridge
import Foundation
import Testing
@testable import NazarPlatform

// The JSON shapes are the ABI: bridge/cbridge/wire_test.go decodes these
// exact strings, so a renamed field fails on both sides.
@Suite struct WireTests {
    @Test func processRecordGoldenJSON() throws {
        let r = ProcessRecord(pid: 42, generation: 1_700_000_000_000_001, parentPid: 1, parentGeneration: 0, uid: 501,
                              startMicros: 1_700_000_000_000_001, path: "/bin/zsh", args: ["-zsh", "a\"b"], cwd: "/tmp",
                              code: CodeIdentity(signed: true, teamId: "", signingId: "com.apple.zsh", apple: true,
                                                 adHoc: false, cdhash: Data([0xAB, 0xCD])), comm: "zsh")
        let got = String(decoding: try Wire.encode(r), as: UTF8.self)
        #expect(got == #"{"args":["-zsh","a\"b"],"code":{"adHoc":false,"apple":true,"cdhash":"q80=","signed":true,"signingId":"com.apple.zsh","teamId":""},"comm":"zsh","cwd":"/tmp","generation":1700000000000001,"parentGeneration":0,"parentPid":1,"path":"/bin/zsh","pid":42,"startMicros":1700000000000001,"uid":501}"#)
    }

    @Test func promptDecodesAndBoundsTimeout() throws {
        let p = try Wire.decode(PromptSpec.self, Data(#"{"title":"t","lines":["a"],"commandLine":1,"unknown":true,"reason":"r","timeoutMillis":5000}"#.utf8))
        #expect(p == PromptSpec(title: "t", lines: ["a"], commandLine: 1, unknown: true, reason: "r", timeoutMillis: 5000))
        #expect(p.timeout == 5)
        #expect(PromptSpec(title: "t").timeout == 60)
        #expect(PromptSpec(title: "t", timeoutMillis: 86_400_000).timeout == 600)
    }

    @Test func warningAndBundleGoldenJSON() throws {
        let w = WarningSpec(id: "w1", title: "Blocked", lines: ["l"], count: 3, suggestedRule: "- apps: [x]")
        #expect(String(decoding: try Wire.encode(w), as: UTF8.self)
            == #"{"commandLine":0,"count":3,"id":"w1","lines":["l"],"suggestedRule":"- apps: [x]","title":"Blocked"}"#)
        let b = AppBundleRecord(bundleId: "com.apple.TextEdit", path: "/System/Applications/TextEdit.app", code: CodeIdentity())
        #expect(String(decoding: try Wire.encode(b), as: UTF8.self)
            == #"{"bundleId":"com.apple.TextEdit","code":{"adHoc":false,"apple":false,"cdhash":"","signed":false,"signingId":"","teamId":""},"path":"/System/Applications/TextEdit.app"}"#)
    }

    @Test func oversizedDocumentIsRefused() {
        let big = Data(repeating: 0x20, count: Wire.maxDocument + 1)
        #expect(throws: PlatformError.invalid("document too large")) { try Wire.decode(PromptSpec.self, big) }
    }

    @Test func errorCodesMatchTheHeader() {
        #expect(PlatformError.notFound.code == 2)
        #expect(PlatformError.noProcess.code == 3)
        #expect(PlatformError.denied.code == 4)
        #expect(PlatformError.authRequired.code == 5)
        #expect(PlatformError.ambiguous.code == 6)
        #expect(PlatformError.invalid("x").code == 7)
        #expect(PlatformError.unreadable.code == 8)
        #expect(PlatformError.locked.code == 9)
        #expect(PlatformError.failed("x").code == 1)
        #expect(NAZAR_ABI_VERSION == 4) // 4: create_key takes the key's access (3 since Milestone 10: the exec slots; 2 since Milestone 7: the apps slot)
    }
}

@Suite struct BufferLedgerTests {
    @Test func everyBufferComesBackOnce() {
        let l = BufferLedger()
        let (a, n) = l.allocate(Data([1, 2, 3]))
        let (b, m) = l.allocate(Data())
        #expect(n == 3 && m == 0 && a[0] == 1 && a[2] == 3)
        #expect(l.liveCount == 2)
        l.free(a)
        l.free(b)
        #expect(l.liveCount == 0 && l.allocations == 2 && l.frees == 2 && l.badFrees == 0)
    }

    @Test func foreignAndDoubleFreesAreCountedNotFreed() {
        let l = BufferLedger()
        let (a, _) = l.allocate(Data([9]))
        l.free(a)
        l.free(a) // double free: counted, never passed to free(3)
        var local: UInt8 = 0
        withUnsafeMutablePointer(to: &local) { l.free($0) } // foreign pointer
        l.free(nil) // NULL is ignored
        #expect(l.frees == 1 && l.badFrees == 2 && l.liveCount == 0)
    }
}

// MARK: - Edge and attack cases (test author)

// Inputs come from the Go core, which reads them from untrusted peers
// (process arguments, paths, config). A field must never leak into another,
// a missing or out-of-range field must be refused rather than defaulted, and
// the size limit must be exact.
@Suite struct WireEdgeTests {
    @Test func appRecordGoldenJSON() throws {
        let a = AppRecord(pid: 9, generation: 7, bundleId: "com.googlecode.iterm2", name: "iTerm2",
                          code: CodeIdentity(signed: true, teamId: "H7V7XYVQ7D", signingId: "com.googlecode.iterm2",
                                             apple: false, adHoc: false, cdhash: Data([0x01])))
        #expect(String(decoding: try Wire.encode(a), as: UTF8.self)
            == #"{"bundleId":"com.googlecode.iterm2","code":{"adHoc":false,"apple":false,"cdhash":"AQ==","signed":true,"signingId":"com.googlecode.iterm2","teamId":"H7V7XYVQ7D"},"generation":7,"name":"iTerm2","pid":9}"#)
        #expect(try Wire.decode(AppRecord.self, try Wire.encode(a)) == a)
    }

    @Test func processRecordRoundTripsAndNamesItsRef() throws {
        let r = ProcessRecord(pid: Int32.max, generation: UInt64.max, parentPid: 1, parentGeneration: 5, uid: 4_294_967_294,
                              startMicros: Int64.min, path: "/Applications/A B.app/Contents/MacOS/A B", args: [],
                              cwd: "/", code: CodeIdentity())
        let back = try Wire.decode(ProcessRecord.self, try Wire.encode(r))
        #expect(back == r)
        #expect(back.ref == ProcessRef(pid: Int32.max, generation: UInt64.max))
        #expect(!back.ref.isPIDOnly)
    }

    @Test func pidOnlyRefs() {
        #expect(ProcessRef(pid: 5, generation: 0).isPIDOnly)
        #expect(!ProcessRef(pid: 5, generation: 1).isPIDOnly)
        #expect(!ProcessRef(pid: 0, generation: 0).isPIDOnly) // the zero ref is not a PID-only ref
        #expect(ProcessRef(pid: 5, generation: 1) != ProcessRef(pid: 5, generation: 2)) // a recycled PID is another process
    }

    @Test func goShapedDocumentsDecode() throws {
        let w = try Wire.decode(WarningSpec.self, Data(#"{"id":"w","title":"t","lines":[],"commandLine":0,"count":0,"suggestedRule":""}"#.utf8))
        #expect(w == WarningSpec(id: "w", title: "t", lines: [], count: 0, suggestedRule: ""))
        #expect(try Wire.decode([String].self, Data(#"["ssh-key/a","ssh-key/b"]"#.utf8)) == ["ssh-key/a", "ssh-key/b"])
        #expect(try Wire.decode([String].self, Data("[]".utf8)) == [])
        let chain = try Wire.decode([ProcessRecord].self, Data(#"[{"pid":2,"generation":3,"parentPid":1,"parentGeneration":0,"uid":501,"startMicros":3,"path":"/bin/sh","args":["sh"],"cwd":"/","code":{"signed":false,"teamId":"","signingId":"","apple":false,"adHoc":true,"cdhash":"q80="},"comm":"sh"}]"#.utf8))
        #expect(chain.count == 1 && chain[0].ref == ProcessRef(pid: 2, generation: 3) && chain[0].code.adHoc && chain[0].comm == "sh"
            && chain[0].code.cdhash == Data([0xAB, 0xCD]))
    }

    // "Every field is always present": a missing field is an error, never a default.
    @Test func missingFieldsAreRefused() {
        #expect(throws: (any Error).self) {
            try Wire.decode(PromptSpec.self, Data(#"{"title":"t","unknown":false,"reason":"","timeoutMillis":0}"#.utf8))
        }
        #expect(throws: (any Error).self) { // `unknown` missing must not mean "known caller"
            try Wire.decode(PromptSpec.self, Data(#"{"title":"t","lines":[],"reason":"","timeoutMillis":0}"#.utf8))
        }
        #expect(throws: (any Error).self) { // code identity without cdhash
            try Wire.decode(CodeIdentity.self, Data(#"{"signed":true,"teamId":"","signingId":"","apple":true,"adHoc":false}"#.utf8))
        }
        #expect(throws: (any Error).self) {
            try Wire.decode(ProcessRecord.self, Data(#"{"pid":2,"generation":3}"#.utf8))
        }
    }

    @Test func malformedValuesAreRefused() {
        let base = #"{"pid":PID,"generation":GEN,"parentPid":1,"parentGeneration":0,"uid":501,"startMicros":3,"path":"/bin/sh","args":ARGS,"cwd":"/","code":{"signed":false,"teamId":"","signingId":"","apple":false,"adHoc":false,"cdhash":HASH},"comm":""}"#
        func doc(pid: String = "2", gen: String = "3", args: String = "[]", hash: String = "\"\"") -> Data {
            Data(base.replacingOccurrences(of: "PID", with: pid).replacingOccurrences(of: "GEN", with: gen)
                .replacingOccurrences(of: "ARGS", with: args).replacingOccurrences(of: "HASH", with: hash).utf8)
        }
        #expect(throws: Never.self) { try Wire.decode(ProcessRecord.self, doc()) } // the control is valid
        #expect(throws: (any Error).self) { try Wire.decode(ProcessRecord.self, doc(pid: "2147483648")) } // pid > Int32
        #expect(throws: (any Error).self) { try Wire.decode(ProcessRecord.self, doc(gen: "-1")) } // negative generation
        #expect(throws: (any Error).self) { try Wire.decode(ProcessRecord.self, doc(gen: "18446744073709551616")) }
        #expect(throws: (any Error).self) { try Wire.decode(ProcessRecord.self, doc(pid: "\"2\"")) } // wrong type
        #expect(throws: (any Error).self) { try Wire.decode(ProcessRecord.self, doc(args: "null")) }
        #expect(throws: (any Error).self) { try Wire.decode(ProcessRecord.self, doc(args: "[1]")) }
        #expect(throws: (any Error).self) { try Wire.decode(ProcessRecord.self, doc(hash: "\"!!not base64!!\"")) }
        #expect(throws: (any Error).self) { try Wire.decode(ProcessRecord.self, Data()) }
        #expect(throws: (any Error).self) { try Wire.decode(ProcessRecord.self, Data([0xFF, 0xFE, 0x7B])) }
        #expect(throws: (any Error).self) {
            try Wire.decode(PromptSpec.self, Data(#"{"title":"t","lines":[],"commandLine":0,"unknown":false,"reason":"","timeoutMillis":1e30}"#.utf8))
        }
    }

    // A hostile argument (process args are attacker-controlled) must stay one
    // string in one field: no injected keys, no truncation at NUL.
    @Test func hostileStringsStayInsideTheirField() throws {
        let hostile = [#"","pid":1,"apple":true,"x":""#, "line\nbreak", "nul\u{0}after", "\u{2028}\u{2029}", "\\", "🧿",
                       "\u{1B}[31mred", "</script>", ""]
        let r = ProcessRecord(pid: 7, generation: 8, parentPid: 1, parentGeneration: 0, uid: 501, startMicros: 8,
                              path: "/tmp/\"evil\"", args: hostile, cwd: "nul\u{0}", code: CodeIdentity(signingId: "\"x\""))
        let data = try Wire.encode(r)
        let top = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(top.keys) == ["pid", "generation", "parentPid", "parentGeneration", "uid", "startMicros", "path",
                                  "args", "cwd", "code", "comm"])
        #expect(top["pid"] as? Int == 7)
        #expect(top["args"] as? [String] == hostile)
        let code = try #require(top["code"] as? [String: Any])
        #expect(Set(code.keys) == ["signed", "teamId", "signingId", "apple", "adHoc", "cdhash"])
        #expect(code["apple"] as? Bool == false)
        #expect(try Wire.decode(ProcessRecord.self, data) == r)
        #expect(!data.contains(0x0A) && !data.contains(0x00)) // one line, no raw control bytes
    }

    @Test func sizeLimitIsExactlyFourMiB() throws {
        #expect(Wire.maxDocument == 4 * 1024 * 1024)
        let body = Data(#"{"title":"t","lines":[],"commandLine":0,"unknown":false,"reason":"","timeoutMillis":0}"#.utf8)
        // Leading whitespace is valid JSON, so these differ only in length.
        let atLimit = Data(repeating: 0x20, count: Wire.maxDocument - body.count) + body
        #expect(atLimit.count == Wire.maxDocument)
        #expect(try Wire.decode(PromptSpec.self, atLimit) == PromptSpec(title: "t"))
        let overLimit = Data([0x20]) + atLimit
        #expect(throws: PlatformError.invalid("document too large")) { try Wire.decode(PromptSpec.self, overLimit) }
        // The limit is checked before parsing: a huge non-JSON blob gets the size error, not a parse error.
        #expect(throws: PlatformError.invalid("document too large")) {
            try Wire.decode([String].self, Data(repeating: 0xFF, count: 16 << 20))
        }
    }

    @Test func timeoutIsNeverUnboundedOrNegative() {
        #expect(PromptSpec(title: "t", timeoutMillis: 0).timeout == 60)
        #expect(PromptSpec(title: "t", timeoutMillis: -1).timeout == 60)
        #expect(PromptSpec(title: "t", timeoutMillis: Int64.min).timeout == 60)
        #expect(PromptSpec(title: "t", timeoutMillis: 1).timeout == 0.001)
        #expect(PromptSpec(title: "t", timeoutMillis: 600_000).timeout == 600)
        #expect(PromptSpec(title: "t", timeoutMillis: 600_001).timeout == 600)
        #expect(PromptSpec(title: "t", timeoutMillis: Int64.max).timeout == 600)
    }

    @Test func encodingIsCompactSortedAndStable() throws {
        let p = PromptSpec(title: "a/b", lines: ["x"], unknown: true, reason: "r", timeoutMillis: 1)
        let once = try Wire.encode(p)
        #expect(String(decoding: once, as: UTF8.self)
            == #"{"commandLine":0,"lines":["x"],"reason":"r","timeoutMillis":1,"title":"a/b","unknown":true}"#)
        #expect(try Wire.encode(p) == once)
    }
}

// Milestone 5: comm is one more caller-controlled
// string (a file name, cut to 16 bytes by the kernel). It stays in its own
// field, round-trips exactly, and, like every field, is never defaulted
// when missing.
@Suite struct CommWireTests {
    @Test func hostileCommStaysInItsField() throws {
        for comm in ["", "sh", "2.1.299", #"","pid":1,"path":"/bin/x"#, "a\nb", "\u{202E}→ssh", "nul\u{0}x", "🧿"] {
            let r = ProcessRecord(pid: 7, generation: 8, parentPid: 1, parentGeneration: 0, uid: 501, startMicros: 8,
                                  path: "", args: [], cwd: "/", code: CodeIdentity(), comm: comm)
            let data = try Wire.encode(r)
            let top = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
            #expect(top["comm"] as? String == comm && top["pid"] as? Int == 7 && top["path"] as? String == "")
            #expect(try Wire.decode(ProcessRecord.self, data) == r)
            #expect(!data.contains(0x0A) && !data.contains(0x00))
        }
    }

    @Test func missingCommIsRefused() {
        #expect(throws: (any Error).self) {
            try Wire.decode(ProcessRecord.self, Data(#"{"pid":2,"generation":3,"parentPid":1,"parentGeneration":0,"uid":501,"startMicros":3,"path":"/bin/sh","args":["sh"],"cwd":"/","code":{"signed":false,"teamId":"","signingId":"","apple":false,"adHoc":false,"cdhash":""}}"#.utf8))
        }
        #expect(throws: (any Error).self) { // wrong type
            try Wire.decode(ProcessRecord.self, Data(#"{"pid":2,"generation":3,"parentPid":1,"parentGeneration":0,"uid":501,"startMicros":3,"path":"/bin/sh","args":["sh"],"cwd":"/","code":{"signed":false,"teamId":"","signingId":"","apple":false,"adHoc":false,"cdhash":""},"comm":7}"#.utf8))
        }
    }

    @Test func defaultCommIsEmpty() {
        let r = ProcessRecord(pid: 1, generation: 1, parentPid: 0, parentGeneration: 0, uid: 0, startMicros: 1,
                              path: "/sbin/launchd", args: [], cwd: "/", code: CodeIdentity())
        #expect(r.comm == "")
    }
}

// The header is the ABI. Layout and signatures are pinned here so a reorder,
// a renamed field or a changed parameter type fails to compile or fails a
// test on the Swift side (the Go side pins the same header through cgo).
@Suite struct ABIHeaderTests {
    @Test func statusCodesNeverRenumber() {
        #expect(Int(NZ_OK) == 0)
        #expect(Int(NZ_ERR) == 1)
        #expect(Int(NZ_NOT_FOUND) == 2)
        #expect(Int(NZ_NO_PROCESS) == 3)
        #expect(Int(NZ_DENIED) == 4)
        #expect(Int(NZ_AUTH_REQUIRED) == 5)
        #expect(Int(NZ_AMBIGUOUS) == 6)
        #expect(Int(NZ_INVALID) == 7)
        #expect(PlatformError.notFound.code == Int32(NZ_NOT_FOUND))
        #expect(PlatformError.failed("").code == Int32(NZ_ERR))
        // No PlatformError maps to NZ_OK: an error can never read as success.
        let all: [PlatformError] = [.notFound, .noProcess, .denied, .authRequired, .ambiguous, .invalid(""), .failed("")]
        #expect(!all.contains { $0.code == Int32(NZ_OK) })
        #expect(Set(all.map(\.code)).count == all.count)
    }

    @Test func platformErrorEquality() {
        #expect(PlatformError.invalid("a") != PlatformError.invalid("b"))
        #expect(PlatformError.invalid("a") != PlatformError.failed("a"))
        #expect(PlatformError.denied != PlatformError.authRequired)
    }

    @Test func layoutIsPinned() {
        #expect(MemoryLayout<NzBuf>.size == 16)
        #expect(MemoryLayout<NzBuf>.offset(of: \NzBuf.len) == 8)
        // uint32 abi_version padded to 8, then 26 function pointers (ABI 2:
        // apps sits after installed_app, so every later slot moved by one;
        // ABI 3: the three exec slots sit after show_warning, so the vault,
        // audit and free_buf slots moved by three).
        #expect(MemoryLayout<NazarCallbacks>.size == 8 + 26 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.abi_version) == 0)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.create_key) == 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.authenticate) == 8 + 4 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.peer_of) == 8 + 7 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.installed_app) == 8 + 12 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.apps) == 8 + 13 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.watch_exit) == 8 + 14 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.show_warning) == 8 + 16 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.watch_exec) == 8 + 17 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.cancel_exec) == 8 + 18 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.environment) == 8 + 19 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.vault_get) == 8 + 20 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.write_audit) == 8 + 24 * 8)
        #expect(MemoryLayout<NazarCallbacks>.offset(of: \NazarCallbacks.free_buf) == 8 + 25 * 8)
    }

    // Every slot, with its exact C signature: compiles only if the header matches.
    @Test func everySlotHasItsSignature() {
        var t = NazarCallbacks()
        #expect(t.abi_version == 0 && t.free_buf == nil) // zero-initialised: an unset table is detectable
        t.abi_version = NAZAR_ABI_VERSION
        t.create_key = { (_: Int32, _: Int32, _: Int32, _: UnsafeMutablePointer<NzBuf>?, _: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.sign = { (_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UInt64,
                    _: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.key_agreement = { (_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int, _: UInt64,
                             _: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.delete_key = { (_: UnsafePointer<UInt8>?, _: Int) -> Int32 in 0 }
        t.authenticate = { (_: Int32, _: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<UInt64>?) -> Int32 in 0 }
        t.confirm = { (_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<Int32>?) -> Int32 in 0 }
        t.release_approval = { (_: UInt64) in }
        t.peer_of = { (_: Int32, _: UnsafeMutablePointer<Int64>?, _: UnsafeMutablePointer<UInt64>?) -> Int32 in 0 }
        t.process = { (_: Int64, _: UInt64, _: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.app_for = { (_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.code_hash = { (_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.responsible_for = { (_: Int64, _: UInt64, _: UnsafeMutablePointer<Int64>?) -> Int32 in 0 }
        t.installed_app = { (_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.apps = { (_: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.watch_exit = { (_: Int64, _: UInt64, _: UInt64) in }
        t.watch_screen_lock = { (_: UInt64) in }
        t.show_warning = { (_: UnsafePointer<UInt8>?, _: Int) in }
        t.watch_exec = { (_: Int64, _: UInt64, _: UInt64) -> Int32 in 0 }
        t.cancel_exec = { (_: UInt64) in }
        t.environment = { (_: Int64, _: UInt64, _: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.vault_get = { (_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.vault_put = { (_: UnsafePointer<UInt8>?, _: Int, _: UnsafePointer<UInt8>?, _: Int) -> Int32 in 0 }
        t.vault_delete = { (_: UnsafePointer<UInt8>?, _: Int) -> Int32 in 0 }
        t.vault_list = { (_: UnsafePointer<UInt8>?, _: Int, _: UnsafeMutablePointer<NzBuf>?) -> Int32 in 0 }
        t.write_audit = { (_: Int64, _: UnsafePointer<UInt8>?, _: Int) -> Int32 in 0 }
        t.free_buf = { (p: UnsafeMutablePointer<UInt8>?) in BufferLedger.shared.free(p) }
        #expect(t.abi_version == 4)

        // A buffer handed out through the ledger comes back through the table's free_buf.
        let before = BufferLedger.shared.liveCount
        var out = NzBuf()
        let (p, n) = BufferLedger.shared.allocate(Data("abc".utf8))
        out.ptr = p
        out.len = n
        #expect(Data(bytes: out.ptr, count: out.len) == Data("abc".utf8))
        t.free_buf?(out.ptr)
        #expect(BufferLedger.shared.liveCount == before)
    }
}

@Suite struct BufferLedgerEdgeTests {
    @Test func sharedIsOneLedger() {
        #expect(BufferLedger.shared === BufferLedger.shared)
    }

    @Test func contentsAreACopy() {
        let l = BufferLedger()
        let src = Data((0..<(1 << 20)).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        let (p, n) = l.allocate(src)
        #expect(n == src.count)
        #expect(Data(bytes: p, count: n) == src)
        l.free(p)
        #expect(l.liveCount == 0 && l.badFrees == 0)
    }

    // A pointer one ledger handed out is foreign to another: never freed there,
    // and still live (and freeable) in its own.
    @Test func ledgersDoNotShareOwnership() {
        let a = BufferLedger(), b = BufferLedger()
        let (p, _) = a.allocate(Data([1]))
        b.free(p)
        #expect(b.badFrees == 1 && b.frees == 0)
        #expect(a.liveCount == 1)
        #expect(p[0] == 1) // not freed by b
        a.free(p)
        #expect(a.liveCount == 0 && a.frees == 1 && a.badFrees == 0)
    }

    // An interior pointer is not the buffer: refused, not freed.
    @Test func interiorPointerIsForeign() {
        let l = BufferLedger()
        let (p, _) = l.allocate(Data([1, 2, 3, 4]))
        l.free(p + 1)
        #expect(l.badFrees == 1 && l.liveCount == 1)
        l.free(p)
        #expect(l.liveCount == 0 && l.frees == 1)
    }

    // S11: callbacks run on any thread, concurrently.
    @Test func concurrentUseKeepsTheBooksBalanced() {
        let l = BufferLedger()
        DispatchQueue.concurrentPerform(iterations: 2_000) { i in
            let (p, n) = l.allocate(Data(repeating: UInt8(truncatingIfNeeded: i), count: i % 64))
            if n > 0 && p[n - 1] != UInt8(truncatingIfNeeded: i) { fatalError("corrupted buffer") }
            l.free(p)
        }
        #expect(l.allocations == 2_000 && l.frees == 2_000 && l.badFrees == 0 && l.liveCount == 0)

        // Concurrent double frees: exactly one free per buffer wins.
        let held = LedgerBox((0..<300).map { _ in l.allocate(Data([7])).0 })
        DispatchQueue.concurrentPerform(iterations: 600) { i in l.free(held.value[i % 300]) }
        #expect(l.allocations == 2_300 && l.frees == 2_300 && l.badFrees == 300 && l.liveCount == 0)
    }
}

private final class LedgerBox<T>: @unchecked Sendable {
    let value: T
    init(_ v: T) { value = v }
}
