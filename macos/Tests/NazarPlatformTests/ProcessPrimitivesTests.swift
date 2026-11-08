import Foundation
import Testing
@testable import NazarPlatform

/// Starts /bin/sleep and kills it at the end of the test.
final class Sleeper {
    let process = Process()
    init(_ seconds: Int = 60) throws {
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = [String(seconds)]
        try process.run()
    }
    var pid: Int32 { process.processIdentifier }
    func kill() {
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
    }
    deinit { kill() }
}

func procargs(argc: Int32, _ parts: [String], trailingNUL: Bool = true) -> [UInt8] {
    var b = withUnsafeBytes(of: argc.littleEndian) { Array($0) }
    for (i, p) in parts.enumerated() {
        b += Array(p.utf8)
        if trailingNUL || i < parts.count - 1 { b.append(0) }
    }
    return b
}

@Suite struct ProcArgsTests {
    @Test func wellFormed() throws {
        var buf = procargs(argc: 3, ["/usr/bin/git"])
        buf += [0, 0, 0] // padding
        buf += procargs(argc: 0, ["git", "push", "origin main", "HOME=/x"]).dropFirst(4)
        let (exe, args) = try #require(ProcArgs.parse(buf))
        #expect(exe == "/usr/bin/git" && args == ["git", "push", "origin main"])
    }

    @Test func hostileBuffers() {
        #expect(ProcArgs.parse([]) == nil)
        #expect(ProcArgs.parse([1, 0, 0]) == nil)
        #expect(ProcArgs.parse(procargs(argc: 0, ["/bin/x", "a"]))?.args == [])
        #expect(ProcArgs.parse(procargs(argc: -5, ["/bin/x", "a"]))?.args == [])
        // argc larger than the strings present: stops at the end of the buffer
        #expect(ProcArgs.parse(procargs(argc: 99, ["/bin/x", "a", "b"]))?.args == ["a", "b"])
        // no terminator on the last string
        #expect(ProcArgs.parse(procargs(argc: 2, ["/bin/x", "a", "bc"], trailingNUL: false))?.args == ["a", "bc"])
        // huge argc is clamped
        let many = procargs(argc: Int32.max, ["/bin/x"] + Array(repeating: "y", count: 5000))
        #expect(ProcArgs.parse(many)?.args.count == ProcArgs.maxArgs)
        // invalid UTF-8 is replaced, never dropped or crashed on
        var bad = procargs(argc: 1, ["/bin/x"])
        bad += [0xff, 0xfe, 0x41, 0]
        #expect(ProcArgs.parse(bad)?.args == ["\u{FFFD}\u{FFFD}A"])
        // an over-long argument is cut
        let long = procargs(argc: 1, ["/bin/x", String(repeating: "z", count: 40_000)])
        #expect(ProcArgs.parse(long)?.args.first?.count == ProcArgs.maxArgBytes)
        // only the header: no exec path at all
        #expect(ProcArgs.parse(procargs(argc: 1, []))?.args == [])
    }
}

@Suite struct KernelProcTests {
    @Test func ownRecord() throws {
        let me = try #require(KernelProc.info(getpid()))
        #expect(me.pid == getpid() && me.ppid == getppid() && me.uid == getuid() && !me.zombie)
        let now = Int64(Date().timeIntervalSince1970 * 1_000_000)
        #expect(me.startMicros > 0 && me.startMicros <= now)
        #expect(KernelProc.info(getpid()) == me) // stable
        #expect(KernelProc.args(getpid()) == CommandLine.arguments)
        let exe = try #require(Bundle.main.executableURL).resolvingSymlinksInPath().path
        #expect(KernelProc.path(getpid()) == exe)
        #expect(URL(fileURLWithPath: KernelProc.cwd(getpid())).resolvingSymlinksInPath()
            == URL(fileURLWithPath: FileManager.default.currentDirectoryPath).resolvingSymlinksInPath())
    }

    @Test func absentAndNonPositivePIDs() {
        for pid: Int32 in [0, -1, .min, .max, .max - 1] { #expect(KernelProc.info(pid) == nil) }
    }

    @Test func childLifecycle() throws {
        let s = try Sleeper()
        let rec = try #require(KernelProc.info(s.pid))
        #expect(rec.ppid == getpid() && KernelProc.args(s.pid) == ["/bin/sleep", "60"])
        #expect(rec.comm == "sleep")
        s.kill()
        #expect(KernelProc.info(s.pid).map { $0.startMicros != rec.startMicros || $0.zombie } ?? true)
    }
}

@Suite struct CodeSigningTests {
    @Test func appleBinaryIdentity() throws {
        let s = try Sleeper()
        defer { s.kill() }
        let code = try #require(CodeSigning.guest(pid: s.pid))
        let id = CodeSigning.identity(of: code)
        #expect(id.signed && id.apple && !id.adHoc && id.teamId.isEmpty && id.signingId == "com.apple.sleep")
        #expect(id.cdhash.count == 20)
    }

    // Not compared with `codesign -d /bin/ls` (the file's default slice):
    // Platform.CodeHash pins `path:` matchers, and core/match compares that pin
    // with the RUNNING process's cdhash (match.go). On macOS 27 Apple's
    // universal binaries carry x86_64, arm64e and arm64e.x1 slices; on an M2
    // the kernel runs arm64e while Security.framework's (and codesign's) static
    // default is arm64e.x1, so the file's default-slice cdhash never equals the
    // running one. The reference here is codesign's reading of the kernel's
    // cdhash for a live /bin/sleep: the slice the kernel executes.
    @Test func cdhashMatchesCodesign() throws {
        let s = try Sleeper()
        defer { s.kill() }
        let h = try CodeSigning.cdhash(path: "/bin/sleep")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        p.arguments = ["-d", "-vvv", String(s.pid)]
        let pipe = Pipe()
        p.standardError = pipe
        p.standardOutput = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let line = try #require(out.split(separator: "\n").first { $0.hasPrefix("CDHash=") })
        #expect(h.map { String(format: "%02x", $0) }.joined() == line.dropFirst("CDHash=".count).lowercased())
        let running = try #require(CodeSigning.guest(pid: s.pid))
        #expect(CodeSigning.identity(of: running).cdhash == h)
    }

    @Test func missingUnsignedAndAdHoc() throws {
        #expect(throws: PlatformError.notFound) { try CodeSigning.cdhash(path: "/nonexistent/nazar-\(UUID())") }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("nzcs-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let text = dir.appendingPathComponent("notes.txt")
        try Data("hello".utf8).write(to: text)
        #expect(throws: PlatformError.self) { try CodeSigning.cdhash(path: text.path) }
        // An ad-hoc signed copy of an Apple tool: signed, but no team and not Apple.
        let tool = dir.appendingPathComponent("true")
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: tool.path)
        let cs = Process()
        cs.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        cs.arguments = ["--force", "--sign", "-", "--identifier", "dev.nazar.test.true", tool.path]
        cs.standardError = FileHandle.nullDevice
        try cs.run()
        cs.waitUntilExit()
        let id = try #require(CodeSigning.staticIdentity(path: tool.path))
        #expect(id.signed && id.adHoc && !id.apple && id.teamId.isEmpty && id.signingId == "dev.nazar.test.true")
        #expect(try CodeSigning.cdhash(path: tool.path) == id.cdhash)
    }
}

// MARK: - Additional edge and attack cases

/// Runs /usr/bin/codesign ad hoc (never a real identity) and requires success.
func adHocSign(_ path: String, identifier: String) throws {
    let cs = Process()
    cs.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    cs.arguments = ["--force", "--sign", "-", "--identifier", identifier, path]
    cs.standardError = FileHandle.nullDevice
    cs.standardOutput = FileHandle.nullDevice
    try cs.run()
    cs.waitUntilExit()
    #expect(cs.terminationStatus == 0)
}

/// A fresh temporary folder, removed by the caller.
func tempDir(_ prefix: String) throws -> URL {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("\(prefix)-\(UUID())")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

/// `codesign -dvv path`: the values after `Key=` in its (stderr) report,
/// the independent reading the signature tests compare with.
func codesignReport(_ path: String) throws -> [String: String] {
    let cs = Process()
    cs.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    cs.arguments = ["-dvv", path]
    let err = Pipe()
    cs.standardError = err
    cs.standardOutput = FileHandle.nullDevice
    try cs.run()
    let text = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    cs.waitUntilExit()
    var out: [String: String] = [:]
    for line in text.split(separator: "\n") {
        guard let eq = line.firstIndex(of: "=") else { continue }
        let key = String(line[..<eq])
        let value = String(line[line.index(after: eq)...])
        if key == "Authority" { out[key, default: ""] += value + "\n" } else { out[key] = value }
    }
    return out
}

/// The Go toolchain's gofmt: Developer ID code (not Apple's, not ad hoc)
/// that every machine building nazar has. Go is a required toolchain, so a
/// missing gofmt fails the test instead of skipping it.
func goToolchainGofmt() throws -> String {
    var root = ProcessInfo.processInfo.environment["GOROOT"] ?? ""
    if root.isEmpty {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["go", "env", "GOROOT"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            root = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            p.waitUntilExit()
        } catch {}
    }
    let gofmt = root + "/bin/gofmt"
    try #require(!root.isEmpty && FileManager.default.isExecutableFile(atPath: gofmt),
                 "gofmt not found (GOROOT=\"\(root)\"): the Go toolchain is required; this test needs its Developer ID signed binary")
    return gofmt
}

/// PROC_PIDTBSDINFO's start time in microseconds: an independent reading
/// of the generation, for processes owned by this user (root-owned ones
/// are EPERM here, which is why KernelProc uses KERN_PROC_PID).
func bsdStartMicros(_ pid: Int32) throws -> Int64 {
    var bi = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    try #require(proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, size) == size)
    return Int64(bi.pbi_start_tvsec) * 1_000_000 + Int64(bi.pbi_start_tvusec)
}

/// This process's own audit token (TASK_AUDIT_TOKEN).
func ownAuditToken() -> audit_token_t? {
    var token = audit_token_t()
    var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
    let kr = withUnsafeMutablePointer(to: &token) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
        }
    }
    return kr == KERN_SUCCESS ? token : nil
}

@Suite struct ProcArgsEdgeTests {
    @Test func execPathAndEnvironmentNeverLeak() throws {
        let (exe, args) = try #require(ProcArgs.parse(procargs(argc: 1, ["/bin/x", "a", "AWS_SECRET=hunter2"])))
        #expect(exe == "/bin/x" && args == ["a"])
        // argc 0: nothing after the exec path is an argument, environment included
        let r = try #require(ProcArgs.parse(procargs(argc: 0, ["/bin/x", "TOKEN=1"])))
        #expect(r.execPath == "/bin/x" && r.args.isEmpty)
    }

    @Test func headerOnlyIsNotNil() throws {
        // nil only when the header itself is cut off
        let r = try #require(ProcArgs.parse([3, 0, 0, 0]))
        #expect(r.execPath.isEmpty && r.args.isEmpty)
        #expect(ProcArgs.parse([0xff, 0xff, 0xff]) == nil)
        // little-endian argc
        #expect(ProcArgs.parse([2, 0, 0, 0] + Array("/x\0a\0b\0c\0".utf8))?.args == ["a", "b"])
    }

    @Test func paddingOnlyAndEmptyArguments() throws {
        // NUL padding after the exec path with nothing behind it: no arguments
        // ("/bin/x" and its NUL are 7 bytes; the kernel pads to 8)
        let pad = procargs(argc: 2, ["/bin/x"]) + [0]
        #expect(ProcArgs.parse(pad)?.args == [])
        // NULs past that padding are empty arguments, never more padding
        let empties = procargs(argc: 2, ["/bin/x"]) + [UInt8](repeating: 0, count: 100)
        #expect(ProcArgs.parse(empties)?.args == ["", ""])
        // an empty argument after argv[0] is kept as ""
        #expect(ProcArgs.parse(procargs(argc: 4, ["/bin/x", "x", "a", "", "b"]))?.args == ["x", "a", "", "b"])
    }

    @Test func exactLimitsAreKept() throws {
        let exact = String(repeating: "q", count: ProcArgs.maxArgBytes)
        #expect(ProcArgs.parse(procargs(argc: 1, ["/bin/x", exact]))?.args == [exact])
        let parts = (0..<(ProcArgs.maxArgs + 10)).map { "a\($0)" }
        let r = try #require(ProcArgs.parse(procargs(argc: Int32(ProcArgs.maxArgs), ["/bin/x"] + parts)))
        #expect(r.args == Array(parts.prefix(ProcArgs.maxArgs)))
    }

    @Test func cutArgumentNeverSmugglesItsTailAsAnotherArgument() throws {
        // The bytes past maxArgBytes must be skipped up to the real terminator,
        // never read as the next argument.
        let tail = "--upload-pack=evil"
        let long = String(repeating: "z", count: ProcArgs.maxArgBytes) + tail
        let r = try #require(ProcArgs.parse(procargs(argc: 2, ["/bin/x", long, "next", "ENV=1"])))
        #expect(r.args.count == 2)
        #expect(r.args.first == String(repeating: "z", count: ProcArgs.maxArgBytes))
        #expect(r.args.last == "next")
        #expect(!r.args.contains { $0.contains(tail) })
    }

    @Test func longExecPathIsCutAndArgumentsStillFollow() throws {
        let path = "/" + String(repeating: "p", count: ProcArgs.maxArgBytes + 500)
        let r = try #require(ProcArgs.parse(procargs(argc: 2, [path, "a", "b"])))
        #expect(r.execPath.utf8.count == ProcArgs.maxArgBytes)
        #expect(r.args == ["a", "b"])
    }

    @Test func multiByteCutDecodesSafely() throws {
        let s = String(repeating: "é", count: ProcArgs.maxArgBytes) // 2 bytes each
        let r = try #require(ProcArgs.parse(procargs(argc: 2, ["/bin/x", s, "after"])))
        #expect(r.args.count == 2 && r.args.last == "after")
        let first = try #require(r.args.first)
        #expect(first.unicodeScalars.allSatisfy { $0 == "é" || $0 == "\u{FFFD}" })
        #expect(first.unicodeScalars.filter { $0 == "é" }.count >= ProcArgs.maxArgBytes / 2 - 1)
    }

    @Test func megabyteUnterminatedBuffer() throws {
        // A process can fill its whole argument area without one NUL.
        let buf = withUnsafeBytes(of: Int32(1).littleEndian) { Array($0) } + [UInt8](repeating: 0x41, count: 4 << 20)
        let r = try #require(ProcArgs.parse(buf))
        #expect(r.execPath.utf8.count == ProcArgs.maxArgBytes && r.args.isEmpty)
        // and a megabyte of tiny arguments under a huge argc stays bounded
        var many = withUnsafeBytes(of: Int32.max.littleEndian) { Array($0) } + Array("/bin/x\0".utf8)
        many += ([0x62, 0] as [UInt8]).repeated(1 << 19)
        let m = try #require(ProcArgs.parse(many))
        #expect(m.args.count == ProcArgs.maxArgs && m.args.allSatisfy { $0 == "b" })
    }

    @Test func controlCharactersAndNewlinesArePreservedVerbatim() throws {
        // The parser does not sanitize: display code must escape. It must keep
        // the bytes so a matcher compares exactly what the process claims.
        let r = try #require(ProcArgs.parse(procargs(argc: 2, ["/bin/x", "a\nb\u{1b}[2J", "\t"])))
        #expect(r.args == ["a\nb\u{1b}[2J", "\t"])
    }
}

extension Array {
    fileprivate func repeated(_ n: Int) -> [Element] {
        var out: [Element] = []
        out.reserveCapacity(count * n)
        for _ in 0..<n { out += self }
        return out
    }
}

@Suite struct KernelProcEdgeTests {
    @Test func generationIsStartMicros() throws {
        let me = try #require(KernelProc.info(getpid()))
        #expect(me.generation == UInt64(me.startMicros) && me.generation > 0)
    }

    @Test func absentPIDsReadAsEmpty() {
        for pid: Int32 in [-1, .min, .max, .max - 1] {
            #expect(KernelProc.path(pid) == "")
            #expect(KernelProc.cwd(pid) == "")
            #expect(KernelProc.args(pid) == [])
        }
    }

    @Test func rootOwnedLaunchdIsReadableButPrivateFieldsAreEmpty() throws {
        // S3: KERN_PROC_PID gets past root-owned processes (where
        // PROC_PIDTBSDINFO is EPERM); launchd is the end of every walk.
        let l = try #require(KernelProc.info(1))
        #expect(l.pid == 1 && l.ppid == 0 && l.uid == 0 && !l.zombie && l.startMicros > 0)
        let mine = try #require(KernelProc.info(getpid()))
        #expect(l.startMicros <= mine.startMicros)
        // another user's arguments and folder are not readable: empty, no crash
        #expect(KernelProc.args(1) == [])
        #expect(KernelProc.cwd(1) == "")
    }

    @Test func childArgumentsCwdAndEnvironment() throws {
        let dir = try tempDir("nzkp")
        defer { try? FileManager.default.removeItem(at: dir) }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/zsh")
        p.arguments = ["-f", "-c", "read x", "zsh", "x y", "", "é\nz", "--flag=1"]
        p.environment = ["NAZAR_TEST_SECRET": "hunter2"]
        p.currentDirectoryURL = dir
        let stdin = Pipe()
        p.standardInput = stdin
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        defer {
            if p.isRunning { p.terminate() }
            p.waitUntilExit()
        }
        let pid = p.processIdentifier
        let rec = try #require(KernelProc.info(pid))
        #expect(rec.ppid == getpid() && rec.uid == getuid() && !rec.zombie)
        #expect(KernelProc.args(pid) == ["/bin/zsh", "-f", "-c", "read x", "zsh", "x y", "", "é\nz", "--flag=1"])
        #expect(!KernelProc.args(pid).contains { $0.contains("hunter2") })
        #expect(KernelProc.path(pid) == "/bin/zsh")
        #expect(URL(fileURLWithPath: KernelProc.cwd(pid)).resolvingSymlinksInPath() == dir.resolvingSymlinksInPath())
        let mine = try #require(KernelProc.info(getpid()))
        #expect(rec.startMicros >= mine.startMicros)
    }

    @Test func unreapedChildIsAZombie() throws {
        // posix_spawn directly, so nothing reaps the child until this test does.
        var pid: pid_t = 0
        let argv: [UnsafeMutablePointer<CChar>?] = [strdup("/usr/bin/true"), nil]
        defer { for a in argv { free(a) } }
        #expect(posix_spawn(&pid, "/usr/bin/true", nil, nil, argv, nil) == 0)
        try #require(pid > 0)
        let before = KernelProc.info(pid)
        var zombie: KProc?
        for _ in 0..<500 {
            if let r = KernelProc.info(pid), r.zombie { zombie = r; break }
            usleep(10_000)
        }
        var status: Int32 = 0
        let reaped = waitpid(pid, &status, 0)
        #expect(reaped == pid)
        let z = try #require(zombie)
        #expect(z.pid == pid && z.ppid == getpid())
        if let b = before { #expect(b.startMicros == z.startMicros) } // the same process, now dead
        // after reaping the PID is gone (or, rarely, a different process)
        #expect(KernelProc.info(pid).map { $0.startMicros != z.startMicros } ?? true)
    }

    @Test func distinctProcessesHaveDistinctRefs() throws {
        let a = try Sleeper()
        let b = try Sleeper()
        defer { a.kill(); b.kill() }
        let ra = try #require(KernelProc.info(a.pid))
        let rb = try #require(KernelProc.info(b.pid))
        #expect((ra.pid, ra.generation) != (rb.pid, rb.generation))
        #expect(KernelProc.path(a.pid) == "/bin/sleep")
    }

    @Test func generationIsPreciseToTheMicrosecond() throws {
        // A ProcessRef must tell a process apart from a later occupant of its
        // PID; with whole-second precision a PID recycled within the same
        // second would get the same ref. The generation must equal an
        // independent microsecond reading (PROC_PIDTBSDINFO), for this
        // process and for a fresh child.
        let me = try #require(KernelProc.info(getpid()))
        #expect(me.startMicros == (try bsdStartMicros(getpid())))
        let s = try Sleeper()
        defer { s.kill() }
        let child = try #require(KernelProc.info(s.pid))
        let reference = try bsdStartMicros(s.pid)
        #expect(child.startMicros == reference)
        #expect(child.generation == UInt64(reference))
        // and at least one of the two really carries sub-second digits
        #expect(me.startMicros % 1_000_000 != 0 || reference % 1_000_000 != 0)
    }
}

@Suite struct CodeSigningEdgeTests {
    @Test func absentProcessesHaveNoGuest() {
        #expect(CodeSigning.guest(pid: .max) == nil)
        #expect(CodeSigning.guest(pid: -1) == nil)
    }

    @Test func auditTokenNamesTheSameCodeAsThePID() throws {
        let token = try #require(ownAuditToken())
        let byToken = try #require(CodeSigning.guest(auditToken: token))
        let byPID = try #require(CodeSigning.guest(pid: getpid()))
        let a = CodeSigning.identity(of: byToken)
        let b = CodeSigning.identity(of: byPID)
        #expect(!a.cdhash.isEmpty && a == b)
    }

    @Test func staleOrForgedAuditTokenNeverMatches() throws {
        // Spec 4.1 step 1: the token's pidversion (val.7) pins one process; a
        // recycled PID (same pid, other pidversion) must never be described.
        var stale = try #require(ownAuditToken())
        stale.val.7 &+= 1
        #expect(CodeSigning.guest(auditToken: stale) == nil)
        var absent = try #require(ownAuditToken())
        absent.val.5 = UInt32(bitPattern: Int32.max)
        #expect(CodeSigning.guest(auditToken: absent) == nil)
        #expect(CodeSigning.guest(auditToken: audit_token_t()) == nil)
    }

    @Test func deadChildIsNeverDescribed() throws {
        // By PID the guest of a dead child is gone, or (recycled PID) a
        // different process: callers re-check the generation (ProcessResolver).
        let s = try Sleeper()
        let rec = try #require(KernelProc.info(s.pid))
        let byPID = try #require(CodeSigning.guest(pid: s.pid))
        #expect(CodeSigning.identity(of: byPID).signingId == "com.apple.sleep")
        s.kill()
        #expect(CodeSigning.guest(pid: s.pid) == nil || KernelProc.info(s.pid)?.startMicros != rec.startMicros)
    }

    @Test func runningAdHocCodeIsNotApple() throws {
        let dir = try tempDir("nzcs")
        defer { try? FileManager.default.removeItem(at: dir) }
        let tool = dir.appendingPathComponent("sleep")
        try FileManager.default.copyItem(atPath: "/bin/sleep", toPath: tool.path)
        try adHocSign(tool.path, identifier: "dev.nazar.test.sleep")
        let p = Process()
        p.executableURL = tool
        p.arguments = ["60"]
        try p.run()
        defer {
            if p.isRunning { p.terminate() }
            p.waitUntilExit()
        }
        let code = try #require(CodeSigning.guest(pid: p.processIdentifier))
        let id = CodeSigning.identity(of: code)
        #expect(id.signed && id.adHoc && !id.apple && id.teamId.isEmpty && id.signingId == "dev.nazar.test.sleep")
        // `nazar run` pins a receiver's cdhash(path:) and compares it with the
        // running process's cdhash: the slice the kernel runs, not the
        // file's default slice (see cdhashMatchesCodesign).
        let onDisk = try CodeSigning.cdhash(path: tool.path)
        #expect(id.cdhash.count == 20 && id.cdhash == onDisk)
        #expect(try #require(CodeSigning.staticIdentity(path: tool.path)).cdhash == onDisk)
        // a copy of an Apple binary is not Apple's code
        let original = try #require(CodeSigning.staticIdentity(path: "/bin/sleep"))
        #expect(original.apple && original.cdhash != id.cdhash)
    }

    @Test func tamperedBinaryIsNotSigned() throws {
        // A pinned binary replaced or patched in place must not look signed.
        let dir = try tempDir("nzcs")
        defer { try? FileManager.default.removeItem(at: dir) }
        let tool = dir.appendingPathComponent("true")
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: tool.path)
        try adHocSign(tool.path, identifier: "dev.nazar.test.true")
        let good = try #require(CodeSigning.staticIdentity(path: tool.path))
        #expect(good.signed)
        var bytes = try [UInt8](Data(contentsOf: tool))
        // flip one byte in every 4 KiB page past the headers, so whichever
        // slice is checked, a hashed page changes
        var off = 0x1000
        while off < bytes.count { bytes[off] ^= 0xff; off += 0x1000 }
        try Data(bytes).write(to: tool)
        let bad = CodeSigning.staticIdentity(path: tool.path)
        #expect(bad == nil || bad?.signed == false)
        #expect(bad == nil || bad?.apple == false)
    }

    @Test func swappedBinaryIsNeitherSignedNorHashed() throws {
        // A cdhash pin (a `nazar run` receiver's) is cdhash(path:) when it is
        // pinned, compared with the RUNNING process's cdhash and nothing else. A
        // process of the same user that can rename over the pinned path
        // (~/bin, /opt/homebrew/bin) can exec its own binary there and put
        // the trusted one back: Security then reads the trusted file's
        // signing information while the kernel runs the other code
        // (SecCodeCheckValidity: errSecCSStaticCodeChanged). The identity
        // must not carry that on-disk cdhash: not signed, no cdhash at all.
        let dir = try tempDir("nzcs")
        defer { try? FileManager.default.removeItem(at: dir) }
        let tool = dir.appendingPathComponent("tool")
        let trusted = dir.appendingPathComponent("trusted")
        try FileManager.default.copyItem(atPath: "/bin/sleep", toPath: tool.path)
        try FileManager.default.copyItem(atPath: "/bin/sleep", toPath: trusted.path)
        try adHocSign(tool.path, identifier: "dev.nazar.test.evil")
        try adHocSign(trusted.path, identifier: "dev.nazar.test.trusted")
        let evilHash = try CodeSigning.cdhash(path: tool.path)
        let trustedHash = try CodeSigning.cdhash(path: trusted.path)
        try #require(evilHash != trustedHash && !trustedHash.isEmpty)

        let p = Process()
        p.executableURL = tool
        p.arguments = ["60"]
        try p.run()
        defer {
            if p.isRunning { p.terminate() }
            p.waitUntilExit()
        }
        let pid = p.processIdentifier
        let before = CodeSigning.identity(of: try #require(CodeSigning.guest(pid: pid)))
        #expect(before.signed && before.cdhash == evilHash && before.signingId == "dev.nazar.test.evil")

        // the swap: the trusted binary is renamed over the running one's path
        #expect(rename(trusted.path, tool.path) == 0)
        #expect(try CodeSigning.cdhash(path: tool.path) == trustedHash)
        #expect(URL(fileURLWithPath: KernelProc.path(pid)).resolvingSymlinksInPath() == tool.resolvingSymlinksInPath())

        let id = CodeSigning.identity(of: try #require(CodeSigning.guest(pid: pid)))
        #expect(!id.signed && !id.apple)
        #expect(id.cdhash.isEmpty)
        #expect(try CodeSigning.cdhash(path: tool.path) != id.cdhash)
        #expect(id.cdhash != trustedHash && id.cdhash != evilHash)
    }

    @Test func developerIDCodeIsSignedButNotApple() throws {
        // spec 4.1 step 2 / 4.2: `signed: {team: apple}` must be the `anchor
        // apple` check, never "has a valid signature". Developer ID code
        // (the Go toolchain's gofmt, signed by its vendor) is validly signed,
        // not ad hoc, carries a team ID, and is not Apple. The reference is
        // codesign's own report of the same file.
        let gofmt = try goToolchainGofmt()
        let report = try codesignReport(gofmt)
        let team = try #require(report["TeamIdentifier"], "gofmt at \(gofmt) is not signed with a team identifier")
        let authority = report["Authority"] ?? ""
        try #require(team.count == 10 && team != "not set", "unexpected TeamIdentifier \(team) for \(gofmt)")
        try #require(authority.contains("Developer ID Application:"), "gofmt at \(gofmt) is not Developer ID code: \(authority)")
        let identifier = try #require(report["Identifier"])

        let onDisk = try #require(CodeSigning.staticIdentity(path: gofmt))
        #expect(onDisk.signed && !onDisk.apple && !onDisk.adHoc)
        #expect(onDisk.teamId == team && onDisk.signingId == identifier)
        let pinned = try CodeSigning.cdhash(path: gofmt)
        #expect(onDisk.cdhash.count == 20 && pinned == onDisk.cdhash)

        // running: gofmt without arguments blocks reading stdin
        let p = Process()
        p.executableURL = URL(fileURLWithPath: gofmt)
        p.standardInput = Pipe()
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        defer {
            if p.isRunning { p.terminate() }
            p.waitUntilExit()
        }
        let running = CodeSigning.identity(of: try #require(CodeSigning.guest(pid: p.processIdentifier)))
        #expect(running.signed && !running.apple && !running.adHoc)
        #expect(running.teamId == team && running.signingId == identifier)
        #expect(running.cdhash == onDisk.cdhash)
    }

    @Test func appleAppBundleStaticIdentity() throws {
        let id = try #require(CodeSigning.staticIdentity(path: "/System/Applications/Calculator.app"))
        #expect(id.signed && id.apple && !id.adHoc && id.signingId == "com.apple.calculator")
        #expect(id.cdhash.count == 20)
        #expect(try CodeSigning.cdhash(path: "/System/Applications/Calculator.app") == id.cdhash)
    }

    @Test func missingAndNonCodePaths() throws {
        #expect(CodeSigning.staticIdentity(path: "/nonexistent/nazar-\(UUID())") == nil)
        let dir = try tempDir("nzcs")
        defer { try? FileManager.default.removeItem(at: dir) }
        let text = dir.appendingPathComponent("notes.txt")
        try Data("#!/bin/sh\necho hi\n".utf8).write(to: text)
        let id = CodeSigning.staticIdentity(path: text.path)
        #expect(id == nil || (id?.signed == false && id?.apple == false && id?.cdhash.isEmpty == true))
        // an empty folder is not code either
        #expect(throws: PlatformError.self) { try CodeSigning.cdhash(path: dir.path) }
        #expect(throws: PlatformError.notFound) { try CodeSigning.cdhash(path: "") }
    }
}

// Milestone 5: Claude Code runs from a version-named file that its
// auto-update deletes while it runs. The kernel then has no path for it
// (proc_pidpath fails), but p_comm keeps the name it was started under.
@Suite struct DeletedExecutableTests {
    @Test func pathIsEmptyAndCommRemains() throws {
        let dir = try tempDir("nzcomm")
        defer { try? FileManager.default.removeItem(at: dir) }
        // An ad-hoc signed copy (a copy of an Apple platform binary that
        // keeps Apple's signature is killed by the system when run).
        let exe = dir.appendingPathComponent("2.1.299")
        try FileManager.default.copyItem(atPath: "/bin/sleep", toPath: exe.path)
        try adHocSign(exe.path, identifier: "dev.nazar.test.sleep")
        let p = Process()
        p.executableURL = exe
        p.arguments = ["60"]
        try p.run()
        defer {
            if p.isRunning { p.terminate() }
            p.waitUntilExit()
        }
        let r = ProcessResolver()
        let before = try r.process(ProcessRef(pid: p.processIdentifier, generation: 0))
        // (proc_pidpath reports /private/var/…; URL's resolvingSymlinksInPath strips /private.)
        #expect(before.path.hasSuffix(dir.lastPathComponent + "/2.1.299") && before.comm == "2.1.299")
        try FileManager.default.removeItem(at: exe)
        let after = try r.process(ProcessRef(pid: p.processIdentifier, generation: 0))
        #expect(after.path == "" && after.comm == "2.1.299" && after.ref == before.ref)
    }

    // p_comm is the file name cut to MAXCOMLEN (16) bytes, never more, and
    // the resolver passes it through as is.
    @Test func commIsCutToSixteenBytes() throws {
        let dir = try tempDir("nzcomm")
        defer { try? FileManager.default.removeItem(at: dir) }
        let exe = dir.appendingPathComponent("claude-code-2.1.299-arm64")
        try FileManager.default.copyItem(atPath: "/bin/sleep", toPath: exe.path)
        try adHocSign(exe.path, identifier: "dev.nazar.test.sleep")
        let p = Process()
        p.executableURL = exe
        p.arguments = ["60"]
        try p.run()
        defer {
            if p.isRunning { p.terminate() }
            p.waitUntilExit()
        }
        let k = try #require(KernelProc.info(p.processIdentifier))
        #expect(k.comm == "claude-code-2.1.")
        #expect(k.comm.utf8.count == 16)
        let rec = try ProcessResolver().process(ProcessRef(pid: p.processIdentifier, generation: 0))
        #expect(rec.comm == k.comm && rec.path.hasSuffix("/claude-code-2.1.299-arm64"))
    }

    // Our own process has a short name too (the test runner's file name).
    @Test func ownCommIsSet() throws {
        let me = try #require(KernelProc.info(getpid()))
        let url = try #require(Bundle.main.executableURL)
        let names = [url.lastPathComponent, url.resolvingSymlinksInPath().lastPathComponent]
        #expect(!me.comm.isEmpty && me.comm.utf8.count <= 16 && names.contains { $0.hasPrefix(me.comm) })
    }
}
