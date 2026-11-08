import Darwin
import Foundation
import Testing
@testable import NazarPlatform

// platform.Exec on macOS (ExecWatcher; secrets design 6.3 step 6, D8, D10).
// The children are NazarExecProbe (built next to this test bundle; not an
// Apple platform binary, so macOS shows its environment), /bin/bash and
// /bin/sleep. Nothing here touches a keychain, shows a window or needs a
// person.

/// NazarExecProbe, which `swift build` puts next to the test bundle (if it
/// is missing, posix_spawn fails and so does the test: never a skip).
enum Probe {
    final class Marker {}
    static var path: String {
        Bundle(for: Marker.self).bundleURL.deletingLastPathComponent()
            .appendingPathComponent("NazarExecProbe").resolvingSymlinksInPath().path
    }
}

/// A child started with posix_spawn in "/", with exactly argv and env and
/// a pipe on its stdin: next() writes one line, which makes the probe (or
/// bash's `read _ && exec "$@"`) exec. Killed and reaped at the end.
final class ExecChild {
    let pid: pid_t
    let ref: ProcessRef
    private let input: Int32
    private var reaped = false

    /// path is what posix_spawn runs (argv[0] when nil).
    init(_ argv: [String], env: [String], path: String? = nil) throws {
        var fds: [Int32] = [0, 0]
        guard pipe(&fds) == 0 else { throw POSIXError(.EIO) }
        var fa: posix_spawn_file_actions_t? = nil
        posix_spawn_file_actions_init(&fa)
        defer { posix_spawn_file_actions_destroy(&fa) }
        posix_spawn_file_actions_adddup2(&fa, fds[0], 0)
        posix_spawn_file_actions_addclose(&fa, fds[0])
        posix_spawn_file_actions_addclose(&fa, fds[1])
        posix_spawn_file_actions_addchdir_np(&fa, "/")
        let cargv = argv.map { strdup($0) } + [nil], cenv = env.map { strdup($0) } + [nil]
        defer { (cargv + cenv).forEach { free($0) } }
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, path ?? argv[0], &fa, nil, cargv, cenv)
        close(fds[0])
        guard rc == 0, let k = KernelProc.info(pid) else {
            close(fds[1])
            throw POSIXError(POSIXErrorCode(rawValue: rc) ?? .EIO)
        }
        self.pid = pid
        ref = ProcessRef(pid: pid, generation: k.generation)
        input = fds[1]
    }

    func next() { _ = write(input, "\n", 1) }

    func kill() {
        guard !reaped else { return }
        reaped = true
        _ = Darwin.kill(pid, SIGKILL)
        var status: Int32 = 0
        _ = waitpid(pid, &status, 0)
    }

    deinit {
        kill()
        close(input)
    }
}

/// What fired reported.
final class Execs: @unchecked Sendable {
    private let lock = NSLock()
    private var got: [ProcessRecord] = []
    var fired: ExecWatcher.Fired { { rec in self.lock.lock(); self.got.append(rec); self.lock.unlock() } }
    var all: [ProcessRecord] { lock.lock(); defer { lock.unlock() }; return got }
    /// Waits until at least n events came, then returns them all.
    func wait(for n: Int, timeout: TimeInterval = 5) -> [ProcessRecord] {
        let end = Date().addingTimeInterval(timeout)
        while all.count < n && Date() < end { Thread.sleep(forTimeInterval: 0.005) }
        return all
    }
}

@Suite struct ProcArgsEnvironmentTests {
    func buf(argc: Int32, _ path: String, _ strings: [String], tail: [UInt8] = [0, 0]) -> [UInt8] {
        var b = withUnsafeBytes(of: argc.littleEndian) { Array($0) }
        b += Array(path.utf8) + [0] // the exec path, padded to 8 bytes as the kernel does
        while (b.count - 4) % 8 != 0 { b.append(0) }
        for s in strings { b += Array(s.utf8) + [0] }
        return b + tail
    }

    @Test func theStringsAfterTheArguments() {
        let b = buf(argc: 2, "/bin/x", ["x", "a b", "A=1", "B=two words", "C=ü=x"])
        #expect(ProcArgs.parse(b)?.args == ["x", "a b"])
        #expect(ProcArgs.environment(b) == ["A=1", "B=two words", "C=ü=x"])
    }

    @Test func endsAtTheFirstEmptyString() {
        let b = buf(argc: 1, "/bin/x", ["x", "A=1"], tail: [0] + Array("ptr_munge=".utf8) + [0])
        #expect(ProcArgs.environment(b) == ["A=1"])
    }

    @Test func aLongArgumentIsSkippedToItsTerminator() {
        #expect(ProcArgs.environment(buf(argc: 1, "/bin/x", [String(repeating: "z", count: 40_000), "A=1"])) == ["A=1"])
    }

    /// Hidden, zero-filled, empty, cut or too big: nil, never [] and never a
    /// cut list (a cut list would hide what follows).
    @Test func nothingToCompareIsNilNeverEmpty() {
        #expect(ProcArgs.environment([]) == nil)
        #expect(ProcArgs.environment([1, 0]) == nil)
        #expect(ProcArgs.environment(buf(argc: 1, "/bin/x", ["x"])) == nil)
        #expect(ProcArgs.environment(buf(argc: 1, "/bin/x", ["x"], tail: [UInt8](repeating: 0, count: 64))) == nil)
        #expect(ProcArgs.environment(buf(argc: 3, "/bin/x", ["x"])) == nil)
        #expect(ProcArgs.environment(buf(argc: -1, "/bin/x", ["A=1"])) == nil)
        #expect(ProcArgs.environment(buf(argc: Int32(ProcArgs.maxArgs + 1), "/bin/x", ["A=1"])) == nil)
        #expect(ProcArgs.environment(buf(argc: 1, "/bin/x", ["x", "V=" + String(repeating: "v", count: ProcArgs.maxArgBytes)])) == nil)
        #expect(ProcArgs.environment(buf(argc: 1, "/bin/x", ["x"] + (0...ProcArgs.maxEnv).map { "V\($0)=1" })) == nil)
    }
}

@Suite struct ExecWatcherTests {
    let p = Probe.path

    /// An empty argv[0] is an argument, not padding: the environment read
    /// from a live process is whole, whatever the length of its exec path
    /// (the kernel pads the path to 8 bytes; here every remainder).
    @Test func anEmptyArgv0HidesNoVariable() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("nz-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: dir) }
        let env = ["NODE_OPTIONS=--require /tmp/e.js", "A=1"]
        for n in 1...8 {
            let link = dir.appendingPathComponent(String(repeating: "p", count: n)).path
            try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: p)
            let c = try ExecChild(["", "x"], env: env, path: link)
            let b = try #require(KernelProc.procArgs(c.pid))
            #expect(ProcArgs.parse(b)?.args == ["", "x"], "exec path of \(link.utf8.count) bytes")
            #expect(ProcArgs.environment(b) == env, "exec path of \(link.utf8.count) bytes")
            c.kill()
        }
    }

    func watcher() throws -> ExecWatcher { try #require(ExecWatcher()) }

    /// Every exec, in order, as read at the event: from bash into the probe,
    /// the probe again, then /bin/sleep. (Not /bin/sh: it is a trampoline
    /// that execs the selected shell, an exec of its own.)
    @Test func everyExecInOrderFromAShell() throws {
        let c = try ExecChild(["/bin/bash", "-c", "read _ && exec \"$@\"", "bash", p, p, "/bin/sleep", "600"], env: ["NAZAR_TEST=bash"])
        let w = try watcher(), seen = Execs()
        try w.watch(c.ref, token: 1, fired: seen.fired)
        let script: [(String, [String])] = [(p, [p, p, "/bin/sleep", "600"]), (p, [p, "/bin/sleep", "600"]), ("/bin/sleep", ["/bin/sleep", "600"])]
        for (i, (path, args)) in script.enumerated() {
            c.next()
            let got = seen.wait(for: i + 1)
            try #require(got.count == i + 1, "exec \(i + 1) not reported")
            #expect(got[i].ref == c.ref && got[i].path == path && got[i].args == args && got[i].cwd == "/")
        }
        #expect(try seen.all[0].code.cdhash == CodeSigning.cdhash(path: p)) // live code = the file's
        Thread.sleep(forTimeInterval: 0.2)
        #expect(seen.all.count == 3)
    }

    /// The environment of the last exec, exactly and in order; unreadable
    /// before any watched exec and for an Apple platform binary (never []);
    /// gone once the process is.
    @Test func environmentIsTheOneReadAtTheExec() throws {
        let env = ["NAZAR_TEST_MARK=\(UUID().uuidString)", "B=two words", "C=ü=x"]
        let c = try ExecChild([p, p, p, "/bin/sleep", "600"], env: env)
        let w = try watcher(), seen = Execs()
        #expect(throws: PlatformError.unreadable) { try w.environment(c.ref) } // not watched
        try w.watch(c.ref, token: 1, fired: seen.fired)
        #expect(throws: PlatformError.unreadable) { try w.environment(c.ref) } // no exec seen yet
        for i in 1...2 {
            c.next()
            try #require(seen.wait(for: i).count == i)
            #expect(try w.environment(c.ref) == env)
        }
        c.next()
        try #require(seen.wait(for: 3).count == 3)
        #expect(seen.all[2].path == "/bin/sleep")
        #expect(throws: PlatformError.unreadable) { try w.environment(c.ref) } // hidden
        c.kill()
        #expect(throws: PlatformError.noProcess) { try w.environment(c.ref) }
        #expect(w.watching == 0)
    }

    /// D10: argv and the environment are read at the exec event. The probe
    /// zero-fills its own area 300 ms after exec (as npm does after ~40 ms);
    /// the event already has its argv, and environment(_:) still answers
    /// the read taken at the event.
    @Test func readAtTheEventBeforeTheProgramRewritesIt() throws {
        let env = ["NAZAR_PROBE_SCRIBBLE=1", "MARK=x"]
        let c = try ExecChild([p, p], env: env)
        let w = try watcher(), seen = Execs()
        try w.watch(c.ref, token: 1, fired: seen.fired)
        c.next()
        try #require(seen.wait(for: 1).count == 1)
        #expect(seen.all[0].args == [p])
        Thread.sleep(forTimeInterval: 0.6)
        #expect(KernelProc.args(c.pid) != [p]) // the probe did zero-fill it
        #expect(try w.environment(c.ref) == env)
    }

    /// environment(_:) takes pending events first: with the event source
    /// held, an exec that already happened is still read (and reported)
    /// before the answer.
    @Test func environmentSeesAnExecTheHandlerHasNotTakenYet() throws {
        let c = try ExecChild([p, p, p], env: ["A=1"])
        let w = try watcher(), seen = Execs()
        try w.watch(c.ref, token: 1, fired: seen.fired)
        c.next()
        try #require(seen.wait(for: 1).count == 1)
        w.source.suspend()
        defer { w.source.resume() }
        c.next()
        let end = Date().addingTimeInterval(5)
        while KernelProc.args(c.pid) != [p] && Date() < end { Thread.sleep(forTimeInterval: 0.005) }
        Thread.sleep(forTimeInterval: 0.05)
        #expect(try w.environment(c.ref) == ["A=1"])
        #expect(seen.all.count == 2)
    }

    /// fired is never called for a token after cancel returns; another
    /// token on the same process keeps getting events; after the last
    /// cancel nothing is watched and the environment is unreadable.
    @Test func cancel() throws {
        let c = try ExecChild([p, p, p, "/bin/sleep", "600"], env: ["A=1"])
        let w = try watcher(), one = Execs(), two = Execs()
        try w.watch(c.ref, token: 1, fired: one.fired)
        try w.watch(c.ref, token: 2, fired: two.fired)
        c.next()
        try #require(one.wait(for: 1).count == 1 && two.wait(for: 1).count == 1)
        w.cancel(token: 1)
        w.cancel(token: 1) // twice is harmless
        c.next()
        try #require(two.wait(for: 2).count == 2)
        Thread.sleep(forTimeInterval: 0.2)
        #expect(one.all.count == 1)
        w.cancel(token: 2)
        #expect(w.watching == 0)
        #expect(throws: PlatformError.unreadable) { try w.environment(c.ref) }
    }

    /// Only the live instance of a full ref: another generation of a live
    /// PID, a PID-only ref, pid 0 and an exited (reaped) process are
    /// refused, leave nothing armed, and do not disturb a watch already on
    /// the PID's live instance.
    @Test func onlyTheLiveInstance() throws {
        let c = try ExecChild([p, p, p], env: ["A=1"])
        let w = try watcher(), seen = Execs()
        try w.watch(c.ref, token: 1, fired: seen.fired)
        for bad in [ProcessRef(pid: c.pid, generation: c.ref.generation + 1), ProcessRef(pid: c.pid, generation: 0),
                    ProcessRef(pid: 0, generation: 1), ProcessRef(pid: Int32.max, generation: 1)] {
            #expect(throws: PlatformError.noProcess) { try w.watch(bad, token: 9, fired: { _ in }) }
            #expect(throws: PlatformError.noProcess) { try w.environment(bad) }
        }
        c.next()
        try #require(seen.wait(for: 1).count == 1) // the live watch was not disturbed
        let gone = try ExecChild([p], env: ["A=1"])
        gone.kill()
        #expect(throws: PlatformError.noProcess) { try w.watch(gone.ref, token: 10, fired: { _ in }) }
        #expect(w.watching == 1)
    }

    /// (b) environment(_:) retries a poll a signal interrupted (EINTR) and
    /// still reads the exec that came first; any other failed poll is
    /// .unreadable, never the environment read before: an exec may be
    /// pending unread.
    @Test func environmentRetriesEINTRAndRefusesOnAFailedPoll() throws {
        let c = try ExecChild([p, p, p], env: ["A=1"])
        let w = try watcher(), seen = Execs()
        try w.watch(c.ref, token: 1, fired: seen.fired)
        w.source.suspend()
        defer { w.source.resume() }
        c.next()
        let end = Date().addingTimeInterval(5)
        while KernelProc.args(c.pid) != [p, p] && Date() < end { Thread.sleep(forTimeInterval: 0.005) }
        Thread.sleep(forTimeInterval: 0.05)
        w.failPolls([EINTR])
        #expect(try w.environment(c.ref) == ["A=1"])
        #expect(seen.all.count == 1)
        w.failPolls([EBADF])
        #expect(throws: PlatformError.unreadable) { try w.environment(c.ref) }
        #expect(try w.environment(c.ref) == ["A=1"]) // one failed poll, not a lasting one
    }

    /// (c) An exec whose process can't be read at the event (gone before
    /// the handler took it) is still reported, as an exec of nothing (the
    /// ref, no path, argv or code), before the watch ends.
    @Test func anExecThatCannotBeReadIsReportedAsNothing() throws {
        let c = try ExecChild([p, p, p], env: ["A=1"])
        let w = try watcher(), seen = Execs()
        try w.watch(c.ref, token: 1, fired: seen.fired)
        w.source.suspend()
        var resumed = false
        defer { if !resumed { w.source.resume() } }
        c.next()
        let end = Date().addingTimeInterval(5)
        while KernelProc.args(c.pid) != [p, p] && Date() < end { Thread.sleep(forTimeInterval: 0.005) }
        c.kill() // reaped: the read at the event fails
        w.source.resume()
        resumed = true
        let got = seen.wait(for: 1)
        try #require(got.count == 1, "the exec was not reported")
        #expect(got[0].ref == c.ref && got[0].path == "" && got[0].args.isEmpty && got[0].code == CodeIdentity())
        let gone = Date().addingTimeInterval(5)
        while w.watching != 0 && Date() < gone { Thread.sleep(forTimeInterval: 0.01) }
        #expect(w.watching == 0)
    }

    /// The exit ends the watch: no event, nothing kept.
    @Test func exitEndsTheWatch() throws {
        let c = try ExecChild([p, p], env: ["A=1"])
        let w = try watcher(), seen = Execs()
        try w.watch(c.ref, token: 1, fired: seen.fired)
        c.kill()
        let end = Date().addingTimeInterval(5)
        while w.watching != 0 && Date() < end { Thread.sleep(forTimeInterval: 0.01) }
        #expect(w.watching == 0 && seen.all.isEmpty)
    }
}
