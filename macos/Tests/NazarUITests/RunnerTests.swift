import Foundation
import Testing
@testable import NazarUI

// ProcessCLIRunner runs the CLI by absolute path with a fixed environment.
// These tests run a tiny shell script in its place (never the real CLI,
// never an agent) through the tests' unchecked runner; the signature check
// every app run makes is VerifiedRunnerTests'.
@Suite struct RunnerTests {
    func script(_ body: String) throws -> (URL, URL) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("nzui-\(UUID().uuidString)")
        let macos = dir.appendingPathComponent("nazar-agent.app/Contents/MacOS")
        try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
        let cli = macos.appendingPathComponent("nazar")
        try Data(("#!/bin/sh\n" + body).utf8).write(to: cli)
        chmod(cli.path, 0o755)
        return (dir, cli)
    }

    /// Arguments arrive one by one, untouched (no shell); the environment is
    /// HOME and a fixed PATH only; stdout, stderr and the exit code come back.
    @Test func runPassesArgumentsAndEnvironment() async throws {
        let (dir, cli) = try script("""
        for a in "$@"; do printf '%s\\n' "$a"; done
        printf 'HOME=%s PATH=%s NAZAR=%s\\n' "$HOME" "$PATH" "${NAZAR_CONTROL_SOCKET:-unset}"
        echo oops >&2
        exit 4

        """)
        defer { try? FileManager.default.removeItem(at: dir) }
        setenv("NAZAR_CONTROL_SOCKET", "/tmp/evil.sock", 1)
        defer { unsetenv("NAZAR_CONTROL_SOCKET") }
        let r = await ProcessCLIRunner(cli: cli, home: "/Users/u").run(["--json", "a b", "; rm -rf ~", "$(x)"])
        let out = String(decoding: r.stdout, as: UTF8.self).split(separator: "\n").map(String.init)
        #expect(r.exitCode == 4 && r.stderr == "oops\n")
        #expect(out == ["--json", "a b", "; rm -rf ~", "$(x)", "HOME=/Users/u PATH=/usr/bin:/bin:/usr/sbin:/sbin NAZAR=unset"])
    }

    /// Input reaches the CLI's stdin byte for byte, then EOF; it is
    /// in no argument and no variable; it is wiped when run returns.
    @Test func inputReachesStdinThenEOF() async throws {
        let (dir, cli) = try script("cat; printf '|eof|%s|' \"$*\"; env | grep -c s3cret || true\n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let value = "s3cret value\nwith é and a tab\t"
        let input = CLIInput(value)
        let r = await ProcessCLIRunner(cli: cli).run(["--json", "secret", "add", "X"], input: input)
        #expect(r.exitCode == 0 && r.stdout == Data((value + "|eof|--json secret add X|0\n").utf8), "\(r.stdout.count) bytes")
        #expect(input.isWiped)
    }

    /// A CLI that exits without reading (a usage error, a refusal before the
    /// read) ends the run with its own code: the write meets a closed pipe and
    /// the app gets EPIPE, not SIGPIPE (which would end this test process).
    /// SIGPIPE is at its default (fatal) for this run, so the test fails
    /// without F_SETNOSIGPIPE even in a host that ignores it.
    @Test func inputToACLIThatDoesNotReadItNeverKillsTheApp() async throws {
        let (dir, cli) = try script("exit 7\n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let old = signal(SIGPIPE, SIG_DFL)
        defer { signal(SIGPIPE, old) }
        let input = CLIInput(String(repeating: "x", count: 1 << 20))
        let r = await ProcessCLIRunner(cli: cli).run(["x"], input: input)
        #expect(r.exitCode == 7 && input.isWiped)
    }

    /// A CLI that can't be started gets nothing, and the input is wiped.
    @Test func inputOfARunThatCannotStartIsWiped() async {
        let input = CLIInput("v")
        let r = await ProcessCLIRunner(cli: URL(fileURLWithPath: "/nonexistent/nazar")).run(["x"], input: input)
        #expect(r.exitCode == ProcessCLIRunner.cannotRun && input.isWiped)
    }

    @Test func aMissingCLIIsAFailureNotACrash() async {
        let r = await ProcessCLIRunner(cli: URL(fileURLWithPath: "/nonexistent/nazar")).run(["--json", "status"])
        #expect(r.exitCode == 127 && r.stderr.contains("cannot run"))
    }

    @Test func streamDeliversLinesThenTheExitCode() async throws {
        let (dir, cli) = try script("printf 'one\\ntwo\\n'; printf 'three'; exit 3\n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let got = LinesBox()
        await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
            _ = ProcessCLIRunner(cli: cli).stream(["x"], onLine: { got.add(String(decoding: $0, as: UTF8.self)) },
                                                  onExit: { code in got.exit = code; k.resume() })
        }
        #expect(got.lines == ["one", "two"] && got.exit == 3) // an unterminated last line is not an object
    }

    @Test func stopEndsAStream() async throws {
        let (dir, cli) = try script("echo started; exec sleep 30\n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let got = LinesBox()
        let start = Date()
        await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
            // Stopped as soon as it printed its first line.
            got.stream = ProcessCLIRunner(cli: cli).stream(["x"], onLine: { l in
                got.add(String(decoding: l, as: UTF8.self))
                got.stream?.stop()
            }, onExit: { code in got.exit = code; k.resume() })
        }
        #expect(got.lines == ["started"], "\(got.lines)")
        #expect(Date().timeIntervalSince(start) < 10)
    }

    /// stdout past maxOutput is cut, and a child that writes a lot to stdout
    /// and stderr never blocks on a full pipe: the run still ends.
    @Test func bigOutputIsCutAndNeverBlocks() async throws {
        let (dir, cli) = try script("head -c \(ProcessCLIRunner.maxOutput + 4_000_000) /dev/zero; head -c 3000000 /dev/zero >&2; exit 0\n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let start = Date()
        let r = await ProcessCLIRunner(cli: cli).run(["x"])
        #expect(r.exitCode == 0 && r.stdout.count == ProcessCLIRunner.maxOutput)
        #expect(r.stderr.utf8.count < 3_000_000)
        #expect(Date().timeIntervalSince(start) < 30)
    }

    /// A stream line longer than maxLine is dropped whole (never delivered
    /// in pieces that could parse as objects); the next line still arrives.
    @Test func streamDropsAnOverlongLine() async throws {
        let (dir, cli) = try script("head -c \(ProcessCLIRunner.maxLine + 1000) /dev/zero | tr '\\0' a; echo; echo ok; exit 0\n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let got = LinesBox()
        await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
            _ = ProcessCLIRunner(cli: cli).stream(["x"], onLine: { got.add(String(decoding: $0, as: UTF8.self)) },
                                                  onExit: { code in got.exit = code; k.resume() })
        }
        #expect(got.lines == ["ok"] && got.exit == 0, "\(got.lines.map(\.count))")
    }

    /// A stream whose CLI can't be started reports an exit, never hangs.
    @Test func aMissingCLIStreamExits() async {
        let got = LinesBox()
        await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
            _ = ProcessCLIRunner(cli: URL(fileURLWithPath: "/nonexistent/nazar")).stream(["--json", "status", "--follow"],
                onLine: { got.add(String(decoding: $0, as: UTF8.self)) }, onExit: { code in got.exit = code; k.resume() })
        }
        #expect(got.lines.isEmpty && got.exit != 0)
    }

    /// The CLI may be waiting on a login prompt the agent shows, so a run
    /// must leave the main thread free while it waits.
    @MainActor @Test func runLeavesTheMainThreadFree() async throws {
        let (dir, cli) = try script("sleep 1\nexit 0\n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let start = Date()
        let ranAt = LinesBox()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { ranAt.add(String(Date().timeIntervalSince(start))) }
        let r = await ProcessCLIRunner(cli: cli).run(["x"])
        #expect(r.exitCode == 0 && Date().timeIntervalSince(start) >= 0.9)
        let mainRan = Double(ranAt.lines.first ?? "") ?? 99
        #expect(mainRan < 0.7, "the main queue ran only after \(mainRan) s")
    }

    /// A program the CLI leaves running with its stdout never holds the run
    /// open: the output is read for the drain limit after the CLI exited,
    /// and the CLI's code and what it printed come back.
    @Test func aProgramHoldingTheOutputNeverHoldsTheRun() async throws {
        let (dir, cli) = try script("sleep 60 &\necho $! > \"$1\"\necho hi\nexit 3\n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let pidFile = dir.appendingPathComponent("held")
        defer {
            if let s = try? String(contentsOf: pidFile, encoding: .utf8), let pid = pid_t(s.trimmingCharacters(in: .whitespacesAndNewlines)) {
                _ = Darwin.kill(pid, SIGKILL)
            }
        }
        let started = Date()
        let r = await ProcessCLIRunner(cli: cli, limits: .init(start: 10, run: 60, drain: 1)).run([pidFile.path])
        let took = Date().timeIntervalSince(started)
        #expect(r.exitCode == 3 && r.stdout == Data("hi\n".utf8), "\(r)")
        #expect(took < 10, "the run waited \(took) s on the program holding its output")
    }

    /// A CLI that never exits is killed at the run limit, and the run says
    /// so without the output it printed so far.
    @Test func aRunPastItsLimitIsStopped() async throws {
        let (dir, cli) = try script("echo partial\nexec sleep 60\n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let started = Date()
        let r = await ProcessCLIRunner(cli: cli, limits: .init(start: 10, run: 1, drain: 1)).run(["x"])
        let took = Date().timeIntervalSince(started)
        #expect(r.exitCode == ProcessCLIRunner.timedOut && r.stdout.isEmpty
                && r.stderr.contains("did not finish within 1 s"), "\(r)")
        #expect(took < 10, "the run took \(took) s")
    }

    /// The child gets no stdin (it can never wait on the window for input).
    @Test func stdinIsEmpty() async throws {
        let (dir, cli) = try script("if read -r line; then echo got; else echo eof; fi\n")
        defer { try? FileManager.default.removeItem(at: dir) }
        let r = await ProcessCLIRunner(cli: cli).run(["x"])
        #expect(String(decoding: r.stdout, as: UTF8.self) == "eof\n")
    }
}

final class LinesBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _lines: [String] = []
    var exit: Int32 = -1
    var stream: CLIStream?
    func add(_ s: String) { lock.withLock { _lines.append(s) } }
    var lines: [String] { lock.withLock { _lines } }
}
