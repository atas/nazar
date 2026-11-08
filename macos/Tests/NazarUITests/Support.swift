import Foundation
import Testing
@testable import NazarUI

/// The fixtures: the real CLI's --json output (cmd/nazar TestUIFixtures).
enum Fixture {
    static let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures")

    static func data(_ name: String) throws -> Data {
        try Data(contentsOf: dir.appendingPathComponent(name))
    }

    /// The stdout of one recorded command (name without .jsonl).
    static func stdout(_ name: String) throws -> Data { try data(name + ".jsonl") }

    static func result(_ name: String, exit: Int32) throws -> CLIResult {
        CLIResult(exitCode: exit, stdout: try stdout(name))
    }
}

/// A CLIRunner that answers from scripted results and records every argv.
/// Nothing is run.
final class FakeCLIRunner: CLIRunner, @unchecked Sendable {
    private let lock = NSLock()
    private var answers: [(match: [String], result: CLIResult)] = []
    private var _calls: [[String]] = []
    private var _inputs: [Data?] = []
    /// Lines each stream started with these leading arguments prints.
    var streamLines: [String: [Data]] = [:]
    var streamExit: Int32 = 0
    /// When set, a stream ends only after stop(), a little later, with 143
    /// (128 + SIGTERM), as the real runner's child does.
    var exitOnStop = false
    /// How long run() takes after it recorded the call (a CLI call is not
    /// instant; `calls` shows one in flight).
    var callDelay: Duration = .zero
    private(set) var stopped = 0

    var calls: [[String]] { lock.lock(); defer { lock.unlock() }; return _calls }
    /// The input of every run, in the order of calls' runs (nil: none). Tests only.
    var inputs: [Data?] { lock.lock(); defer { lock.unlock() }; return _inputs }

    /// Answers argv that starts with ["--json"] + prefix with result
    /// (the first match wins; answers are reused).
    func on(_ prefix: [String], _ result: CLIResult) {
        lock.lock()
        answers.append((["--json"] + prefix, result))
        lock.unlock()
    }

    func run(_ args: [String], input: CLIInput?) async -> CLIResult {
        let given = input?.drain { Data($0) }
        let delay: Duration = lock.withLock { _calls.append(args); _inputs.append(given); return callDelay }
        try? await Task.sleep(for: delay)
        return lock.withLock {
            for a in answers where args.starts(with: a.match) { return a.result }
            return CLIResult(exitCode: 1, stderr: "FakeCLIRunner: no answer for \(args)")
        }
    }

    func stream(_ args: [String], onLine: @escaping @Sendable (Data) -> Void,
                onExit: @escaping @Sendable (Int32) -> Void) -> CLIStream {
        lock.lock()
        _calls.append(args)
        let lines = streamLines[args.dropFirst().joined(separator: " ")] ?? []
        let code = streamExit
        let late = exitOnStop
        lock.unlock()
        var onStop: (@Sendable () -> Void)?
        if late {
            onStop = { DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { onExit(143) } }
        }
        let s = FakeStream(self, onStop: onStop)
        DispatchQueue.global().async {
            for l in lines { onLine(l) }
            if !late { onExit(code) }
        }
        return s
    }

    fileprivate func noteStop() { lock.lock(); stopped += 1; lock.unlock() }
}

final class FakeStream: CLIStream, @unchecked Sendable {
    let runner: FakeCLIRunner
    private let lock = NSLock()
    private var onStop: (@Sendable () -> Void)?
    init(_ r: FakeCLIRunner, onStop: (@Sendable () -> Void)? = nil) {
        runner = r
        self.onStop = onStop
    }
    func stop() {
        runner.noteStop()
        let end: (@Sendable () -> Void)? = lock.withLock { defer { onStop = nil }; return onStop }
        end?()
    }
}

/// How busy the machine is now: 1 plus twice the load per core, at most 30
/// (as in NazarPlatformTests). A test whose steps must fit inside a short
/// interval stretches the interval by it, so a stall doesn't fail it.
func loadFactor() -> Double {
    var load = [0.0]
    guard getloadavg(&load, 1) == 1 else { return 30 }
    return min(30, 1 + 2 * load[0] / Double(ProcessInfo.processInfo.activeProcessorCount))
}

/// Waits (letting the main queue run) until cond holds, at most 30 s: it
/// stops as soon as it does, so the limit only costs time on a failure.
@MainActor
func eventually(_ cond: @MainActor () -> Bool) async -> Bool {
    let end = Date().addingTimeInterval(30)
    while Date() < end {
        if cond() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return cond()
}
