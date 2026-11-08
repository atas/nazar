import Foundation

// Nazar UI.app is a thin client of the CLI (spec 6.1): every read and every
// action runs the `nazar` CLI of the installed agent (CLILocator), by
// absolute path, with --json, only after checking its signature
// (CLIRequirement), and shows what it printed. Nothing here reads
// config.yaml, opens a socket or calls the Go core.

/// What one CLI run printed and how it ended.
public struct CLIResult: Equatable, Sendable {
    public var exitCode: Int32
    public var stdout: Data
    public var stderr: String
    public init(exitCode: Int32, stdout: Data = Data(), stderr: String = "") {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

/// Bytes a run writes to the CLI's stdin before closing it: the value of
/// `nazar secret add`, the one command that reads stdin. It owns
/// one buffer, copied once from the text; the runner writes from it in
/// place (never into a Data or String) once the running CLI passed the
/// check, and it is zeroed (memset_s, never elided) after the write, on a
/// refusal, on wipe() and when dropped. It prints as "<hidden>" and
/// mirrors nothing; it is not Codable, Equatable or Hashable.
public final class CLIInput: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let lock = NSLock()
    private let storage: UnsafeMutableRawBufferPointer
    private var count: Int

    public init(_ text: String) {
        // Copied straight from the text's own storage, or byte by byte (a
        // bridged NSString): never through another String (withUTF8 would
        // make one, freed unwiped).
        let u = text.utf8
        let n = u.count
        storage = .allocate(byteCount: max(n, 1), alignment: 1)
        count = n
        if u.withContiguousStorageIfAvailable({ storage.copyMemory(from: UnsafeRawBufferPointer($0)) }) == nil {
            for (i, b) in u.enumerated() { storage[i] = b }
        }
    }

    deinit {
        wipe()
        storage.deallocate()
    }

    public var isWiped: Bool { lock.withLock { count == 0 } }

    /// Zeroes the bytes. During a run's write it waits for the write to end
    /// (the CLI read the value or exited), so the CLI never gets half a
    /// value: call it off the main thread.
    public func wipe() { lock.withLock { zero() } }

    /// Runs body over the bytes once, then wipes them; later calls see none.
    func drain<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        lock.lock()
        defer { zero(); lock.unlock() }
        return try body(UnsafeRawBufferPointer(rebasing: storage[0..<count]))
    }

    private func zero() {
        _ = memset_s(storage.baseAddress, storage.count, 0, storage.count)
        count = 0
    }

    public var description: String { "<hidden>" }
    public var debugDescription: String { "<hidden>" }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}

/// A running `--follow` command; stop() ends it (SIGTERM, which the CLI
/// treats as the user leaving the stream).
public protocol CLIStream: AnyObject, Sendable {
    func stop()
}

/// Runs the CLI. Implementations never block the main thread: run is async
/// and stream reports on a background queue. (The CLI may be waiting on a
/// login prompt the agent shows: the window must stay responsive.)
public protocol CLIRunner: Sendable {
    /// Runs args; input, when given, is written to the CLI's stdin and then
    /// stdin is closed (otherwise stdin is /dev/null).
    func run(_ args: [String], input: CLIInput?) async -> CLIResult
    /// Starts args and calls onLine for every stdout line (without its
    /// newline), then onExit once with the exit code.
    func stream(_ args: [String], onLine: @escaping @Sendable (Data) -> Void,
                onExit: @escaping @Sendable (Int32) -> Void) -> CLIStream
}

extension CLIRunner {
    public func run(_ args: [String]) async -> CLIResult { await run(args, input: nil) }
}

/// Runs the nazar CLI as a child process of Nazar UI.app, so the agent's
/// audit log records the caller chain `Nazar UI → nazar` (spec 6.1). The
/// app's runner is always `.verified`: every run starts the CLI suspended,
/// checks the RUNNING process against the requirement (CLIRequirement) and
/// only then lets it run, so a file swapped between the locator's check and
/// the start is never run (it is killed before its first instruction).
/// It also requires the child to have been started as the CLI itself
/// (checkStarted), so a `#!` script naming the genuine CLI as its
/// interpreter is refused too.
public final class ProcessCLIRunner: CLIRunner, @unchecked Sendable {
    public let cli: URL
    /// What every run checks before the CLI runs; nil only for the tests'
    /// unchecked runner (internal init), never in the app.
    let requirement: CLIRequirement?
    /// The environment every run gets: HOME (the CLI finds ~/.nazar under
    /// it) and a fixed PATH; nothing else from the
    /// app's own environment (no NAZAR_* overrides).
    public let environment: [String: String]
    /// The longest stdout a run may print; more is cut (the CLI's replies
    /// are far smaller).
    public static let maxOutput = 16 << 20
    /// The longest line a stream may print; a longer one is dropped.
    public static let maxLine = 4 << 20
    /// Exit codes of runs that never ran the CLI.
    public static let cannotRun: Int32 = 127
    public static let refusedSignature: Int32 = 126
    /// The exit code of a run whose CLI was killed for taking too long.
    public static let timedOut: Int32 = 124

    /// How long a run may wait on its CLI; no wait is unbounded.
    struct Limits: Sendable {
        /// From the resume to the CLI's first system call; a CLI that has
        /// not started by then is killed and started once more (twice:
        /// cannotRun).
        var start: TimeInterval
        /// From the start to the CLI's exit; a CLI still running then is
        /// killed (timedOut). Longer than any prompt it may wait on (a
        /// rule's timeout is at most 10 minutes).
        var run: TimeInterval
        /// How long the output is still read once the CLI exited (a program
        /// it started may hold the pipe open).
        var drain: TimeInterval
        static let app = Limits(start: 30, run: 15 * 60, drain: 2)
    }
    let limits: Limits

    /// The check of the started (suspended) child: nil when it may run,
    /// otherwise why not. Always CodeSignature.checkRunning in the app; the
    /// tests replace it (internal init) to hold the child suspended for a
    /// while and prove that nothing ran before the answer.
    typealias RunningCheck = @Sendable (pid_t, CLIRequirement) -> String?
    let checkRunning: RunningCheck
    /// Lets the checked child run: always SpawnedChild.resume in the app;
    /// the tests replace it to lose the resume.
    typealias Resume = @Sendable (SpawnedChild) -> Void
    let resumeChild: Resume

    /// The app's runner: cli runs only when its running process satisfies
    /// requirement.
    public convenience init(cli: URL, requirement: CLIRequirement, home: String = CLILocator.userHome()) {
        self.init(cli: cli, requirement: requirement, home: home,
                  checkRunning: { CodeSignature.checkRunning(pid: $0, $1) })
    }

    /// Tests only: the app's runner with its running-process check, its
    /// resume or its limits replaced.
    init(cli: URL, requirement: CLIRequirement, home: String = CLILocator.userHome(), checkRunning: @escaping RunningCheck,
         resume: @escaping Resume = { $0.resume() }, limits: Limits = .app) {
        self.cli = cli
        self.requirement = requirement
        self.checkRunning = checkRunning
        resumeChild = resume
        self.limits = limits
        environment = Self.environment(home: home)
    }

    /// Tests only (shell scripts stand in for the CLI and carry no
    /// signature): no check. Internal, so the app can't make one.
    init(cli: URL, home: String = NSHomeDirectory(), limits: Limits = .app) {
        self.cli = cli
        requirement = nil
        checkRunning = { _, _ in "no requirement" }
        resumeChild = { $0.resume() }
        self.limits = limits
        environment = Self.environment(home: home)
    }

    static func environment(home: String) -> [String: String] {
        ["HOME": home, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"]
    }

    /// A started child, or the result a run reports instead.
    enum Started {
        case child(SpawnedChild)
        case failed(CLIResult)
    }

    /// Starts args: spawned (suspended when checked), checked, resumed.
    /// With input, the child's stdin is a pipe whose write end the child
    /// keeps (SpawnedChild.writeInput); a refused child's is closed unwritten.
    /// A checked child that does not start (resumed) is killed and the CLI
    /// is started once more, from the spawn and the check on.
    func start(_ args: [String], input: Bool) -> Started {
        if let s = startOnce(args, input: input) { return s }
        if let s = startOnce(args, input: input) { return s }
        return .failed(CLIResult(exitCode: Self.cannotRun,
                                  stderr: "\(cli.path) did not start within \(Int(limits.start)) s, twice; it was stopped"))
    }

    /// One start; nil when the checked child did not start (it was killed).
    private func startOnce(_ args: [String], input: Bool) -> Started? {
        let child: SpawnedChild
        do {
            child = try SpawnedChild.spawn(cli.path, args: args, environment: environment, suspended: requirement != nil, input: input)
        } catch {
            return .failed(CLIResult(exitCode: Self.cannotRun, stderr: "cannot run \(cli.path): \(error)"))
        }
        if let requirement {
            if let why = checkRunning(child.pid, requirement) ?? checkStarted(child, args) {
                child.kill()
                _ = child.waitExit()
                child.closeInput()
                return .failed(CLIResult(exitCode: Self.refusedSignature,
                                          stderr: "not running \(cli.path): it is not the nazar CLI this app trusts (\(why))"))
            }
            guard resumed(child) else {
                child.kill()
                _ = child.waitExit()
                child.closeInput()
                return nil
            }
        }
        return .child(child)
    }

    /// Resumes the checked child and waits until it has run
    /// (SpawnedChild.hasRun); false when it still has not by limits.start.
    /// SIGCONT is what ends the hold POSIX_SPAWN_START_SUSPENDED puts on the
    /// new task (xnu: SIGCONT's default action calls task_resume_internal);
    /// the app has nothing stronger (pid_resume only undoes pid_suspend and,
    /// like it, is refused to an unprivileged caller; task_resume needs the
    /// child's task port). Other software may hold a new process too (a
    /// security scanner holds a binary it has not seen for a moment after
    /// exec), and once a resumed child never left _dyld_start: a run waited
    /// on it for hours. The resume is sent once (another SIGCONT would also
    /// end such a scanner's hold before its verdict), and the child is never
    /// waited on past the limit.
    func resumed(_ child: SpawnedChild) -> Bool {
        let deadline = Date().addingTimeInterval(limits.start)
        resumeChild(child)
        var pause: useconds_t = 100
        while !child.hasRun() {
            if Date() >= deadline { return false }
            usleep(pause)
            pause = min(pause * 2, 20_000)
        }
        return true
    }

    /// Why the suspended child was not started as the CLI itself (nil: it
    /// was): its exec path and argv (KERN_PROCARGS2) must be exactly cli.path
    /// and [cli.path] + args. A `#!` script at the path is started as its
    /// interpreter, whose running code may well be the genuine CLI and pass
    /// checkRunning; the kernel then puts the interpreter, the script's own
    /// arguments and the script's path in front of args. The child has not
    /// run, so what is read is what the kernel laid out; the check can't be
    /// replaced by the tests. Compared byte for byte (String's == would
    /// treat canonically equivalent Unicode as equal).
    func checkStarted(_ child: SpawnedChild, _ args: [String]) -> String? {
        guard let got = child.startedAs() else { return "can't read how the started process was started" }
        func same(_ a: String, _ b: String) -> Bool { a.utf8.elementsEqual(b.utf8) }
        guard same(got.path, cli.path) else { return "it was started as \(got.path), not as itself (a script names its interpreter)" }
        let want = [cli.path] + args
        guard got.argv.count == want.count, zip(got.argv, want).allSatisfy(same) else {
            return "it was started with other arguments than the app gave it"
        }
        return nil
    }

    /// Runs args. Input is written only to a child that passed the check
    /// and was resumed, on its own queue (a value larger than the pipe
    /// buffer never blocks the readers); then stdin is closed, so the CLI
    /// reads to EOF. It is wiped by the time run returns, written or not.
    /// A CLI still running after limits.run is killed and the run reports
    /// timedOut, without its output; the output is read for at most
    /// limits.drain after the CLI exited.
    public func run(_ args: [String], input: CLIInput?) async -> CLIResult {
        await withCheckedContinuation { (k: CheckedContinuation<CLIResult, Never>) in
            DispatchQueue.global().async {
                let child: SpawnedChild
                switch self.start(args, input: input != nil) {
                case .failed(let r):
                    input?.wipe()
                    k.resume(returning: r)
                    return
                case .child(let c): child = c
                }
                let group = DispatchGroup()
                if let input {
                    group.enter()
                    DispatchQueue.global().async {
                        child.writeInput(input)
                        group.leave()
                    }
                }
                let killAt = DispatchTime.now() + self.limits.run
                let readUntil = Deadline(killAt + self.limits.drain)
                // Weak: a finished run's child (and its pipes) is not kept
                // until the deadline.
                DispatchQueue.global().asyncAfter(deadline: killAt) { [weak child] in child?.kill() }
                let stdout = Collected(), stderr = Collected()
                group.enter()
                DispatchQueue.global().async {
                    stdout.data = Self.readAll(child.stdout, limit: Self.maxOutput, until: readUntil)
                    group.leave()
                }
                group.enter()
                DispatchQueue.global().async {
                    stderr.data = Self.readAll(child.stderr, limit: 1 << 20, until: readUntil)
                    group.leave()
                }
                let code = child.waitExit()
                readUntil.tighten(.now() + self.limits.drain)
                group.wait()
                if child.wasKilled {
                    k.resume(returning: CLIResult(exitCode: Self.timedOut,
                                                  stderr: "nazar did not finish within \(Int(self.limits.run)) s; it was stopped"))
                    return
                }
                k.resume(returning: CLIResult(exitCode: code, stdout: stdout.data,
                                              stderr: String(decoding: stderr.data, as: UTF8.self)))
            }
        }
    }

    /// Reads until EOF, keeping at most limit bytes (the rest is drained so
    /// the child never blocks on a full pipe); with a deadline, never past
    /// it (a program the CLI started may keep the pipe open after the CLI
    /// exited).
    static func readAll(_ h: FileHandle, limit: Int, until deadline: Deadline? = nil) -> Data {
        guard let deadline else {
            var data = Data()
            while true {
                let chunk = h.availableData
                if chunk.isEmpty { return data }
                if data.count < limit { data.append(chunk.prefix(limit - data.count)) }
            }
        }
        let fd = h.fileDescriptor
        var data = Data()
        var buf = [UInt8](repeating: 0, count: 64 << 10)
        while true {
            // Polled in slices, so a deadline moved earlier is seen.
            let now = DispatchTime.now(), end = deadline.value
            guard now < end else { return data }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ms = Int32(min(250, (end.uptimeNanoseconds - now.uptimeNanoseconds) / 1_000_000 + 1))
            let ready = poll(&p, 1, ms)
            if ready < 0 && errno != EINTR { return data }
            if ready <= 0 { continue }
            let n = buf.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { return data }
            if data.count < limit { data.append(contentsOf: buf[0..<min(n, limit - data.count)]) }
        }
    }

    public func stream(_ args: [String], onLine: @escaping @Sendable (Data) -> Void,
                       onExit: @escaping @Sendable (Int32) -> Void) -> CLIStream {
        let s = ProcessStream()
        DispatchQueue.global().async {
            let child: SpawnedChild
            switch self.start(args, input: false) {
            case .failed(let r): onExit(r.exitCode); return
            case .child(let c): child = c
            }
            // stderr is not shown for a stream; drain it so the child never blocks.
            DispatchQueue.global().async { _ = Self.readAll(child.stderr, limit: 0) }
            s.attach(child)
            var buf = Data()
            // True while the rest of a line longer than maxLine is being
            // thrown away: it is never delivered, not even in pieces.
            var dropping = false
            while true {
                let chunk = child.stdout.availableData
                if chunk.isEmpty { break }
                buf.append(chunk)
                while let nl = buf.firstIndex(of: 0x0A) {
                    let line = buf[buf.startIndex..<nl]
                    if !dropping && line.count <= Self.maxLine { onLine(Data(line)) }
                    dropping = false
                    buf.removeSubrange(buf.startIndex...nl)
                }
                if buf.count > Self.maxLine {
                    buf.removeAll()
                    dropping = true
                }
            }
            onExit(child.waitExit())
        }
        return s
    }
}

/// Output collected by a reader thread; the dispatch group orders the
/// write before the read.
final class Collected: @unchecked Sendable {
    var data = Data()
}

/// When a run's readers stop reading: moved earlier once the CLI exited.
final class Deadline: @unchecked Sendable {
    private let lock = NSLock()
    private var at: DispatchTime
    init(_ at: DispatchTime) { self.at = at }
    var value: DispatchTime { lock.withLock { at } }
    func tighten(_ t: DispatchTime) { lock.withLock { if t < at { at = t } } }
}

/// A running `--follow` command. stop() before the child started is
/// remembered: it is terminated as soon as it is attached.
final class ProcessStream: CLIStream, @unchecked Sendable {
    private let lock = NSLock()
    private var child: SpawnedChild?
    private var stopped = false

    func attach(_ c: SpawnedChild) {
        let stopNow: Bool = lock.withLock {
            child = c
            return stopped
        }
        if stopNow { c.terminate() }
    }

    func stop() {
        let c: SpawnedChild? = lock.withLock {
            stopped = true
            return child
        }
        c?.terminate()
    }
}

/// A child started with posix_spawn: stdin is /dev/null (or, with input, a
/// pipe whose write end only the app holds), stdout and stderr are pipes,
/// no other descriptor of the app is inherited
/// (POSIX_SPAWN_CLOEXEC_DEFAULT), and every signal is at its default,
/// unblocked (POSIX_SPAWN_SETSIGDEF, POSIX_SPAWN_SETSIGMASK). Started suspended
/// (POSIX_SPAWN_START_SUSPENDED) it has not run an instruction until
/// resume(). The pid is never signalled once the child is reaped: waitExit
/// waits without reaping (waitid WNOWAIT), marks it exited under the lock,
/// and only then reaps it, so a pid the system gave to another process is
/// never signalled.
final class SpawnedChild: @unchecked Sendable {
    let pid: pid_t
    let stdout: FileHandle
    let stderr: FileHandle
    private let lock = NSLock()
    private var exited = false
    private var status: Int32 = 0
    /// The write end of the child's stdin pipe; -1 without input or once closed.
    private var inputFD: Int32

    private init(pid: pid_t, stdout: FileHandle, stderr: FileHandle, inputFD: Int32) {
        self.pid = pid
        self.stdout = stdout
        self.stderr = stderr
        self.inputFD = inputFD
    }

    struct SpawnError: Error, CustomStringConvertible {
        let errno: Int32
        var description: String { String(cString: strerror(errno)) }
    }

    /// With input, stdin is a pipe: both ends close-on-exec at once (no
    /// other child of the app gets one), the write end never raises SIGPIPE
    /// (a CLI that exits unread gives EPIPE), and the read end is closed here
    /// after the spawn, so the CLI's exit ends any write.
    static func spawn(_ path: String, args: [String], environment: [String: String], suspended: Bool, input: Bool = false) throws -> SpawnedChild {
        var outFDs: [Int32] = [-1, -1], errFDs: [Int32] = [-1, -1], inFDs: [Int32] = [-1, -1]
        guard pipe(&outFDs) == 0 else { throw SpawnError(errno: errno) }
        guard pipe(&errFDs) == 0 else {
            let e = errno
            close(outFDs[0]); close(outFDs[1])
            throw SpawnError(errno: e)
        }
        if input {
            guard pipe(&inFDs) == 0 else {
                let e = errno
                close(outFDs[0]); close(outFDs[1]); close(errFDs[0]); close(errFDs[1])
                throw SpawnError(errno: e)
            }
            _ = fcntl(inFDs[0], F_SETFD, FD_CLOEXEC)
            _ = fcntl(inFDs[1], F_SETFD, FD_CLOEXEC)
            guard fcntl(inFDs[1], F_SETNOSIGPIPE, 1) == 0 else {
                let e = errno
                [outFDs[0], outFDs[1], errFDs[0], errFDs[1], inFDs[0], inFDs[1]].forEach { close($0) }
                throw SpawnError(errno: e)
            }
        }
        var fa: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fa)
        defer { posix_spawn_file_actions_destroy(&fa) }
        if input {
            posix_spawn_file_actions_adddup2(&fa, inFDs[0], 0)
        } else {
            posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0)
        }
        posix_spawn_file_actions_adddup2(&fa, outFDs[1], 1)
        posix_spawn_file_actions_adddup2(&fa, errFDs[1], 2)
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }
        // Every signal at its default and none blocked: the child must not
        // inherit an ignored SIGTERM (stop() relies on it) or a mask.
        var none = sigset_t(), all = sigset_t()
        sigemptyset(&none)
        sigfillset(&all)
        posix_spawnattr_setsigmask(&attr, &none)
        posix_spawnattr_setsigdefault(&attr, &all)
        var flags = Int32(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF)
        if suspended { flags |= Int32(POSIX_SPAWN_START_SUSPENDED) }
        posix_spawnattr_setflags(&attr, Int16(flags))
        let argv = ([path] + args).map { strdup($0) } + [nil]
        let envp = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer {
            argv.forEach { free($0) }
            envp.forEach { free($0) }
        }
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, path, &fa, &attr, argv, envp)
        close(outFDs[1])
        close(errFDs[1])
        if input { close(inFDs[0]) }
        guard rc == 0 else {
            close(outFDs[0]); close(errFDs[0])
            if input { close(inFDs[1]) }
            throw SpawnError(errno: rc)
        }
        return SpawnedChild(pid: pid, stdout: FileHandle(fileDescriptor: outFDs[0], closeOnDealloc: true),
                            stderr: FileHandle(fileDescriptor: errFDs[0], closeOnDealloc: true), inputFD: inFDs[1])
    }

    /// Writes input to the child's stdin straight from its buffer, then
    /// closes stdin; the input is wiped either way. A write error other than
    /// EINTR (EPIPE: the CLI exited without reading) ends the write.
    func writeInput(_ input: CLIInput) {
        let fd = lock.withLock { inputFD }
        guard fd >= 0 else {
            input.wipe()
            return
        }
        input.drain { buf in
            guard let base = buf.baseAddress else { return }
            var done = 0
            while done < buf.count {
                let n = Darwin.write(fd, base + done, buf.count - done)
                if n > 0 {
                    done += n
                } else if n < 0 && errno == EINTR {
                    continue
                } else {
                    break
                }
            }
        }
        closeInput()
    }

    /// Closes the write end of the child's stdin, once.
    func closeInput() {
        lock.withLock {
            if inputFD >= 0 {
                close(inputFD)
                inputFD = -1
            }
        }
    }

    /// How the child was started, as the kernel recorded it
    /// (KERN_PROCARGS2): the path of the program it executed and its argv;
    /// nil once it was reaped (its pid may be another process's), or when it
    /// can't be read or is not UTF-8. Read under the lock, so the child
    /// can't be reaped meanwhile.
    func startedAs() -> (path: String, argv: [String])? {
        lock.withLock { exited ? nil : Self.processArguments(pid) }
    }

    static func processArguments(_ pid: pid_t) -> (path: String, argv: [String])? {
        var argmax: Int32 = 0
        var size = MemoryLayout<Int32>.size
        var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
        guard sysctl(&mib, 2, &argmax, &size, nil, 0) == 0, argmax > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: Int(argmax))
        size = buf.count
        mib = [CTL_KERN, KERN_PROCARGS2, pid]
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size >= 4, size <= buf.count else { return nil }
        // int argc, the exec path, NUL padding, then argc NUL-terminated strings.
        let argc = buf.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        var i = 4
        func next() -> String? {
            guard i < size, let end = buf[i..<size].firstIndex(of: 0) else { return nil }
            defer { i = end + 1 }
            return String(validating: buf[i..<end], as: UTF8.self)
        }
        guard argc >= 0, let path = next() else { return nil }
        while i < size && buf[i] == 0 { i += 1 }
        var argv: [String] = []
        for _ in 0..<argc {
            guard let a = next() else { return nil }
            argv.append(a)
        }
        return (path, argv)
    }

    /// Lets a suspended child run (SIGCONT; see ProcessCLIRunner.resumed).
    func resume() { signal(SIGCONT) }

    /// Kills the child at once (SIGKILL), unless it already exited.
    func kill() { signal(SIGKILL) }

    /// Asks the child to end (SIGTERM, which the CLI treats as the user
    /// leaving a stream), unless it already exited.
    func terminate() { signal(SIGTERM) }

    /// Whether kill() was sent before the child was reaped: set under the
    /// lock before the signal, so it is seen by anyone waitExit returned to.
    var wasKilled: Bool { lock.withLock { killed } }
    private var killed = false

    private func signal(_ sig: Int32) {
        lock.withLock {
            guard !exited else { return }
            if sig == SIGKILL { killed = true }
            _ = Darwin.kill(pid, sig)
        }
    }

    /// Whether the child has run: made a system call (dyld makes dozens
    /// before main; a child still suspended has made none) or exited. Read
    /// under the lock, so a reaped pid is never read.
    func hasRun() -> Bool {
        lock.withLock {
            if exited { return true }
            var info = proc_taskinfo()
            let size = Int32(MemoryLayout<proc_taskinfo>.size)
            if proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, size) == size {
                return info.pti_syscalls_unix > 0 || info.pti_syscalls_mach > 0
            }
            // No task to read: a zombie (it exited), or not readable.
            var si = siginfo_t()
            return waitid(P_PID, id_t(pid), &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == pid
        }
    }

    /// Blocks until the child exits and returns its exit code (128 + n
    /// for signal n). Safe to call more than once.
    func waitExit() -> Int32 {
        if let done = lock.withLock({ exited ? status : nil }) { return done }
        var info = siginfo_t()
        while waitid(P_PID, id_t(pid), &info, WEXITED | WNOWAIT) != 0 && errno == EINTR {}
        return lock.withLock {
            if exited { return status }
            var st: Int32 = 0
            while waitpid(pid, &st, 0) == -1 && errno == EINTR {}
            let sig = st & 0x7f
            status = sig == 0 ? (st >> 8) & 0xff : 128 + sig
            exited = true
            return status
        }
    }
}
