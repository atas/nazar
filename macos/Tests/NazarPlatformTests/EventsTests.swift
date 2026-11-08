import Darwin
import Foundation
import Testing
@testable import NazarPlatform

// Platform.OnProcessExit and Platform.OnScreenLock (spec 4.3, 4.7).
// Security-relevant: session approvals end when the session root exits, so
// an exit that never fires keeps an approval alive; a watch that fires for
// the wrong process (or twice) ends or confuses the wrong session.
// Nothing here needs a human. The screen-lock tests post only their own
// random dev.nazar.test.* names, never the system's com.apple.screenIsLocked.

/// Counts calls and lets a test wait for them.
final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func hit() { lock.lock(); n += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return n }
    func wait(for want: Int, timeout: TimeInterval = 5) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if count >= want { return true }
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        return count >= want
    }
}

/// A /bin/sleep started with posix_spawn, so Foundation never reaps it:
/// after SIGKILL it stays a zombie (exited, still in the process table)
/// until reap(). Always reaped at the end of the test.
final class RawChild {
    let pid: pid_t
    private var reaped = false

    init(seconds: Int = 60) throws {
        var pid: pid_t = 0
        let argv: [UnsafeMutablePointer<CChar>?] = [strdup("/bin/sleep"), strdup(String(seconds)), nil]
        defer { argv.forEach { free($0) } }
        let rc = posix_spawn(&pid, "/bin/sleep", nil, nil, argv, environ)
        guard rc == 0 else { throw POSIXError(POSIXErrorCode(rawValue: rc) ?? .EIO) }
        self.pid = pid
    }

    /// Kills the child without reaping it.
    func killKeepingZombie() { _ = Darwin.kill(pid, SIGKILL) }

    /// Waits until the kernel reports the child as a zombie.
    func waitUntilZombie(timeout: TimeInterval = 5) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if KernelProc.info(pid)?.zombie == true { return true }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return false
    }

    func reap() {
        guard !reaped else { return }
        reaped = true
        _ = Darwin.kill(pid, SIGKILL)
        var status: Int32 = 0
        _ = waitpid(pid, &status, 0)
    }

    deinit { reap() }
}

@Suite(.serialized) struct ExitWatcherTests {
    let w = ExitWatcher()

    func ref(_ pid: Int32) throws -> ProcessRef {
        ProcessRef(pid: pid, generation: try #require(KernelProc.info(pid)).generation)
    }

    // MARK: core behaviour

    @Test func firesOnceAfterExit() throws {
        let s = try Sleeper()
        let c = Counter()
        w.watch(try ref(s.pid)) { c.hit() }
        Thread.sleep(forTimeInterval: 0.05)
        #expect(c.count == 0)
        s.kill()
        #expect(c.wait(for: 1))
        Thread.sleep(forTimeInterval: 0.1)
        #expect(c.count == 1 && w.pending == 0)
    }

    @Test func firesPromptlyForGoneMismatchedAndPIDOnlyRefs() throws {
        let s = try Sleeper()
        let live = try ref(s.pid)
        let gone = try Sleeper()
        let goneRef = try ref(gone.pid)
        gone.kill()
        for r in [goneRef, ProcessRef(pid: .max, generation: 1), ProcessRef(pid: live.pid, generation: live.generation + 1),
                  ProcessRef(pid: live.pid, generation: 0), ProcessRef(pid: 0, generation: 0)] {
            let c = Counter()
            w.watch(r) { c.hit() }
            #expect(c.wait(for: 1), "ref \(r)")
            Thread.sleep(forTimeInterval: 0.05)
            #expect(c.count == 1)
        }
        s.kill()
    }

    @Test func manyWatchersOnOneProcess() throws {
        let s = try Sleeper()
        let c = Counter()
        let r = try ref(s.pid)
        for _ in 0..<20 { w.watch(r) { c.hit() } }
        s.kill()
        #expect(c.wait(for: 20))
        Thread.sleep(forTimeInterval: 0.1)
        #expect(c.count == 20)
    }

    // MARK: edge and attack cases

    /// A live, matching ref never fires on its own, watch returns at once,
    /// and the watch is counted as pending until the process exits.
    @Test func liveProcessStaysPendingUntilExit() throws {
        let s = try Sleeper()
        let c = Counter()
        let r = try ref(s.pid)
        let start = Date()
        w.watch(r) { c.hit() }
        #expect(Date().timeIntervalSince(start) < 0.5, "watch must not block")
        #expect(w.pending == 1)
        Thread.sleep(forTimeInterval: 0.3)
        #expect(c.count == 0 && w.pending == 1)
        s.kill()
        #expect(c.wait(for: 1))
        Thread.sleep(forTimeInterval: 0.1)
        #expect(c.count == 1 && w.pending == 0)
    }

    /// Our own process is alive for the whole test: watching it must never
    /// fire (a spurious fire would end a live session's approvals).
    @Test func neverFiresForALiveMatchingRef() throws {
        let c = Counter()
        w.watch(try ref(getpid())) { c.hit() }
        Thread.sleep(forTimeInterval: 0.3)
        #expect(c.count == 0 && w.pending == 1)
    }

    /// Recycled PID: the ref names an older (or newer) instance than the
    /// process now holding that PID. The ref's process is gone, so the watch
    /// fires promptly instead of waiting on the PID's new occupant.
    @Test func recycledPIDFiresPromptlyNotOnTheNewOccupant() throws {
        let s = try Sleeper()
        let live = try ref(s.pid)
        for r in [ProcessRef(pid: live.pid, generation: live.generation - 1),
                  ProcessRef(pid: live.pid, generation: 1),
                  ProcessRef(pid: live.pid, generation: .max),
                  ProcessRef(pid: 1, generation: 1)] { // launchd, wrong instance
            let c = Counter()
            w.watch(r) { c.hit() }
            #expect(c.wait(for: 1, timeout: 2), "ref \(r)")
            Thread.sleep(forTimeInterval: 0.05)
            #expect(c.count == 1, "ref \(r)")
        }
        #expect(w.pending == 0)
        // The live process is untouched and still running.
        #expect(KernelProc.info(s.pid).map { !$0.zombie && $0.generation == live.generation } == true)
        s.kill()
    }

    /// Refs that can never name a process: zero, negative and minimum PIDs,
    /// with or without a generation. Each fires exactly once, promptly, and
    /// leaves no pending watch (never a kqueue watch on pid -1 or 0).
    @Test func impossiblePIDsFirePromptlyAndLeaveNothingPending() {
        let refs = [ProcessRef(pid: 0, generation: 1), ProcessRef(pid: -1, generation: 0), ProcessRef(pid: -1, generation: 7),
                    ProcessRef(pid: .min, generation: .max), ProcessRef(pid: .max, generation: 0)]
        for r in refs {
            let c = Counter()
            w.watch(r) { c.hit() }
            #expect(c.wait(for: 1, timeout: 2), "ref \(r)")
            Thread.sleep(forTimeInterval: 0.05)
            #expect(c.count == 1, "ref \(r)")
        }
        #expect(w.pending == 0)
    }

    /// A session root that has exited but not been reaped by its parent is
    /// a zombie: it is gone, so the watch fires promptly.
    @Test func zombieCountsAsExited() throws {
        let child = try RawChild()
        defer { child.reap() }
        let r = try ref(child.pid)
        child.killKeepingZombie()
        #expect(child.waitUntilZombie())
        let c = Counter()
        w.watch(r) { c.hit() }
        #expect(c.wait(for: 1, timeout: 2))
        Thread.sleep(forTimeInterval: 0.1)
        #expect(c.count == 1 && w.pending == 0)
    }

    /// NOTE_EXIT fires at exit, not when the parent reaps: a watch on a
    /// process whose parent never waits for it still fires.
    @Test func firesAtExitBeforeTheParentReaps() throws {
        let child = try RawChild()
        defer { child.reap() }
        let c = Counter()
        w.watch(try ref(child.pid)) { c.hit() }
        Thread.sleep(forTimeInterval: 0.05)
        #expect(c.count == 0)
        child.killKeepingZombie()
        #expect(c.wait(for: 1))
        Thread.sleep(forTimeInterval: 0.1)
        #expect(c.count == 1 && w.pending == 0)
    }

    /// One process exiting fires only its own watches.
    @Test func exitOfAnotherProcessDoesNotFire() throws {
        let a = try Sleeper(), b = try Sleeper()
        let ca = Counter(), cb = Counter()
        w.watch(try ref(a.pid)) { ca.hit() }
        w.watch(try ref(b.pid)) { cb.hit() }
        b.kill()
        #expect(cb.wait(for: 1))
        Thread.sleep(forTimeInterval: 0.2)
        #expect(ca.count == 0 && cb.count == 1 && w.pending == 1)
        a.kill()
        #expect(ca.wait(for: 1))
        Thread.sleep(forTimeInterval: 0.1)
        #expect(ca.count == 1 && cb.count == 1 && w.pending == 0)
    }

    /// The process exits while watch is registering: whichever of the event
    /// and the generation check sees it first, fired runs exactly once.
    @Test func exitRacingTheWatchFiresExactlyOnce() throws {
        for i in 0..<40 {
            let s = try Sleeper()
            let r = try ref(s.pid)
            let c = Counter()
            let pid = s.pid
            let go = DispatchSemaphore(value: 0)
            DispatchQueue.global().async {
                go.wait()
                _ = Darwin.kill(pid, SIGKILL)
            }
            go.signal()
            w.watch(r) { c.hit() }
            #expect(c.wait(for: 1), "iteration \(i)")
            s.kill()
            Thread.sleep(forTimeInterval: 0.02)
            #expect(c.count == 1, "iteration \(i)")
        }
        Thread.sleep(forTimeInterval: 0.1)
        #expect(w.pending == 0)
    }

    /// Many threads watching at once (the Go core calls from any goroutine):
    /// every watch fires exactly once and none is lost or left pending.
    @Test func concurrentWatchesFromManyThreads() throws {
        let s = try Sleeper()
        let live = try ref(s.pid)
        let gone = ProcessRef(pid: live.pid, generation: live.generation + 1)
        let onLive = Counter(), onGone = Counter()
        DispatchQueue.concurrentPerform(iterations: 64) { i in
            if i % 2 == 0 { w.watch(live) { onLive.hit() } } else { w.watch(gone) { onGone.hit() } }
        }
        #expect(onGone.wait(for: 32))
        Thread.sleep(forTimeInterval: 0.1)
        #expect(onLive.count == 0 && onGone.count == 32 && w.pending == 32)
        s.kill()
        #expect(onLive.wait(for: 32))
        Thread.sleep(forTimeInterval: 0.1)
        #expect(onLive.count == 32 && onGone.count == 32 && w.pending == 0)
    }

    /// fired runs without the watcher's lock held: it may watch again and
    /// read pending without deadlocking.
    @Test func firedMayCallBackIntoTheWatcher() throws {
        let s = try Sleeper()
        let r = try ref(s.pid)
        let outer = Counter(), inner = Counter()
        let watcher = w
        watcher.watch(r) {
            _ = watcher.pending
            watcher.watch(ProcessRef(pid: 0, generation: 0)) { inner.hit() }
            outer.hit()
        }
        s.kill()
        #expect(outer.wait(for: 1) && inner.wait(for: 1))
        Thread.sleep(forTimeInterval: 0.1)
        #expect(outer.count == 1 && inner.count == 1 && watcher.pending == 0)
    }

    /// fired runs on a background queue: it needs no run loop on the
    /// calling thread (the Go core's goroutines have none).
    @Test func firesWithoutARunLoop() throws {
        let s = try Sleeper()
        let done = DispatchSemaphore(value: 0)
        w.watch(try ref(s.pid)) { done.signal() }
        s.kill()
        #expect(done.wait(timeout: .now() + 5) == .success)
        let prompt = DispatchSemaphore(value: 0)
        w.watch(ProcessRef(pid: .max, generation: 1)) { prompt.signal() }
        #expect(prompt.wait(timeout: .now() + 2) == .success)
    }
}

@Suite struct ScreenLockWatcherTests {
    static func testName() -> String { "dev.nazar.test.screenlock.\(UUID().uuidString)" }

    static func post(_ name: String) {
        precondition(name != ScreenLockWatcher.systemName, "tests never post the system's screen-lock notification")
        DistributedNotificationCenter.default().postNotificationName(Notification.Name(name), object: nil, userInfo: nil,
                                                                    deliverImmediately: true)
    }

    // MARK: core behaviour

    @Test func everyHandlerRunsOnEveryLock() {
        let name = "dev.nazar.test.screenlock.\(UUID().uuidString)"
        let w = ScreenLockWatcher(name: name)
        let a = Counter(), b = Counter()
        w.register { a.hit() }
        w.register { b.hit() }
        for _ in 0..<2 {
            DistributedNotificationCenter.default().postNotificationName(Notification.Name(name), object: nil, userInfo: nil,
                                                                        deliverImmediately: true)
        }
        #expect(a.wait(for: 2) && b.wait(for: 2))
    }

    // MARK: edge cases

    /// The production default is the system's lock notification (spec 4.3).
    @Test func defaultNameIsTheSystemLockNotification() {
        #expect(ScreenLockWatcher.systemName == "com.apple.screenIsLocked")
    }

    /// One lock runs each handler once, not once per registration or per
    /// watcher instance.
    @Test func oneLockRunsEachHandlerExactlyOnce() {
        let name = Self.testName()
        let w = ScreenLockWatcher(name: name)
        let a = Counter()
        w.register { a.hit() }
        Self.post(name)
        #expect(a.wait(for: 1))
        Thread.sleep(forTimeInterval: 0.3)
        #expect(a.count == 1)
        withExtendedLifetime(w) {}
    }

    /// Other notification names (e.g. screenIsUnlocked, another watcher's
    /// name) never run the handlers.
    @Test func otherNamesDoNotRunHandlers() {
        let mine = Self.testName(), other = Self.testName()
        let w = ScreenLockWatcher(name: mine)
        let o = ScreenLockWatcher(name: other)
        let a = Counter(), b = Counter()
        w.register { a.hit() }
        o.register { b.hit() }
        Self.post(other)
        Self.post(mine + ".unlocked")
        #expect(b.wait(for: 1))
        Thread.sleep(forTimeInterval: 0.3)
        #expect(a.count == 0 && b.count == 1)
        withExtendedLifetime((w, o)) {}
    }

    /// A handler registered after a lock does not see that lock (no replay),
    /// only later ones.
    @Test func lateRegistrationSeesOnlyLaterLocks() {
        let name = Self.testName()
        let w = ScreenLockWatcher(name: name)
        let early = Counter(), late = Counter()
        w.register { early.hit() }
        Self.post(name)
        #expect(early.wait(for: 1))
        w.register { late.hit() }
        Thread.sleep(forTimeInterval: 0.2)
        #expect(late.count == 0)
        Self.post(name)
        #expect(early.wait(for: 2) && late.wait(for: 1))
        Thread.sleep(forTimeInterval: 0.2)
        #expect(early.count == 2 && late.count == 1)
    }

    /// A slow handler must not hold up the others (or the next lock).
    @Test func slowHandlerDoesNotBlockOthers() {
        let name = Self.testName()
        let w = ScreenLockWatcher(name: name)
        let slow = Counter(), fast = Counter()
        w.register { Thread.sleep(forTimeInterval: 3); slow.hit() }
        w.register { fast.hit() }
        Self.post(name)
        #expect(fast.wait(for: 1, timeout: 1.5))
        #expect(slow.count == 0)
        withExtendedLifetime(w) {}
    }

    /// register returns at once, also from inside a handler.
    @Test func registerFromAHandlerDoesNotDeadlock() {
        let name = Self.testName()
        let w = ScreenLockWatcher(name: name)
        let outer = Counter(), inner = Counter()
        w.register {
            w.register { inner.hit() }
            outer.hit()
        }
        let start = Date()
        w.register {}
        #expect(Date().timeIntervalSince(start) < 0.5)
        Self.post(name)
        #expect(outer.wait(for: 1))
        Self.post(name)
        #expect(outer.wait(for: 2) && inner.wait(for: 1))
    }

    /// Handlers run off the posting thread: no run loop is needed on the
    /// thread that registered them (the Go core's goroutines have none).
    @Test func handlersRunWithoutARunLoopOnTheRegisteringThread() {
        let name = Self.testName()
        let w = ScreenLockWatcher(name: name)
        let done = DispatchSemaphore(value: 0)
        w.register { done.signal() }
        Self.post(name)
        #expect(done.wait(timeout: .now() + 5) == .success)
        withExtendedLifetime(w) {}
    }

    /// A released watcher stops listening: no handler runs after deinit.
    @Test func releasedWatcherStopsListening() {
        let name = Self.testName()
        let a = Counter()
        do {
            let w = ScreenLockWatcher(name: name)
            w.register { a.hit() }
            Self.post(name)
            #expect(a.wait(for: 1))
        }
        Self.post(name)
        Thread.sleep(forTimeInterval: 0.3)
        _ = a.wait(for: 2, timeout: 0.3)
        #expect(a.count == 1)
    }
}
