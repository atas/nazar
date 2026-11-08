import Darwin
import Dispatch
import Foundation

/// platform.Exec on macOS (secrets design 6.3 step 6, D8, D10): one kqueue
/// with an EVFILT_PROC NOTE_EXEC|NOTE_EXIT knote per watched process,
/// drained on one serial queue by a read source on the kqueue and by every
/// call.
///
/// - At every exec the process is read before the next event is taken
///   (ProcessResolver.read: KERN_PROCARGS2 first, then the path, the cwd,
///   the live code identity, the start time checked before and after),
///   every fired of that process gets the record, and the environment
///   parsed from that same buffer is kept until the next exec, the exit or
///   the last cancel. It is never read again later: npm zero-fills that
///   area about 40 ms after exec (spike S12).
/// - A watch is armed first and checked second, as ExitWatcher does: if
///   the ref's instance is still the PID's live occupant after EV_ADD, the
///   knote is on that instance. A knote belongs to the process, so a later
///   occupant of the PID never fires it.
/// - environment(_:) and watch drain the kqueue first, on the same queue.
///   The kernel posts NOTE_EXEC inside execve, before the new image runs,
///   so an exec that happened before the call is read before the answer:
///   never a stale environment. (libdispatch's process source could not
///   promise that: it takes events on its own thread.)
/// - Two execs before the queue takes the first are one event (kqueue
///   coalesces), read after the later: every record describes the image
///   the process runs when read.
/// - fired runs on the queue and must return at once (the bridge copies the
///   record to Go and queues it there); it is never called for a token
///   after cancel(token) returned.
public final class ExecWatcher: @unchecked Sendable {
    public typealias Fired = @Sendable (ProcessRecord) -> Void

    private struct Watch {
        let ref: ProcessRef
        var fired: [UInt64: Fired]
        var environment: [String]? // as read at the last exec; nil before one, or hidden
    }

    private let queue = DispatchQueue(label: "dev.nazar.exec-watcher")
    /// The read source on the kqueue (internal: a test holds it to show
    /// that environment(_:) drains by itself).
    let source: DispatchSourceRead
    private let kq: Int32
    private let resolver: ProcessResolver
    private var watches: [Int32: Watch] = [:] // by PID; on the queue only
    private var pidOf: [UInt64: Int32] = [:] // token → PID; on the queue only

    /// nil when no kqueue can be made: the bridge then offers no Exec and
    /// late-env is refused (secrets design 6.3, D8).
    public init?(resolver: ProcessResolver = ProcessResolver()) {
        let kq = kqueue()
        guard kq >= 0 else { return nil }
        self.kq = kq
        self.resolver = resolver
        source = DispatchSource.makeReadSource(fileDescriptor: kq, queue: queue)
        source.setEventHandler { [weak self] in self?.drain() }
        source.setCancelHandler { close(kq) }
        source.resume()
    }

    deinit { source.cancel() }

    /// Watches the live instance ref names; .noProcess when ref is not a
    /// full ref or not the PID's live occupant.
    public func watch(_ ref: ProcessRef, token: UInt64, fired: @escaping Fired) throws {
        try queue.sync {
            drain()
            guard ref.pid > 0, ref.generation != 0 else { throw PlatformError.noProcess }
            if var w = watches[ref.pid] {
                if w.ref == ref {
                    w.fired[token] = fired
                    watches[ref.pid] = w
                    pidOf[token] = ref.pid
                    return
                }
                // Another instance's watch: if that one still lives, ref is
                // not the occupant; else its exit was missed.
                if Self.alive(w.ref) { throw PlatformError.noProcess }
                forget(ref.pid)
            }
            guard change(ref.pid, EV_ADD | EV_CLEAR) else { throw PlatformError.noProcess }
            guard Self.alive(ref) else { // armed first, checked second
                forget(ref.pid)
                throw PlatformError.noProcess
            }
            watches[ref.pid] = Watch(ref: ref, fired: [token: fired], environment: nil)
            pidOf[token] = ref.pid
        }
    }

    /// No fired call for token after this returns; the last cancel of a
    /// process forgets its environment.
    public func cancel(token: UInt64) {
        queue.sync {
            guard let pid = pidOf.removeValue(forKey: token), var w = watches[pid] else { return }
            w.fired[token] = nil
            if w.fired.isEmpty { forget(pid) } else { watches[pid] = w }
        }
    }

    /// The startup environment read at the last exec a watch of ref saw:
    /// .unreadable when there is none (not watched, no exec since the watch
    /// began, hidden, unreadable) or the poll failed, .noProcess when ref
    /// is not live.
    public func environment(_ ref: ProcessRef) throws -> [String] {
        try queue.sync {
            guard drain() else { throw PlatformError.unreadable } // an exec may be pending unread
            guard ref.pid > 0, ref.generation != 0, Self.alive(ref) else { throw PlatformError.noProcess }
            guard let w = watches[ref.pid], w.ref == ref, let env = w.environment else { throw PlatformError.unreadable }
            return env
        }
    }

    /// Watched processes (tests).
    var watching: Int { queue.sync { watches.count } }

    private static func alive(_ ref: ProcessRef) -> Bool {
        guard let k = KernelProc.info(ref.pid) else { return false }
        return !k.zombie && k.generation == ref.generation
    }

    /// Errnos the next kevent polls fail with instead of polling (tests;
    /// on the queue only).
    private var failNext: [Int32] = []
    func failPolls(_ errnos: [Int32]) { queue.sync { failNext = errnos } }

    /// Takes every pending event; on the queue. false when a poll failed:
    /// an exec may then be pending unread. A poll a signal
    /// interrupted is retried.
    @discardableResult
    private func drain() -> Bool {
        var evs: [kevent] = Array(repeating: kevent(), count: 16)
        var now = timespec(tv_sec: 0, tv_nsec: 0)
        while true {
            let n: Int32
            if failNext.isEmpty {
                n = kevent(kq, nil, 0, &evs, Int32(evs.count), &now)
            } else {
                errno = failNext.removeFirst()
                n = -1
            }
            if n < 0 && errno == EINTR { continue }
            if n < 0 { return false }
            if n == 0 { return true }
            for ev in evs.prefix(Int(n)) { handle(Int32(ev.ident), ev.fflags) }
        }
    }

    private func handle(_ pid: Int32, _ fflags: UInt32) {
        guard var w = watches[pid] else { return }
        if fflags & UInt32(NOTE_EXEC) != 0 {
            guard let read = try? resolver.read(w.ref) else {
                // Gone before it could be read: still an exec, of nothing
                // (the ref, no path, argv or code), so it matches no plan
                // and counts, and a later exec is never silent (bridge
                // ProcessExecd). No record that might describe
                // another process.
                let none = ProcessRecord(pid: w.ref.pid, generation: w.ref.generation, parentPid: 0,
                                         parentGeneration: 0, uid: -1, startMicros: 0, path: "", args: [],
                                         cwd: "", code: CodeIdentity())
                for f in w.fired.values { f(none) }
                forget(pid)
                return
            }
            w.environment = read.procargs.flatMap(ProcArgs.environment)
            watches[pid] = w
            for f in w.fired.values { f(read.record) }
        }
        if fflags & UInt32(NOTE_EXIT) != 0 { forget(pid) }
    }

    @discardableResult
    private func change(_ pid: Int32, _ flags: Int32) -> Bool {
        var ev = kevent(ident: UInt(pid), filter: Int16(EVFILT_PROC), flags: UInt16(flags),
                        fflags: UInt32(NOTE_EXEC) | UInt32(NOTE_EXIT), data: 0, udata: nil)
        return kevent(kq, &ev, 1, nil, 0, nil) == 0
    }

    private func forget(_ pid: Int32) {
        if let w = watches.removeValue(forKey: pid) {
            for t in w.fired.keys { pidOf[t] = nil }
        }
        change(pid, EV_DELETE) // ENOENT after an exit: nothing to do
    }
}
