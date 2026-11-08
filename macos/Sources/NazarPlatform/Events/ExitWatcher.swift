import Dispatch
import Foundation

/// Platform.OnProcessExit (spec 4.3: session approvals end when the session
/// root exits): a kqueue NOTE_EXIT source per watch. fired runs exactly
/// once, on a background queue: after the process named by the full ref
/// exits, or promptly when that process is already gone (a zombie counts
/// as gone), never existed, or the ref is not a full ref (pid <= 0 or
/// generation 0, which can never name one process instance).
///
/// The source is registered before the generation check: if the check
/// still sees the ref's instance, the source was attached to that instance,
/// so an exit between the two is caught either by the event or by the
/// check, and `Once` makes fired run a single time whichever is first. The
/// check also covers the kqueue refusing to attach for a reason other than
/// ESRCH (libdispatch turns ESRCH into a synthetic NOTE_EXIT).
public final class ExitWatcher: @unchecked Sendable {
    private let queue = DispatchQueue(label: "dev.nazar.exit-watcher")
    private let lock = NSLock()
    private var sources: [UInt64: DispatchSourceProcess] = [:]
    private var nextID: UInt64 = 1

    public init() {}

    deinit {
        lock.lock()
        let all = sources.values
        sources.removeAll()
        lock.unlock()
        for src in all { src.cancel() }
    }

    /// Returns at once; fired runs exactly once, on a background queue,
    /// never with the watcher's lock held (it may call back into the watcher).
    public func watch(_ ref: ProcessRef, _ fired: @escaping @Sendable () -> Void) {
        let once = Once(fired)
        // Not a full ref: never a kqueue watch on pid 0, -1 or a PID-only
        // ref (it names no single instance), so fire promptly.
        guard ref.pid > 0, ref.generation != 0 else {
            queue.async { once.run() }
            return
        }
        lock.lock()
        let id = nextID
        nextID += 1
        lock.unlock()
        // Register first, then check (see the type comment).
        let src = DispatchSource.makeProcessSource(identifier: ref.pid, eventMask: .exit, queue: queue)
        src.setEventHandler { [weak self] in self?.finish(id, once) }
        lock.lock()
        sources[id] = src
        lock.unlock()
        src.resume()
        let alive: Bool
        if let k = KernelProc.info(ref.pid), !k.zombie, k.generation == ref.generation {
            alive = true
        } else {
            alive = false
        }
        if !alive {
            queue.async { [weak self] in self?.finish(id, once) }
        }
    }

    /// Watches still waiting for an exit (tests).
    public var pending: Int {
        lock.lock()
        defer { lock.unlock() }
        return sources.count
    }

    private func finish(_ id: UInt64, _ once: Once) {
        lock.lock()
        let src = sources.removeValue(forKey: id)
        lock.unlock()
        src?.cancel()
        once.run()
    }
}

/// Runs a closure at most once, whoever calls first.
final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var fn: (@Sendable () -> Void)?
    init(_ fn: @escaping @Sendable () -> Void) { self.fn = fn }
    func run() {
        lock.lock()
        let f = fn
        fn = nil
        lock.unlock()
        f?()
    }
}
