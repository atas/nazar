import Foundation

/// Allocation audit for buffers handed to Go (spike S11): every buffer is
/// recorded when allocated and must come back through free_buf exactly
/// once. `leaks` can't see these (S11), so this is the boundary-leak check.
public final class BufferLedger: @unchecked Sendable {
    public static let shared = BufferLedger()

    private let lock = NSLock()
    private var live = Set<UInt>()
    public private(set) var allocations = 0
    public private(set) var frees = 0
    /// free_buf of a pointer never handed out, or a second free of one.
    public private(set) var badFrees = 0

    public init() {}

    /// Copies bytes into a new malloc'ed buffer and records it. Empty data
    /// still allocates one byte, so a successful result is never NULL.
    public func allocate(_ data: Data) -> (UnsafeMutablePointer<UInt8>, Int) {
        let p = malloc(max(data.count, 1))!.assumingMemoryBound(to: UInt8.self)
        data.copyBytes(to: p, count: data.count)
        lock.lock()
        allocations += 1
        live.insert(UInt(bitPattern: p))
        lock.unlock()
        return (p, data.count)
    }

    /// Frees p if this ledger handed it out and it is still live. A foreign
    /// or double free is counted and never passed to free(3).
    public func free(_ p: UnsafeMutablePointer<UInt8>?) {
        guard let p else { return }
        lock.lock()
        let mine = live.remove(UInt(bitPattern: p)) != nil
        if mine { frees += 1 } else { badFrees += 1 }
        lock.unlock()
        if mine { Darwin.free(p) }
    }

    public var liveCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return live.count
    }
}
