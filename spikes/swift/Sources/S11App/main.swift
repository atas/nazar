import AppKit
import CryptoKit
import LocalAuthentication
import CSpikeCore

// Software P-256 key: S11 tests the bridge, not the Secure Enclave (that is S1).
let signingKey = P256.Signing.PrivateKey()
let laContext = LAContext()
var authenticated = false
let authLock = NSLock()

// `--no-auth`: skip LocalAuthentication (no prompt), but still hop Go thread -> main thread
// once on the first callback (DispatchQueue.main.async + semaphore) so the cross-thread
// blocking pattern is exercised without a human. The "exactly one prompt" criterion of the
// plan can only be checked by a run WITHOUT this flag.
let noAuth = CommandLine.arguments.contains("--no-auth")

/// Boundary allocation audit. Every buffer handed to Go is recorded when malloc'd and must come
/// back through free_buf exactly once. `leaks --atExit` cannot see these buffers (stale Go
/// stack/heap pointers keep them "reachable"), so this is the actual no-boundary-leak evidence.
final class AllocAudit: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var mallocs = 0
    private(set) var frees = 0
    private(set) var badFrees = 0   // free of a pointer we never handed out, or a double free
    private var live = Set<UInt>()

    func didMalloc(_ p: UnsafeMutablePointer<UInt8>) {
        lock.lock(); defer { lock.unlock() }
        mallocs += 1
        live.insert(UInt(bitPattern: p))
    }
    /// Returns true when `p` is a live buffer we own (and removes it); the caller then frees it.
    func willFree(_ p: UnsafeMutablePointer<UInt8>?) -> Bool {
        lock.lock(); defer { lock.unlock() }
        frees += 1
        guard let p, live.remove(UInt(bitPattern: p)) != nil else { badFrees += 1; return false }
        return true
    }
    var liveCount: Int { lock.lock(); defer { lock.unlock() }; return live.count }
}
let audit = AllocAudit()

/// Blocks the calling (Go) thread; runs the LocalAuthentication prompt via the main thread.
/// Concurrent callers queue on authLock, so one prompt serves them all.
func ensureAuthenticated() -> Bool {
    authLock.lock(); defer { authLock.unlock() }
    if authenticated { return true }
    let sem = DispatchSemaphore(value: 0)
    var ok = false
    DispatchQueue.main.async {
        if noAuth {
            ok = Thread.isMainThread
            print("S11 --no-auth: main-thread hop done (isMainThread=\(ok)), no prompt")
            sem.signal()
            return
        }
        laContext.evaluatePolicy(.deviceOwnerAuthentication,
                                 localizedReason: "S11 spike: allow test signatures") { success, error in
            ok = success
            if let error { print("LA error: \(error)") }
            sem.signal()
        }
    }
    sem.wait()
    authenticated = ok
    return ok
}

let signCB: sign_fn = { data, len, out, outLen in
    guard let data, let out, let outLen else { return 1 }
    guard ensureAuthenticated() else { return 2 }
    let msg = Data(bytes: data, count: len)
    guard let sig = try? signingKey.signature(for: msg) else { return 3 }
    let der = sig.derRepresentation
    let buf = malloc(der.count)!.assumingMemoryBound(to: UInt8.self)
    der.copyBytes(to: buf, count: der.count)
    audit.didMalloc(buf)
    out.pointee = buf
    outLen.pointee = der.count
    return 0
}
let freeCB: free_fn = { p in
    if audit.willFree(p) { free(p) }
}

let cbs = UnsafeMutablePointer<Callbacks>.allocate(capacity: 1)
cbs.initialize(to: Callbacks(sign: signCB, free_buf: freeCB))

var pub = [UInt8](signingKey.publicKey.x963Representation)
let startRC = pub.withUnsafeMutableBufferPointer { CoreStart(cbs, $0.baseAddress, $0.count) }
guard startRC == 0 else { print("CoreStart failed: \(startRC)"); exit(1) }

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
// First non-flag argument is the round count (flags such as --no-auth may come first).
let rounds = Int32(CommandLine.arguments.dropFirst().first(where: { !$0.hasPrefix("--") }).flatMap { Int32($0) } ?? 50)
let firstBatchNote = noAuth ? "includes the main-thread hop, no prompt" : "includes the prompt"
DispatchQueue.global().async {
    var t = Date()
    let fails1 = CoreRunSignTest(rounds)
    print("S11 batch 1: \(rounds) concurrent signs, failures=\(fails1), \(Date().timeIntervalSince(t))s (\(firstBatchNote))")
    t = Date()
    let fails2 = CoreRunSignTest(rounds)
    print("S11 batch 2: \(rounds) concurrent signs, failures=\(fails2), \(Date().timeIntervalSince(t))s (must not prompt)")

    var goSigns: Int64 = 0, goFrees: Int64 = 0
    CoreCallCounts(&goSigns, &goFrees)
    let expected = Int(rounds) * 2
    let auditOK = audit.mallocs == expected && audit.frees == expected && audit.liveCount == 0
        && audit.badFrees == 0 && goSigns == Int64(expected) && goFrees == Int64(expected)
    print("S11 alloc audit: swift mallocs=\(audit.mallocs) frees=\(audit.frees) live=\(audit.liveCount) badFrees=\(audit.badFrees); go signs=\(goSigns) frees=\(goFrees); expected=\(expected) -> \(auditOK ? "OK" : "LEAK")")
    exit(fails1 == 0 && fails2 == 0 && auditOK ? 0 : 1)
}
app.run()
