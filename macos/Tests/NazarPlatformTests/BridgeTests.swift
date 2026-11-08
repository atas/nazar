import CNazarBridge
import CryptoKit
import Darwin
import Foundation
import Testing
@testable import NazarPlatform

// The Swift end of the C ABI (nazar_bridge.h, spec 4.7, S11).
// Security-relevant: every Platform, Vault and audit.Sink call of the Go
// core crosses this table. A callback that trusts a length, keeps a Go
// pointer, leaves a stale output behind, frees memory it did not hand out,
// or does the work (a prompt, a signature) when it cannot return the answer
// breaks the boundary. Nothing here needs a human: the login and dialog
// gates are scripted, keys are software keys, the vault and audit sink are
// in memory (no Keychain API is called), warnings are recorded, and the
// screen-lock watcher listens to a random dev.nazar.test.* name.

/// A Confirmer that always throws (a dialog that timed out or failed).
final class ThrowingConfirmer: Confirmer, @unchecked Sendable {
    let error: PlatformError
    private(set) var calls = 0
    init(_ error: PlatformError) { self.error = error }
    func confirm(_ prompt: PromptSpec) throws -> Bool {
        calls += 1
        throw error
    }
}

/// A VaultStore that fails every call with a chosen error.
final class ThrowingVault: VaultStore, @unchecked Sendable {
    var error: Error = PlatformError.failed("locked")
    func get(_ name: String) throws -> Data { throw error }
    func put(_ name: String, _ value: Data) throws { throw error }
    func delete(_ name: String) throws { throw error }
    func list(prefix: String) throws -> [String] { throw error }
}

/// An AuditWriter that records the timestamp too, or fails with a chosen error.
final class RecordingAudit: AuditWriter, @unchecked Sendable {
    var error: Error?
    private(set) var entries: [(Int64, String)] = []
    func write(unixNanos: Int64, line: String) throws {
        if let error { throw error }
        entries.append((unixNanos, line))
    }
}

struct SomeOtherError: Error {}

/// Calls the callbacks table exactly as Go does: inputs as pointers + length,
/// outputs as NzBuf filled by Swift and handed back through free_buf.
@Suite(.serialized) struct BridgeTests {
    final class Env {
        /// Parts a test swaps in; everything else comes from testPlatform.
        struct Parts {
            var backend: EnclaveBackend = SoftwareEnclaveBackend()
            var dialog: Confirmer?
            var resolver: ProcessResolver?
            var installed: InstalledApps?
            var vault: VaultStore?
            var audit: AuditWriter?
            /// platform.Exec: set, the runtime also reaches "Go"
            /// (execRecords), so the table offers the exec callbacks.
            var execs: ExecWatcher?
        }

        let ledger = BufferLedger()
        let login = ScriptedLoginEvaluator()
        let confirm = ScriptedConfirmer()
        let warnings = RecordedWarnings()
        let vault = MemoryVault()
        let audit = MemoryAudit()
        let exits = Counter()
        let locks = Counter()
        var exitTokens: [UInt64] = []
        var lockTokens: [UInt64] = []
        var execRecords: [(UInt64, Data)] = []
        let lock = NSLock()
        /// Never the system's com.apple.screenIsLocked.
        let lockName = "dev.nazar.test.bridge.screenlock.\(UUID().uuidString)"
        let cb: NazarCallbacks
        let platform: SwiftPlatform

        init(_ parts: Parts = Parts()) {
            let base = SwiftPlatform.testPlatform(backend: parts.backend, login: login, confirm: confirm, warnings: warnings,
                                                  screenLockName: lockName)
            platform = SwiftPlatform(enclave: base.enclave, approvals: base.approvals, login: base.login,
                                     dialog: parts.dialog ?? base.dialog, resolver: parts.resolver ?? base.resolver,
                                     installed: parts.installed ?? base.installed, exits: base.exits,
                                     screenLocks: base.screenLocks, warnings: base.warnings, execs: parts.execs)
            var me: Env?
            var execFired: (@Sendable (UInt64, Data) -> Void)?
            if parts.execs != nil {
                execFired = { (t: UInt64, d: Data) in me?.lock.lock(); me?.execRecords.append((t, d)); me?.lock.unlock() }
            }
            let p = NazarBridge.install(NazarBridge.Runtime(platform: platform, vault: parts.vault ?? vault,
                                                           audit: parts.audit ?? audit, ledger: ledger,
                                                           exitFired: { t in me?.lock.lock(); me?.exitTokens.append(t); me?.lock.unlock(); me?.exits.hit() },
                                                           screenLocked: { t in me?.lock.lock(); me?.lockTokens.append(t); me?.lock.unlock(); me?.locks.hit() },
                                                           execFired: execFired))
            cb = p.pointee
            me = self
        }

        /// The first exec record "Go" got for token, waiting up to 5 s.
        func waitExec(token: UInt64) -> Data? {
            let end = Date().addingTimeInterval(5)
            while Date() < end {
                lock.lock()
                let d = execRecords.first { $0.0 == token }?.1
                lock.unlock()
                if let d { return d }
                Thread.sleep(forTimeInterval: 0.005)
            }
            return nil
        }

        /// Copies an output buffer and frees it through the table.
        func take(_ b: NzBuf) -> Data {
            guard let p = b.ptr else { return Data() }
            let d = Data(bytes: p, count: b.len)
            cb.free_buf(p)
            return d
        }

        /// A new key through the table: (handle, X9.63 public key).
        func key(purpose: Int32 = 1, auth: Int32 = 0) -> (Data, Data) {
            var h = NzBuf(), pub = NzBuf()
            let st = cb.create_key(purpose, auth, 0, &h, &pub)
            precondition(st == NZ_OK, "create_key: \(st)")
            return (take(h), take(pub))
        }
    }

    func call(_ d: Data, _ body: (UnsafePointer<UInt8>?, Int) -> Int32) -> Int32 {
        d.withUnsafeBytes { body($0.bindMemory(to: UInt8.self).baseAddress, d.count) }
    }

    static let prompt = Data(#"{"title":"t","lines":[],"commandLine":0,"unknown":false,"reason":"r","timeoutMillis":2000}"#.utf8)
    /// A pointer that must never be read, written or freed.
    static let garbage = UnsafeMutablePointer<UInt8>(bitPattern: 0xdead)
    static func stale() -> NzBuf { NzBuf(ptr: garbage, len: 77) }
    static func isClear(_ b: NzBuf) -> Bool { b.ptr == nil && b.len == 0 }

    // MARK: core behaviour

    @Test func keysRoundTripAndEveryBufferIsFreed() throws {
        let e = Env()
        #expect(e.cb.abi_version == NAZAR_ABI_VERSION)
        var h = NzBuf(), pub = NzBuf()
        #expect(e.cb.create_key(1, 0, 0, &h, &pub) == NZ_OK)
        let handle = e.take(h), pk = e.take(pub)
        var sig = NzBuf()
        let msg = Data("bridge".utf8)
        let st = call(handle) { hp, hn in self.call(msg) { mp, mn in e.cb.sign(hp, hn, mp, mn, 0, &sig) } }
        #expect(st == NZ_OK)
        let der = e.take(sig)
        let key = try P256.Signing.PublicKey(x963Representation: pk)
        #expect(key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: der), for: msg))
        #expect(call(handle) { e.cb.delete_key($0, $1) } == NZ_OK)
        sig = NzBuf(ptr: UnsafeMutablePointer(bitPattern: 0x1), len: 99) // stale garbage must be cleared
        #expect(call(handle) { hp, hn in self.call(msg) { mp, mn in e.cb.sign(hp, hn, mp, mn, 0, &sig) } } == NZ_NOT_FOUND)
        #expect(sig.ptr == nil && sig.len == 0)
        #expect(e.ledger.liveCount == 0 && e.ledger.badFrees == 0 && e.ledger.allocations == 3)
    }

    @Test func statusCodes() {
        let e = Env()
        var h = NzBuf(), pub = NzBuf()
        #expect(e.cb.create_key(3, 0, 0, &h, &pub) == NZ_INVALID && h.ptr == nil)
        #expect(e.cb.create_key(1, 0, 0, nil, &pub) == NZ_ERR)
        #expect(e.cb.create_key(1, 1, 0, &h, &pub) == NZ_OK)
        let handle = e.take(h)
        _ = e.take(pub)
        var sig = NzBuf()
        #expect(call(handle) { hp, hn in e.cb.sign(hp, hn, nil, 0, 0, &sig) } == NZ_AUTH_REQUIRED)
        var info = NzBuf()
        #expect(e.cb.process(-1, 0, &info) == NZ_NO_PROCESS)
        #expect(e.cb.process(Int64(Int32.max) + 1, 0, &info) == NZ_NO_PROCESS)
        var r: Int64 = 7
        #expect(e.cb.responsible_for(0, 0, &r) == NZ_NOT_FOUND && r == 0)
        var app = NzBuf()
        #expect(call(Data("not json".utf8)) { e.cb.app_for($0, $1, &app) } == NZ_INVALID)
        #expect(call(Data("[]".utf8)) { e.cb.app_for($0, $1, &app) } == NZ_NOT_FOUND)
        var cd = NzBuf()
        #expect(call(Data("/nonexistent/x".utf8)) { e.cb.code_hash($0, $1, &cd) } == NZ_NOT_FOUND)
        #expect(call(Data([0xff, 0xfe])) { e.cb.code_hash($0, $1, &cd) } == NZ_INVALID)
        #expect(e.cb.sign(nil, 5, nil, 0, 0, &sig) == NZ_INVALID) // NULL with a length
        #expect(e.ledger.liveCount == 0)
    }

    /// The access crosses the table: an out-of-range one is refused, a
    /// when-unlocked key used while the Mac is locked is NZ_LOCKED (for
    /// signing and key agreement), an after-first-unlock key still signs.
    @Test func accessAndLockedThroughTheTable() {
        let b = SoftwareEnclaveBackend()
        let e = Env(Env.Parts(backend: b))
        var h = NzBuf(), pub = NzBuf()
        #expect(e.cb.create_key(1, 0, 2, &h, &pub) == NZ_INVALID && Self.isClear(h))
        #expect(e.cb.create_key(1, 0, 0, &h, &pub) == NZ_OK)
        let unlockedOnly = e.take(h)
        _ = e.take(pub)
        #expect(e.cb.create_key(1, 0, 1, &h, &pub) == NZ_OK)
        let whileLocked = e.take(h)
        _ = e.take(pub)
        #expect(e.cb.create_key(2, 0, 0, &h, &pub) == NZ_OK)
        let ka = e.take(h), kaPub = e.take(pub)
        b.locked = true
        let msg = Data("locked".utf8)
        var out = NzBuf()
        #expect(call(unlockedOnly) { hp, hn in self.call(msg) { mp, mn in e.cb.sign(hp, hn, mp, mn, 0, &out) } } == NZ_LOCKED && Self.isClear(out))
        #expect(call(ka) { hp, hn in self.call(kaPub) { pp, pn in e.cb.key_agreement(hp, hn, pp, pn, 0, &out) } } == NZ_LOCKED)
        #expect(call(whileLocked) { hp, hn in self.call(msg) { mp, mn in e.cb.sign(hp, hn, mp, mn, 0, &out) } } == NZ_OK)
        _ = e.take(out)
        b.locked = false
        #expect(call(unlockedOnly) { hp, hn in self.call(msg) { mp, mn in e.cb.sign(hp, hn, mp, mn, 0, &out) } } == NZ_OK)
        _ = e.take(out)
        #expect(e.ledger.liveCount == 0)
    }

    @Test func gatesThroughTheTable() {
        let e = Env()
        let prompt = Data(#"{"title":"t","lines":[],"commandLine":0,"unknown":false,"reason":"r","timeoutMillis":2000}"#.utf8)
        e.login.push(true)
        var ref: UInt64 = 0
        #expect(call(prompt) { e.cb.authenticate(1, $0, $1, &ref) } == NZ_OK && ref != 0)
        e.login.push(false)
        var ref2: UInt64 = 9
        #expect(call(prompt) { e.cb.authenticate(1, $0, $1, &ref2) } == NZ_DENIED && ref2 == 0)
        e.cb.release_approval(ref)
        e.cb.release_approval(ref)
        e.cb.release_approval(0)
        #expect(e.platform.approvals.liveCount == 0)
        e.confirm.push(true)
        var allowed: Int32 = 0
        #expect(call(prompt) { e.cb.confirm($0, $1, &allowed) } == NZ_OK && allowed == 1)
        #expect(call(Data("{".utf8)) { e.cb.confirm($0, $1, &allowed) } == NZ_INVALID && allowed == 0)
        _ = call(Data(#"{"id":"w","title":"Blocked","lines":["l"],"commandLine":0,"count":2,"suggestedRule":""}"#.utf8)) { e.cb.show_warning($0, $1); return 0 }
        _ = call(Data("garbage".utf8)) { e.cb.show_warning($0, $1); return 0 }
        #expect(e.warnings.shown.map(\.id) == ["w"])
    }

    @Test func processesAndExitEvents() throws {
        let e = Env()
        let s = try Sleeper()
        var info = NzBuf()
        #expect(e.cb.process(Int64(s.pid), 0, &info) == NZ_OK)
        let rec = try Wire.decode(ProcessRecord.self, e.take(info))
        #expect(rec.pid == s.pid && rec.generation != 0 && rec.args == ["/bin/sleep", "60"])
        e.cb.watch_exit(Int64(s.pid), rec.generation, 77)
        e.cb.watch_exit(-5, 1, 78) // not a process: fires promptly
        s.kill()
        #expect(e.exits.wait(for: 2))
        e.lock.lock()
        #expect(Set(e.exitTokens) == [77, 78])
        e.lock.unlock()
        #expect(e.ledger.liveCount == 0)
    }

    @Test func vaultAndAudit() throws {
        let e = Env()
        let name = Data("ssh-key/github".utf8), value = Data("handle".utf8)
        #expect(call(name) { np, nn in self.call(value) { vp, vn in e.cb.vault_put(np, nn, vp, vn) } } == NZ_OK)
        var out = NzBuf()
        #expect(call(name) { e.cb.vault_get($0, $1, &out) } == NZ_OK)
        #expect(e.take(out) == value)
        #expect(call(Data("ssh-key/".utf8)) { e.cb.vault_list($0, $1, &out) } == NZ_OK)
        #expect(try Wire.decode([String].self, e.take(out)) == ["ssh-key/github"])
        #expect(call(name) { e.cb.vault_delete($0, $1) } == NZ_OK)
        #expect(call(name) { e.cb.vault_delete($0, $1) } == NZ_NOT_FOUND)
        #expect(call(name) { e.cb.vault_get($0, $1, &out) } == NZ_NOT_FOUND && out.ptr == nil)
        #expect(call(Data("decision=allowed target=ssh:x".utf8)) { e.cb.write_audit(0, $0, $1) } == NZ_OK)
        #expect(e.audit.lines == ["decision=allowed target=ssh:x"])
        #expect(e.ledger.liveCount == 0)
    }

    @Test func foreignFreesAreHarmless() {
        let e = Env()
        var x: UInt8 = 0
        withUnsafeMutablePointer(to: &x) { e.cb.free_buf($0) }
        e.cb.free_buf(nil)
        #expect(e.ledger.badFrees == 1)
    }

    // MARK: exec

    // D8: the exec callbacks are in the table only when the
    // runtime has an exec watcher and a way to reach Go.
    @Test func execCallbacksAreOptional() throws {
        let e = Env()
        #expect(e.cb.watch_exec == nil && e.cb.cancel_exec == nil && e.cb.environment == nil)
        let x = Env(Env.Parts(execs: try #require(ExecWatcher())))
        #expect(x.cb.watch_exec != nil && x.cb.cancel_exec != nil && x.cb.environment != nil)
    }

    @Test func execThroughTheTable() throws {
        let e = Env(Env.Parts(execs: try #require(ExecWatcher())))
        let watch = try #require(e.cb.watch_exec), cancel = try #require(e.cb.cancel_exec)
        let environment = try #require(e.cb.environment)
        let p = Probe.path, env = ["NAZAR_TEST=bridge", "B=2"]
        let c = try ExecChild([p, p, "/bin/sleep", "600"], env: env)
        let pid = Int64(c.pid), gen = c.ref.generation
        #expect(watch(pid, gen + 1, 7) == NZ_NO_PROCESS)
        #expect(watch(-1, 1, 7) == NZ_NO_PROCESS)
        #expect(watch(Int64(Int32.max) + 1, 1, 7) == NZ_NO_PROCESS)
        #expect(watch(pid, gen, 7) == NZ_OK)
        var out = Self.stale()
        #expect(environment(pid, gen, &out) == NZ_UNREADABLE && Self.isClear(out))
        c.next()
        let rec = try Wire.decode(ProcessRecord.self, try #require(e.waitExec(token: 7)))
        #expect(rec.ref == c.ref && rec.path == p && rec.args == [p, "/bin/sleep", "600"] && rec.cwd == "/")
        #expect(environment(pid, gen, &out) == NZ_OK)
        #expect(try Wire.decode([String].self, e.take(out)) == env)
        out = Self.stale()
        #expect(environment(pid, gen + 1, &out) == NZ_NO_PROCESS && Self.isClear(out))
        #expect(environment(pid, gen, nil) == NZ_ERR)
        cancel(7)
        cancel(7) // unknown now: nothing
        #expect(environment(pid, gen, &out) == NZ_UNREADABLE)
        #expect(e.ledger.liveCount == 0)
    }

    // MARK: the table itself

    /// Go's cbridge refuses a table with any NULL required entry; every
    /// required slot is set (the exec slots are optional).
    @Test func tableIsCompleteAndVersioned() {
        let e = Env()
        let c = e.cb
        #expect(c.abi_version == NAZAR_ABI_VERSION && NAZAR_ABI_VERSION == 4)
        #expect(c.create_key != nil && c.sign != nil && c.key_agreement != nil && c.delete_key != nil)
        #expect(c.authenticate != nil && c.confirm != nil && c.release_approval != nil)
        #expect(c.peer_of != nil && c.process != nil && c.app_for != nil && c.code_hash != nil)
        #expect(c.responsible_for != nil && c.installed_app != nil && c.apps != nil)
        #expect(c.watch_exit != nil && c.watch_screen_lock != nil && c.show_warning != nil)
        #expect(c.vault_get != nil && c.vault_put != nil && c.vault_delete != nil && c.vault_list != nil)
        #expect(c.write_audit != nil && c.free_buf != nil)
        #expect(NazarBridge.maxInput == 16 << 20)
    }

    // MARK: outputs

    /// Every failing call leaves its outputs cleared (Go frees any non-NULL
    /// ptr whatever the status, so a stale pointer would reach free_buf)
    /// and allocates nothing.
    @Test func failedCallsClearStaleOutputs() {
        let e = Env()
        var h = Self.stale(), pub = Self.stale()
        #expect(e.cb.create_key(9, 0, 0, &h, &pub) == NZ_INVALID)
        #expect(Self.isClear(h) && Self.isClear(pub))
        h = Self.stale(); pub = Self.stale()
        #expect(e.cb.create_key(1, 7, 0, &h, &pub) == NZ_INVALID)
        #expect(Self.isClear(h) && Self.isClear(pub))

        let bogus = Data("NZK1".utf8) + [1, 0] + Data(repeating: 0xff, count: 33)
        var out = Self.stale()
        #expect(call(bogus) { hp, hn in e.cb.sign(hp, hn, nil, 0, 0, &out) } == NZ_NOT_FOUND && Self.isClear(out))
        out = Self.stale()
        let peer = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        #expect(call(bogus) { hp, hn in self.call(peer) { pp, pn in e.cb.key_agreement(hp, hn, pp, pn, 0, &out) } } == NZ_NOT_FOUND)
        #expect(Self.isClear(out))
        out = Self.stale()
        #expect(e.cb.process(-1, 0, &out) == NZ_NO_PROCESS && Self.isClear(out))
        out = Self.stale()
        #expect(call(Data("[]".utf8)) { e.cb.app_for($0, $1, &out) } == NZ_NOT_FOUND && Self.isClear(out))
        out = Self.stale()
        #expect(call(Data("/nonexistent/nazar-\(UUID())".utf8)) { e.cb.code_hash($0, $1, &out) } == NZ_NOT_FOUND)
        #expect(Self.isClear(out))
        out = Self.stale()
        #expect(call(Data("not a bundle id\n".utf8)) { e.cb.installed_app($0, $1, &out) } == NZ_INVALID && Self.isClear(out))
        out = Self.stale()
        #expect(call(Data("missing".utf8)) { e.cb.vault_get($0, $1, &out) } == NZ_NOT_FOUND && Self.isClear(out))
        out = Self.stale()
        #expect(call(Data([0xc3, 0x28])) { e.cb.vault_list($0, $1, &out) } == NZ_INVALID && Self.isClear(out))

        var pid: Int64 = 5, gen: UInt64 = 6
        #expect(e.cb.peer_of(-1, &pid, &gen) == NZ_NO_PROCESS && pid == 0 && gen == 0)
        var r: Int64 = 9
        #expect(e.cb.responsible_for(Int64(Int32.max), 1, &r) == NZ_NOT_FOUND && r == 0)
        var ref: UInt64 = 42
        #expect(call(Data("{}".utf8)) { e.cb.authenticate(1, $0, $1, &ref) } == NZ_INVALID && ref == 0)
        var allowed: Int32 = 1
        #expect(call(Data("[]".utf8)) { e.cb.confirm($0, $1, &allowed) } == NZ_INVALID && allowed == 0)

        #expect(e.ledger.allocations == 0 && e.ledger.liveCount == 0 && e.ledger.badFrees == 0)
    }

    /// A NULL output pointer is NZ_ERR, and the work is never done: no key
    /// is created, nothing is signed, no prompt or dialog is shown, no
    /// approval is issued (an answer that cannot be returned must not cost
    /// the user a prompt or leave an approval alive).
    @Test func nullOutputsAreRefusedBeforeAnyWork() {
        let sw = SoftwareEnclaveBackend()
        let e = Env(.init(backend: sw))
        let (signKey, _) = e.key(purpose: 1)
        let (kaKey, _) = e.key(purpose: 2)
        let before = e.ledger.allocations

        var h = Self.stale(), pub = Self.stale()
        #expect(e.cb.create_key(1, 0, 0, nil, &pub) == NZ_ERR && Self.isClear(pub))
        #expect(e.cb.create_key(1, 0, 0, &h, nil) == NZ_ERR && Self.isClear(h))
        let msg = Data("m".utf8)
        #expect(call(signKey) { hp, hn in self.call(msg) { mp, mn in e.cb.sign(hp, hn, mp, mn, 0, nil) } } == NZ_ERR)
        let peer = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        #expect(call(kaKey) { hp, hn in self.call(peer) { pp, pn in e.cb.key_agreement(hp, hn, pp, pn, 0, nil) } } == NZ_ERR)
        #expect(sw.signCalls == 0 && sw.agreeCalls == 0)

        e.login.defaultAnswer = true
        e.confirm.defaultAnswer = true
        #expect(call(Self.prompt) { e.cb.authenticate(1, $0, $1, nil) } == NZ_ERR)
        #expect(e.login.reasons.isEmpty && e.platform.approvals.liveCount == 0)
        #expect(call(Self.prompt) { e.cb.confirm($0, $1, nil) } == NZ_ERR)
        #expect(e.confirm.prompts.isEmpty)

        var pid: Int64 = 3, gen: UInt64 = 4
        #expect(e.cb.peer_of(0, nil, &gen) == NZ_ERR && gen == 0)
        #expect(e.cb.peer_of(0, &pid, nil) == NZ_ERR && pid == 0)
        #expect(e.cb.process(Int64(getpid()), 0, nil) == NZ_ERR)
        #expect(e.cb.responsible_for(Int64(getpid()), 0, nil) == NZ_ERR)
        #expect(call(Data("[]".utf8)) { e.cb.app_for($0, $1, nil) } == NZ_ERR)
        #expect(call(Data("/bin/sleep".utf8)) { e.cb.code_hash($0, $1, nil) } == NZ_ERR)
        #expect(call(Data("com.example.app".utf8)) { e.cb.installed_app($0, $1, nil) } == NZ_ERR)
        _ = call(Data("n".utf8)) { np, nn in self.call(Data("v".utf8)) { vp, vn in e.cb.vault_put(np, nn, vp, vn) } }
        #expect(call(Data("n".utf8)) { e.cb.vault_get($0, $1, nil) } == NZ_ERR)
        #expect(call(Data("".utf8)) { e.cb.vault_list($0, $1, nil) } == NZ_ERR)

        #expect(e.ledger.allocations == before && e.ledger.liveCount == 0)
    }

    /// free_buf is safe against a double free and a pointer into a live
    /// buffer: neither reaches free(3), and the real pointer still frees.
    @Test func freeBufIsSafeAgainstMisuse() throws {
        let e = Env()
        _ = call(Data("n".utf8)) { np, nn in self.call(Data("12345678".utf8)) { vp, vn in e.cb.vault_put(np, nn, vp, vn) } }
        var out = NzBuf()
        #expect(call(Data("n".utf8)) { e.cb.vault_get($0, $1, &out) } == NZ_OK)
        let p = try #require(out.ptr)
        e.cb.free_buf(p + 1) // interior pointer
        #expect(e.ledger.badFrees == 1 && e.ledger.liveCount == 1)
        e.cb.free_buf(p)
        #expect(e.ledger.liveCount == 0 && e.ledger.frees == 1)
        e.cb.free_buf(p) // double free
        #expect(e.ledger.badFrees == 2 && e.ledger.frees == 1)
    }

    // MARK: inputs

    /// Lengths are never trusted: more than maxInput, or a size_t that is
    /// negative as a Swift Int, is NZ_INVALID before any byte is read; NULL
    /// with a non-zero length is NZ_INVALID; nothing is stored or prompted.
    @Test func hostileLengthsAreRefused() throws {
        let e = Env()
        let name = Data("n".utf8)
        let big = Data(count: NazarBridge.maxInput + 1)
        #expect(call(name) { np, nn in self.call(big) { vp, vn in e.cb.vault_put(np, nn, vp, vn) } } == NZ_INVALID)
        #expect(call(big) { np, nn in self.call(name) { vp, vn in e.cb.vault_put(np, nn, vp, vn) } } == NZ_INVALID)
        #expect(call(name) { np, _ in self.call(name) { vp, vn in e.cb.vault_put(np, -1, vp, vn) } } == NZ_INVALID)
        #expect(call(name) { np, nn in self.call(name) { vp, _ in e.cb.vault_put(np, nn, vp, Int.min) } } == NZ_INVALID)
        #expect(e.cb.vault_put(nil, 4, nil, 0) == NZ_INVALID)
        #expect(call(name) { np, nn in e.cb.vault_put(np, nn, nil, 8) } == NZ_INVALID)
        #expect(try e.vault.list(prefix: "").isEmpty)

        // Exactly maxInput is accepted.
        let edge = Data(repeating: 0xa5, count: NazarBridge.maxInput)
        #expect(call(name) { np, nn in self.call(edge) { vp, vn in e.cb.vault_put(np, nn, vp, vn) } } == NZ_OK)
        #expect(try e.vault.get("n") == edge)

        var out = Self.stale()
        #expect(e.cb.vault_get(nil, 3, &out) == NZ_INVALID && Self.isClear(out))
        #expect(e.cb.vault_delete(nil, 3) == NZ_INVALID)
        out = Self.stale()
        #expect(e.cb.vault_list(nil, 3, &out) == NZ_INVALID && Self.isClear(out))
        out = Self.stale()
        #expect(e.cb.code_hash(nil, 3, &out) == NZ_INVALID && Self.isClear(out))
        out = Self.stale()
        #expect(e.cb.installed_app(nil, 3, &out) == NZ_INVALID && Self.isClear(out))
        out = Self.stale()
        #expect(e.cb.app_for(nil, 3, &out) == NZ_INVALID && Self.isClear(out))
        #expect(e.cb.write_audit(0, nil, 3) == NZ_INVALID)
        #expect(call(big) { e.cb.write_audit(0, $0, $1) } == NZ_INVALID)
        #expect(e.audit.lines.isEmpty)

        e.login.defaultAnswer = true
        e.confirm.defaultAnswer = true
        var ref: UInt64 = 0
        #expect(e.cb.authenticate(1, nil, 10, &ref) == NZ_INVALID && ref == 0)
        #expect(call(Self.prompt) { p, _ in e.cb.authenticate(1, p, -1, &ref) } == NZ_INVALID && ref == 0)
        var allowed: Int32 = 1
        #expect(e.cb.confirm(nil, 10, &allowed) == NZ_INVALID && allowed == 0)
        #expect(e.login.reasons.isEmpty && e.confirm.prompts.isEmpty && e.platform.approvals.liveCount == 0)

        let (handle, _) = e.key()
        var sig = Self.stale()
        #expect(call(handle) { hp, hn in e.cb.sign(hp, hn, nil, 3, 0, &sig) } == NZ_INVALID && Self.isClear(sig))
        sig = Self.stale()
        #expect(call(handle) { hp, _ in e.cb.sign(hp, -1, nil, 0, 0, &sig) } == NZ_INVALID && Self.isClear(sig))
        #expect(e.cb.delete_key(nil, 9) == NZ_INVALID)
        #expect(e.ledger.liveCount == 0)
    }

    /// Inputs belong to Go and are valid only during the call: what Swift
    /// keeps is a copy, so Go reusing the memory afterwards changes nothing.
    /// Every input here is longer than Data's inline capacity (14 bytes): a
    /// shorter Data is stored inline, which copies even through
    /// Data(bytesNoCopy:), so only a longer one can tell a copy from a kept
    /// Go pointer (a use-after-free once Go reuses the memory).
    @Test func inputsAreCopied() throws {
        let e = Env()

        // The helper itself: the Data it answers aliases nothing in the
        // caller's buffer and keeps its bytes after the buffer is overwritten.
        let n = 64
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: n)
        defer { buf.deallocate() }
        for i in 0..<n { buf[i] = UInt8(i) }
        let copy = try NazarBridge.input(buf, n)
        #expect(copy.count == n)
        copy.withUnsafeBytes { raw in
            let lo = UnsafeRawPointer(buf), hi = lo + n
            if let base = raw.baseAddress { #expect(base < lo || base >= hi) } else { Issue.record("no storage") }
        }
        buf.update(repeating: 0xee, count: n)
        #expect(copy == Data((0..<n).map { UInt8($0) }))

        // Through the table: the vault keeps the value Go handed it, not Go's
        // memory. The name crosses as text (always a fresh String), the value
        // as the bytes Swift stores, so the value is the one that matters.
        var name: [UInt8] = Array("ssh-key/github-personal".utf8) // 23 bytes
        var value: [UInt8] = (0..<64).map { UInt8(truncatingIfNeeded: $0 &* 7) }
        let want = Data(value)
        let st = name.withUnsafeBufferPointer { np in
            value.withUnsafeBufferPointer { vp in e.cb.vault_put(np.baseAddress, np.count, vp.baseAddress, vp.count) }
        }
        #expect(st == NZ_OK)
        for i in name.indices { name[i] = UInt8(ascii: "x") }
        for i in value.indices { value[i] = 0xee }
        #expect(try e.vault.get("ssh-key/github-personal") == want)
        #expect(try e.vault.list(prefix: "") == ["ssh-key/github-personal"])

        // JSON and text inputs: what the dialog and the audit sink kept is
        // unchanged after Go overwrites the buffers.
        let title = String(repeating: "Allow ssh to github.com? ", count: 4)
        var prompt: [UInt8] = Array(#"{"title":"\#(title)","lines":["l1","l2"],"commandLine":0,"unknown":false,"reason":"r","timeoutMillis":2000}"#.utf8)
        e.confirm.push(true)
        var allowed: Int32 = 0
        #expect(prompt.withUnsafeBufferPointer { e.cb.confirm($0.baseAddress, $0.count, &allowed) } == NZ_OK && allowed == 1)
        for i in prompt.indices { prompt[i] = UInt8(ascii: "}") }
        #expect(e.confirm.prompts == [PromptSpec(title: title, lines: ["l1", "l2"], unknown: false, reason: "r", timeoutMillis: 2000)])

        let lineText = "decision=allowed target=ssh:github.com caller=/usr/bin/ssh"
        var line: [UInt8] = Array(lineText.utf8)
        #expect(line.withUnsafeBufferPointer { e.cb.write_audit(5, $0.baseAddress, $0.count) } == NZ_OK)
        for i in line.indices { line[i] = 0 }
        #expect(e.audit.lines == [lineText])
        #expect(e.ledger.liveCount == 0)
    }

    // MARK: keys and approvals

    /// A user-presence key signs only with a live approval from the login
    /// gate; 0, an unknown or a released ref is NZ_AUTH_REQUIRED and the
    /// backend is never asked. AuthNone keys ignore the approval argument.
    @Test func presenceKeysNeedALiveApprovalThroughTheTable() throws {
        let sw = SoftwareEnclaveBackend()
        let e = Env(.init(backend: sw))
        let (handle, pk) = e.key(purpose: 1, auth: 1)
        let msg = Data("approve me".utf8)
        func sign(_ approval: UInt64) -> (Int32, Data) {
            var out = Self.stale()
            let st = call(handle) { hp, hn in self.call(msg) { mp, mn in e.cb.sign(hp, hn, mp, mn, approval, &out) } }
            if st != NZ_OK { #expect(Self.isClear(out)) }
            return (st, st == NZ_OK ? e.take(out) : Data())
        }
        #expect(sign(0).0 == NZ_AUTH_REQUIRED)
        #expect(sign(424_242).0 == NZ_AUTH_REQUIRED)
        #expect(sign(.max).0 == NZ_AUTH_REQUIRED)
        #expect(sw.signCalls == 0)

        e.login.push(true)
        var ref: UInt64 = 0
        #expect(call(Self.prompt) { e.cb.authenticate(1, $0, $1, &ref) } == NZ_OK && ref != 0)
        #expect(e.login.reasons == ["r"])
        let (st, der) = sign(ref)
        #expect(st == NZ_OK)
        let key = try P256.Signing.PublicKey(x963Representation: pk)
        #expect(key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: der), for: msg))
        let ctx = try #require((sw.contexts.last ?? nil) as? ScriptedAuthContext)
        #expect(!ctx.invalidated)

        e.cb.release_approval(ref)
        #expect(ctx.invalidated)
        #expect(sign(ref).0 == NZ_AUTH_REQUIRED)
        #expect(sw.signCalls == 1)

        // Refs are never reused.
        e.login.push(true)
        var ref2: UInt64 = 0
        #expect(call(Self.prompt) { e.cb.authenticate(0, $0, $1, &ref2) } == NZ_OK && ref2 != 0 && ref2 != ref)
        e.cb.release_approval(ref2)

        // AuthNone: any approval value, no context.
        let (plain, _) = e.key(purpose: 1, auth: 0)
        var out = NzBuf()
        #expect(call(plain) { hp, hn in self.call(msg) { mp, mn in e.cb.sign(hp, hn, mp, mn, 999, &out) } } == NZ_OK)
        _ = e.take(out)
        #expect((sw.contexts.last ?? nil) == nil)
        #expect(e.platform.approvals.liveCount == 0 && e.ledger.liveCount == 0)
    }

    /// A handle that names no key is NZ_NOT_FOUND, also when its envelope
    /// claims user presence: a caller learns nothing about approvals from a
    /// key that does not exist.
    @Test func malformedHandlesAreNotFound() {
        let sw = SoftwareEnclaveBackend()
        let e = Env(.init(backend: sw))
        let (real, _) = e.key()
        let cases: [Data] = [
            Data(), Data("NZK1".utf8), Data((0..<70).map { _ in UInt8.random(in: 0...255) }),
            real.prefix(real.count - 1), real + [0x00],
            Data("NZK1".utf8) + [1, 1] + Data(repeating: 0xff, count: 33),
            Data("NZK1".utf8) + [3, 0] + real.suffix(33),
            Data("NZK1".utf8) + [1, 2] + real.suffix(33),
        ]
        for c in cases {
            var out = Self.stale()
            #expect(call(c) { hp, hn in e.cb.sign(hp, hn, nil, 0, 7, &out) } == NZ_NOT_FOUND && Self.isClear(out))
            #expect(call(c) { e.cb.delete_key($0, $1) } == NZ_NOT_FOUND)
        }
        #expect(sw.signCalls == 0 && e.ledger.liveCount == 0)
    }

    @Test func keyAgreementThroughTheTable() throws {
        let e = Env()
        let (ka, pub) = e.key(purpose: 2)
        let peer = P256.KeyAgreement.PrivateKey()
        var out = NzBuf()
        let pp = peer.publicKey.x963Representation
        #expect(call(ka) { hp, hn in self.call(pp) { p, n in e.cb.key_agreement(hp, hn, p, n, 0, &out) } } == NZ_OK)
        let secret = e.take(out)
        let want = try peer.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: pub))
            .withUnsafeBytes { Data($0) }
        #expect(secret == want && secret.count == 32)

        // Purposes do not mix; a bad peer point is refused input.
        let (signKey, _) = e.key(purpose: 1)
        out = Self.stale()
        #expect(call(signKey) { hp, hn in self.call(pp) { p, n in e.cb.key_agreement(hp, hn, p, n, 0, &out) } } == NZ_INVALID)
        #expect(Self.isClear(out))
        out = Self.stale()
        #expect(call(ka) { hp, hn in e.cb.sign(hp, hn, nil, 0, 0, &out) } == NZ_INVALID && Self.isClear(out))
        for bad in [Data(count: 65), Data(pp.prefix(33)), Data(), Data([0x04]) + Data(repeating: 0xff, count: 64)] {
            out = Self.stale()
            #expect(call(ka) { hp, hn in self.call(bad) { p, n in e.cb.key_agreement(hp, hn, p, n, 0, &out) } } == NZ_INVALID)
            #expect(Self.isClear(out))
        }
        #expect(e.ledger.liveCount == 0 && e.ledger.badFrees == 0)
    }

    /// Automated hosts wrap the Secure Enclave in NoUserPresenceBackend: a
    /// user-presence key request through the table is refused input and
    /// allocates nothing.
    @Test func noUserPresenceBackendRefusesThroughTheTable() {
        let e = Env(.init(backend: NoUserPresenceBackend(SoftwareEnclaveBackend())))
        var h = Self.stale(), pub = Self.stale()
        #expect(e.cb.create_key(1, 1, 0, &h, &pub) == NZ_INVALID && Self.isClear(h) && Self.isClear(pub))
        #expect(e.cb.create_key(2, 1, 0, &h, &pub) == NZ_INVALID && Self.isClear(h) && Self.isClear(pub))
        #expect(e.ledger.allocations == 0)
        #expect(e.cb.create_key(1, 0, 0, &h, &pub) == NZ_OK)
        _ = e.take(h)
        _ = e.take(pub)
        #expect(e.ledger.liveCount == 0)
    }

    // MARK: gates

    /// The prompt reaches the gate exactly as Go sent it; a deny is an
    /// answer (NZ_OK, allowed 0), a failing dialog is its status; refused
    /// input (bad policy, bad or incomplete JSON) never shows anything.
    @Test func promptsAreDecodedStrictlyAndBadOnesNeverShow() {
        let e = Env()
        let full = Data(#"{"title":"Allow ssh?","lines":["a","b"],"commandLine":0,"unknown":true,"reason":"why","timeoutMillis":1500}"#.utf8)
        e.confirm.push(false)
        var allowed: Int32 = 1
        #expect(call(full) { e.cb.confirm($0, $1, &allowed) } == NZ_OK && allowed == 0)
        #expect(e.confirm.prompts == [PromptSpec(title: "Allow ssh?", lines: ["a", "b"], unknown: true, reason: "why", timeoutMillis: 1500)])

        let missing = Data(#"{"title":"t","lines":[],"unknown":false,"reason":"r"}"#.utf8) // no timeoutMillis
        let wrongType = Data(#"{"title":"t","lines":"x","unknown":false,"reason":"r","timeoutMillis":1}"#.utf8)
        for bad in [missing, wrongType, Data("null".utf8), Data([0xff])] {
            allowed = 1
            #expect(call(bad) { e.cb.confirm($0, $1, &allowed) } == NZ_INVALID && allowed == 0)
            var ref: UInt64 = 5
            #expect(call(bad) { e.cb.authenticate(1, $0, $1, &ref) } == NZ_INVALID && ref == 0)
        }
        e.login.defaultAnswer = true
        for policy: Int32 in [-1, 2, .max, .min] {
            var ref: UInt64 = 5
            #expect(call(Self.prompt) { e.cb.authenticate(policy, $0, $1, &ref) } == NZ_INVALID && ref == 0)
        }
        #expect(e.confirm.prompts.count == 1 && e.login.reasons.isEmpty && e.platform.approvals.liveCount == 0)
    }

    @Test func aFailingDialogReturnsItsStatus() {
        let dialog = ThrowingConfirmer(.denied)
        let e = Env(.init(dialog: dialog))
        var allowed: Int32 = 1
        #expect(call(Self.prompt) { e.cb.confirm($0, $1, &allowed) } == NZ_DENIED && allowed == 0)
        #expect(dialog.calls == 1)
        let failing = ThrowingConfirmer(.failed("no window"))
        let e2 = Env(.init(dialog: failing))
        allowed = 1
        #expect(call(Self.prompt) { e2.cb.confirm($0, $1, &allowed) } == NZ_ERR && allowed == 0)
    }

    // MARK: callers

    @Test func peerOfThroughTheTable() throws {
        let e = Env()
        let f = try PeerFixture()
        var pid: Int64 = 0, gen: UInt64 = 0
        #expect(e.cb.peer_of(f.conn, &pid, &gen) == NZ_OK)
        #expect(pid == Int64(f.nc.processIdentifier) && gen != 0 && gen == KernelProc.info(Int32(pid))?.generation)
        var info = NzBuf()
        #expect(e.cb.process(pid, gen, &info) == NZ_OK)
        let rec = try Wire.decode(ProcessRecord.self, e.take(info))
        #expect(rec.path == "/usr/bin/nc" && rec.generation == gen)
        f.killPeer()
        pid = 5; gen = 6
        #expect(e.cb.peer_of(f.conn, &pid, &gen) == NZ_NO_PROCESS && pid == 0 && gen == 0)
        var p: [Int32] = [0, 0]
        #expect(pipe(&p) == 0)
        defer { close(p[0]); close(p[1]) }
        #expect(e.cb.peer_of(p[0], &pid, &gen) == NZ_NO_PROCESS && pid == 0 && gen == 0)
        #expect(e.cb.peer_of(.max, &pid, &gen) == NZ_NO_PROCESS)
        #expect(e.ledger.liveCount == 0)
    }

    /// A full ref answers only that instance; a PID-only ref answers the live
    /// occupant with its full ref; anything else is NZ_NO_PROCESS.
    /// ResponsibleFor answers NZ_NOT_FOUND, never NZ_NO_PROCESS, for
    /// anything it cannot name (platform.ResponsibleFor has only ok=false).
    @Test func processRefsThroughTheTable() throws {
        let e = Env()
        let me = Int64(getpid())
        let gen = try #require(KernelProc.info(getpid())?.generation)
        var out = NzBuf()
        #expect(e.cb.process(me, 0, &out) == NZ_OK)
        let rec = try Wire.decode(ProcessRecord.self, e.take(out))
        #expect(rec.pid == getpid() && rec.generation == gen && rec.uid == Int64(getuid()))
        #expect(e.cb.process(me, gen, &out) == NZ_OK)
        _ = e.take(out)
        // Out of Int32 range is never truncated to a PID (1 << 32 | me would otherwise name this process).
        let badRefs: [(Int64, UInt64)] = [(me, gen + 1), (0, 0), (-1, 0), (Int64.min, 0), (Int64.max, gen),
                                          ((Int64(1) << 32) | me, gen), ((Int64(1) << 32) | me, 0), ((Int64(-1) << 32) | me, gen)]
        for (pid, g) in badRefs {
            out = Self.stale()
            #expect(e.cb.process(pid, g, &out) == NZ_NO_PROCESS && Self.isClear(out))
        }

        let s = try Sleeper()
        let sg = try #require(KernelProc.info(s.pid)?.generation)
        s.kill()
        out = Self.stale()
        #expect(e.cb.process(Int64(s.pid), sg, &out) == NZ_NO_PROCESS && Self.isClear(out))

        var r: Int64 = 3
        let direct = ProcessResolver().responsibleFor(ProcessRef(pid: getpid(), generation: gen))
        let st = e.cb.responsible_for(me, gen, &r)
        if let direct {
            #expect(st == NZ_OK && r == Int64(direct))
        } else {
            #expect(st == NZ_NOT_FOUND && r == 0)
        }
        let unknown: [(Int64, UInt64)] = [(me, gen + 1), (Int64(s.pid), sg), (-1, 0), (0, 0), (Int64.max, 0), (Int64.min, 1),
                                          ((Int64(1) << 32) | me, 0)]
        for (pid, g) in unknown {
            r = 3
            #expect(e.cb.responsible_for(pid, g, &r) == NZ_NOT_FOUND && r == 0)
        }
        #expect(e.ledger.liveCount == 0)
    }

    /// AppFor decides from the live process, never from the record; a
    /// forged or PID-only record is no app; oversized JSON is refused.
    @Test func appForThroughTheTable() throws {
        let e = Env(.init(resolver: ProcessResolver(gui: AllApps())))
        var out = NzBuf()
        #expect(e.cb.process(Int64(getpid()), 0, &out) == NZ_OK)
        let rec = try Wire.decode(ProcessRecord.self, e.take(out))
        #expect(call(try Wire.encode([rec])) { e.cb.app_for($0, $1, &out) } == NZ_OK)
        let app = try Wire.decode(AppRecord.self, e.take(out))
        #expect(app.pid == getpid() && app.generation == rec.generation && app.bundleId == "com.example.claimed")

        var forged = rec
        forged.generation += 1
        var pidOnly = rec
        pidOnly.generation = 0
        for bad in [forged, pidOnly] {
            out = Self.stale()
            #expect(call(try Wire.encode([bad])) { e.cb.app_for($0, $1, &out) } == NZ_NOT_FOUND && Self.isClear(out))
        }
        let huge = Data("[".utf8) + Data(repeating: UInt8(ascii: " "), count: Wire.maxDocument) + Data("]".utf8)
        out = Self.stale()
        #expect(call(huge) { e.cb.app_for($0, $1, &out) } == NZ_INVALID && Self.isClear(out))
        #expect(e.ledger.liveCount == 0)
    }

    /// Apps through the table (Milestone 7): an empty array when the lookup
    /// names nothing, the resolver's records otherwise, NZ_ERR for no
    /// buffer; every buffer comes back.
    @Test func appsThroughTheTable() throws {
        let gui = AllApps()
        let e = Env(.init(resolver: ProcessResolver(gui: gui)))
        var out = NzBuf()
        #expect(e.cb.apps(&out) == NZ_OK)
        #expect(try Wire.decode([AppRecord].self, e.take(out)).isEmpty)
        gui.running = [getpid(), 0]
        out = Self.stale()
        #expect(e.cb.apps(&out) == NZ_OK)
        let apps = try Wire.decode([AppRecord].self, e.take(out))
        #expect(apps.count == 1 && apps[0].pid == getpid() && apps[0].bundleId == "com.example.claimed" && apps[0].generation != 0)
        #expect(e.cb.apps(nil) == NZ_ERR)
        #expect(e.ledger.liveCount == 0)
    }

    /// CodeHash hashes exactly the absolute path Go named: a relative path
    /// (it would resolve against Nazar.app's own working directory) and a
    /// path with an embedded NUL (C would see only the part before it) are
    /// never hashed.
    @Test func codeHashThroughTheTable() throws {
        let e = Env()
        var out = NzBuf()
        #expect(call(Data("/bin/sleep".utf8)) { e.cb.code_hash($0, $1, &out) } == NZ_OK)
        let h = e.take(out)
        #expect(h == (try CodeSigning.cdhash(path: "/bin/sleep")) && h.count == 20)

        let relative = String(repeating: "../", count: 64) + "bin/sleep" // resolves to /bin/sleep from any cwd
        for bad in [relative, "bin/sleep", "/bin/sleep\0/etc/passwd", ""] {
            out = Self.stale()
            #expect(call(Data(bad.utf8)) { e.cb.code_hash($0, $1, &out) } != NZ_OK)
            #expect(Self.isClear(out))
        }
        #expect(e.ledger.liveCount == 0)
    }

    @Test func installedAppThroughTheTable() throws {
        let loc = FakeLocator()
        loc.byId["com.example.app"] = [URL(fileURLWithPath: "/Applications/E.app")]
        loc.byId["com.example.two"] = [URL(fileURLWithPath: "/Applications/A.app"), URL(fileURLWithPath: "/Applications/B.app")]
        let teamA = CodeIdentity(signed: true, teamId: "AAAAAAAAAA", signingId: "com.example.app", cdhash: Data([1, 2]))
        let teamB = CodeIdentity(signed: true, teamId: "BBBBBBBBBB", signingId: "com.example.two")
        let codes: [String: (String, CodeIdentity)] = ["/Applications/E.app": ("com.example.app", teamA), "/Applications/A.app": ("com.example.two", teamA),
                     "/Applications/B.app": ("com.example.two", teamB)]
        let apps = InstalledApps(locator: loc, inspect: { url in codes[url.path].map { (bundleId: $0.0, code: $0.1) } },
                                 roots: ["/Applications/"])
        let e = Env(.init(installed: apps))
        var out = NzBuf()
        #expect(call(Data("com.example.app".utf8)) { e.cb.installed_app($0, $1, &out) } == NZ_OK)
        let b = try Wire.decode(AppBundleRecord.self, e.take(out))
        #expect(b == AppBundleRecord(bundleId: "com.example.app", path: "/Applications/E.app", code: teamA))
        out = Self.stale()
        #expect(call(Data("com.example.none".utf8)) { e.cb.installed_app($0, $1, &out) } == NZ_NOT_FOUND && Self.isClear(out))
        out = Self.stale()
        #expect(call(Data("com.example.two".utf8)) { e.cb.installed_app($0, $1, &out) } == NZ_AMBIGUOUS && Self.isClear(out))
        for bad in [Data("com.example.app\n".utf8), Data(), Data([0xff, 0xfe]), Data("com.example.app\0x".utf8)] {
            out = Self.stale()
            #expect(call(bad) { e.cb.installed_app($0, $1, &out) } == NZ_INVALID && Self.isClear(out))
        }
        #expect(e.ledger.liveCount == 0)
    }

    // MARK: events

    /// Each watch fires exactly once with its own token: on exit, or
    /// promptly for a ref that names no live instance (PID-only, wrong
    /// generation, out of range).
    @Test func exitWatchesFireOncePerToken() throws {
        let e = Env()
        let s = try Sleeper()
        let sg = try #require(KernelProc.info(s.pid)?.generation)
        e.cb.watch_exit(Int64(s.pid), sg, 1)
        e.cb.watch_exit(Int64(s.pid), sg + 1, 2) // wrong generation: not this instance
        e.cb.watch_exit(Int64(s.pid), 0, 3)       // PID-only names no instance
        e.cb.watch_exit(.max, 1, 4)
        e.cb.watch_exit(.min, 1, 5)
        #expect(e.exits.wait(for: 4))
        e.lock.lock()
        #expect(Set(e.exitTokens) == [2, 3, 4, 5]) // the live one has not fired
        e.lock.unlock()
        s.kill()
        #expect(e.exits.wait(for: 5))
        RunLoop.current.run(until: Date().addingTimeInterval(0.3))
        e.lock.lock()
        #expect(e.exitTokens.sorted() == [1, 2, 3, 4, 5])
        e.lock.unlock()
    }

    @Test func screenLocksFireEveryRegisteredToken() {
        let e = Env()
        #expect(e.lockName != ScreenLockWatcher.systemName)
        e.cb.watch_screen_lock(11)
        e.cb.watch_screen_lock(12)
        for _ in 0..<2 {
            DistributedNotificationCenter.default().postNotificationName(Notification.Name(e.lockName), object: nil,
                                                                        userInfo: nil, deliverImmediately: true)
        }
        #expect(e.locks.wait(for: 4))
        e.lock.lock()
        #expect(e.lockTokens.sorted() == [11, 11, 12, 12])
        e.lock.unlock()
    }

    @Test func warningsDecodeEveryFieldAndIgnoreBadInput() {
        let e = Env()
        let w = Data(#"{"id":"ssh:x","title":"Blocked","lines":["a","b"],"commandLine":2,"count":3,"suggestedRule":"rule: x"}"#.utf8)
        _ = call(w) { e.cb.show_warning($0, $1); return 0 }
        _ = call(Data(#"{"id":"m","title":"t","lines":[],"count":1}"#.utf8)) { e.cb.show_warning($0, $1); return 0 } // no suggestedRule
        _ = call(Data([0xff, 0x7b])) { e.cb.show_warning($0, $1); return 0 }
        e.cb.show_warning(nil, 12)
        e.cb.show_warning(nil, 0)
        #expect(e.warnings.shown == [WarningSpec(id: "ssh:x", title: "Blocked", lines: ["a", "b"], commandLine: 2, count: 3, suggestedRule: "rule: x")])
    }

    // MARK: vault and audit

    @Test func vaultEdgeCases() throws {
        let e = Env()
        func put(_ n: Data, _ v: Data) -> Int32 { call(n) { np, nn in self.call(v) { vp, vn in e.cb.vault_put(np, nn, vp, vn) } } }
        func get(_ n: Data) -> (Int32, Data) {
            var out = NzBuf()
            let st = call(n) { e.cb.vault_get($0, $1, &out) }
            return (st, e.take(out))
        }
        func list(_ p: String) throws -> Data {
            var out = NzBuf()
            #expect(call(Data(p.utf8)) { e.cb.vault_list($0, $1, &out) } == NZ_OK)
            return e.take(out)
        }
        // An empty value is a value.
        #expect(put(Data("empty".utf8), Data()) == NZ_OK)
        let (st, v) = get(Data("empty".utf8))
        #expect(st == NZ_OK && v.isEmpty)
        // Binary values round-trip byte for byte; a put replaces.
        let bin = Data([0, 0xff, 0, 0x80, 0x0a])
        #expect(put(Data("bin".utf8), Data("old".utf8)) == NZ_OK)
        #expect(put(Data("bin".utf8), bin) == NZ_OK)
        let g = get(Data("bin".utf8))
        #expect(g.0 == NZ_OK && g.1 == bin)
        // Lists are JSON arrays, sorted, matched by literal prefix; none is [] (never null).
        #expect(put(Data("ssh-key/b".utf8), Data([1])) == NZ_OK)
        #expect(put(Data("ssh-key/a".utf8), Data([1])) == NZ_OK)
        #expect(put(Data("ssh-keyX".utf8), Data([1])) == NZ_OK)
        #expect(try list("nothing/") == Data("[]".utf8))
        #expect(try Wire.decode([String].self, list("ssh-key/")) == ["ssh-key/a", "ssh-key/b"])
        #expect(try Wire.decode([String].self, list("")) == ["bin", "empty", "ssh-key/a", "ssh-key/b", "ssh-keyX"])
        #expect(try Wire.decode([String].self, list("ssh-key.")).isEmpty)
        // Names must be UTF-8.
        let badName = Data([0x73, 0xff])
        #expect(put(badName, Data([1])) == NZ_INVALID)
        #expect(get(badName).0 == NZ_INVALID)
        #expect(call(badName) { e.cb.vault_delete($0, $1) } == NZ_INVALID)
        #expect(try e.vault.list(prefix: "").count == 5)
        #expect(e.ledger.liveCount == 0 && e.ledger.badFrees == 0)
    }

    /// Vault and audit errors cross as their NZ_* status, outputs cleared.
    @Test func vaultAndAuditErrorsMapToStatusCodes() {
        let tv = ThrowingVault()
        let ra = RecordingAudit()
        let e = Env(.init(vault: tv, audit: ra))
        let cases: [(PlatformError, Int)] = [
            (.notFound, Int(NZ_NOT_FOUND)), (.noProcess, Int(NZ_NO_PROCESS)), (.denied, Int(NZ_DENIED)),
            (.authRequired, Int(NZ_AUTH_REQUIRED)), (.ambiguous, Int(NZ_AMBIGUOUS)), (.invalid("x"), Int(NZ_INVALID)),
            (.failed("locked"), Int(NZ_ERR)),
        ]
        let n = Data("n".utf8)
        for (err, code) in cases {
            tv.error = err
            var out = Self.stale()
            #expect(call(n) { e.cb.vault_get($0, $1, &out) } == code && Self.isClear(out))
            #expect(call(n) { np, nn in self.call(n) { vp, vn in e.cb.vault_put(np, nn, vp, vn) } } == code)
            #expect(call(n) { e.cb.vault_delete($0, $1) } == code)
            out = Self.stale()
            #expect(call(n) { e.cb.vault_list($0, $1, &out) } == code && Self.isClear(out))
            ra.error = err
            #expect(call(n) { e.cb.write_audit(1, $0, $1) } == code)
        }
        tv.error = SomeOtherError()
        ra.error = SomeOtherError()
        var out = Self.stale()
        #expect(call(n) { e.cb.vault_get($0, $1, &out) } != NZ_OK && Self.isClear(out))
        #expect(call(n) { e.cb.write_audit(1, $0, $1) } != NZ_OK)

        ra.error = nil
        #expect(call(Data("line one".utf8)) { e.cb.write_audit(1_700_000_000_123_456_789, $0, $1) } == NZ_OK)
        #expect(call(Data("".utf8)) { e.cb.write_audit(.min, $0, $1) } == NZ_OK)
        #expect(call(Data([0x61, 0xff])) { e.cb.write_audit(5, $0, $1) } == NZ_INVALID)
        #expect(ra.entries.map { $0.0 } == [1_700_000_000_123_456_789, .min] && ra.entries.map { $0.1 } == ["line one", ""])
        #expect(e.ledger.allocations == 0)
    }

    // MARK: concurrency

    /// Go calls from many threads at once (nazar_bridge.h: "any thread,
    /// concurrently"); the ledger stays exact.
    @Test func concurrentCallsKeepTheLedgerExact() throws {
        let e = Env()
        let threads = 8, rounds = 20
        let failures = Counter()
        DispatchQueue.concurrentPerform(iterations: threads) { t in
            for i in 0..<rounds {
                var h = NzBuf(), pub = NzBuf()
                guard e.cb.create_key(1, 0, 0, &h, &pub) == NZ_OK else { failures.hit(); continue }
                let handle = e.take(h)
                _ = e.take(pub)
                var sig = NzBuf()
                let msg = Data("\(t)-\(i)".utf8)
                if call(handle, { hp, hn in self.call(msg) { mp, mn in e.cb.sign(hp, hn, mp, mn, 0, &sig) } }) != NZ_OK { failures.hit() }
                _ = e.take(sig)
                let name = Data("k/\(t)/\(i)".utf8)
                if call(name, { np, nn in self.call(handle) { vp, vn in e.cb.vault_put(np, nn, vp, vn) } }) != NZ_OK { failures.hit() }
            }
        }
        #expect(failures.count == 0)
        #expect(e.ledger.allocations == threads * rounds * 3 && e.ledger.liveCount == 0 && e.ledger.badFrees == 0)
        #expect(try e.vault.list(prefix: "k/").count == threads * rounds)
    }
}
