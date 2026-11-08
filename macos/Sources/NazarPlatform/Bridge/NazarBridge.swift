import CNazarBridge
import Foundation

/// The Swift end of the C ABI (nazar_bridge.h). install() makes the one
/// runtime of this process and returns the NazarCallbacks table to hand to
/// NazarCoreStart (Nazar.app) or NazarRunConformance (the conformance host).
///
/// Every callback: copies its inputs before use (they belong to Go), clears
/// its NzBuf outputs first, fills them only on success with buffers from
/// the ledger, never throws or traps across the boundary, and answers an
/// NZ_* status. A NULL output pointer is NZ_ERR before any work is done (an
/// answer that cannot be returned must not cost a prompt, a key or an
/// approval). free_buf frees only buffers the ledger handed out.
public enum NazarBridge {
    public struct Runtime {
        public var platform: SwiftPlatform
        public var vault: VaultStore
        public var audit: AuditWriter
        public var ledger: BufferLedger
        /// Calls Go's NazarProcessExited(token).
        public var exitFired: @Sendable (UInt64) -> Void
        /// Calls Go's NazarScreenLocked(token).
        public var screenLocked: @Sendable (UInt64) -> Void
        /// Calls Go's NazarProcessExecd(token, record); nil leaves the exec
        /// callbacks out of the table (secrets design 6.3, D8).
        public var execFired: (@Sendable (UInt64, Data) -> Void)?
        public init(platform: SwiftPlatform, vault: VaultStore, audit: AuditWriter, ledger: BufferLedger = .shared,
                    exitFired: @escaping @Sendable (UInt64) -> Void, screenLocked: @escaping @Sendable (UInt64) -> Void,
                    execFired: (@Sendable (UInt64, Data) -> Void)? = nil) {
            self.platform = platform
            self.vault = vault
            self.audit = audit
            self.ledger = ledger
            self.exitFired = exitFired
            self.screenLocked = screenLocked
            self.execFired = execFired
        }
    }

    /// Inputs larger than this are refused (NZ_INVALID) before any byte is read.
    public static let maxInput = 16 << 20

    private static let lock = NSLock()
    nonisolated(unsafe) private static var runtime: Runtime?

    /// The installed runtime, or nil before install().
    static var current: Runtime? {
        lock.lock()
        defer { lock.unlock() }
        return runtime
    }

    /// Installs the runtime and returns a callbacks table that lives for
    /// the rest of the process (Go keeps a copy; the original is never freed).
    public static func install(_ r: Runtime) -> UnsafeMutablePointer<NazarCallbacks> {
        lock.lock()
        runtime = r
        lock.unlock()
        let p = UnsafeMutablePointer<NazarCallbacks>.allocate(capacity: 1)
        p.initialize(to: table(r))
        return p
    }

    /// The table for r. The exec slots are set only when r has an exec
    /// watcher and a way to reach Go; else NULL, and Go offers no Exec
    /// (secrets design 6.3, D8: late-env refused).
    static func table(_ r: Runtime) -> NazarCallbacks {
        let exec = r.platform.execs != nil && r.execFired != nil
        return NazarCallbacks(
            abi_version: NAZAR_ABI_VERSION,
            create_key: cbCreateKey, sign: cbSign, key_agreement: cbKeyAgreement, delete_key: cbDeleteKey,
            authenticate: cbAuthenticate, confirm: cbConfirm, release_approval: cbReleaseApproval,
            peer_of: cbPeerOf, process: cbProcess, app_for: cbAppFor, code_hash: cbCodeHash,
            responsible_for: cbResponsibleFor, installed_app: cbInstalledApp, apps: cbApps,
            watch_exit: cbWatchExit, watch_screen_lock: cbWatchScreenLock, show_warning: cbShowWarning,
            watch_exec: exec ? cbWatchExec : nil, cancel_exec: exec ? cbCancelExec : nil,
            environment: exec ? cbEnvironment : nil,
            vault_get: cbVaultGet, vault_put: cbVaultPut, vault_delete: cbVaultDelete, vault_list: cbVaultList,
            write_audit: cbWriteAudit, free_buf: cbFreeBuf)
    }

    // MARK: helpers

    /// Runs body and answers its outcome as a status: a PlatformError is its
    /// own code, a JSON decoding failure is refused input (NZ_INVALID), and
    /// anything else is NZ_ERR. Nothing propagates across the boundary.
    static func status(_ body: () throws -> Void) -> Int32 {
        do {
            try body()
            return Int32(NZ_OK)
        } catch let e as PlatformError {
            return e.code
        } catch is DecodingError {
            return Int32(NZ_INVALID)
        } catch {
            return Int32(NZ_ERR)
        }
    }

    /// The Runtime's execFired for a host whose Go archive exports
    /// NazarProcessExecd: hands it the record's bytes for the call only.
    public static func execFired(_ export: @escaping @Sendable (UInt64, UnsafeMutablePointer<UInt8>?, Int) -> Void)
        -> @Sendable (UInt64, Data) -> Void {
        { token, record in
            record.withUnsafeBytes {
                export(token, UnsafeMutablePointer(mutating: $0.bindMemory(to: UInt8.self).baseAddress), $0.count)
            }
        }
    }

    /// A copy of an input buffer. The length is never trusted: negative (a
    /// huge size_t) or above maxInput is refused before any byte is read, and
    /// NULL is accepted only with length 0.
    static func input(_ p: UnsafePointer<UInt8>?, _ n: Int) throws -> Data {
        guard n >= 0, n <= maxInput else { throw PlatformError.invalid("input too large") }
        if n == 0 { return Data() }
        guard let p else { throw PlatformError.invalid("NULL input") }
        return Data(bytes: p, count: n)
    }

    /// An input buffer as UTF-8 text (the ABI's strings carry no NUL
    /// terminator; a NUL inside is still valid UTF-8 and left to the callee).
    static func text(_ p: UnsafePointer<UInt8>?, _ n: Int) throws -> String {
        guard let s = String(data: try input(p, n), encoding: .utf8) else { throw PlatformError.invalid("not UTF-8") }
        return s
    }

    static func clear(_ b: UnsafeMutablePointer<NzBuf>?) {
        b?.pointee = NzBuf(ptr: nil, len: 0)
    }

    static func fill(_ b: UnsafeMutablePointer<NzBuf>, _ d: Data, _ ledger: BufferLedger) {
        let (p, n) = ledger.allocate(d)
        b.pointee = NzBuf(ptr: p, len: n)
    }

    /// The ref Go named, or .noProcess for a PID no process can have: an
    /// int64 outside Int32 is never truncated (1 << 32 | pid would otherwise
    /// name pid).
    static func ref(_ pid: Int64, _ gen: UInt64) throws -> ProcessRef {
        guard pid > 0, pid <= Int64(Int32.max) else { throw PlatformError.noProcess }
        return ProcessRef(pid: Int32(pid), generation: gen)
    }
}

// The callbacks are file-level constants: @convention(c) closures can't
// capture, so they reach the runtime through NazarBridge.current.

private typealias NB = NazarBridge

// MARK: keys

let cbCreateKey: @convention(c) (Int32, Int32, Int32, UnsafeMutablePointer<NzBuf>?, UnsafeMutablePointer<NzBuf>?) -> Int32 = { purpose, auth, access, h, pub in
    NB.clear(h); NB.clear(pub)
    guard let rt = NB.current, let h, let pub else { return Int32(NZ_ERR) }
    return NB.status {
        let (handle, pk) = try rt.platform.enclave.createKey(purpose: purpose, auth: auth, access: access)
        NB.fill(h, handle, rt.ledger)
        NB.fill(pub, pk, rt.ledger)
    }
}

let cbSign: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UInt64, UnsafeMutablePointer<NzBuf>?) -> Int32 = { hp, hn, dp, dn, approval, out in
    NB.clear(out)
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status {
        let handle = try NB.input(hp, hn)
        let data = try NB.input(dp, dn)
        let sig = try rt.platform.enclave.sign(handle: handle, data: data, approval: approval)
        NB.fill(out, sig, rt.ledger)
    }
}

let cbKeyAgreement: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UInt64, UnsafeMutablePointer<NzBuf>?) -> Int32 = { hp, hn, pp, pn, approval, out in
    NB.clear(out)
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status {
        let handle = try NB.input(hp, hn)
        let peer = try NB.input(pp, pn)
        let secret = try rt.platform.enclave.keyAgreement(handle: handle, peer: peer, approval: approval)
        NB.fill(out, secret, rt.ledger)
    }
}

let cbDeleteKey: @convention(c) (UnsafePointer<UInt8>?, Int) -> Int32 = { hp, hn in
    guard let rt = NB.current else { return Int32(NZ_ERR) }
    return NB.status { try rt.platform.enclave.deleteKey(handle: NB.input(hp, hn)) }
}

// MARK: approvals

let cbAuthenticate: @convention(c) (Int32, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UInt64>?) -> Int32 = { policy, jp, jn, out in
    out?.pointee = 0
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status {
        let prompt = try Wire.decode(PromptSpec.self, NB.input(jp, jn))
        out.pointee = try rt.platform.login.authenticate(policy: policy, prompt: prompt)
    }
}

let cbConfirm: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<Int32>?) -> Int32 = { jp, jn, out in
    out?.pointee = 0
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status {
        let prompt = try Wire.decode(PromptSpec.self, NB.input(jp, jn))
        // How it ended (nazar_bridge.h); only .allowed (1) allows.
        out.pointee = try rt.platform.dialog.answer(prompt).rawValue
    }
}

let cbReleaseApproval: @convention(c) (UInt64) -> Void = { ref in
    NB.current?.platform.approvals.release(ref)
}

// MARK: callers

let cbPeerOf: @convention(c) (Int32, UnsafeMutablePointer<Int64>?, UnsafeMutablePointer<UInt64>?) -> Int32 = { fd, pid, gen in
    pid?.pointee = 0
    gen?.pointee = 0
    guard let rt = NB.current, let pid, let gen else { return Int32(NZ_ERR) }
    return NB.status {
        let r = try rt.platform.resolver.peerOf(fd: fd)
        pid.pointee = Int64(r.pid)
        gen.pointee = r.generation
    }
}

let cbProcess: @convention(c) (Int64, UInt64, UnsafeMutablePointer<NzBuf>?) -> Int32 = { pid, gen, out in
    NB.clear(out)
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status {
        let rec = try rt.platform.resolver.process(NB.ref(pid, gen))
        NB.fill(out, try Wire.encode(rec), rt.ledger)
    }
}

let cbAppFor: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<NzBuf>?) -> Int32 = { jp, jn, out in
    NB.clear(out)
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status {
        let chain = try Wire.decode([ProcessRecord].self, NB.input(jp, jn))
        guard let app = rt.platform.resolver.appFor(chain) else { throw PlatformError.notFound }
        NB.fill(out, try Wire.encode(app), rt.ledger)
    }
}

let cbCodeHash: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<NzBuf>?) -> Int32 = { pp, pn, out in
    NB.clear(out)
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status {
        let path = try NB.text(pp, pn)
        // Only the absolute path Go named is ever hashed: a relative one
        // would resolve against Nazar.app's own working directory, and C
        // would see only the part of a path before an embedded NUL.
        guard path.hasPrefix("/"), !path.contains("\0") else { throw PlatformError.notFound }
        NB.fill(out, try CodeSigning.cdhash(path: path), rt.ledger)
    }
}

let cbResponsibleFor: @convention(c) (Int64, UInt64, UnsafeMutablePointer<Int64>?) -> Int32 = { pid, gen, out in
    out?.pointee = 0
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status {
        guard let ref = try? NB.ref(pid, gen), let r = rt.platform.resolver.responsibleFor(ref) else {
            throw PlatformError.notFound // unknown, never an error (platform.ResponsibleFor's ok=false)
        }
        out.pointee = Int64(r)
    }
}

let cbInstalledApp: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<NzBuf>?) -> Int32 = { bp, bn, out in
    NB.clear(out)
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status {
        let b = try rt.platform.installed.installedApp(NB.text(bp, bn))
        NB.fill(out, try Wire.encode(b), rt.ledger)
    }
}

let cbApps: @convention(c) (UnsafeMutablePointer<NzBuf>?) -> Int32 = { out in
    NB.clear(out)
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status {
        NB.fill(out, try Wire.encode(rt.platform.resolver.apps()), rt.ledger)
    }
}

// MARK: events

let cbWatchExit: @convention(c) (Int64, UInt64, UInt64) -> Void = { pid, gen, token in
    guard let rt = NB.current else { return }
    // A PID no process can have names no instance: the watcher fires promptly.
    let r = (pid > 0 && pid <= Int64(Int32.max)) ? ProcessRef(pid: Int32(pid), generation: gen) : ProcessRef(pid: 0, generation: 0)
    let fire = rt.exitFired
    rt.platform.exits.watch(r) { fire(token) }
}

let cbWatchScreenLock: @convention(c) (UInt64) -> Void = { token in
    guard let rt = NB.current else { return }
    let fire = rt.screenLocked
    rt.platform.screenLocks.register { fire(token) }
}

let cbShowWarning: @convention(c) (UnsafePointer<UInt8>?, Int) -> Void = { jp, jn in
    guard let rt = NB.current, let d = try? NB.input(jp, jn), let w = try? Wire.decode(WarningSpec.self, d) else { return }
    rt.platform.warnings.show(w)
}

// MARK: exec (optional, D8)

let cbWatchExec: @convention(c) (Int64, UInt64, UInt64) -> Int32 = { pid, gen, token in
    guard let rt = NB.current, let execs = rt.platform.execs, let fire = rt.execFired else { return Int32(NZ_ERR) }
    return NB.status {
        try execs.watch(NB.ref(pid, gen), token: token) { rec in
            fire(token, (try? Wire.encode(rec)) ?? Data()) // an empty record is still an exec, of nothing
        }
    }
}

let cbCancelExec: @convention(c) (UInt64) -> Void = { token in
    NB.current?.platform.execs?.cancel(token: token)
}

let cbEnvironment: @convention(c) (Int64, UInt64, UnsafeMutablePointer<NzBuf>?) -> Int32 = { pid, gen, out in
    NB.clear(out)
    guard let rt = NB.current, let execs = rt.platform.execs, let out else { return Int32(NZ_ERR) }
    return NB.status { NB.fill(out, try Wire.encode(execs.environment(NB.ref(pid, gen))), rt.ledger) }
}

// MARK: vault and audit

let cbVaultGet: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<NzBuf>?) -> Int32 = { np, nn, out in
    NB.clear(out)
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status { NB.fill(out, try rt.vault.get(NB.text(np, nn)), rt.ledger) }
}

let cbVaultPut: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int) -> Int32 = { np, nn, vp, vn in
    guard let rt = NB.current else { return Int32(NZ_ERR) }
    return NB.status {
        let name = try NB.text(np, nn)
        let value = try NB.input(vp, vn)
        try rt.vault.put(name, value)
    }
}

let cbVaultDelete: @convention(c) (UnsafePointer<UInt8>?, Int) -> Int32 = { np, nn in
    guard let rt = NB.current else { return Int32(NZ_ERR) }
    return NB.status { try rt.vault.delete(NB.text(np, nn)) }
}

let cbVaultList: @convention(c) (UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<NzBuf>?) -> Int32 = { pp, pn, out in
    NB.clear(out)
    guard let rt = NB.current, let out else { return Int32(NZ_ERR) }
    return NB.status { NB.fill(out, try Wire.encode(rt.vault.list(prefix: NB.text(pp, pn))), rt.ledger) }
}

let cbWriteAudit: @convention(c) (Int64, UnsafePointer<UInt8>?, Int) -> Int32 = { nanos, lp, ln in
    guard let rt = NB.current else { return Int32(NZ_ERR) }
    return NB.status { try rt.audit.write(unixNanos: nanos, line: NB.text(lp, ln)) }
}

let cbFreeBuf: @convention(c) (UnsafeMutablePointer<UInt8>?) -> Void = { p in
    (NB.current?.ledger ?? BufferLedger.shared).free(p)
}
