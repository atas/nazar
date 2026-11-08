import AppKit
import Darwin
import Foundation

/// Decides whether a live process is a GUI app bundle (spec 4.1 step 3).
public protocol GUIAppLookup: AnyObject {
    /// The bundle ID and display name of pid when it is a regular
    /// (Dock-level) app whose executable lives inside its bundle.
    func app(pid: Int32) -> (bundleId: String, name: String)?
    /// The PIDs of the running regular apps: candidates for Platform.Apps,
    /// each of which the resolver then judges exactly as app(pid:) and
    /// appFor do (Milestone 7).
    func regularApps() -> [Int32]
}

/// NSRunningApplication-based lookup.
public final class RunningAppLookup: GUIAppLookup, @unchecked Sendable {
    public init() {}
    public func regularApps() -> [Int32] {
        NSWorkspace.shared.runningApplications.filter { $0.activationPolicy == .regular }.map(\.processIdentifier)
    }

    public func app(pid: Int32) -> (bundleId: String, name: String)? {
        guard pid > 0, let app = NSRunningApplication(processIdentifier: pid), app.activationPolicy == .regular,
              let id = app.bundleIdentifier, !id.isEmpty, let bundle = app.bundleURL?.resolvingSymlinksInPath().path
        else { return nil }
        // A command-line tool can claim a bundle ID through an embedded
        // Info.plist and turn itself into a regular app; its executable is
        // then not inside a bundle.
        guard KernelProc.path(pid).hasPrefix(bundle + "/Contents/MacOS/") else { return nil }
        return (id, app.localizedName ?? id)
    }
}

/// The caller half of the Platform contract: PeerOf, Process, AppFor,
/// Apps, ResponsibleFor (core/platform, spike S3).
public final class ProcessResolver: @unchecked Sendable {
    static let LOCAL_PEERTOKEN: Int32 = 0x006 // <sys/un.h>
    static let SOL_LOCAL: Int32 = 0
    static let maxTokens = 256

    private let gui: GUIAppLookup
    private let lock = NSLock()
    private var tokens: [ProcessRef: audit_token_t] = [:]
    private var tokenOrder: [ProcessRef] = []

    public init(gui: GUIAppLookup = RunningAppLookup()) { self.gui = gui }

    /// Platform.PeerOf: the peer's audit token (LOCAL_PEERTOKEN), turned
    /// into a full ref by reading KERN_PROC_PID for its PID and then
    /// checking that the token's process is still alive. A live token
    /// means the PID was never recycled in between, so the record read is
    /// the peer's own (the token carries the pidversion; spike S3).
    ///
    /// The returned length must be the whole token: SOL_LOCAL is 0, like
    /// IPPROTO_IP, so a UDP socket answers option 6 with 4 bytes.
    public func peerOf(fd: Int32) throws -> ProcessRef {
        guard let tok = Self.peerToken(fd: fd) else { throw PlatformError.noProcess }
        return try peer(token: tok)
    }

    /// The whole LOCAL_PEERTOKEN of a connected Unix-domain socket, or nil.
    static func peerToken(fd: Int32) -> audit_token_t? {
        guard fd >= 0 else { return nil }
        var tok = audit_token_t()
        var len = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &tok, &len) == 0,
              len == socklen_t(MemoryLayout<audit_token_t>.size) else { return nil }
        return tok
    }

    /// The process a peer token names, as a full ref. The kernel record is
    /// read by PID; a PID alone may have been recycled since the token was
    /// issued, and KERN_PROC_PID then describes the new occupant. The
    /// token's pidversion tells the two apart, so the token itself must
    /// still resolve to running code (SecCodeCopyGuestWithAttributes with
    /// kSecGuestAttributeAudit fails for a dead or recycled one). Without
    /// that check a live PID with a stale pidversion would be described.
    func peer(token tok: audit_token_t) throws -> ProcessRef {
        let pid = Int32(bitPattern: tok.val.5)
        guard let k = KernelProc.info(pid), !k.zombie else { throw PlatformError.noProcess }
        guard CodeSigning.guest(auditToken: tok) != nil else { throw PlatformError.noProcess }
        let ref = ProcessRef(pid: pid, generation: k.generation)
        remember(ref, tok)
        return ref
    }

    /// Platform.Process. A full ref answers only that instance; a PID-only
    /// ref answers the live occupant with its full ref. The generation is
    /// checked again after everything is read, so a record is never a mix
    /// of two processes.
    public func process(_ ref: ProcessRef) throws -> ProcessRecord {
        try read(ref).record
    }

    /// process(_:), with the raw KERN_PROCARGS2 buffer its argv came from
    /// (ExecWatcher keeps the environment from it). That buffer is
    /// read first: a program may rewrite it soon after exec (npm does
    /// within about 40 ms, spike S12).
    func read(_ ref: ProcessRef) throws -> (record: ProcessRecord, procargs: [UInt8]?) {
        guard ref.pid > 0, let k = KernelProc.info(ref.pid), !k.zombie else { throw PlatformError.noProcess }
        guard ref.generation == 0 || ref.generation == k.generation else { throw PlatformError.noProcess }
        let full = ProcessRef(pid: ref.pid, generation: k.generation)
        let procargs = KernelProc.procArgs(ref.pid)
        let path = KernelProc.path(ref.pid)
        let args = procargs.flatMap { ProcArgs.parse($0)?.args } ?? []
        let cwd = KernelProc.cwd(ref.pid)
        let code: CodeIdentity
        if let tok = token(full), let c = CodeSigning.guest(auditToken: tok) {
            code = CodeSigning.identity(of: c)
        } else if let c = CodeSigning.guest(pid: ref.pid) {
            code = CodeSigning.identity(of: c)
        } else {
            code = CodeIdentity()
        }
        guard let again = KernelProc.info(ref.pid), again.generation == k.generation, !again.zombie else {
            throw PlatformError.noProcess
        }
        let record = ProcessRecord(pid: ref.pid, generation: k.generation, parentPid: k.ppid > 0 ? k.ppid : 0,
                                   parentGeneration: 0, uid: Int64(k.uid), startMicros: k.startMicros, path: path,
                                   args: args, cwd: cwd, code: code, comm: k.comm)
        return (record, procargs)
    }

    /// Platform.AppFor: the first GUI app bundle in chain, decided from the
    /// live process, never from the record (a forged record is never an
    /// app, and the returned code identity is read fresh). PID-only records
    /// name no instance and are never an app.
    public func appFor(_ chain: [ProcessRecord]) -> AppRecord? {
        for rec in chain where rec.pid > 0 && rec.generation != 0 {
            guard let fresh = try? process(rec.ref), fresh.ref == rec.ref,
                  let app = gui.app(pid: rec.pid),
                  let again = KernelProc.info(rec.pid), again.generation == rec.generation, !again.zombie
            else { continue }
            return AppRecord(pid: rec.pid, generation: rec.generation, bundleId: app.bundleId, name: app.name, code: fresh.code)
        }
        return nil
    }

    /// Platform.Apps: the running GUI apps, each judged exactly as appFor
    /// judges a record of it (live, a full ref, the code identity read
    /// fresh). The lookup only names candidates: a PID it names that is
    /// gone, or that is not an app, is left out.
    public func apps() -> [AppRecord] {
        gui.regularApps().compactMap { pid -> AppRecord? in
            guard pid > 0, let rec = try? process(ProcessRef(pid: pid, generation: 0)) else { return nil }
            return appFor([rec])
        }
    }

    typealias ResponsibleFn = @convention(c) (pid_t) -> pid_t
    /// responsibility_get_pid_responsible_for_pid is not in the SDK
    /// headers; RTLD_DEFAULT is ((void *) -2).
    static let responsibleFn: ResponsibleFn? = dlsym(UnsafeMutableRawPointer(bitPattern: -2),
                                                     "responsibility_get_pid_responsible_for_pid")
        .map { unsafeBitCast($0, to: ResponsibleFn.self) }

    /// Platform.ResponsibleFor (display only, core/caller): a bare PID, or
    /// nil when ref is not a live process or the lookup fails.
    public func responsibleFor(_ ref: ProcessRef) -> Int32? {
        guard ref.pid > 0, (try? process(ref)) != nil, let fn = Self.responsibleFn else { return nil }
        let r = fn(ref.pid)
        return r > 0 ? r : nil
    }

    private func remember(_ ref: ProcessRef, _ tok: audit_token_t) {
        lock.lock()
        defer { lock.unlock() }
        if tokens[ref] == nil {
            tokenOrder.append(ref)
            if tokenOrder.count > Self.maxTokens { tokens[tokenOrder.removeFirst()] = nil }
        }
        tokens[ref] = tok
    }

    private func token(_ ref: ProcessRef) -> audit_token_t? {
        lock.lock()
        defer { lock.unlock() }
        return tokens[ref]
    }
}
