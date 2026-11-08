import Darwin
import Foundation
import MachO
import Security

/// libmacho's `macho_best_slice` (<mach-o/utils.h>, macOS 13+): "for main
/// executables, the best slice is the slice the kernel would execute". The
/// header is not in the MachO module map, so it is declared here with its
/// C signature (a path and a block). Returns 0 and calls the block once, or
/// an errno (ENOENT, EACCES, EFTYPE: not Mach-O, EBADARCH: no loadable
/// slice, EBADMACHO: malformed) without calling it.
@_silgen_name("macho_best_slice")
private func nz_macho_best_slice(
    _ path: UnsafePointer<CChar>,
    _ bestSlice: (@convention(block) (UnsafePointer<mach_header>, UInt64, Int) -> Void)?
) -> Int32

/// Code-signature checks with Security.framework (spec 4.1 step 2, 4.2).
///
/// Static code (`staticIdentity`, `cdhash`) is always read from the slice
/// the kernel executes on this machine, not from Security's static default
/// slice: Apple's universal binaries on macOS 27 carry x86_64, arm64e and
/// arm64e.x1, Security's and codesign's default is arm64e.x1 while an M2
/// runs arm64e, and core/match compares the `path:` pin from
/// `Platform.CodeHash` with the RUNNING process's cdhash.
public enum CodeSigning {
    static let adHocFlag: UInt32 = 0x0002 // kSecCodeSignatureAdhoc
    static let appleAnchor: SecRequirement = {
        var r: SecRequirement?
        let status = SecRequirementCreateWithString("anchor apple" as CFString, [], &r)
        guard status == errSecSuccess, let r else {
            preconditionFailure("SecRequirementCreateWithString(\"anchor apple\") failed: \(status)")
        }
        return r
    }()

    /// The running code of the process named by an audit token (the
    /// socket peer, LOCAL_PEERTOKEN), or nil when that process is gone:
    /// the token carries the pidversion, so a recycled PID never matches.
    public static func guest(auditToken: audit_token_t) -> SecCode? {
        guard Int32(bitPattern: auditToken.val.5) > 0 else { return nil } // pid 0 is the kernel
        var t = auditToken
        let data = Data(bytes: &t, count: MemoryLayout<audit_token_t>.size)
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &code)
                == errSecSuccess
        else { return nil }
        return code
    }

    /// The running code of pid. Callers must re-check the generation after
    /// using it (the PID may be recycled meanwhile).
    public static func guest(pid: Int32) -> SecCode? {
        guard pid > 0 else { return nil }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary,
                                             [], &code) == errSecSuccess
        else { return nil }
        return code
    }

    /// The identity of running code. Signed means the kernel and
    /// Security.framework accept the running code's signature AND the code
    /// directory of the file at the process's path equals the cdhash the
    /// kernel holds for the process (otherwise SecCodeCheckValidity fails
    /// with errSecCSStaticCodeChanged). The signing information itself is
    /// read from that file, so when the check fails, its cdhash describes
    /// whatever is on disk now, not the mapped text: a process that ran one
    /// binary at a pinned path and then renamed the trusted one back would
    /// present the trusted cdhash. The kernel's own cdhash is not readable
    /// through the public SDK (csops/CS_OPS_CDHASH is private), so a cdhash
    /// the kernel did not vouch for is never reported: unsigned, tampered or
    /// swapped running code has an empty cdhash, which `path:` pins and the
    /// approval-cache identity (core/match) treat as "matches nothing".
    public static func identity(of code: SecCode) -> CodeIdentity {
        let signed = SecCodeCheckValidity(code, [], nil) == errSecSuccess
        let apple = signed && SecCodeCheckValidity(code, [], appleAnchor) == errSecSuccess
        // A SecCodeRef is accepted wherever a SecStaticCodeRef is (SecCode.h);
        // SecCodeCopySigningInformation then describes the running code.
        var id = describe(unsafeBitCast(code, to: SecStaticCode.self), signed: signed, apple: apple)
        if !signed { id.cdhash = Data() }
        return id
    }

    /// The identity of code on disk (an app bundle or a binary), validated
    /// statically: what `app:` pins are taken from (InstalledApp). nil when
    /// Security cannot even open it as code (missing, a folder).
    public static func staticIdentity(path: String) -> CodeIdentity? {
        guard let sc = staticCode(path) else { return nil }
        let signed = SecStaticCodeCheckValidity(sc, [], nil) == errSecSuccess
        let apple = signed && SecStaticCodeCheckValidity(sc, [], appleAnchor) == errSecSuccess
        return describe(sc, signed: signed, apple: apple)
    }

    /// Platform.CodeHash: the cdhash of the code at path (`nazar run` pins a
    /// receiver's), of
    /// the slice the kernel executes. A missing file is .notFound; a path
    /// that is not code or carries no signature is .failed.
    public static func cdhash(path: String) throws -> Data {
        var st = stat()
        guard stat(path, &st) == 0 else { throw PlatformError.notFound }
        guard let sc = staticCode(path) else { throw PlatformError.failed("not code: \(path)") }
        guard let h = info(sc)[kSecCodeInfoUnique as String] as? Data, !h.isEmpty else {
            throw PlatformError.failed("no code signature: \(path)")
        }
        return h
    }

    /// Static code for path, pinned to the slice the kernel would execute
    /// when its main executable is a universal binary; Security's default
    /// slice when it is thin, not Mach-O, or has no loadable slice (the
    /// kernel would never run it, so no running process can match it).
    static func staticCode(_ path: String) -> SecStaticCode? {
        let url = URL(fileURLWithPath: path) as CFURL
        var sc: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &sc) == errSecSuccess, let sc else { return nil }
        guard let exe = mainExecutable(sc), let offset = kernelSliceOffset(exe), offset > 0 else { return sc }
        var sliced: SecStaticCode?
        let attrs = [kSecCodeAttributeUniversalFileOffset: NSNumber(value: offset)] as CFDictionary
        guard SecStaticCodeCreateWithPathAndAttributes(url, [], attrs, &sliced) == errSecSuccess, let sliced
        else { return sc }
        return sliced
    }

    /// The main executable Security found for the code (the bundle's binary,
    /// or the file itself).
    static func mainExecutable(_ sc: SecStaticCode) -> String? {
        let v = info(sc)[kSecCodeInfoMainExecutable as String]
        if let u = v as? URL { return u.path }
        if let u = v as? NSURL { return u.path }
        return nil
    }

    /// The file offset of the slice the kernel would execute, 0 for a thin
    /// Mach-O, nil when libmacho finds nothing loadable or the file is not
    /// Mach-O.
    static func kernelSliceOffset(_ path: String) -> UInt64? {
        var offset: UInt64?
        let rc = nz_macho_best_slice(path) { _, off, _ in offset = off }
        guard rc == 0 else { return nil }
        return offset
    }

    static func info(_ sc: SecStaticCode) -> [String: Any] {
        var out: CFDictionary?
        SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &out)
        return out as? [String: Any] ?? [:]
    }

    static func describe(_ sc: SecStaticCode, signed: Bool, apple: Bool) -> CodeIdentity {
        let d = info(sc)
        let flags = (d[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let adHoc = flags & adHocFlag != 0
        return CodeIdentity(signed: signed,
                            teamId: adHoc ? "" : (d[kSecCodeInfoTeamIdentifier as String] as? String ?? ""),
                            signingId: d[kSecCodeInfoIdentifier as String] as? String ?? "",
                            apple: apple && !adHoc, adHoc: adHoc,
                            cdhash: d[kSecCodeInfoUnique as String] as? Data ?? Data())
    }
}
