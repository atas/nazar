import AppKit
import Darwin
import Foundation
import Security

// Note: stdout is block-buffered when piped to `tee`/a file, so the spike's
// `S3Callers | tee ~/.nazar/spike/s3.log` left the log empty while the server ran. Line-buffer it.
setvbuf(stdout, nil, _IOLBF, 0)

let SOL_LOCAL: Int32 = 0
let LOCAL_PEERPID: Int32 = 0x002

func bsdInfo(_ pid: pid_t) -> proc_bsdinfo? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    if proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size { return info }
    // Note: PROC_PIDTBSDINFO returns EPERM for root-owned processes such as the
    // /usr/bin/login that iTerm2 puts in every session. Without this fallback the chain walk
    // stops at login and every iTerm row reports UNKNOWN. sysctl KERN_PROC_PID returns the
    // ppid even for root-owned pids. Phase 1's Platform.Process must do the same.
    var kp = kinfo_proc()
    var sz = MemoryLayout<kinfo_proc>.size
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
    guard sysctl(&mib, 4, &kp, &sz, nil, 0) == 0, sz > 0 else { return nil }
    info.pbi_ppid = UInt32(kp.kp_eproc.e_ppid)
    info.pbi_start_tvsec = UInt64(kp.kp_proc.p_un.__p_starttime.tv_sec)
    return info
}

func exePath(_ pid: pid_t) -> String {
    var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
    return proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : "?"
}

func cwd(_ pid: pid_t) -> String {
    var vi = proc_vnodepathinfo()
    guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vi, Int32(MemoryLayout<proc_vnodepathinfo>.size)) > 0 else { return "?" }
    return withUnsafePointer(to: vi.pvi_cdir.vip_path) {
        $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
    }
}

func arguments(_ pid: pid_t) -> [String] {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return ["<no access>"] }
    var buf = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0 else { return ["<no access>"] }
    let argc = Int(buf.withUnsafeBytes { $0.load(as: Int32.self) })
    var i = MemoryLayout<Int32>.size
    while i < size && buf[i] != 0 { i += 1 }   // skip exec path
    while i < size && buf[i] == 0 { i += 1 }   // skip padding
    var out: [String] = []
    while out.count < argc && i < size {
        let s = i
        while i < size && buf[i] != 0 { i += 1 }
        out.append(String(decoding: buf[s..<i], as: UTF8.self))
        i += 1
    }
    return out
}

// NOTE for Phase 1: this spike identifies the caller by pid
// (LOCAL_PEERPID) and checks its code signature with kSecGuestAttributePid. That is open to
// pid reuse between accept() and the signature check. Phase 1's Platform.PeerOf must use
// LOCAL_PEERTOKEN (the audit token) with kSecGuestAttributeAudit instead. Kept pid-based here
// because that is what the spike demonstrates.
func signing(_ pid: pid_t) -> String {
    var code: SecCode?
    let attrs = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else { return "no-code" }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return "no-static" }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let d = info as? [String: Any] else { return "no-info" }
    let team = d[kSecCodeInfoTeamIdentifier as String] as? String ?? "-"
    let ident = d[kSecCodeInfoIdentifier as String] as? String ?? "-"
    return "\(team):\(ident)"
}

typealias ResponsibleFn = @convention(c) (pid_t) -> pid_t
let responsible: ResponsibleFn? = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "responsibility_get_pid_responsible_for_pid")
    .map { unsafeBitCast($0, to: ResponsibleFn.self) }

func report(_ pid: pid_t) {
    print("=== connection from pid \(pid) at \(Date())")
    var p = pid, app: String? = nil, depth = 0
    while p > 1 && depth < 64 {
        guard let bi = bsdInfo(p) else { print("  pid \(p): gone"); break }
        let isGUI = NSRunningApplication(processIdentifier: p)?.activationPolicy == .regular
        if isGUI && app == nil { app = exePath(p) }
        print("  pid \(p) ppid \(bi.pbi_ppid) start \(bi.pbi_start_tvsec)\(isGUI ? " [GUI APP]" : "") \(exePath(p))")
        print("      args \(arguments(p))  cwd \(cwd(p))  sig \(signing(p))")
        p = pid_t(bi.pbi_ppid); depth += 1
    }
    if let responsible { let r = responsible(pid); print("  responsible pid \(r) \(exePath(r))") }
    print("  → app: \(app ?? "UNKNOWN (chain ended at launchd)")")
}

func readFull(_ fd: Int32, _ n: Int) -> [UInt8]? {
    var buf = [UInt8](repeating: 0, count: n), got = 0
    while got < n {
        let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, n - got) }
        if r <= 0 { return nil }
        got += r
    }
    return buf
}

/// Minimal agent: answers REQUEST_IDENTITIES (11) with zero keys, everything else with FAILURE (5).
func serve(_ fd: Int32) {
    while let lenBytes = readFull(fd, 4) {
        let len = Int(lenBytes[0]) << 24 | Int(lenBytes[1]) << 16 | Int(lenBytes[2]) << 8 | Int(lenBytes[3])
        guard let body = readFull(fd, len), let type = body.first else { break }
        let reply: [UInt8] = type == 11 ? [0, 0, 0, 5, 12, 0, 0, 0, 0] : [0, 0, 0, 1, 5]
        _ = reply.withUnsafeBytes { write(fd, $0.baseAddress!, reply.count) }
    }
    close(fd)
}

let sockPath = NSHomeDirectory() + "/.nazar/s3.sock"
try? FileManager.default.createDirectory(atPath: NSHomeDirectory() + "/.nazar", withIntermediateDirectories: true,
                                         attributes: [.posixPermissions: 0o700])
unlink(sockPath)
let listener = socket(AF_UNIX, SOCK_STREAM, 0)
var addr = sockaddr_un()
addr.sun_family = sa_family_t(AF_UNIX)
addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
_ = sockPath.withCString { src in
    withUnsafeMutablePointer(to: &addr.sun_path) {
        $0.withMemoryRebound(to: CChar.self, capacity: 104) { strncpy($0, src, 103) }
    }
}
let bound = withUnsafePointer(to: &addr) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
}
guard bound == 0, listen(listener, 16) == 0 else { perror("bind/listen"); exit(1) }
chmod(sockPath, 0o600)
print("S3 listening on \(sockPath)")
while true {
    let c = accept(listener, nil, nil)
    if c < 0 { continue }
    var pid: pid_t = 0
    var len = socklen_t(MemoryLayout<pid_t>.size)
    getsockopt(c, SOL_LOCAL, LOCAL_PEERPID, &pid, &len)
    report(pid)
    DispatchQueue.global().async { serve(c) }
}
