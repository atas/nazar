import Darwin
import Foundation

/// One KERN_PROC_PID record (spike S3: sysctl works for root-owned
/// processes such as /usr/bin/login, where PROC_PIDTBSDINFO gets EPERM).
public struct KProc: Equatable, Sendable {
    public var pid: Int32
    public var ppid: Int32
    public var uid: UInt32
    /// Start time in microseconds since the Unix epoch: the ProcessRef
    /// generation on macOS (core/platform ProcessRef).
    public var startMicros: Int64
    public var zombie: Bool
    /// p_comm: the file name the executable was started under, cut to
    /// MAXCOMLEN (16) bytes. It stays when the file is deleted.
    public var comm: String = ""

    public var generation: UInt64 { UInt64(max(startMicros, 0)) }
}

public enum KernelProc {
    /// The live record of pid, or nil when no process has that PID
    /// (pid <= 0 is never a process here: 0 is the kernel).
    public static func info(_ pid: Int32) -> KProc? {
        guard pid > 0 else { return nil }
        var kp = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &kp, &size, nil, 0) == 0, size == MemoryLayout<kinfo_proc>.size,
              kp.kp_proc.p_pid == pid else { return nil }
        let st = kp.kp_proc.p_un.__p_starttime
        let micros = Int64(st.tv_sec) * 1_000_000 + Int64(st.tv_usec)
        guard micros > 0 else { return nil }
        let comm = withUnsafeBytes(of: kp.kp_proc.p_comm) { raw -> String in
            let bytes = raw.prefix(Int(MAXCOMLEN)).prefix { $0 != 0 }
            return String(decoding: bytes, as: UTF8.self)
        }
        return KProc(pid: pid, ppid: kp.kp_eproc.e_ppid, uid: kp.kp_eproc.e_ucred.cr_uid,
                     startMicros: micros, zombie: Int32(kp.kp_proc.p_stat) == SZOMB, comm: comm)
    }

    /// The executable path (proc_pidpath), or "" when unreadable.
    public static func path(_ pid: Int32) -> String {
        guard pid > 0 else { return "" }
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return "" }
        return String(cString: buf)
    }

    /// The current folder (PROC_PIDVNODEPATHINFO), or "" when unreadable
    /// (another user's process).
    public static func cwd(_ pid: Int32) -> String {
        guard pid > 0 else { return "" }
        var vi = proc_vnodepathinfo()
        let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vi, size) == size else { return "" }
        return withUnsafePointer(to: vi.pvi_cdir.vip_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
        }
    }

    /// The raw KERN_PROCARGS2 buffer (argc, the exec path, argv, the
    /// environment), or nil when unreadable (another user's process) or
    /// absent.
    public static func procArgs(_ pid: Int32) -> [UInt8]? {
        guard pid > 0 else { return nil }
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0, size <= 4 << 20 else { return nil }
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0 else { return nil }
        return Array(buf.prefix(size))
    }

    /// The arguments (KERN_PROCARGS2 through ProcArgs), or [] when
    /// unreadable (another user's process) or absent.
    public static func args(_ pid: Int32) -> [String] {
        procArgs(pid).flatMap { ProcArgs.parse($0)?.args } ?? []
    }
}
