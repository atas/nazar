import Foundation

/// Parses a KERN_PROCARGS2 buffer: int32 argc, the exec path, NUL padding,
/// then argc NUL-terminated arguments, then the environment (environment(_:)).
///
/// The buffer is untrusted: a process can rewrite its own argument area, so
/// argc, the strings and the terminators are all attacker-controlled. The
/// parser never reads outside the buffer, keeps at most maxArgs arguments of
/// at most maxArgBytes bytes each (the bytes of a cut argument are skipped
/// up to its real terminator, never read as the next argument), decodes
/// invalid UTF-8 with replacement characters, keeps control characters
/// verbatim (display code escapes), never reads the environment as an
/// argument, and returns nil only when the header itself is cut off.
public enum ProcArgs {
    public static let maxArgs = 1024
    public static let maxArgBytes = 16 * 1024
    /// At most this many environment entries; more is unreadable.
    public static let maxEnv = 4096

    /// The startup environment in a KERN_PROCARGS2 buffer: the
    /// NUL-terminated strings after the argc arguments. nil, never [], when
    /// there is nothing to compare: no entry (macOS hides an Apple platform
    /// binary's; an empty environment looks the same), a cut header, an
    /// argc out of range or beyond the strings, more than maxEnv entries,
    /// an entry over maxArgBytes, or anything after the environment that is
    /// not the kernel's own strings. An environment is never cut: a cut
    /// list would hide what follows.
    ///
    /// The kernel's own strings (apple[]: "pfz=…", "stack_guard=…", …)
    /// follow the environment in this buffer. The kernel pads the end of
    /// argv and the environment with 0–7 NULs to an 8-byte boundary of the
    /// string area (which starts at offset 4, the exec path), so when the
    /// environment already ends on one, no empty string separates the two
    /// (measured on macOS 27). Hence two cases:
    /// - Read before the program ran: apple[] starts with "pfz=" on that
    ///   boundary. The environment ends at the last such string, followed
    ///   by at most 7 NULs. After it no run of 8 NULs may come before the
    ///   end: libSystem zero-fills "pfz=…" (and other secrets) first thing
    ///   in the new image, so such a run means the real "pfz=…" is gone
    ///   and the one found is the environment's own.
    /// - Read after libSystem zero-filled "pfz=…": the environment ends at
    ///   its first empty string, and only NULs and strings with the
    ///   kernel's names (appleKeys) may follow, so an empty entry never
    ///   hides the entries after it.
    public static func environment(_ buf: [UInt8]) -> [String]? {
        guard buf.count >= 4 else { return nil }
        let argc = Int(Int32(littleEndian: buf.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }))
        guard argc >= 0, argc <= maxArgs else { return nil }
        var i = 4
        _ = execPath(buf, &i)
        for _ in 0..<argc {
            guard i < buf.count else { return nil }
            _ = readString(buf, &i)
        }
        let apple = lastPFZ(buf, from: i)
        let end = apple ?? buf.count
        if let apple, !noLongNULRun(buf, from: apple) { return nil }
        var env: [String] = []
        while i < end && buf[i] != 0 {
            let start = i
            while i < end && buf[i] != 0 { i += 1 }
            guard i - start <= maxArgBytes, env.count < maxEnv else { return nil }
            env.append(String(decoding: buf[start..<i], as: UTF8.self))
            i += 1
        }
        var j = i
        while j < end && buf[j] == 0 { j += 1 }
        if apple != nil {
            guard j == end, j - i < 8 else { return nil } // only the padding before apple[]
        } else {
            guard onlyAppleStrings(buf, from: j) else { return nil }
        }
        return env.isEmpty ? nil : env
    }

    /// The names of the kernel's own strings (apple[]) that may follow the
    /// environment once libSystem zero-filled "pfz=…" (environment(_:)).
    static let appleKeys: Set<String> = [
        "pfz", "stack_guard", "malloc_entropy", "ptr_munge", "main_stack", "executable_file", "dyld_file",
        "executable_cdhash", "executable_boothash", "th_port", "security_config", "executable_path", "arm64e_abi",
        "dyld_flags", "has_sec_transition", "subsystem_root_path", "libmalloc_experiments",
    ]

    /// The offset of the last string from i on that starts "pfz=" on an
    /// 8-byte boundary of the string area, or nil.
    static func lastPFZ(_ buf: [UInt8], from i: Int) -> Int? {
        let pfz = Array("pfz=".utf8)
        var last: Int?
        var k = i
        while k < buf.count {
            if buf[k] == 0 { k += 1; continue }
            if (k - 4) % 8 == 0, buf[k...].starts(with: pfz) { last = k }
            while k < buf.count && buf[k] != 0 { k += 1 }
        }
        return last
    }

    /// No run of 8 or more NULs from i up to the last non-NUL byte.
    static func noLongNULRun(_ buf: [UInt8], from i: Int) -> Bool {
        guard let last = buf.lastIndex(where: { $0 != 0 }), i <= last else { return true }
        var run = 0
        for b in buf[i...last] {
            run = b == 0 ? run + 1 : 0
            if run >= 8 { return false }
        }
        return true
    }

    /// From i on, only NULs and strings named in appleKeys.
    static func onlyAppleStrings(_ buf: [UInt8], from i: Int) -> Bool {
        var k = i
        while k < buf.count {
            if buf[k] == 0 { k += 1; continue }
            let start = k
            while k < buf.count && buf[k] != 0 { k += 1 }
            guard let eq = buf[start..<k].firstIndex(of: UInt8(ascii: "=")),
                  appleKeys.contains(String(decoding: buf[start..<eq], as: UTF8.self)) else { return false }
        }
        return true
    }

    public static func parse(_ buf: [UInt8]) -> (execPath: String, args: [String])? {
        guard buf.count >= 4 else { return nil }
        let argcRaw = Int32(littleEndian: buf.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) })
        let argc = max(0, min(Int(argcRaw), maxArgs))
        var i = 4
        let execPath = execPath(buf, &i)
        var args: [String] = []
        while args.count < argc && i < buf.count {
            args.append(readString(buf, &i))
        }
        return (execPath, args)
    }

    /// Reads the exec path at i and leaves i on argv[0]: the kernel pads
    /// the path with NULs to 8 bytes of the string area (which starts at
    /// offset 4; measured on macOS 27), and only that padding is skipped.
    /// An empty argv[0] after it is an argument: taking it for padding
    /// would read the first variable as the last argument.
    static func execPath(_ buf: [UInt8], _ i: inout Int) -> String {
        let path = readString(buf, &i)
        while i < buf.count && buf[i] == 0 && (i - 4) % 8 != 0 { i += 1 }
        return path
    }

    /// Reads one NUL-terminated string at i (or to the end of the buffer),
    /// cut to maxArgBytes, and leaves i after its terminator.
    static func readString(_ buf: [UInt8], _ i: inout Int) -> String {
        let start = i
        while i < buf.count && buf[i] != 0 { i += 1 }
        let end = min(i, start + maxArgBytes)
        let s = String(decoding: buf[start..<end], as: UTF8.self)
        if i < buf.count { i += 1 } // the terminator
        return s
    }
}
