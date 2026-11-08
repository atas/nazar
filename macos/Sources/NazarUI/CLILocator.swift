import Foundation

/// One place Nazar UI.app looked for the nazar CLI, and what it found.
public struct CLICandidate: Equatable, Sendable {
    /// Where the place came from, e.g. "LaunchAgent dev.nazar.agent".
    public let source: String
    /// The path looked at (as the place names it).
    public let path: String
    /// Why it can't be used; nil for the one that is.
    public let problem: String?
}

/// Where the CLI is, or everything that was looked at instead.
public enum CLILocation: Equatable, Sendable {
    case found(URL, [CLICandidate])
    case notFound([CLICandidate])

    public var candidates: [CLICandidate] {
        switch self {
        case .found(_, let c), .notFound(let c): return c
        }
    }
}

/// Finds the CLI of the installed agent (spec 6.1, Milestone 6): the
/// nazar-agent.app the LaunchAgent dev.nazar.agent starts (wherever it is:
/// `nazar install` registers the place the agent runs from), then the links
/// a package makes. The first that is a regular executable Mach-O file satisfying
/// the requirement is used, by its resolved absolute path, never via $PATH.
/// These places are the user's to write, so finding a file proves nothing:
/// the signature check decides, here and again on every run
/// (ProcessCLIRunner checks the running process).
public enum CLILocator {
    public static let agentLabel = "dev.nazar.agent"
    public static let agentExecutable = "nazar-agent"

    /// The home folder from the passwd entry, never $HOME.
    public static func userHome() -> String {
        if let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir, dir.pointee != 0 { return String(cString: dir) }
        return NSHomeDirectory()
    }

    /// The places, in order: the LaunchAgent's program, then the Homebrew
    /// links (Apple silicon, Intel prefixes) and `nazar install`'s default
    /// link.
    public static func places(home: String) -> [(source: String, path: String)] {
        var out: [(String, String)] = []
        let plist = home + "/Library/LaunchAgents/\(agentLabel).plist"
        switch agentProgram(plist: plist) {
        case .success(let prog):
            let macos = (prog as NSString).deletingLastPathComponent
            if (prog as NSString).lastPathComponent == agentExecutable && macos.hasSuffix(".app/Contents/MacOS") {
                out.append(("LaunchAgent \(agentLabel)", macos + "/nazar"))
            } else {
                out.append(("LaunchAgent \(agentLabel)", prog + " (not a nazar-agent.app)"))
            }
        case .failure:
            break
        }
        out.append(("Homebrew link", "/opt/homebrew/bin/nazar"))
        out.append(("Homebrew link", "/usr/local/bin/nazar"))
        out.append(("nazar install link", home + "/.local/bin/nazar"))
        return out
    }

    /// ProgramArguments[0] of a LaunchAgent plist (at most 64 KiB).
    static func agentProgram(plist: String) -> Result<String, CocoaError> {
        guard let fh = FileHandle(forReadingAtPath: plist) else { return .failure(CocoaError(.fileNoSuchFile)) }
        defer { try? fh.close() }
        let data = fh.readData(ofLength: 64 << 10)
        guard let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let args = obj["ProgramArguments"] as? [String], let first = args.first, first.hasPrefix("/") else {
            return .failure(CocoaError(.fileReadCorruptFile))
        }
        return .success(first)
    }

    /// The first usable place, checked against requirement.
    public static func locate(requirement: CLIRequirement, home: String = userHome(),
                              places: [(source: String, path: String)]? = nil) -> CLILocation {
        var seen: [CLICandidate] = []
        for (source, path) in places ?? Self.places(home: home) {
            let problem = check(path, requirement)
            seen.append(CLICandidate(source: source, path: path, problem: problem.why))
            if problem.why == nil, let url = problem.url { return .found(url, seen) }
        }
        return .notFound(seen)
    }

    /// The resolved file at path if it can be run, else why not.
    static func check(_ path: String, _ requirement: CLIRequirement) -> (url: URL?, why: String?) {
        guard path.hasPrefix("/") else { return (nil, "not an absolute path") }
        guard let r = realpath(path, nil) else { return (nil, "not found") }
        let real = String(cString: r)
        free(r)
        var st = stat()
        guard lstat(real, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return (nil, "not a regular file") }
        guard access(real, X_OK) == 0 else { return (nil, "not executable") }
        guard isMachO(real) else { return (nil, "not a Mach-O program") }
        let url = URL(fileURLWithPath: real)
        if let why = CodeSignature.checkFile(url, requirement) { return (nil, why) }
        return (url, nil)
    }

    /// Whether the file at path starts with a Mach-O or universal magic
    /// number. A script is never offered (whatever its interpreter is: it
    /// could name the genuine CLI and put its own arguments first); the
    /// runner refuses one at the start as well (checkStarted).
    static func isMachO(_ path: String) -> Bool {
        guard let fh = FileHandle(forReadingAtPath: path) else { return false }
        defer { try? fh.close() }
        let head = [UInt8](fh.readData(ofLength: 4))
        guard head.count == 4 else { return false }
        return [[0xcf, 0xfa, 0xed, 0xfe], [0xce, 0xfa, 0xed, 0xfe], // MH_MAGIC_64, MH_MAGIC (little-endian)
                [0xca, 0xfe, 0xba, 0xbe], [0xca, 0xfe, 0xba, 0xbf]] // FAT_MAGIC, FAT_MAGIC_64 (big-endian)
            .contains(head)
    }
}
