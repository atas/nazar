import Foundation

// Wire format of the structured values that cross the C ABI as JSON
// (nazar_bridge.h). Field names are part of the ABI and match
// bridge/cbridge/wire.go. Data fields are base64 (JSONEncoder's default,
// and what Go's encoding/json uses for []byte).

/// One process instance: PID plus generation (start time in microseconds
/// since the Unix epoch, spec/platform.go ProcessRef). Generation 0 is a
/// PID-only ref.
public struct ProcessRef: Hashable, Sendable {
    public var pid: Int32
    public var generation: UInt64
    public init(pid: Int32, generation: UInt64) {
        self.pid = pid
        self.generation = generation
    }
    public var isPIDOnly: Bool { pid != 0 && generation == 0 }
}

/// platform.CodeIdentity.
public struct CodeIdentity: Codable, Equatable, Sendable {
    public var signed: Bool = false
    public var teamId: String = ""
    public var signingId: String = ""
    public var apple: Bool = false
    public var adHoc: Bool = false
    public var cdhash: Data = Data()
    public init(signed: Bool = false, teamId: String = "", signingId: String = "", apple: Bool = false,
                adHoc: Bool = false, cdhash: Data = Data()) {
        self.signed = signed
        self.teamId = teamId
        self.signingId = signingId
        self.apple = apple
        self.adHoc = adHoc
        self.cdhash = cdhash
    }
}

/// platform.ProcessInfo.
public struct ProcessRecord: Codable, Equatable, Sendable {
    public var pid: Int32
    public var generation: UInt64
    public var parentPid: Int32
    public var parentGeneration: UInt64
    public var uid: Int64
    public var startMicros: Int64
    public var path: String
    public var args: [String]
    public var cwd: String
    public var code: CodeIdentity
    /// The kernel's short name (p_comm, at most 16 bytes): display only,
    /// for a process whose executable file is gone (path is then "").
    public var comm: String = ""
    public var ref: ProcessRef { ProcessRef(pid: pid, generation: generation) }
}

/// platform.AppInfo.
public struct AppRecord: Codable, Equatable, Sendable {
    public var pid: Int32
    public var generation: UInt64
    public var bundleId: String
    public var name: String
    public var code: CodeIdentity
}

/// platform.AppBundle.
public struct AppBundleRecord: Codable, Equatable, Sendable {
    public var bundleId: String
    public var path: String
    public var code: CodeIdentity
}

/// platform.Prompt. timeoutMillis <= 0 means the platform default (60 s).
public struct PromptSpec: Codable, Equatable, Sendable {
    public var title: String
    public var lines: [String]
    /// The line number (1-based) of what the user ran, shown as code; 0 for none.
    public var commandLine: Int
    public var unknown: Bool
    public var reason: String
    public var timeoutMillis: Int64
    public init(title: String, lines: [String] = [], commandLine: Int = 0, unknown: Bool = false, reason: String = "", timeoutMillis: Int64 = 0) {
        self.title = title
        self.lines = lines
        self.commandLine = commandLine
        self.unknown = unknown
        self.reason = reason
        self.timeoutMillis = timeoutMillis
    }
    /// The timeout to apply, never longer than 10 minutes.
    public var timeout: TimeInterval {
        timeoutMillis <= 0 ? 60 : min(Double(timeoutMillis) / 1000, 600)
    }
}

/// platform.Warning.
public struct WarningSpec: Codable, Equatable, Sendable {
    public var id: String
    public var title: String
    public var lines: [String]
    /// The line number (1-based) of what the user ran, shown as code; 0 for none.
    public var commandLine: Int
    public var count: Int
    public var suggestedRule: String
    public init(id: String, title: String, lines: [String] = [], commandLine: Int = 0, count: Int = 1, suggestedRule: String = "") {
        self.id = id
        self.title = title
        self.lines = lines
        self.commandLine = commandLine
        self.count = count
        self.suggestedRule = suggestedRule
    }
}

/// JSON helpers with the ABI's settings: sorted keys (stable for tests),
/// no pretty printing, and a hard size limit when decoding.
public enum Wire {
    public static let maxDocument = 4 << 20

    public static func encode<T: Encodable>(_ v: T) throws -> Data {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try e.encode(v)
    }

    public static func decode<T: Decodable>(_ t: T.Type, _ data: Data) throws -> T {
        guard data.count <= maxDocument else { throw PlatformError.invalid("document too large") }
        return try JSONDecoder().decode(t, from: data)
    }
}
