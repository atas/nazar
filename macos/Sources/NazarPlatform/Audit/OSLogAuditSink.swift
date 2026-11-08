import Foundation
import os

/// audit.Sink on the unified log (spec 4.6): subsystem dev.nazar, category
/// audit, `default` level (persisted), the whole line marked public so macOS
/// never replaces it with <private>. The log stamps its own time, so the
/// event time is not written. Lines are at most audit.MaxLine (1000) bytes
/// from Go; anything longer is refused rather than truncated by the log.
public final class OSLogAuditSink: @unchecked Sendable {
    public static let productionSubsystem = "dev.nazar"
    public static let category = "audit"
    public static let maxLine = 1000

    let log: OSLog

    /// Tests pass a dev.nazar.test.* subsystem: nothing they write may ever
    /// look like a real audit entry.
    public init(subsystem: String = OSLogAuditSink.productionSubsystem) {
        log = OSLog(subsystem: subsystem, category: Self.category)
    }

    public func write(unixNanos: Int64, line: String) throws {
        guard line.utf8.count <= Self.maxLine else {
            throw PlatformError.invalid("audit line longer than \(Self.maxLine) bytes")
        }
        // One entry must never read as two, and %s must never cut it short:
        // refuse every line separator and NUL. Checked on scalars, not
        // Characters, because "\r\n" is one Character equal to neither "\r"
        // nor "\n".
        guard !line.unicodeScalars.contains(where: Self.isBreak) else {
            throw PlatformError.invalid("audit line with a line break or NUL")
        }
        os_log(.default, log: log, "%{public}s", line)
    }

    private static func isBreak(_ s: Unicode.Scalar) -> Bool {
        switch s {
        case "\n", "\r", "\u{0}", "\u{85}", "\u{2028}", "\u{2029}": return true
        default: return false
        }
    }
}
