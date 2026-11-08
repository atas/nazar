import Foundation
import Testing
@testable import NazarPlatform

@Suite(.timeLimit(.minutes(1))) struct OSLogAuditSinkTests {
    @Test func linesReachTheUnifiedLogInFull() throws {
        let sub = "dev.nazar.test.\(UUID().uuidString.prefix(8))"
        let sink = OSLogAuditSink(subsystem: sub)
        let line = "decision=allowed reason=\"cached approval\" target=ssh:test cwd=~/x marker=\(UUID().uuidString)"
        try sink.write(unixNanos: 0, line: line)
        var found = false
        let end = Date().addingTimeInterval(30)
        while !found && Date() < end {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/log")
            p.arguments = ["show", "--last", "2m", "--style", "ndjson", "--predicate", "subsystem == \"\(sub)\" AND category == \"audit\""]
            let pipe = Pipe()
            p.standardOutput = pipe
            try p.run()
            let out = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            for l in out.split(separator: UInt8(ascii: "\n")) {
                if let obj = try? JSONSerialization.jsonObject(with: Data(l)) as? [String: Any],
                   obj["eventMessage"] as? String == line, obj["messageType"] as? String == "Default" {
                    found = true
                }
            }
            if !found { Thread.sleep(forTimeInterval: 1) }
        }
        #expect(found, "the line never showed up public and in full at default level")
    }

    @Test func oversizedAndMultiLineAreRefused() {
        let sink = OSLogAuditSink(subsystem: "dev.nazar.test.refuse")
        #expect(throws: PlatformError.self) { try sink.write(unixNanos: 0, line: String(repeating: "x", count: 1001)) }
        #expect(throws: PlatformError.self) { try sink.write(unixNanos: 0, line: "decision=allowed\ndecision=forged") }
    }

    // Additional edge and attack cases (test author).

    @Test func productionConstantsMatchTheGoSide() {
        #expect(OSLogAuditSink.productionSubsystem == "dev.nazar")
        #expect(OSLogAuditSink.category == "audit")
        #expect(OSLogAuditSink.maxLine == 1000) // core/audit.MaxLine
    }

    /// The limit is in UTF-8 bytes (what Go's audit.MaxLine counts), not in
    /// Characters: 501 two-byte characters are 1002 bytes and are refused.
    @Test func limitIsInBytesAndInclusive() throws {
        let sink = OSLogAuditSink(subsystem: "dev.nazar.test.limit")
        try sink.write(unixNanos: 0, line: String(repeating: "x", count: 1000))
        try sink.write(unixNanos: 0, line: String(repeating: "\u{e9}", count: 500))
        #expect(throws: PlatformError.self) { try sink.write(unixNanos: 0, line: String(repeating: "\u{e9}", count: 501)) }
        #expect(throws: PlatformError.self) { try sink.write(unixNanos: 0, line: String(repeating: "x", count: 999) + "\u{e9}") }
    }

    /// Anything that would make one audit entry read as two, or that %s
    /// would cut short, is refused. "\r\n" is a single Swift Character that
    /// equals neither "\r" nor "\n", so a Character comparison misses it.
    @Test func lineBreaksOfEveryKindAndNULAreRefused() {
        let sink = OSLogAuditSink(subsystem: "dev.nazar.test.refuse")
        for bad in [
            "decision=allowed\r\ndecision=forged",
            "decision=allowed\rdecision=forged",
            "decision=allowed\n",
            "\ndecision=forged",
            "decision=allowed\u{2028}decision=forged",
            "decision=allowed\u{2029}decision=forged",
            "decision=allowed\u{85}decision=forged",
            "decision=allowed\u{0}decision=forged",
        ] {
            #expect(throws: PlatformError.self, "\(bad.debugDescription) was accepted") { try sink.write(unixNanos: 0, line: bad) }
        }
    }
}
