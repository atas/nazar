import Foundation
import Testing
@testable import NazarPlatform

// Where the environment ends in a KERN_PROCARGS2 buffer as macOS
// lays it out (measured on macOS 27): the string area (from offset 4, the
// exec path) pads the exec path, and then argv plus the environment, to 8
// bytes with NULs, and the kernel's own strings (apple[], "pfz=…" first)
// follow. When the environment ends on a boundary, no empty string
// separates it from apple[]. libSystem zero-fills "pfz=…", "stack_guard=…"
// and "malloc_entropy=…" (and some values) as the new image starts.
// Pure parsing: no process, no keychain, no window.

@Suite struct ProcArgsAppleTests {
    static let kernel = ["pfz=0xffffd8000", "stack_guard=0xb2a15fc97c1f0047", "malloc_entropy=0x4dfb8667,0x9c5906ee",
                         "ptr_munge=0xe8d660a40bfdf321", "main_stack=0x16f000000,0x7fc000", "executable_file=0x1a01,0x1299",
                         "th_port=0x103", "security_config=0x0"]

    /// A buffer as the kernel lays it out; zeroed names apple[] entries
    /// libSystem already zero-filled (whole, or the value only when
    /// valueOnly).
    static func layout(path: String = "/bin/x", argv: [String], env: [String], apple: [String] = kernel,
                       zeroed: Set<String> = [], valueOnly: Set<String> = []) -> [UInt8] {
        func pad(_ a: inout [UInt8]) { while a.count % 8 != 0 { a.append(0) } }
        var area = Array(path.utf8) + [0]
        pad(&area)
        for s in argv + env { area += Array(s.utf8) + [0] }
        pad(&area)
        for s in apple {
            let key = String(s.prefix { $0 != "=" })
            if zeroed.contains(key) {
                area += [UInt8](repeating: 0, count: s.utf8.count + 1)
            } else if valueOnly.contains(key) {
                area += Array((key + "=").utf8) + [UInt8](repeating: 0, count: s.utf8.count - key.utf8.count)
            } else {
                area += Array(s.utf8) + [0]
            }
        }
        pad(&area)
        return withUnsafeBytes(of: Int32(argv.count).littleEndian) { Array($0) } + area
    }

    /// argv "x234567" ends the argv at 16; "A=12345" then ends the
    /// environment at 24, on a boundary: no padding, no empty string.
    @Test func noSeparatorBeforeTheKernelsStrings() {
        let b = Self.layout(argv: ["x234567"], env: ["A=12345"])
        #expect(b[4 + 24] == UInt8(ascii: "p")) // the layout really has no separator
        #expect(ProcArgs.parse(b)?.args == ["x234567"])
        #expect(ProcArgs.environment(b) == ["A=12345"])
        #expect(ProcArgs.environment(Self.layout(argv: ["x"], env: ["A=1", "B=two words"])) == ["A=1", "B=two words"])
    }

    /// The environment's own "pfz=…", even on a boundary, is the
    /// environment's: the kernel's comes last.
    @Test func anEnvironmentPFZIsPartOfTheEnvironment() {
        let env = ["A=12345", "pfz=0x1", "NODE_OPTIONS=--require /tmp/x.js"]
        #expect(ProcArgs.environment(Self.layout(argv: ["x234567"], env: env)) == env)
    }

    /// After libSystem zero-filled "pfz=…": the environment ends at its
    /// first empty string and the kernel's strings after it are ignored.
    @Test func afterLibSystemRan() {
        let b = Self.layout(argv: ["x234567"], env: ["A=12345"], zeroed: ["pfz", "stack_guard", "malloc_entropy"],
                            valueOnly: ["ptr_munge", "main_stack", "th_port"])
        #expect(ProcArgs.environment(b) == ["A=12345"])
    }

    /// An empty entry never hides the entries after it: with "pfz=…" in
    /// place (only padding may sit before it) and after it was zero-filled
    /// (only the kernel's names may follow).
    @Test func anEmptyEntryHidesNothing() {
        let env = ["A=1", "", "NODE_OPTIONS=--require /tmp/x.js"]
        #expect(ProcArgs.environment(Self.layout(argv: ["x"], env: env)) == nil)
        #expect(ProcArgs.environment(Self.layout(argv: ["x"], env: env, zeroed: ["pfz", "stack_guard"])) == nil)
        #expect(ProcArgs.environment(Self.layout(argv: ["x"], env: ["A=1", "", "http_proxy=http://evil"], zeroed: ["pfz"])) == nil)
    }

    /// A "pfz=…" of the environment on a boundary, the kernel's zero-filled:
    /// cutting there would hide what follows it, so it is unreadable.
    @Test func aFakePFZAfterTheRealOneWasZeroFilledHidesNothing() {
        let b = Self.layout(argv: ["x234567"], env: ["A=12345", "pfz=0x1", "NODE_OPTIONS=--require /tmp/x.js"],
                            zeroed: ["pfz", "stack_guard", "malloc_entropy"])
        #expect(ProcArgs.environment(b) == nil)
        let onlyKernelNames = Self.layout(argv: ["x234567"], env: ["A=12345", "pfz=0x1", "http_proxy=http://evil"],
                                          zeroed: ["pfz"])
        #expect(ProcArgs.environment(onlyKernelNames) == nil)
    }

    /// An empty argv[0] (or more empty arguments) right after the exec
    /// path's padding is an argument, not more padding: skipping it would
    /// read the first variable as the last argument, hiding it from the
    /// environment and showing it in argv.
    @Test func emptyLeadingArgumentsAreArguments() {
        let env = ["NODE_OPTIONS=--require /tmp/e.js", "A=1"]
        for n in 1...8 {
            let path = "/" + String(repeating: "p", count: n)
            for argv in [[""], ["", "x"], ["", ""], ["", "", "x"]] {
                let b = Self.layout(path: path, argv: argv, env: env)
                #expect(ProcArgs.parse(b)?.args == argv, "\(path) \(argv)")
                #expect(ProcArgs.environment(b) == env, "\(path) \(argv)")
                let after = Self.layout(path: path, argv: argv, env: env, zeroed: ["pfz", "stack_guard", "malloc_entropy"])
                #expect(ProcArgs.environment(after) == env, "\(path) \(argv) after libSystem ran")
            }
        }
    }
}
