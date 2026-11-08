import Foundation
import Testing
@testable import NazarUI

// Milestone 6 (spec 6.1): Nazar UI.app finds the installed agent's CLI and
// runs it only when it is signed as nazar's CLI by the UI's own developer.
// Every program here is a thin, ad-hoc-signed copy of a system tool in a
// temporary folder (never the real CLI, never an agent, never a real
// identity). No keychain is touched: these are code-signature calls only.

/// A temporary folder, removed by the caller.
func tempDir() throws -> URL {
    let u = FileManager.default.temporaryDirectory.appendingPathComponent("nzui-sig-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}

/// Runs a tool and requires exit 0; its stdout and stderr.
@discardableResult
func tool(_ path: String, _ args: [String]) throws -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let out = Pipe()
    p.standardOutput = out
    p.standardError = out
    try p.run()
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    let text = String(decoding: data, as: UTF8.self)
    try #require(p.terminationStatus == 0, "\(path) \(args): \(text)")
    return text
}

/// `system` (a path under /bin or /usr/bin) copied to `to`, thinned to its
/// arm64e slice (a cdhash names one architecture; the real CLI is arm64
/// only) and signed ad hoc as `identifier`.
@discardableResult
func signedCopy(of system: String, to: URL, identifier: String) throws -> URL {
    try FileManager.default.createDirectory(at: to.deletingLastPathComponent(), withIntermediateDirectories: true)
    try? FileManager.default.removeItem(at: to)
    try tool("/usr/bin/lipo", [system, "-thin", "arm64e", "-output", to.path])
    try tool("/usr/bin/codesign", ["--force", "--sign", "-", "--identifier", identifier, to.path])
    return to
}

/// codesign's own idea of the cdhash (what `make ui` pins).
func codesignCDHash(_ url: URL) throws -> String {
    let out = try tool("/usr/bin/codesign", ["-dvvv", url.path])
    let line = try #require(out.split(separator: "\n").first { $0.hasPrefix("CDHash=") })
    return String(line.dropFirst("CDHash=".count)).lowercased()
}

func pinned(_ url: URL) throws -> CLIRequirement {
    try CLIRequirement.make(ownTeam: nil, devPin: try #require(CodeSignature.cdhash(of: url))).get()
}

@Suite struct CLIRequirementTests {
    // A team build trusts dev.nazar.cli of its team, whatever it pins; an
    // ad-hoc build trusts exactly its pinned build; one without a pin
    // trusts nothing. Values that could add a clause are refused.
    @Test func rules() throws {
        let pin = String(repeating: "0123456789", count: 4)
        let team = try CLIRequirement.make(ownTeam: "ABCDE12345", devPin: pin).get()
        #expect(team.text == #"identifier "dev.nazar.cli" and anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345""#)
        #expect(try CLIRequirement.make(ownTeam: "ABCDE12345", devPin: nil).get() == team, "the pin never changes a team build's rule")
        let dev = try CLIRequirement.make(ownTeam: nil, devPin: pin).get()
        #expect(dev.text == #"identifier "dev.nazar.cli" and cdhash H"\#(pin)""#)
        #expect(team.compiled() != nil && dev.compiled() != nil, "both parse")
        #expect(CLIRequirement.make(ownTeam: nil, devPin: nil) == .failure(.noRule))
        for t in ["", "abcde12345", "ABCDE1234", "ABCDE123456", #"ABCDE1234""#, "ABCDE1234\n", #"X" or anchor apple"#] {
            #expect(CLIRequirement.make(ownTeam: t, devPin: pin) == .failure(.badTeam(t)), "\(t.debugDescription)")
        }
        for p in ["", String(pin.dropLast()), pin + "0", pin.uppercased().replacingOccurrences(of: "0", with: "A"),
                  String(pin.dropLast()) + "g", String(pin.dropLast(2)) + #"" or anchor apple"#] {
            #expect(CLIRequirement.make(ownTeam: nil, devPin: p) == .failure(.badPin(p)), "\(p.debugDescription)")
        }
    }

    @Test func ownSignatureIsReadable() {
        guard case .success = CodeSignature.ownTeam() else {
            Issue.record("the test runner's own signature could not be read")
            return
        }
    }

    // The cdhash the UI pins is the one codesign reports, and a file
    // satisfies its own pin and no other build's.
    @Test func cdhashAndFileCheck() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cli = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("a/nazar"), identifier: "dev.nazar.cli")
        let other = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("b/nazar"), identifier: "dev.nazar.cli.other")
        let h = try #require(CodeSignature.cdhash(of: cli))
        #expect(h == (try codesignCDHash(cli)) && h.count == 40)
        let req = try pinned(cli)
        #expect(CodeSignature.checkFile(cli, req) == nil)
        #expect(CodeSignature.checkFile(other, req) != nil)
        // An ad-hoc copy can't pass a team rule, whatever its identifier.
        let teamRule = try CLIRequirement.make(ownTeam: "ABCDE12345", devPin: nil).get()
        #expect(CodeSignature.checkFile(cli, teamRule) != nil)
        let unsigned = dir.appendingPathComponent("plain")
        try Data("#!/bin/sh\n".utf8).write(to: unsigned)
        #expect(CodeSignature.cdhash(of: unsigned) == nil)
        #expect(CodeSignature.checkFile(unsigned, req) != nil)
    }
}

@Suite struct CLILocatorTests {
    /// A home whose LaunchAgent starts <bundle>/Contents/MacOS/nazar-agent.
    func home(_ dir: URL, program: String) throws -> URL {
        let home = dir.appendingPathComponent("home")
        let agents = home.appendingPathComponent("Library/LaunchAgents")
        try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
        let plist: [String: Any] = ["Label": "dev.nazar.agent", "ProgramArguments": [program]]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: agents.appendingPathComponent("dev.nazar.agent.plist"))
        return home
    }

    // The agent the LaunchAgent starts, wherever it is installed, comes
    // first, and its CLI is used when it passes.
    @Test func findsTheCLIOfTheRegisteredAgent() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let bundle = dir.appendingPathComponent("Caskroom/nazar/0.2.0/nazar-agent.app/Contents/MacOS")
        let cli = try signedCopy(of: "/bin/echo", to: bundle.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        let h = try home(dir, program: bundle.appendingPathComponent("nazar-agent").path)
        let places = CLILocator.places(home: h.path)
        #expect(places.first?.source == "LaunchAgent dev.nazar.agent" && places.first?.path == cli.path)
        #expect(places.map(\.path).contains("/opt/homebrew/bin/nazar"))
        let found = CLILocator.locate(requirement: try pinned(cli), home: h.path)
        guard case .found(let url, let seen) = found else { Issue.record("\(found)"); return }
        let real = try #require(realpath(cli.path, nil))
        defer { free(real) }
        #expect(url.path == String(cString: real), "the resolved path runs (/var is /private/var)")
        #expect(seen.count == 1 && seen[0].problem == nil)
    }

    // Nothing usable: every place is listed with what was wrong, so the
    // window can say what it found. A link is followed and its target is
    // what is checked and would run.
    @Test func reportsWhatItFound() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let good = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("good/nazar"), identifier: "dev.nazar.cli")
        let other = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("other/nazar"), identifier: "dev.nazar.evil")
        let link = dir.appendingPathComponent("bin/nazar")
        try FileManager.default.createDirectory(at: link.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: other)
        let folder = dir.appendingPathComponent("folder")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let noexec = dir.appendingPathComponent("noexec")
        try FileManager.default.copyItem(at: good, to: noexec)
        chmod(noexec.path, 0o644)
        let req = try pinned(good)
        let result = CLILocator.locate(requirement: req, places: [
            ("missing", dir.appendingPathComponent("gone").path), ("relative", "bin/nazar"), ("folder", folder.path),
            ("not executable", noexec.path), ("link to another signature", link.path)])
        guard case .notFound(let seen) = result else { Issue.record("\(result)"); return }
        #expect(seen.map(\.source) == ["missing", "relative", "folder", "not executable", "link to another signature"])
        #expect(seen.map(\.problem) == ["not found", "not an absolute path", "not a regular file", "not executable",
                                        "not signed as dev.nazar.cli by this app's developer"])
        // A LaunchAgent program that is not a nazar-agent.app is shown, not used.
        let h = try home(dir, program: "/usr/bin/true")
        #expect(CLILocator.places(home: h.path).first?.path == "/usr/bin/true (not a nazar-agent.app)")
    }
}

@Suite(.serialized) struct VerifiedRunnerTests {
    // Input reaches a verified CLI's stdin, and only after its
    // running process passed the check: when the check runs the input is
    // still whole (a write before the check would have wiped it).
    @Test func inputGoesToAVerifiedCLIAfterTheCheck() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cli = try signedCopy(of: "/bin/cat", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        let input = CLIInput("s3cret-m11-verified")
        let atCheck = LinesBox()
        let runner = ProcessCLIRunner(cli: cli, requirement: try pinned(cli), checkRunning: { pid, r in
            Thread.sleep(forTimeInterval: 0.2) // an early writer would have drained it by now
            atCheck.add(input.isWiped ? "wiped" : "whole")
            return CodeSignature.checkRunning(pid: pid, r)
        })
        let r = await runner.run([], input: input)
        #expect(r.exitCode == 0 && r.stdout == Data("s3cret-m11-verified".utf8), "exit \(r.exitCode) \(r.stderr)")
        #expect(atCheck.lines == ["whole"] && input.isWiped)
    }

    // A program swapped in at the CLI's path after the pin is refused unrun
    // and never gets the input (tee would write it to the marker).
    @Test func inputNeverGoesToAnotherSignature() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cli = dir.appendingPathComponent("nazar")
        try signedCopy(of: "/bin/cat", to: cli, identifier: "dev.nazar.cli")
        let req = try pinned(cli)
        try signedCopy(of: "/usr/bin/tee", to: cli, identifier: "dev.nazar.cli")
        let marker = dir.appendingPathComponent("got")
        let input = CLIInput("s3cret-m11-swapped")
        let atCheck = LinesBox()
        let runner = ProcessCLIRunner(cli: cli, requirement: req, checkRunning: { pid, r in
            Thread.sleep(forTimeInterval: 0.2)
            atCheck.add(input.isWiped ? "wiped" : "whole")
            return CodeSignature.checkRunning(pid: pid, r)
        })
        let r = await runner.run([marker.path], input: input)
        #expect(r.exitCode == ProcessCLIRunner.refusedSignature && r.stdout.isEmpty, "\(r.exitCode)")
        // Whole at the check (nothing was written before it), wiped after the refusal.
        #expect(atCheck.lines == ["whole"] && input.isWiped)
        #expect(!FileManager.default.fileExists(atPath: marker.path))
    }

    // The app's runner runs a CLI that satisfies the requirement, with the
    // arguments and the fixed environment.
    @Test func runsAVerifiedCLI() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cli = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        let r = await ProcessCLIRunner(cli: cli, requirement: try pinned(cli), home: "/Users/u").run(["--json", "a b"])
        #expect(r.exitCode == 0 && String(decoding: r.stdout, as: UTF8.self) == "--json a b\n", "\(r)")
    }

    // A file at the CLI's path that does not satisfy the requirement is
    // killed before its first instruction: it never runs (touch never
    // creates its file), and the run says why (exit 126). That includes a
    // file swapped in after the locator checked the path.
    @Test func neverRunsAnotherSignature() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cli = dir.appendingPathComponent("nazar")
        try signedCopy(of: "/bin/echo", to: cli, identifier: "dev.nazar.cli")
        let req = try pinned(cli)
        #expect(CLILocator.check(cli.path, req).why == nil, "checked and offered")
        try signedCopy(of: "/usr/bin/touch", to: cli, identifier: "dev.nazar.cli") // swapped after the check
        let marker = dir.appendingPathComponent("ran")
        let runner = ProcessCLIRunner(cli: cli, requirement: req)
        let r = await runner.run([marker.path])
        #expect(r.exitCode == ProcessCLIRunner.refusedSignature && r.stderr.contains("not the nazar CLI this app trusts"), "\(r)")
        #expect(!FileManager.default.fileExists(atPath: marker.path), "the unverified program ran")
        let got = LinesBox()
        await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
            _ = runner.stream([marker.path], onLine: { got.add(String(decoding: $0, as: UTF8.self)) },
                              onExit: { code in got.exit = code; k.resume() })
        }
        #expect(got.lines.isEmpty && got.exit == ProcessCLIRunner.refusedSignature)
        #expect(!FileManager.default.fileExists(atPath: marker.path), "the unverified stream ran")
        // An unsigned script at the path is refused the same way.
        try? FileManager.default.removeItem(at: cli)
        try Data("#!/bin/sh\ntouch \"$1\"\n".utf8).write(to: cli)
        chmod(cli.path, 0o755)
        let s = await runner.run([marker.path])
        #expect(s.exitCode == ProcessCLIRunner.refusedSignature && !FileManager.default.fileExists(atPath: marker.path), "\(s)")
    }

    // A `#!` script at the CLI's path that names the genuine (pinned) CLI as
    // its interpreter: the kernel runs the interpreter, so the running
    // process passes the signature check, but it would run with arguments
    // the script chose in front of the UI's own (and the script path among
    // them). The runner checks how the suspended child was started (exec
    // path and argv exactly the CLI's path and [path] + args) and refuses
    // it unrun: exit 126, not a byte of output, through run() and stream().
    // Without that check (the runner's started-as check removed) this fails:
    // the genuine echo prints "injected <path> --json status".
    @Test func neverRunsAScriptThatNamesTheCLIAsItsInterpreter() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let genuine = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("genuine/nazar"), identifier: "dev.nazar.cli")
        let req = try pinned(genuine)
        let cli = dir.appendingPathComponent("nazar")
        let runner = ProcessCLIRunner(cli: cli, requirement: req)
        for line in ["#!\(genuine.path) injected\n", "#!\(genuine.path)\n", "#!\(genuine.path) ssh-key rule add github --app /tmp/evil\n"] {
            try? FileManager.default.removeItem(at: cli)
            try Data(line.utf8).write(to: cli)
            chmod(cli.path, 0o755)
            #expect(CodeSignature.checkFile(genuine, req) == nil, "the interpreter is the genuine CLI")
            let r = await runner.run(["--json", "status"])
            #expect(r.exitCode == ProcessCLIRunner.refusedSignature && r.stdout.isEmpty
                    && r.stderr.contains("not the nazar CLI this app trusts"), "\(line.debugDescription): \(r)")
            let got = LinesBox()
            await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
                _ = runner.stream(["--json", "status"], onLine: { got.add(String(decoding: $0, as: UTF8.self)) },
                                  onExit: { code in got.exit = code; k.resume() })
            }
            #expect(got.lines.isEmpty && got.exit == ProcessCLIRunner.refusedSignature,
                    "\(line.debugDescription): \(got.lines), exit \(got.exit)")
        }
        // The genuine CLI itself, at its own path, still runs.
        let ok = await ProcessCLIRunner(cli: genuine, requirement: req).run(["--json", "status"])
        #expect(ok.exitCode == 0 && String(decoding: ok.stdout, as: UTF8.self) == "--json status\n", "\(ok)")
    }

    // The check judges the program that runs, not the file at the path when
    // it is asked: an evil file is swapped in after the locator's check, the
    // runner starts it suspended, and the genuine file is swapped back
    // before the running-process check (inside the check seam, which then
    // makes the real check). The started program never runs (touch never
    // creates its file): exit 126, through run() and stream(). A check of
    // the file on disk (SecCodeCopyStaticCode of the guest, or of the path)
    // would pass here and let the evil program run.
    @Test func aFileSwappedBackBeforeTheCheckIsStillRefused() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let genuine = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("genuine/nazar"), identifier: "dev.nazar.cli")
        let evil = try signedCopy(of: "/usr/bin/touch", to: dir.appendingPathComponent("evil/nazar"), identifier: "dev.nazar.cli")
        let req = try pinned(genuine)
        let cli = dir.appendingPathComponent("nazar")
        let marker = dir.appendingPathComponent("ran")
        /// Puts a copy of src at cli in one rename (a new file, as an attacker would).
        @Sendable func swap(in src: URL) -> Bool {
            let staged = dir.appendingPathComponent("staged-\(UUID().uuidString)")
            guard (try? FileManager.default.copyItem(at: src, to: staged)) != nil else { return false }
            return rename(staged.path, cli.path) == 0
        }
        let seen = CheckBox()
        let runner = ProcessCLIRunner(cli: cli, requirement: req, checkRunning: { pid, r in
            let back = swap(in: genuine)
            let fileNow = CodeSignature.checkFile(cli, r)
            seen.record(pid: pid, requirement: r, ranBeforeAnswer: !back || fileNow != nil)
            return CodeSignature.checkRunning(pid: pid, r)
        })
        #expect(swap(in: genuine) && CLILocator.check(cli.path, req).why == nil, "checked and offered")
        #expect(swap(in: evil), "swapped after the check")
        let r = await runner.run([marker.path])
        #expect(r.exitCode == ProcessCLIRunner.refusedSignature && r.stdout.isEmpty, "\(r)")
        #expect(!FileManager.default.fileExists(atPath: marker.path), "the swapped-in program ran (run)")
        #expect(swap(in: evil), "swapped again")
        let got = LinesBox()
        await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
            _ = runner.stream([marker.path], onLine: { got.add(String(decoding: $0, as: UTF8.self)) },
                              onExit: { code in got.exit = code; k.resume() })
        }
        #expect(got.lines.isEmpty && got.exit == ProcessCLIRunner.refusedSignature, "exit \(got.exit)")
        #expect(!FileManager.default.fileExists(atPath: marker.path), "the swapped-in program ran (stream)")
        // Each check really saw the genuine file back at the path.
        let calls = seen.calls
        #expect(calls.count == 2 && calls.allSatisfy { !$0.ranBeforeAnswer }, "\(calls)")
    }

    // The runner starts the CLI suspended: however long the check of the
    // running process takes, the program at the path runs nothing before
    // the answer, and a refusal kills it unrun. The check here holds the
    // child 300 ms (an unsuspended touch creates its file well within that)
    // and then refuses, through run() and stream(). Without the suspended
    // start (`suspended: false` in start) this fails.
    @Test func theCLIIsSuspendedWhileItIsChecked() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cli = try signedCopy(of: "/usr/bin/touch", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        let req = try pinned(cli)
        let marker = dir.appendingPathComponent("ran")
        let seen = CheckBox()
        let runner = ProcessCLIRunner(cli: cli, requirement: req, checkRunning: { pid, r in
            usleep(300_000)
            seen.record(pid: pid, requirement: r, ranBeforeAnswer: FileManager.default.fileExists(atPath: marker.path))
            return "held for the test, then refused"
        })
        let r = await runner.run([marker.path])
        #expect(r.exitCode == ProcessCLIRunner.refusedSignature && r.stderr.contains("held for the test"), "\(r)")
        #expect(!FileManager.default.fileExists(atPath: marker.path), "the CLI ran while it was being checked (run)")
        let got = LinesBox()
        await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
            _ = runner.stream([marker.path], onLine: { got.add(String(decoding: $0, as: UTF8.self)) },
                              onExit: { code in got.exit = code; k.resume() })
        }
        #expect(got.lines.isEmpty && got.exit == ProcessCLIRunner.refusedSignature)
        #expect(!FileManager.default.fileExists(atPath: marker.path), "the CLI ran while it was being checked (stream)")
        let calls = seen.calls
        #expect(calls.count == 2 && calls.allSatisfy { $0.pid > 0 && $0.requirement == req && !$0.ranBeforeAnswer }, "\(calls)")
        #expect(Set(calls.map(\.pid)).count == 2, "each run checks its own child")
    }

    // A stream of a verified CLI delivers its lines, and stop() ends it.
    @Test func verifiedStreamStops() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cli = try signedCopy(of: "/usr/bin/yes", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        let got = LinesBox()
        let start = Date()
        await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
            got.stream = ProcessCLIRunner(cli: cli, requirement: try! pinned(cli)).stream(["line"], onLine: { l in
                got.add(String(decoding: l, as: UTF8.self))
                got.stream?.stop()
            }, onExit: { code in got.exit = code; k.resume() })
        }
        #expect(got.lines.first == "line" && got.exit == 128 + SIGTERM, "\(got.lines.count) lines, exit \(got.exit)")
        #expect(Date().timeIntervalSince(start) < 10)
    }
}

// Edge and attack cases (test author).

@Suite struct CLIRequirementEdgeTests {
    // A team build's rule never depends on the pin, not even a malformed
    // one: an edited or stray NazarDevCLICDHash can neither weaken a team
    // build nor stop it from working.
    @Test func aTeamBuildIgnoresAnyPin() throws {
        let team = try CLIRequirement.make(ownTeam: "ABCDE12345", devPin: nil).get()
        for p in ["", "zz", #"0" or anchor apple"#, String(repeating: "0", count: 40)] {
            #expect(CLIRequirement.make(ownTeam: "ABCDE12345", devPin: p) == .success(team), "\(p.debugDescription)")
        }
        #expect(!team.text.contains("cdhash"))
    }

    // The process running the tests is not nazar's CLI: neither rule
    // accepts it, so checkRunning never says yes to a process just because
    // it can be asked about.
    @Test func theTestRunnerIsNotTheCLI() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cli = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        #expect(CodeSignature.checkRunning(pid: getpid(), try pinned(cli)) != nil)
        let teamRule = try CLIRequirement.make(ownTeam: "ABCDE12345", devPin: nil).get()
        #expect(CodeSignature.checkRunning(pid: getpid(), teamRule) != nil)
    }

    // The right cdhash under another identifier is not the CLI either: the
    // dev rule names both.
    @Test func thePinIsNotEnoughWithoutTheIdentifier() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cli = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.evil")
        let h = try #require(CodeSignature.cdhash(of: cli))
        let req = try CLIRequirement.make(ownTeam: nil, devPin: h).get()
        #expect(CodeSignature.checkFile(cli, req) != nil)
    }
}

@Suite struct CLILocatorEdgeTests {
    func writeAgentPlist(_ home: URL, _ data: Data) throws {
        let agents = home.appendingPathComponent("Library/LaunchAgents")
        try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
        try data.write(to: agents.appendingPathComponent("dev.nazar.agent.plist"))
    }

    // A LaunchAgent plist that names no absolute program (relative, empty,
    // not a plist at all) adds no place: the package links follow.
    @Test func aBrokenLaunchAgentAddsNoPlace() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let home = dir.appendingPathComponent("home")
        let plists: [Any?] = [["Label": "dev.nazar.agent", "ProgramArguments": ["nazar-agent.app/Contents/MacOS/nazar-agent"]],
                              ["Label": "dev.nazar.agent", "ProgramArguments": [String]()],
                              ["Label": "dev.nazar.agent", "Program": "/x/nazar-agent.app/Contents/MacOS/nazar-agent"],
                              nil]
        for p in plists {
            let data = try p.map { try PropertyListSerialization.data(fromPropertyList: $0, format: .xml, options: 0) }
                ?? Data("not a plist \u{0}\u{1}".utf8)
            try writeAgentPlist(home, data)
            let places = CLILocator.places(home: home.path)
            #expect(places.map(\.path) == ["/opt/homebrew/bin/nazar", "/usr/local/bin/nazar", home.path + "/.local/bin/nazar"],
                    "\(String(describing: p))")
        }
        // No plist at all: the same.
        try FileManager.default.removeItem(at: home.appendingPathComponent("Library/LaunchAgents/dev.nazar.agent.plist"))
        #expect(CLILocator.places(home: home.path).count == 3)
    }

    // The first place that passes is used and nothing after it is looked at;
    // a link to a passing CLI is accepted by its resolved target.
    @Test func theFirstPassingPlaceWins() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let good = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("good/nazar"), identifier: "dev.nazar.cli")
        let link = dir.appendingPathComponent("bin/nazar")
        try FileManager.default.createDirectory(at: link.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: good)
        let second = dir.appendingPathComponent("second/nazar")
        try FileManager.default.createDirectory(at: second.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: good, to: second)
        let result = CLILocator.locate(requirement: try pinned(good), places: [
            ("missing", dir.appendingPathComponent("gone").path), ("link", link.path), ("second", second.path)])
        guard case .found(let url, let seen) = result else { Issue.record("\(result)"); return }
        let real = try #require(realpath(good.path, nil))
        defer { free(real) }
        #expect(url.path == String(cString: real), "the link's target is what runs")
        #expect(seen.map(\.source) == ["missing", "link"] && seen.map(\.problem) == ["not found", nil])
    }

    // A file that passes is still refused when it is not executable or is a
    // folder named like the CLI: being signed is not enough to be run.
    @Test func aSignedFileMustStillBeARegularExecutable() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let good = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("good/nazar"), identifier: "dev.nazar.cli")
        let req = try pinned(good)
        chmod(good.path, 0o644)
        #expect(CLILocator.check(good.path, req).why == "not executable")
        #expect(CLILocator.check(good.path, req).url == nil)
        #expect(CLILocator.check(dir.path, req).why == "not a regular file")
    }

    // A script is never offered, whatever its interpreter: the window says
    // it is not a program (the runner refuses one on its own as well).
    @Test func aScriptIsNotOffered() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let good = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("good/nazar"), identifier: "dev.nazar.cli")
        let req = try pinned(good)
        let script = dir.appendingPathComponent("bin/nazar")
        try FileManager.default.createDirectory(at: script.deletingLastPathComponent(), withIntermediateDirectories: true)
        for body in ["#!\(good.path) injected\n", "#!/bin/sh\n", "", "\u{cf}\u{fa}"] {
            try? FileManager.default.removeItem(at: script)
            try Data(body.utf8).write(to: script)
            chmod(script.path, 0o755)
            let c = CLILocator.check(script.path, req)
            #expect(c.url == nil && c.why == "not a Mach-O program", "\(body.debugDescription): \(c)")
        }
        #expect(CLILocator.check(good.path, req).why == nil)
    }
}

@Suite(.serialized) struct VerifiedRunnerEdgeTests {
    // The verified runner passes HOME, the fixed PATH and LANG and nothing
    // else of the app's environment (no NAZAR_* override reaches the CLI).
    @Test func theVerifiedCLIGetsOnlyTheFixedEnvironment() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cli = try signedCopy(of: "/usr/bin/env", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        setenv("NAZAR_CONTROL_SOCKET", "/tmp/evil.sock", 1)
        defer { unsetenv("NAZAR_CONTROL_SOCKET") }
        let r = await ProcessCLIRunner(cli: cli, requirement: try pinned(cli), home: "/Users/u").run([])
        let lines = String(decoding: r.stdout, as: UTF8.self).split(separator: "\n").map(String.init).sorted()
        #expect(r.exitCode == 0, "\(r)")
        #expect(lines == ["HOME=/Users/u", "LANG=en_US.UTF-8", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"], "\(lines)")
    }

    // A CLI with the right shape but the wrong identifier never prints a
    // byte; a missing CLI is "cannot run" (127), not a crash or a hang.
    @Test func refusalsAndMissingCLI() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let good = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("good/nazar"), identifier: "dev.nazar.cli")
        let req = try pinned(good)
        let evil = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("evil/nazar"), identifier: "dev.nazar.evil")
        let r = await ProcessCLIRunner(cli: evil, requirement: req).run(["leaked"])
        #expect(r.exitCode == ProcessCLIRunner.refusedSignature && r.stdout.isEmpty, "\(r)")
        let m = await ProcessCLIRunner(cli: dir.appendingPathComponent("gone/nazar"), requirement: req).run(["x"])
        #expect(m.exitCode == ProcessCLIRunner.cannotRun && m.stderr.contains("cannot run"), "\(m)")
        let got = LinesBox()
        await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
            _ = ProcessCLIRunner(cli: dir.appendingPathComponent("gone/nazar"), requirement: req).stream(["x"],
                onLine: { got.add(String(decoding: $0, as: UTF8.self)) }, onExit: { code in got.exit = code; k.resume() })
        }
        #expect(got.lines.isEmpty && got.exit == ProcessCLIRunner.cannotRun)
    }

    // A child started suspended runs nothing until resume(); its running
    // process satisfies its own pin and no other; a killed child reports
    // 128 + SIGKILL, and asking again gives the same answer.
    @Test func aSuspendedChildRunsNothingUntilResumed() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let touch = try signedCopy(of: "/usr/bin/touch", to: dir.appendingPathComponent("t/nazar"), identifier: "dev.nazar.cli")
        let echo = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("e/nazar"), identifier: "dev.nazar.cli")
        let marker = dir.appendingPathComponent("ran")
        let env = ProcessCLIRunner.environment(home: "/Users/u")

        let a = try SpawnedChild.spawn(touch.path, args: [marker.path], environment: env, suspended: true)
        usleep(300_000)
        #expect(!FileManager.default.fileExists(atPath: marker.path), "a suspended child ran")
        #expect(!a.hasRun(), "a suspended child counts as started")
        #expect(CodeSignature.checkRunning(pid: a.pid, try pinned(touch)) == nil)
        #expect(!a.hasRun(), "the check counts as the child's own system calls")
        #expect(CodeSignature.checkRunning(pid: a.pid, try pinned(echo)) != nil)
        a.resume()
        #expect(a.waitExit() == 0 && a.waitExit() == 0)
        #expect(FileManager.default.fileExists(atPath: marker.path))
        a.kill() // after it was reaped: never signals a pid that may be another process's

        try FileManager.default.removeItem(at: marker)
        let b = try SpawnedChild.spawn(touch.path, args: [marker.path], environment: env, suspended: true)
        b.kill()
        #expect(b.waitExit() == 128 + SIGKILL && b.waitExit() == 128 + SIGKILL)
        #expect(!FileManager.default.fileExists(atPath: marker.path), "a killed suspended child ran")

        // A child that is running counts as started. (Not suspended: what
        // is judged here is hasRun, not how soon a resume takes; a scanner
        // may hold a binary it has not seen for a moment after exec.)
        let sleep = try signedCopy(of: "/bin/sleep", to: dir.appendingPathComponent("s/nazar"), identifier: "dev.nazar.cli")
        let c = try SpawnedChild.spawn(sleep.path, args: ["30"], environment: env, suspended: false)
        defer { c.kill(); _ = c.waitExit() }
        let end = Date().addingTimeInterval(20)
        while !c.hasRun() && Date() < end { usleep(1000) }
        #expect(c.hasRun(), "a running child never counted as started")
        #expect(Darwin.kill(c.pid, 0) == 0, "it exited: the test proves nothing")
    }

    // checkRunning judges the code that is running, not the file now at its
    // path: a suspended touch whose file is then replaced by the pinned echo
    // fails the echo's pin although the file at the path passes it. (A
    // static check of the guest's file, SecCodeCopyStaticCode +
    // SecStaticCodeCheckValidity, passes here.) The file is replaced in
    // one rename, as an attacker would.
    @Test func checkRunningJudgesTheRunningCodeNotTheFile() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("nazar")
        try signedCopy(of: "/usr/bin/touch", to: path, identifier: "dev.nazar.cli")
        let staged = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("staged"), identifier: "dev.nazar.cli")
        let echo = try pinned(staged)
        let marker = dir.appendingPathComponent("ran")
        let a = try SpawnedChild.spawn(path.path, args: [marker.path], environment: ProcessCLIRunner.environment(home: "/Users/u"),
                                       suspended: true)
        defer { a.kill(); _ = a.waitExit() }
        #expect(rename(staged.path, path.path) == 0, "a new file at the same path, in one rename")
        #expect(CodeSignature.checkFile(path, echo) == nil, "the file now at the path is the pinned echo")
        let why = CodeSignature.checkRunning(pid: a.pid, echo)
        #expect(why != nil, "the running touch passed the echo's pin")
        #expect(!(why ?? "").hasPrefix("can't identify"), "the process was identified and its code judged: \(why ?? "")")
        a.kill()
        #expect(a.waitExit() == 128 + SIGKILL)
        #expect(!FileManager.default.fileExists(atPath: marker.path), "the suspended child ran")
    }

    // The runner reads how its suspended child was started (KERN_PROCARGS2):
    // a Mach-O CLI is started as itself with exactly [path] + args; a `#!`
    // script is started as its interpreter, with the script's arguments and
    // the script path in front of the caller's.
    @Test func aChildIsSeenAsItWasStarted() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let echo = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("e/nazar"), identifier: "dev.nazar.cli")
        let script = dir.appendingPathComponent("s/nazar")
        try FileManager.default.createDirectory(at: script.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("#!\(echo.path) a b\n".utf8).write(to: script)
        chmod(script.path, 0o755)
        let env = ProcessCLIRunner.environment(home: "/Users/u")
        let c = try SpawnedChild.spawn(echo.path, args: ["--json", "x y"], environment: env, suspended: true)
        defer { c.kill(); _ = c.waitExit() }
        let cs = try #require(c.startedAs())
        #expect(cs.path == echo.path && cs.argv == [echo.path, "--json", "x y"], "\(cs)")
        let s = try SpawnedChild.spawn(script.path, args: ["--json"], environment: env, suspended: true)
        defer { s.kill(); _ = s.waitExit() }
        let ss = try #require(s.startedAs())
        #expect(ss.path == echo.path && ss.argv == [echo.path, "a", "b", script.path, "--json"], "\(ss)")
        s.kill()
        _ = s.waitExit()
        #expect(s.startedAs() == nil, "a reaped child's pid is never read")
    }

    // stop() relies on SIGTERM reaching the child. An ignored signal
    // survives exec, so a child spawned while the app ignores SIGTERM would
    // ignore it too and a `--follow` stream would outlive the window; the
    // spawn resets every signal to its default (POSIX_SPAWN_SETSIGDEF). A
    // sleep spawned while this process ignores SIGTERM still dies of it.
    @Test func aChildDoesNotInheritAnIgnoredSIGTERM() throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let sleep = try signedCopy(of: "/bin/sleep", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        let previous = signal(SIGTERM, SIG_IGN)
        let c = try SpawnedChild.spawn(sleep.path, args: ["5"], environment: ProcessCLIRunner.environment(home: "/Users/u"),
                                       suspended: false)
        signal(SIGTERM, previous)
        let started = Date()
        c.terminate()
        let code = c.waitExit()
        let took = Date().timeIntervalSince(started)
        #expect(code == 128 + SIGTERM, "exit \(code) after \(took)s: the child inherited the ignored SIGTERM")
        #expect(took < 4, "the child ran on for \(took)s")
    }

    // No descriptor of the app reaches the CLI (POSIX_SPAWN_CLOEXEC_DEFAULT):
    // not a file opened without O_CLOEXEC, nor another run's pipe write end
    // (whose reader would then never see EOF). A verified ls of /dev/fd sees
    // only its own descriptors, never the one this process holds open. That
    // one is numbered 100 or more, never a number ls uses for itself (it
    // opens /dev/fd as 3, so a probe at 3 would be seen either way).
    @Test func aChildInheritsNoDescriptorOfTheApp() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let ls = try signedCopy(of: "/bin/ls", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        let low = open("/dev/null", O_RDONLY)
        try #require(low >= 0)
        let held = fcntl(low, F_DUPFD, 100)
        close(low)
        try #require(held >= 100)
        defer { close(held) }
        #expect(fcntl(held, F_GETFD) & FD_CLOEXEC == 0, "the probe would be inherited without POSIX_SPAWN_CLOEXEC_DEFAULT")
        let r = await ProcessCLIRunner(cli: ls, requirement: try pinned(ls), home: "/Users/u").run(["/dev/fd"])
        let entries = String(decoding: r.stdout, as: UTF8.self).split(separator: "\n").compactMap { Int32($0) }.sorted()
        #expect(r.exitCode == 0, "\(r)")
        #expect(entries.starts(with: [0, 1, 2]), "ls listed \(entries)")
        #expect(!entries.contains(held), "the child inherited descriptor \(held): \(entries)")
        #expect(entries.count <= 5, "the child has more than stdin, stdout, stderr and its own: \(entries)")
    }

    // A checked child whose resume is lost (it stays suspended, as one once
    // did at _dyld_start for hours) is killed after the start limit and the
    // CLI is started once more, checked again; when that one does not start
    // either, the run says so: never a wait without end. Nothing of it ran.
    @Test func aChildThatNeverStartsIsStopped() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let touch = try signedCopy(of: "/usr/bin/touch", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        let marker = dir.appendingPathComponent("ran")
        let pids = LinesBox(), resumes = LinesBox()
        let runner = ProcessCLIRunner(cli: touch, requirement: try pinned(touch), checkRunning: { pid, r in
            pids.add(String(pid))
            return CodeSignature.checkRunning(pid: pid, r)
        }, resume: { child in resumes.add(String(child.pid)) }, limits: .init(start: 1, run: 60, drain: 1))
        let input = CLIInput("unsent")
        let started = Date()
        let r = await runner.run([marker.path], input: input)
        let took = Date().timeIntervalSince(started)
        #expect(r.exitCode == ProcessCLIRunner.cannotRun && r.stderr.contains("did not start within 1 s, twice"), "\(r)")
        #expect(input.isWiped)
        #expect(took < 10, "the run waited \(took) s on a child that never started")
        #expect(!FileManager.default.fileExists(atPath: marker.path), "the child ran")
        #expect(pids.lines.count == 2, "started and checked \(pids.lines.count) times")
        // One resume each: another SIGCONT would end any other holder's hold too.
        #expect(resumes.lines == pids.lines, "resumed \(resumes.lines) of \(pids.lines)")
        for pid in pids.lines.compactMap({ pid_t($0) }) {
            #expect(Darwin.kill(pid, 0) == -1 && errno == ESRCH, "the child \(pid) is still there")
        }

        let got = LinesBox()
        await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in
            _ = runner.stream([marker.path], onLine: { got.add(String(decoding: $0, as: UTF8.self)) },
                              onExit: { code in got.exit = code; k.resume() })
        }
        #expect(got.lines.isEmpty && got.exit == ProcessCLIRunner.cannotRun)
        #expect(!FileManager.default.fileExists(atPath: marker.path), "the streamed child ran")
    }

    // A child that never starts is replaced: the second, checked like the
    // first and resumed once like it, runs, and the run gets its output.
    // (The limit leaves the second time to start on a loaded machine.)
    @Test func aChildThatNeverStartsIsReplaced() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let echo = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("nazar"), identifier: "dev.nazar.cli")
        let checked = LinesBox(), resumes = LinesBox()
        let runner = ProcessCLIRunner(cli: echo, requirement: try pinned(echo), checkRunning: { pid, r in
            checked.add(String(pid))
            return CodeSignature.checkRunning(pid: pid, r)
        }, resume: { child in
            resumes.add(String(child.pid))
            if checked.lines.first != String(child.pid) { child.resume() }
        }, limits: .init(start: 5, run: 60, drain: 1))
        let r = await runner.run(["hi"])
        #expect(r.exitCode == 0 && r.stdout == Data("hi\n".utf8), "\(r)")
        #expect(checked.lines.count == 2 && resumes.lines == checked.lines, "checked \(checked.lines), resumed \(resumes.lines)")
    }
}

/// What the replaced running-process check saw, from the runner's threads.
final class CheckBox: @unchecked Sendable {
    struct Call: CustomStringConvertible {
        let pid: pid_t
        let requirement: CLIRequirement
        let ranBeforeAnswer: Bool
        var description: String { "pid \(pid), ran before the answer: \(ranBeforeAnswer)" }
    }
    private let lock = NSLock()
    private var all: [Call] = []
    func record(pid: pid_t, requirement: CLIRequirement, ranBeforeAnswer: Bool) {
        lock.withLock { all.append(Call(pid: pid, requirement: requirement, ranBeforeAnswer: ranBeforeAnswer)) }
    }
    var calls: [Call] { lock.withLock { all } }
}
