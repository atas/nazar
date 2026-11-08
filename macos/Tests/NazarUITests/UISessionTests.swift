import Foundation
import Testing
@testable import NazarUI

// Milestone 6 (spec 6.1): Nazar UI.app runs nothing in the background. The
// session finds a verified CLI or says what it found; the live streams run
// only while the window is open and all stop when it closes or the app
// quits. A FakeCLIRunner stands in for the CLI: nothing is run, nothing is
// put on screen.

@MainActor @Suite struct UISessionTests {
    let req = CLIRequirement(text: #"identifier "dev.nazar.cli" and cdhash H"0000000000000000000000000000000000000000""#)
    let cli = URL(fileURLWithPath: "/opt/homebrew/Caskroom/nazar/0.1.0/nazar-agent.app/Contents/MacOS/nazar")

    func ready(_ runner: FakeCLIRunner) -> UISession {
        UISession(requirement: .success(req), locate: { _ in .found(cli, []) }, makeRunner: { _, _ in runner })
    }

    func streams(_ r: FakeCLIRunner) -> [[String]] { r.calls.filter { $0.contains("--follow") } }

    @Test func noRuleMeansNoCLI() {
        var made = 0
        let s = UISession(requirement: .failure(.noRule), locate: { _ in Issue.record("looked for a CLI without a rule"); return .notFound([]) },
                          makeRunner: { _, _ in made += 1; return FakeCLIRunner() })
        guard case .noCLI(let reason, let c) = s.state else { Issue.record("\(s.state)"); return }
        #expect(reason.contains("trusts no nazar CLI") && c.isEmpty && made == 0)
        s.windowOpened()
        s.retry()
        #expect(made == 0)
    }

    @Test func notFoundListsWhatWasFound() {
        let seen = [CLICandidate(source: "LaunchAgent dev.nazar.agent", path: "/x/nazar", problem: "not signed as dev.nazar.cli by this app's developer")]
        var asked: [CLIRequirement] = []
        let s = UISession(requirement: .success(req), locate: { asked.append($0); return .notFound(seen) },
                          makeRunner: { _, _ in Issue.record("made a runner for no CLI"); return FakeCLIRunner() })
        guard case .noCLI(let reason, let c) = s.state else { Issue.record("\(s.state)"); return }
        #expect(c == seen && reason.contains(UISession.installHint) && asked == [req])
    }

    // Nothing runs before the window opens; opening starts the approvals
    // stream once; closing stops it and it never comes back by itself.
    @Test func streamsRunOnlyWhileTheWindowIsOpen() async {
        let r = FakeCLIRunner()
        r.streamExit = 0
        let s = ready(r)
        guard case .ready(let m) = s.state else { Issue.record("\(s.state)"); return }
        #expect(r.calls.isEmpty, "something ran before the window opened")
        s.windowOpened()
        #expect(streams(r) == [["--json", "status", "--follow"]])
        #expect(m.approvals.reconnectAfter == NazarModels.reconnectAfter)
        s.windowClosed()
        #expect(r.stopped >= 1 && m.approvals.reconnectAfter == nil)
        try? await Task.sleep(nanoseconds: 200_000_000)
        #expect(streams(r).count == 1, "a stream started again after the window closed")
    }

    // Quitting (applicationWillTerminate → stopAll) stops the Activity
    // stream too.
    @Test func stopAllStopsEveryStream() async {
        let r = FakeCLIRunner()
        r.on(["log"], CLIResult(exitCode: 0))
        let s = ready(r)
        guard case .ready(let m) = s.state else { Issue.record("\(s.state)"); return }
        s.windowOpened()
        await m.activity.start()
        #expect(streams(r).count == 2)
        let before = r.stopped
        s.stopAll()
        #expect(r.stopped - before == 2, "stopped \(r.stopped - before) of 2 streams")
    }

    // After installing nazar, "Look again" finds it and, with the window
    // open, starts its stream.
    @Test func retryFindsANewlyInstalledCLI() {
        let r = FakeCLIRunner()
        var installed = false
        let s = UISession(requirement: .success(req), locate: { _ in installed ? .found(cli, []) : .notFound([]) },
                          makeRunner: { url, rq in
                              #expect(url == cli && rq == req)
                              return r
                          })
        s.windowOpened()
        s.retry()
        guard case .noCLI = s.state else { Issue.record("\(s.state)"); return }
        installed = true
        s.retry()
        guard case .ready = s.state else { Issue.record("\(s.state)"); return }
        #expect(streams(r) == [["--json", "status", "--follow"]])
    }

    // RootView's appearance hooks hang on one view that stays while the
    // state changes (a ZStack), never on a Group: a modifier on a Group
    // applies to each of its members, so "Look again" (noCLI → ready)
    // would run SetupView's onDisappear and the window's onAppear in an
    // order SwiftUI does not document, and windowClosed() landing last
    // would leave an open window whose streams are stopped for good. No
    // test can open a window, so the source is pinned.
    @Test func appearanceHooksBelongToOneStableView() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../Sources/NazarUI/Views/RootView.swift").standardizedFileURL
        let src = try String(contentsOf: url, encoding: .utf8)
        let rootView = try #require(src.components(separatedBy: "public struct RootView: View {").last?
            .components(separatedBy: "\n}\n").first)
        let body = try #require(rootView.components(separatedBy: "var body: some View {").last)
        #expect(body.contains(".onAppear { session.windowOpened() }") && body.contains(".onDisappear { session.windowClosed() }"))
        #expect(!rootView.contains("Group {"), "a Group forwards onAppear/onDisappear to each branch of the switch")
        #expect(body.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("ZStack {"), "the hooks' view is not the ZStack")
    }

    // ---- edge and attack cases

    // Every way the app's own rule can fail leaves it with no CLI: nothing
    // is looked for, no runner is made, nothing runs, and the reason is the
    // problem's own plain text (shown through plain in SetupView).
    @Test func everyRuleProblemMeansNoCLI() {
        let problems: [CLIRequirement.Problem] = [.noRule, .badTeam("ABCDE12345\" or anchor apple"), .badPin("00 or true"), .ownSignature(-67062)]
        for p in problems {
            var made = 0, looked = 0
            let s = UISession(requirement: .failure(p), locate: { _ in looked += 1; return .found(cli, []) },
                              makeRunner: { _, _ in made += 1; return FakeCLIRunner() })
            s.windowOpened()
            s.retry()
            s.windowClosed()
            s.stopAll()
            guard case .noCLI(let reason, let c) = s.state else { Issue.record("\(p): \(s.state)"); continue }
            #expect(reason == p.description && c.isEmpty, "\(p): \(reason)")
            #expect(looked == 0 && made == 0, "\(p): looked \(looked), made \(made)")
        }
    }

    // A verified CLI is kept: "Look again" while ready neither looks again
    // nor swaps the runner under the open window (a CLI planted later at a
    // location searched first never replaces the one already checked).
    @Test func retryWhileReadyKeepsTheVerifiedCLI() {
        var looked = 0, made = 0
        let r = FakeCLIRunner()
        let s = UISession(requirement: .success(req), locate: { _ in looked += 1; return .found(cli, []) },
                          makeRunner: { _, _ in made += 1; return r })
        guard case .ready(let m1) = s.state else { Issue.record("\(s.state)"); return }
        s.windowOpened()
        s.retry()
        s.retry()
        guard case .ready(let m2) = s.state else { Issue.record("\(s.state)"); return }
        #expect(looked == 1 && made == 1 && m1 === m2)
        #expect(streams(r).count == 1, "retry restarted the stream")
    }

    // "Look again" with no window open (the app is about to show it) finds
    // the CLI but runs nothing until the window opens.
    @Test func retryWithTheWindowClosedRunsNothing() {
        let r = FakeCLIRunner()
        var installed = false
        let s = UISession(requirement: .success(req), locate: { _ in installed ? .found(cli, []) : .notFound([]) },
                          makeRunner: { _, _ in r })
        installed = true
        s.retry()
        guard case .ready = s.state else { Issue.record("\(s.state)"); return }
        #expect(r.calls.isEmpty, "ran \(r.calls) with no window open")
        s.windowOpened()
        #expect(streams(r) == [["--json", "status", "--follow"]])
    }

    // Closing and opening the window again starts the stream again, once,
    // reconnecting as before.
    @Test func reopeningStartsTheStreamAgain() {
        let r = FakeCLIRunner()
        let s = ready(r)
        guard case .ready(let m) = s.state else { Issue.record("\(s.state)"); return }
        s.windowOpened()
        s.windowClosed()
        #expect(m.approvals.reconnectAfter == nil)
        s.windowOpened()
        #expect(streams(r).count == 2 && m.approvals.reconnectAfter == NazarModels.reconnectAfter)
    }

    // The real stream ends only after stop(): the terminated child exits a
    // little later (status 143), after the window opened again and started
    // a new stream. That exit is the old stream's: the new one stays
    // connected, shows no error and is not restarted (without the guard the
    // reconnect restarts it, whose exit restarts the next one, for ever).
    @Test func aStoppedStreamsExitDoesNotTouchItsSuccessor() async {
        let r = FakeCLIRunner()
        r.exitOnStop = true
        let s = ready(r)
        guard case .ready(let m) = s.state else { Issue.record("\(s.state)"); return }
        s.windowOpened()
        s.windowClosed()
        s.windowOpened()
        m.approvals.reconnectAfter = 0.1 // shorter than the app's, same path
        try? await Task.sleep(nanoseconds: 500_000_000)
        #expect(m.approvals.connected && m.approvals.error == nil, "the old stream's exit reached the new stream: \(m.approvals.error ?? "")")
        #expect(streams(r).count == 2, "the new stream was restarted: \(streams(r))")
    }

    // A reconnect already scheduled when the window closes (the agent was
    // not running: exit 5) never starts a stream after the close.
    @Test func aPendingReconnectDoesNotOutliveTheWindow() async {
        let r = FakeCLIRunner()
        r.streamExit = 5
        let s = ready(r)
        guard case .ready(let m) = s.state else { Issue.record("\(s.state)"); return }
        s.windowOpened()
        // Shorter than the app's, same path; scaled with the load so the
        // test sees the stream end before the reconnect, and then waits
        // three times as long for a reconnect that must not come.
        let after = 0.2 * loadFactor()
        m.approvals.reconnectAfter = after
        #expect(await eventually { !m.approvals.connected }, "the stream never ended")
        s.windowClosed()
        try? await Task.sleep(nanoseconds: UInt64(3 * after * 1e9))
        #expect(streams(r).count == 1, "reconnected after the window closed: \(streams(r))")
        #expect(!m.approvals.connected)
    }

    // The runner the app wires (forThisApp → UISession.verifiedRunner) is
    // the checked one: a file at the CLI's path that is not the required
    // build is killed before its first instruction (touch never creates its
    // file, exit 126, through run() and stream()), and the required build
    // runs. With the unchecked runner (ProcessCLIRunner(cli:), tests only)
    // wired instead, touch runs and this fails.
    @Test func verifiedRunnerRunsOnlyTheRequiredCLI() async throws {
        let dir = try tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let genuine = try signedCopy(of: "/bin/echo", to: dir.appendingPathComponent("genuine/nazar"), identifier: "dev.nazar.cli")
        let req = try pinned(genuine)
        let other = try signedCopy(of: "/usr/bin/touch", to: dir.appendingPathComponent("other/nazar"), identifier: "dev.nazar.cli")
        let marker = dir.appendingPathComponent("ran")
        let runner = UISession.verifiedRunner(other, req)
        #expect((runner as? ProcessCLIRunner)?.requirement == req, "the app's runner carries the requirement")
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
        let ok = await UISession.verifiedRunner(genuine, req).run(["--json", "status"])
        #expect(ok.exitCode == 0 && String(decoding: ok.stdout, as: UTF8.self) == "--json status\n", "\(ok)")
    }

    // The window and the setup view name one way to get nazar.
    @Test func installHintIsTheCask() {
        #expect(UISession.installHint == "brew install --cask atas/tap/nazar")
        #expect(NazarModels.reconnectAfter == 5)
    }
}
