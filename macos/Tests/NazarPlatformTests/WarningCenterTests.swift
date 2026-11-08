import AppKit
import Foundation
import Testing
@testable import NazarPlatform

// The block warning (spec 4.4; Platform.ShowWarning). Nothing here puts a
// window on screen, touches the real clipboard or opens a file: panels are
// built on the main actor and inspected, a RecordingPresenter stands in
// for ordering them front, and the clipboard and the opener are fakes. The
// real window in front of a full-screen app, the real clipboard and Finder
// opening the config are checked by hand.

final class FakePasteboard: RuleClipboard { var copied: [String] = []; func copy(_ s: String) { copied.append(s) } }
final class FakeOpener: URLOpener { var opened: [URL] = []; func open(_ u: URL) { opened.append(u) } }

/// A UI queue that never runs anything. It lives for the whole process: a
/// suspended dispatch queue that is released crashes the test runner, so it
/// must not depend on the WarningCenter holding on to it.
private let stuckUIQueue: DispatchQueue = {
    let q = DispatchQueue(label: "dev.nazar.test.warning.never-drained")
    q.suspend()
    return q
}()

@Suite @MainActor struct WarningCenterTests {
    func center(configPath: String = "/Users/u/.nazar/config/config.yaml")
        -> (WarningCenter, RecordingPresenter, FakePasteboard, FakeOpener) {
        _ = NSApplication.shared
        let pr = RecordingPresenter(), pb = FakePasteboard(), op = FakeOpener()
        return (WarningCenter(configPath: configPath, presenter: pr, pasteboard: pb, opener: op), pr, pb, op)
    }

    let blocked = WarningSpec(id: "python3|secret:GH", title: "Blocked: python3 tried to read secret \"GH\"",
                              lines: ["chain: Terminal → zsh → python3 sync.py      in ~/projects/foo"], count: 1,
                              suggestedRule: "- apps: [{path: /usr/bin/python3}]\n  gate: login")

    // MARK: core behaviour

    @Test func noAllowButtonAndTheButtonsDoOnlyWhatTheySay() throws {
        let (c, pr, pb, op) = center()
        c.showNow(blocked)
        let p = try #require(c.open.first?.panel)
        #expect(ViewText.buttons(p.panel.contentView!) == ["Copy suggested rule", "Open config", "Dismiss"])
        let text = ViewText.labels(p.panel.contentView!)
        #expect(text.contains("🧿 Blocked: python3 tried to read secret \"GH\"") && text.contains(blocked.lines[0]))
        #expect(pr.presented.count == 1 && p.panel.level == .floating)
        p.copyPressed()
        #expect(pb.copied == [blocked.suggestedRule])
        p.openPressed()
        #expect(op.opened == [URL(fileURLWithPath: "/Users/u/.nazar/config/config.yaml")])
        p.dismissPressed()
        #expect(c.open.isEmpty && pr.dismissed.count == 1)
    }

    @Test func repeatsUpdateOneWindowWithACounter() throws {
        let (c, _, _, _) = center()
        c.showNow(blocked)
        var again = blocked
        again.count = 14
        c.showNow(again)
        #expect(c.open.count == 1)
        let text = ViewText.labels(try #require(c.open.first?.panel.panel.contentView))
        #expect(text.contains("blocked 14 times"))
        var other = blocked
        other.id = "other"
        c.showNow(other)
        #expect(c.open.count == 2)
    }

    @Test func boundedWindowsAndLines() {
        let (c, pr, _, _) = center()
        for i in 0..<(WarningCenter.maxWindows + 3) {
            c.showNow(WarningSpec(id: "w\(i)", title: "t", lines: Array(repeating: String(repeating: "x", count: 900), count: 50)))
        }
        #expect(c.open.count == WarningCenter.maxWindows && pr.dismissed.count == 3 && c.open.first?.id == "w3")
        let b = WarningCenter.bounded(WarningSpec(id: "x", title: "t", lines: Array(repeating: String(repeating: "y", count: 900), count: 50)))
        #expect(b.lines.count == 20 && b.lines.allSatisfy { $0.count == 500 })
    }

    @Test func emptySuggestionDisablesCopy() throws {
        let (c, _, pb, _) = center()
        c.showNow(WarningSpec(id: "n", title: "t"))
        let p = try #require(c.open.first?.panel)
        #expect(!p.copyButton.isEnabled)
        p.copyPressed()
        #expect(pb.copied.isEmpty)
    }

    @Test func showReturnsAtOnce() {
        _ = NSApplication.shared
        let c = WarningCenter(configPath: "/x", presenter: RecordingPresenter(), pasteboard: FakePasteboard(),
                              opener: FakeOpener(), uiQueue: stuckUIQueue)
        let start = Date()
        c.show(blocked) // the UI queue is stuck; show must not wait for it
        #expect(Date().timeIntervalSince(start) < 0.5)
        #expect(c.open.isEmpty)
    }

    // MARK: nothing in the window allows (spec 4.4)

    /// No control in the window can approve anything, whatever the caller
    /// chose to put in the text: a title, line or suggested rule that reads
    /// like a button never becomes one.
    @Test func noControlCanAllowWhateverTheTextSays() throws {
        let (c, _, _, _) = center()
        c.showNow(WarningSpec(id: "evil", title: "Allow", lines: ["[ Allow ]", "Approve", "OK"], count: 3,
                              suggestedRule: "[ Allow once ]"))
        let p = try #require(c.open.first?.panel)
        let content = try #require(p.panel.contentView)
        let titles = ViewText.buttons(content)
        #expect(titles == ["Copy suggested rule", "Open config", "Dismiss"])
        for t in titles {
            let l = t.lowercased()
            #expect(!l.contains("allow") && !l.contains("approve") && !l.contains("ok") && !l.contains("yes"), "button \(t)")
        }
        // The only controls are those three buttons: no text field is
        // editable, so caller text never becomes an input.
        for f in textFields(content) { #expect(!f.isEditable, "editable field \(f.stringValue)") }
    }

    /// The window never blocks other work: it is a floating panel, not a
    /// modal session or a sheet, and it stays up when nazar is not active.
    @Test func theWindowIsNotModalAndStaysVisible() throws {
        let (c, _, _, _) = center()
        c.showNow(blocked)
        let p = try #require(c.open.first?.panel)
        #expect(NSApp.modalWindow == nil)
        #expect(p.panel.sheetParent == nil && !p.panel.isSheet)
        #expect(!p.panel.styleMask.contains(.docModalWindow))
        #expect(p.panel.level == .floating)
        #expect(!p.panel.hidesOnDeactivate)
        #expect(!p.panel.isReleasedWhenClosed) // closing it from the title bar must not free what the center holds
        // S2: it must reach the user on another Space and over a full-screen app.
        #expect(p.panel.collectionBehavior.contains(.canJoinAllSpaces))
        #expect(p.panel.collectionBehavior.contains(.fullScreenAuxiliary))
    }

    /// The buttons on screen are wired to their own handlers: pressing each
    /// one through AppKit's target/action does exactly its own job (a
    /// "Dismiss" wired to Open config, or Open config wired to copy, would
    /// pass the direct-call tests above).
    @Test func eachButtonOnScreenDoesItsOwnJob() throws {
        let (c, pr, pb, op) = center()
        c.showNow(blocked)
        let p = try #require(c.open.first?.panel)
        let bs = buttons(try #require(p.panel.contentView))
        func press(_ title: String) throws {
            let b = try #require(bs.first { $0.title == title }, "no button \(title)")
            let action = try #require(b.action, "button \(title) has no action")
            #expect(NSApp.sendAction(action, to: b.target, from: b), "button \(title) did nothing")
        }
        try press("Copy suggested rule")
        #expect(pb.copied == [blocked.suggestedRule] && op.opened.isEmpty && c.open.count == 1)
        try press("Open config")
        #expect(op.opened == [URL(fileURLWithPath: "/Users/u/.nazar/config/config.yaml")])
        #expect(pb.copied.count == 1 && c.open.count == 1)
        try press("Dismiss")
        #expect(c.open.isEmpty && pr.dismissed.count == 1 && pr.dismissed.first === p.panel)
        #expect(pb.copied.count == 1 && op.opened.count == 1)
    }

    // MARK: the counter and updates

    @Test func aSingleAttemptShowsNoCounter() throws {
        let (c, _, _, _) = center()
        c.showNow(blocked)
        let text = ViewText.labels(try #require(c.open.first?.panel.panel.contentView))
        #expect(!text.contains { $0.contains("blocked 1 time") })
        var two = blocked
        two.count = 2
        c.showNow(two)
        #expect(ViewText.labels(try #require(c.open.first?.panel.panel.contentView)).contains("blocked 2 times"))
    }

    /// An update rewrites the same window: the same panel object, re-shown,
    /// never dismissed; its lines are replaced (none left over from before),
    /// and Copy uses the latest suggested rule (or turns off without one).
    @Test func anUpdateReplacesTheWindowsContentInPlace() throws {
        let (c, pr, pb, _) = center()
        c.showNow(WarningSpec(id: "a", title: "first", lines: ["old 1", "old 2", "old 3"], count: 1, suggestedRule: "rule A"))
        let first = try #require(c.open.first?.panel)
        c.showNow(WarningSpec(id: "a", title: "second", lines: ["new 1"], count: 5, suggestedRule: "rule B"))
        let p = try #require(c.open.first?.panel)
        #expect(p === first && c.open.count == 1)
        #expect(pr.dismissed.isEmpty)
        #expect(pr.presented.count == 2 && pr.presented.allSatisfy { $0 === p.panel })
        let text = ViewText.labels(try #require(p.panel.contentView))
        #expect(text.contains("🧿 second") && !text.contains("🧿 first"))
        #expect(text.contains("new 1") && !text.contains("old 1") && !text.contains("old 2") && !text.contains("old 3"))
        #expect(text.contains("blocked 5 times"))
        p.copyPressed()
        #expect(pb.copied == ["rule B"])
        c.showNow(WarningSpec(id: "a", title: "third", lines: [], count: 6))
        #expect(!p.copyButton.isEnabled)
        p.copyPressed()
        #expect(pb.copied == ["rule B"])
        // And back: a later suggestion turns Copy on again.
        c.showNow(WarningSpec(id: "a", title: "fourth", count: 7, suggestedRule: "rule C"))
        #expect(p.copyButton.isEnabled)
        p.copyPressed()
        #expect(pb.copied == ["rule B", "rule C"])
    }

    /// Many repeats of one caller never stack windows or close others.
    @Test func aFloodOfOneCallerKeepsOneWindow() {
        let (c, pr, _, _) = center()
        c.showNow(WarningSpec(id: "bystander", title: "t"))
        for n in 1...200 { c.showNow(WarningSpec(id: "flood", title: "t", count: n)) }
        #expect(c.open.map(\.id) == ["bystander", "flood"])
        #expect(pr.dismissed.isEmpty)
    }

    // MARK: dismissing and the window limit

    @Test func dismissClosesOnlyItsOwnWindowOnce() throws {
        let (c, pr, _, _) = center()
        for id in ["a", "b", "c"] { c.showNow(WarningSpec(id: id, title: id)) }
        let b = try #require(c.open.first { $0.id == "b" }?.panel)
        b.dismissPressed()
        b.dismissPressed() // a second press (or a stale panel) changes nothing
        #expect(c.open.map(\.id) == ["a", "c"])
        #expect(pr.dismissed.count == 1 && pr.dismissed.first === b.panel)
        // The same caller again after Dismiss gets a fresh window.
        c.showNow(WarningSpec(id: "b", title: "b again"))
        #expect(c.open.map(\.id) == ["a", "c", "b"])
        #expect(c.open.last?.panel !== b)
    }

    /// The Dismiss of a panel that is already gone closes nothing: not the
    /// window of another ID that opened since.
    @Test func aStalePanelNeverClosesAnotherIDsWindow() throws {
        let (c, _, _, _) = center()
        c.showNow(WarningSpec(id: "a", title: "a"))
        let a = try #require(c.open.first?.panel)
        a.dismissPressed()
        c.showNow(WarningSpec(id: "z", title: "z"))
        a.dismissPressed()
        #expect(c.open.map(\.id) == ["z"])
    }

    @Test func repeatsAtTheLimitUpdateWithoutClosingAnything() {
        let (c, pr, _, _) = center()
        for i in 0..<WarningCenter.maxWindows { c.showNow(WarningSpec(id: "w\(i)", title: "t")) }
        c.showNow(WarningSpec(id: "w0", title: "t", count: 2))
        c.showNow(WarningSpec(id: "w\(WarningCenter.maxWindows - 1)", title: "t", count: 9))
        #expect(c.open.count == WarningCenter.maxWindows && pr.dismissed.isEmpty)
    }

    @Test func theOldestWindowsAreClosedFirstInOrder() {
        let (c, pr, _, _) = center()
        #expect(WarningCenter.maxWindows == 8)
        var panels: [String: NSWindow] = [:]
        for i in 0..<(WarningCenter.maxWindows + 3) {
            c.showNow(WarningSpec(id: "w\(i)", title: "t"))
            if let last = c.open.last { panels[last.id] = last.panel.panel }
        }
        #expect(pr.dismissed.count == 3)
        for (i, w) in pr.dismissed.enumerated() { #expect(w === panels["w\(i)"], "evicted #\(i)") }
        #expect(c.open.map(\.id) == (3..<(WarningCenter.maxWindows + 3)).map { "w\($0)" })
    }

    // MARK: bounded text

    @Test func boundedKeepsShortTextAndCutsAtTheEdges() {
        let ok = String(repeating: "a", count: 500)
        let long = String(repeating: "b", count: 501)
        let b = WarningCenter.bounded(WarningSpec(id: "i", title: "T", lines: [ok, long, ""], count: 3, suggestedRule: "R"))
        #expect(b.lines.count == 3)
        #expect(b.lines[0] == ok)
        #expect(b.lines[1].count == 500 && b.lines[1].hasSuffix("…") && b.lines[1].hasPrefix(String(repeating: "b", count: 499)))
        #expect(b.lines[2] == "")
        #expect(b.id == "i" && b.title == "T" && b.count == 3 && b.suggestedRule == "R")

        let twenty = (0..<20).map { "line \($0)" }
        #expect(WarningCenter.bounded(WarningSpec(id: "i", title: "t", lines: twenty)).lines == twenty)
        let more = (0..<21).map { "line \($0)" }
        #expect(WarningCenter.bounded(WarningSpec(id: "i", title: "t", lines: more)).lines == twenty)
        #expect(WarningCenter.bounded(WarningSpec(id: "i", title: "t")).lines.isEmpty)
    }

    /// Lines are cut by characters a person sees, never inside one: a line of
    /// emoji or combining marks stays valid text of the same bound.
    @Test func boundedNeverSplitsACharacter() {
        let eyes = String(repeating: "🧿", count: 900)
        let flags = String(repeating: "🇹🇷", count: 900)
        let combining = String(repeating: "e\u{301}", count: 900)
        let b = WarningCenter.bounded(WarningSpec(id: "i", title: "t", lines: [eyes, flags, combining]))
        for l in b.lines {
            #expect(l.count == 500 && l.hasSuffix("…"))
            #expect(l.dropLast().allSatisfy { $0 == "🧿" || $0 == "🇹🇷" || $0 == "e\u{301}" })
        }
    }

    /// The window shows the bounded text, not the raw document.
    @Test func theWindowShowsAtMostTheBoundedLines() throws {
        let (c, _, _, _) = center()
        let huge = String(repeating: "x", count: 100_000)
        c.showNow(WarningSpec(id: "big", title: "t", lines: Array(repeating: huge, count: 1_000)))
        let text = ViewText.labels(try #require(c.open.first?.panel.panel.contentView))
        let lines = text.filter { $0.hasPrefix("x") }
        #expect(lines.count == 20)
        #expect(lines.allSatisfy { $0.count == 500 })
    }

    // MARK: Open config

    @Test func openConfigOpensTheConfigFileAndNothingElse() throws {
        let path = "/Users/u w/.nazar ü/config/config.yaml"
        let (c, _, _, op) = center(configPath: path)
        // A caller-supplied rule or line that looks like a URL is never opened.
        c.showNow(WarningSpec(id: "u", title: "t", lines: ["https://evil.example/"], suggestedRule: "file:///etc/passwd"))
        let p = try #require(c.open.first?.panel)
        p.openPressed()
        p.openPressed()
        #expect(op.opened.count == 2)
        for u in op.opened {
            #expect(u.isFileURL && u.path == path)
            #expect(u == URL(fileURLWithPath: path))
        }
    }

    // MARK: show() goes through the UI queue

    /// show() only schedules: on the main queue the window appears after the
    /// current main-actor work yields, never inside show().
    @Test func showDeliversOnTheUIQueue() async throws {
        let (c, pr, _, _) = center()
        c.show(blocked)
        #expect(c.open.isEmpty && pr.presented.isEmpty)
        let deadline = Date().addingTimeInterval(5)
        while c.open.isEmpty && Date() < deadline { try await Task.sleep(for: .milliseconds(10)) }
        #expect(c.open.map(\.id) == [blocked.id] && pr.presented.count == 1)
    }

    /// The production types exist and fit the seams (never called here: they
    /// would touch the real clipboard and open a real file).
    @Test func productionSeamsExist() {
        let pb: RuleClipboard.Type = SystemPasteboard.self
        let op: URLOpener.Type = WorkspaceOpener.self
        #expect(pb == SystemPasteboard.self && op == WorkspaceOpener.self)
    }

    // MARK: helpers

    func textFields(_ v: NSView) -> [NSTextField] {
        var out: [NSTextField] = []
        if let t = v as? NSTextField { out.append(t) }
        for s in v.subviews { out += textFields(s) }
        return out
    }

    func buttons(_ v: NSView) -> [NSButton] {
        var out: [NSButton] = []
        if let b = v as? NSButton { out.append(b) }
        for s in v.subviews { out += buttons(s) }
        return out
    }
}

/// The command line is shown as code: a box around a monospaced label, and
/// a line number outside the lines marks nothing.
@MainActor struct CodeBoxTests {
    @Test func commandLineIsABoxedMonospacedLabel() throws {
        let rows = CodeBox.rows(["login to github.com as git", "git push -q    in ~/projects/nazar", "Scope: this request only"], commandLine: 2)
        #expect(rows.count == 3)
        #expect(!(rows[0] is NSBox) && !(rows[2] is NSBox))
        let box = try #require(rows[1] as? NSBox)
        let label = try #require(box.contentView as? NSTextField)
        #expect(label.stringValue == "git push -q    in ~/projects/nazar")
        #expect(label.font?.fontDescriptor.symbolicTraits.contains(.monoSpace) == true)
        for n in [0, 4, -1] {
            #expect(!CodeBox.rows(["a", "b", "c"], commandLine: n).contains { $0 is NSBox })
        }
    }
}
