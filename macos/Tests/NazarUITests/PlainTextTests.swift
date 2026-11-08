import Testing
@testable import NazarUI

// Untrusted text (app names, command lines, chains, reasons) is shown as
// plain text only, one line, bounded.
@Suite struct PlainTextTests {
    @Test func controlFormatAndSeparatorsBecomeQuestionMarks() {
        #expect(PlainText.clean("ok → ssh") == "ok → ssh")
        #expect(PlainText.clean("a\nb\rc\u{1B}[2Jd") == "a?b?c?[2Jd")
        #expect(PlainText.clean("evil\u{202E}gpj.exe") == "evil?gpj.exe")       // bidi override
        #expect(PlainText.clean("zero\u{200B}width\u{2028}line\u{2029}") == "zero?width?line?")
        #expect(PlainText.clean("\u{E000}private") == "?private")
    }

    @Test func cutWithAnEllipsis() {
        #expect(PlainText.clean(String(repeating: "a", count: 10), max: 4) == "aaaa…")
        #expect(PlainText.clean("abc", max: 3) == "abc")
        #expect(PlainText.clean(String(repeating: "x", count: 1000)).count == PlainText.defaultMax + 1)
    }

    /// Markdown and links are not interpreted (Text(verbatim:) shows the
    /// characters); clean leaves them as they are.
    @Test func markdownIsJustText() {
        #expect(PlainText.clean("**Allow** [click](https://evil)") == "**Allow** [click](https://evil)")
    }

    /// Invisible and reordering scalars that can make one name read as
    /// another: tag characters (ASCII smuggling), bidi marks and isolates,
    /// the Arabic letter mark, soft hyphen, BOM; tab, DEL and C1 controls;
    /// an unassigned scalar.
    @Test func invisibleAndReorderingScalars() {
        for s in ["\u{E0041}", "\u{E007F}", "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}", "\u{202A}", "\u{202D}",
                  "\u{200E}", "\u{200F}", "\u{061C}", "\u{00AD}", "\u{FEFF}", "\u{2060}", "\t", "\u{7F}", "\u{85}",
                  "\u{9B}", "\u{0}", "\u{0378}", "\u{F8FF}", "\u{FFFFD}"] {
            let hex = s.unicodeScalars.map { String($0.value, radix: 16) }
            #expect(PlainText.clean("a" + s + "b") == "a?b", "U+\(hex)")
        }
        #expect(PlainText.clean("") == "")
    }

    /// Ordinary non-ASCII text is kept (names are not mangled).
    @Test func ordinaryUnicodeIsKept() {
        for s in ["café", "Müller", "日本語", "iTerm2 → bash → ssh", "🧿 nazar", "naïve – “quoted”"] {
            #expect(PlainText.clean(s) == s, "\(s)")
        }
    }

    /// The bound counts scalars, so a pile of combining marks (a "Zalgo"
    /// name that grows a row's height) is cut too.
    @Test func combiningMarksAreBounded() {
        let zalgo = "a" + String(repeating: "\u{0301}", count: 1000)
        #expect(PlainText.clean(zalgo, max: 10).unicodeScalars.count == 11)
        #expect(PlainText.clean(zalgo, max: 10).hasSuffix("…"))
    }
}
