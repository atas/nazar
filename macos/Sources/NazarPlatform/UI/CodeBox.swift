import AppKit

/// What the user ran, shown as code: monospaced, selectable, in a box with
/// a thin border and its own background, so it reads as a command and not
/// as one of nazar's sentences. The text is the core's cleaned line, shown
/// verbatim.
enum CodeBox {
    static func make(_ text: String) -> NSView {
        let label = NSTextField(wrappingLabelWithString: text)
        label.font = .monospacedSystemFont(ofSize: NSFont.smallSystemFontSize + 1, weight: .regular)
        label.isSelectable = true
        let box = NSBox()
        box.boxType = .custom
        box.borderColor = .separatorColor
        box.borderWidth = 1
        box.cornerRadius = 5
        box.fillColor = .quaternarySystemFill
        box.titlePosition = .noTitle
        box.contentViewMargins = NSSize(width: 8, height: 5)
        box.contentView = label
        box.setAccessibilityLabel("command")
        return box
    }

    /// The rows for lines, with the 1-based commandLine as a code box (0, or
    /// a number outside lines, marks none).
    static func rows(_ lines: [String], commandLine: Int) -> [NSView] {
        lines.enumerated().map { i, l in
            i + 1 == commandLine ? make(l) : NSTextField(wrappingLabelWithString: l)
        }
    }
}
