import Foundation

/// Untrusted text for the window: app names, command lines, chains, folders
/// and reasons from the audit log, matcher values and paths from
/// config.yaml. The window shows it only as plain text (SwiftUI
/// `Text(verbatim:)`, never a LocalizedStringKey, so no Markdown or link is
/// ever interpreted) and only after clean: every control, format (bidi
/// overrides, zero-width), line or paragraph separator, private-use,
/// surrogate or unassigned scalar becomes "?", and the text is cut to max
/// characters with an ellipsis, so no value can add a line, reverse the
/// reading order or push the rest of a row off screen.
public enum PlainText {
    public static let defaultMax = 400

    public static func clean(_ s: String, max: Int = defaultMax) -> String {
        var out = String.UnicodeScalarView()
        var n = 0
        for u in s.unicodeScalars {
            if n == max {
                out.append("…")
                break
            }
            switch u.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .surrogate, .unassigned:
                out.append("?")
            default:
                out.append(u)
            }
            n += 1
        }
        return String(out)
    }
}
