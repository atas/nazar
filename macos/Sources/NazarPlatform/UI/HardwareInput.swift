import CoreGraphics
import Foundation

/// The `dialog` gate's input filter (spec 4.4, spike S4). A click on Allow
/// counts only when both its mouse-down and its mouse-up events carry the
/// HID system state as their source and no posting process
/// (kCGEventSourceUnixProcessID == 0). Spike S4 found that a synthetic event
/// can carry sourceStateID 1 and that a poster may be able to zero the PID
/// field, so whether this can be faked stays unverified until a person
/// checks it on a real Mac (spec 10, manual test script).
/// If it can, a process with the Accessibility grant alone could click
/// Allow once it is armed; nothing claims "can't be faked" yet.
public enum HardwareInput {
    public static func isHardware(sourcePID: Int64, sourceStateID: Int64) -> Bool {
        sourcePID == 0 && sourceStateID == Int64(CGEventSourceStateID.hidSystemState.rawValue)
    }

    public static func isHardware(_ event: CGEvent) -> Bool {
        isHardware(sourcePID: event.getIntegerValueField(.eventSourceUnixProcessID),
                   sourceStateID: event.getIntegerValueField(.eventSourceStateID))
    }
}

/// One key press while the dialog is up. Only Escape means anything (it
/// denies, from any source: denying is always safe); every other key is
/// swallowed and ignored, so the key code is all the dialog needs.
public struct KeyPress: Equatable, Sendable {
    public var keyCode: UInt16
    public init(keyCode: UInt16) { self.keyCode = keyCode }
    public var isEscape: Bool { keyCode == Self.escapeKeyCode }
    public static let escapeKeyCode: UInt16 = 53
}

/// One click on Allow as the dialog sees it. `hardware` is true only when
/// both the mouse-down and the mouse-up passed HardwareInput.isHardware;
/// `downAt` is when the button went down, in seconds of system uptime
/// (NSEvent.timestamp, the same clock as ProcessInfo.systemUptime), or nil
/// when no mouse-down was recorded (performClick, an Accessibility press).
public struct Click: Equatable, Sendable {
    public var hardware: Bool
    public var downAt: TimeInterval?
    public init(hardware: Bool, downAt: TimeInterval?) {
        self.hardware = hardware
        self.downAt = downAt
    }
}
