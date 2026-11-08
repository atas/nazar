import Carbon

/// Secure Event Input while the dialog is up (spec 4.4): other processes
/// can't read keystrokes meanwhile.
public protocol SecureInput: AnyObject {
    func enable()
    func disable()
}

/// The real seam. Never called by a test; whether `ioreg` shows nazar's PID
/// while a dialog is up is checked by hand.
public final class CarbonSecureInput: SecureInput {
    public init() {}
    public func enable() { _ = EnableSecureEventInput() }
    public func disable() { _ = DisableSecureEventInput() }
}
