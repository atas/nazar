import Dispatch
import Foundation

/// Platform.OnScreenLock (spec 4.3): every registered function runs on each
/// screen lock, each on a background queue so a slow one holds up neither
/// the others nor the next lock. The notification name is injectable so
/// tests never post the system's real "com.apple.screenIsLocked" (other
/// apps listen to it); production uses the default.
public final class ScreenLockWatcher: @unchecked Sendable {
    public static let systemName = "com.apple.screenIsLocked"

    private let lock = NSLock()
    private var handlers: [@Sendable () -> Void] = []
    private var observer: NSObjectProtocol?

    public init(name: String = ScreenLockWatcher.systemName) {
        observer = DistributedNotificationCenter.default().addObserver(
            forName: Notification.Name(name), object: nil, queue: nil) { [weak self] _ in self?.locked() }
    }

    deinit {
        if let observer { DistributedNotificationCenter.default().removeObserver(observer) }
    }

    /// Registers fn for every later lock (no replay); returns at once, also
    /// from inside a handler.
    public func register(_ fn: @escaping @Sendable () -> Void) {
        lock.lock()
        handlers.append(fn)
        lock.unlock()
    }

    private func locked() {
        lock.lock()
        let hs = handlers
        lock.unlock()
        for h in hs { DispatchQueue.global().async(execute: h) }
    }
}
