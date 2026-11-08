import CNazarBridge

/// The errors of the Go platform contract (core/platform/platform.go), as
/// the status codes of nazar_bridge.h.
public enum PlatformError: Error, Equatable {
    case notFound
    case noProcess
    case denied
    case authRequired
    case ambiguous
    /// platform.ErrUnreadable: the kernel hides it, or it could
    /// not be read.
    case unreadable
    /// platform.ErrLocked: a when-unlocked key, used while the Mac is locked.
    case locked
    case invalid(String)
    case failed(String)

    /// The NZ_* status code for this error.
    public var code: Int32 {
        switch self {
        case .notFound: return Int32(NZ_NOT_FOUND)
        case .noProcess: return Int32(NZ_NO_PROCESS)
        case .denied: return Int32(NZ_DENIED)
        case .authRequired: return Int32(NZ_AUTH_REQUIRED)
        case .ambiguous: return Int32(NZ_AMBIGUOUS)
        case .unreadable: return Int32(NZ_UNREADABLE)
        case .locked: return Int32(NZ_LOCKED)
        case .invalid: return Int32(NZ_INVALID)
        case .failed: return Int32(NZ_ERR)
        }
    }
}
