import Foundation
import Security

/// A keychain file in a temporary folder, for tests and the smoke host
/// (never Nazar.app). It is never added to the user's search list and is
/// deleted (with its folder) by destroy() or deinit. SecKeychainSetSettings
/// is never called: changing keychain settings can block on a password
/// dialog (seen while building the vault). The keychain is never locked
/// either (an unlock prompt is a password dialog), and Keychain Services
/// dialogs are turned off for the process before it is created, so a test
/// process whose first Keychain call is this one can never show a dialog
/// (AGENTS.md, hard rules).
public final class TemporaryKeychain: @unchecked Sendable {
    public let dir: URL
    public let keychain: SecKeychain
    private let lock = NSLock()
    private var gone = false

    /// directory nil: a new folder under the temporary directory. A folder
    /// under any `Library/Keychains` path is refused (`.invalid`): securityd
    /// treats a keychain there like the login keychain (managed Integrity and
    /// PartitionID entries, partition checks), which is the machinery behind
    /// SecurityAgent dialogs, and automation never creates one (AGENTS.md, hard
    /// rules). The real placement is left to a check by hand.
    public init(directory: URL? = nil) throws {
        dir = directory ?? FileManager.default.temporaryDirectory.appendingPathComponent("nzkc-\(UUID().uuidString)")
        guard !Self.isUnderLibraryKeychains(dir) else {
            throw PlatformError.invalid("temporary keychain under a Library/Keychains folder: \(dir.path)")
        }
        // Dialogs off BEFORE the first Keychain call of this process (the
        // real switch, not the vault's seam: this is not a vault).
        let off = SecKeychainSetUserInteractionAllowed(false)
        guard off == errSecSuccess else { throw PlatformError.failed("SecKeychainSetUserInteractionAllowed: \(off)") }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let path = dir.appendingPathComponent("test.keychain-db").path
        let pw = UUID().uuidString
        var kc: SecKeychain?
        let st = pw.withCString { SecKeychainCreate(path, UInt32(strlen($0)), $0, false, nil, &kc) }
        guard st == errSecSuccess, let kc else {
            try? FileManager.default.removeItem(at: dir)
            throw PlatformError.failed("SecKeychainCreate \(st)")
        }
        keychain = kc
    }

    /// True when `dir` (as given, or with symlinks resolved along its longest
    /// existing prefix, `KeychainVault.realPath`) is a `Library/Keychains`
    /// folder or anything below one.
    static func isUnderLibraryKeychains(_ dir: URL) -> Bool {
        [dir.standardizedFileURL.path, KeychainVault.realPath(dir.path)].contains { path in
            let parts = URL(fileURLWithPath: path).pathComponents
            return parts.indices.dropLast().contains { parts[$0] == "Library" && parts[$0 + 1] == "Keychains" }
        }
    }

    /// Deletes the keychain file and its folder. Idempotent.
    public func destroy() {
        lock.lock()
        defer { lock.unlock() }
        guard !gone else { return }
        gone = true
        SecKeychainDelete(keychain)
        try? FileManager.default.removeItem(at: dir)
    }

    deinit { destroy() }
}
