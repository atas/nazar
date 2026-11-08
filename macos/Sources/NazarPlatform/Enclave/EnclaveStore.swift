import CryptoKit
import Foundation

/// The key half of the Platform contract (core/platform: CreateKey, Sign,
/// KeyAgreement, DeleteKey).
///
/// - An unknown, empty, malformed or deleted handle is .notFound.
/// - A key works only for its purpose (.invalid otherwise).
/// - A user-presence key needs a live approval ref; with 0, an unknown or a
///   released ref the call is .authRequired and the Secure Enclave is never
///   asked (so nothing can prompt). An AuthNone key ignores the approval
///   argument and always runs with no approval context.
/// - DeleteKey: a CryptoKit Secure Enclave key has no persistent identity
///   to destroy (S5: the handle is the key). Deleting records the key's blob
///   as deleted for this process, whatever envelope it later arrives in;
///   the Go registry deletes the Vault item, the only place the handle lives.
public final class EnclaveStore: @unchecked Sendable {
    private let backend: EnclaveBackend
    private let approvals: ApprovalStore
    private let lock = NSLock()
    private var deleted = Set<Data>() // SHA-256 of deleted key blobs

    public init(backend: EnclaveBackend, approvals: ApprovalStore) {
        self.backend = backend
        self.approvals = approvals
    }

    /// access is platform.Access: 0 when unlocked, 1 after first unlock
    /// (the key works while the Mac is locked too).
    public func createKey(purpose: Int32, auth: Int32, access: Int32) throws -> (handle: Data, publicKey: Data) {
        guard purpose >= 0, purpose <= 255, let p = KeyPurpose(rawValue: UInt8(purpose)) else {
            throw PlatformError.invalid("purpose \(purpose)")
        }
        guard auth == 0 || auth == 1 else { throw PlatformError.invalid("auth policy \(auth)") }
        guard access == 0 || access == 1 else { throw PlatformError.invalid("access \(access)") }
        // A key that asks for the user on every use can't work while the
        // Mac is locked: never made to (platform.Access.Fits).
        guard !(auth == 1 && access == 1) else { throw PlatformError.invalid("user presence takes access 0") }
        let userPresence = auth == 1
        let (blob, pub) = try backend.create(purpose: p, userPresence: userPresence, whileLocked: access == 1)
        guard pub.count == 65, pub.first == 0x04 else { throw PlatformError.failed("public key is not an X9.63 point") }
        return (KeyHandle(purpose: p, userPresence: userPresence, blob: blob).encoded, pub)
    }

    public func sign(handle: Data, data: Data, approval: UInt64) throws -> Data {
        let h = try live(handle)
        guard h.purpose == .sign else { throw PlatformError.invalid("not a signing key") }
        let ctx = try context(for: h, approval: approval)
        return try backend.sign(blob: h.blob, message: data, context: ctx)
    }

    public func keyAgreement(handle: Data, peer: Data, approval: UInt64) throws -> Data {
        let h = try live(handle)
        guard h.purpose == .keyAgreement else { throw PlatformError.invalid("not a key-agreement key") }
        guard peer.count == 65, peer.first == 0x04,
              let pk = try? P256.KeyAgreement.PublicKey(x963Representation: peer) else {
            throw PlatformError.invalid("peer key is not an uncompressed P-256 point")
        }
        let ctx = try context(for: h, approval: approval)
        return try backend.agree(blob: h.blob, peer: pk, context: ctx)
    }

    /// Needs no approval: deleting a user-presence key never asks the chip.
    public func deleteKey(handle: Data) throws {
        let h = try live(handle)
        lock.lock()
        deleted.insert(Self.digest(h.blob))
        lock.unlock()
    }

    /// The parsed handle if it names a key this backend knows and that was
    /// not deleted; .notFound otherwise. Runs before any approval check, so
    /// a caller learns nothing about approvals from a key that does not exist.
    private func live(_ handle: Data) throws -> KeyHandle {
        guard let h = KeyHandle(decoding: handle) else { throw PlatformError.notFound }
        lock.lock()
        let gone = deleted.contains(Self.digest(h.blob))
        lock.unlock()
        guard !gone, backend.isKey(h.blob, purpose: h.purpose) else { throw PlatformError.notFound }
        return h
    }

    private func context(for h: KeyHandle, approval: UInt64) throws -> AuthContext? {
        guard h.userPresence else { return nil } // AuthNone ignores the approval argument
        guard let ctx = approvals.context(approval) else { throw PlatformError.authRequired }
        return ctx
    }

    static func digest(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }
}
