import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// The key operations the EnclaveStore needs. SecureEnclaveBackend is the
/// real one; SoftwareEnclaveBackend backs tests and the seamed conformance
/// run, never Nazar.app.
public protocol EnclaveBackend: AnyObject {
    /// whileLocked: the key also works while the Mac is locked, once the
    /// user has logged in (platform.AccessAfterFirstUnlock).
    func create(purpose: KeyPurpose, userPresence: Bool, whileLocked: Bool) throws -> (blob: Data, publicKey: Data)
    /// True when blob is a key of this backend for purpose.
    func isKey(_ blob: Data, purpose: KeyPurpose) -> Bool
    /// DER ECDSA signature over SHA-256(message).
    func sign(blob: Data, message: Data, context: AuthContext?) throws -> Data
    /// The raw ECDH shared secret (the x coordinate, 32 bytes).
    func agree(blob: Data, peer: P256.KeyAgreement.PublicKey, context: AuthContext?) throws -> Data
}

/// CryptoKit Secure Enclave keys (spec 4.5).
public final class SecureEnclaveBackend: EnclaveBackend, @unchecked Sendable {
    public init() {}

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// The access control of a new key: private-key usage only, plus the
    /// chip's own user-presence requirement for login + scope: use keys
    /// (spec 4.5, S1). whileLocked: usable while the Mac is locked too,
    /// once the user has logged in since it started
    /// (AfterFirstUnlockThisDeviceOnly); otherwise only while it is
    /// unlocked (WhenUnlockedThisDeviceOnly, every key made before the
    /// choice existed). Creating it never prompts.
    static func accessControl(userPresence: Bool, whileLocked: Bool) throws -> SecAccessControl {
        var err: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = userPresence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
        let protection = whileLocked ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard let ac = SecAccessControlCreateWithFlags(nil, protection, flags, &err) else {
            throw PlatformError.failed("access control: \(String(describing: err?.takeRetainedValue()))")
        }
        return ac
    }

    public func create(purpose: KeyPurpose, userPresence: Bool, whileLocked: Bool) throws -> (blob: Data, publicKey: Data) {
        let ac = try Self.accessControl(userPresence: userPresence, whileLocked: whileLocked)
        do {
            switch purpose {
            case .sign:
                let k = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: ac)
                return (k.dataRepresentation, k.publicKey.x963Representation)
            case .keyAgreement:
                let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: false, accessControl: ac)
                return (k.dataRepresentation, k.publicKey.x963Representation)
            }
        } catch {
            // The chip makes no when-unlocked key while the Mac is locked
            // (-25308, as for using one).
            if Self.mapOperationError(error) == .locked { throw PlatformError.locked }
            throw PlatformError.failed("create key: \(error)")
        }
    }

    public func isKey(_ blob: Data, purpose: KeyPurpose) -> Bool {
        switch purpose {
        case .sign: return (try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)) != nil
        case .keyAgreement: return (try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob)) != nil
        }
    }

    /// The context for one operation: the approval's LAContext, or for a
    /// key without an approval a fresh one that may never show UI, so a
    /// key that unexpectedly needs the user fails instead of prompting.
    static func operationContext(_ ctx: AuthContext?) -> LAContext {
        if let la = ctx?.laContext { return la }
        let la = LAContext()
        la.interactionNotAllowed = true
        return la
    }

    public func sign(blob: Data, message: Data, context: AuthContext?) throws -> Data {
        let k: SecureEnclave.P256.Signing.PrivateKey
        do {
            k = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob,
                                                          authenticationContext: Self.operationContext(context))
        } catch {
            throw PlatformError.notFound
        }
        do {
            return try k.signature(for: message).derRepresentation
        } catch {
            throw Self.mapOperationError(error)
        }
    }

    public func agree(blob: Data, peer: P256.KeyAgreement.PublicKey, context: AuthContext?) throws -> Data {
        let k: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob,
                                                               authenticationContext: Self.operationContext(context))
        } catch {
            throw PlatformError.notFound
        }
        do {
            return try k.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
        } catch {
            throw Self.mapOperationError(error)
        }
    }

    /// A LocalAuthentication error during a key operation means the
    /// approval is not (or no longer) usable: ErrAuthRequired.
    /// errSecInteractionNotAllowed (-25308) means the chip refused a
    /// when-unlocked key because the Mac is locked: ErrLocked. Observed on
    /// the chip (CryptoKit, macOS 27): an NSOSStatusErrorDomain error with
    /// that code (userInfo AKSError 0xe00002e2) for signing and key
    /// agreement alike, while an after-first-unlock key keeps working.
    static func mapOperationError(_ error: Error) -> PlatformError {
        let ns = error as NSError
        let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError
        if ns.domain == LAErrorDomain || underlying?.domain == LAErrorDomain { return .authRequired }
        for e in [ns, underlying].compactMap({ $0 }) where e.domain == NSOSStatusErrorDomain && e.code == Int(errSecInteractionNotAllowed) {
            return .locked
        }
        return .failed("key operation: \(error)")
    }
}

/// Software P-256 keys (tests, seamed conformance). The blob is the raw
/// private scalar plus one byte recording the purpose.
public final class SoftwareEnclaveBackend: EnclaveBackend, @unchecked Sendable {
    private let lock = NSLock()
    private var _signCalls = 0
    private var _agreeCalls = 0
    private var _contexts: [AuthContext?] = []
    private var _locked = false
    private var _unlockedOnly = Set<Data>()

    public init() {}

    public var signCalls: Int {
        lock.lock()
        defer { lock.unlock() }
        return _signCalls
    }

    public var agreeCalls: Int {
        lock.lock()
        defer { lock.unlock() }
        return _agreeCalls
    }

    /// The contexts passed to sign/agree, in order (tests).
    public var contexts: [AuthContext?] {
        lock.lock()
        defer { lock.unlock() }
        return _contexts
    }

    public func create(purpose: KeyPurpose, userPresence: Bool, whileLocked: Bool) throws -> (blob: Data, publicKey: Data) {
        // As on the chip: no when-unlocked key is made while locked.
        if !whileLocked && locked { throw PlatformError.locked }
        let blob: Data, pub: Data
        switch purpose {
        case .sign:
            let k = P256.Signing.PrivateKey()
            (blob, pub) = (k.rawRepresentation + [purpose.rawValue], k.publicKey.x963Representation)
        case .keyAgreement:
            let k = P256.KeyAgreement.PrivateKey()
            (blob, pub) = (k.rawRepresentation + [purpose.rawValue], k.publicKey.x963Representation)
        }
        lock.lock()
        if !whileLocked { _unlockedOnly.insert(blob) }
        lock.unlock()
        return (blob, pub)
    }

    /// Makes the software Mac locked or unlocked: while locked, a key
    /// without whileLocked can't be made or used (.locked), as on the chip.
    public var locked: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _locked }
        set { lock.lock(); _locked = newValue; lock.unlock() }
    }

    private func refuseWhileLocked(_ blob: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        if _locked && _unlockedOnly.contains(blob) { throw PlatformError.locked }
    }

    public func isKey(_ blob: Data, purpose: KeyPurpose) -> Bool {
        blob.count == 33 && blob.last == purpose.rawValue
            && (try? P256.Signing.PrivateKey(rawRepresentation: blob.prefix(32))) != nil
    }

    public func sign(blob: Data, message: Data, context: AuthContext?) throws -> Data {
        lock.lock()
        _signCalls += 1
        _contexts.append(context)
        lock.unlock()
        guard isKey(blob, purpose: .sign), let k = try? P256.Signing.PrivateKey(rawRepresentation: blob.prefix(32)) else {
            throw PlatformError.notFound
        }
        try refuseWhileLocked(blob)
        return try k.signature(for: message).derRepresentation
    }

    public func agree(blob: Data, peer: P256.KeyAgreement.PublicKey, context: AuthContext?) throws -> Data {
        lock.lock()
        _agreeCalls += 1
        _contexts.append(context)
        lock.unlock()
        guard isKey(blob, purpose: .keyAgreement),
              let k = try? P256.KeyAgreement.PrivateKey(rawRepresentation: blob.prefix(32)) else {
            throw PlatformError.notFound
        }
        try refuseWhileLocked(blob)
        return try k.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }
}
