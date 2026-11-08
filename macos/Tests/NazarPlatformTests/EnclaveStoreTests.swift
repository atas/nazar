import CoreGraphics
import CryptoKit
import Foundation
import IOKit
import LocalAuthentication
import Testing
@testable import NazarPlatform

/// A context that only records whether it was invalidated.
final class FakeAuthContext: AuthContext, @unchecked Sendable {
    var invalidated = false
    var laContext: LAContext? { nil }
    func invalidate() { invalidated = true }
}

@Suite struct KeyHandleTests {
    @Test func roundTrip() {
        let h = KeyHandle(purpose: .keyAgreement, userPresence: true, blob: Data([1, 2, 3]))
        #expect(h.encoded == Data("NZK1".utf8) + Data([2, 1, 1, 2, 3]))
        #expect(KeyHandle(decoding: h.encoded) == h)
        #expect(KeyHandle(decoding: h.encoded.dropFirst(0)) == h) // a slice with a non-zero start index
    }

    static let malformed: [Data] = {
        let m = Data("NZK1".utf8)
        var out: [Data] = [Data(), Data([1, 2, 3]), m]
        out.append(m + Data([1, 0]))                  // no blob
        out.append(Data("NZK2".utf8) + Data([1, 0, 9])) // wrong magic
        out.append(m + Data([0, 0, 9]))               // purpose 0
        out.append(m + Data([3, 0, 9]))               // purpose 3
        out.append(m + Data([1, 2, 9]))               // presence byte 2
        out.append(m + Data([1, 0]) + Data(repeating: 7, count: 4097)) // blob too long
        return out
    }()

    @Test(arguments: malformed)
    func malformedHandlesAreRejected(_ d: Data) {
        #expect(KeyHandle(decoding: d) == nil)
    }
}

@Suite struct EnclaveStoreTests {
    func store() -> (EnclaveStore, SoftwareEnclaveBackend, ApprovalStore) {
        let b = SoftwareEnclaveBackend(), a = ApprovalStore()
        return (EnclaveStore(backend: b, approvals: a), b, a)
    }

    @Test func signVerifiesAndIgnoresApprovalOnAuthNoneKey() throws {
        let (s, _, _) = store()
        let (h, pub) = try s.createKey(purpose: 1, auth: 0, access: 0)
        let pk = try P256.Signing.PublicKey(x963Representation: pub)
        for ref: UInt64 in [0, 0x5eed1234abcd] {
            let der = try s.sign(handle: h, data: Data("msg".utf8), approval: ref)
            #expect(pk.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: der), for: Data("msg".utf8)))
        }
    }

    @Test func unknownHandlesAreNotFound() throws {
        let (s, _, _) = store()
        let peer = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        for h in [Data(), Data([1, 2, 3]), Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
                  KeyHandle(purpose: .sign, userPresence: false, blob: Data(repeating: 0, count: 33)).encoded] {
            #expect(throws: PlatformError.notFound) { try s.sign(handle: h, data: Data("x".utf8), approval: 0) }
            #expect(throws: PlatformError.notFound) { try s.keyAgreement(handle: h, peer: peer, approval: 0) }
            #expect(throws: PlatformError.notFound) { try s.deleteKey(handle: h) }
        }
    }

    @Test func deleteIsFinal() throws {
        let (s, _, _) = store()
        let (h, _) = try s.createKey(purpose: 1, auth: 0, access: 0)
        try s.deleteKey(handle: h)
        #expect(throws: PlatformError.notFound) { try s.sign(handle: h, data: Data("x".utf8), approval: 0) }
        #expect(throws: PlatformError.notFound) { try s.deleteKey(handle: h) }
    }

    @Test func purposeIsEnforced() throws {
        let (s, _, _) = store()
        let (sh, _) = try s.createKey(purpose: 1, auth: 0, access: 0)
        let (kh, _) = try s.createKey(purpose: 2, auth: 0, access: 0)
        let peer = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        #expect(throws: PlatformError.invalid("not a key-agreement key")) { try s.keyAgreement(handle: sh, peer: peer, approval: 0) }
        #expect(throws: PlatformError.invalid("not a signing key")) { try s.sign(handle: kh, data: Data("x".utf8), approval: 0) }
    }

    @Test func outOfRangeCreateIsRefusedBeforeTheBackend() {
        let (s, _, _) = store()
        for (p, a) in [(0, 0), (3, 0), (-1, 0), (Int32.max, 0), (1, 2), (1, -1), (1, Int32.max)] as [(Int32, Int32)] {
            #expect(throws: PlatformError.self) { try s.createKey(purpose: p, auth: a, access: 0) }
        }
    }

    @Test func keyAgreementMatchesSoftwareECDH() throws {
        let (s, _, _) = store()
        let (h, pub) = try s.createKey(purpose: 2, auth: 0, access: 0)
        let local = P256.KeyAgreement.PrivateKey()
        let got = try s.keyAgreement(handle: h, peer: local.publicKey.x963Representation, approval: 0)
        let want = try local.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: pub))
            .withUnsafeBytes { Data($0) }
        #expect(got == want && got.count == 32)
        let x963 = local.publicKey.x963Representation
        var notOnCurve = Data(repeating: 0, count: 65); notOnCurve[0] = 4
        for bad in [Data(), Data([4]), x963.prefix(40), notOnCurve, Data([2]) + x963.subdata(in: 1..<33)] {
            #expect(throws: PlatformError.self) { try s.keyAgreement(handle: h, peer: bad, approval: 0) }
        }
    }

    // A user-presence key never reaches the backend without a live ref, so
    // the Secure Enclave can never be asked to prompt for a stale approval.
    @Test func userPresenceNeedsALiveRefAndNeverTouchesTheBackendWithout() throws {
        let (s, b, a) = store()
        let (h, _) = try s.createKey(purpose: 1, auth: 1, access: 0)
        let (kh, _) = try s.createKey(purpose: 2, auth: 1, access: 0)
        let peer = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        for ref: UInt64 in [0, 0x1234567, .max] {
            #expect(throws: PlatformError.authRequired) { try s.sign(handle: h, data: Data("x".utf8), approval: ref) }
            #expect(throws: PlatformError.authRequired) { try s.keyAgreement(handle: kh, peer: peer, approval: ref) }
        }
        #expect(b.signCalls == 0 && b.agreeCalls == 0)
        let ctx = FakeAuthContext()
        let ref = try #require(a.issue(ctx))
        _ = try s.sign(handle: h, data: Data("x".utf8), approval: ref)
        #expect(b.signCalls == 1 && b.contexts.last! === ctx)
        a.release(ref)
        #expect(ctx.invalidated)
        #expect(throws: PlatformError.authRequired) { try s.sign(handle: h, data: Data("x".utf8), approval: ref) }
        #expect(b.signCalls == 1)
    }
}

@Suite struct ApprovalStoreTests {
    @Test func refsAreNeverReusedAndReleaseIsIdempotent() throws {
        let a = ApprovalStore()
        var seen = Set<UInt64>()
        for _ in 0..<100 {
            let r = try #require(a.issue(FakeAuthContext()))
            #expect(r != 0 && !seen.contains(r))
            seen.insert(r)
            a.release(r)
            a.release(r)
        }
        let keep = try #require(a.issue(FakeAuthContext()))
        for r in [0, keep + 1, keep &- 1, keep ^ 1, .max] as [UInt64] where r != keep { a.release(r) }
        #expect(a.context(keep) != nil && a.liveCount == 1)
    }

    @Test func exhaustionFailsClosed() {
        let a = ApprovalStore()
        a.setNextForTesting(.max)
        #expect(a.issue(FakeAuthContext()) == nil)
    }
}

/// Whether the Mac's screen is locked, read passively (no prompt, no
/// keychain access): the login session's CGSSessionScreenIsLocked, or the
/// IORegistry root's IOConsoleLocked when there is no GUI session (ssh).
/// Secure Enclave keys are kSecAttrAccessibleWhenUnlockedThisDeviceOnly, so
/// while locked the chip refuses to create them (errSecInteractionNotAllowed,
/// -25308): that is the environment, not a bug in the code under test.
enum ScreenLock {
    static var isLocked: Bool {
        if let d = CGSessionCopyCurrentDictionary() as? [String: Any],
           (d["CGSSessionScreenIsLocked"] as? Bool) == true { return true }
        let root = IORegistryGetRootEntry(kIOMainPortDefault)
        guard root != 0 else { return false }
        defer { IOObjectRelease(root) }
        let v = IORegistryEntryCreateCFProperty(root, "IOConsoleLocked" as CFString, kCFAllocatorDefault, 0)?
            .takeRetainedValue()
        return (v as? Bool) == true
    }
}

// The real Secure Enclave, AuthNone keys only: no test in this repository
// creates a user-presence key on the chip (it could prompt if misused).
@Suite(.enabled(if: SecureEnclaveBackend.isAvailable)) struct SecureEnclaveTests {
    @Test(.disabled(if: ScreenLock.isLocked,
                    "screen locked: Secure Enclave key creation refused; re-run unlocked"))
    func signAndAgreeWithoutUserPresence() throws {
        let s = EnclaveStore(backend: SecureEnclaveBackend(), approvals: ApprovalStore())
        let (h, pub) = try s.createKey(purpose: 1, auth: 0, access: 0)
        let der = try s.sign(handle: h, data: Data("enclave".utf8), approval: 0)
        let pk = try P256.Signing.PublicKey(x963Representation: pub)
        #expect(pk.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: der), for: Data("enclave".utf8)))
        let (kh, kpub) = try s.createKey(purpose: 2, auth: 0, access: 0)
        let local = P256.KeyAgreement.PrivateKey()
        let got = try s.keyAgreement(handle: kh, peer: local.publicKey.x963Representation, approval: 0)
        let want = try local.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: kpub))
            .withUnsafeBytes { Data($0) }
        #expect(got == want)
        // A key that works while the Mac is locked too: made and used the
        // same way (nothing here can lock the Mac).
        let (lh, lpub) = try s.createKey(purpose: 1, auth: 0, access: 1)
        let lder = try s.sign(handle: lh, data: Data("enclave".utf8), approval: 0)
        #expect(try P256.Signing.PublicKey(x963Representation: lpub)
            .isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: lder), for: Data("enclave".utf8)))
        let (lkh, _) = try s.createKey(purpose: 2, auth: 0, access: 1)
        #expect(try s.keyAgreement(handle: lkh, peer: local.publicKey.x963Representation, approval: 0).count == 32)
        #expect(throws: PlatformError.invalid("access 2")) { try s.createKey(purpose: 1, auth: 0, access: 2) }
        // (A relabelled handle is not tested: the Secure Enclave signs with a key-agreement blob
        // (CryptoKit does not record the purpose), so the purpose byte guards only handles the
        // Vault returned unmodified. See KeyHandle.)
        try s.deleteKey(handle: h)
        try s.deleteKey(handle: kh)
        #expect(throws: PlatformError.notFound) { try s.sign(handle: h, data: Data("x".utf8), approval: 0) }
    }

    @Test func garbageBlobsAreNotFound() {
        let s = EnclaveStore(backend: SecureEnclaveBackend(), approvals: ApprovalStore())
        let fake = KeyHandle(purpose: .sign, userPresence: false, blob: Data((0..<324).map { _ in UInt8.random(in: 0...255) }))
        #expect(throws: PlatformError.notFound) { try s.sign(handle: fake.encoded, data: Data("x".utf8), approval: 0) }
        #expect(throws: PlatformError.notFound) { try s.deleteKey(handle: fake.encoded) }
    }
}

// MARK: - Edge and attack cases (test author)

/// A backend that answers create with a public key that is not an X9.63
/// point, to check the store refuses to hand such a key to Go.
final class BadPublicKeyBackend: EnclaveBackend, @unchecked Sendable {
    let pub: Data
    init(pub: Data) { self.pub = pub }
    func create(purpose: KeyPurpose, userPresence: Bool, whileLocked: Bool) throws -> (blob: Data, publicKey: Data) { (Data([1]), pub) }
    func isKey(_ blob: Data, purpose: KeyPurpose) -> Bool { true }
    func sign(blob: Data, message: Data, context: AuthContext?) throws -> Data { Data() }
    func agree(blob: Data, peer: P256.KeyAgreement.PublicKey, context: AuthContext?) throws -> Data { Data() }
}

@Suite struct KeyHandleBoundaryTests {
    @Test func blobLengthBoundaries() {
        let m = KeyHandle.magic
        #expect(KeyHandle(decoding: m + Data([1, 0, 9]))?.blob == Data([9]))                         // 1-byte blob
        let max = KeyHandle(decoding: m + Data([2, 1]) + Data(repeating: 7, count: KeyHandle.maxBlob))
        #expect(max?.blob.count == 4096 && max?.purpose == .keyAgreement && max?.userPresence == true)
    }

    @Test func decodingASliceDoesNotReadOutsideIt() {
        // The bytes before the slice form a valid handle header; the slice itself does not.
        let whole = KeyHandle.magic + Data([1, 0]) + KeyHandle.magic + Data([1, 7, 9])
        #expect(KeyHandle(decoding: whole.dropFirst(6)) == nil)          // presence byte 7
        let ok = Data([0xff, 0xff]) + KeyHandle.magic + Data([1, 1, 5, 6])
        #expect(KeyHandle(decoding: ok.dropFirst(2)) == KeyHandle(purpose: .sign, userPresence: true, blob: Data([5, 6])))
    }
}

@Suite struct EnclaveStoreEdgeTests {
    func store() -> (EnclaveStore, SoftwareEnclaveBackend, ApprovalStore) {
        let b = SoftwareEnclaveBackend(), a = ApprovalStore()
        return (EnclaveStore(backend: b, approvals: a), b, a)
    }

    @Test func createdHandlesRecordPurposeAndPresence() throws {
        let (s, _, _) = store()
        for (p, a) in [(1, 0), (1, 1), (2, 0), (2, 1)] as [(Int32, Int32)] {
            let (h, pub) = try s.createKey(purpose: p, auth: a, access: 0)
            let k = try #require(KeyHandle(decoding: h))
            #expect(k.purpose.rawValue == UInt8(p) && k.userPresence == (a == 1))
            #expect(pub.count == 65 && pub.first == 0x04)
        }
    }

    @Test func outOfRangeCreateNeverReachesTheBackend() {
        // A backend whose create would succeed with a bad public key: if the
        // store reached it, the error would be .failed, never .invalid.
        let s = EnclaveStore(backend: BadPublicKeyBackend(pub: Data([4])), approvals: ApprovalStore())
        for (p, a) in [(0, 0), (3, 0), (256, 0), (257, 0), (-1, 0), (1, 2), (1, -1)] as [(Int32, Int32)] {
            let e = #expect(throws: PlatformError.self) { try s.createKey(purpose: p, auth: a, access: 0) }
            if case .invalid = e {} else { Issue.record("purpose \(p) auth \(a): want .invalid, got \(String(describing: e))") }
        }
        // An unknown access never becomes "works while locked", and a
        // user-presence key is never made to work while locked.
        for (a, x) in [(0, 2), (0, -1), (0, Int32.max), (1, 1)] as [(Int32, Int32)] {
            let e = #expect(throws: PlatformError.self) { try s.createKey(purpose: 1, auth: a, access: x) }
            if case .invalid = e {} else { Issue.record("auth \(a) access \(x): want .invalid, got \(String(describing: e))") }
        }
    }

    /// The software backend refuses a when-unlocked key while "locked", as
    /// the chip does, and keeps the while-locked one working.
    @Test func softwareBackendRefusesWhenUnlockedKeysWhileLocked() throws {
        let (s, b, _) = store()
        let (unlockedOnly, _) = try s.createKey(purpose: 1, auth: 0, access: 0)
        let (whileLocked, _) = try s.createKey(purpose: 1, auth: 0, access: 1)
        let (ka, _) = try s.createKey(purpose: 2, auth: 0, access: 0)
        b.locked = true
        // As on the chip: no when-unlocked key is made while locked.
        #expect(throws: PlatformError.locked) { try s.createKey(purpose: 1, auth: 0, access: 0) }
        _ = try s.createKey(purpose: 2, auth: 0, access: 1)
        #expect(throws: PlatformError.locked) { try s.sign(handle: unlockedOnly, data: Data("x".utf8), approval: 0) }
        #expect(throws: PlatformError.locked) {
            try s.keyAgreement(handle: ka, peer: P256.KeyAgreement.PrivateKey().publicKey.x963Representation, approval: 0)
        }
        _ = try s.sign(handle: whileLocked, data: Data("x".utf8), approval: 0)
        b.locked = false
        _ = try s.sign(handle: unlockedOnly, data: Data("x".utf8), approval: 0)
    }

    @Test func aPublicKeyThatIsNotAnX963PointIsRefused() {
        var compressed = Data(repeating: 1, count: 33); compressed[0] = 2
        var wrongTag = Data(repeating: 1, count: 65); wrongTag[0] = 2
        for pub in [Data(), Data([4]), compressed, wrongTag, Data(repeating: 4, count: 66)] {
            let s = EnclaveStore(backend: BadPublicKeyBackend(pub: pub), approvals: ApprovalStore())
            let e = #expect(throws: PlatformError.self) { try s.createKey(purpose: 1, auth: 0, access: 0) }
            if case .failed = e {} else { Issue.record("public key \(pub.count) bytes: want .failed, got \(String(describing: e))") }
        }
    }

    // AuthNone keys always reach the backend with no context, even when the
    // caller passes a live ref: the Secure Enclave backend then signs with a
    // fresh non-interactive LAContext, never with an approval's context.
    @Test func authNoneKeysNeverGetAnApprovalContext() throws {
        let (s, b, a) = store()
        let (h, _) = try s.createKey(purpose: 1, auth: 0, access: 0)
        let (kh, _) = try s.createKey(purpose: 2, auth: 0, access: 0)
        let ref = try #require(a.issue(FakeAuthContext()))
        let peer = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        _ = try s.sign(handle: h, data: Data("x".utf8), approval: ref)
        _ = try s.keyAgreement(handle: kh, peer: peer, approval: ref)
        #expect(b.signCalls == 1 && b.agreeCalls == 1)
        #expect(b.contexts.count == 2 && b.contexts.allSatisfy { $0 == nil })
    }

    @Test func keyAgreementOnAPresenceKeyPassesTheRefsContext() throws {
        let (s, b, a) = store()
        let (kh, pub) = try s.createKey(purpose: 2, auth: 1, access: 0)
        let ctx = FakeAuthContext()
        let ref = try #require(a.issue(ctx))
        let local = P256.KeyAgreement.PrivateKey()
        let got = try s.keyAgreement(handle: kh, peer: local.publicKey.x963Representation, approval: ref)
        let want = try local.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: pub))
            .withUnsafeBytes { Data($0) }
        #expect(got == want)
        #expect(b.agreeCalls == 1 && b.contexts.last! === ctx)
    }

    // An approval is not tied to a key: any live ref unlocks any presence
    // key (the core binds refs to rules); but a ref issued by ANOTHER store
    // is unknown here.
    @Test func refsFromAnotherApprovalStoreAreUnknown() throws {
        let (s, b, _) = store()
        let (h, _) = try s.createKey(purpose: 1, auth: 1, access: 0)
        let other = ApprovalStore()
        let foreign = try #require(other.issue(FakeAuthContext()))
        #expect(throws: PlatformError.authRequired) { try s.sign(handle: h, data: Data("x".utf8), approval: foreign) }
        #expect(b.signCalls == 0)
    }

    @Test func malformedOrUnknownHandlesNeverReachTheBackend() throws {
        let (s, b, a) = store()
        let ref = try #require(a.issue(FakeAuthContext()))
        let peer = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
        let junk = KeyHandle(purpose: .sign, userPresence: true, blob: Data(repeating: 0, count: 33)).encoded
        for h in [Data(), Data("NZK1".utf8), junk] {
            #expect(throws: PlatformError.notFound) { try s.sign(handle: h, data: Data("x".utf8), approval: ref) }
            #expect(throws: PlatformError.notFound) { try s.keyAgreement(handle: h, peer: peer, approval: ref) }
        }
        #expect(b.signCalls == 0 && b.agreeCalls == 0)
    }

    // The handle check runs before the approval check: an unknown handle is
    // .notFound even without a ref, so a caller cannot tell from the error
    // whether a ref would have been needed for a key that does not exist.
    @Test func unknownHandleIsNotFoundBeforeAuthRequired() {
        let (s, _, _) = store()
        let junk = KeyHandle(purpose: .sign, userPresence: true, blob: Data(repeating: 0, count: 33)).encoded
        #expect(throws: PlatformError.notFound) { try s.sign(handle: junk, data: Data("x".utf8), approval: 0) }
    }

    @Test func deleteAffectsOnlyThatKey() throws {
        let (s, _, _) = store()
        let (h1, _) = try s.createKey(purpose: 1, auth: 0, access: 0)
        let (h2, pub2) = try s.createKey(purpose: 1, auth: 0, access: 0)
        try s.deleteKey(handle: h1)
        let der = try s.sign(handle: h2, data: Data("y".utf8), approval: 0)
        let pk = try P256.Signing.PublicKey(x963Representation: pub2)
        #expect(pk.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: der), for: Data("y".utf8)))
    }

    @Test func deleteNeedsNoApprovalForAPresenceKey() throws {
        let (s, b, _) = store()
        let (h, _) = try s.createKey(purpose: 1, auth: 1, access: 0)
        try s.deleteKey(handle: h)
        #expect(throws: PlatformError.notFound) { try s.sign(handle: h, data: Data("x".utf8), approval: 0) }
        #expect(b.signCalls == 0)
    }

    // A deleted handle stays deleted when the same bytes arrive in another
    // Data (a slice with a non-zero start index, a copy).
    @Test func deletedHandleStaysDeletedInAnyBuffer() throws {
        let (s, _, _) = store()
        let (h, _) = try s.createKey(purpose: 1, auth: 0, access: 0)
        try s.deleteKey(handle: h)
        let slice = (Data([0xaa, 0xbb]) + h).dropFirst(2)
        #expect(throws: PlatformError.notFound) { try s.sign(handle: slice, data: Data("x".utf8), approval: 0) }
        #expect(throws: PlatformError.notFound) { try s.sign(handle: Data(Array(h)), data: Data("x".utf8), approval: 0) }
    }

    // Deletion is of the KEY, not of one spelling of its handle: flipping the
    // presence byte of a deleted handle must not bring the key back.
    @Test func deletedKeyStaysDeletedWhenItsHandleIsRelabelled() throws {
        let (s, _, a) = store()
        let (h, _) = try s.createKey(purpose: 1, auth: 0, access: 0)
        try s.deleteKey(handle: h)
        var k = try #require(KeyHandle(decoding: h))
        k.userPresence = true
        let ref = try #require(a.issue(FakeAuthContext()))
        #expect(throws: PlatformError.notFound) { try s.sign(handle: k.encoded, data: Data("x".utf8), approval: ref) }
    }

    @Test func emptyAndLargeMessagesSign() throws {
        let (s, _, _) = store()
        let (h, pub) = try s.createKey(purpose: 1, auth: 0, access: 0)
        let pk = try P256.Signing.PublicKey(x963Representation: pub)
        for msg in [Data(), Data(repeating: 0x5a, count: 1 << 20)] {
            let der = try s.sign(handle: h, data: msg, approval: 0)
            #expect(pk.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: der), for: msg))
        }
    }
}

@Suite struct ApprovalStoreEdgeTests {
    @Test func zeroIsNeverAContext() {
        let a = ApprovalStore()
        #expect(a.context(0) == nil)
        a.release(0)
        #expect(a.liveCount == 0)
    }

    @Test func firstRefIsOneThenIncrements() throws {
        let a = ApprovalStore()
        #expect(a.issue(FakeAuthContext()) == 1)
        #expect(a.issue(FakeAuthContext()) == 2)
    }

    @Test func releaseInvalidatesOnlyItsOwnContextAndForgetsIt() throws {
        let a = ApprovalStore()
        let c1 = FakeAuthContext(), c2 = FakeAuthContext()
        let r1 = try #require(a.issue(c1)), r2 = try #require(a.issue(c2))
        #expect(a.context(r1) === c1 && a.context(r2) === c2)
        a.release(r1)
        #expect(c1.invalidated && !c2.invalidated)
        #expect(a.context(r1) == nil && a.context(r2) === c2 && a.liveCount == 1)
    }

    @Test func theSameContextUnderTwoRefsIsTwoApprovals() throws {
        let a = ApprovalStore()
        let c = FakeAuthContext()
        let r1 = try #require(a.issue(c)), r2 = try #require(a.issue(c))
        #expect(r1 != r2 && a.liveCount == 2)
    }

    // The last ref handed out is .max - 1; the counter never wraps to 0 or 1,
    // and once exhausted it stays closed.
    @Test func exhaustionBoundary() throws {
        let a = ApprovalStore()
        a.setNextForTesting(UInt64.max - 1)
        #expect(a.issue(FakeAuthContext()) == UInt64.max - 1)
        #expect(a.issue(FakeAuthContext()) == nil)
        #expect(a.issue(FakeAuthContext()) == nil)
        #expect(a.liveCount == 1 && a.context(UInt64.max) == nil)
    }

    @Test func concurrentIssueAndReleaseHandOutUniqueRefs() {
        let a = ApprovalStore()
        let n = 2000
        let lock = NSLock()
        var refs: [UInt64] = []
        var ctxs: [FakeAuthContext] = []
        DispatchQueue.concurrentPerform(iterations: n) { _ in
            let c = FakeAuthContext()
            guard let r = a.issue(c) else { return }
            lock.lock(); refs.append(r); ctxs.append(c); lock.unlock()
        }
        #expect(refs.count == n && Set(refs).count == n && !refs.contains(0))
        #expect(a.liveCount == n)
        DispatchQueue.concurrentPerform(iterations: n) { i in a.release(refs[i]) }
        #expect(a.liveCount == 0 && ctxs.allSatisfy { $0.invalidated })
    }
}

// Seams of the real backend that need neither the chip nor a person:
// creating an LAContext or a SecAccessControl never prompts; nothing here
// evaluates a policy or uses a key.
@Suite struct SecureEnclaveBackendSeamTests {
    @Test func noApprovalMeansANonInteractiveContext() {
        let la = SecureEnclaveBackend.operationContext(nil)
        #expect(la.interactionNotAllowed)
        // A software context (no LAContext) must not yield an interactive one either.
        let soft = SecureEnclaveBackend.operationContext(FakeAuthContext())
        #expect(soft.interactionNotAllowed)
        // Fresh each time: one operation's context is never shared with another.
        #expect(SecureEnclaveBackend.operationContext(nil) !== la)
    }

    @Test func anApprovalUsesItsOwnLAContext() {
        let la = LAContext()
        let ctx = LAAuthContext(la)
        #expect(ctx.laContext === la && ctx.context === la)
        #expect(SecureEnclaveBackend.operationContext(ctx) === la)
    }

    @Test func accessControlMatchesThePresenceAndLockFlags() throws {
        func expected(_ f: SecAccessControlCreateFlags, _ p: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) -> SecAccessControl {
            SecAccessControlCreateWithFlags(nil, p, f, nil)!
        }
        let none = try SecureEnclaveBackend.accessControl(userPresence: false, whileLocked: false)
        let presence = try SecureEnclaveBackend.accessControl(userPresence: true, whileLocked: false)
        #expect(CFEqual(none, expected([.privateKeyUsage])))
        #expect(CFEqual(presence, expected([.privateKeyUsage, .userPresence])))
        #expect(!CFEqual(none, presence))
        let locked = try SecureEnclaveBackend.accessControl(userPresence: false, whileLocked: true)
        #expect(CFEqual(locked, expected([.privateKeyUsage], kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)))
        #expect(!CFEqual(locked, none))
    }

    @Test func localAuthenticationErrorsMeanAuthRequired() {
        let la = NSError(domain: LAErrorDomain, code: LAError.Code.notInteractive.rawValue)
        #expect(SecureEnclaveBackend.mapOperationError(la) == .authRequired)
        let wrapped = NSError(domain: "CryptoTokenKit", code: -9, userInfo: [NSUnderlyingErrorKey: la])
        #expect(SecureEnclaveBackend.mapOperationError(wrapped) == .authRequired)
        let other = NSError(domain: "CryptoTokenKit", code: -3)
        if case .failed = SecureEnclaveBackend.mapOperationError(other) {} else {
            Issue.record("a non-LocalAuthentication error must be .failed")
        }
    }

    /// What the chip answers for a when-unlocked key while the Mac is
    /// locked (observed: CryptoKit, signing and key agreement alike) is
    /// .locked; another OSStatus stays .failed.
    @Test func interactionNotAllowedMeansLocked() {
        let chip = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecInteractionNotAllowed),
                           userInfo: [NSDebugDescriptionErrorKey: "<sepk:p256(u)>: unable to sign digest", "AKSError": -536870174])
        #expect(SecureEnclaveBackend.mapOperationError(chip) == .locked)
        let wrapped = NSError(domain: "CryptoKit", code: 1, userInfo: [NSUnderlyingErrorKey: chip])
        #expect(SecureEnclaveBackend.mapOperationError(wrapped) == .locked)
        let other = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecParam))
        if case .failed = SecureEnclaveBackend.mapOperationError(other) {} else {
            Issue.record("another OSStatus must be .failed")
        }
    }
}
