import Foundation

/// What a key is for (platform.Purpose; the values cross the ABI).
public enum KeyPurpose: UInt8, Sendable {
    case sign = 1
    case keyAgreement = 2
}

/// The opaque handle Go stores in the Vault. CryptoKit lets a key-agreement
/// handle sign and does not say whether a key needs user presence, so the
/// handle carries both, in front of the Secure Enclave's own blob:
///
///     "NZK1" | purpose (1 byte) | userPresence (1 byte: 0 or 1) | key blob
///
/// Handles live only in the Vault (a Keychain item only Nazar.app can read),
/// so the prefix is a record of how the key was made, not a security
/// boundary: a key made with user presence still needs it, whatever a
/// tampered prefix says, because the Secure Enclave enforces its own access
/// control and AuthNone signing never allows interaction (EnclaveStore).
/// The purpose byte is not enforced by the chip: the Secure Enclave signs
/// with a key-agreement blob relabelled as a signing handle (observed on the
/// chip). Only a process that can write the Vault could relabel one.
public struct KeyHandle: Equatable, Sendable {
    public static let magic = Data("NZK1".utf8)
    public static let maxBlob = 4096

    public var purpose: KeyPurpose
    public var userPresence: Bool
    public var blob: Data

    public init(purpose: KeyPurpose, userPresence: Bool, blob: Data) {
        self.purpose = purpose
        self.userPresence = userPresence
        self.blob = blob
    }

    /// Parses a handle; nil for anything that is not exactly this format.
    public init?(decoding data: Data) {
        let d = Data(data) // rebase to index 0 (data may be a slice)
        let header = Self.magic.count + 2
        guard d.count > header, d.count <= header + Self.maxBlob,
              d.prefix(Self.magic.count) == Self.magic,
              let purpose = KeyPurpose(rawValue: d[Self.magic.count]),
              d[Self.magic.count + 1] <= 1
        else { return nil }
        self.purpose = purpose
        self.userPresence = d[Self.magic.count + 1] == 1
        self.blob = d.subdata(in: header..<d.count)
    }

    public var encoded: Data {
        var d = Self.magic
        d.append(purpose.rawValue)
        d.append(userPresence ? 1 : 0)
        d.append(blob)
        return d
    }
}
