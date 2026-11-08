import Foundation
import Security

/// One Keychain Services call that failed: which one, and its status. Every
/// `KeychainStore` failure is one of these so `KeychainVault` can map the two
/// statuses securityd answers with dialogs off (`errSecAuthFailed`,
/// `errSecInteractionNotAllowed`) to the message `nazar status` shows.
struct KeychainCallFailed: Error, Equatable {
    /// The call, e.g. `SecKeychainItemCopyAccess`; for an ACL entry whose
    /// trusted application cannot be identified, the call and the entry's
    /// authorizations.
    var call: String
    var status: OSStatus
}

/// The Keychain Services calls `KeychainVault` makes, as one seam, so the
/// vault's rules (`checkAccess`, `refusal`, the status mapping) run unchanged
/// against an in-memory store in tests: hostile access lists, foreign code
/// identities, securityd's partition check, its managed entries and a locked
/// keychain are all behaviour a real keychain can only show by reaching
/// securityd, and in some of those cases SecurityAgent, which automation must
/// never do (AGENTS.md, hard rules; cross-process behaviour is checked by hand).
/// `SecKeychainStore` is the real one; the tests' `FakeKeychainStore` records
/// every call, which is how the suite proves `get` and `put` never touch a
/// value before the access list has passed.
///
/// Items are opaque handles (`AnyObject`): a `SecKeychainItem` for the real
/// store, so the vault reads the very item whose access list it checked, not
/// whatever a fresh query would match.
protocol KeychainStore: AnyObject {
    /// The item for `service`/`account`, or nil when there is none.
    func find(service: String, account: String) throws -> AnyObject?
    /// The item's access list, one `Entry` per ACL entry (`apps` nil = ANY
    /// application). Reads only the access list: no authorization is needed,
    /// so this never prompts; on a locked keychain it is the first call to
    /// fail (`errSecAuthFailed`, seen on macOS 27).
    func accessList(of item: AnyObject) throws -> [KeychainVault.Entry]
    /// The item's value. Only ever called after `accessList` passed `refusal`.
    func content(of item: AnyObject) throws -> Data
    /// Replaces the item's value in place; the access list is untouched.
    func replaceContent(of item: AnyObject, with value: Data) throws
    /// Adds an item whose access list is the store's own shape: every entry
    /// except the bare ChangeACL entry trusts exactly the store's trusted
    /// applications; shaped BEFORE the add, the only place automation may
    /// shape an access list.
    func add(service: String, account: String, label: String, value: Data) throws
    /// Deletes the item (`errSecItemNotFound` when there is none). Consults no
    /// access list: deleting a record in a legacy keychain never does.
    func delete(service: String, account: String) throws
    /// The accounts of every item under `service` (attributes only, never a value).
    func accounts(service: String) throws -> [String]
}

/// The real store: one `SecKeychain`, one list of trusted applications. The
/// Keychain Services calls it makes are exactly these, and nothing else:
/// `SecItemCopyMatching` (a reference or attributes, never data),
/// `SecKeychainItemCopyAccess` + `SecAccessCopyACLList` +
/// `SecACLCopyAuthorizations` + `SecACLCopyContents` (reading an access
/// list), `SecKeychainItemCopyContent` and
/// `SecKeychainItemModifyAttributesAndData` (on an item the vault has
/// checked), `SecAccessCreate` + `SecACLSetContents` on an IN-MEMORY access
/// followed by `SecItemAdd` with it as `kSecAttrAccess`, and `SecItemDelete`.
/// Never `SecKeychainItemSetAccess`, `SecACL*` on a stored item's access,
/// `SecKeychainSetSettings`, `SecKeychainChangePassword` or `SecKeychainLock`:
/// changing a stored item's access list is confirmed by a prompt-only
/// ChangeACL entry that `SecKeychainSetUserInteractionAllowed(false)` does
/// NOT suppress (the SecurityAgent password dialog has been seen).
final class SecKeychainStore: KeychainStore, @unchecked Sendable {
    let keychain: SecKeychain
    let trusted: [SecTrustedApplication]

    init(keychain: SecKeychain, trusted: [SecTrustedApplication]) {
        self.keychain = keychain
        self.trusted = trusted
    }

    private func query(service: String, account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: account, kSecMatchSearchList as String: [keychain]]
    }

    func find(service: String, account: String) throws -> AnyObject? {
        var q = query(service: service, account: account)
        q[kSecReturnRef as String] = true
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return nil }
        guard st == errSecSuccess, let out else { throw KeychainCallFailed(call: "SecItemCopyMatching", status: st) }
        return out
    }

    func accessList(of item: AnyObject) throws -> [KeychainVault.Entry] {
        var access: SecAccess?
        let st = SecKeychainItemCopyAccess(item as! SecKeychainItem, &access)
        guard st == errSecSuccess, let access else { throw KeychainCallFailed(call: "SecKeychainItemCopyAccess", status: st) }
        var acls: CFArray?
        let lst = SecAccessCopyACLList(access, &acls)
        guard lst == errSecSuccess, let list = acls as? [SecACL] else {
            throw KeychainCallFailed(call: "SecAccessCopyACLList", status: lst)
        }
        var entries: [KeychainVault.Entry] = []
        for acl in list {
            let auths = SecACLCopyAuthorizations(acl) as? [String] ?? []
            if KeychainVault.isManaged(auths) {
                // securityd's own Integrity / PartitionID entry: it grants no
                // application anything and reads back as "any application";
                // its contents are not consulted (and `classify` skips it).
                entries.append(KeychainVault.Entry(auths: auths, apps: nil))
                continue
            }
            var apps: CFArray?
            var desc: CFString?
            var prompt = SecKeychainPromptSelector()
            let cst = SecACLCopyContents(acl, &apps, &desc, &prompt)
            guard cst == errSecSuccess else { throw KeychainCallFailed(call: "SecACLCopyContents (\(auths))", status: cst) }
            var ids: [AppIdentity]?
            if let apps = apps as? [SecTrustedApplication] {
                ids = []
                for app in apps {
                    do {
                        ids!.append(try AppIdentity(app))
                    } catch let f as KeychainCallFailed {
                        // An entry whose application cannot be identified is
                        // reported, never guessed at: the vault fails closed.
                        throw KeychainCallFailed(call: "\(f.call) (\(auths))", status: f.status)
                    }
                }
            }
            entries.append(KeychainVault.Entry(auths: auths, apps: ids))
        }
        return entries
    }

    func content(of item: AnyObject) throws -> Data {
        var length: UInt32 = 0
        var bytes: UnsafeMutableRawPointer?
        let st = SecKeychainItemCopyContent(item as! SecKeychainItem, nil, nil, &length, &bytes)
        guard st == errSecSuccess else { throw KeychainCallFailed(call: "SecKeychainItemCopyContent", status: st) }
        defer { SecKeychainItemFreeContent(nil, bytes) }
        guard let bytes, length > 0 else { return Data() }
        return Data(bytes: bytes, count: Int(length))
    }

    func replaceContent(of item: AnyObject, with value: Data) throws {
        let st = value.withUnsafeBytes { buf in
            SecKeychainItemModifyAttributesAndData(item as! SecKeychainItem, nil, UInt32(buf.count), buf.baseAddress)
        }
        guard st == errSecSuccess else { throw KeychainCallFailed(call: "SecKeychainItemModifyAttributesAndData", status: st) }
    }

    func add(service: String, account: String, label: String, value: Data) throws {
        let add: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                  kSecAttrAccount as String: account, kSecUseKeychain as String: keychain,
                                  kSecValueData as String: value, kSecAttrAccess as String: try access(label),
                                  kSecAttrLabel as String: label]
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw KeychainCallFailed(call: "SecItemAdd", status: st) }
    }

    func delete(service: String, account: String) throws {
        let st = SecItemDelete(query(service: service, account: account) as CFDictionary)
        guard st == errSecSuccess else { throw KeychainCallFailed(call: "SecItemDelete", status: st) }
    }

    func accounts(service: String) throws -> [String] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecMatchSearchList as String: [keychain], kSecReturnAttributes as String: true,
                                kSecMatchLimit as String: kSecMatchLimitAll]
        q[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return [] }
        guard st == errSecSuccess, let items = out as? [[String: Any]] else {
            throw KeychainCallFailed(call: "SecItemCopyMatching", status: st)
        }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }
    }

    /// The access list for a new item, shaped in memory: every ACL entry
    /// except the bare ChangeACL entry trusts exactly `trusted`
    /// (`SecAccessCreate` leaves Encrypt open to ANY application, which would
    /// let any process rewrite the value). The ChangeACL entry stays as
    /// `SecAccessCreate` makes it: a prompt-only owner entry (no applications),
    /// which this process never answers, see `KeychainVault.classify`.
    func access(_ label: String) throws -> SecAccess {
        var access: SecAccess?
        let st = SecAccessCreate(label as CFString, trusted as CFArray, &access)
        guard st == errSecSuccess, let access else { throw KeychainCallFailed(call: "SecAccessCreate", status: st) }
        var acls: CFArray?
        let lst = SecAccessCopyACLList(access, &acls)
        guard lst == errSecSuccess, let list = acls as? [SecACL] else {
            throw KeychainCallFailed(call: "SecAccessCopyACLList", status: lst)
        }
        for acl in list {
            let auths = SecACLCopyAuthorizations(acl) as? [String] ?? []
            if auths.contains(kSecACLAuthorizationChangeACL as String) { continue }
            var apps: CFArray?
            var desc: CFString?
            var prompt = SecKeychainPromptSelector()
            let cst = SecACLCopyContents(acl, &apps, &desc, &prompt)
            guard cst == errSecSuccess else { throw KeychainCallFailed(call: "SecACLCopyContents", status: cst) }
            let set = SecACLSetContents(acl, trusted as CFArray, desc ?? ("nazar" as CFString), prompt)
            guard set == errSecSuccess else { throw KeychainCallFailed(call: "SecACLSetContents", status: set) }
        }
        return access
    }
}

/// What identifies a trusted application in an access list: the code
/// requirement securityd matches the client against, and nothing else
/// (spec 4, Milestone 6: identity is the signature, not the place). The
/// recorded path (SecTrustedApplicationCopyData; a NUL-terminated path) is
/// kept for messages only and never compared: Homebrew installs every
/// version of the agent into a new folder and a move must not orphan the
/// keys, so one requirement under two paths is ONE program; and the path
/// is forgeable anyway (SecTrustedApplicationCreateFromRequirement puts any
/// requirement under any path), so one path under two requirements is TWO
/// programs. `==` and `hash(into:)` therefore look at `requirement` only.
/// SecTrustedApplicationCopyRequirement is Security.framework SPI
/// (SecTrustedApplicationPriv.h, exported by Security.tbd); it is resolved
/// with dlsym so the build has no private header, and a system without it
/// fails closed (the vault cannot be constructed).
struct AppIdentity: Hashable {
    /// Where the entry says the application was; for messages only.
    let path: Data
    let requirement: Data

    static func == (a: AppIdentity, b: AppIdentity) -> Bool { a.requirement == b.requirement }
    func hash(into h: inout Hasher) { h.combine(requirement) }

    private typealias CopyRequirementFn = @convention(c) (SecTrustedApplication,
                                                          UnsafeMutablePointer<Unmanaged<SecRequirement>?>) -> OSStatus
    private static let copyRequirement: CopyRequirementFn? = {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2) /* RTLD_DEFAULT */,
                              "SecTrustedApplicationCopyRequirement") else { return nil }
        return unsafeBitCast(sym, to: CopyRequirementFn.self)
    }()

    /// A made-up identity (tests of `classify` and the in-memory store).
    init(path: Data, requirement: Data) {
        self.path = path
        self.requirement = requirement
    }

    /// Throws `KeychainCallFailed`.
    init(_ app: SecTrustedApplication) throws {
        var d: CFData?
        let st = SecTrustedApplicationCopyData(app, &d)
        guard st == errSecSuccess, let d else { throw KeychainCallFailed(call: "SecTrustedApplicationCopyData", status: st) }
        path = d as Data
        guard let copy = Self.copyRequirement else {
            throw KeychainCallFailed(call: "SecTrustedApplicationCopyRequirement (not available)", status: errSecUnimplemented)
        }
        var out: Unmanaged<SecRequirement>?
        let rst = copy(app, &out)
        guard rst == errSecSuccess, let out else {
            throw KeychainCallFailed(call: "SecTrustedApplicationCopyRequirement", status: rst)
        }
        let req = out.takeRetainedValue()
        var rd: CFData?
        let dst = SecRequirementCopyData(req, [], &rd)
        guard dst == errSecSuccess, let rd, (rd as Data).count > 0 else {
            throw KeychainCallFailed(call: "SecRequirementCopyData", status: dst == errSecSuccess ? errSecDecode : dst)
        }
        requirement = rd as Data
    }
}
