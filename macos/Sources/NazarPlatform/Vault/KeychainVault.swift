import Foundation
import Security

/// platform.Vault on a file-based Keychain (spec 4.5, 4.8; spike S5): one
/// generic-password item per name (service = the vault's service, account
/// = the name). Every item is created with an access list in which every
/// authorization except ChangeACL trusts only the given applications
/// (Nazar.app itself in production), so another process can neither read
/// nor rewrite a value without a Keychain dialog the user can deny.
///
/// What this vault guarantees, and what it cannot:
///
/// - Another process cannot READ a value Nazar wrote, or REWRITE it in place,
///   without a Keychain dialog (securityd enforces the access list on live
///   access; THREAT-MODEL 5.11: still to be checked by hand).
/// - An item under Nazar's name whose access list is not the one this vault
///   creates (open to any application, an extra application, another
///   program's code requirement, even under Nazar's own path, a ChangeACL entry
///   bundled with a grant such as `[ChangeACL, Decrypt]` answered by a
///   password prompt instead of an application, or no Decrypt or no Encrypt
///   entry trusting Nazar at all) is never read and never written: get and
///   put fail with `.failed`, and the item is left as it is for the user to
///   inspect (`checkAccess`, whose rule is the pure `refusal(of:trusted:)`).
///   The value of an item is only ever touched AFTER its access list passed;
///   the tests prove that order against an in-memory `KeychainStore` that
///   records every call.
/// - The vault never performs an operation that shows a Keychain dialog from
///   Nazar's process (spec 4.5: no prompt out of context). Every vault sets
///   `SecKeychainSetUserInteractionAllowed(false)` (process-wide) before its
///   first Keychain call; that flag is observed to suppress the unlock prompt
///   of a locked keychain and the Decrypt/Encrypt threshold prompts (securityd
///   log: `ObjectAcl REJECTS access`, no prompt, `-25293`), so an
///   item this process may not use fails with `.failed` instead. It does NOT
///   suppress the prompt-only ChangeACL confirmation (`AclValidationContext
///   action:65536`, a 1-of-1 `KeychainPromptAclSubject`), which asks for the
///   keychain's password even with dialogs off; so the vault never changes the
///   access list of an existing item. The Keychain Services calls it makes are
///   exactly those of `SecKeychainStore` (see its type doc): never
///   `SecKeychainItemSetAccess`, `SecACL*` on a stored item,
///   `SecKeychainSetSettings`, `SecKeychainChangePassword` or `SecKeychainLock`.
///   A dialog from Nazar at login is exactly what a planted item would need
///   (next bullet).
/// - A Nazar-shaped item that another process planted (delete Nazar's item,
///   re-add one with Nazar's exact access list) passes `checkAccess`: a legacy
///   keychain records no creator the vault could compare. On the login
///   keychain securityd still refuses it without a dialog: it appends its own
///   `PartitionID` entry naming the CREATOR's code identity to every item
///   (even against a client-supplied one), and the read fails with
///   `errSecAuthFailed` (-25293), which `get`/`put` report as `.failed`.
///   Verified with two separately ad-hoc-signed helpers on a
///   keychain under a temporary `Library/Keychains`; the exact partition
///   securityd derives for Nazar.app is left to a check by hand.
///   The vault itself accepts a Nazar-shaped plant from Nazar's own code
///   identity, and on a keychain outside `Library/Keychains` (no partition
///   entry) from anyone: it gives confidentiality and in-place integrity for
///   Nazar's items; authenticity of an item it finds comes from securityd's
///   partition check, a known limit.
/// - The keychain file itself is a plain file owned by the user; the access list
///   protects live access through securityd, not the bytes at rest.
///
/// Production uses the login keychain (`KeychainVault.login()`), opened by
/// its canonical path; tests use a temporary keychain file (own items only)
/// and the in-memory store, and never touch the login keychain.
public final class KeychainVault: @unchecked Sendable {
    public static let productionService = "dev.nazar"

    let store: any KeychainStore
    let service: String
    /// The identities of the trusted applications, for comparing access lists.
    let trustedIDs: Set<AppIdentity>
    private let lock = NSLock()

    /// trusted nil means "this executable" (SecTrustedApplicationCreateFromPath(nil)).
    /// Fails when a trusted application's code requirement cannot be read:
    /// without it the vault could not tell its own items from planted ones.
    public convenience init(keychain: SecKeychain, service: String, trusted: [SecTrustedApplication]? = nil) throws {
        try Self.disableUserInteraction()
        let apps: [SecTrustedApplication]
        if let trusted {
            apps = trusted
        } else {
            var me: SecTrustedApplication?
            let st = SecTrustedApplicationCreateFromPath(nil, &me)
            guard st == errSecSuccess, let me else { throw PlatformError.failed("trusted application: \(st)") }
            apps = [me]
        }
        var ids = Set<AppIdentity>()
        for app in apps {
            do {
                ids.insert(try AppIdentity(app))
            } catch let f as KeychainCallFailed {
                throw PlatformError.failed("trusted application: \(f.call): \(f.status)")
            }
        }
        try self.init(dialogsOff: (), store: SecKeychainStore(keychain: keychain, trusted: apps), service: service,
                      trustedIDs: ids)
    }

    /// The seam: a vault on any `KeychainStore` (the in-memory one in tests),
    /// trusting the applications identified by `trustedIDs`. Turns Keychain
    /// dialogs off like every other way of making a vault.
    convenience init(store: any KeychainStore, service: String, trustedIDs: Set<AppIdentity>) throws {
        try Self.disableUserInteraction()
        try self.init(dialogsOff: (), store: store, service: service, trustedIDs: trustedIDs)
    }

    /// Every initializer turns Keychain dialogs off exactly once, before any
    /// other Security call, and then comes here.
    private init(dialogsOff: Void, store: any KeychainStore, service: String, trustedIDs: Set<AppIdentity>) throws {
        guard !trustedIDs.isEmpty else { throw PlatformError.failed("trusted application: none") }
        self.store = store
        self.service = service
        self.trustedIDs = trustedIDs
    }

    // MARK: No dialogs

    /// The process-wide switch behind `disableUserInteraction`
    /// (`SecKeychainSetUserInteractionAllowed`). A seam: tests replace it to
    /// record the calls; the vault only ever passes `false`, and no test may
    /// pass `true` to the real function (the suite must never be able to show
    /// a dialog).
    nonisolated(unsafe) static var setUserInteractionAllowed: (Bool) -> OSStatus = {
        SecKeychainSetUserInteractionAllowed($0)
    }

    /// Turns off Keychain Services dialogs for this process (idempotent, and
    /// process-wide: nothing in Nazar.app wants one). With them on, a locked
    /// keychain asks for its password and an item this process may not use
    /// shows "NazarApp wants to use your confidential information" with an
    /// Allow button, from Nazar's own process; one click on a planted
    /// `config/approved` or `state/trust` installs an attacker's rules (spec
    /// 4.8, threat model 8). With them off both fail: `errSecInteractionNotAllowed`
    /// (-25308) and `errSecAuthFailed` (-25293), see `accessError`. The flag
    /// is known NOT to cover a prompt-only ChangeACL confirmation
    /// (`SecKeychainItemSetAccess` on a stored item asks for the keychain's
    /// password regardless, as observed), which is why the vault never
    /// changes a stored item's access list: see `SecKeychainStore` for the
    /// exact calls it makes.
    static func disableUserInteraction() throws {
        let st = setUserInteractionAllowed(false)
        guard st == errSecSuccess else { throw PlatformError.failed("SecKeychainSetUserInteractionAllowed: \(st)") }
    }

    /// The error for a Keychain call that failed with `f` during `op` on
    /// `name`. `errSecAuthFailed` is securityd refusing the item without a
    /// dialog (its partition check: the item was created by another code
    /// identity; or an access list that does not trust this process), and
    /// `errSecInteractionNotAllowed` a call that needed a dialog with dialogs
    /// off (a locked keychain). Both are spelled out so `nazar status` shows
    /// the cause.
    static func accessError(_ op: String, _ name: String, _ f: KeychainCallFailed) -> PlatformError {
        switch f.status {
        case errSecAuthFailed, errSecInteractionNotAllowed:
            return .failed("vault \(name): item was not created by this program (securityd partition check) "
                + "or the keychain is locked (\(op): \(f.call) \(f.status))")
        default:
            return .failed("vault \(op) \(name): \(f.call) \(f.status)")
        }
    }

    // MARK: Login keychain

    /// The user's login keychain, opened by its canonical path
    /// (`<home>/Library/Keychains/login.keychain-db`, home from the passwd
    /// entry, never $HOME). Fails closed when the user-domain default
    /// keychain is not that file: `security default-keychain -d user -s
    /// <file>` is a plain preference any process of the user can write, and
    /// a vault that silently followed it would put every new key handle into
    /// a keychain file whose password the attacker knows. Only Nazar.app
    /// calls this.
    public static func login(service: String = productionService) throws -> KeychainVault {
        try disableUserInteraction()
        var kc: SecKeychain?
        let st = SecKeychainCopyDomainDefault(.user, &kc)
        guard st == errSecSuccess, let kc else { throw PlatformError.failed("default keychain: \(st)") }
        return try login(service: service, home: try homeDirectory(), defaultKeychainPath: try path(of: kc),
                         open: openKeychain)
    }

    /// The seam behind `login(service:)`: `home` is the user's home directory,
    /// `defaultKeychainPath` the user-domain default keychain and `open` what
    /// opens the checked path (`openKeychain` in production). Tests pass a
    /// temporary home (with nothing inside it) and an `open` that records the
    /// path and hands back a plain `TemporaryKeychain`, so nothing under a
    /// `Library/Keychains` folder is ever created or opened by automation
    /// (AGENTS.md, hard rules) and the real login keychain is never touched.
    static func login(service: String, home: String, defaultKeychainPath: String,
                      open: (String) throws -> SecKeychain) throws -> KeychainVault {
        try disableUserInteraction()
        let path = try checkedLoginKeychainPath(home: home, defaultKeychainPath: defaultKeychainPath)
        return try KeychainVault(keychain: try open(path), service: service)
    }

    /// `SecKeychainOpen` of `path`.
    static func openKeychain(_ path: String) throws -> SecKeychain {
        var kc: SecKeychain?
        let st = SecKeychainOpen(path, &kc)
        guard st == errSecSuccess, let kc else { throw PlatformError.failed("login keychain \(path): \(st)") }
        return kc
    }

    /// Where the login keychain of `home` lives.
    static func loginKeychainPath(home: String) -> String {
        (home.hasSuffix("/") ? String(home.dropLast()) : home) + "/Library/Keychains/login.keychain-db"
    }

    /// The login keychain path for `home`, after checking that
    /// `defaultKeychainPath` is that file (symlinks resolved). Throws
    /// `.failed` otherwise; nothing is opened.
    static func checkedLoginKeychainPath(home: String, defaultKeychainPath: String) throws -> String {
        let login = loginKeychainPath(home: home)
        guard realPath(defaultKeychainPath) == realPath(login) else {
            throw PlatformError.failed("default keychain is not the login keychain: \(defaultKeychainPath) (expected \(login))")
        }
        return login
    }

    /// The home directory from the passwd entry of the real uid, never from
    /// $HOME (the environment is the caller's to set).
    static func homeDirectory() throws -> String {
        guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir, dir.pointee != 0 else {
            throw PlatformError.failed("no home directory for uid \(getuid())")
        }
        return String(cString: dir)
    }

    private static func path(of keychain: SecKeychain) throws -> String {
        var len = UInt32(PATH_MAX)
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let st = SecKeychainGetPath(keychain, &len, &buf)
        guard st == errSecSuccess else { throw PlatformError.failed("SecKeychainGetPath: \(st)") }
        return String(cString: buf)
    }

    /// `path` with `.`/`..` removed and symlinks resolved along its longest
    /// EXISTING prefix (`realpath(3)` of that prefix, so `/var` becomes
    /// `/private/var`), with the rest appended as given. `realpath` alone
    /// returns nothing for a path whose leaf does not exist, and Foundation's
    /// `resolvingSymlinksInPath` leaves such a path untouched; this resolves
    /// what can be resolved, so two spellings of one place compare equal
    /// whether or not the file is there yet. The relative `path` "" is "".
    static func realPath(_ path: String) -> String {
        guard !path.isEmpty else { return path }
        var url = URL(fileURLWithPath: path).standardizedFileURL
        var tail: [String] = []
        while true {
            if let r = realpath(url.path, nil) {
                defer { free(r) }
                var out = URL(fileURLWithPath: String(cString: r))
                for c in tail.reversed() { out.appendPathComponent(c) }
                return out.path
            }
            guard url.pathComponents.count > 1 else { return URL(fileURLWithPath: path).standardizedFileURL.path }
            tail.append(url.lastPathComponent)
            url.deleteLastPathComponent()
        }
    }

    // MARK: Names

    /// `^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$` checked byte by byte: a regex
    /// `$` (ICU) also matches before a final line terminator, which would
    /// let "ssh-key/github\n" through as a second item for the same key.
    static func validName(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        guard (1...128).contains(bytes.count), isAlnum(bytes[0]) else { return false }
        return bytes.dropFirst().allSatisfy { isAlnum($0) || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "_")
            || $0 == UInt8(ascii: "/") || $0 == UInt8(ascii: "-") }
    }

    private static func isAlnum(_ b: UInt8) -> Bool {
        (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(b) || (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(b)
            || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(b)
    }

    private static func checkName(_ name: String) throws {
        guard validName(name) else { throw PlatformError.invalid("vault name") }
    }

    // MARK: Vault

    /// The item for `name`, or nil when there is none.
    private func item(_ name: String) throws -> AnyObject? {
        do {
            return try store.find(service: service, account: name)
        } catch let f as KeychainCallFailed {
            throw Self.accessError("find", name, f)
        }
    }

    public func get(_ name: String) throws -> Data {
        try Self.checkName(name)
        guard let item = try item(name) else { throw PlatformError.notFound }
        try checkAccess(of: item, name)
        // Read the very item whose access list was checked (a fresh query
        // could match an item swapped in since).
        do {
            return try store.content(of: item)
        } catch let f as KeychainCallFailed {
            if f.status == errSecItemNotFound { throw PlatformError.notFound }
            throw Self.accessError("get", name, f)
        }
    }

    public func put(_ name: String, _ value: Data) throws {
        try Self.checkName(name)
        lock.lock()
        defer { lock.unlock() }
        if let item = try item(name) {
            // Replace in place; the item keeps its (checked) access list. A
            // foreign-shaped item is refused and left where it is, never
            // deleted and re-added behind the user's back.
            try checkAccess(of: item, name)
            do {
                try store.replaceContent(of: item, with: value)
            } catch let f as KeychainCallFailed {
                throw Self.accessError("update", name, f)
            }
            return
        }
        do {
            try store.add(service: service, account: name, label: "nazar: \(name)", value: value)
        } catch let f as KeychainCallFailed {
            throw Self.accessError("add", name, f)
        }
    }

    public func delete(_ name: String) throws {
        try Self.checkName(name)
        lock.lock()
        defer { lock.unlock() }
        do {
            try store.delete(service: service, account: name)
        } catch let f as KeychainCallFailed {
            if f.status == errSecItemNotFound { throw PlatformError.notFound }
            throw PlatformError.failed("vault delete \(name): \(f.call) \(f.status)")
        }
    }

    public func list(prefix: String) throws -> [String] {
        do {
            return try store.accounts(service: service).filter { $0.hasPrefix(prefix) }.sorted()
        } catch let f as KeychainCallFailed {
            throw PlatformError.failed("vault list: \(f.call) \(f.status)")
        }
    }

    // MARK: Access lists

    /// ACL entries securityd adds and maintains itself on every item in a
    /// keychain under `Library/Keychains` (so on the login keychain, not on a
    /// temporary one elsewhere): Integrity (a hash over the item's
    /// attributes; a client cannot supply one) and PartitionID (which
    /// code-signing partitions may use the item without a dialog; securityd
    /// always appends one naming the creator's own partition). Neither grants
    /// an application anything, and both read back as "any application", so
    /// `checkAccess` skips entries that carry only these. Seen once by hand on
    /// macOS 27 on a keychain under a temporary `Library/Keychains` folder;
    /// automation never creates one there (AGENTS.md, hard rules), so the
    /// skip is unit-tested on made-up entries (`classify`, the in-memory
    /// store) and the real placement is left to a check by hand.
    static let managedAuthorizations: Set<String> = [kSecACLAuthorizationIntegrity as String,
                                                     kSecACLAuthorizationPartitionID as String]

    /// True for an entry securityd manages: EVERY authorization it carries is
    /// one of `managedAuthorizations` (and it carries at least one). An entry
    /// mixing `PartitionID` with `Decrypt` or `Encrypt` (which any process can
    /// plant with `SecACLUpdateAuthorizations`) is not managed: it grants that
    /// access, and is judged like any other entry.
    static func isManaged(_ auths: [String]) -> Bool {
        !auths.isEmpty && auths.allSatisfy(managedAuthorizations.contains)
    }

    /// What `checkAccess` decides about one ACL entry.
    enum EntryVerdict: Equatable {
        /// securityd's own Integrity / PartitionID entry: ignored.
        case managed
        /// The shape this vault creates.
        case trusted
        /// Not Nazar's shape; the reason, as `checkAccess` reports it.
        case refused(String)
    }

    /// True for the ChangeACL entry as SecAccessCreate makes it and as the
    /// vault's own items read back: exactly [ChangeACL] and nothing else
    /// (checked in memory: `["ACLAuthorizationChangeACL"]` with
    /// no applications). An entry that carries ChangeACL NEXT TO another
    /// authorization is not that entry: it is a grant of the other
    /// authorization too, and is judged as one.
    static func isChangeACLOnly(_ auths: [String]) -> Bool {
        Set(auths) == [kSecACLAuthorizationChangeACL as String]
    }

    /// The per-entry rule of `checkAccess`, pure so hostile shapes can be
    /// checked with made-up inputs (no keychain, no item): `auths` is the
    /// entry's authorizations, `apps` the applications it trusts (nil = ANY
    /// application), `trusted` the vault's applications. A managed entry is
    /// skipped; an open entry is refused; the ChangeACL entry (exactly
    /// [ChangeACL], `isChangeACLOnly`) may trust any subset of `trusted` (an
    /// empty list means "ask the user", which this process never does);
    /// every other entry, INCLUDING one that bundles ChangeACL with another
    /// authorization, must trust exactly `trusted` (no extra, no missing, no
    /// duplicate). The subset rule is confined to the bare ChangeACL entry
    /// because `[ChangeACL, Decrypt]` with no applications is a Decrypt
    /// grant answered by a password prompt (a `KeychainPromptAclSubject`,
    /// the one subject the dialogs-off flag is not known to silence), not by
    /// this process; an earlier version let it through.
    static func classify(auths: [String], apps: [AppIdentity]?, trusted: Set<AppIdentity>) -> EntryVerdict {
        if isManaged(auths) { return .managed }
        guard let apps else { return .refused("item is open to any application (\(auths))") }
        let ok: Bool
        if isChangeACLOnly(auths) {
            ok = apps.allSatisfy(trusted.contains)
        } else {
            ok = apps.count == trusted.count && Set(apps) == trusted
        }
        return ok ? .trusted : .refused("item trusts another application (\(auths))")
    }

    /// One ACL entry as `checkAccess` sees it: its authorizations and the
    /// applications it trusts (nil = ANY application).
    struct Entry: Equatable {
        var auths: [String]
        var apps: [AppIdentity]?
    }

    /// The whole-item rule of `checkAccess`, pure: the reason to refuse
    /// `entries`, or nil when they have the shape this vault creates. Every
    /// entry passes `classify`, and among the `.trusted` entries at least one
    /// carries Decrypt and at least one carries Encrypt, so the item's read
    /// and its in-place rewrite are both granted to exactly `trusted` (and
    /// not left to some other subject securityd may find, such as a
    /// password prompt). An item with no entries at all is refused.
    static func refusal(of entries: [Entry], trusted: Set<AppIdentity>) -> String? {
        var grantsDecrypt = false
        var grantsEncrypt = false
        for e in entries {
            switch classify(auths: e.auths, apps: e.apps, trusted: trusted) {
            case .managed: continue
            case .refused(let why): return why
            case .trusted:
                if e.auths.contains(kSecACLAuthorizationDecrypt as String) { grantsDecrypt = true }
                if e.auths.contains(kSecACLAuthorizationEncrypt as String) { grantsEncrypt = true }
            }
        }
        if !grantsDecrypt { return "item has no Decrypt entry trusting this program" }
        if !grantsEncrypt { return "item has no Encrypt entry trusting this program" }
        return nil
    }

    /// Fails unless the item's access list has the shape this vault creates
    /// (`refusal`): every entry (other than securityd's `managedAuthorizations`)
    /// names a finite application list (never "any application"); every
    /// entry except the bare ChangeACL entry trusts exactly `trusted`; the
    /// bare ChangeACL entry trusts nothing outside `trusted` (`classify`); and
    /// a Decrypt entry and an Encrypt entry trusting exactly `trusted` are
    /// both present. Applications are compared by code requirement only
    /// (`AppIdentity`), never by recorded path: the same signature at
    /// another path is the same program (a Homebrew upgrade, a move), and
    /// another signature at the same path is another program
    /// (SecTrustedApplicationCreateFromRequirement puts any requirement under
    /// any path). An entry whose requirement cannot be read counts as
    /// foreign.
    ///
    /// This refuses foreign-shaped items. It cannot refuse an item another
    /// process planted with Nazar's exact access list, which is
    /// indistinguishable from Nazar's own; on the login keychain securityd's
    /// partition check refuses that one at read time (see the type doc).
    /// Internal so tests can check hostile shapes without ever reading an item.
    /// Reads only the access list (no authorization needed); never changes it.
    func checkAccess(of item: AnyObject, _ name: String) throws {
        let entries: [Entry]
        do {
            entries = try store.accessList(of: item)
        } catch let f as KeychainCallFailed {
            // On a locked keychain this is the first call to fail (-25293, seen on macOS 27).
            throw Self.accessError("access list", name, f)
        }
        if let why = Self.refusal(of: entries, trusted: trustedIDs) {
            throw PlatformError.failed("vault \(name): \(why)")
        }
    }
}
