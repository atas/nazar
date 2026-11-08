import AppKit
import Foundation

/// Finds the bundles LaunchServices knows for a bundle ID.
public protocol AppLocator: AnyObject {
    func urls(bundleId: String) -> [URL]
}

public final class LaunchServicesLocator: AppLocator, @unchecked Sendable {
    public init() {}
    public func urls(bundleId: String) -> [URL] {
        NSWorkspace.shared.urlsForApplications(withBundleIdentifier: bundleId)
    }
}

/// Platform.InstalledApp (core/platform; spec 4.2 `app:` pinning): the app
/// installed for a bundle ID and its static code signature. Only bundles
/// under the install roots count (not a copy in Downloads or a build
/// folder). Bundles whose signatures name different teams are ambiguous:
/// there is no one team to pin.
public final class InstalledApps: @unchecked Sendable {
    public typealias Inspect = (URL) -> (bundleId: String, code: CodeIdentity)?

    let locator: AppLocator
    let inspect: Inspect
    let roots: [String]

    public static func defaultRoots(home: String) -> [String] {
        ["/Applications/", "/System/Applications/", home + "/Applications/"]
    }

    public static let realInspect: Inspect = { url in
        guard let id = Bundle(url: url)?.bundleIdentifier, let code = CodeSigning.staticIdentity(path: url.path) else {
            return nil
        }
        return (id, code)
    }

    public init(locator: AppLocator = LaunchServicesLocator(), inspect: @escaping Inspect = InstalledApps.realInspect,
                roots: [String] = InstalledApps.defaultRoots(home: NSHomeDirectory())) {
        self.locator = locator
        self.inspect = inspect
        self.roots = roots.map(Self.resolvedRoot)
    }

    /// A root with its symlinks and `..` resolved and one trailing slash:
    /// bundle paths are compared after the same resolution, so an
    /// `~/Applications` that is itself a symlink still counts as a root
    /// and a root never matches a sibling folder sharing its prefix.
    static func resolvedRoot(_ root: String) -> String {
        let p = URL(fileURLWithPath: root).resolvingSymlinksInPath().standardizedFileURL.path
        return p.hasSuffix("/") ? p : p + "/"
    }

    /// A bundle ID is 1 to 255 ASCII letters, digits, dots and hyphens and
    /// starts with a letter or digit. Checked byte by byte: a regular
    /// expression's `$` also matches before a trailing newline.
    static func isValidBundleId(_ s: String) -> Bool {
        let bytes = Array(s.utf8)
        guard (1...255).contains(bytes.count) else { return false }
        func alnum(_ b: UInt8) -> Bool {
            (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(b) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(b)
                || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(b)
        }
        guard alnum(bytes[0]) else { return false }
        return bytes.allSatisfy { alnum($0) || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "-") }
    }

    public func installedApp(_ bundleId: String) throws -> AppBundleRecord {
        guard Self.isValidBundleId(bundleId) else { throw PlatformError.invalid("bundle id") }
        var found: [(rank: Int, rec: AppBundleRecord)] = []
        for url in locator.urls(bundleId: bundleId) {
            // Symlinks and `..` resolved before the root check, so a path
            // that only looks as if it were under a root is not.
            let path = url.resolvingSymlinksInPath().standardizedFileURL.path
            guard let rank = roots.firstIndex(where: { path.hasPrefix($0) }),
                  let (id, code) = inspect(URL(fileURLWithPath: path)), id == bundleId else { continue }
            found.append((rank, AppBundleRecord(bundleId: bundleId, path: path, code: code)))
        }
        guard !found.isEmpty else { throw PlatformError.notFound }
        let teams = Set(found.map { Self.team($0.rec.code) })
        guard teams.count == 1 else { throw PlatformError.ambiguous }
        return found.sorted { ($0.rank, $0.rec.path) < ($1.rank, $1.rec.path) }[0].rec
    }

    /// CodeIdentity.Team() of core/platform: unsigned and ad-hoc code has
    /// no team, Apple-signed code is "apple".
    static func team(_ c: CodeIdentity) -> String {
        guard c.signed, !c.adHoc else { return "" }
        return c.apple ? "apple" : c.teamId
    }
}
