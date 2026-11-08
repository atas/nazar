import AppKit
import Darwin
import Foundation
import Testing
@testable import NazarPlatform

/// A listening Unix socket under /tmp (sun_path is 104 bytes) and a peer
/// process (/usr/bin/nc -U) connected to it.
final class PeerFixture {
    let path: String
    let listener: Int32
    let nc = Process()
    let stdin = Pipe()
    private(set) var conn: Int32 = -1

    init() throws {
        path = "/tmp/nzpt-\(getpid())-\(UInt32.random(in: 0...UInt32.max)).sock"
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = path.withCString { src in
            withUnsafeMutablePointer(to: &addr.sun_path) { $0.withMemoryRebound(to: CChar.self, capacity: 104) { strncpy($0, src, 103) } }
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0, listen(listener, 4) == 0 else { throw PlatformError.failed("bind \(path)") }
        nc.executableURL = URL(fileURLWithPath: "/usr/bin/nc")
        nc.arguments = ["-U", path]
        nc.standardInput = stdin
        nc.standardOutput = FileHandle.nullDevice
        try nc.run()
        conn = accept(listener, nil, nil)
        guard conn >= 0 else { throw PlatformError.failed("accept") }
    }

    func killPeer() {
        if nc.isRunning { nc.terminate() }
        nc.waitUntilExit()
    }

    deinit {
        killPeer()
        close(conn)
        close(listener)
        unlink(path)
    }
}

/// A GUI lookup that says no process is an app (for the forged-record tests).
final class NoApps: GUIAppLookup {
    func app(pid: Int32) -> (bundleId: String, name: String)? { nil }
    func regularApps() -> [Int32] { [] }
}

/// A GUI lookup that claims every PID is an app, and names `running` as
/// the running apps: whatever the lookup says, liveness and the generation
/// are the resolver's to check, and the code identity is read fresh from
/// the live process.
final class AllApps: GUIAppLookup {
    var asked: [Int32] = []
    var running: [Int32] = []
    func app(pid: Int32) -> (bundleId: String, name: String)? {
        asked.append(pid)
        return ("com.example.claimed", "Claimed")
    }
    func regularApps() -> [Int32] { running }
}

@Suite(.serialized) struct ProcessResolverTests {
    let r = ProcessResolver()

    @Test func peerIsIdentifiedByItsAuditToken() throws {
        let f = try PeerFixture()
        let ref = try r.peerOf(fd: f.conn)
        #expect(ref.pid == f.nc.processIdentifier && ref.generation == KernelProc.info(ref.pid)?.generation)
        let rec = try r.process(ref)
        #expect(rec.ref == ref && rec.path == "/usr/bin/nc" && rec.args == ["/usr/bin/nc", "-U", f.path])
        #expect(rec.code.apple && rec.code.signingId == "com.apple.nc")
        #expect(rec.parentPid == getpid() && rec.parentGeneration == 0 && rec.uid == Int64(getuid()))
        #expect(try r.process(ProcessRef(pid: ref.pid, generation: 0)).ref == ref)
        f.killPeer()
        #expect(throws: PlatformError.noProcess) { try r.peerOf(fd: f.conn) }
        #expect(throws: PlatformError.noProcess) { try r.process(ref) }
    }

    @Test func peerOfBadDescriptors() throws {
        #expect(throws: PlatformError.noProcess) { try r.peerOf(fd: -1) }
        var p: [Int32] = [0, 0]
        pipe(&p)
        defer { close(p[0]); close(p[1]) }
        #expect(throws: PlatformError.noProcess) { try r.peerOf(fd: p[0]) }
    }

    /// Sockets that are not a connected Unix-domain stream. A UDP socket
    /// answers getsockopt(level 0, option 6) with success and a 4-byte
    /// value (IPPROTO_IP == SOL_LOCAL == 0): a resolver that does not check
    /// the returned length would read a mostly zero "token".
    @Test func peerOfRejectsSocketsWithoutAPeerToken() throws {
        let udp = socket(AF_INET, SOCK_DGRAM, 0)
        try #require(udp >= 0)
        defer { close(udp) }
        #expect(throws: PlatformError.noProcess) { try r.peerOf(fd: udp) }

        let unconnected = socket(AF_UNIX, SOCK_STREAM, 0)
        try #require(unconnected >= 0)
        defer { close(unconnected) }
        #expect(throws: PlatformError.noProcess) { try r.peerOf(fd: unconnected) }

        let f = try PeerFixture()
        #expect(throws: PlatformError.noProcess) { try r.peerOf(fd: f.listener) } // a listener has no peer

        let closed = socket(AF_UNIX, SOCK_STREAM, 0)
        close(closed)
        #expect(throws: PlatformError.noProcess) { try r.peerOf(fd: closed) }
        #expect(throws: PlatformError.noProcess) { try r.peerOf(fd: .max) }
    }

    /// The peer of one end of a socketpair is this very process.
    @Test func peerOfASocketpairIsThisProcess() throws {
        var sv: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) == 0)
        defer { close(sv[0]); close(sv[1]) }
        let ref = try r.peerOf(fd: sv[0])
        #expect(ref.pid == getpid() && ref.generation == KernelProc.info(getpid())?.generation && ref.generation != 0)
        let rec = try r.process(ref)
        #expect(rec.ref == ref && rec.uid == Int64(getuid()) && rec.parentPid == getppid())
    }

    /// Spec 4.1 step 1: a recycled PID looks like a token whose PID is live
    /// but whose pidversion is not the occupant's. KERN_PROC_PID still
    /// answers for the PID, so only the audit-token liveness check tells the
    /// peer from the new occupant: PeerOf must fail and never describe the
    /// occupant. The token's PID and pidversion are forged separately, each
    /// onto a live process; the unmodified token still resolves before and
    /// after.
    @Test func peerTokenOfARecycledPIDIsNoProcess() throws {
        var sv: [Int32] = [-1, -1]
        try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &sv) == 0)
        defer { close(sv[0]); close(sv[1]) }
        let tok = try #require(ProcessResolver.peerToken(fd: sv[0]))
        #expect(Int32(bitPattern: tok.val.5) == getpid())
        let me = try r.peer(token: tok)
        #expect(me.pid == getpid() && me.generation == KernelProc.info(getpid())?.generation)

        var stalePidversion = tok
        stalePidversion.val.7 &+= 1
        try #require(KernelProc.info(getpid()) != nil) // the PID itself is live
        #expect(throws: PlatformError.noProcess) { try r.peer(token: stalePidversion) }

        let s = try Sleeper()
        defer { s.kill() }
        var otherLivePid = tok
        otherLivePid.val.5 = UInt32(bitPattern: s.pid)
        try #require(KernelProc.info(s.pid)?.zombie == false)
        #expect(throws: PlatformError.noProcess) { try r.peer(token: otherLivePid) }

        // The same through a real peer: nc is alive, its token with another
        // pidversion is nobody.
        let f = try PeerFixture()
        let ncTok = try #require(ProcessResolver.peerToken(fd: f.conn))
        #expect(Int32(bitPattern: ncTok.val.5) == f.nc.processIdentifier)
        var staleNc = ncTok
        staleNc.val.7 &+= 1
        try #require(f.nc.isRunning)
        #expect(throws: PlatformError.noProcess) { try r.peer(token: staleNc) }
        #expect(try r.peer(token: ncTok).pid == f.nc.processIdentifier)

        #expect(try r.peer(token: tok) == me)
        #expect(try r.peerOf(fd: sv[1]) == me)
    }

    @Test func fullRefsAreExact() throws {
        let s = try Sleeper()
        let ref = try r.process(ProcessRef(pid: s.pid, generation: 0)).ref
        #expect(ref.generation != 0)
        for g in [ref.generation + 1, ref.generation - 1, ref.generation ^ 1] {
            #expect(throws: PlatformError.noProcess) { try r.process(ProcessRef(pid: s.pid, generation: g)) }
        }
        let child = try r.process(ref)
        let parent = try r.process(ProcessRef(pid: child.parentPid, generation: 0))
        #expect(parent.pid == getpid() && parent.startMicros <= child.startMicros)
        s.kill()
        #expect(throws: PlatformError.noProcess) { try r.process(ref) }
        for bad in [ProcessRef(pid: 0, generation: 0), ProcessRef(pid: -1, generation: 1), ProcessRef(pid: 0, generation: 1),
                    ProcessRef(pid: .max, generation: 0), ProcessRef(pid: .min, generation: .max)] {
            #expect(throws: PlatformError.noProcess) { try r.process(bad) }
        }
    }

    /// A Sleeper's record carries what the kernel says: path, arguments,
    /// cwd, code identity read from the live process.
    @Test func recordDescribesTheLiveProcess() throws {
        let s = try Sleeper()
        defer { s.kill() }
        let rec = try r.process(ProcessRef(pid: s.pid, generation: 0))
        #expect(rec.pid == s.pid && rec.generation == KernelProc.info(s.pid)?.generation)
        #expect(rec.path == "/bin/sleep" && rec.args == ["/bin/sleep", "60"])
        #expect(!rec.cwd.isEmpty && rec.cwd == KernelProc.cwd(getpid())) // inherited from this process
        #expect(rec.code.signed && rec.code.apple && !rec.code.adHoc && rec.code.signingId == "com.apple.sleep")
        #expect(rec.parentPid == getpid() && rec.parentGeneration == 0 && rec.uid == Int64(getuid()))
    }

    /// A dead child that nobody has reaped yet still has a kernel record:
    /// it is not a process for nazar.
    @Test func zombieIsNoProcess() throws {
        var pid: pid_t = 0
        let argv: [UnsafeMutablePointer<CChar>?] = [strdup("/usr/bin/true"), nil]
        defer { for a in argv { free(a) } }
        try #require(posix_spawn(&pid, "/usr/bin/true", nil, nil, argv, nil) == 0 && pid > 0)
        var zombie: KProc?
        for _ in 0..<500 {
            if let k = KernelProc.info(pid), k.zombie { zombie = k; break }
            usleep(10_000)
        }
        defer { var st: Int32 = 0; _ = waitpid(pid, &st, 0) }
        let z = try #require(zombie)
        #expect(throws: PlatformError.noProcess) { try r.process(ProcessRef(pid: pid, generation: 0)) }
        #expect(throws: PlatformError.noProcess) { try r.process(ProcessRef(pid: pid, generation: z.generation)) }
        #expect(r.responsibleFor(ProcessRef(pid: pid, generation: z.generation)) == nil)
        let fake = ProcessRecord(pid: pid, generation: z.generation, parentPid: getpid(), parentGeneration: 0, uid: Int64(getuid()),
                                 startMicros: z.startMicros, path: "/usr/bin/true", args: [], cwd: "/", code: CodeIdentity())
        #expect(ProcessResolver(gui: AllApps()).appFor([fake]) == nil)
    }

    /// Spike S3: the parent walk uses KERN_PROC_PID, which also works for
    /// root-owned ancestors (such as /usr/bin/login); every step from this
    /// process resolves, and the walk ends at launchd (pid 1, parent 0).
    @Test func parentWalkReachesLaunchd() throws {
        var rec = try r.process(ProcessRef(pid: getpid(), generation: 0))
        var steps = 0
        while rec.pid != 1 {
            steps += 1
            try #require(steps < 64, "parent walk did not reach launchd")
            #expect(rec.parentPid > 0)
            let parent = try r.process(ProcessRef(pid: rec.parentPid, generation: 0))
            #expect(parent.startMicros <= rec.startMicros)
            rec = parent
        }
        #expect(rec.parentPid == 0 && rec.uid == 0 && rec.generation != 0 && rec.path == "/sbin/launchd")
    }

    @Test func appForUsesTheLiveProcessNeverTheRecord() throws {
        let finder = try #require(NSWorkspace.shared.runningApplications.first { $0.bundleIdentifier == "com.apple.finder" },
                                  "Finder is not running (no GUI session?)")
        let rec = try r.process(ProcessRef(pid: finder.processIdentifier, generation: 0))
        let app = try #require(r.appFor([rec]))
        #expect(app.bundleId == "com.apple.finder" && app.code.apple && app.pid == rec.pid && app.generation == rec.generation)
        var forgedCode = rec
        forgedCode.code = CodeIdentity(signed: true, teamId: "FORGED0000", signingId: "x", apple: false, adHoc: false)
        #expect(r.appFor([forgedCode])?.code.apple == true) // fresh identity, not the record's
        var wrongGen = rec
        wrongGen.generation += 1
        #expect(r.appFor([wrongGen]) == nil)
        let s = try Sleeper()
        var sleeper = try r.process(ProcessRef(pid: s.pid, generation: 0))
        #expect(r.appFor([sleeper]) == nil)
        sleeper.path = "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
        #expect(r.appFor([sleeper]) == nil)
        #expect(r.appFor([]) == nil)
        #expect(r.appFor([sleeper, rec])?.bundleId == "com.apple.finder") // first app in the chain
        #expect(ProcessResolver(gui: NoApps()).appFor([rec]) == nil)
    }

    /// Through the GUIAppLookup seam: even a lookup that calls everything an
    /// app cannot make a dead process, a wrong generation or a PID-only
    /// record an app, and the code identity is the live process's own.
    @Test func appForChecksLivenessWhateverTheLookupSays() throws {
        let gui = AllApps()
        let rr = ProcessResolver(gui: gui)
        let s = try Sleeper()
        var rec = try rr.process(ProcessRef(pid: s.pid, generation: 0))
        rec.code = CodeIdentity(signed: true, teamId: "FORGED0000", signingId: "com.example.claimed")
        let app = try #require(rr.appFor([rec]))
        #expect(app.bundleId == "com.example.claimed" && app.name == "Claimed")
        #expect(app.pid == s.pid && app.generation == rec.generation)
        #expect(app.code.apple && app.code.signingId == "com.apple.sleep" && app.code.teamId != "FORGED0000")

        var pidOnly = rec
        pidOnly.generation = 0
        #expect(rr.appFor([pidOnly]) == nil)
        var wrongGen = rec
        wrongGen.generation ^= 1
        #expect(rr.appFor([wrongGen]) == nil)
        var noPid = rec
        noPid.pid = 0
        #expect(rr.appFor([noPid]) == nil)
        var negPid = rec
        negPid.pid = -1
        #expect(rr.appFor([negPid]) == nil)

        s.kill()
        #expect(rr.appFor([rec]) == nil)
        #expect(!gui.asked.contains(0) && !gui.asked.contains(-1))
    }

    /// The real lookup: Finder is an app; a command-line tool, this test
    /// process and non-PIDs are not.
    @Test func runningAppLookup() throws {
        let look = RunningAppLookup()
        let finder = try #require(NSWorkspace.shared.runningApplications.first { $0.bundleIdentifier == "com.apple.finder" },
                                  "Finder is not running (no GUI session?)")
        let f = try #require(look.app(pid: finder.processIdentifier))
        #expect(f.bundleId == "com.apple.finder" && !f.name.isEmpty)
        let s = try Sleeper()
        defer { s.kill() }
        #expect(look.app(pid: s.pid) == nil)
        #expect(look.app(pid: getpid()) == nil)
        #expect(look.app(pid: 0) == nil)
        #expect(look.app(pid: -1) == nil)
        #expect(look.app(pid: .max) == nil)
    }

    /// Platform.Apps through the seam (Milestone 7): the lookup names
    /// candidates; the resolver keeps only live processes, under their full
    /// ref, that it would call apps, with the live code identity.
    @Test func appsKeepsOnlyLiveCandidatesTheResolverAccepts() throws {
        let gui = AllApps()
        let rr = ProcessResolver(gui: gui)
        #expect(rr.apps().isEmpty)
        let s = try Sleeper()
        gui.running = [s.pid, 0, -1, .max]
        let apps = rr.apps()
        #expect(apps.count == 1 && apps[0].pid == s.pid && apps[0].generation == KernelProc.info(s.pid)?.generation)
        #expect(apps[0].bundleId == "com.example.claimed" && apps[0].code.apple && apps[0].code.signingId == "com.apple.sleep")
        let rec = try rr.process(ProcessRef(pid: s.pid, generation: 0))
        #expect(apps == [rr.appFor([rec])].compactMap { $0 })
        s.kill()
        #expect(rr.apps().isEmpty)
        #expect(ProcessResolver(gui: NoApps()).apps().isEmpty)
    }

    /// The real lookup: Finder is among the running regular apps, apps()
    /// answers for it what appFor answers for its record, and this test
    /// process (not an app) is not listed.
    @Test func runningAppsIncludeFinder() throws {
        let finder = try #require(NSWorkspace.shared.runningApplications.first { $0.bundleIdentifier == "com.apple.finder" },
                                  "Finder is not running (no GUI session?)")
        #expect(RunningAppLookup().regularApps().contains(finder.processIdentifier))
        let apps = r.apps()
        let app = try #require(apps.first { $0.pid == finder.processIdentifier })
        let rec = try r.process(ProcessRef(pid: finder.processIdentifier, generation: 0))
        #expect(app == r.appFor([rec]))
        #expect(!apps.contains { $0.pid == getpid() })
        #expect(apps.allSatisfy { $0.generation != 0 && !$0.bundleId.isEmpty })
    }

    @Test func responsibleFor() throws {
        let me = try r.process(ProcessRef(pid: getpid(), generation: 0)).ref
        #expect((r.responsibleFor(me) ?? 0) > 0)
        #expect(r.responsibleFor(ProcessRef(pid: 0, generation: 0)) == nil)
        #expect(r.responsibleFor(ProcessRef(pid: .max, generation: 1)) == nil)
        #expect(r.responsibleFor(ProcessRef(pid: me.pid, generation: me.generation + 1)) == nil)
    }

    /// Display only, but never for a process that is gone.
    @Test func responsibleForADeadProcessIsNil() throws {
        let s = try Sleeper()
        let ref = try r.process(ProcessRef(pid: s.pid, generation: 0)).ref
        #expect((r.responsibleFor(ref) ?? 0) > 0)
        #expect((r.responsibleFor(ProcessRef(pid: s.pid, generation: 0)) ?? 0) > 0)
        s.kill()
        #expect(r.responsibleFor(ref) == nil)
        #expect(r.responsibleFor(ProcessRef(pid: -1, generation: 0)) == nil)
    }
}

final class FakeLocator: AppLocator {
    var byId: [String: [URL]] = [:]
    func urls(bundleId: String) -> [URL] { byId[bundleId] ?? [] }
}

@Suite struct InstalledAppsTests {
    func apps(_ urls: [String], codes: [String: CodeIdentity], ids: [String: String] = [:]) -> InstalledApps {
        let loc = FakeLocator()
        loc.byId["com.example.app"] = urls.map { URL(fileURLWithPath: $0) }
        return InstalledApps(locator: loc, inspect: { url in
            guard let c = codes[url.path] else { return nil }
            return (ids[url.path] ?? "com.example.app", c)
        }, roots: ["/Applications/", "/Users/u/Applications/"])
    }

    let teamA = CodeIdentity(signed: true, teamId: "AAAAAAAAAA", signingId: "com.example.app")
    let teamB = CodeIdentity(signed: true, teamId: "BBBBBBBBBB", signingId: "com.example.app")

    @Test func onePinnableTeam() throws {
        let a = apps(["/Users/u/Applications/E.app", "/Applications/E.app"],
                     codes: ["/Users/u/Applications/E.app": teamA, "/Applications/E.app": teamA])
        let b = try a.installedApp("com.example.app")
        #expect(b.path == "/Applications/E.app" && b.code.teamId == "AAAAAAAAAA")
    }

    @Test func differentTeamsAreAmbiguous() {
        let a = apps(["/Applications/E.app", "/Users/u/Applications/E.app"],
                     codes: ["/Applications/E.app": teamA, "/Users/u/Applications/E.app": teamB])
        #expect(throws: PlatformError.ambiguous) { try a.installedApp("com.example.app") }
        var adhoc = teamA
        adhoc.adHoc = true
        let c = apps(["/Applications/E.app", "/Users/u/Applications/E.app"],
                     codes: ["/Applications/E.app": teamA, "/Users/u/Applications/E.app": adhoc])
        #expect(throws: PlatformError.ambiguous) { try c.installedApp("com.example.app") }
    }

    /// An Apple-signed copy and a team-signed copy are two teams; so are a
    /// signed and an unsigned copy.
    @Test func appleAndUnsignedCopiesAreTeamsToo() {
        let apple = CodeIdentity(signed: true, signingId: "com.example.app", apple: true)
        let a = apps(["/Applications/E.app", "/Users/u/Applications/E.app"],
                     codes: ["/Applications/E.app": apple, "/Users/u/Applications/E.app": teamA])
        #expect(throws: PlatformError.ambiguous) { try a.installedApp("com.example.app") }
        let b = apps(["/Applications/E.app", "/Users/u/Applications/E.app"],
                     codes: ["/Applications/E.app": teamA, "/Users/u/Applications/E.app": CodeIdentity()])
        #expect(throws: PlatformError.ambiguous) { try b.installedApp("com.example.app") }
    }

    @Test func outsideRootsMismatchedIdsAndAbsent() {
        let a = apps(["/Users/u/Downloads/E.app", "/Applications/Other.app"],
                     codes: ["/Users/u/Downloads/E.app": teamA, "/Applications/Other.app": teamA],
                     ids: ["/Applications/Other.app": "com.example.other"])
        #expect(throws: PlatformError.notFound) { try a.installedApp("com.example.app") }
        #expect(throws: PlatformError.notFound) { try a.installedApp("com.example.absent") }
        #expect(throws: PlatformError.invalid("bundle id")) { try a.installedApp("") }
        #expect(throws: PlatformError.invalid("bundle id")) { try a.installedApp("a b") }
    }

    /// Paths that only look as if they were under an install root: a
    /// sibling folder sharing the prefix, and `..` climbing out of one.
    @Test func lookalikeAndTraversingPathsAreOutsideTheRoots() {
        let paths = ["/ApplicationsEvil/E.app", "/Applications/../Users/u/Downloads/E.app",
                     "/Users/u/Applications/../Downloads/E.app"]
        var codes: [String: CodeIdentity] = [:]
        for p in paths { codes[p] = teamA }
        codes["/Users/u/Downloads/E.app"] = teamA // whatever form inspect is handed
        let a = apps(paths, codes: codes)
        #expect(throws: PlatformError.notFound) { try a.installedApp("com.example.app") }
    }

    /// A root that is itself a symlink (an `~/Applications` pointing
    /// elsewhere) is resolved like the bundle paths are, so a bundle reached
    /// through the link is under the root; a sibling folder is not.
    @Test func symlinkedRootsAreResolved() throws {
        let fm = FileManager.default
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("nzia-\(getpid())-\(UInt32.random(in: 0...UInt32.max))")
        let real = tmp.appendingPathComponent("real")
        let other = tmp.appendingPathComponent("other")
        let link = tmp.appendingPathComponent("apps")
        // The bundles exist (empty folders): Foundation resolves symlinks
        // only along a path that is there, as every installed app's is.
        try fm.createDirectory(at: real.appendingPathComponent("E.app"), withIntermediateDirectories: true)
        try fm.createDirectory(at: other.appendingPathComponent("E.app"), withIntermediateDirectories: true)
        try fm.createSymbolicLink(at: link, withDestinationURL: real)
        defer { try? fm.removeItem(at: tmp) }
        let resolvedReal = real.resolvingSymlinksInPath().path
        #expect(InstalledApps.resolvedRoot(link.path) == resolvedReal + "/")
        #expect(InstalledApps.resolvedRoot(link.path + "/") == resolvedReal + "/")
        #expect(InstalledApps.resolvedRoot("/Applications/") == "/Applications/")
        #expect(InstalledApps.resolvedRoot("/Users/u/Applications") == "/Users/u/Applications/")

        let loc = FakeLocator()
        loc.byId["com.example.app"] = [link.appendingPathComponent("E.app"), other.appendingPathComponent("E.app")]
        var inspected: [String] = []
        let a = InstalledApps(locator: loc, inspect: { url in
            inspected.append(url.path)
            return ("com.example.app", self.teamA)
        }, roots: [link.path + "/"])
        let rec = try a.installedApp("com.example.app")
        #expect(rec.path == resolvedReal + "/E.app" && rec.code == teamA)
        #expect(inspected == [resolvedReal + "/E.app"]) // the sibling folder was never a candidate
    }

    /// A bundle under a root that cannot be inspected (no Info.plist, no
    /// readable signature) does not count.
    @Test func uninspectableBundlesDoNotCount() throws {
        let a = apps(["/Applications/E.app"], codes: [:])
        #expect(throws: PlatformError.notFound) { try a.installedApp("com.example.app") }
        let b = apps(["/Applications/Broken.app", "/Users/u/Applications/E.app"],
                     codes: ["/Users/u/Applications/E.app": teamB])
        let rec = try b.installedApp("com.example.app")
        #expect(rec.path == "/Users/u/Applications/E.app" && rec.bundleId == "com.example.app" && rec.code == teamB)
    }

    @Test func bundleIdsAreValidated() {
        let a = apps([], codes: [:])
        for bad in [".com.example", "-x", "com.example/app", "com.example\napp", "../x", "com.exämple",
                    String(repeating: "a", count: 256), "com.example.app\0", "com.example.app\n", " com.example.app"] {
            #expect(throws: PlatformError.invalid("bundle id")) { try a.installedApp(bad) }
        }
        for ok in ["a", "com.example.app", "com.Example-App.2", String(repeating: "a", count: 255)] {
            #expect(throws: PlatformError.notFound) { try a.installedApp(ok) }
        }
    }

    @Test func teamAndRoots() {
        #expect(InstalledApps.team(teamA) == "AAAAAAAAAA")
        #expect(InstalledApps.team(CodeIdentity(signed: true, teamId: "AAAAAAAAAA", apple: true)) == "apple")
        var adhoc = teamA
        adhoc.adHoc = true
        #expect(InstalledApps.team(adhoc) == "")
        #expect(InstalledApps.team(CodeIdentity(signed: false, teamId: "AAAAAAAAAA")) == "")
        #expect(InstalledApps.team(CodeIdentity()) == "")
        #expect(InstalledApps.defaultRoots(home: "/Users/x") == ["/Applications/", "/System/Applications/", "/Users/x/Applications/"])
    }

    @Test func realLaunchServices() throws {
        let real = InstalledApps()
        let t = try real.installedApp("com.apple.TextEdit")
        #expect(t.path.hasSuffix("/TextEdit.app") && InstalledApps.team(t.code) == "apple")
        #expect(throws: PlatformError.notFound) { try real.installedApp("dev.nazar.test.absent.\(UInt32.random(in: 0...UInt32.max))") }
    }
}
