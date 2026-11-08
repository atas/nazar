package caller

import (
	"testing"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Milestone 5: what the dialog, the audit chain and `nazar status`
// call a process. Display only; matching keeps using code signatures.
func TestProcName(t *testing.T) {
	adHoc := platform.CodeIdentity{Signed: true, AdHoc: true, SigningID: "com.anthropic.claude-code"}
	unsigned := platform.CodeIdentity{}
	cases := []struct {
		name    string
		p       platform.ProcessInfo
		want    string
		deleted bool
	}{
		{"plain file name", platform.ProcessInfo{Path: "/usr/bin/ssh", Code: fake.AppleCode("com.apple.openssh"), Comm: "ssh"}, "ssh", false},
		{"Claude Code's version-named file", platform.ProcessInfo{Path: "/Users/u/.local/share/claude/versions/2.1.299", Code: fake.ClaudeCode, Comm: "2.1.299"}, "claude-code", false},
		{"deleted after an update", platform.ProcessInfo{Path: "", Code: fake.ClaudeCode, Comm: "2.1.299"}, "claude-code", true},
		{"deleted, unsigned: p_comm", platform.ProcessInfo{Path: "", Code: unsigned, Comm: "mytool"}, "mytool", true},
		{"deleted, Apple-signed: p_comm", platform.ProcessInfo{Path: "", Code: fake.AppleCode("com.apple.zsh"), Comm: "zsh"}, "zsh", true},
		// An ad-hoc signature proves nothing: its identifier is never shown.
		{"ad hoc, version-named", platform.ProcessInfo{Path: "/tmp/2.1.299", Code: adHoc, Comm: "2.1.299"}, "2.1.299", false},
		{"ad hoc, deleted", platform.ProcessInfo{Path: "", Code: adHoc, Comm: "x"}, "x", true},
		// A readable file name wins over the identifier, signed or not.
		{"signed, readable name", platform.ProcessInfo{Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: fake.ITermCode}, "iTerm2", false},
		{"identifier without dots", platform.ProcessInfo{Path: "/opt/x/1.0", Code: platform.CodeIdentity{Signed: true, TeamID: "T1", SigningID: "tool"}}, "tool", false},
		{"identifier ending in a dot", platform.ProcessInfo{Path: "/opt/x/1.0", Code: platform.CodeIdentity{Signed: true, TeamID: "T1", SigningID: "com.x."}}, "com.x.", false},
		{"version with a v", platform.ProcessInfo{Path: "/opt/x/v2.0.1-beta", Code: fake.ClaudeCode}, "claude-code", false},
		{"nothing known", platform.ProcessInfo{}, "", true},
	}
	for _, c := range cases {
		name, deleted := ProcName(c.p)
		if name != c.want || deleted != c.deleted {
			t.Errorf("%s: ProcName = %q, %v; want %q, %v", c.name, name, deleted, c.want, c.deleted)
		}
	}
	if got := DisplayName(platform.ProcessInfo{Code: fake.ClaudeCode, Comm: "2.1.299"}); got != "claude-code (file deleted)" {
		t.Fatalf("DisplayName = %q", got)
	}
}

// The chain line shows readable names, and the deleted mark outside the
// quoting, so a crafted p_comm still can't forge a hop.
func TestSummaryUsesDisplayNames(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{},
		fake.Proc{Path: "/Users/u/.local/share/claude/versions/2.1.299", Args: []string{"claude"}, Code: fake.ClaudeCode},
		fake.SSHProc("h"))
	claude, _ := f.Process(tab.Procs[0])
	r := &Resolver{P: f}
	if got := r.Resolve(tab.Peer()).Summary(); got != "iTerm2 → bash → claude-code → ssh" {
		t.Fatalf("summary %q", got)
	}
	claude.Path = "" // the update deleted the file
	f.SetProcess(claude)
	if got := r.Resolve(tab.Peer()).Summary(); got != "iTerm2 → bash → claude-code (file deleted) → ssh" {
		t.Fatalf("summary %q", got)
	}
	claude.Code, claude.Comm = platform.CodeIdentity{}, "x → ssh"
	f.SetProcess(claude)
	if got, want := r.Resolve(tab.Peer()).Summary(), `iTerm2 → bash → "x → ssh" (file deleted) → ssh`; got != want {
		t.Fatalf("summary %q, want %q", got, want)
	}
}

// Edge cases of the version-shaped rule: only a
// file name that is a version number gives way to the signing identifier;
// a program name that merely contains digits is kept.
func TestProcNameVersionShapes(t *testing.T) {
	team := func(id string) platform.CodeIdentity {
		return platform.CodeIdentity{Signed: true, TeamID: "T1", SigningID: id}
	}
	cases := []struct {
		path string
		code platform.CodeIdentity
		want string
	}{
		{"/opt/x/2.1.299-arm64", team("com.x.tool"), "tool"},
		{"/opt/x/1_2_3", team("com.x.tool"), "tool"},
		{"/opt/x/42", team("com.x.tool"), "tool"},
		{"/usr/local/bin/python3.12", team("org.python.python3"), "python3.12"},
		{"/usr/local/bin/7z", team("org.7zip.7z"), "7z"},
		{"/opt/x/v", team("com.x.tool"), "v"},
		{"/opt/x/1.0 copy", team("com.x.tool"), "1.0 copy"},
		// Apple's identifiers say nothing more than the file name.
		{"/usr/libexec/1.0", fake.AppleCode("com.apple.something"), "1.0"},
		// Signed but with no team (not Developer ID): the file name stays.
		{"/opt/x/1.0", platform.CodeIdentity{Signed: true, SigningID: "com.x.tool"}, "1.0"},
		// Team-signed with an empty identifier: nothing better to show.
		{"/opt/x/1.0", team(""), "1.0"},
	}
	for _, c := range cases {
		name, deleted := ProcName(platform.ProcessInfo{Path: c.path, Code: c.code, Comm: "comm"})
		if name != c.want || deleted {
			t.Errorf("ProcName(%q, %+v) = %q, %v; want %q, false", c.path, c.code, name, deleted, c.want)
		}
	}
	// A present path is never "deleted", whatever p_comm says.
	if _, deleted := ProcName(platform.ProcessInfo{Path: "/usr/bin/ssh", Comm: ""}); deleted {
		t.Error("a process with a path is reported deleted")
	}
	// Deleted with no p_comm either: an empty name, still marked.
	if got := DisplayName(platform.ProcessInfo{Comm: ""}); got != DeletedMark {
		t.Errorf("DisplayName of nothing = %q, want %q", got, DeletedMark)
	}
	if DeletedMark != " (file deleted)" {
		t.Errorf("DeletedMark = %q", DeletedMark)
	}
}

// Attack: a signing identifier is chosen by whoever signs the code. A
// team-signed program whose identifier ends in a crafted component must not
// forge hops, the separator or the deleted mark in the chain line.
func TestSummaryQuotesCraftedNames(t *testing.T) {
	f := fake.New(t0)
	crafted := platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM01", SigningID: "com.evil.claude → ssh"}
	tab := f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/opt/evil/1.0", Args: []string{"x"}, Code: crafted}, fake.SSHProc("h"))
	r := &Resolver{P: f}
	if got, want := r.Resolve(tab.Peer()).Summary(), `iTerm2 → bash → "claude → ssh" → ssh`; got != want {
		t.Fatalf("summary %q, want %q", got, want)
	}
	// A file literally named "claude-code (file deleted)" is quoted, so it
	// can't pass for a deleted claude-code, whose mark is outside quotes.
	f2 := fake.New(t0)
	tab2 := f2.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/tmp/claude-code (file deleted)", Code: fake.Unsigned}, fake.SSHProc("h"))
	if got, want := (&Resolver{P: f2}).Resolve(tab2.Peer()).Summary(), `iTerm2 → bash → "claude-code (file deleted)" → ssh`; got != want {
		t.Fatalf("summary %q, want %q", got, want)
	}
	// A crafted p_comm with a newline, for a deleted file, stays one quoted hop.
	info, _ := f2.Process(tab2.Procs[0])
	info.Path, info.Comm = "", "a\nb"
	f2.SetProcess(info)
	if got, want := (&Resolver{P: f2}).Resolve(tab2.Peer()).Summary(), `iTerm2 → bash → "a\nb" (file deleted) → ssh`; got != want {
		t.Fatalf("summary %q, want %q", got, want)
	}
}

// Command's wrapper check is steered by the executable's file name only,
// never by a display name: a team-signed program whose identifier ends in
// "bash" (shown as "bash") is still the command, and so is a deleted
// program whose p_comm is "ssh".
func TestWrappersIgnoreDisplayNames(t *testing.T) {
	f := fake.New(t0)
	fakeShell := fake.Proc{Path: "/opt/evil/1.0", Args: []string{"evil", "--x"}, Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM01", SigningID: "com.evil.bash"}}
	tab := f.ITermTab(platform.ProcessRef{}, fakeShell, fake.SSHProc("h"))
	r := &Resolver{P: f}
	c := r.Resolve(tab.Peer())
	if got := c.Summary(); got != "iTerm2 → bash → bash → ssh" {
		t.Fatalf("summary %q", got)
	}
	cmd, ok := c.Command()
	if !ok || cmd.Ref != tab.Procs[0] {
		t.Fatalf("Command = %v, %v; want the program shown as bash (%v): wrappers are judged by the file name", cmd.Ref, ok, tab.Procs[0])
	}

	f2 := fake.New(t0)
	tab2 := f2.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/tmp/tool", Args: []string{"tool"}, Code: fake.Unsigned}, fake.SSHProc("h"))
	info, _ := f2.Process(tab2.Procs[0])
	info.Path, info.Comm = "", "ssh"
	f2.SetProcess(info)
	c2 := (&Resolver{P: f2}).Resolve(tab2.Peer())
	if cmd, ok := c2.Command(); !ok || cmd.Ref != tab2.Procs[0] {
		t.Fatalf("Command = %v, %v; want the deleted program whose p_comm is ssh (%v)", cmd.Ref, ok, tab2.Procs[0])
	}
	if got := c2.Summary(); got != "iTerm2 → bash → ssh (file deleted) → ssh" {
		t.Fatalf("summary %q", got)
	}
}

// fake.Proc.Comm defaults to the file name, cut to 16 bytes as on macOS;
// an explicit Comm is kept.
func TestFakeCommDefaults(t *testing.T) {
	f := fake.New(t0)
	short := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/usr/bin/ssh"})
	long := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/opt/x/a-very-long-program-name"})
	set := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/opt/x/2.1.299", Comm: "claude"})
	for ref, want := range map[platform.ProcessRef]string{short: "ssh", long: "a-very-long-prog", set: "claude"} {
		info, err := f.Process(ref)
		if err != nil || info.Comm != want {
			t.Errorf("Process(%v).Comm = %q, %v; want %q", ref, info.Comm, err, want)
		}
	}
}
