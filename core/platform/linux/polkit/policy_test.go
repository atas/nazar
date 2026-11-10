//go:build linux

package polkit

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"

	"github.com/atas/nazar/core/platform"
)

// The packaging file nazar installs for polkit, as the authority reads it:
// one action, ours, whose message is the request's own text and whose
// three defaults all ask the user to authenticate as themselves. No
// default is ever `yes`: that would approve without a prompt. The action
// names its owner, the user, because polkitd takes a message detail only
// from root or an owner; the packaging file carries a placeholder that
// `nazar install --system` (and the test image) fill in.
type policyConfig struct {
	Actions []struct {
		ID       string `xml:"id,attr"`
		Message  string `xml:"message"`
		Defaults struct {
			Any      string `xml:"allow_any"`
			Inactive string `xml:"allow_inactive"`
			Active   string `xml:"allow_active"`
		} `xml:"defaults"`
		Annotations []struct {
			Key   string `xml:"key,attr"`
			Value string `xml:",chardata"`
		} `xml:"annotate"`
	} `xml:"action"`
}

func (c policyConfig) owner() (string, bool) {
	for _, an := range c.Actions[0].Annotations {
		if an.Key == OwnerAnnotation {
			return an.Value, true
		}
	}
	return "", false
}

func policyFile(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "packaging", "linux", "dev.nazar.authenticate.policy")
	return filepath.Clean(path)
}

func TestPolicyFile(t *testing.T) {
	data, err := os.ReadFile(policyFile(t))
	if err != nil {
		t.Fatal(err)
	}
	var cfg policyConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Actions) != 1 {
		t.Fatalf("%d actions, want 1", len(cfg.Actions))
	}
	a := cfg.Actions[0]
	if a.ID != ActionID {
		t.Errorf("action id = %q, want %q", a.ID, ActionID)
	}
	if want := "$(" + PromptDetail + ")"; a.Message != want {
		t.Errorf("message = %q, want %q", a.Message, want)
	}
	for name, got := range map[string]string{"allow_any": a.Defaults.Any, "allow_inactive": a.Defaults.Inactive, "allow_active": a.Defaults.Active} {
		if got != "auth_self" {
			t.Errorf("%s = %q, want auth_self", name, got)
		}
	}
	owner, ok := cfg.owner()
	if !ok {
		t.Fatalf("no %s annotation: polkitd refuses the prompt text from a caller that is not an owner", OwnerAnnotation)
	}
	if owner != OwnerPlaceholder {
		t.Errorf("owner = %q, want the placeholder %q (the installer fills it in)", owner, OwnerPlaceholder)
	}
	if n := strings.Count(string(data), OwnerPlaceholder); n != 1 {
		t.Errorf("the placeholder appears %d times, want 1", n)
	}
}

// The file with the placeholder filled in, as the installer and the test
// image (test/linux/run.sh) write it, names the user as the owner.
func TestPolicyFileWithOwner(t *testing.T) {
	data, err := os.ReadFile(policyFile(t))
	if err != nil {
		t.Fatal(err)
	}
	const owner = "unix-user:nazartest"
	filled := strings.ReplaceAll(string(data), OwnerPlaceholder, owner)
	var cfg policyConfig
	if err := xml.Unmarshal([]byte(filled), &cfg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Actions) != 1 {
		t.Fatalf("%d actions, want 1", len(cfg.Actions))
	}
	if got, _ := cfg.owner(); got != owner {
		t.Errorf("owner = %q, want %q", got, owner)
	}
	if strings.Contains(filled, OwnerPlaceholder) {
		t.Error("the placeholder is still there")
	}
}

func TestPromptText(t *testing.T) {
	p := platform.Prompt{Title: `iTerm2 wants to use key "github"`, Lines: []string{"git push", "app: iTerm2"}, Timeout: time.Minute}
	if got, want := PromptText(p), "iTerm2 wants to use key \"github\"\ngit push\napp: iTerm2"; got != want {
		t.Errorf("PromptText = %q, want %q", got, want)
	}
	if got := PromptText(platform.Prompt{Title: "only a title"}); got != "only a title" {
		t.Errorf("title only = %q", got)
	}
}

// A very long request is cut to within 1000 bytes, on a character
// boundary, so polkit never gets an invalid string and the title is always
// there. The cut is visible: the line ends with an ellipsis.
func TestPromptTextIsBounded(t *testing.T) {
	long := platform.Prompt{Title: "t", Lines: []string{strings.Repeat("é", 800)}}
	got := PromptText(long)
	if len(got) > maxPromptBytes {
		t.Fatalf("len = %d, want at most %d", len(got), maxPromptBytes)
	}
	if !utf8.ValidString(got) {
		t.Fatal("cut inside a character")
	}
	if !strings.HasPrefix(got, "t\né") {
		t.Fatalf("prefix lost: %q", got[:10])
	}
	if !strings.HasSuffix(got, "é"+ellipsis) {
		t.Fatalf("the cut line does not end with an ellipsis: %q", got[len(got)-10:])
	}
	if len(got) < maxLineBytes-utf8.UTFMax {
		t.Fatalf("len = %d, cut too short", len(got))
	}
}

// A long text that fits is not cut at all.
func TestPromptTextFitsUncut(t *testing.T) {
	line := strings.Repeat("x", 900)
	if got, want := PromptText(platform.Prompt{Title: "t", Lines: []string{line}}), "t\n"+line; got != want {
		t.Fatalf("PromptText cut a text that fits: %d bytes, want %d", len(got), len(want))
	}
}

// The config approval lists every change and then what the change
// loosens (core/daemon). With more changes than fit, the loosening lines
// are still shown, and the text says how many changes are not.
func TestPromptTextKeepsTheLoosening(t *testing.T) {
	var lines []string
	for i := 0; i < 40; i++ {
		lines = append(lines, fmt.Sprintf("sshKeys.key-%02d.rules[0].gate: dialog -> login", i))
	}
	const looseA, looseB = "loosens ssh:prod: gate login becomes none", "loosens secret:db: any app"
	lines = append(lines, looseA, looseB)
	got := PromptText(platform.Prompt{Title: "Allow this change to nazar's config?", Lines: lines})
	if len(got) > maxPromptBytes {
		t.Fatalf("len = %d, want at most %d", len(got), maxPromptBytes)
	}
	shown := strings.Split(got, "\n")
	if shown[0] != "Allow this change to nazar's config?" {
		t.Fatalf("the title is not first:\n%s", got)
	}
	if !strings.HasSuffix(got, "\n"+looseA+"\n"+looseB) {
		t.Fatalf("the loosening lines are not the last lines:\n%s", got)
	}
	var n int
	if _, err := fmt.Sscanf(shown[1], "(%d lines not shown)", &n); err != nil {
		t.Fatalf("the second line %q does not say what is left out: %v", shown[1], err)
	}
	if want := len(lines) - (len(shown) - 2); n != want {
		t.Fatalf("it says %d lines not shown, %d of %d are shown: want %d", n, len(shown)-2, len(lines), want)
	}
}

// A key approval: lines long enough to push the rest out do not hide the
// scope, nor the command the user is asked about.
func TestPromptTextKeepsScopeAndCommand(t *testing.T) {
	long := func(c string) string { return strings.Repeat(c, 400) }
	p := platform.Prompt{
		Title:       `iTerm2 wants to use key "github"`,
		Lines:       []string{"unknown", "summary", "git push " + long("c"), "chain: " + long("d"), "matched: " + long("e"), "Scope: this terminal"},
		CommandLine: 3,
	}
	got := PromptText(p)
	if len(got) > maxPromptBytes {
		t.Fatalf("len = %d, want at most %d", len(got), maxPromptBytes)
	}
	if !strings.HasSuffix(got, "\nScope: this terminal") {
		t.Fatalf("the scope is not the last line:\n%s", got)
	}
	if !strings.Contains(got, "\ngit push ccc") || !strings.Contains(got, ellipsis) {
		t.Fatalf("the command is not shown, cut visibly:\n%s", got)
	}
	if !strings.Contains(got, "\nunknown\n") {
		t.Fatalf("the first line is not shown:\n%s", got)
	}
	if !strings.Contains(got, "\n(1 line not shown)\n") || strings.Contains(got, "chain: ") {
		t.Fatalf("want the chain line left out, and counted:\n%s", got)
	}
}

// One left-out line reads as one, the worst lines still fit, and the text
// is valid and bounded whatever the lines are.
func TestPromptTextWorstCase(t *testing.T) {
	long := strings.Repeat("é", 400)
	got := PromptText(platform.Prompt{Title: long, Lines: []string{long, long, long}, CommandLine: 1})
	if len(got) > maxPromptBytes || !utf8.ValidString(got) {
		t.Fatalf("len = %d, valid %v", len(got), utf8.ValidString(got))
	}
	if !strings.Contains(got, "\n(2 lines not shown)\n") {
		t.Fatalf("want two lines not shown:\n%s", got)
	}
	got = PromptText(platform.Prompt{Title: "t", Lines: []string{strings.Repeat("a", 390), strings.Repeat("b", 390), strings.Repeat("c", 390)}})
	if !strings.Contains(got, "\n(1 line not shown)\n") {
		t.Fatalf("want one line not shown:\n%s", got)
	}
	longer := strings.Repeat("é", 600)
	if got := PromptText(platform.Prompt{Title: longer}); len(got) > maxPromptBytes || !strings.HasSuffix(got, ellipsis) {
		t.Fatalf("a long title alone: len %d, %q", len(got), got[len(got)-10:])
	}
}

// Some polkit agents set the message as markup (mate-polkit, LXQt's) with
// no escaping, so a caller's command line could hide or restyle the other
// lines, and a stray '<' could leave the prompt empty. The text handed to
// polkit has no '<', '>' or '&': each is its fullwidth look-alike, which
// a plain-text agent shows as such, with no entity. The bound still holds
// with the wider characters, and the prompt is left as it was.
func TestPromptTextHasNoMarkup(t *testing.T) {
	p := platform.Prompt{
		Title: `iTerm2 wants to use key "github"`,
		Lines: []string{`git push <b>origin</b> & <span size="1">main</span>`, "chain: iTerm2 > zsh > ssh", "Scope: this request only"},
	}
	before := slices.Clone(p.Lines)
	got := PromptText(p)
	if strings.ContainsAny(got, "<>&") {
		t.Fatalf("markup reaches polkit:\n%s", got)
	}
	want := "iTerm2 wants to use key \"github\"\ngit push ＜b＞origin＜/b＞ ＆ ＜span size=\"1\"＞main＜/span＞\nchain: iTerm2 ＞ zsh ＞ ssh\nScope: this request only"
	if got != want {
		t.Fatalf("PromptText =\n%s\nwant\n%s", got, want)
	}
	if !slices.Equal(p.Lines, before) {
		t.Fatalf("the prompt's lines were changed in place: %q", p.Lines)
	}
	// 400 '<' are 1200 bytes once replaced: still cut to the bound, on a
	// character boundary, with the cut visible.
	long := PromptText(platform.Prompt{Title: "t", Lines: []string{strings.Repeat("<", 400), strings.Repeat("&", 400)}})
	if len(long) > maxPromptBytes || !utf8.ValidString(long) || strings.ContainsAny(long, "<>&") || !strings.Contains(long, ellipsis) {
		t.Fatalf("long markup: len %d, valid %v:\n%s", len(long), utf8.ValidString(long), long)
	}
}

// Check needs a timeout: nothing else would end a check that polkit never
// answers.
func TestNoTimeoutIsAnError(t *testing.T) {
	auth := New(nil, func() (Subject, error) { t.Fatal("the subject was resolved"); return Subject{}, nil })
	for _, d := range []time.Duration{0, -time.Second} {
		if err := auth.Check(platform.Prompt{Title: "t", Timeout: d}); !errors.Is(err, errNoTimeout) {
			t.Fatalf("Check with Timeout %v = %v, want errNoTimeout", d, err)
		}
	}
}

// polkit approves root without asking, so a Check from a root process
// would pass with nobody asked.
func TestRootIsRefused(t *testing.T) {
	defer func(f func() (int, int)) { processUIDs = f }(processUIDs)
	for _, ids := range [][2]int{{0, 0}, {0, 1000}, {1000, 0}} {
		processUIDs = func() (int, int) { return ids[0], ids[1] }
		auth := New(nil, func() (Subject, error) { t.Fatal("the subject was resolved"); return Subject{}, nil })
		if err := auth.Check(platform.Prompt{Title: "t", Timeout: time.Minute}); !errors.Is(err, errRoot) {
			t.Fatalf("Check with uid %d, euid %d = %v, want errRoot", ids[0], ids[1], err)
		}
	}
}

// A subject that is root or another user, or that names nobody, is refused
// before polkit is asked (the Authority has no connection here).
func TestForeignSubjectIsRefused(t *testing.T) {
	defer func(f func() (int, int)) { processUIDs = f }(processUIDs)
	processUIDs = func() (int, int) { return 1000, 1000 }
	for name, s := range map[string]Subject{
		"root":         ProcessSubject(1, 0, 0),
		"another user": ProcessSubject(1, 0, 1001),
		"no uid":       {Kind: "unix-process", Details: map[string]dbus.Variant{"pid": dbus.MakeVariant(uint32(1))}},
		"odd uid":      {Kind: "unix-process", Details: map[string]dbus.Variant{"uid": dbus.MakeVariant("1000")}},
		"no session":   {Kind: "unix-session"},
		"odd session":  {Kind: "unix-session", Details: map[string]dbus.Variant{"session-id": dbus.MakeVariant(uint32(2))}},
		"other kind":   {Kind: "system-bus-name", Details: map[string]dbus.Variant{"name": dbus.MakeVariant(":1.1")}},
	} {
		auth := New(nil, func() (Subject, error) { return s, nil })
		err := auth.Check(platform.Prompt{Title: "t", Timeout: time.Minute})
		if err == nil || errors.Is(err, platform.ErrDenied) {
			t.Errorf("%s: Check = %v, want an error other than ErrDenied", name, err)
		} else if !strings.HasPrefix(err.Error(), "polkit: subject: ") {
			t.Errorf("%s: Check = %v, want a subject error", name, err)
		}
	}
}
