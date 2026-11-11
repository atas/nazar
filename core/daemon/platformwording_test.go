package daemon

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/secrets/envpolicy"
	"github.com/atas/nazar/core/trust"
)

// Every message the daemon words from its platform's traits, pinned on
// both platforms: macOS byte for byte as before, Linux in its own words.
// Portable: these run on every OS.

func TestAccessLineWording(t *testing.T) {
	for _, tc := range []struct {
		tr                    platform.Traits
		whenUnlocked, anyTime string
	}{
		{platform.MacTraits,
			"works only while the Mac is unlocked; fixed for the key's life",
			"works while the Mac is locked too, once you have logged in since it started; fixed for the key's life"},
		{platform.LinuxTraits,
			"works only while the screen is unlocked (enforced by nazar from the key's record)",
			"works while the screen is locked too (enforced by nazar from the key's record)"},
	} {
		if got := accessLine(platform.AccessWhenUnlocked, tc.tr); got != tc.whenUnlocked {
			t.Errorf("%s when unlocked: %q, want %q", tc.tr.Machine, got, tc.whenUnlocked)
		}
		if got := accessLine(platform.AccessAfterFirstUnlock, tc.tr); got != tc.anyTime {
			t.Errorf("%s after first unlock: %q, want %q", tc.tr.Machine, got, tc.anyTime)
		}
	}
}

// On Linux the choice is two plain bytes of the key's record, which any
// program running as the user can rewrite (THREAT-MODEL 7.3, 7.11): no
// prompt line claims it is fixed. The create prompts of a key and of a
// k8s CA are the lines a person reads before approving.
func TestLinuxPromptsNeverSayFixed(t *testing.T) {
	for _, a := range []platform.Access{platform.AccessWhenUnlocked, platform.AccessAfterFirstUnlock} {
		if got := accessLine(a, platform.LinuxTraits); strings.Contains(got, "fixed for") || strings.Contains(got, "chip") {
			t.Errorf("Linux access line claims a chip's protection: %q", got)
		}
	}
	e := startWith(t, onLinux)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	for _, args := range []map[string]string{{"name": "a"}, {"name": "b", "onlyWhenUnlocked": "true"}, {"name": "c", "alwaysAsk": "true"}} {
		if err := e.call(t, control.CmdSSHKeyCreate, args, control.KindSSHKey, &control.SSHKey{}); err != nil {
			t.Fatal(err)
		}
		if lines := strings.Join(lastLoginLines(e), "\n"); strings.Contains(lines, "fixed for") || strings.Contains(lines, "chip") {
			t.Errorf("ssh-key create %v prompt claims a chip's protection:\n%s", args, lines)
		}
	}
	k := startAdminOn(t, true)
	if _, p := k.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	if lines := strings.Join(lastLoginLines(k.env), "\n"); strings.Contains(lines, "fixed for") || strings.Contains(lines, "chip") {
		t.Errorf("k8s ca create prompt claims a chip's protection:\n%s", lines)
	}
}

func TestPresenceLineWording(t *testing.T) {
	for _, tc := range []struct {
		tr      platform.Traits
		on, off string
	}{
		{platform.MacTraits,
			"Touch ID on every use, enforced by the chip: this key can never get a session, dialog or no-prompt rule",
			"Secure Enclave user presence: off (a rule remembers approvals or allows a dialog, or no rule allows the key yet; nazar's gates are the check)"},
		{platform.LinuxTraits,
			"your password on every use, enforced by nazar: this key can never get a session, dialog or no-prompt rule",
			"user presence enforced by nazar: off (a rule remembers approvals or allows a dialog, or no rule allows the key yet; nazar's gates are the check)"},
	} {
		if got := presenceLine(platform.AuthUserPresence, tc.tr); got != tc.on {
			t.Errorf("on: %q, want %q", got, tc.on)
		}
		if got := presenceLine(platform.AuthNone, tc.tr); got != tc.off {
			t.Errorf("off: %q, want %q", got, tc.off)
		}
	}
}

// adviceConfig parses a config whose key github has one rule for iTerm2
// with gate and scope.
func adviceConfig(t *testing.T, gate, scope string) *config.Config {
	t.Helper()
	src := "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\nssh_agent:\n  keys:\n    github:\n      gate: block\n      rules:\n" +
		"        - apps: [iterm]\n          gate: " + gate + "\n          scope: " + scope + "\n"
	c, probs := config.Parse([]byte(src), config.Env{Home: "/Users/u"})
	if c == nil {
		t.Fatal(probs.Error())
	}
	return c
}

func TestPresenceAdviceWording(t *testing.T) {
	use := adviceConfig(t, "login", "use")
	session := adviceConfig(t, "login", "session")
	dialog := adviceConfig(t, "dialog", "use")
	for _, tc := range []struct {
		name string
		tr   platform.Traits
		c    *config.Config
		auth platform.AuthPolicy
		want string
	}{
		{"mac none", platform.MacTraits, use, platform.AuthNone,
			`SSH key "github" was created without Secure Enclave user presence, but every gate that can reach it is block or login with scope: use, so it could be re-created with user presence (then even a compromised nazar process can't sign without your authentication)`},
		// On Linux the same nazar would ask: re-creating the key gains
		// nothing, so there is no advice to destroy it.
		{"linux none", platform.LinuxTraits, use, platform.AuthNone, ""},
		{"mac lapsing", platform.MacTraits, session, platform.AuthUserPresence,
			`SSH key "github" was created with Secure Enclave user presence, but ` + gateWhat(t, session) + ` with scope session remembers an approval longer than the Secure Enclave honours one (minutes), so those requests fail once it lapses; re-create the key without user presence or use scope: use`},
		{"linux remembered", platform.LinuxTraits, session, platform.AuthUserPresence,
			`SSH key "github" was created with user presence enforced by nazar, but ` + gateWhat(t, session) + ` with scope session remembers an approval, so the key does not ask on every use while that approval lasts; use scope: use, or re-create the key without user presence`},
		{"mac weak", platform.MacTraits, dialog, platform.AuthUserPresence,
			`SSH key "github" was created with Secure Enclave user presence, but ` + gateWhat(t, dialog) + ` can reach it, so those requests fail; re-create the key without user presence`},
		{"linux weak", platform.LinuxTraits, dialog, platform.AuthUserPresence,
			`SSH key "github" was created with user presence enforced by nazar, but ` + gateWhat(t, dialog) + ` can reach it, so those requests fail; re-create the key without user presence`},
		{"linux use", platform.LinuxTraits, use, platform.AuthUserPresence, ""},
	} {
		if got := presenceAdviceOn(tc.tr, tc.c, "github", tc.auth); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
	if presenceAdvice(use, "github", platform.AuthNone) != presenceAdviceOn(platform.MacTraits, use, "github", platform.AuthNone) {
		t.Error("presenceAdvice is the macOS wording")
	}
}

// gateWhat is how the advice names the only rule of c's key github.
func gateWhat(t *testing.T, c *config.Config) string {
	t.Helper()
	for _, s := range gateSources(c, "github") {
		if s.pol.Gate != config.GateBlock {
			return s.what
		}
	}
	t.Fatal("no rule")
	return ""
}

// trustPrompt runs trust --app for toolID, installed at path with code,
// and returns its login prompt and the audit reason it logged.
func trustPrompt(t *testing.T, e *env, path string, code platform.CodeIdentity) (platform.Prompt, string) {
	t.Helper()
	e.f.UninstallApp(path)
	e.f.InstallApp(path, toolID, code)
	before := len(e.auditFor(t, "app:"+toolID))
	if _, p := e.trustApp(t, toolID); p != nil {
		t.Fatalf("trust --app: %+v", p)
	}
	var prompt platform.Prompt
	for _, s := range e.f.Shown() {
		if s.Kind == fake.KindAuthenticate {
			prompt = s.Prompt
		}
	}
	lines := e.auditFor(t, "app:"+toolID)
	if len(lines) != before+1 {
		t.Fatalf("%d audit lines, want one more than %d", len(lines), before)
	}
	return prompt, lines[len(lines)-1]["reason"]
}

func TestTrustAppPromptWording(t *testing.T) {
	type want struct {
		title  string
		lines  []string
		reason string
	}
	for _, tc := range []struct {
		name          string
		mod           func(*fake.Fake, *Options)
		path          string
		first, second platform.CodeIdentity
		pin, repin    want
	}{
		{"mac", nil, "/Applications/Tool.app", toolCode, toolCode2,
			want{`Trust team "TOOLTEAM01" as app "com.example.tool"?`, []string{
				`app: "com.example.tool"`, `installed at "/Applications/Tool.app"`, `signed by team "TOOLTEAM01"`,
				"app: matchers for this bundle id will match only this team from now on."}, `trust --app: pin team "TOOLTEAM01": `},
			want{`Replace the pinned team of app "com.example.tool" ("TOOLTEAM01" → "NEWTEAM002")?`, []string{
				`app: "com.example.tool"`, `installed at "/Applications/Tool.app"`, `signed by team "NEWTEAM002"`,
				`replaces the pinned team "TOOLTEAM01": the app's signer changed`,
				"app: matchers for this bundle id will match only this team from now on."}, `trust --app: pin team "NEWTEAM002": `}},
		{"linux", onLinux, "/usr/bin/tool",
			platform.CodeIdentity{Signed: true, TeamID: "sha256:0a0b", SigningID: toolID},
			platform.CodeIdentity{Signed: true, TeamID: "sha256:0c0d", SigningID: toolID},
			want{`Trust executable hash "sha256:0a0b" as app "com.example.tool"?`, []string{
				`app: "com.example.tool"`, `installed at "/usr/bin/tool"`, `executable hash "sha256:0a0b"`,
				"app: matchers for this app will match only this executable from now on."}, `trust --app: pin executable hash "sha256:0a0b": `},
			want{`Replace the pinned executable hash of app "com.example.tool" ("sha256:0a0b" → "sha256:0c0d")?`, []string{
				`app: "com.example.tool"`, `installed at "/usr/bin/tool"`, `executable hash "sha256:0c0d"`,
				`replaces the pinned executable hash "sha256:0a0b": the app's executable changed`,
				"app: matchers for this app will match only this executable from now on."}, `trust --app: pin executable hash "sha256:0c0d": `}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := startWith(t, tc.mod)
			e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
			for _, step := range []struct {
				code platform.CodeIdentity
				w    want
			}{{tc.first, tc.pin}, {tc.second, tc.repin}} {
				p, reason := trustPrompt(t, e, tc.path, step.code)
				if p.Title != step.w.title || strings.Join(p.Lines, "\n") != strings.Join(step.w.lines, "\n") {
					t.Errorf("prompt %q\n%q\nwant %q\n%q", p.Title, p.Lines, step.w.title, step.w.lines)
				}
				if !strings.HasPrefix(reason, step.w.reason) {
					t.Errorf("audit reason %q, want prefix %q", reason, step.w.reason)
				}
			}
		})
	}
}

func TestCreateHintAndDeletePromptWording(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mod          func(*fake.Fake, *Options)
		hint, delete string
	}{
		{"mac", nil,
			"ssh-key create takes no --scope or --gate: the key's rules decide its protection (for a key the chip itself guards: `nazar ssh-key create github --always-ask`)",
			"The key is destroyed in the Secure Enclave. This can't be undone."},
		{"linux", onLinux,
			"ssh-key create takes no --scope or --gate: the key's rules decide its protection (for a key that asks on every use: `nazar ssh-key create github --always-ask`)",
			"nazar deletes its copy of the key. A copy of ~/.nazar/vault made earlier, such as a backup, still works on this TPM."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := startWith(t, tc.mod)
			e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
			p := control.AsProblem(e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github", "scope": "use"}, control.KindSSHKey, &control.SSHKey{}))
			if p == nil || p.Message != tc.hint {
				t.Errorf("hint %+v, want %q", p, tc.hint)
			}
			if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
				t.Fatal(err)
			}
			if err := e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
				t.Fatal(err)
			}
			shown := e.f.Shown()
			if lines := shown[len(shown)-1].Prompt.Lines; lines[len(lines)-1] != tc.delete {
				t.Errorf("delete prompt %q, want last line %q", lines, tc.delete)
			}
		})
	}
}

// lastLoginLines is the lines of the last login prompt shown.
func lastLoginLines(e *env) []string {
	var lines []string
	for _, s := range e.f.Shown() {
		if s.Kind == fake.KindAuthenticate {
			lines = s.Prompt.Lines
		}
	}
	return lines
}

// startAdminOn is startAdmin on macOS or on the Linux-described fake (with
// no signed: app, which Linux refuses).
func startAdminOn(t *testing.T, linux bool) *adminEnv {
	t.Helper()
	if !linux {
		return startAdmin(t)
	}
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.VerifyCLI = genuineCLI(f)
		o.Pipes = f
		o.RunHost = func(int) (envpolicy.Host, error) { return envpolicy.Host{Home: "/home/dev", User: "dev"}, nil }
		onLinux(f, o)
	})
	clusterPEM := clusterCA(t, "hydra cluster CA")
	pin, err := cluster.PinOf(cluster.Info{Server: "https://hydra.example:16443", CAData: clusterPEM})
	if err != nil {
		t.Fatal(err)
	}
	e.approved(t, "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\n")
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.asCLI(cliProc("k8s"))
	return &adminEnv{env: e, pin: pin, clusterPEM: clusterPEM}
}

func TestK8sCAWording(t *testing.T) {
	for _, tc := range []struct {
		linux                          bool
		made, access, locked, unlocked string
		destroyed                      string
	}{
		{false,
			"The CA key is made in the Secure Enclave. A cluster that trusts its certificate accepts every certificate nazar mints for hydra.",
			"works while the Mac is locked too, once you have logged in since it started; fixed for the key's life",
			"hydra is set up already, and its CA signs while the Mac is locked too, for the CA's life: run this again without --only-when-unlocked to finish its setup, or nazar k8s forget hydra, then nazar k8s ca create hydra --only-when-unlocked, for a new CA",
			"prod is set up already, and its CA signs only while the Mac is unlocked, for the CA's life: run this again with --only-when-unlocked to finish its setup, or nazar k8s forget prod, then nazar k8s ca create prod, for a new CA",
			"The CA is destroyed in the Secure Enclave; this can't be undone. Certificates it minted stay valid until they end."},
		{true,
			"The CA key is made in the TPM. A cluster that trusts its certificate accepts every certificate nazar mints for hydra.",
			"works while the screen is locked too (enforced by nazar from the key's record)",
			"hydra is set up already, and its CA signs while the screen is locked too, for the CA's life: run this again without --only-when-unlocked to finish its setup, or nazar k8s forget hydra, then nazar k8s ca create hydra --only-when-unlocked, for a new CA",
			"prod is set up already, and its CA signs only while the screen is unlocked, for the CA's life: run this again with --only-when-unlocked to finish its setup, or nazar k8s forget prod, then nazar k8s ca create prod, for a new CA",
			"nazar deletes its copy of the CA. A copy of ~/.nazar/vault made earlier, such as a backup, still works on this TPM. Certificates it minted stay valid until they end."},
	} {
		e := startAdminOn(t, tc.linux)
		if _, p := e.caCreate(t, "hydra"); p != nil {
			t.Fatal(p)
		}
		if lines := lastLoginLines(e.env); len(lines) < 2 || lines[0] != tc.made || lines[1] != tc.access {
			t.Errorf("linux %v: create prompt %q, want %q, %q", tc.linux, lines, tc.made, tc.access)
		}
		args := e.createArgs("hydra")
		args["onlyWhenUnlocked"] = "true"
		if _, p := e.create(t, args); p == nil || p.Message != tc.locked {
			t.Errorf("linux %v: other access %+v, want %q", tc.linux, p, tc.locked)
		}
		args = e.createArgs("prod")
		args["onlyWhenUnlocked"] = "true"
		if _, p := e.create(t, args); p != nil {
			t.Fatal(p)
		}
		if _, p := e.caCreate(t, "prod"); p == nil || p.Message != tc.unlocked {
			t.Errorf("linux %v: other access %+v, want %q", tc.linux, p, tc.unlocked)
		}
		if err := e.call(t, control.CmdK8sForget, map[string]string{"name": "hydra", "kubeconfig": args["kubeconfig"]}, control.KindK8sContext, &control.K8sContext{}); err != nil {
			t.Fatal(err)
		}
		if lines := lastLoginLines(e.env); len(lines) == 0 || lines[0] != tc.destroyed {
			t.Errorf("linux %v: forget prompt %q, want %q", tc.linux, lines, tc.destroyed)
		}
	}
}

func TestAWSCAWording(t *testing.T) {
	for _, tc := range []struct {
		linux                          bool
		made, access, locked, unlocked string
		destroyed                      string
	}{
		{false,
			"The CA key is made in the Secure Enclave. AWS accepts every certificate it issues for any role whose trust policy names its trust anchor.",
			"works while the Mac is locked too, once you have logged in since it started; fixed for the key's life",
			"dev is set up already, and its CA signs while the Mac is locked too, for the CA's life: run this again without --only-when-unlocked, or nazar aws forget dev, then nazar aws ca create dev --only-when-unlocked, for a new CA",
			"prod is set up already, and its CA signs only while the Mac is unlocked, for the CA's life: run this again with --only-when-unlocked, or nazar aws forget prod, then nazar aws ca create prod, for a new CA",
			"The CA is destroyed in the Secure Enclave; this can't be undone. Sessions it gave stay valid until they end."},
		{true,
			"The CA key is made in the TPM. AWS accepts every certificate it issues for any role whose trust policy names its trust anchor.",
			"works while the screen is locked too (enforced by nazar from the key's record)",
			"dev is set up already, and its CA signs while the screen is locked too, for the CA's life: run this again without --only-when-unlocked, or nazar aws forget dev, then nazar aws ca create dev --only-when-unlocked, for a new CA",
			"prod is set up already, and its CA signs only while the screen is unlocked, for the CA's life: run this again with --only-when-unlocked, or nazar aws forget prod, then nazar aws ca create prod, for a new CA",
			"nazar deletes its copy of the CA. A copy of ~/.nazar/vault made earlier, such as a backup, still works on this TPM. Sessions it gave stay valid until they end."},
	} {
		var e *awsAdmin
		if tc.linux {
			env := startWith(t, func(f *fake.Fake, o *Options) {
				o.VerifyCLI = genuineCLI(f)
				o.Pipes = f
				o.RunHost = func(int) (envpolicy.Host, error) { return envpolicy.Host{Home: "/home/dev", User: "dev"}, nil }
				onLinux(f, o)
			})
			env.approved(t, "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\n")
			env.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
			env.asCLI(cliProc("aws"))
			e = &awsAdmin{env: env}
		} else {
			e = startAWSAdmin(t)
		}
		if _, p := e.create(t, map[string]string{"name": "dev"}); p != nil {
			t.Fatal(p)
		}
		if lines := lastLoginLines(e.env); len(lines) < 2 || lines[0] != tc.made || lines[1] != tc.access {
			t.Errorf("linux %v: create prompt %q, want %q, %q", tc.linux, lines, tc.made, tc.access)
		}
		if _, p := e.create(t, map[string]string{"name": "dev", "onlyWhenUnlocked": "true"}); p == nil || p.Message != tc.locked {
			t.Errorf("linux %v: other access %+v, want %q", tc.linux, p, tc.locked)
		}
		if _, p := e.create(t, map[string]string{"name": "prod", "onlyWhenUnlocked": "true"}); p != nil {
			t.Fatal(p)
		}
		if _, p := e.create(t, map[string]string{"name": "prod"}); p == nil || p.Message != tc.unlocked {
			t.Errorf("linux %v: other access %+v, want %q", tc.linux, p, tc.unlocked)
		}
		if err := e.call(t, control.CmdAWSForget, map[string]string{"name": "dev"}, control.KindAWSEntry, &control.AWSEntry{}); err != nil {
			t.Fatal(err)
		}
		if lines := lastLoginLines(e.env); len(lines) == 0 || lines[0] != tc.destroyed {
			t.Errorf("linux %v: forget prompt %q, want %q", tc.linux, lines, tc.destroyed)
		}
	}
}

// --- the vault's reasons and remedies ---

var fileWords = vaultWords{files: true}

func fileOf(item string) string {
	return "~/.nazar/vault/" + hex.EncodeToString([]byte(item)) + ".item"
}

// The file vault's remedies remove the item's file (a hex name, always
// pasteable) and never name the Keychain or the security command.
func TestFileVaultRemedies(t *testing.T) {
	key := fileOf("ssh-key/github")
	if got, want := fileWords.deleteItem("ssh-key/github"), "rm "+key; got != want {
		t.Errorf("deleteItem %q, want %q", got, want)
	}
	want := "first, if " + key + " is not a regular file you own with mode 0600 (a symlink, another owner, a changed mode), fix that, " +
		"and run nazar status again (deleting the item destroys the key for good); if the key is still unreadable: rm " + key +
		", then nazar ssh-key create github, then add the new public key (~/.nazar/keys/github.pub) where the old one was"
	if got := fileWords.keyRemedy("github"); got != want {
		t.Errorf("keyRemedy\n got %q\nwant %q", got, want)
	}
	secret := fileOf("secret/API")
	want = "first, if " + secret + " is not a regular file you own with mode 0600 (a symlink, another owner, a changed mode), fix that, " +
		"and run nazar status again (deleting the item destroys the secret for good); if the secret is still unreadable: rm " + secret + ", then nazar secret add API"
	if got := fileWords.secretRemedy("API"); got != want {
		t.Errorf("secretRemedy\n got %q\nwant %q", got, want)
	}
	hostile := "ssh-key/a'$(x)\n"
	if got, want := fileWords.keyRemedy("a'$(x)\n"), "remove its file by hand: rm "+fileOf(hostile)+` (item "ssh-key/a'$(x)\n")`; got != want {
		t.Errorf("hostile name\n got %q\nwant %q", got, want)
	}
	for name, got := range map[string]string{
		"k8s": fileWords.k8sCARemedy("hydra"), "aws": fileWords.awsCARemedy("dev"),
		"unreadable": fileWords.unreadableReason("ssh-key/github", "boom"), "retrust": fileWords.retrust(),
		"cantRecord": fileWords.cantRecord(), "refusal": fileWords.unreadable(), "ca refusal": fileWords.caUnreadable(),
	} {
		for _, mac := range []string{"Keychain", "keychain", "security ", "signature", "bundle id", "bundle-id"} {
			if strings.Contains(got, mac) {
				t.Errorf("%s says %q: %q", name, mac, got)
			}
		}
	}
	if got, want := fileWords.k8sCARemedy("hydra"), "first, if "+fileOf("k8s-ca/hydra")+" is not a regular file you own with mode 0600 (a symlink, another owner, a changed mode), fix that, "+
		"and run nazar k8s list again (deleting the item destroys the CA for good, and the cluster must then trust a new one); if the CA is still unreadable: rm "+fileOf("k8s-ca/hydra")+
		", then nazar k8s forget hydra"; !strings.HasPrefix(got, want) {
		t.Errorf("k8sCARemedy\n got %q\nwant prefix %q", got, want)
	}
	if got, want := fileWords.unreadableReason("ssh-key/github", "boom"), `vault item "ssh-key/github" can't be read by this nazar-agent: its file `+key+
		" is not a regular file of yours that it may read (a symlink, another owner or a changed mode), or reading it failed (boom)"; got != want {
		t.Errorf("unreadableReason\n got %q\nwant %q", got, want)
	}
	if got, want := fileWords.retrust(), "run the fix nazar apps list names for each app: matcher it shows as not trusted (nazar trust --app <app-id>)"; got != want {
		t.Errorf("retrust %q", got)
	}
	if got, want := fileWords.cantRecord(), "(can nazar-agent write ~/.nazar/vault?)"; got != want {
		t.Errorf("cantRecord %q", got)
	}
}

// The Keychain's words are those macOS always printed.
func TestKeychainRemediesUnchanged(t *testing.T) {
	w := keychainWords
	for _, tc := range []struct{ got, want string }{
		{w.checkFirst(k8sCACheckRest, "k8s-ca/hydra"), "first, if the login keychain is locked, unlock it, and if this nazar-agent is not the one you installed, reinstall that one, " +
			"and run nazar k8s list again (deleting the item destroys the CA for good, and the cluster must then trust a new one); if the CA is still unreadable: "},
		{w.checkFirst(awsCACheckRest, "aws-ca/dev"), "first, if the login keychain is locked, unlock it, and if this nazar-agent is not the one you installed, reinstall that one, " +
			"and run nazar aws list again (deleting the item destroys the CA for good, and AWS must then trust a new one); if the CA is still unreadable: "},
		{w.checkFirst(keyCheckRest, "ssh-key/github"), keyCheckFirst},
		{keyCheckFirst, "first, if the login keychain is locked, unlock it, and if this nazar-agent is not the one you installed, reinstall that one, " +
			"and run nazar status again (deleting the item destroys the key for good); if the key is still unreadable: "},
		{secretCheckFirst, "first, if the login keychain is locked, unlock it, and if this nazar-agent is not the one you installed, reinstall that one, " +
			"and run nazar status again (deleting the item destroys the secret for good); if the secret is still unreadable: "},
		{w.unreadable(), "its Keychain item belongs to another signature of the agent, or the login keychain is locked"},
		{w.caUnreadable(), "its Keychain item belongs to another signature of the agent, the login keychain is locked, or the item is not one nazar made"},
		{w.cantRecord(), "(is the login keychain locked?)"},
		{w.retrust(), retrust},
		{w.removeItemByHand("secret/a b"), `remove it by hand in Keychain Access: service dev.nazar, account shown as "secret/a b"`},
		{w.awsCARemedy("dev"), "first, if the login keychain is locked, unlock it, and if this nazar-agent is not the one you installed, reinstall that one, " +
			"and run nazar aws list again (deleting the item destroys the CA for good, and AWS must then trust a new one); if the CA is still unreadable: " +
			"security delete-generic-password -s dev.nazar -a aws-ca/dev, then nazar aws forget dev, then nazar aws ca create dev, then give the trust anchor its certificate (nazar aws ca show dev)"},
	} {
		if tc.got != tc.want {
			t.Errorf("\n got %q\nwant %q", tc.got, tc.want)
		}
	}
	if vaultWordsOf(platform.MacTraits) != keychainWords || vaultWordsOf(platform.LinuxTraits) != fileWords {
		t.Error("vaultWordsOf")
	}
}

// On Linux, nazar status after items became unreadable names the vault's
// files and the rm that removes one, never the Keychain; a key delete is
// refused with the same fix.
func TestLinuxUnreadableItemsNameTheVaultFiles(t *testing.T) {
	var v *otherBuildVault
	e := startWith(t, func(f *fake.Fake, o *Options) {
		onLinux(f, o)
		inner := o.Vault.(*fake.Vault)
		for _, n := range []string{PromptsVaultItem, configstage.ApprovedVaultItem, trust.VaultItem, keys.VaultPrefix + "github"} {
			inner.Put(n, []byte("unreadable"))
		}
		v = &otherBuildVault{Vault: inner, foreign: map[string]bool{PromptsVaultItem: true, configstage.ApprovedVaultItem: true,
			trust.VaultItem: true, keys.VaultPrefix + "github": true}}
		o.Vault = v
		p := layout.ConfigFile(o.Home)
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(keyConfig), 0o600)
	})
	st := e.status(t)
	if len(st.Vault) != 4 {
		t.Fatalf("vault problems %+v", st.Vault)
	}
	for _, p := range st.Vault {
		text := p.Reason + "\n" + p.Effect + "\n" + p.Remedy
		for _, mac := range []string{"Keychain", "keychain", "security ", "signature", "bundle-id"} {
			if strings.Contains(text, mac) {
				t.Errorf("%s says %q:\n%s", p.Item, mac, text)
			}
		}
		if !strings.Contains(p.Remedy, "rm "+fileOf(p.Item)) {
			t.Errorf("%s: remedy %q does not remove its file", p.Item, p.Remedy)
		}
	}
	if got := st.Vault[3].Remedy; got != fileWords.keyRemedy("github") {
		t.Errorf("key remedy %q", got)
	}
	v.securityDelete(PromptsVaultItem)
	p := control.AsProblem(e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}))
	want := "SSH key github can't be deleted by this nazar-agent: its vault item can't be read; nothing was changed. To fix it: " + fileWords.keyRemedy("github")
	if p == nil || p.Message != want {
		t.Fatalf("delete: %+v\nwant %q", p, want)
	}
}
