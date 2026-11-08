package kubeconfig

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

// The k8s design: `nazar k8s ca create` reads the public facts
// of the current context and its cluster (never a user entry), adds exactly
// nazar's three entries for the new context as lines of text (every other
// byte stays), refuses names it did not write, and `nazar k8s forget`
// removes them again only while they are exactly nazar's.

// noSecret fails if s carries any credential of the corpus.
func noSecret(t *testing.T, what, s string) {
	t.Helper()
	for _, sec := range allSecrets {
		if strings.Contains(s, sec) || strings.Contains(s, b64([]byte(sec))) {
			t.Errorf("%s carries a credential (%s)", what, sec)
		}
	}
	for _, sec := range []string{hydraKey, otherKey} {
		if strings.Contains(s, b64([]byte(sec))) {
			t.Errorf("%s carries a key", what)
		}
	}
}

func (c *corpus) entries(name string) Entries {
	return Entries{Context: name, Server: "https://hydra.example:16443", CAPEM: c.clusterCA, Command: "/Users/u/.local/bin/nazar"}
}

func TestCurrentContextReadsTheClusterOnly(t *testing.T) {
	c := newCorpus(t)
	name, cl := load(t, c.path).CurrentContext()
	if name != "hydra" || cl == nil || cl.Name != "hydra-cluster" || cl.Server != "https://hydra.example:16443" ||
		!bytes.Equal(cl.CAPEM, c.clusterCA) || cl.Insecure || cl.CAErr != nil || cl.File != c.path {
		t.Fatalf("%q %+v", name, cl)
	}
	noSecret(t, "the defaults", fmt.Sprintf("%+v %s", cl, cl.CAPEM))
	// No current-context, or one naming nothing: no defaults.
	p := filepath.Join(t.TempDir(), "config")
	_ = os.WriteFile(p, []byte(strings.Replace(c.body, "current-context: hydra\n", "current-context: gone\n", 1)), 0o600)
	if name, cl := load(t, p).CurrentContext(); name != "gone" || cl != nil {
		t.Fatalf("%q %+v", name, cl)
	}
	_ = os.WriteFile(p, []byte(strings.Replace(c.body, "current-context: hydra\n", "", 1)), 0o600)
	if name, cl := load(t, p).CurrentContext(); name != "" || cl != nil {
		t.Fatalf("%q %+v", name, cl)
	}
	// insecure-skip-tls-verify, as kubectl reads it (YAML 1.1 booleans).
	for _, v := range []string{"true", "True", "yes", "on"} {
		_ = os.WriteFile(p, []byte(strings.Replace(c.body, "   # the node\n", "\n    insecure-skip-tls-verify: "+v+"\n", 1)), 0o600)
		if _, cl := load(t, p).CurrentContext(); cl == nil || !cl.Insecure {
			t.Errorf("%s: insecure", v)
		}
	}
}

func TestClusterByServer(t *testing.T) {
	c := newCorpus(t)
	// A second file first in the set: a file-referenced CA relative to its
	// own directory, and the first definition of a name wins.
	sub := t.TempDir()
	_ = os.MkdirAll(filepath.Join(sub, "pki"), 0o700)
	_ = os.WriteFile(filepath.Join(sub, "pki", "ca.crt"), c.clusterCA, 0o600)
	first := filepath.Join(sub, "first")
	_ = os.WriteFile(first, []byte(`apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster: {server: "https://dev.example", certificate-authority: pki/ca.crt, tls-server-name: dev.internal, proxy-url: "socks5://localhost:1080"}
- name: eks
  cluster: {server: "https://shadowed.example", certificate-authority-data: `+b64(c.clusterCA)+`}
`), 0o600)
	s := load(t, first, c.path, filepath.Join(t.TempDir(), "missing"))
	cl, err := s.ClusterByServer("https://dev.example")
	if err != nil || cl == nil || cl.Name != "dev" || !bytes.Equal(cl.CAPEM, c.clusterCA) || cl.TLSServerName != "dev.internal" || cl.ProxyURL != "socks5://localhost:1080" {
		t.Fatalf("%+v %v", cl, err)
	}
	if cl, err := s.ClusterByServer("https://hydra.example:16443"); err != nil || cl == nil || cl.Name != "hydra-cluster" {
		t.Fatalf("%+v %v", cl, err)
	}
	// Exactly: no normalising, no prefix.
	for _, other := range []string{"https://hydra.example:16443/", "https://HYDRA.example:16443", "https://hydra.example", "https://nowhere.example"} {
		if cl, err := s.ClusterByServer(other); cl != nil || err != nil {
			t.Errorf("%s: %+v %v", other, cl, err)
		}
	}
	// The eks entry of the second file is shadowed by the first's.
	if cl, _ := s.ClusterByServer("https://ABC.gr7.eu-west-1.eks.amazonaws.com"); cl != nil {
		t.Fatalf("a shadowed definition: %+v", cl)
	}
	// Two clusters with the server and different CAs: never one of them.
	p := filepath.Join(t.TempDir(), "config")
	_ = os.WriteFile(p, []byte(strings.Replace(c.body, "    server: https://ABC.gr7.eu-west-1.eks.amazonaws.com\n    certificate-authority-data: "+b64(c.clusterCA),
		"    server: https://hydra.example:16443\n    certificate-authority-data: "+b64(pemCert(t, "evil CA", nil, true)), 1)), 0o600)
	if cl, err := load(t, p).ClusterByServer("https://hydra.example:16443"); cl != nil || !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ambiguous: %+v %v", cl, err)
	}
	// The same CA twice is one cluster.
	_ = os.WriteFile(p, []byte(strings.Replace(c.body, "    server: https://ABC.gr7.eu-west-1.eks.amazonaws.com\n", "    server: https://hydra.example:16443\n", 1)), 0o600)
	if cl, err := load(t, p).ClusterByServer("https://hydra.example:16443"); cl == nil || err != nil {
		t.Fatalf("the same CA twice: %+v %v", cl, err)
	}
}

// strip removes from got the lines of each added item, so the rest can be
// compared with the original byte for byte.
func strip(got string, added ...string) string {
	for _, a := range added {
		got = strings.Replace(got, a, "", 1)
	}
	return got
}

func TestAddWritesExactlyTheThreeEntries(t *testing.T) {
	c := newCorpus(t)
	e := c.entries("hydra-nazar")
	e.TLSServerName = "hydra.internal"
	ch, err := load(t, c.path).Add(e)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Path != c.path || ch.New || string(ch.Original) != c.body {
		t.Fatalf("%+v", ch)
	}
	got := string(ch.Data)
	items := e.items()
	added := []string{itemText(0, items["clusters"]...), itemText(0, items["users"]...), itemText(0, items["contexts"]...)}
	for _, a := range added {
		if !strings.Contains(got, a) {
			t.Fatalf("the entry is missing:\n%s\nin:\n%s", a, got)
		}
	}
	if rest := strip(got, added...); rest != c.body {
		t.Fatalf("every other byte stays:\n%s", rest)
	}
	// It reads back: nazar's own entries, a context naming them.
	p := filepath.Join(t.TempDir(), "config")
	_ = os.WriteFile(p, ch.Data, 0o600)
	s := load(t, p)
	ctx, _ := s.find("contexts", "context", "hydra-nazar")
	us, _ := s.find("users", "user", "nazar-hydra-nazar")
	cl, _ := s.find("clusters", "cluster", "nazar-hydra-nazar")
	if cmd, ok := exactEntry(us.body, "hydra-nazar"); !ok || cmd != e.Command || scalar(ctx.body, "cluster") != "nazar-hydra-nazar" ||
		scalar(cl.body, "server") != e.Server || scalar(cl.body, "tls-server-name") != "hydra.internal" {
		t.Fatalf("read back:\n%s", ch.Data)
	}
	if rc := readCluster(cl); !bytes.Equal(rc.CAPEM, c.clusterCA) {
		t.Fatal("the CA is the given one")
	}
	// The current context stays.
	if name, _ := s.CurrentContext(); name != "hydra" {
		t.Fatalf("current-context changed: %q", name)
	}
	// Again: exactly nazar's, so set up.
	if _, err := s.Add(e); !errors.Is(err, ErrSetUp) {
		t.Fatalf("again: %v", err)
	}
}

func TestAddToEveryListLayout(t *testing.T) {
	c := newCorpus(t)
	e := c.entries("hydra-nazar")
	items := e.items()
	at := func(indent int) []string {
		return []string{itemText(indent, items["clusters"]...), itemText(indent, items["users"]...), itemText(indent, items["contexts"]...)}
	}
	for name, tc := range map[string]struct {
		body string
		want []string // the added text; the rest must be body
	}{
		"indented lists": {"apiVersion: v1\nclusters:\n  - name: a\n    cluster:\n      server: https://a.example\n      # a comment\n\n      certificate-authority-data: x\nusers:\n  - name: u\n    user:\n      token: " + otherToken + "\ncontexts:\n  - name: a\n    context: {cluster: a, user: u}\n# trailing\n", at(2)},
		"block scalar":   {"clusters:\n- name: a\n  cluster:\n    x: |\n      line one\n\n      line two\nusers: []\ncontexts: null\n", nil},
		"no lists":       {"apiVersion: v1\nkind: Config\ncurrent-context: x", nil},
		"empty file":     {"", nil},
		"nulls":          {"apiVersion: v1\nclusters: null\nusers:\ncontexts: ~ # none\npreferences: {}\n", nil},
		// Security review: the last list's last item ends the file.
		"no final newline": {"contexts: []\nclusters: []\nusers:\n- name: u\n  user:\n    token: " + otherToken, nil},
	} {
		p := filepath.Join(t.TempDir(), "config")
		_ = os.WriteFile(p, []byte(tc.body), 0o600)
		ch, err := load(t, p).Add(e)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if tc.want != nil {
			if rest := strip(string(ch.Data), tc.want...); rest != tc.body {
				t.Errorf("%s: every other byte stays:\n%s", name, rest)
			}
		}
		_ = os.WriteFile(p, ch.Data, 0o600)
		if _, err := load(t, p).Add(e); !errors.Is(err, ErrSetUp) {
			t.Errorf("%s: the result holds exactly nazar's entries: %v\n%s", name, err, ch.Data)
		}
		noSecret(t, name, strip(string(ch.Data), otherToken))
	}
	// The block scalar keeps its lines: the item goes after them.
	p := filepath.Join(t.TempDir(), "config")
	_ = os.WriteFile(p, []byte("clusters:\n- name: a\n  cluster:\n    x: |\n      line one\n\n      line two\nusers: []\n"), 0o600)
	ch, err := load(t, p).Add(e)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Clusters []struct {
			Name    string         `yaml:"name"`
			Cluster map[string]any `yaml:"cluster"`
		} `yaml:"clusters"`
	}
	if err := yaml.Unmarshal(ch.Data, &doc); err != nil || len(doc.Clusters) != 2 || doc.Clusters[0].Cluster["x"] != "line one\n\nline two\n" {
		t.Fatalf("%+v %v\n%s", doc, err, ch.Data)
	}
}

func TestAddToANewFile(t *testing.T) {
	c := newCorpus(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "kube", "config")
	ch, err := load(t, p).Add(c.entries("hydra-nazar"))
	if err != nil {
		t.Fatal(err)
	}
	if !ch.New || ch.Path != p {
		t.Fatalf("%+v", ch)
	}
	pend, err := PrepareChange(ch)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "kube")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the directory is made 0700: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("nothing at the path before Commit")
	}
	if b, err := pend.Commit(nil, time.Now()); err != nil || b != "" {
		t.Fatalf("no backup of a new file: %q %v", b, err)
	}
	if got, _ := os.ReadFile(p); !bytes.Equal(got, ch.Data) {
		t.Fatal("written")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("0600: %v", fi.Mode())
	}
	if files, _ := os.ReadDir(filepath.Join(dir, "kube")); len(files) != 1 {
		t.Fatalf("no temp file left: %v", files)
	}
	// A file that appears meanwhile is never replaced.
	q := filepath.Join(dir, "other")
	ch, _ = load(t, q).Add(c.entries("hydra-nazar"))
	pend, err = PrepareChange(ch)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(q, []byte("theirs\n"), 0o600)
	if _, err := pend.Commit(nil, time.Now()); err == nil {
		t.Fatal("a file put there meanwhile must stay")
	}
	if got, _ := os.ReadFile(q); string(got) != "theirs\n" {
		t.Fatal("left alone")
	}
}

func TestAddRefusesNamesItDidNotWrite(t *testing.T) {
	c := newCorpus(t)
	e := c.entries("hydra")
	// The context hydra is the user's admin context: refused, by name.
	_, err := load(t, c.path).Add(e)
	if err == nil || errors.Is(err, ErrSetUp) || !strings.Contains(err.Error(), `context "hydra"`) {
		t.Fatalf("%v", err)
	}
	noSecret(t, "the error", err.Error())
	// A cluster or a user of nazar's names, anywhere in the set.
	for _, list := range []string{"clusters", "users"} {
		extra := filepath.Join(t.TempDir(), "extra")
		_ = os.WriteFile(extra, []byte(list+":\n- name: nazar-hydra-nazar\n  "+strings.TrimSuffix(list, "s")+": {}\n"), 0o600)
		if _, err := load(t, c.path, extra).Add(c.entries("hydra-nazar")); err == nil || errors.Is(err, ErrSetUp) || !strings.Contains(err.Error(), "nazar-hydra-nazar") {
			t.Errorf("%s: %v", list, err)
		}
	}
	// nazar's entries, but changed: not set up, refused.
	ch, err := load(t, c.path).Add(c.entries("hydra-nazar"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config")
	for name, edit := range map[string][2]string{
		"another nazar":   {`command: "/Users/u/.local/bin/nazar"`, `command: "/opt/homebrew/bin/nazar"`},
		"a bare nazar":    {`command: "/Users/u/.local/bin/nazar"`, `command: "nazar"`},
		"an env block":    {`interactiveMode: "Never"`, "interactiveMode: \"Never\"\n      env: [{name: HOME, value: /tmp}]"},
		"a credential":    {"- name: \"nazar-hydra-nazar\"\n  user:\n    exec:", "- name: \"nazar-hydra-nazar\"\n  user:\n    token: x\n    exec:"},
		"a namespace":     {`  user: "nazar-hydra-nazar"`, "  user: \"nazar-hydra-nazar\"\n    namespace: kube-system"},
		"another server":  {`server: "https://hydra.example:16443"`, `server: "https://evil.example"`},
		"insecure":        {`server: "https://hydra.example:16443"`, "server: \"https://hydra.example:16443\"\n    insecure-skip-tls-verify: true"},
		"another context": {`  cluster: "nazar-hydra-nazar"`, `  cluster: "hydra-cluster"`},
	} {
		body := strings.Replace(string(ch.Data), edit[0], edit[1], 1)
		if body == string(ch.Data) {
			t.Fatalf("%s: the edit did not apply", name)
		}
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := load(t, p).Add(c.entries("hydra-nazar")); err == nil || errors.Is(err, ErrSetUp) {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
}

func TestAddQuotesEveryValue(t *testing.T) {
	c := newCorpus(t)
	p := filepath.Join(t.TempDir(), "config")
	_ = os.WriteFile(p, []byte(c.body), 0o600)
	// A name YAML would read as a boolean, a path with quotes, a newline
	// and a "key: value" in it: each stays one string.
	e := c.entries("true")
	e.Command = "/Users/a b/\"x\": y\n- k8s/nazar"
	ch, err := load(t, p).Add(e)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p, ch.Data, 0o600)
	s := load(t, p)
	us, _ := s.find("users", "user", "nazar-true")
	if cmd, ok := exactEntry(us.body, "true"); !ok || cmd != e.Command {
		t.Fatalf("%q %v\n%s", cmd, ok, ch.Data)
	}
	if _, err := s.Add(e); !errors.Is(err, ErrSetUp) {
		t.Fatal(err)
	}
	// Bad entries are refused before anything is rendered.
	for name, bad := range map[string]Entries{
		"name":    {Context: "a/b", Server: e.Server, CAPEM: c.clusterCA, Command: "/n"},
		"server":  {Context: "x", Server: "https://hydra.example:443", CAPEM: c.clusterCA, Command: "/n"},
		"ca":      {Context: "x", Server: e.Server, CAPEM: []byte("not a cert"), Command: "/n"},
		"command": {Context: "x", Server: e.Server, CAPEM: c.clusterCA, Command: "nazar"},
	} {
		if _, err := s.Add(bad); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}

func TestAddRefusesWhatItCanNotEditByLine(t *testing.T) {
	c := newCorpus(t)
	e := c.entries("hydra-nazar")
	for name, body := range map[string]string{
		"flow list":    "clusters: [{name: a, cluster: {server: https://a.example}}]\n",
		"flow top":     "{clusters: [], users: []}\n",
		"scalar list":  "clusters: none\n",
		"mapping list": "clusters: {a: b}\n",
	} {
		p := filepath.Join(t.TempDir(), "config")
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := load(t, p).Add(e); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}

func TestRemoveTakesOnlyNazarsExactEntries(t *testing.T) {
	c := newCorpus(t)
	ch, err := load(t, c.path).Add(c.entries("hydra-nazar"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "config")
	_ = os.WriteFile(p, ch.Data, 0o600)
	rm, left, err := load(t, p).Remove("hydra-nazar")
	if err != nil || len(left) != 0 || rm == nil || rm.Path != p || string(rm.Data) != c.body || len(rm.Removed) != 3 {
		t.Fatalf("%+v %v %v", rm, left, err)
	}
	// Nothing of nazar's: nothing to do.
	if rm, left, err := load(t, c.path).Remove("hydra-nazar"); rm != nil || len(left) != 0 || err != nil {
		t.Fatalf("%+v %v %v", rm, left, err)
	}
	// The user's own context of that name is never removed: only named.
	if rm, left, err := load(t, c.path).Remove("hydra"); rm != nil || err != nil || len(left) != 1 || left[0] != "kubectl config delete-context hydra" {
		t.Fatalf("%+v %v %v", rm, left, err)
	}
	// One entry changed: the other two go, the changed one is named.
	body := strings.Replace(string(ch.Data), `  user: "nazar-hydra-nazar"`, "  user: \"nazar-hydra-nazar\"\n    namespace: kube-system", 1)
	_ = os.WriteFile(p, []byte(body), 0o600)
	rm, left, err = load(t, p).Remove("hydra-nazar")
	if err != nil || rm == nil || len(rm.Removed) != 2 || len(left) != 1 || left[0] != "kubectl config delete-context hydra-nazar" {
		t.Fatalf("%+v %v %v", rm, left, err)
	}
	if !strings.Contains(string(rm.Data), "namespace: kube-system") || strings.Contains(string(rm.Data), "k8s\"\n") {
		t.Fatalf("%s", rm.Data)
	}
	noSecret(t, "forget", fmt.Sprint(left))
	// An entry of nazar's name defined twice: named, never guessed.
	two := string(ch.Data) + "" // the first file
	other := filepath.Join(t.TempDir(), "other")
	_ = os.WriteFile(other, []byte("clusters:\n- name: nazar-hydra-nazar\n  cluster: {server: https://x.example}\n"), 0o600)
	_ = os.WriteFile(p, []byte(two), 0o600)
	rm, left, err = load(t, p, other).Remove("hydra-nazar")
	if err != nil || rm == nil || len(rm.Removed) != 2 || len(left) != 1 || left[0] != "kubectl config delete-cluster nazar-hydra-nazar" {
		t.Fatalf("%+v %v %v", rm, left, err)
	}
}

func TestRemoveKeepsEveryOtherByte(t *testing.T) {
	c := newCorpus(t)
	// nazar's entries in the middle of indented lists, comments around.
	body := "apiVersion: v1\nclusters:\n  - name: a\n    cluster: {server: https://a.example}\n  # head of b\n  - name: b\n    cluster: {server: https://b.example}\nusers:\n  - name: u\n    user: {token: " + otherToken + "}\ncontexts:\n  - name: a\n    context: {cluster: a, user: u}\n"
	p := filepath.Join(t.TempDir(), "config")
	_ = os.WriteFile(p, []byte(body), 0o600)
	ch, err := load(t, p).Add(c.entries("x"))
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(p, ch.Data, 0o600)
	rm, left, err := load(t, p).Remove("x")
	if err != nil || len(left) != 0 || string(rm.Data) != body {
		t.Fatalf("%v %v\n%s", left, err, rm.Data)
	}
}

// Every error and every value Add, Remove and the defaults return is
// free of the corpus's credentials, whatever goes wrong.
func TestNoCredentialInAnyResult(t *testing.T) {
	c := newCorpus(t)
	s := load(t, c.path)
	_, cl := s.CurrentContext()
	byServer, _ := s.ClusterByServer("https://ABC.gr7.eu-west-1.eks.amazonaws.com")
	results := fmt.Sprintf("%+v %+v", cl, byServer)
	for _, name := range []string{"hydra", "eks", "tok", "basic", "hydra-nazar", "nazar-hydra"} {
		e := c.entries(name)
		if ch, err := s.Add(e); err != nil {
			results += err.Error()
		} else {
			added := []string{}
			for _, l := range lists {
				added = append(added, itemText(0, e.items()[l.list]...))
			}
			if strip(string(ch.Data), added...) != c.body {
				t.Errorf("%s: more than nazar's entries changed", name)
			}
			results += strings.Join(added, "")
		}
		rm, left, err := s.Remove(name)
		results += fmt.Sprint(left, err)
		if rm != nil {
			t.Errorf("%s: nothing of nazar's to remove", name)
		}
	}
	noSecret(t, "a result", results)
}
