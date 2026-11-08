package kubeconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The k8s design: reading the kubeconfig set, and
// the atomic, symlink-safe write with its one backup. entries_test.go has
// the defaults and nazar's three entries.

func pemCert(t *testing.T, cn string, orgs []string, isCA bool) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn, Organization: orgs},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// secrets of the corpus: every one must stay out of every printed diff.
const (
	hydraKey   = "-----BEGIN EC PRIVATE KEY-----\nHYDRAKEYSECRET0123456789\n-----END EC PRIVATE KEY-----\n"
	otherToken = "OTHERTOKENSECRET-abcdef0123456789"
	otherKey   = "-----BEGIN EC PRIVATE KEY-----\nOTHERKEYSECRET987654321\n-----END EC PRIVATE KEY-----\n"
	awsSecret  = "AWSSECRETVALUE-0000111122223333"
	password   = "PASSWORDSECRET-xyz"
	// Reviews: credentials kept in comments, in other plugins'
	// args and in an auth-provider's config.
	commentKey  = "COMMENTKEYSECRET-555"
	lineComment = "LINECOMMENTSECRET-666"
	argSecret   = "ARGTOKENSECRET-777"
	idToken     = "IDTOKENSECRET-888"
	refreshTok  = "REFRESHSECRET-999"
	clientSec   = "CLIENTSECRET-000"
)

// allSecrets is every credential of the corpus.
var allSecrets = []string{"HYDRAKEYSECRET", otherToken, "OTHERKEYSECRET", awsSecret, password, commentKey, lineComment, argSecret, idToken, refreshTok, clientSec}

type corpus struct {
	dir, path string
	clusterCA []byte
	hydraCert []byte
	body      string
}

// newCorpus writes a kubeconfig shaped like real ones: the hydra context
// with an inline admin certificate (CN=admin, O=system:masters), an
// impersonating key, comments, a token user, an aws exec user with an env
// block, a basic-auth user and a second cluster.
func newCorpus(t *testing.T) *corpus {
	t.Helper()
	// Resolved: on macOS t.TempDir() is under /var, a link to /private/var,
	// and Prepare works in the resolved directory.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := &corpus{dir: dir}
	c.clusterCA = pemCert(t, "microk8s CA", nil, true)
	c.hydraCert = pemCert(t, "admin", []string{"system:masters"}, false)
	c.body = `# kubeconfig written by microk8s config
apiVersion: v1
kind: Config
clusters:
- name: hydra-cluster
  cluster:
    server: https://hydra.example:16443   # the node
    certificate-authority-data: ` + b64(c.clusterCA) + `
- name: eks
  cluster:
    server: https://ABC.gr7.eu-west-1.eks.amazonaws.com
    certificate-authority-data: ` + b64(c.clusterCA) + `
users:
- name: hydra-admin
  user:
    # client-key-data: ` + commentKey + `
    client-certificate-data: ` + b64(c.hydraCert) + `
    client-key-data: ` + b64([]byte(hydraKey)) + `
    as-groups: [readers] # old token ` + lineComment + `
    x-unknown-key: kept
- name: other
  user:
    token: ` + otherToken + `
    client-key-data: ` + b64([]byte(otherKey)) + `
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args: [eks, get-token]
      env:
      - name: AWS_SECRET_ACCESS_KEY
        value: ` + awsSecret + `
- name: basic
  user:
    username: admin
    password: ` + password + `
- name: gke
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: get-token
      args: [--token, ` + argSecret + `]
- name: oidc
  user:
    auth-provider:
      name: oidc
      config: {id-token: ` + idToken + `, refresh-token: ` + refreshTok + `, client-secret: ` + clientSec + `}
contexts:
- name: hydra
  context: {cluster: hydra-cluster, user: hydra-admin, namespace: default}
- name: eks
  context: {cluster: eks, user: aws}
- name: tok
  context: {cluster: hydra-cluster, user: other}
- name: basic
  context: {cluster: hydra-cluster, user: basic}
current-context: hydra
`
	c.path = filepath.Join(c.dir, "config")
	if err := os.WriteFile(c.path, []byte(c.body), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

func load(t *testing.T, paths ...string) *Set {
	t.Helper()
	s, err := Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPaths(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	if got := Paths(getenv, "/Users/u"); !slices.Equal(got, []string{"/Users/u/.kube/config"}) {
		t.Fatal(got)
	}
	// client-go does not expand ~ in $KUBECONFIG, and neither does nazar
	// (security review: the file pinned must be the file kubectl reads).
	// A relative entry is relative to the working directory, as kubectl
	// reads it (security review: the daemon takes absolute paths only).
	wd, _ := os.Getwd()
	env["KUBECONFIG"] = "/a/one::~/two:" + string(os.PathListSeparator)
	if got := Paths(getenv, "/Users/u"); !slices.Equal(got, []string{"/a/one", filepath.Join(wd, "~/two")}) {
		t.Fatal(got)
	}
}

// Security review nit: only a regular file is read, so a certificate-
// authority naming a FIFO (or /dev/tty) can't hang the CLI or take the
// answers typed at its questions.
func TestReadsOnlyRegularFiles(t *testing.T) {
	c := newCorpus(t)
	fifo := filepath.Join(c.dir, "ca.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(c.body, "    certificate-authority-data: "+b64(c.clusterCA)+"\n", "    certificate-authority: ca.fifo\n", 1)
	_ = os.WriteFile(c.path, []byte(body), 0o600)
	done := make(chan *Cluster, 1)
	go func() { _, cl := load(t, c.path).CurrentContext(); done <- cl }()
	select {
	case cl := <-done:
		if cl == nil || cl.CAErr == nil || cl.CAPEM != nil {
			t.Fatalf("%+v", cl)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO hangs")
	}
	if _, err := Load([]string{fifo}); err == nil {
		t.Fatal("a FIFO is not a kubeconfig")
	}
}

func TestPrepareCommitAbort(t *testing.T) {
	c := newCorpus(t)
	if err := os.Chmod(c.path, 0o640); err != nil {
		t.Fatal(err)
	}
	// A stale temp file of a crashed run: removed, never read.
	stale := filepath.Join(c.dir, ".config.nazar-tmp.123abc")
	_ = os.WriteFile(stale, []byte("old plaintext"), 0o600)
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(stale, old, old)
	p, err := Prepare(c.path, []byte("new: content\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("a stale temp file must be removed")
	}
	fi, err := os.Stat(p.TempPath())
	if err != nil || fi.Mode().Perm() != 0o600 || filepath.Dir(p.TempPath()) != c.dir || !strings.HasPrefix(filepath.Base(p.TempPath()), ".config.nazar-tmp.") {
		t.Fatalf("the temp file is 0600 in the target's directory: %v %v", fi, err)
	}
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	backup, err := p.Commit([]byte(c.body), now)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(c.path); string(got) != "new: content\n" {
		t.Fatal("the target holds the new content")
	}
	if fi, _ := os.Stat(c.path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("a group-readable original ends 0600: %v", fi.Mode())
	}
	if backup != filepath.Join(c.dir, "config.nazar-backup-20261018T000000Z") {
		t.Fatal(backup)
	}
	if b, _ := os.ReadFile(backup); string(b) != c.body {
		t.Fatal("the backup is the original, byte for byte")
	}
	if fi, _ := os.Stat(backup); fi.Mode().Perm() != 0o600 {
		t.Fatalf("the backup is 0600: %v", fi.Mode())
	}
	if _, err := os.Stat(p.TempPath()); !os.IsNotExist(err) {
		t.Fatal("no temp file left")
	}
	// A second commit in the same second never overwrites a backup.
	p2, err := Prepare(c.path, []byte("again\n"))
	if err != nil {
		t.Fatal(err)
	}
	if b2, err := p2.Commit([]byte("new: content\n"), now); err != nil || b2 == backup {
		t.Fatalf("a second backup: %q %v", b2, err)
	}
	// Abort: nothing changes, nothing left.
	before, _ := os.ReadFile(c.path)
	p3, err := Prepare(c.path, []byte("never\n"))
	if err != nil {
		t.Fatal(err)
	}
	p3.Abort()
	if after, _ := os.ReadFile(c.path); string(after) != string(before) {
		t.Fatal("abort must leave the file")
	}
	if _, err := os.Stat(p3.TempPath()); !os.IsNotExist(err) {
		t.Fatal("abort removes the temp file")
	}
}

func TestCommitRefusesAChangedFile(t *testing.T) {
	c := newCorpus(t)
	p, err := Prepare(c.path, []byte("new\n"))
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(c.path, []byte("edited meanwhile\n"), 0o600)
	if _, err := p.Commit([]byte(c.body), time.Now()); err == nil {
		t.Fatal("a file edited after it was read must not be overwritten")
	}
	if got, _ := os.ReadFile(c.path); string(got) != "edited meanwhile\n" {
		t.Fatal("left as it was")
	}
	if _, err := os.Stat(p.TempPath()); !os.IsNotExist(err) {
		t.Fatal("no temp file left")
	}
	if m, _ := filepath.Glob(filepath.Join(c.dir, "*nazar-backup*")); len(m) != 0 {
		t.Fatalf("no backup written: %v", m)
	}
}

func TestCommitFollowsTheLinkAndKeepsIt(t *testing.T) {
	c := newCorpus(t)
	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "config")
	if err := os.Symlink(c.path, link); err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(link, []byte("new\n"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p.TempPath()) != c.dir {
		t.Fatalf("the temp file belongs in the target's directory: %s", p.TempPath())
	}
	backup, err := p.Commit([]byte(c.body), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the link is kept")
	}
	if got, _ := os.ReadFile(c.path); string(got) != "new\n" {
		t.Fatal("the target is rewritten")
	}
	// Security review: the backup sits beside the path the user
	// named, not in the link's target directory (a dotfiles repo).
	if filepath.Dir(backup) != linkDir {
		t.Fatalf("the backup sits beside the link: %s", backup)
	}
}

func TestTempAndBackupNeverFollowAPlantedFile(t *testing.T) {
	c := newCorpus(t)
	victim := filepath.Join(t.TempDir(), "victim")
	_ = os.WriteFile(victim, []byte("victim"), 0o600)
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	// A link planted where the backup would go.
	if err := os.Symlink(victim, filepath.Join(c.dir, "config.nazar-backup-20261018T000000Z")); err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(c.path, []byte("new\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Commit([]byte(c.body), now)
	if err == nil && b == filepath.Join(c.dir, "config.nazar-backup-20261018T000000Z") {
		t.Fatal("the planted link must not be written through")
	}
	if got, _ := os.ReadFile(victim); string(got) != "victim" {
		t.Fatal("the link's target was written")
	}
	// A stale-temp-looking link is removed, never followed.
	planted := filepath.Join(c.dir, ".config.nazar-tmp.zzz")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatal(err)
	}
	// (a link is never one of nazar's temp files: removed whatever its age)
	if p, err := Prepare(c.path, []byte("x\n")); err == nil {
		p.Abort()
	}
	if got, _ := os.ReadFile(victim); string(got) != "victim" {
		t.Fatal("the link's target was touched")
	}
	if _, err := os.Lstat(planted); !os.IsNotExist(err) {
		t.Fatal("the planted link is removed")
	}
}

func TestPrepareRefusesAnUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	c := newCorpus(t)
	if err := os.Chmod(c.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(c.dir, 0o700) })
	if _, err := Prepare(c.path, []byte("x\n")); err == nil {
		t.Fatal("a kubeconfig in a directory nazar can't write fails before anything else")
	}
}

// Security review: a file nazar can't edit faithfully is
// refused, never half-written: a second YAML document, anchors, aliases
// and merge keys (an entry could then be other than its text reads).
func TestLoadRefusesWhatARewriteWouldDamage(t *testing.T) {
	c := newCorpus(t)
	for name, body := range map[string]string{
		"two documents": c.body + "---\napiVersion: v1\nkind: Config\n",
		"anchor":        strings.Replace(c.body, "    client-key-data: ", "    client-key-data: &k ", 1),
		"alias":         strings.Replace(c.body, "    username: admin\n", "    username: &u admin\n    x: *u\n", 1),
		"merge key":     strings.Replace(c.body, "    x-unknown-key: kept\n", "    <<: {token: x}\n", 1),
		"a key twice":   strings.Replace(c.body, "    server: https://hydra.example:16443   # the node\n", "    server: https://hydra.example:16443\n    server: https://evil.example\n", 1),
	} {
		p := filepath.Join(t.TempDir(), "config")
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := Load([]string{p}); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}

// Reviews: only the exact entry import writes counts as imported;
// any other entry that runs nazar for the context is refused, by name.
// Security and spec reviews: Commit honours
// client-go's lock file, says when it tightened the mode, and keeps a
// stricter mode as it is.
func TestCommitLockAndMode(t *testing.T) {
	c := newCorpus(t)
	_ = os.WriteFile(c.path+".lock", nil, 0o600)
	p, err := Prepare(c.path, []byte("new\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit([]byte(c.body), time.Now()); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("a kubeconfig another program is writing: %v", err)
	}
	if b, _ := os.ReadFile(c.path); string(b) != c.body {
		t.Fatal("left as it was")
	}
	_ = os.Remove(c.path + ".lock")
	_ = os.Chmod(c.path, 0o400)
	p, err = Prepare(c.path, []byte("new\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Commit([]byte(c.body), time.Now()); err != nil || p.Tightened() {
		t.Fatalf("%v %v", err, p.Tightened())
	}
	if fi, _ := os.Stat(c.path); fi.Mode().Perm() != 0o400 {
		t.Fatalf("a stricter mode is kept: %v", fi.Mode())
	}
	if _, err := os.Stat(c.path + ".lock"); !os.IsNotExist(err) {
		t.Fatal("the lock is released")
	}
	_ = os.Chmod(c.path, 0o644)
	p, _ = Prepare(c.path, []byte("again\n"))
	if _, err := p.Commit([]byte("new\n"), time.Now()); err != nil || !p.Tightened() {
		t.Fatalf("a world-readable kubeconfig is made 0600 and says so: %v", err)
	}
}

// Security review: only an old temp file is stale; a live one of
// another run is left alone.
func TestPrepareKeepsAFreshTempFile(t *testing.T) {
	c := newCorpus(t)
	fresh := filepath.Join(c.dir, ".config.nazar-tmp.fresh")
	_ = os.WriteFile(fresh, []byte("x"), 0o600)
	if p, err := Prepare(c.path, []byte("x\n")); err == nil {
		p.Abort()
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("a temp file another run is writing must stay")
	}
}
