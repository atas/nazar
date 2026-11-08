//go:build darwin

package pipes_test

// THREAT-MODEL 5.16: the stdout check against the real kubectl.
// kubectl runs its exec plugin, here this test binary, with fd 1 a pipe
// whose read end kubectl holds, so the check says yes; a kubeconfig that
// wraps the plugin in exec hops which relay its stdout through cat keeps
// kubectl the plugin's parent, and kubectl still gets the credential, but
// the check says no. So it does for a launcher that hands kubectl a pipe
// (its stdin and stderr) and keeps the read end: the wrapper sends the
// plugin's stdout down kubectl's stderr, which client-go gives every
// plugin, and kubectl holds that pipe's read end on stdin. So it does too
// for a launcher that closes its copy once kubectl runs: the credential
// would wait in kubectl's stdin, which kubectl can forward (exec -i), and
// kubectl, the only holder, inherited that read end instead of opening it.
// So it does for a wrapper that leaves a background job holding the
// plugin's stdout: a co-writer that could write around the reply.
// The cluster is an httptest server on 127.0.0.1 in a temp kubeconfig; no
// real kubeconfig or cluster is read. Skipped when no
// kubectl is on PATH. The conformance host (`make conformance`) runs the
// platform conformance group on this package with real processes.

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/pipes"
	"golang.org/x/sys/unix"
)

// pluginEnv names the file the plugin writes its findings to; set only in
// the kubeconfig's exec env, never by a person.
const pluginEnv = "NAZAR_PIPES_TEST_PLUGIN"

const token = "nazar-pipes-test-token"

func TestMain(m *testing.M) {
	if out := os.Getenv(pluginEnv); out != "" {
		plugin(out)
		return
	}
	os.Exit(m.Run())
}

func ref(pid int) (platform.ProcessRef, string, error) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return platform.ProcessRef{}, "", err
	}
	st := k.Proc.P_starttime
	comm := unix.ByteSliceToString(k.Proc.P_comm[:])
	return platform.ProcessRef{PID: pid, Generation: uint64(st.Sec)*1_000_000 + uint64(st.Usec)}, comm, nil
}

// plugin is this binary run by kubectl as an exec plugin: it records
// whether its fd 1 is a pipe, its parent's name and what the stdout check
// answers about its parent, then prints an ExecCredential with a token.
func plugin(out string) {
	self, _, err1 := ref(os.Getpid())
	parent, comm, err2 := ref(os.Getppid())
	fi, err3 := os.Stdout.Stat()
	fifo := err3 == nil && fi.Mode()&os.ModeNamedPipe != 0
	answer := "no stdout check"
	if p := pipes.New(); p != nil && err1 == nil && err2 == nil {
		ok, err := p.StdoutReadBy(self, parent)
		answer = fmt.Sprintf("%v %v", ok, err)
	}
	_ = os.WriteFile(out, []byte(fmt.Sprintf("fifo=%v parent=%s check=%s\n", fifo, comm, answer)), 0o600)
	fmt.Printf(`{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":%q}}`, token)
}

func TestNewOnMacOS(t *testing.T) {
	if pipes.New() == nil {
		t.Fatal("pipes.New() is nil on macOS: nazar-agent would refuse every k8s credential")
	}
}

func TestRealKubectlPipesThePluginsStdout(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("no kubectl on PATH")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var authed atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		authed.Add(1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	for _, tc := range []struct {
		name    string
		command string
		args    []string
		check   string
		// launcher: kubectl's stdin is a pipe's read end, and its stderr
		// that pipe's write end; "keep" keeps the read end here too,
		// "hand over" closes it once kubectl runs.
		launcher string
	}{
		{"the plugin itself", self, nil, "true <nil>", ""},
		// THREAT-MODEL 5.16's wrapper: both hops exec, so kubectl is still
		// the parent, and cat hands kubectl what the plugin wrote.
		{"an exec-hop relay", "/bin/bash", []string{"-c", `exec > >(exec /bin/cat); exec "$0"`, self}, "false <nil>", ""},
		// kubectl alone reads the pipe, but a background job the wrapper
		// left holds the write end too: a co-writer that could write
		// around the reply (kubectl waits for it to exit).
		{"a co-writer", "/bin/bash", []string{"-c", `(exec /bin/sleep 1) & exec "$0"`, self}, "false <nil>", ""},
		// kubectl holds the read end of the plugin's fd 1, but so does this
		// test, which reads the credential; kubectl gets none.
		{"a launcher's own pipe", "/bin/bash", []string{"-c", `exec 1>&2; exec "$0"`, self}, "false <nil>", "keep"},
		// kubectl alone holds the read end, on its stdin: a pipe it was
		// handed, not the one client-go made; kubectl gets none.
		{"a launcher's pipe, handed over", "/bin/bash", []string{"-c", `exec 1>&2; exec "$0"`, self}, "false <nil>", "hand over"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			found := filepath.Join(dir, "plugin.txt")
			kc := filepath.Join(dir, "kubeconfig")
			args := ""
			for _, a := range tc.args {
				args += fmt.Sprintf("\n      - %q", a)
			}
			if args == "" {
				args = " []"
			}
			body := `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: ` + srv.URL + `
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString(ca) + `
users:
- name: test
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: ` + fmt.Sprintf("%q", tc.command) + `
      args:` + args + `
      interactiveMode: Never
      env:
      - {name: ` + pluginEnv + `, value: ` + fmt.Sprintf("%q", found) + `}
contexts:
- name: test
  context: {cluster: test, user: test}
current-context: test
`
			if err := os.WriteFile(kc, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			before := authed.Load()
			cmd := exec.Command(kubectl, "--kubeconfig", kc, "--request-timeout", "30s", "get", "--raw", "/healthz")
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "KUBECONFIG=" + kc}
			cmd.WaitDelay = 5 * time.Second
			if tc.launcher != "" {
				r, w, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				var out bytes.Buffer
				cmd.Stdin, cmd.Stdout, cmd.Stderr = r, &out, w
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				w.Close()
				var leaked []byte
				if tc.launcher == "keep" {
					leaked, _ = io.ReadAll(r)
				} else {
					r.Close()
				}
				err = cmd.Wait()
				if (tc.launcher == "keep") != bytes.Contains(leaked, []byte(token)) || err == nil || authed.Load() != before {
					t.Fatalf("kubectl: %v\n%s\nthe launcher read: %s", err, out.Bytes(), leaked)
				}
			} else if out, err := cmd.CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "ok" || authed.Load() != before+1 {
				t.Fatalf("kubectl: %v\n%s", err, out)
			}
			b, err := os.ReadFile(found)
			if err != nil {
				t.Fatalf("the plugin did not run: %v", err)
			}
			want := "fifo=true parent=kubectl check=" + tc.check + "\n"
			if string(b) != want {
				t.Fatalf("the plugin found %q, want %q", b, want)
			}
		})
	}
}

// TestRealKubectlNeverLeaksTheCredential pins THREAT-MODEL 5.16's "What
// remains". The stdout check keeps every other process off both ends of
// the plugin's pipe, so a wrapper that keeps kubectl the plugin's parent
// cannot read the key or write while the CLI runs; it can only PREFIX
// nazar's bytes, writing before the CLI runs. The danger is that a prefix
// could make client-go's decoder (which reads YAML as well as JSON) read
// nazar's bytes into a field kubectl then sends to the server the
// attacker's kubeconfig names: a prepended `status:\n  token: >-` folded
// scalar captures nazar's whole JSON as the value of status.token, and
// kubectl sends it as a bearer token, key included. nazar closes this by
// starting its reply with a line break and a YAML document-start marker
// (`\n---\n`): at column 0 whatever line a prefix left open, it ends any
// block scalar a prefix opened and is an error inside a flow or quoted
// one, so nazar's bytes can never become part of a prepended field. As
// defence in depth some cases also append, as a co-writer the stdout check
// refuses would. This runs the real kubectl against a TLS server that
// records every request, with a plugin that emits nazar's own encoding of
// a credential whose key carries a marker, framed each way a wrapper
// could, at -v=10 (which dumps HTTP bodies). The marker (the key's base64
// body) must never reach the server, in any header, the URL or the body,
// and never kubectl's own stdout or stderr either. Without the `---`
// marker the folded-token case leaks the key to the server, and with a
// marker not on a line of its own the flow-quoted case with a suffix
// does; with `\n---\n`, none do. Skipped when no kubectl is on PATH.
func TestRealKubectlNeverLeaksTheCredential(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("no kubectl on PATH")
	}
	var seen atomic.Value // the last request the server saw, as text
	seen.Store("")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen.Store(fmt.Sprintf("%s\n%v\n%s", r.URL, r.Header, body))
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	// The marker is how the key appears on the wire: the base64 body of its
	// PEM. nazar encodes the credential exactly as it does in production.
	keyDER := []byte("NAZAR-5-16-KEY-MARKER-9d41b7-uniqueuniqueuniq")
	marker := base64.StdEncoding.EncodeToString(keyDER)
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("certbodycertbodycertbodycertbody")})
	credB, err := k8s.EncodeExecCredential(cert, key, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cred := string(credB)
	decoy := `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"x"}}`
	// The leak the `---` marker closes: a prepended folded scalar that, but
	// for the marker, would capture nazar's whole reply as status.token.
	foldedToken := "apiVersion: client.authentication.k8s.io/v1\nkind: ExecCredential\nstatus:\n  token: >-\n    "
	// A prefix that leaves the line open, so a marker that is not on a
	// line of its own is no marker: a flow single-quoted scalar (nazar's
	// JSON has no ') that a co-writer's suffix closes, which captured the
	// whole reply as status.token while the reply began `---` at whatever
	// column the prefix left.
	flowToken := "# x\n{apiVersion: client.authentication.k8s.io/v1, kind: ExecCredential, status: {token: '"

	for _, tc := range []struct{ name, out string }{
		{"the plugin's own bytes", cred},
		{"garbage prepended", "NOT JSON GARBAGE\n" + cred},
		{"garbage appended", cred + "\nNOT JSON GARBAGE"},
		{"a decoy document first", decoy + "\n---\n" + cred},
		{"the credential first", cred + "\n---\n" + decoy},
		{"a wrong apiVersion", strings.Replace(cred, "/v1", "/v1beta1", 1)},
		{"a folded-scalar token prefix", foldedToken + cred},
		{"a literal-scalar token prefix", strings.Replace(foldedToken, ">-", "|", 1) + cred},
		{"a flow-quoted token prefix and suffix", flowToken + cred + "'}}\n"},
		{"a flow-quoted token prefix", flowToken + cred},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			plug := filepath.Join(dir, "plugin.sh")
			// base64 lets the shell emit arbitrary bytes verbatim.
			b64 := base64.StdEncoding.EncodeToString([]byte(tc.out))
			if err := os.WriteFile(plug, []byte("#!/bin/bash\necho "+b64+" | base64 -d\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			kc := filepath.Join(dir, "kubeconfig")
			body := `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: ` + srv.URL + `
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString(ca) + `
users:
- name: test
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: ` + fmt.Sprintf("%q", plug) + `
      args: []
      interactiveMode: Never
contexts:
- name: test
  context: {cluster: test, user: test}
current-context: test
`
			if err := os.WriteFile(kc, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			seen.Store("")
			cmd := exec.Command(kubectl, "--kubeconfig", kc, "--request-timeout", "20s", "get", "--raw", "/healthz", "-v=10")
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "KUBECONFIG=" + kc}
			cmd.WaitDelay = 5 * time.Second
			// The credential may or may not parse; the test is that the key
			// never reaches the server and kubectl never prints it.
			out, _ := cmd.CombinedOutput()
			if r, _ := seen.Load().(string); strings.Contains(r, marker) {
				t.Fatalf("kubectl sent the plugin's key to the server:\n%s", r)
			}
			if bytes.Contains(out, []byte(marker)) {
				t.Fatalf("kubectl echoed the plugin's key:\n%s", out)
			}
		})
	}
}
