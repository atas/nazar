//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/layout"
)

// aws design 8, 11.3: every nazar aws command of the test build against
// nazar-testd in a temp home, in the order docs/CLI.md's AWS section gives
// them, then credential_process run the ways the SDKs run it: by sh -c with
// stdout a pipe (the Go SDK, Terraform) and by Popen with stdout=PIPE
// (botocore, the AWS CLI). nazar-testd vouches for no CLI, so every
// credential here is refused by check 0, with nothing on stdout; minting is
// the daemon tests'. Nothing here reads ~/.aws or reaches AWS.
func TestAWSCommandsAsTheDocsSay(t *testing.T) {
	cli := filepath.Join(bin, "nazar")
	if body, err := os.ReadFile(cli); err != nil || !strings.Contains(string(body), "NAZAR_TEST_CONTROL_SOCKET") {
		t.Fatalf("%s is not the nazartest build (%v): its aws credential would dial the account's nazar-agent", cli, err)
	}
	w := newWorld(t, `{"auth":"allow"}`)
	// No aws on PATH: ca create pins no program, so it needs none (aws
	// design 6.1).
	path := "PATH=/usr/bin:/bin"
	run := func(want int, args ...string) string {
		t.Helper()
		out, code := w.run([]string{path}, cli, args...)
		if code != want {
			t.Fatalf("nazar %s: exit %d, want %d\n%s", strings.Join(args, " "), code, want, out)
		}
		return out
	}
	says(t, run(0, "aws", "list"), "No aws entries.")

	out := run(0, "aws", "ca", "create", "dev")
	says(t, out, "dev is set up")
	says(t, out, "aws rolesanywhere create-trust-anchor --name nazar-dev --enabled", "docs/design/aws-design.md")
	says(t, out, "aws iam create-role --role-name dev")
	says(t, out, "[profile dev]", "docs/CLI.md")
	says(t, out, "credential_process = "+cli+" aws credential dev")
	says(t, out, "aws sts get-caller-identity --profile dev", "docs/CLI.md")
	crt := filepath.Join(layout.KeysDir(w.home), "aws-ca-dev.crt")
	pemFile, err := os.ReadFile(crt)
	if err != nil {
		t.Fatal(err)
	}
	says(t, out, crt)
	c := w.readConfig()
	if !strings.Contains(c, "aws:\n  dev:\n") || !strings.Contains(c, "-nazar") || !strings.Contains(c, "gate: block") ||
		strings.Contains(c, "clients") || strings.Contains(c, "path:") {
		t.Errorf("config.yaml must have an aws.dev entry with identity <user>-nazar, and no clients or apps.aws:\n%s", c)
	}
	says(t, run(0, "aws", "ca", "show", "dev"), string(pemFile))
	out = run(0, "aws", "list")
	says(t, out, "is not connected yet: add trustAnchorArn, profileArn and roleArn")
	says(t, out, "CA: SHA-256 ")
	var list struct {
		Kind  string `json:"kind"`
		Items []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(run(0, "--json", "aws", "list")), &list); err != nil || list.Kind != "AWSEntryList" ||
		len(list.Items) != 1 || list.Items[0].Name != "dev" || list.Items[0].State != "not-connected" {
		t.Errorf("aws list --json: %v %+v", err, list)
	}
	// A rule edit that loosens: refused and only shown without the flag,
	// written and approved at once with it.
	rule := []string{"--json", "aws", "rule", "add", "dev", "--apps", "signed:Q6L2SF6YDW:com.anthropic.claude-code", "--gate", "dialog", "--scope", "session"}
	says(t, run(2, rule...), "this change loosens access; nothing was changed")
	if strings.Contains(w.readConfig(), "com.anthropic.claude-code") {
		t.Fatal("a refused rule edit wrote config.yaml")
	}
	says(t, run(0, append(rule, "--allow-loosen-access")...), `"aws":"dev"`)
	says(t, run(0, "aws", "list"), `rule 2: apps=[signed:"Q6L2SF6YDW":"com.anthropic.claude-code"]`)

	// credential_process, as the SDKs run it: refused by check 0 here,
	// exit 3, one line on stderr, nothing on stdout.
	process := cli + " aws credential dev"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second) // the Go SDK's timeout
	defer cancel()
	sdk := exec.CommandContext(ctx, "/bin/sh", "-c", process)
	sdk.Env = w.env(path)
	var stdout, stderr bytes.Buffer
	sdk.Stdout, sdk.Stderr = &stdout, &stderr
	err = sdk.Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 3 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "nazar: peer is not the nazar CLI") {
		t.Fatalf("sh -c: %v, stdout %q, stderr %q", err, stdout.String(), stderr.String())
	}
	if !w.auditHas("decision=blocked", "target=aws:dev", "not the nazar CLI") {
		t.Errorf("no blocked aws:dev line in nazar-testd's audit:\n%s", w.auditDump())
	}
	if py, err := exec.LookPath("python3"); err != nil {
		t.Log("no python3: the botocore-like run is not tested")
	} else {
		const botocore = `import shlex, subprocess, sys
p = subprocess.Popen(shlex.split(sys.argv[1]), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = p.communicate()
sys.stdout.write("%d %d %s" % (p.returncode, len(out), err.decode()))
`
		pc := exec.CommandContext(ctx, py, "-I", "-c", botocore, process)
		pc.Env = w.env(path)
		got, err := pc.Output()
		if err != nil || !strings.HasPrefix(string(got), "3 0 nazar: peer is not the nazar CLI") {
			t.Fatalf("Popen: %v %q", err, got)
		}
	}

	// nazar aws forget dev: the CA, its file and the entry go.
	out = run(0, "aws", "forget", "dev")
	says(t, out, "nazar forgot dev")
	says(t, out, "disable or delete the trust anchor")
	if _, err := os.Stat(crt); !os.IsNotExist(err) {
		t.Errorf("forget left %s (%v)", crt, err)
	}
}
