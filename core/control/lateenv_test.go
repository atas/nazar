package control

import (
	"context"
	"strings"
	"testing"
)

// Secrets design 7.3: secret.run carries the caller's candidate
// environment, so it may be up to MaxLargeRequestSize; every other command
// keeps MaxRequestSize. secret.run is a value command: only the genuine
// nazar CLI is served.
func TestSecretRunMayBeLarger(t *testing.T) {
	if MaxLargeRequestSize != 128*1024 {
		t.Fatalf("MaxLargeRequestSize = %d", MaxLargeRequestSize)
	}
	h := &stubHandler{got: make(chan Request, 1), fn: func(_ context.Context, _ Request, out Emitter) {
		out.Emit(RevokeResult{TypeMeta: Meta(KindRevokeResult)})
	}}
	ts := serve(t, h)
	big := strings.Repeat("e", 100*1024)
	var res RevokeResult
	if err := client(ts.path).Call(context.Background(), NewRequest(CmdSecretRun, map[string]string{"callerEnv": big}), KindRevokeResult, &res); err != nil {
		t.Fatalf("a 100 KiB secret.run must be accepted: %v", err)
	}
	if req := <-h.got; req.Args["callerEnv"] != big {
		t.Fatal("argument mangled")
	}
	err := client(ts.path).Call(context.Background(), NewRequest(CmdTrustApp, map[string]string{"app": strings.Repeat("a", 65*1024)}), KindRevokeResult, &res)
	if p := AsProblem(err); p == nil || p.Code != CodeUsage || !strings.Contains(p.Message, "too large (max 65536 bytes)") {
		t.Fatalf("a 65 KiB trust must still be refused: %v", err)
	}
	err = client(ts.path).Call(context.Background(), NewRequest(CmdSecretRun, map[string]string{"callerEnv": strings.Repeat("e", 129*1024)}), KindRevokeResult, &res)
	if p := AsProblem(err); p == nil || p.Code != CodeUsage || !strings.Contains(p.Message, "too large (max 131072 bytes)") {
		t.Fatalf("a 129 KiB secret.run must be refused: %v", err)
	}
	if !ValueCommand(CmdSecretRun) {
		t.Fatal("secret.run is a value command")
	}
}
