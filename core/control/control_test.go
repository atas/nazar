package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/unixsock"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// shortSocket returns a socket path in a fresh short /tmp dir (macOS
// sun_path is 104 bytes, so t.TempDir() is too long).
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nzc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "control.sock")
}

type stubHandler struct {
	got   chan Request
	peer  chan *caller.Chain
	calls atomic.Int32
	fn    func(ctx context.Context, req Request, out Emitter)
}

func (h *stubHandler) Serve(ctx context.Context, req Request, peer *caller.Chain, out Emitter) {
	h.calls.Add(1)
	if h.got != nil {
		select {
		case h.got <- req:
		default:
		}
	}
	if h.peer != nil {
		select {
		case h.peer <- peer:
		default:
		}
	}
	if h.fn != nil {
		h.fn(ctx, req, out)
	}
}

type testServer struct {
	path  string
	chain *caller.Chain // what Resolve returns
	fds   chan int      // SO_TYPE of each fd Resolve was called with (-1: not a socket)
	stop  func() error  // closes the listener, returns Serve's result
}

// serve runs a Server on a fresh socket. Resolve returns one fixed chain, so
// tests can check the handler gets exactly what Resolve produced.
func serve(t *testing.T, h Handler) *testServer {
	t.Helper()
	return serveWith(t, h, nil)
}

// serveWith is serve with a hook that may adjust the Server before it runs.
func serveWith(t *testing.T, h Handler, configure func(*Server)) *testServer {
	t.Helper()
	path := shortSocket(t)
	l, err := unixsock.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{path: path, chain: &caller.Chain{Unknown: true}, fds: make(chan int, 64)}
	srv := &Server{Handler: h, Resolve: func(fd int) *caller.Chain {
		typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
		if err != nil {
			typ = -1
		}
		select {
		case ts.fds <- typ:
		default:
		}
		return ts.chain
	}, Logf: t.Logf}
	if configure != nil {
		configure(srv)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	var once sync.Once
	var serveErr error
	ts.stop = func() error {
		once.Do(func() {
			l.Close()
			select {
			case serveErr = <-done:
			case <-time.After(5 * time.Second):
				serveErr = errors.New("Serve did not return after the listener was closed")
			}
		})
		return serveErr
	}
	t.Cleanup(func() {
		if err := ts.stop(); err != nil {
			t.Errorf("stopping the server: %v", err)
		}
	})
	return ts
}

// asyncWrite writes b to c from its own goroutine, so a write the peer never
// reads cannot deadlock the test, and makes sure that goroutine has ended
// (closing c if need be) before the test does.
func asyncWrite(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.Write(b)
	}()
	t.Cleanup(func() {
		c.Close()
		<-done
	})
}

func client(path string) *Client { return &Client{Socket: path, Verifier: SameUserVerifier{}} }

func ignore(string, json.RawMessage) error { return nil }

// rawExchange sends line on a raw connection (no client-side checks) and
// returns every reply line the server sends before it closes. The write runs
// in its own goroutine so an oversized request cannot deadlock the test.
func rawExchange(t *testing.T, path, line string, wait time.Duration) []map[string]any {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	asyncWrite(t, conn, []byte(line))
	conn.SetReadDeadline(time.Now().Add(wait))
	var out []map[string]any
	br := bufio.NewReader(conn)
	for {
		reply, err := br.ReadBytes('\n')
		if len(reply) > 0 {
			var m map[string]any
			if jerr := json.Unmarshal(reply, &m); jerr != nil {
				t.Fatalf("reply is not one JSON object per line: %q: %v", reply, jerr)
			}
			out = append(out, m)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
				t.Fatalf("server did not answer and close within %v: %v (got %v)", wait, err, out)
			}
			return out
		}
	}
}

// fakeServer is a hand-written control-socket peer (e.g. an impostor or a
// buggy/hostile Nazar.app) for client tests. For every connection it reads
// what the client sends (up to a newline, EOF or 2 s) into received, then
// calls reply, then closes. Its cleanup closes the listener and every
// connection it accepted, then waits for the accept goroutine and the
// per-connection goroutines, so none of them outlives the test.
type fakeServer struct {
	path     string
	received chan []byte

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func (fs *fakeServer) track(c net.Conn) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.conns[c] = struct{}{}
}

func (fs *fakeServer) closeAll() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for c := range fs.conns {
		c.Close()
	}
}

func newFakeServer(t *testing.T, reply func(c net.Conn, req []byte)) *fakeServer {
	t.Helper()
	path := shortSocket(t)
	l, err := unixsock.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeServer{path: path, received: make(chan []byte, 16), conns: map[net.Conn]struct{}{}}
	// The accept goroutine is counted too, and it is the one that adds its
	// children: the counter is never raised from zero while the cleanup
	// below may be waiting, which the race detector (rightly) reports.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			fs.track(c)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				var buf bytes.Buffer
				one := make([]byte, 1)
				for {
					n, err := c.Read(one)
					if n > 0 {
						buf.WriteByte(one[0])
						if one[0] == '\n' {
							break
						}
					}
					if err != nil {
						break
					}
				}
				c.SetReadDeadline(time.Time{})
				fs.received <- buf.Bytes()
				if reply != nil {
					reply(c, buf.Bytes())
				}
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		fs.closeAll()
		wg.Wait()
	})
	return fs
}

func writeLines(c net.Conn, lines ...string) {
	for _, l := range lines {
		c.Write([]byte(l + "\n"))
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// API objects (spec 6: apiVersion + kind on every object, exit codes)
// ---------------------------------------------------------------------------

func TestConstants(t *testing.T) {
	if APIVersion != "nazar/v1" {
		t.Errorf("APIVersion = %q", APIVersion)
	}
	if MaxRequestSize != 64*1024 {
		t.Errorf("MaxRequestSize = %d, want 64 KiB", MaxRequestSize)
	}
	// Spec 6 exit codes.
	for name, c := range map[string][2]int{
		"ok": {ExitOK, 0}, "error": {ExitError, 1}, "usage": {ExitUsage, 2},
		"refused": {ExitRefused, 3}, "staged": {ExitStaged, 4}, "unavailable": {ExitUnavailable, 5},
	} {
		if c[0] != c[1] {
			t.Errorf("exit %s = %d, want %d", name, c[0], c[1])
		}
	}
	// Kind names are part of the versioned --json contract.
	for got, want := range map[string]string{
		KindRequest: "Request", KindSSHKey: "SSHKey", KindSSHKeyList: "SSHKeyList",
		KindApproval: "Approval", KindApprovalList: "ApprovalList", KindStatus: "Status",
		KindConfigCheck: "ConfigCheck", KindConfigDiff: "ConfigDiff", KindAppPin: "AppPin",
		KindRevokeResult: "RevokeResult", KindAuditEvent: "AuditEvent", KindAuditSummary: "AuditSummary",
		KindProblem: "Problem",
	} {
		if got != want {
			t.Errorf("kind %q, want %q", got, want)
		}
	}
	for got, want := range map[string]string{
		CmdSSHKeyCreate: "ssh-key.create", CmdSSHKeyList: "ssh-key.list", CmdSSHKeyPubkey: "ssh-key.pubkey",
		CmdSSHKeyDelete: "ssh-key.delete", CmdStatus: "status", CmdRevoke: "revoke",
		CmdConfigCheck: "config.check", CmdConfigApply: "config.apply", CmdTrustApp: "trust.app",
	} {
		if got != want {
			t.Errorf("command %q, want %q", got, want)
		}
	}
	for got, want := range map[string]string{
		CodeError: "error", CodeUsage: "usage", CodeRefused: "refused", CodeStaged: "staged", CodeUnavailable: "unavailable",
	} {
		if got != want {
			t.Errorf("code %q, want %q", got, want)
		}
	}
}

func TestExitCodes(t *testing.T) {
	for code, want := range map[string]int{CodeError: 1, CodeUsage: 2, CodeRefused: 3, CodeStaged: 4, CodeUnavailable: 5, "other": 1, "": 1, "ok": 1} {
		if got := (&Problem{Code: code}).ExitCode(); got != want {
			t.Errorf("%q → %d want %d", code, got, want)
		}
	}
}

func TestEveryObjectCarriesAPIVersionAndKind(t *testing.T) {
	for _, v := range []any{
		NewRequest(CmdStatus, nil),
		NewProblem(CodeError, "x"),
		SSHKey{TypeMeta: Meta(KindSSHKey)},
		SSHKeyList{TypeMeta: Meta(KindSSHKeyList)},
		Approval{TypeMeta: Meta(KindApproval)},
		ApprovalList{TypeMeta: Meta(KindApprovalList)},
		Status{TypeMeta: Meta(KindStatus)},
		ConfigCheck{TypeMeta: Meta(KindConfigCheck)},
		ConfigDiff{TypeMeta: Meta(KindConfigDiff)},
		AppPin{TypeMeta: Meta(KindAppPin)},
		RevokeResult{TypeMeta: Meta(KindRevokeResult)},
		AuditEvent{TypeMeta: Meta(KindAuditEvent)},
		AuditSummary{TypeMeta: Meta(KindAuditSummary)},
	} {
		var m map[string]any
		if err := json.Unmarshal([]byte(mustJSON(t, v)), &m); err != nil {
			t.Fatal(err)
		}
		if m["apiVersion"] != APIVersion {
			t.Errorf("%T: apiVersion %v", v, m["apiVersion"])
		}
		if k, _ := m["kind"].(string); k == "" {
			t.Errorf("%T: no kind: %v", v, m)
		}
	}
	// The kind field matches the type.
	var m map[string]any
	json.Unmarshal([]byte(mustJSON(t, NewRequest(CmdRevoke, map[string]string{"all": "true"}))), &m)
	if m["kind"] != KindRequest || m["command"] != CmdRevoke {
		t.Fatalf("request wire form %v", m)
	}
	if args, _ := m["args"].(map[string]any); args["all"] != "true" {
		t.Fatalf("request args %v", m)
	}
}

func TestProblem(t *testing.T) {
	p := NewProblem(CodeStaged, "change %s staged (%d rules)", "abc", 2)
	if p.APIVersion != APIVersion || p.Kind != KindProblem || p.Code != CodeStaged || p.Message != "change abc staged (2 rules)" {
		t.Fatalf("%+v", p)
	}
	if p.Error() != p.Message {
		t.Fatalf("Error() = %q", p.Error())
	}
	var m map[string]any
	json.Unmarshal([]byte(mustJSON(t, p)), &m)
	if m["code"] != CodeStaged || m["message"] != p.Message || m["kind"] != KindProblem {
		t.Fatalf("wire form %v", m)
	}
	// Arguments are not re-interpreted as format verbs.
	if q := NewProblem(CodeError, "%s", "100%d %n"); q.Message != "100%d %n" {
		t.Fatalf("message %q", q.Message)
	}
}

func TestAsProblem(t *testing.T) {
	p := AsProblem(errors.New("disk on fire"))
	if p == nil || p.Code != CodeError || p.ExitCode() != ExitError || !strings.Contains(p.Message, "disk on fire") {
		t.Fatalf("%+v", p)
	}
	if p.APIVersion != APIVersion || p.Kind != KindProblem {
		t.Fatalf("wrapped plain error lacks apiVersion/kind: %+v", p)
	}
	orig := NewProblem(CodeRefused, "denied")
	if got := AsProblem(fmt.Errorf("ssh-key delete: %w", orig)); got != orig {
		t.Fatalf("wrapped problem not unwrapped: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Server + client round trips
// ---------------------------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	h := &stubHandler{got: make(chan Request, 1), peer: make(chan *caller.Chain, 1), fn: func(_ context.Context, req Request, out Emitter) {
		out.Emit(RevokeResult{TypeMeta: Meta(KindRevokeResult), Revoked: 3})
	}}
	ts := serve(t, h)
	var res RevokeResult
	if err := client(ts.path).Call(context.Background(), NewRequest(CmdRevoke, map[string]string{"all": "true"}), KindRevokeResult, &res); err != nil {
		t.Fatal(err)
	}
	if res.Revoked != 3 || res.APIVersion != APIVersion || res.Kind != KindRevokeResult {
		t.Fatalf("%+v", res)
	}
	if req := <-h.got; req.Command != CmdRevoke || req.Args["all"] != "true" || req.APIVersion != APIVersion || req.Kind != KindRequest {
		t.Fatalf("%+v", req)
	}
	if p := <-h.peer; p != ts.chain {
		t.Fatalf("handler got peer %p, want the chain Resolve returned (%p)", p, ts.chain)
	}
	// Resolve was handed the connection's live socket fd.
	select {
	case typ := <-ts.fds:
		if typ != syscall.SOCK_STREAM {
			t.Fatalf("Resolve got an fd that is not the connected stream socket (SO_TYPE %d)", typ)
		}
	default:
		t.Fatal("Resolve was not called")
	}
}

func TestProblemIsReturnedWithExitCode(t *testing.T) {
	ts := serve(t, &stubHandler{fn: func(_ context.Context, _ Request, out Emitter) {
		p := NewProblem(CodeRefused, "denied at the login prompt")
		p.Details = []string{"gate: login", "timeout: 60s"}
		out.Emit(p)
	}})
	n := 0
	err := client(ts.path).Do(context.Background(), NewRequest(CmdTrustApp, nil), func(string, json.RawMessage) error { n++; return nil })
	if err == nil {
		t.Fatal("a trailing Problem must be returned as an error")
	}
	var pe *Problem
	if !errors.As(err, &pe) {
		t.Fatalf("error is %T, want *Problem", err)
	}
	p := AsProblem(err)
	if p.Code != CodeRefused || p.ExitCode() != ExitRefused || p.Message != "denied at the login prompt" {
		t.Fatalf("%+v", p)
	}
	if len(p.Details) != 2 || p.Details[1] != "timeout: 60s" {
		t.Fatalf("details lost: %+v", p.Details)
	}
	if n != 0 {
		t.Fatalf("the Problem was also passed to fn (%d calls)", n)
	}
}

func TestEveryProblemCodeSurvivesTheWire(t *testing.T) {
	for _, code := range []string{CodeError, CodeUsage, CodeRefused, CodeStaged, CodeUnavailable} {
		ts := serve(t, &stubHandler{fn: func(_ context.Context, _ Request, out Emitter) {
			out.Emit(NewProblem(code, "x"))
		}})
		err := client(ts.path).Do(context.Background(), NewRequest(CmdConfigApply, nil), ignore)
		if p := AsProblem(err); p.Code != code || p.ExitCode() != (&Problem{Code: code}).ExitCode() {
			t.Errorf("%s: %+v", code, p)
		}
	}
}

func TestStagedResultThenProblem(t *testing.T) {
	// A loosening change shows the diff and exits 4 (spec 6).
	ts := serve(t, &stubHandler{fn: func(_ context.Context, _ Request, out Emitter) {
		out.Emit(ConfigDiff{TypeMeta: Meta(KindConfigDiff), Hash: "h1", Loosens: true, Changes: []string{"+ rule"}})
		out.Emit(NewProblem(CodeStaged, "staged; approve at the login prompt"))
	}})
	var kinds []string
	err := client(ts.path).Do(context.Background(), NewRequest(CmdConfigApply, nil), func(k string, raw json.RawMessage) error {
		kinds = append(kinds, k)
		var d ConfigDiff
		if err := json.Unmarshal(raw, &d); err != nil || d.Hash != "h1" || !d.Loosens {
			t.Errorf("diff %s: %v", raw, err)
		}
		return nil
	})
	if p := AsProblem(err); p.ExitCode() != ExitStaged {
		t.Fatalf("%+v", p)
	}
	if len(kinds) != 1 || kinds[0] != KindConfigDiff {
		t.Fatalf("kinds %v", kinds)
	}
}

func TestStreamingAndCancel(t *testing.T) {
	done := make(chan struct{})
	ts := serve(t, &stubHandler{fn: func(ctx context.Context, _ Request, out Emitter) {
		defer close(done)
		for {
			if out.Emit(Approval{TypeMeta: Meta(KindApproval), Event: "added", Target: "ssh:k"}) != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := 0
	err := client(ts.path).Do(ctx, Request{TypeMeta: Meta(KindRequest), Command: CmdStatus, Follow: true}, func(kind string, _ json.RawMessage) error {
		if kind != KindApproval {
			t.Errorf("kind %q", kind)
		}
		n++
		if n == 3 {
			cancel()
		}
		return nil
	})
	if err != nil || n < 3 {
		t.Fatalf("err %v n %d", err, n)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler not cancelled after the client went away")
	}
}

func TestHandlerContextCancelledWhenClientDisconnects(t *testing.T) {
	// A handler that only waits on ctx (emits nothing) must still learn that
	// the client is gone: no goroutine left behind per abandoned --follow.
	ended := make(chan struct{})
	started := make(chan struct{})
	ts := serve(t, &stubHandler{fn: func(ctx context.Context, _ Request, _ Emitter) {
		close(started)
		<-ctx.Done()
		close(ended)
	}})
	conn, err := net.Dial("unix", ts.path)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte(mustJSON(t, Request{TypeMeta: Meta(KindRequest), Command: CmdStatus, Follow: true}) + "\n"))
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler never started")
	}
	conn.Close()
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("handler ctx not cancelled after the client closed the connection")
	}
}

func TestFollowStreamOutlivesRequestReadDeadline(t *testing.T) {
	// The 5 s read deadline bounds reading the request, not the life of a
	// --follow stream.
	if testing.Short() {
		t.Skip("takes ~6 s")
	}
	t.Parallel()
	ts := serve(t, &stubHandler{fn: func(ctx context.Context, _ Request, out Emitter) {
		for {
			if out.Emit(Approval{TypeMeta: Meta(KindApproval), Event: "added", Target: "ssh:k"}) != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	late := false
	err := client(ts.path).Do(ctx, Request{TypeMeta: Meta(KindRequest), Command: CmdStatus, Follow: true}, func(string, json.RawMessage) error {
		if time.Since(start) > 6500*time.Millisecond {
			late = true
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !late {
		t.Fatalf("stream ended after %v; a --follow stream must not be cut by the request read deadline", time.Since(start))
	}
}

func TestConcurrentEmitsAreWholeLines(t *testing.T) {
	const workers, each = 16, 64
	ts := serve(t, &stubHandler{fn: func(_ context.Context, _ Request, out Emitter) {
		var wg sync.WaitGroup
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range each {
					out.Emit(Approval{TypeMeta: Meta(KindApproval), Target: fmt.Sprintf("ssh:%d-%d", w, i), Chain: strings.Repeat("x", 512)})
				}
			}()
		}
		wg.Wait()
	}})
	seen := map[string]bool{}
	err := client(ts.path).Do(context.Background(), NewRequest(CmdStatus, nil), func(kind string, raw json.RawMessage) error {
		var a Approval
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		seen[a.Target] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != workers*each {
		t.Fatalf("got %d distinct objects, want %d", len(seen), workers*each)
	}
}

func TestOneRequestPerConnection(t *testing.T) {
	h := &stubHandler{fn: func(_ context.Context, _ Request, out Emitter) {
		out.Emit(RevokeResult{TypeMeta: Meta(KindRevokeResult)})
	}}
	ts := serve(t, h)
	req := mustJSON(t, NewRequest(CmdStatus, nil))
	second := mustJSON(t, NewRequest(CmdTrustApp, map[string]string{"app": "/tmp/evil"}))
	replies := rawExchange(t, ts.path, req+"\n"+second+"\n", 3*time.Second)
	if len(replies) != 1 || replies[0]["kind"] != KindRevokeResult {
		t.Fatalf("replies %v", replies)
	}
	time.Sleep(50 * time.Millisecond)
	if n := h.calls.Load(); n != 1 {
		t.Fatalf("handler called %d times; a second request on one connection must be ignored", n)
	}
}

func TestServerRejectsBadRequests(t *testing.T) {
	h := &stubHandler{fn: func(_ context.Context, _ Request, out Emitter) {
		out.Emit(RevokeResult{TypeMeta: Meta(KindRevokeResult)})
	}}
	ts := serve(t, h)
	valid := `{"apiVersion":"nazar/v1","kind":"Request","command":"status"}`
	bigArgs := mustJSON(t, NewRequest(CmdTrustApp, map[string]string{"app": strings.Repeat("a", MaxRequestSize)}))
	for name, line := range map[string]string{
		"not json":           "not json\n",
		"empty line":         "\n",
		"json null":          "null\n",
		"empty object":       "{}\n",
		"json array":         `[` + valid + `]` + "\n",
		"future apiVersion":  `{"apiVersion":"nazar/v2","kind":"Request","command":"status"}` + "\n",
		"no apiVersion":      `{"kind":"Request","command":"status"}` + "\n",
		"apiVersion case":    `{"apiVersion":"Nazar/v1","kind":"Request","command":"status"}` + "\n",
		"no kind":            `{"apiVersion":"nazar/v1","command":"status"}` + "\n",
		"wrong kind":         `{"apiVersion":"nazar/v1","kind":"Status","command":"status"}` + "\n",
		"kind case":          `{"apiVersion":"nazar/v1","kind":"request","command":"status"}` + "\n",
		"problem as request": `{"apiVersion":"nazar/v1","kind":"Problem","code":"usage","message":"x"}` + "\n",
		"unknown field":      `{"apiVersion":"nazar/v1","kind":"Request","command":"status","sneaky":1}` + "\n",
		"non-string arg":     `{"apiVersion":"nazar/v1","kind":"Request","command":"trust.app","args":{"app":1}}` + "\n",
		"nested arg":         `{"apiVersion":"nazar/v1","kind":"Request","command":"trust.app","args":{"app":{"x":"y"}}}` + "\n",
		"follow not bool":    `{"apiVersion":"nazar/v1","kind":"Request","command":"status","follow":"yes"}` + "\n",
		"trailing object":    valid + `{"apiVersion":"nazar/v1","kind":"Request","command":"trust.app"}` + "\n",
		"trailing garbage":   valid + ` xyz` + "\n",
		"oversized garbage":  strings.Repeat("x", MaxRequestSize+10) + "\n",
		"oversized valid":    bigArgs + "\n",
		"no newline at EOF":  "", // sent then half-closed below
	} {
		t.Run(name, func(t *testing.T) {
			var replies []map[string]any
			if name == "no newline at EOF" {
				// A request without its newline, then the client half-closes.
				conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: ts.path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.Write([]byte(`{"apiVersion":"nazar/v1","kind":"Request","comm`))
				conn.CloseWrite()
				conn.SetReadDeadline(time.Now().Add(7 * time.Second))
				b, err := io.ReadAll(conn)
				if err != nil {
					t.Fatalf("no reply: %v", err)
				}
				for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
					var m map[string]any
					if json.Unmarshal(l, &m) != nil {
						t.Fatalf("reply %q", b)
					}
					replies = append(replies, m)
				}
			} else {
				replies = rawExchange(t, ts.path, line, 7*time.Second)
			}
			if len(replies) != 1 {
				t.Fatalf("want exactly one Problem, got %v", replies)
			}
			m := replies[0]
			if m["kind"] != KindProblem || m["code"] != CodeUsage || m["apiVersion"] != APIVersion {
				t.Fatalf("reply %v", m)
			}
			if msg, _ := m["message"].(string); msg == "" {
				t.Fatalf("problem without a message: %v", m)
			}
		})
	}
	if n := h.calls.Load(); n != 0 {
		t.Fatalf("handler ran %d times for refused requests", n)
	}
}

func TestRequestUnderSizeCapIsServed(t *testing.T) {
	h := &stubHandler{got: make(chan Request, 1), fn: func(_ context.Context, _ Request, out Emitter) {
		out.Emit(RevokeResult{TypeMeta: Meta(KindRevokeResult), Revoked: 1})
	}}
	ts := serve(t, h)
	base := len(mustJSON(t, NewRequest(CmdTrustApp, map[string]string{"app": ""})))
	pad := strings.Repeat("p", MaxRequestSize-base-64)
	var res RevokeResult
	if err := client(ts.path).Call(context.Background(), NewRequest(CmdTrustApp, map[string]string{"app": pad}), KindRevokeResult, &res); err != nil {
		t.Fatalf("a %d-byte request must be accepted: %v", MaxRequestSize-64, err)
	}
	if req := <-h.got; req.Args["app"] != pad {
		t.Fatal("argument mangled")
	}
}

func TestSlowClientIsCutOffAndDoesNotBlockOthers(t *testing.T) {
	if testing.Short() {
		t.Skip("takes ~5 s")
	}
	t.Parallel()
	h := &stubHandler{fn: func(_ context.Context, _ Request, out Emitter) {
		out.Emit(RevokeResult{TypeMeta: Meta(KindRevokeResult)})
	}}
	ts := serve(t, h)

	// Slowloris: half a request and then silence; another connects and says
	// nothing at all.
	partial, err := net.Dial("unix", ts.path)
	if err != nil {
		t.Fatal(err)
	}
	defer partial.Close()
	partial.Write([]byte(`{"apiVersion":"nazar/v1","kind":"Requ`))
	silent, err := net.Dial("unix", ts.path)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	// Meanwhile a well-behaved client is served at once.
	start := time.Now()
	var res RevokeResult
	if err := client(ts.path).Call(context.Background(), NewRequest(CmdRevoke, nil), KindRevokeResult, &res); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("a stalled connection delayed another client by %v", d)
	}

	for name, c := range map[string]net.Conn{"partial": partial, "silent": silent} {
		c.SetReadDeadline(time.Now().Add(8 * time.Second))
		b, err := io.ReadAll(c)
		if err != nil {
			t.Fatalf("%s: server never closed a stalled connection: %v", name, err)
		}
		if el := time.Since(start); el < 4*time.Second || el > 7*time.Second {
			t.Errorf("%s: closed after %v; want the ~5 s request read deadline", name, el)
		}
		var m map[string]any
		json.Unmarshal(bytes.TrimSpace(b), &m)
		if m["kind"] != KindProblem || m["code"] != CodeUsage {
			t.Errorf("%s: reply %q", name, b)
		}
	}
	if n := h.calls.Load(); n != 1 {
		t.Fatalf("handler ran %d times; only the complete request may be served", n)
	}
}

func TestServeReturnsNilWhenListenerClosed(t *testing.T) {
	ts := serve(t, &stubHandler{})
	if err := ts.stop(); err != nil {
		t.Fatal(err)
	}
}

// TestServeStopsItsConnectionsBeforeReturning pins the shutdown contract:
// closing the listener cancels every running handler's ctx (its client is
// still connected, so nothing else would) and Serve returns only once the
// handlers' goroutines have ended. Without it, connection goroutines keep
// running after Serve returned and log into a test that has finished.
func TestServeStopsItsConnectionsBeforeReturning(t *testing.T) {
	const clients = 3
	started := make(chan struct{}, clients)
	var running, cancelled atomic.Int32
	ts := serve(t, &stubHandler{fn: func(ctx context.Context, _ Request, out Emitter) {
		running.Add(1)
		defer running.Add(-1)
		out.Emit(Approval{TypeMeta: Meta(KindApproval)})
		started <- struct{}{}
		<-ctx.Done()
		cancelled.Add(1)
		// Serve has to wait for this too, not just for the cancellation.
		time.Sleep(100 * time.Millisecond)
	}})
	var conns []net.Conn
	for range clients {
		conn, err := net.Dial("unix", ts.path)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conns = append(conns, conn)
		asyncWrite(t, conn, []byte(mustJSON(t, Request{TypeMeta: Meta(KindRequest), Command: CmdStatus, Follow: true})+"\n"))
	}
	for range clients {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("handlers did not start")
		}
	}
	if err := ts.stop(); err != nil {
		t.Fatal(err)
	}
	if n := running.Load(); n != 0 {
		t.Fatalf("Serve returned while %d handlers were still running", n)
	}
	if n := cancelled.Load(); n != clients {
		t.Fatalf("%d of %d handlers saw their ctx cancelled by the shutdown", n, clients)
	}
	// The clients were cut off: after the first reply the server closed.
	for i, conn := range conns {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		rest, err := io.ReadAll(bufio.NewReader(conn))
		if err != nil && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("client %d: the connection was not closed by the shutdown: %v", i, err)
		}
		if lines := bytes.Count(rest, []byte("\n")); lines != 1 {
			t.Fatalf("client %d: got %d lines, want the one reply emitted before the shutdown: %q", i, lines, rest)
		}
	}
}

// TestServeSurvivesAcceptFailure: a transient accept error must not end
// Serve. The socket stays bound while nobody accepts, so a dead loop would
// make every later `nazar revoke/status/config` hang instead of being
// answered, and any same-user process (or plain fd pressure in Nazar.app)
// could provoke it. Here accept fails with EMFILE: every fd number below a
// lowered RLIMIT_NOFILE is used up except one, which the client's socket()
// takes, so the server's accept() has none left.
func TestServeSurvivesAcceptFailure(t *testing.T) {
	acceptErr := make(chan string, 16)
	h := &stubHandler{fn: func(_ context.Context, _ Request, out Emitter) {
		out.Emit(RevokeResult{TypeMeta: Meta(KindRevokeResult), Revoked: 9})
	}}
	ts := serveWith(t, h, func(s *Server) {
		base := s.Logf
		s.Logf = func(format string, args ...any) {
			base(format, args...)
			if strings.HasPrefix(format, "control: accept:") {
				select {
				case acceptErr <- fmt.Sprintf(format, args...):
				default:
				}
			}
		}
	})

	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		t.Fatal(err)
	}
	probe, err := syscall.Open("/dev/null", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.Close(probe)
	low := orig
	low.Cur = uint64(probe) + 8 // the lowest free fd number plus a few
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Fatal(err)
	}
	var fill []int
	var restoreOnce sync.Once
	restore := func() {
		restoreOnce.Do(func() {
			for _, fd := range fill {
				syscall.Close(fd)
			}
			if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
				t.Errorf("restoring RLIMIT_NOFILE: %v", err)
			}
		})
	}
	defer restore()
	for {
		fd, err := syscall.Open("/dev/null", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			if !errors.Is(err, syscall.EMFILE) {
				restore()
				t.Fatal(err)
			}
			break
		}
		fill = append(fill, fd)
	}
	if len(fill) == 0 {
		restore()
		t.Fatal("could not use up the fd table")
	}
	// Exactly one fd number is free now: the client's socket.
	syscall.Close(fill[len(fill)-1])
	fill = fill[:len(fill)-1]

	done := make(chan error, 1)
	var res RevokeResult
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		done <- client(ts.path).Call(ctx, NewRequest(CmdRevoke, nil), KindRevokeResult, &res)
	}()
	// done is buffered, so the client goroutine is checked afterwards; here
	// only the accept failure matters (the client may already have been told
	// about it by the kernel, see below).
	select {
	case msg := <-acceptErr:
		if !strings.Contains(msg, "too many open files") {
			t.Logf("accept failed with %q (expected EMFILE, but any transient error will do)", msg)
		}
	case <-time.After(5 * time.Second):
		restore()
		t.Fatal("the server never reported an accept failure (or does not log one)")
	}
	restore()
	// The triggering client is either served once the loop recovers (Linux
	// leaves it queued) or told so at once (XNU closes the connection whose
	// accept failed); it must not hang either way.
	select {
	case err := <-done:
		if err != nil {
			t.Logf("the client that hit the failure got: %v", err)
		} else if res.Revoked != 9 {
			t.Fatalf("%+v", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client that hit the accept failure hangs")
	}
	// Serve is still accepting: the next client is served, and Serve ends
	// only when the listener is closed.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res = RevokeResult{}
	if err := client(ts.path).Call(ctx, NewRequest(CmdRevoke, nil), KindRevokeResult, &res); err != nil {
		t.Fatalf("Serve stopped accepting after a transient accept error: %v", err)
	}
	if res.Revoked != 9 {
		t.Fatalf("%+v", res)
	}
	if err := ts.stop(); err != nil {
		t.Fatalf("Serve returned %v, want nil once the listener is closed", err)
	}
}

// TestServerDropsPeerTheCheckRejects pins the UID gate: a peer the check
// rejects is closed before a byte is read, so no request is parsed, Resolve
// and the handler never run and nothing is sent back.
func TestServerDropsPeerTheCheckRejects(t *testing.T) {
	var checked, resolved atomic.Int32
	h := &stubHandler{fn: func(_ context.Context, _ Request, out Emitter) {
		out.Emit(RevokeResult{TypeMeta: Meta(KindRevokeResult), Revoked: 1})
	}}
	ts := serveWith(t, h, func(s *Server) {
		s.peerCheck = func(c *net.UnixConn) error {
			checked.Add(1)
			return errors.New("unixsock: peer uid 0 is not 501")
		}
		resolve := s.Resolve
		s.Resolve = func(fd int) *caller.Chain {
			resolved.Add(1)
			return resolve(fd)
		}
	})
	conn, err := net.Dial("unix", ts.path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	asyncWrite(t, conn, []byte(mustJSON(t, NewRequest(CmdRevoke, map[string]string{"all": "true"}))+"\n"))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, err := io.ReadAll(conn)
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("the server did not close a refused peer's connection promptly: %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("the server answered a refused peer: %q", b)
	}
	time.Sleep(50 * time.Millisecond)
	if n := checked.Load(); n != 1 {
		t.Fatalf("peer check ran %d times, want 1", n)
	}
	if n := resolved.Load(); n != 0 {
		t.Fatalf("Resolve ran %d times for a refused peer", n)
	}
	if n := h.calls.Load(); n != 0 {
		t.Fatalf("handler ran %d times for a refused peer", n)
	}
	// Peers the check accepts are still served, so the gate is the check
	// and not something else on the path.
	ts2 := serveWith(t, h, func(s *Server) {
		s.peerCheck = func(c *net.UnixConn) error {
			uid, err := unixsock.PeerUID(c)
			if err != nil {
				return err
			}
			if uid != os.Getuid() {
				return fmt.Errorf("check got a connection whose peer is uid %d", uid)
			}
			return nil
		}
	})
	var res RevokeResult
	if err := client(ts2.path).Call(context.Background(), NewRequest(CmdRevoke, nil), KindRevokeResult, &res); err != nil {
		t.Fatal(err)
	}
	if res.Revoked != 1 {
		t.Fatalf("%+v", res)
	}
}

// Without a check of its own, a Server uses unixsock.RequireSameUser, which
// fails closed: a conn whose peer cannot be read is refused, never let in.
func TestServerDefaultPeerCheckFailsClosed(t *testing.T) {
	fs := newFakeServer(t, nil)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: fs.path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Server{}).checkPeer(conn); err != nil {
		t.Fatalf("a same-user peer was refused: %v", err)
	}
	conn.Close()
	if err := (&Server{}).checkPeer(conn); err == nil {
		t.Fatal("the default peer check passed a closed conn")
	}
}

func TestServeConnWithoutUnixSocket(t *testing.T) {
	// ServeConn works on any net.Conn and hands the given peer to the handler.
	peer := &caller.Chain{Truncated: true}
	h := &stubHandler{peer: make(chan *caller.Chain, 1), fn: func(_ context.Context, req Request, out Emitter) {
		out.Emit(RevokeResult{TypeMeta: Meta(KindRevokeResult), Revoked: len(req.Args)})
	}}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	srv := &Server{Handler: h}
	done := make(chan struct{})
	go func() {
		srv.ServeConn(b, peer)
		close(done)
	}()
	asyncWrite(t, a, []byte(mustJSON(t, NewRequest(CmdRevoke, map[string]string{"key": "k1"}))+"\n"))
	a.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(a).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var res RevokeResult
	if err := json.Unmarshal(line, &res); err != nil || res.Revoked != 1 || res.APIVersion != APIVersion {
		t.Fatalf("%s %v", line, err)
	}
	if got := <-h.peer; got != peer {
		t.Fatal("ServeConn did not pass the peer chain through")
	}
	a.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ServeConn did not return")
	}
}

// ---------------------------------------------------------------------------
// Client: unavailable, peer verification, hostile servers
// ---------------------------------------------------------------------------

func TestUnavailable(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "nzc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// A stale socket: the file exists but nobody listens.
	stale := filepath.Join(dir, "stale.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()

	for name, path := range map[string]string{
		"missing":     filepath.Join(dir, "no-such.sock"),
		"missing dir": filepath.Join(dir, "nope", "control.sock"),
		"stale":       stale,
	} {
		called := false
		err := client(path).Do(context.Background(), NewRequest(CmdStatus, nil), func(string, json.RawMessage) error { called = true; return nil })
		p := AsProblem(err)
		if err == nil || p.ExitCode() != ExitUnavailable || p.Code != CodeUnavailable {
			t.Errorf("%s: %v → %+v", name, err, p)
		}
		if called {
			t.Errorf("%s: fn called", name)
		}
		// Call reports the same.
		var st Status
		if p := AsProblem(client(path).Call(context.Background(), NewRequest(CmdStatus, nil), KindStatus, &st)); p.ExitCode() != ExitUnavailable {
			t.Errorf("%s: Call → %+v", name, p)
		}
	}
}

func TestVerifierRejectsPeer(t *testing.T) {
	fs := newFakeServer(t, func(c net.Conn, _ []byte) {
		writeLines(c, mustJSON(t, Status{TypeMeta: Meta(KindStatus)}))
	})
	var verified atomic.Int32
	c := &Client{Socket: fs.path, Verifier: VerifierFunc(func(uc *net.UnixConn) error {
		verified.Add(1)
		return errors.New("not signed by Nazar")
	})}
	called := false
	err := c.Do(context.Background(), NewRequest(CmdStatus, nil), func(string, json.RawMessage) error { called = true; return nil })
	p := AsProblem(err)
	if err == nil || p.ExitCode() != ExitError || !strings.Contains(p.Message, "not nazar-agent") {
		t.Fatalf("%+v", p)
	}
	if verified.Load() != 1 {
		t.Fatalf("verifier called %d times", verified.Load())
	}
	if called {
		t.Fatal("a reply from an unverified peer was delivered")
	}
	select {
	case got := <-fs.received:
		if len(got) != 0 {
			t.Fatalf("client sent %q to an unverified peer", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake server saw no connection")
	}
}

func TestClientWithoutVerifierRefuses(t *testing.T) {
	fs := newFakeServer(t, func(c net.Conn, _ []byte) {
		writeLines(c, mustJSON(t, Status{TypeMeta: Meta(KindStatus)}))
	})
	called := false
	err := (&Client{Socket: fs.path}).Do(context.Background(), NewRequest(CmdStatus, nil), func(string, json.RawMessage) error { called = true; return nil })
	if err == nil {
		t.Fatal("a client without a verifier must refuse")
	}
	if p := AsProblem(err); p.ExitCode() == ExitOK || p.ExitCode() == ExitUnavailable {
		t.Fatalf("%+v", p)
	}
	if called {
		t.Fatal("reply delivered without peer verification")
	}
	select {
	case got := <-fs.received:
		if len(got) != 0 {
			t.Fatalf("client without a verifier sent %q", got)
		}
	case <-time.After(3 * time.Second):
		// Not connecting at all is fine too.
	}
}

func TestVerifierGetsTheConnectedSocket(t *testing.T) {
	fs := newFakeServer(t, func(c net.Conn, _ []byte) {
		writeLines(c, mustJSON(t, RevokeResult{TypeMeta: Meta(KindRevokeResult), Revoked: 7}))
	})
	var uid int = -2
	c := &Client{Socket: fs.path, Verifier: VerifierFunc(func(uc *net.UnixConn) error {
		u, err := unixsock.PeerUID(uc)
		uid = u
		return err
	})}
	var res RevokeResult
	if err := c.Call(context.Background(), NewRequest(CmdRevoke, nil), KindRevokeResult, &res); err != nil {
		t.Fatal(err)
	}
	if uid != os.Getuid() || res.Revoked != 7 {
		t.Fatalf("verifier saw peer uid %d (want %d); result %+v", uid, os.Getuid(), res)
	}
}

// SameUserVerifier is the CLI's only peer check until Milestone 3 adds the
// code-signature check. It must fail closed: a peer it cannot read is
// rejected, never let through.
func TestSameUserVerifierFailsClosed(t *testing.T) {
	fs := newFakeServer(t, nil)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: fs.path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := (SameUserVerifier{}).VerifyPeer(conn); err != nil {
		t.Fatalf("a same-user peer was rejected: %v", err)
	}
	conn.Close()
	if err := (SameUserVerifier{}).VerifyPeer(conn); err == nil {
		t.Fatal("SameUserVerifier passed a conn whose peer cannot be read")
	}
	// The Client acts on that: nothing is sent and the reply is not read.
	fs2 := newFakeServer(t, func(c net.Conn, _ []byte) {
		writeLines(c, mustJSON(t, RevokeResult{TypeMeta: Meta(KindRevokeResult), Revoked: 1}))
	})
	c := &Client{Socket: fs2.path, Verifier: VerifierFunc(func(uc *net.UnixConn) error {
		uc.Close()
		return (SameUserVerifier{}).VerifyPeer(uc)
	})}
	var res RevokeResult
	err = c.Call(context.Background(), NewRequest(CmdRevoke, nil), KindRevokeResult, &res)
	if p := AsProblem(err); err == nil || p.ExitCode() != ExitError || !strings.Contains(p.Message, "not nazar-agent") {
		t.Fatalf("%+v (result %+v)", p, res)
	}
	if res.Revoked != 0 {
		t.Fatal("a reply from an unverified peer was decoded")
	}
}

func TestClientSendsOneVersionedRequestLine(t *testing.T) {
	fs := newFakeServer(t, func(c net.Conn, _ []byte) {
		writeLines(c, mustJSON(t, RevokeResult{TypeMeta: Meta(KindRevokeResult)}))
	})
	var res RevokeResult
	args := map[string]string{"session": "s-1", "note": "line\nbreak \"quoted\""}
	if err := client(fs.path).Call(context.Background(), NewRequest(CmdRevoke, args), KindRevokeResult, &res); err != nil {
		t.Fatal(err)
	}
	got := <-fs.received
	if bytes.Count(got, []byte("\n")) != 1 || !bytes.HasSuffix(got, []byte("\n")) {
		t.Fatalf("request is not exactly one line: %q", got)
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(got))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		t.Fatalf("request %q: %v", got, err)
	}
	if req.APIVersion != APIVersion || req.Kind != KindRequest || req.Command != CmdRevoke || req.Args["note"] != args["note"] || req.Args["session"] != "s-1" {
		t.Fatalf("%+v", req)
	}
}

func TestClientRejectsBadReplies(t *testing.T) {
	big := mustJSON(t, Status{TypeMeta: Meta(KindStatus), ActiveHash: strings.Repeat("h", 8192)})
	for name, tc := range map[string]struct {
		lines     []string
		raw       string // written as is, without a newline
		maxObject int
	}{
		"future apiVersion": {lines: []string{`{"apiVersion":"nazar/v2","kind":"Status"}`}},
		"no apiVersion":     {lines: []string{`{"kind":"Status"}`}},
		"no kind":           {lines: []string{`{"apiVersion":"nazar/v1"}`}},
		"not json":          {lines: []string{`hello`}},
		"json array":        {lines: []string{`[{"apiVersion":"nazar/v1","kind":"Status"}]`}},
		"truncated object":  {raw: `{"apiVersion":"nazar/v1","kind":"Sta`},
		"object too large":  {lines: []string{big}, maxObject: 1024},
		"bad problem body":  {lines: []string{`{"apiVersion":"nazar/v1","kind":"Problem","code":5}`}},
	} {
		t.Run(name, func(t *testing.T) {
			fs := newFakeServer(t, func(c net.Conn, _ []byte) {
				writeLines(c, tc.lines...)
				if tc.raw != "" {
					c.Write([]byte(tc.raw))
				}
			})
			c := client(fs.path)
			c.MaxObject = tc.maxObject
			var kinds []string
			err := c.Do(context.Background(), NewRequest(CmdStatus, nil), func(k string, _ json.RawMessage) error {
				kinds = append(kinds, k)
				return nil
			})
			if err == nil {
				t.Fatalf("bad reply accepted (fn saw %v)", kinds)
			}
			if p := AsProblem(err); p.ExitCode() != ExitError {
				t.Fatalf("exit %d: %+v", p.ExitCode(), p)
			}
			if len(kinds) != 0 {
				t.Fatalf("fn saw %v from a bad reply", kinds)
			}
		})
	}
}

func TestClientStopsAtProblem(t *testing.T) {
	fs := newFakeServer(t, func(c net.Conn, _ []byte) {
		writeLines(c,
			mustJSON(t, SSHKey{TypeMeta: Meta(KindSSHKey), Name: "a"}),
			mustJSON(t, NewProblem(CodeRefused, "blocked")),
			mustJSON(t, SSHKey{TypeMeta: Meta(KindSSHKey), Name: "smuggled"}),
		)
	})
	var names []string
	err := client(fs.path).Do(context.Background(), NewRequest(CmdSSHKeyList, nil), func(_ string, raw json.RawMessage) error {
		var k SSHKey
		json.Unmarshal(raw, &k)
		names = append(names, k.Name)
		return nil
	})
	if p := AsProblem(err); p.ExitCode() != ExitRefused || p.Message != "blocked" {
		t.Fatalf("%+v", p)
	}
	if len(names) != 1 || names[0] != "a" {
		t.Fatalf("objects after the Problem were delivered: %v", names)
	}
}

func TestClientFnErrorStopsAndPropagates(t *testing.T) {
	fs := newFakeServer(t, func(c net.Conn, _ []byte) {
		for range 5 {
			writeLines(c, mustJSON(t, Approval{TypeMeta: Meta(KindApproval)}))
		}
	})
	stop := errors.New("enough")
	n := 0
	err := client(fs.path).Do(context.Background(), NewRequest(CmdStatus, nil), func(string, json.RawMessage) error {
		n++
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("err %v", err)
	}
	if n != 1 {
		t.Fatalf("fn called %d times after returning an error", n)
	}
}

func TestClientEmptyReply(t *testing.T) {
	// The server closing without any object is fine for Do (nothing to show)
	// but an error for Call, which promised one object.
	fs := newFakeServer(t, func(net.Conn, []byte) {})
	if err := client(fs.path).Do(context.Background(), NewRequest(CmdStatus, nil), ignore); err != nil {
		t.Fatalf("Do: %v", err)
	}
	var st Status
	err := client(fs.path).Call(context.Background(), NewRequest(CmdStatus, nil), KindStatus, &st)
	if p := AsProblem(err); err == nil || p.ExitCode() != ExitError {
		t.Fatalf("Call with no reply: %v", err)
	}
}

func TestCallRejectsWrongKind(t *testing.T) {
	fs := newFakeServer(t, func(c net.Conn, _ []byte) {
		writeLines(c, mustJSON(t, AppPin{TypeMeta: Meta(KindAppPin), BundleID: "x"}))
	})
	var st Status
	err := client(fs.path).Call(context.Background(), NewRequest(CmdStatus, nil), KindStatus, &st)
	if p := AsProblem(err); err == nil || p.ExitCode() != ExitError {
		t.Fatalf("wrong kind accepted: %v (%+v)", err, st)
	}
}

func TestClientCancelWithSilentServer(t *testing.T) {
	release := make(chan struct{})
	fs := newFakeServer(t, func(net.Conn, []byte) { <-release })
	// Registered after newFakeServer so it runs before the fake server's
	// cleanup waits for its connections (cleanups run last-in first-out).
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		client(fs.path).Do(ctx, NewRequest(CmdStatus, nil), ignore)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Do ignored its context while the server said nothing")
	}
}

func TestNoGoroutineLeakOnCancelledFollow(t *testing.T) {
	// Repeated short-lived follows leave no handler running on the server.
	var running atomic.Int32
	ts := serve(t, &stubHandler{fn: func(ctx context.Context, _ Request, out Emitter) {
		running.Add(1)
		defer running.Add(-1)
		out.Emit(Approval{TypeMeta: Meta(KindApproval)})
		<-ctx.Done()
	}})
	for range 10 {
		ctx, cancel := context.WithCancel(context.Background())
		client(ts.path).Do(ctx, Request{TypeMeta: Meta(KindRequest), Command: CmdStatus, Follow: true}, func(string, json.RawMessage) error {
			cancel()
			return nil
		})
		cancel()
	}
	deadline := time.Now().Add(3 * time.Second)
	for running.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := running.Load(); n != 0 {
		t.Fatalf("%d handlers still running after their clients left", n)
	}
}

// A verifier's refusal about the CLI itself reaches the user as it is: the
// peer passed, so nothing says it is not nazar-agent, and nothing is sent.
func TestVerifierSelfErrorIsNotAboutThePeer(t *testing.T) {
	var n atomic.Int32
	ts := serve(t, &stubHandler{fn: func(context.Context, Request, Emitter) { n.Add(1) }})
	c := &Client{Socket: ts.path, Verifier: VerifierFunc(func(*net.UnixConn) error {
		return &SelfError{Err: errors.New("this CLI is out of date")}
	})}
	err := c.Do(context.Background(), NewRequest(CmdStatus, nil), nil)
	p := AsProblem(err)
	if p == nil || p.Code != CodeError || p.Message != "this CLI is out of date" {
		t.Fatalf("problem %+v", p)
	}
	if n.Load() != 0 {
		t.Fatal("a request was sent after the verifier refused")
	}
	// Any other refusal still names the peer.
	c.Verifier = VerifierFunc(func(*net.UnixConn) error { return errors.New("bad peer") })
	if p := AsProblem(c.Do(context.Background(), NewRequest(CmdStatus, nil), nil)); p == nil || !strings.Contains(p.Message, "is not nazar-agent: bad peer") {
		t.Fatalf("problem %+v", p)
	}
}
