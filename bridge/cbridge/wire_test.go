package cbridge

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
)

// These strings are exactly what WireTests.swift pins Swift's encoder to.
const (
	goldenProcess = `{"args":["-zsh","a\"b"],"code":{"adHoc":false,"apple":true,"cdhash":"q80=","signed":true,"signingId":"com.apple.zsh","teamId":""},"comm":"zsh","cwd":"/tmp","generation":1700000000000001,"parentGeneration":0,"parentPid":1,"path":"/bin/zsh","pid":42,"startMicros":1700000000000001,"uid":501}`
	goldenBundle  = `{"bundleId":"com.apple.TextEdit","code":{"adHoc":false,"apple":false,"cdhash":"","signed":false,"signingId":"","teamId":""},"path":"/System/Applications/TextEdit.app"}`
)

func TestSwiftGoldenDocumentsDecode(t *testing.T) {
	var p wireProcess
	if err := decodeStrict([]byte(goldenProcess), &p); err != nil {
		t.Fatal(err)
	}
	info := p.info()
	want := platform.ProcessInfo{Ref: platform.ProcessRef{PID: 42, Generation: 1700000000000001}, Parent: platform.ProcessRef{PID: 1},
		UID: 501, StartTime: time.UnixMicro(1700000000000001), Path: "/bin/zsh", Args: []string{"-zsh", `a"b`}, Cwd: "/tmp",
		Code: platform.CodeIdentity{Signed: true, Apple: true, SigningID: "com.apple.zsh", CDHash: []byte{0xab, 0xcd}}}
	if info.Ref != want.Ref || info.Parent != want.Parent || !info.StartTime.Equal(want.StartTime) || info.Path != want.Path || info.Comm != "zsh" ||
		len(info.Args) != 2 || info.Args[1] != `a"b` || info.Code.Team() != "apple" || string(info.Code.CDHash) != "\xab\xcd" {
		t.Fatalf("decoded %+v", info)
	}
	var b wireBundle
	if err := decodeStrict([]byte(goldenBundle), &b); err != nil || b.BundleID != "com.apple.TextEdit" {
		t.Fatalf("%+v %v", b, err)
	}
}

// Swift's decoder needs every field, so Go never sends null for a list.
func TestGoDocumentsAlwaysCarryEveryField(t *testing.T) {
	js, _ := json.Marshal(toWirePrompt(platform.Prompt{Title: "t", Timeout: 1500 * time.Millisecond}))
	if string(js) != `{"title":"t","lines":[],"commandLine":0,"unknown":false,"reason":"","timeoutMillis":1500}` {
		t.Fatalf("prompt %s", js)
	}
	js, _ = json.Marshal(toWireWarning(platform.Warning{ID: "w"}))
	if string(js) != `{"id":"w","title":"","lines":[],"commandLine":0,"count":0,"suggestedRule":""}` {
		t.Fatalf("warning %s", js)
	}
	js, _ = json.Marshal([]wireProcess{toWireProcess(platform.ProcessInfo{})})
	var back []map[string]any
	json.Unmarshal(js, &back)
	if back[0]["args"] == nil || back[0]["code"].(map[string]any)["cdhash"] != "" {
		t.Fatalf("process %s", js)
	}
}

func TestDecodeStrictRefusesWhatIsNotExactlyOneDocument(t *testing.T) {
	var v wirePrompt
	for _, bad := range []string{``, `{`, `{"title":"t","extra":1}`, `{"title":"t"} {"title":"u"}`, `[]`, `null x`} {
		if err := decodeStrict([]byte(bad), &v); err == nil {
			t.Errorf("decodeStrict(%q) succeeded", bad)
		}
	}
	big := make([]byte, maxDocument+1)
	if err := decodeStrict(big, &v); err == nil {
		t.Error("oversized document accepted")
	}
}

// Comm crosses the wire both ways unchanged, hostile text included, and is
// always present (Swift's decoder needs every field).
func TestProcessCommCrossesTheWire(t *testing.T) {
	for _, comm := range []string{"", "zsh", "2.1.299", "a\"b\n‮→ssh", "0123456789abcdef"} {
		js, err := json.Marshal(toWireProcess(platform.ProcessInfo{Path: "", Comm: comm}))
		if err != nil {
			t.Fatal(err)
		}
		var top map[string]any
		if err := json.Unmarshal(js, &top); err != nil {
			t.Fatal(err)
		}
		if got, ok := top["comm"].(string); !ok || got != comm {
			t.Errorf("encoded comm = %#v (present %v), want %q: %s", top["comm"], ok, comm, js)
		}
		var back wireProcess
		if err := decodeStrict(js, &back); err != nil {
			t.Fatal(err)
		}
		if info := back.info(); info.Comm != comm || info.Path != "" {
			t.Errorf("round trip: Comm %q Path %q, want %q and \"\"", info.Comm, info.Path, comm)
		}
	}
}

// Confirm's `allowed` output. Only 1 allows; 2 to 5
// say how the dialog was denied; 0 and anything else are a plain denial.
func TestConfirmAnswer(t *testing.T) {
	for allowed, want := range map[int32]struct {
		ok  bool
		how platform.DialogHow // -1: a plain (false, nil) denial
	}{
		1: {true, -1}, 0: {false, -1}, 2: {false, platform.DialogDenyButton}, 3: {false, platform.DialogEscape},
		4: {false, platform.DialogTimedOut}, 5: {false, platform.DialogClosed}, 6: {false, -1}, -1: {false, -1}, 255: {false, -1},
	} {
		ok, err := confirmAnswer(allowed)
		var d platform.DialogDenied
		switch {
		case ok != want.ok:
			t.Errorf("allowed=%d: ok %v", allowed, ok)
		case want.how == -1 && err != nil:
			t.Errorf("allowed=%d: err %v, want none", allowed, err)
		case want.how != -1 && (!errors.As(err, &d) || d.How != want.how || !errors.Is(err, platform.ErrDenied)):
			t.Errorf("allowed=%d: err %v, want DialogDenied{%v} wrapping ErrDenied", allowed, err, want.how)
		}
	}
}

// Attack case: whatever the Swift side writes into `allowed` (a bug,
// an uninitialised value, a sign flip), only exactly 1 allows, and only 2
// to 5 carry a DialogDenied; every other value is a plain (false, nil)
// denial, never an error that could be mistaken for something else.
func TestConfirmAnswerOnlyOneAllows(t *testing.T) {
	values := []int32{math.MinInt32, math.MinInt32 + 1, -256, -2, 256, 257, 1 << 16, 1 << 24, math.MaxInt32 - 1, math.MaxInt32}
	for v := int32(-300); v <= 300; v++ {
		values = append(values, v)
	}
	for _, v := range values {
		ok, err := confirmAnswer(v)
		if ok != (v == 1) {
			t.Errorf("allowed=%d: ok %v", v, ok)
		}
		var d platform.DialogDenied
		isHow := v >= 2 && v <= 5
		if errors.As(err, &d) != isHow {
			t.Errorf("allowed=%d: err %v (DialogDenied %v)", v, err, !isHow)
		}
		if !isHow && err != nil {
			t.Errorf("allowed=%d: err %v, want a plain denial", v, err)
		}
		if ok && err != nil {
			t.Errorf("allowed=%d: allowed with an error %v", v, err)
		}
	}
}

// The DialogDenied error itself: it is a denial (ErrDenied) and its text
// says how, for any log that prints the error.
func TestDialogDeniedIsADenial(t *testing.T) {
	for how, text := range map[platform.DialogHow]string{
		platform.DialogDenyButton: "Deny button",
		platform.DialogEscape:     "Esc",
		platform.DialogTimedOut:   "the dialog timed out",
		platform.DialogClosed:     "the dialog closed without an answer",
		platform.DialogNoReason:   "no reason given",
		platform.DialogHow(1):     "no reason given", // 1 is Allow, never a way to be denied
		platform.DialogHow(99):    "no reason given",
	} {
		if how.String() != text {
			t.Errorf("DialogHow(%d).String() = %q, want %q", int(how), how.String(), text)
		}
		var err error = platform.DialogDenied{How: how}
		if !errors.Is(err, platform.ErrDenied) {
			t.Errorf("DialogDenied{%d} does not wrap ErrDenied", int(how))
		}
		if want := "platform: user denied (" + text + ")"; err.Error() != want {
			t.Errorf("DialogDenied{%d}.Error() = %q, want %q", int(how), err.Error(), want)
		}
	}
}

// A command line number outside the lines never crosses the wire: the
// platform would index past them.
func TestCommandLineNumberStaysInsideTheLines(t *testing.T) {
	for _, tc := range []struct{ n, want int }{{0, 0}, {1, 1}, {2, 2}, {3, 0}, {-1, 0}} {
		if got := toWirePrompt(platform.Prompt{Lines: []string{"a", "b"}, CommandLine: tc.n}).CommandLine; got != tc.want {
			t.Errorf("prompt CommandLine %d -> %d, want %d", tc.n, got, tc.want)
		}
		if got := toWireWarning(platform.Warning{Lines: []string{"a", "b"}, CommandLine: tc.n}).CommandLine; got != tc.want {
			t.Errorf("warning CommandLine %d -> %d, want %d", tc.n, got, tc.want)
		}
	}
}
