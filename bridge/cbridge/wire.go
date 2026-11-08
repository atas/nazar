package cbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/atas/nazar/core/platform"
)

// The JSON documents that cross the C ABI (nazar_bridge.h). Field names are
// part of the ABI and match macos/Sources/NazarPlatform/Wire.swift; the
// golden strings in wire_test.go are the ones WireTests.swift encodes.

type wireCode struct {
	Signed    bool   `json:"signed"`
	TeamID    string `json:"teamId"`
	SigningID string `json:"signingId"`
	Apple     bool   `json:"apple"`
	AdHoc     bool   `json:"adHoc"`
	CDHash    []byte `json:"cdhash"`
}

type wireProcess struct {
	PID              int      `json:"pid"`
	Generation       uint64   `json:"generation"`
	ParentPID        int      `json:"parentPid"`
	ParentGeneration uint64   `json:"parentGeneration"`
	UID              int      `json:"uid"`
	StartMicros      int64    `json:"startMicros"`
	Path             string   `json:"path"`
	Args             []string `json:"args"`
	Cwd              string   `json:"cwd"`
	Code             wireCode `json:"code"`
	Comm             string   `json:"comm"`
}

type wireApp struct {
	PID        int      `json:"pid"`
	Generation uint64   `json:"generation"`
	BundleID   string   `json:"bundleId"`
	Name       string   `json:"name"`
	Code       wireCode `json:"code"`
}

type wireBundle struct {
	BundleID string   `json:"bundleId"`
	Path     string   `json:"path"`
	Code     wireCode `json:"code"`
}

type wirePrompt struct {
	Title         string   `json:"title"`
	Lines         []string `json:"lines"`
	CommandLine   int      `json:"commandLine"`
	Unknown       bool     `json:"unknown"`
	Reason        string   `json:"reason"`
	TimeoutMillis int64    `json:"timeoutMillis"`
}

type wireWarning struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Lines         []string `json:"lines"`
	CommandLine   int      `json:"commandLine"`
	Count         int      `json:"count"`
	SuggestedRule string   `json:"suggestedRule"`
}

// maxDocument bounds every JSON document Go accepts from Swift.
const maxDocument = 4 << 20

// decodeStrict decodes exactly one JSON document into v: unknown fields,
// trailing data and oversized documents are errors.
func decodeStrict(b []byte, v any) error {
	if len(b) > maxDocument {
		return errors.New("cbridge: document too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("cbridge: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("cbridge: trailing data after the document")
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func toWireCode(c platform.CodeIdentity) wireCode {
	h := c.CDHash
	if h == nil {
		h = []byte{}
	}
	return wireCode{Signed: c.Signed, TeamID: c.TeamID, SigningID: c.SigningID, Apple: c.Apple, AdHoc: c.AdHoc, CDHash: h}
}

func (w wireCode) identity() platform.CodeIdentity {
	return platform.CodeIdentity{Signed: w.Signed, TeamID: w.TeamID, SigningID: w.SigningID, Apple: w.Apple, AdHoc: w.AdHoc, CDHash: w.CDHash}
}

func toWireProcess(p platform.ProcessInfo) wireProcess {
	return wireProcess{PID: p.Ref.PID, Generation: p.Ref.Generation, ParentPID: p.Parent.PID, ParentGeneration: p.Parent.Generation,
		UID: p.UID, StartMicros: p.StartTime.UnixMicro(), Path: p.Path, Args: nonNil(p.Args), Cwd: p.Cwd, Code: toWireCode(p.Code),
		Comm: p.Comm}
}

func (w wireProcess) info() platform.ProcessInfo {
	return platform.ProcessInfo{
		Ref:       platform.ProcessRef{PID: w.PID, Generation: w.Generation},
		Parent:    platform.ProcessRef{PID: w.ParentPID, Generation: w.ParentGeneration},
		UID:       w.UID,
		StartTime: time.UnixMicro(w.StartMicros),
		Path:      w.Path, Args: w.Args, Cwd: w.Cwd, Code: w.Code.identity(), Comm: w.Comm,
	}
}

func toWirePrompt(p platform.Prompt) wirePrompt {
	return wirePrompt{Title: p.Title, Lines: nonNil(p.Lines), CommandLine: commandIndex(p.CommandLine, p.Lines), Unknown: p.Unknown, Reason: p.Reason, TimeoutMillis: p.Timeout.Milliseconds()}
}

func (w wirePrompt) prompt() platform.Prompt {
	return platform.Prompt{Title: w.Title, Lines: w.Lines, CommandLine: w.CommandLine, Unknown: w.Unknown, Reason: w.Reason, Timeout: time.Duration(w.TimeoutMillis) * time.Millisecond}
}

func toWireWarning(w platform.Warning) wireWarning {
	return wireWarning{ID: w.ID, Title: w.Title, Lines: nonNil(w.Lines), CommandLine: commandIndex(w.CommandLine, w.Lines), Count: w.Count, SuggestedRule: w.SuggestedRule}
}

func (w wireWarning) warning() platform.Warning {
	return platform.Warning{ID: w.ID, Title: w.Title, Lines: w.Lines, CommandLine: w.CommandLine, Count: w.Count, SuggestedRule: w.SuggestedRule}
}

func toWireApp(a platform.AppInfo) wireApp {
	return wireApp{PID: a.Ref.PID, Generation: a.Ref.Generation, BundleID: a.BundleID, Name: a.Name, Code: toWireCode(a.Code)}
}

func toWireBundle(b platform.AppBundle) wireBundle {
	return wireBundle{BundleID: b.BundleID, Path: b.Path, Code: toWireCode(b.Code)}
}

// commandIndex is n when it is the 1-based number of one of lines, else
// 0 (none): the platform never gets a line number outside the lines it
// was sent.
func commandIndex(n int, lines []string) int {
	if n < 1 || n > len(lines) {
		return 0
	}
	return n
}
