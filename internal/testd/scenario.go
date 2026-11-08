// Package testd scripts the fake platform from a JSON file that tests can
// rewrite while nazar-testd runs. It is test-only code; nothing in it ships.
package testd

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"sync"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Script is the scenario file. Every field is re-read on each use.
type Script struct {
	Chain   string `json:"chain"`   // iterm (default) | iterm-claude | terminal | unknown
	Auth    string `json:"auth"`    // login gate: allow | deny (default) | hang
	Confirm string `json:"confirm"` // dialog gate: allow | deny (default) | hang
}

// Scenario drives a fake.Fake from a script file.
type Scenario struct {
	F    *fake.Fake
	Path string

	mu     sync.Mutex
	chains map[string]platform.ProcessRef
	hang   chan struct{}
}

// New wires the scenario into f: peers, gate answers and code hashes. The
// apps of the scripted chains are installed with their real teams, because
// app: team pins come from the INSTALLED app when a config is approved
// (spec 4.2): an integration test that approves `app: com.googlecode.iterm2`
// gets a working matcher, as on a typical Mac.
func New(f *fake.Fake, path string) *Scenario {
	s := &Scenario{F: f, Path: path, chains: map[string]platform.ProcessRef{}, hang: make(chan struct{})}
	f.InstallApp("/Applications/iTerm.app", "com.googlecode.iterm2", fake.ITermCode)
	f.InstallApp("/System/Applications/Utilities/Terminal.app", "com.apple.Terminal", fake.AppleCode("com.apple.Terminal"))
	f.PeerFunc = func(int) (platform.ProcessRef, error) { return s.peer(s.read().Chain), nil }
	f.SetGateFuncs(
		func(platform.Prompt) fake.Answer { return s.answer(s.read().Auth) },
		func(platform.Prompt) fake.Answer { return s.answer(s.read().Confirm) },
	)
	f.CodeHashFunc = func(p string) ([]byte, error) {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		return sum[:20], nil
	}
	return s
}

// read returns the script as it is now; a missing or unreadable file is
// the zero Script (iterm chain, both gates deny).
func (s *Scenario) read() Script {
	var sc Script
	if b, err := os.ReadFile(s.Path); err == nil {
		_ = json.Unmarshal(b, &sc)
	}
	return sc
}

func (s *Scenario) answer(v string) fake.Answer {
	switch v {
	case "allow":
		return fake.Answer{Allow: true}
	case "hang":
		return fake.Answer{Wait: s.hang}
	}
	return fake.Answer{}
}

// peer returns the (stable) peer process for a chain name, so repeated
// connections in one scenario share a session.
func (s *Scenario) peer(name string) platform.ProcessRef {
	if name == "" {
		name = "iterm"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ref, ok := s.chains[name]; ok {
		return ref
	}
	f := s.F
	var ref platform.ProcessRef
	switch name {
	case "iterm-claude":
		ref = f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")}, fake.SSHProc()).Peer()
	case "terminal":
		term := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
			Code: fake.AppleCode("com.apple.Terminal"), App: &fake.App{BundleID: "com.apple.Terminal", Name: "Terminal"}})
		login := f.Launch(term, fake.Proc{Path: "/usr/bin/login", Root: true, Code: fake.AppleCode("com.apple.login")})
		shell := f.Launch(login, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
		ref = f.Launch(shell, fake.SSHProc())
	case "unknown":
		ref = f.Launch(platform.ProcessRef{}, fake.SSHProc())
	default:
		ref = f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/usr/bin/git", Code: fake.AppleCode("com.apple.git")}, fake.SSHProc()).Peer()
	}
	s.chains[name] = ref
	return ref
}
