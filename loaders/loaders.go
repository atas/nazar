// Package loaders is nazar run's two loaders as nazar-agent is built with
// them (secrets design 6.3.1). make agent copies the same
// files into nazar-agent.app/Contents/Resources/loaders, and the agent
// refuses a run whose loader there is not byte for byte these: what runs in
// a receiver is decided by the agent's own code, which the kernel holds to
// its signature, not by the bundle's seal, which macOS checks only when
// Gatekeeper first assesses the app.
package loaders

import _ "embed"

// Node is node/env.cjs.
//
//go:embed node/env.cjs
var Node string

// Python is python/sitecustomize.py.
//
//go:embed python/sitecustomize.py
var Python string
