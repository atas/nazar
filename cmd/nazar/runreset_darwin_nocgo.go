//go:build darwin && !cgo

package main

// resetForExec needs cgo on macOS (the Mach exception ports have no system
// call of their own). A build without cgo leaves it nil, and nazar run
// refuses before it asks nazar-agent anything.
var resetForExec func(dirFD int) error
