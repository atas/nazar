//go:build !darwin || !cgo

package main

// openUIApp: Nazar UI.app exists only on macOS.
func openUIApp(string) (string, error) { return "", errUINotInstalled }
