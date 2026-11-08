//go:build darwin && cgo

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

// The Launch Services lookup behind `nazar ui` reports an unknown bundle
// id as not installed (and opens nothing: it is a lookup only).
func TestAppForBundleIDAbsent(t *testing.T) {
	b := make([]byte, 8)
	rand.Read(b)
	id := "dev.nazar.test.absent." + hex.EncodeToString(b)
	if p, err := appForBundleID(id); !errors.Is(err, errUINotInstalled) {
		t.Fatalf("appForBundleID(%q) = %q, %v; want errUINotInstalled", id, p, err)
	}
}

// openUIApp looks the bundle id up before it runs anything: an id Launch
// Services does not know is errUINotInstalled with no path, so /usr/bin/open
// is never asked to open (or search for) an app that is not there.
func TestOpenUIAppAbsent(t *testing.T) {
	b := make([]byte, 8)
	rand.Read(b)
	id := "dev.nazar.test.absent." + hex.EncodeToString(b)
	if p, err := openUIApp(id); !errors.Is(err, errUINotInstalled) || p != "" {
		t.Fatalf("openUIApp(%q) = %q, %v; want errUINotInstalled", id, p, err)
	}
}
