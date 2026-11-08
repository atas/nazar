// Command nazar-testd runs the nazar core with the fake platform and a
// software "enclave", for integration tests. It is never installed.
//
//	nazar-testd -home DIR [-script FILE] [-audit FILE] [-known-hosts FILE] [-timeout 5s]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/daemon"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/internal/testd"
)

func main() {
	home := flag.String("home", "", "home directory to use instead of $HOME (required)")
	script := flag.String("script", "", "scenario JSON file (re-read on every use)")
	auditPath := flag.String("audit", "", "file to append audit lines to (default stderr)")
	knownHosts := flag.String("known-hosts", "", "known_hosts file (default <home>/.ssh/known_hosts)")
	timeout := flag.Duration("timeout", 5*time.Second, "gate timeout")
	flag.Parse()
	if *home == "" {
		fmt.Fprintln(os.Stderr, "nazar-testd: -home is required")
		os.Exit(2)
	}
	f := fake.New(time.Now())
	testd.New(f, *script)
	var sink audit.Sink = &audit.WriterSink{W: os.Stderr}
	if *auditPath != "" {
		af, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		defer af.Close()
		sink = &audit.WriterSink{W: af}
	}
	d, err := daemon.New(daemon.Options{
		Platform: f, Vault: fake.NewVault(), AuditSink: sink, Home: *home, KnownHosts: *knownHosts,
		PollInterval: 100 * time.Millisecond, GateTimeout: func() time.Duration { return *timeout },
		Logf: func(format string, args ...any) { log.Printf(format, args...) },
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Printf("nazar-testd: home=%s", *home)
	if err := d.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
