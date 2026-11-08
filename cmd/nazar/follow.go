package main

import (
	"context"
	"os/signal"
	"syscall"
)

// commandContext is a command's context: it ends on SIGINT or SIGTERM and,
// for a --follow stream, also once the process that started the CLI exits
// (Nazar UI.app quit or was killed), so a stream with nothing to print never
// outlives its reader under launchd. The command then exits 0, printing
// nothing more. A stream started with launchd as its parent already (a
// shell that exec'd it) runs as before. Writing to a stdout whose reader is
// gone ends the CLI too (SIGPIPE), but only once there is a line to write.
func commandContext(follow bool) (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	if !follow {
		return ctx, stop
	}
	ctx, cancel := context.WithCancel(ctx)
	watchParent(ctx, cancel)
	return ctx, func() { cancel(); stop() }
}
