package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/devwooops/sentinelflow/internal/buildinfo"
	"golang.org/x/sys/unix"
)

func main() {
	os.Exit(run())
}

func run() int {
	// The executor creates only owner-private state until the verified UDS is
	// explicitly chmodded to its final shared-group 0660 mode.
	_ = unix.Umask(0o077)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	application, err := newProductionApplication(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "SentinelFlow executor startup failed")
		return 1
	}
	defer application.close()

	fmt.Fprintf(os.Stdout, "%s executor %s ready\n", buildinfo.Name, buildinfo.Version)
	if err = application.serve(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "SentinelFlow executor stopped unexpectedly")
		return 1
	}
	return 0
}
