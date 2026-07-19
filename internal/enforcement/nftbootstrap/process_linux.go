//go:build linux

package nftbootstrap

import (
	"bytes"
	"context"
	"os/exec"
)

// NewProductionManager returns the Linux-only fixed nft bootstrap boundary.
// The executable, argv, working directory, environment, and resource bounds
// are compile-time constants and cannot be supplied by a caller.
func NewProductionManager() (*Manager, error) {
	return &Manager{run: runProductionProcess}, nil
}

func runProductionProcess(ctx context.Context, request processRequest) (processResult, bool) {
	result := processResult{exitStatus: -1}
	if ctx == nil || (request.kind != processInventory && request.kind != processApply && request.kind != processVerifyLive) ||
		(request.kind != processApply && len(request.stdin) != 0) {
		return result, true
	}

	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	capture := newBoundedCapture(MaxProcessOutput, cancel)
	command := newProductionCommand(processCtx, request)
	command.Stdout = capture.writer(false)
	command.Stderr = capture.writer(true)
	runError := command.Run() != nil
	result.stdout, result.stderr, result.overflow = capture.result()
	if command.ProcessState != nil {
		result.exitStatus = command.ProcessState.ExitCode()
		result.signaled = result.exitStatus < 0
	}
	return result, runError
}

func newProductionCommand(ctx context.Context, request processRequest) *exec.Cmd {
	command := exec.CommandContext(ctx, request.path(), request.arguments()...)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.WaitDelay = processWaitDelay
	if request.kind == processApply {
		command.Stdin = bytes.NewReader(append([]byte(nil), request.stdin...))
	}
	return command
}
