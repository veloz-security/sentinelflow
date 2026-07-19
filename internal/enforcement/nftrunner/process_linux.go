//go:build linux

package nftrunner

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

const processWaitDelay = 100 * time.Millisecond

// NewProductionRunner returns the Linux-only fixed nft process adapter. The
// binary path, arguments, environment, working directory, and output bound are
// compile-time constants and cannot be supplied by a caller.
func NewProductionRunner() (*Runner, error) {
	return &Runner{run: runProductionProcess}, nil
}

func runProductionProcess(ctx context.Context, request processRequest) (processResult, bool) {
	result := processResult{exitStatus: -1}
	if ctx == nil || (request.kind != processMutation && request.kind != processInspect) ||
		(request.kind == processInspect && len(request.stdin) != 0) {
		return result, true
	}

	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	capture := newBoundedCapture(MaxProcessOutput, cancel)
	command := exec.CommandContext(processCtx, request.path(), request.arguments()...)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.WaitDelay = processWaitDelay
	if request.kind == processMutation {
		command.Stdin = bytes.NewReader(append([]byte(nil), request.stdin...))
	}
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
