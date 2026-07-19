//go:build linux

package nftcheck

import (
	"bytes"
	"context"
	"os/exec"
	"sync"
	"time"
)

const processWaitDelay = 100 * time.Millisecond

type productionRunner struct{}

// NewProductionRunner returns the Linux-only, fixed-path nft process runner.
func NewProductionRunner() (ProcessRunner, error) {
	return productionRunner{}, nil
}

func (productionRunner) Version(ctx context.Context) (ProcessResult, error) {
	return runFixed(ctx, versionArguments, nil)
}

func (productionRunner) Check(ctx context.Context, canonical []byte) (ProcessResult, error) {
	if !validCanonicalEnvelope(canonical) {
		return ProcessResult{
			Path:       FixedNFTBinaryPath,
			Arguments:  cloneStrings(checkArguments),
			ExitStatus: -1,
		}, reject(ErrorCandidateInvalid)
	}
	return runFixed(ctx, checkArguments, append([]byte(nil), canonical...))
}

func runFixed(ctx context.Context, arguments []string, stdin []byte) (ProcessResult, error) {
	result := ProcessResult{
		Path:       FixedNFTBinaryPath,
		Arguments:  cloneStrings(arguments),
		ExitStatus: -1,
	}
	if ctx == nil {
		return result, reject(ErrorInvalidInput)
	}

	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	capture := newBoundedCapture(MaxProcessOutput, cancel)
	command := exec.CommandContext(processCtx, FixedNFTBinaryPath, arguments...)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.WaitDelay = processWaitDelay
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	command.Stdout = capture.writer(false)
	command.Stderr = capture.writer(true)
	err := command.Run()
	result.Stdout, result.Stderr, result.OutputOverflow = capture.result()
	if command.ProcessState != nil {
		result.ExitStatus = command.ProcessState.ExitCode()
	}
	return result, err
}

type boundedCapture struct {
	mu       sync.Mutex
	limit    int
	total    int
	overflow bool
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	cancel   context.CancelFunc
}

func newBoundedCapture(limit int, cancel context.CancelFunc) *boundedCapture {
	return &boundedCapture{limit: limit, cancel: cancel}
}

func (capture *boundedCapture) writer(stderr bool) captureWriter {
	return captureWriter{capture: capture, stderr: stderr}
}

func (capture *boundedCapture) write(value []byte, stderr bool) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()

	remaining := capture.limit - capture.total
	if remaining < 0 {
		remaining = 0
	}
	accepted := len(value)
	if accepted > remaining {
		accepted = remaining
		if !capture.overflow {
			capture.overflow = true
			capture.cancel()
		}
	}
	if accepted > 0 {
		if stderr {
			_, _ = capture.stderr.Write(value[:accepted])
		} else {
			_, _ = capture.stdout.Write(value[:accepted])
		}
		capture.total += accepted
	}
	return len(value), nil
}

func (capture *boundedCapture) result() ([]byte, []byte, bool) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]byte(nil), capture.stdout.Bytes()...),
		append([]byte(nil), capture.stderr.Bytes()...), capture.overflow
}

type captureWriter struct {
	capture *boundedCapture
	stderr  bool
}

func (writer captureWriter) Write(value []byte) (int, error) {
	return writer.capture.write(value, writer.stderr)
}
