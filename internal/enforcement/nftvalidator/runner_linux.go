//go:build linux

package nftvalidator

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

const processWaitDelay = 100 * time.Millisecond

var fixedCheckArguments = []string{"--check", "-f", "-"}

type productionRunner struct {
	versionRunner nftcheck.ProcessRunner
	baseContract  []byte
}

// NewProductionRunner returns a fixed-path runner whose only syntax operation
// checks the startup-pinned base declaration and one canonical candidate in a
// single non-mutating nft --check transaction.
func NewProductionRunner(baseContract []byte) (nftcheck.ProcessRunner, error) {
	if _, err := combineCheckScript(baseContract, []byte("add element inet sentinelflow blacklist_ipv4 { 192.0.2.1 timeout 60s }\n")); err != nil {
		return nil, reject(ErrorInvalidConfiguration)
	}
	versionRunner, err := nftcheck.NewProductionRunner()
	if err != nil {
		return nil, runnerError(nftcheck.ErrorRunnerUnavailable)
	}
	return &productionRunner{
		versionRunner: versionRunner, baseContract: append([]byte(nil), baseContract...),
	}, nil
}

func (r *productionRunner) Version(ctx context.Context) (nftcheck.ProcessResult, error) {
	if r == nil || r.versionRunner == nil || ctx == nil {
		return nftcheck.ProcessResult{
			Path: nftcheck.FixedNFTBinaryPath, Arguments: []string{"--version"}, ExitStatus: -1,
		}, runnerError(nftcheck.ErrorInvalidInput)
	}
	return r.versionRunner.Version(ctx)
}

func (r *productionRunner) Check(ctx context.Context, candidate []byte) (nftcheck.ProcessResult, error) {
	result := nftcheck.ProcessResult{
		Path: nftcheck.FixedNFTBinaryPath, Arguments: append([]string(nil), fixedCheckArguments...), ExitStatus: -1,
	}
	if r == nil || ctx == nil {
		return result, runnerError(nftcheck.ErrorInvalidInput)
	}
	script, err := combineCheckScript(r.baseContract, candidate)
	if err != nil {
		return result, runnerError(nftcheck.ErrorCandidateInvalid)
	}
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	capture := newBoundedCapture(nftcheck.MaxProcessOutput, cancel)
	command := exec.CommandContext(processCtx, nftcheck.FixedNFTBinaryPath, fixedCheckArguments...)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.WaitDelay = processWaitDelay
	command.Stdin = bytes.NewReader(script)
	command.Stdout = capture.writer(false)
	command.Stderr = capture.writer(true)
	runErr := command.Run()
	result.Stdout, result.Stderr, result.OutputOverflow = capture.result()
	if command.ProcessState != nil {
		result.ExitStatus = command.ProcessState.ExitCode()
	}
	if contextErr := processContextError(processCtx.Err()); contextErr != nil {
		return result, contextErr
	}
	return result, runErr
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

func processContextError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return runnerError(nftcheck.ErrorTimeout)
	case errors.Is(err, context.Canceled):
		return runnerError(nftcheck.ErrorCancelled)
	default:
		return nil
	}
}
