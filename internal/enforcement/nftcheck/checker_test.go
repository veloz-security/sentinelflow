package nftcheck

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testVersion = "nftables v1.0.9"
	testBase    = "table inet sentinelflow {\n" +
		"  set blacklist_ipv4 {\n" +
		"    type ipv4_addr\n" +
		"    flags timeout\n" +
		"  }\n\n" +
		"  chain gateway_input {\n" +
		"    type filter hook input priority 0\n" +
		"    policy accept\n" +
		"    tcp dport 8080 ip saddr @blacklist_ipv4 drop\n" +
		"  }\n" +
		"}\n"
	testCandidate = "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n"
)

type fakeRunner struct {
	mu            sync.Mutex
	versionResult ProcessResult
	versionError  error
	checkResult   ProcessResult
	checkError    error
	versionCalls  int
	checkCalls    int
	checkedInput  []byte
	versionBlock  bool
	checkBlock    bool
	mutateInput   bool
}

func goodRunner() *fakeRunner {
	return &fakeRunner{
		versionResult: ProcessResult{
			Path:       FixedNFTBinaryPath,
			Arguments:  cloneStrings(versionArguments),
			ExitStatus: 0,
			Stdout:     []byte(testVersion + " (Old Doc Yak #3)\n"),
		},
		checkResult: ProcessResult{
			Path:       FixedNFTBinaryPath,
			Arguments:  cloneStrings(checkArguments),
			ExitStatus: 0,
		},
	}
}

func (runner *fakeRunner) Version(ctx context.Context) (ProcessResult, error) {
	runner.mu.Lock()
	runner.versionCalls++
	block := runner.versionBlock
	result := cloneProcessResult(runner.versionResult)
	err := runner.versionError
	runner.mu.Unlock()
	if block {
		<-ctx.Done()
		return result, ctx.Err()
	}
	return result, err
}

func (runner *fakeRunner) Check(ctx context.Context, input []byte) (ProcessResult, error) {
	runner.mu.Lock()
	runner.checkCalls++
	runner.checkedInput = append([]byte(nil), input...)
	block := runner.checkBlock
	mutate := runner.mutateInput
	result := cloneProcessResult(runner.checkResult)
	err := runner.checkError
	runner.mu.Unlock()
	if mutate && len(input) > 0 {
		input[0] = 'X'
	}
	if block {
		<-ctx.Done()
		return result, ctx.Err()
	}
	return result, err
}

func cloneProcessResult(value ProcessResult) ProcessResult {
	value.Arguments = cloneStrings(value.Arguments)
	value.Stdout = append([]byte(nil), value.Stdout...)
	value.Stderr = append([]byte(nil), value.Stderr...)
	return value
}

func validInput() Input {
	canonical := []byte(testCandidate)
	return Input{
		CanonicalBytes:     canonical,
		CanonicalDigest:    digest(canonical),
		BaseContract:       []byte(testBase),
		BaseContractDigest: PinnedBaseContractDigest,
	}
}

func newTestChecker(t *testing.T, runner ProcessRunner) *Checker {
	t.Helper()
	checker, err := New(runner, testVersion)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return checker
}

func requireCode(t *testing.T, err error, expected ErrorCode) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != expected {
		t.Fatalf("error = %v, want code %q", err, expected)
	}
	if strings.Contains(err.Error(), testCandidate) || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error leaked untrusted data: %q", err)
	}
}

func TestCheckAcceptsPinnedCanonicalArtifact(t *testing.T) {
	runner := goodRunner()
	checker := newTestChecker(t, runner)
	evidence, err := checker.Check(context.Background(), validInput())
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if evidence.GateVersion != GateVersion || evidence.CanonicalDigest != digest([]byte(testCandidate)) ||
		evidence.BaseContractDigest != PinnedBaseContractDigest || evidence.NFTBinaryPath != FixedNFTBinaryPath ||
		evidence.NFTVersion != testVersion || evidence.VersionExitStatus != 0 || evidence.SyntaxExitStatus != 0 {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
	if evidence.VersionArguments != [1]string{"--version"} ||
		evidence.SyntaxArguments != [3]string{"--check", "-f", "-"} {
		t.Fatalf("unexpected fixed arguments: %#v", evidence)
	}
	if !digestPattern.MatchString(evidence.VersionOutputDigest) ||
		!digestPattern.MatchString(evidence.SyntaxOutputDigest) {
		t.Fatalf("missing sanitized output digests: %#v", evidence)
	}
	if string(runner.checkedInput) != testCandidate {
		t.Fatalf("runner input = %q", runner.checkedInput)
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		runner  ProcessRunner
		version string
	}{
		{name: "nil runner", version: testVersion},
		{name: "empty version", runner: goodRunner()},
		{name: "unbounded suffix", runner: goodRunner(), version: "nftables v1.0.9 " + strings.Repeat("x", 100)},
		{name: "shell shaped", runner: goodRunner(), version: "nftables v1.0.9; id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.runner, test.version)
			requireCode(t, err, ErrorInvalidInput)
		})
	}
}

func TestCheckRejectsCandidateAndBaseBeforeProcess(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Input)
		code ErrorCode
	}{
		{name: "empty candidate", edit: func(input *Input) { input.CanonicalBytes = nil }, code: ErrorCandidateInvalid},
		{name: "missing LF", edit: func(input *Input) { input.CanonicalBytes = []byte(strings.TrimSuffix(testCandidate, "\n")) }, code: ErrorCandidateInvalid},
		{name: "multiple LF", edit: func(input *Input) { input.CanonicalBytes = []byte(testCandidate + "\n") }, code: ErrorCandidateInvalid},
		{name: "carriage return", edit: func(input *Input) { input.CanonicalBytes = []byte(strings.TrimSuffix(testCandidate, "\n") + "\r\n") }, code: ErrorCandidateInvalid},
		{name: "tab", edit: func(input *Input) { input.CanonicalBytes = []byte("x\t\n") }, code: ErrorCandidateInvalid},
		{name: "unicode", edit: func(input *Input) { input.CanonicalBytes = []byte("한\n") }, code: ErrorCandidateInvalid},
		{name: "BOM", edit: func(input *Input) { input.CanonicalBytes = append([]byte{0xef, 0xbb, 0xbf}, []byte("x\n")...) }, code: ErrorCandidateInvalid},
		{name: "oversize", edit: func(input *Input) {
			input.CanonicalBytes = append([]byte(strings.Repeat("a", MaxCandidateBytes)), '\n')
		}, code: ErrorCandidateInvalid},
		{name: "malformed candidate digest", edit: func(input *Input) { input.CanonicalDigest = "sha256:ABC" }, code: ErrorCandidateDigest},
		{name: "candidate mismatch", edit: func(input *Input) { input.CanonicalDigest = digest([]byte("different\n")) }, code: ErrorCandidateMismatch},
		{name: "caller selected base digest", edit: func(input *Input) { input.BaseContractDigest = digest([]byte("other")) }, code: ErrorBaseDigest},
		{name: "malformed base digest", edit: func(input *Input) { input.BaseContractDigest = "SHA256:" + strings.Repeat("0", 64) }, code: ErrorBaseDigest},
		{name: "empty base", edit: func(input *Input) { input.BaseContract = nil }, code: ErrorBaseContract},
		{name: "oversize base", edit: func(input *Input) { input.BaseContract = []byte(strings.Repeat("a", MaxBaseContractBytes+1)) }, code: ErrorBaseContract},
		{name: "mutated base", edit: func(input *Input) { input.BaseContract[0] ^= 1 }, code: ErrorBaseContract},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := goodRunner()
			input := validInput()
			test.edit(&input)
			_, err := newTestChecker(t, runner).Check(context.Background(), input)
			requireCode(t, err, test.code)
			if runner.versionCalls != 0 || runner.checkCalls != 0 {
				t.Fatalf("process started before pure validation: version=%d check=%d", runner.versionCalls, runner.checkCalls)
			}
		})
	}
}

func TestCheckRejectsVersionFailuresWithoutSyntaxInvocation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*fakeRunner)
		code ErrorCode
	}{
		{name: "wrong path", edit: func(r *fakeRunner) { r.versionResult.Path = "/tmp/nft" }, code: ErrorInvocationMismatch},
		{name: "wrong arguments", edit: func(r *fakeRunner) { r.versionResult.Arguments = []string{"--help"} }, code: ErrorInvocationMismatch},
		{name: "missing binary", edit: func(r *fakeRunner) { r.versionResult.ExitStatus = -1; r.versionError = errors.New("not found") }, code: ErrorRunnerUnavailable},
		{name: "nonzero", edit: func(r *fakeRunner) { r.versionResult.ExitStatus = 2; r.versionError = errors.New("exit status 2") }, code: ErrorVersionCommand},
		{name: "stderr", edit: func(r *fakeRunner) { r.versionResult.Stderr = []byte("warning") }, code: ErrorVersionInvalid},
		{name: "invalid output", edit: func(r *fakeRunner) { r.versionResult.Stdout = []byte("nft 1.0.9\n") }, code: ErrorVersionInvalid},
		{name: "trailing line", edit: func(r *fakeRunner) { r.versionResult.Stdout = []byte(testVersion + "\nSECRET=token\n") }, code: ErrorVersionInvalid},
		{name: "wrong version", edit: func(r *fakeRunner) { r.versionResult.Stdout = []byte("nftables v1.1.0\n") }, code: ErrorVersionMismatch},
		{name: "overflow marker", edit: func(r *fakeRunner) { r.versionResult.OutputOverflow = true }, code: ErrorOutputLimit},
		{name: "oversize output", edit: func(r *fakeRunner) { r.versionResult.Stdout = []byte(strings.Repeat("x", MaxProcessOutput+1)) }, code: ErrorOutputLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := goodRunner()
			test.edit(runner)
			evidence, err := newTestChecker(t, runner).Check(context.Background(), validInput())
			requireCode(t, err, test.code)
			if runner.checkCalls != 0 {
				t.Fatalf("syntax process ran after version failure")
			}
			if test.code == ErrorOutputLimit && evidence.VersionOutputDigest != "" {
				t.Fatalf("partial oversized output was attested: %#v", evidence)
			}
		})
	}
}

func TestCheckRejectsSyntaxProcessFailures(t *testing.T) {
	tests := []struct {
		name string
		edit func(*fakeRunner)
		code ErrorCode
	}{
		{name: "wrong path", edit: func(r *fakeRunner) { r.checkResult.Path = "/usr/bin/nft" }, code: ErrorInvocationMismatch},
		{name: "wrong arguments", edit: func(r *fakeRunner) { r.checkResult.Arguments = []string{"-f", "/tmp/input"} }, code: ErrorInvocationMismatch},
		{name: "start error", edit: func(r *fakeRunner) { r.checkResult.ExitStatus = -1; r.checkError = errors.New("missing") }, code: ErrorRunnerUnavailable},
		{name: "syntax nonzero", edit: func(r *fakeRunner) {
			r.checkResult.ExitStatus = 1
			r.checkError = errors.New("exit status 1")
			r.checkResult.Stderr = []byte("SECRET=raw nft diagnostic")
		}, code: ErrorSyntaxRejected},
		{name: "runner error after zero", edit: func(r *fakeRunner) { r.checkError = errors.New("wait failure") }, code: ErrorRunnerUnavailable},
		{name: "overflow marker", edit: func(r *fakeRunner) { r.checkResult.OutputOverflow = true }, code: ErrorOutputLimit},
		{name: "combined oversize", edit: func(r *fakeRunner) {
			r.checkResult.Stdout = []byte(strings.Repeat("a", MaxProcessOutput))
			r.checkResult.Stderr = []byte("b")
		}, code: ErrorOutputLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := goodRunner()
			test.edit(runner)
			evidence, err := newTestChecker(t, runner).Check(context.Background(), validInput())
			requireCode(t, err, test.code)
			if test.code == ErrorOutputLimit && evidence.SyntaxOutputDigest != "" {
				t.Fatalf("partial oversized output was attested: %#v", evidence)
			}
			if strings.Contains(fmt.Sprintf("%#v", evidence), "SECRET") {
				t.Fatalf("evidence leaked raw output: %#v", evidence)
			}
		})
	}
}

func TestCheckCancellationAndTimeout(t *testing.T) {
	t.Run("pre-cancelled", func(t *testing.T) {
		runner := goodRunner()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := newTestChecker(t, runner).Check(ctx, validInput())
		requireCode(t, err, ErrorCancelled)
		if runner.versionCalls != 0 {
			t.Fatal("pre-cancelled check started a process")
		}
	})

	t.Run("caller deadline", func(t *testing.T) {
		runner := goodRunner()
		runner.versionBlock = true
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		_, err := newTestChecker(t, runner).Check(ctx, validInput())
		requireCode(t, err, ErrorTimeout)
		if runner.checkCalls != 0 {
			t.Fatal("timed-out version check reached syntax process")
		}
	})

	t.Run("fixed gate deadline", func(t *testing.T) {
		runner := goodRunner()
		runner.versionBlock = true
		checker := newTestChecker(t, runner)
		checker.timeout = 5 * time.Millisecond
		_, err := checker.Check(context.Background(), validInput())
		requireCode(t, err, ErrorTimeout)
		if runner.checkCalls != 0 {
			t.Fatal("gate timeout reached syntax process")
		}
	})

	t.Run("cancel during syntax", func(t *testing.T) {
		runner := goodRunner()
		runner.checkBlock = true
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := newTestChecker(t, runner).Check(ctx, validInput())
			done <- err
		}()
		for {
			runner.mu.Lock()
			called := runner.checkCalls > 0
			runner.mu.Unlock()
			if called {
				break
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		requireCode(t, <-done, ErrorCancelled)
	})
}

func TestCheckCopiesInputAndSanitizesOutput(t *testing.T) {
	runner := goodRunner()
	runner.checkResult.Stdout = []byte("SECRET=do-not-persist")
	input := validInput()
	original := string(input.CanonicalBytes)
	evidence, err := newTestChecker(t, runner).Check(context.Background(), input)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if string(input.CanonicalBytes) != original {
		t.Fatal("caller candidate was mutated")
	}
	formatted := fmt.Sprintf("%#v", evidence)
	if strings.Contains(formatted, "SECRET") || strings.Contains(formatted, testCandidate) {
		t.Fatalf("evidence leaked raw data: %s", formatted)
	}
	if evidence.SyntaxOutputByteCount != uint32(len("SECRET=do-not-persist")) ||
		!digestPattern.MatchString(evidence.SyntaxOutputDigest) {
		t.Fatalf("missing sanitized output evidence: %#v", evidence)
	}
}

func TestCheckRejectsRunnerInputMutation(t *testing.T) {
	runner := goodRunner()
	runner.mutateInput = true
	input := validInput()
	original := string(input.CanonicalBytes)
	_, err := newTestChecker(t, runner).Check(context.Background(), input)
	requireCode(t, err, ErrorCandidateMismatch)
	if string(input.CanonicalBytes) != original {
		t.Fatal("caller candidate was mutated")
	}
}

func TestOutputDigestSeparatesStreams(t *testing.T) {
	if outputDigest([]byte("ab"), []byte("c")) == outputDigest([]byte("a"), []byte("bc")) {
		t.Fatal("stdout/stderr boundary was not committed")
	}
	emptyDigest := outputDigest(nil, nil)
	if emptyDigest != outputDigest(nil, nil) {
		t.Fatal("output digest is not deterministic")
	}
}

func TestCheckerConcurrentUse(t *testing.T) {
	runner := goodRunner()
	checker := newTestChecker(t, runner)
	const workers = 32
	errorsSeen := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := checker.Check(context.Background(), validInput())
			errorsSeen <- err
		}()
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent Check() error = %v", err)
		}
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.versionCalls != workers || runner.checkCalls != workers {
		t.Fatalf("calls = (%d,%d), want (%d,%d)", runner.versionCalls, runner.checkCalls, workers, workers)
	}
}

func TestNilCheckerAndContextFailClosed(t *testing.T) {
	var checker *Checker
	_, err := checker.Check(context.Background(), validInput())
	requireCode(t, err, ErrorInvalidInput)

	checker = newTestChecker(t, goodRunner())
	var nilContext context.Context
	_, err = checker.Check(nilContext, validInput())
	requireCode(t, err, ErrorInvalidInput)
}
