package nftcheck

import (
	"bytes"
	"context"
	"errors"
	"time"
	"unicode/utf8"
)

// Checker is immutable after construction and safe for concurrent use when
// its ProcessRunner implementation is safe for concurrent use.
type Checker struct {
	runner          ProcessRunner
	expectedVersion string
	timeout         time.Duration
}

// New constructs a checker pinned to one normalized nft version, for example
// "nftables v1.0.9". The production gate timeout is always GateTimeout.
func New(runner ProcessRunner, expectedVersion string) (*Checker, error) {
	if runner == nil || !expectedVersionPattern.MatchString(expectedVersion) {
		return nil, reject(ErrorInvalidInput)
	}
	return &Checker{
		runner:          runner,
		expectedVersion: expectedVersion,
		timeout:         GateTimeout,
	}, nil
}

// Check performs digest and pinned-base validation before starting either
// fixed nft subprocess. The returned Evidence is sanitized on success and all
// failures; callers must only treat a nil error as a passed syntax gate.
func (c *Checker) Check(ctx context.Context, input Input) (Evidence, error) {
	evidence := initialEvidence()
	if c == nil || c.runner == nil || ctx == nil {
		return evidence, reject(ErrorInvalidInput)
	}
	if err := contextFailure(ctx); err != nil {
		return evidence, err
	}

	canonical := append([]byte(nil), input.CanonicalBytes...)
	baseContract := append([]byte(nil), input.BaseContract...)
	if !validCanonicalEnvelope(canonical) {
		return evidence, reject(ErrorCandidateInvalid)
	}
	if !digestPattern.MatchString(input.CanonicalDigest) {
		return evidence, reject(ErrorCandidateDigest)
	}
	evidence.CanonicalDigest = digest(canonical)
	if evidence.CanonicalDigest != input.CanonicalDigest {
		return evidence, reject(ErrorCandidateMismatch)
	}
	if input.BaseContractDigest != PinnedBaseContractDigest ||
		!digestPattern.MatchString(input.BaseContractDigest) {
		return evidence, reject(ErrorBaseDigest)
	}
	if len(baseContract) == 0 || len(baseContract) > MaxBaseContractBytes {
		return evidence, reject(ErrorBaseContract)
	}
	evidence.BaseContractDigest = digest(baseContract)
	if evidence.BaseContractDigest != PinnedBaseContractDigest {
		return evidence, reject(ErrorBaseContract)
	}

	gateCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	versionResult, runErr := c.runner.Version(gateCtx)
	populateVersionEvidence(&evidence, versionResult)
	if err := validateProcessResult(gateCtx, versionResult, runErr, versionArguments, true); err != nil {
		return evidence, err
	}
	version, ok := normalizeVersion(versionResult.Stdout, versionResult.Stderr)
	if !ok {
		return evidence, reject(ErrorVersionInvalid)
	}
	evidence.NFTVersion = version
	if version != c.expectedVersion {
		return evidence, reject(ErrorVersionMismatch)
	}

	// Keep the validated copy immutable and give the runner a separate copy.
	checkInput := append([]byte(nil), canonical...)
	checkResult, runErr := c.runner.Check(gateCtx, checkInput)
	populateSyntaxEvidence(&evidence, checkResult)
	if err := validateProcessResult(gateCtx, checkResult, runErr, checkArguments, false); err != nil {
		return evidence, err
	}
	// A runner must not be able to turn mutable input into a different passed
	// artifact without detection.
	if digest(checkInput) != input.CanonicalDigest || digest(canonical) != input.CanonicalDigest {
		return evidence, reject(ErrorCandidateMismatch)
	}
	return evidence, nil
}

func validCanonicalEnvelope(value []byte) bool {
	if len(value) == 0 || len(value) > MaxCandidateBytes || !utf8.Valid(value) ||
		bytes.HasPrefix(value, []byte{0xef, 0xbb, 0xbf}) || value[len(value)-1] != '\n' {
		return false
	}
	for index, current := range value {
		if current > 0x7e || current == 0 || current == '\r' || current == '\t' ||
			(current == '\n' && index != len(value)-1) || (current < 0x20 && current != '\n') {
			return false
		}
	}
	return true
}

func validateProcessResult(
	ctx context.Context,
	result ProcessResult,
	runErr error,
	expectedArguments []string,
	versionCommand bool,
) error {
	if err := contextFailure(ctx); err != nil {
		return err
	}
	if result.OutputOverflow || outputTooLarge(result.Stdout, result.Stderr) {
		return reject(ErrorOutputLimit)
	}
	if result.Path != FixedNFTBinaryPath || !sameArguments(result.Arguments, expectedArguments) {
		return reject(ErrorInvocationMismatch)
	}
	if result.ExitStatus < 0 {
		return reject(ErrorRunnerUnavailable)
	}
	if result.ExitStatus > 0 {
		if versionCommand {
			return reject(ErrorVersionCommand)
		}
		return reject(ErrorSyntaxRejected)
	}
	if runErr != nil {
		return reject(ErrorRunnerUnavailable)
	}
	return nil
}

func contextFailure(ctx context.Context) error {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return reject(ErrorTimeout)
	case errors.Is(ctx.Err(), context.Canceled):
		return reject(ErrorCancelled)
	default:
		return nil
	}
}

func outputTooLarge(stdout, stderr []byte) bool {
	return len(stdout) > MaxProcessOutput ||
		len(stderr) > MaxProcessOutput-len(stdout)
}

func normalizeVersion(stdout, stderr []byte) (string, bool) {
	if len(stderr) != 0 || !utf8.Valid(stdout) {
		return "", false
	}
	matches := observedVersionPattern.FindSubmatch(stdout)
	if len(matches) != 2 {
		return "", false
	}
	return "nftables v" + string(matches[1]), true
}

func populateVersionEvidence(evidence *Evidence, result ProcessResult) {
	evidence.VersionExitStatus = result.ExitStatus
	if !result.OutputOverflow && !outputTooLarge(result.Stdout, result.Stderr) {
		evidence.VersionOutputDigest = outputDigest(result.Stdout, result.Stderr)
		evidence.VersionOutputByteCount = uint32(len(result.Stdout) + len(result.Stderr))
	}
}

func populateSyntaxEvidence(evidence *Evidence, result ProcessResult) {
	evidence.SyntaxExitStatus = result.ExitStatus
	if !result.OutputOverflow && !outputTooLarge(result.Stdout, result.Stderr) {
		evidence.SyntaxOutputDigest = outputDigest(result.Stdout, result.Stderr)
		evidence.SyntaxOutputByteCount = uint32(len(result.Stdout) + len(result.Stderr))
	}
}
