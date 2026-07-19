package nftrunner

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/executor"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

const (
	// MaxProcessOutput bounds stdout and stderr together. A read-back larger
	// than this value is not partially interpreted because omitted elements
	// could change target membership.
	MaxProcessOutput = 64 * 1024
	// MaxOperationDuration is a defense-in-depth process bound. The executor
	// supplies an equal or shorter deadline, but direct adapter use cannot
	// accidentally create an unbounded privileged subprocess.
	MaxOperationDuration = 2 * time.Second

	maxMutationBytes = nftvalidate.MaxCandidateBytes
)

var _ executor.Runner = (*Runner)(nil)

// Runner is immutable after construction and safe for concurrent use. The
// executor currently serializes mutations, but the adapter does not depend on
// that implementation detail.
type Runner struct {
	run processFunc
}

func (r *Runner) String() string   { return "fixed Linux nft runner [redacted]" }
func (r *Runner) GoString() string { return r.String() }

// Mutate invokes only the executor's closed mutation value. It returns a
// bounded exit classification and never process output.
func (r *Runner) Mutate(ctx context.Context, mutation executor.Mutation) (executor.MutationOutcome, error) {
	return r.mutate(ctx, mutation.Operation(), mutation.Path(), mutation.Arguments(), mutation.Stdin())
}

func (r *Runner) mutate(
	ctx context.Context,
	operation capability.Operation,
	path string,
	arguments []string,
	stdin []byte,
) (executor.MutationOutcome, error) {
	defaultOutcome := executor.MutationOutcome{ExitClass: capability.NFTExitNonzero}
	if r == nil || r.run == nil || ctx == nil || ctx.Err() != nil ||
		path != executor.FixedNFTBinaryPath ||
		!sameStrings(arguments, mutationArguments[:]) ||
		(operation != capability.OperationAdd && operation != capability.OperationRevoke) ||
		!validMutationEnvelope(stdin) {
		if ctx != nil && ctx.Err() != nil {
			return contextMutationFailure(ctx)
		}
		return defaultOutcome, reject(ErrorInvalidInput)
	}

	request := processRequest{kind: processMutation, stdin: append([]byte(nil), stdin...)}
	operationCtx, cancel := context.WithTimeout(ctx, MaxOperationDuration)
	defer cancel()
	result, runErr := r.run(operationCtx, request)
	if err := contextFailure(operationCtx); err != nil {
		return executor.MutationOutcome{ExitClass: capability.NFTExitTimeout}, err
	}
	if result.overflow || outputTooLarge(result) {
		return defaultOutcome, reject(ErrorOutputLimit)
	}
	if result.exitStatus == 0 && !runErr && !result.signaled {
		return executor.MutationOutcome{ExitClass: capability.NFTExitSuccess}, nil
	}
	if result.signaled {
		return executor.MutationOutcome{ExitClass: capability.NFTExitSignaled}, reject(ErrorProcessSignaled)
	}
	if result.exitStatus > 0 {
		return defaultOutcome, reject(ErrorProcessNonzero)
	}
	return defaultOutcome, reject(ErrorProcessUnavailable)
}

// Inspect invokes only the executor's fixed owned-set query and returns a
// bounded projection. The set handle is deliberately ignored because nft's
// exact list-set JSON does not expose a per-element handle.
func (r *Runner) Inspect(ctx context.Context, inspection executor.Inspection) (executor.Observation, error) {
	return r.inspect(ctx, inspectInput{
		path:              inspection.Path(),
		arguments:         inspection.Arguments(),
		targetIPv4:        inspection.TargetIPv4(),
		ownedSchemaDigest: inspection.OwnedSchemaDigest(),
	})
}

type inspectInput struct {
	path              string
	arguments         []string
	targetIPv4        string
	ownedSchemaDigest string
}

func (r *Runner) inspect(ctx context.Context, input inspectInput) (executor.Observation, error) {
	if r == nil || r.run == nil || ctx == nil || ctx.Err() != nil ||
		input.path != executor.FixedNFTBinaryPath ||
		!sameStrings(input.arguments, inspectArguments[:]) ||
		input.ownedSchemaDigest != nftvalidate.PinnedLiveSchemaDigest ||
		!canonicalIPv4(input.targetIPv4) {
		if ctx != nil && ctx.Err() != nil {
			return executor.Observation{}, contextFailure(ctx)
		}
		return executor.Observation{}, reject(ErrorInvalidInput)
	}

	operationCtx, cancel := context.WithTimeout(ctx, MaxOperationDuration)
	defer cancel()
	result, runErr := r.run(operationCtx, processRequest{kind: processInspect})
	if err := contextFailure(operationCtx); err != nil {
		return executor.Observation{}, err
	}
	if result.overflow || outputTooLarge(result) {
		return executor.Observation{}, reject(ErrorOutputLimit)
	}
	if runErr || result.exitStatus != 0 || result.signaled || len(result.stderr) != 0 {
		switch {
		case result.signaled:
			return executor.Observation{}, reject(ErrorProcessSignaled)
		case result.exitStatus > 0:
			return executor.Observation{}, reject(ErrorProcessNonzero)
		default:
			return executor.Observation{}, reject(ErrorProcessUnavailable)
		}
	}
	return parseReadback(result.stdout, input.targetIPv4, input.ownedSchemaDigest)
}

func contextMutationFailure(ctx context.Context) (executor.MutationOutcome, error) {
	err := contextFailure(ctx)
	return executor.MutationOutcome{ExitClass: capability.NFTExitTimeout}, err
}

func contextFailure(ctx context.Context) error {
	if ctx == nil {
		return reject(ErrorInvalidInput)
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return reject(ErrorTimeout)
	case errors.Is(ctx.Err(), context.Canceled):
		return reject(ErrorCancelled)
	default:
		return nil
	}
}

func validMutationEnvelope(value []byte) bool {
	if len(value) == 0 || len(value) > maxMutationBytes || !utf8.Valid(value) ||
		value[len(value)-1] != '\n' || bytes.Count(value, []byte{'\n'}) != 1 {
		return false
	}
	for index, current := range value {
		if current > 0x7e || current == 0 || current == '\r' || current == '\t' ||
			(current == '\n' && index != len(value)-1) ||
			(current < 0x20 && current != '\n') {
			return false
		}
	}
	return true
}

func canonicalIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range right {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func outputTooLarge(result processResult) bool {
	return len(result.stdout) > MaxProcessOutput ||
		len(result.stderr) > MaxProcessOutput-len(result.stdout)
}
