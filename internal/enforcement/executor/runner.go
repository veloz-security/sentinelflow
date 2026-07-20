package executor

import (
	"context"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

const (
	// FixedNFTBinaryPath is inherited from the syntax-check boundary. Runner
	// implementations MUST execute this absolute path directly, never through
	// a shell or PATH lookup.
	FixedNFTBinaryPath = nftcheck.FixedNFTBinaryPath
)

var (
	fixedMutationArguments = [...]string{"-f", "-"}
	fixedInspectArguments  = [...]string{"--json", "list", "set", nftvalidate.Family, nftvalidate.Table, nftvalidate.BlacklistSet}
)

// Mutation is constructed only after a durable journal Permit releases one
// operation-specific artifact. There is no public constructor and no caller-
// supplied path or argument field.
type Mutation struct {
	operation capability.Operation
	stdin     []byte
}

func (m Mutation) Operation() capability.Operation { return m.operation }
func (m Mutation) Path() string                    { return FixedNFTBinaryPath }
func (m Mutation) Arguments() []string {
	return append([]string(nil), fixedMutationArguments[:]...)
}
func (m Mutation) Stdin() []byte { return append([]byte(nil), m.stdin...) }
func (m Mutation) String() string {
	return "executor fixed nft mutation [redacted]"
}
func (m Mutation) GoString() string { return m.String() }

// Inspection is a fixed, read-only set query. It cannot carry stdin, a
// mutation operation, or caller-selected arguments.
type Inspection struct {
	actionID          string
	targetIPv4        string
	originalAddDigest string
	ownedSchemaDigest string
}

func (i Inspection) ActionID() string          { return i.actionID }
func (i Inspection) TargetIPv4() string        { return i.targetIPv4 }
func (i Inspection) OriginalAddDigest() string { return i.originalAddDigest }
func (i Inspection) OwnedSchemaDigest() string { return i.ownedSchemaDigest }
func (i Inspection) Path() string              { return FixedNFTBinaryPath }
func (i Inspection) Arguments() []string {
	return append([]string(nil), fixedInspectArguments[:]...)
}
func (i Inspection) String() string   { return "executor fixed nft inspection [redacted]" }
func (i Inspection) GoString() string { return i.String() }

// MutationOutcome contains only the bounded process classification needed by
// execution-result-v2. Raw stdout, stderr, argv, environment, and command text
// are intentionally not representable.
type MutationOutcome struct {
	ExitClass capability.NFTExitClass
}

// Observation is the already parsed, bounded projection of the owned set.
// The exact `nft --json list set` response exposes the set handle but not an
// element handle, so active entries are identified by their exact canonical
// IPv4 value and positive remaining native timeout. A set handle must never be
// substituted for an element handle in an execution result.
type Observation struct {
	State               capability.ReadbackState
	TargetIPv4          string
	OwnedSchemaDigest   string
	RemainingTTLSeconds uint64

	// The Runner cannot provide lifecycle timestamps. Service writes these
	// private fields immediately around its fixed Runner.Inspect call so the
	// executor, rather than an OS adapter, binds the read-back window.
	readbackStartedAt   time.Time
	readbackCompletedAt time.Time
}

// Runner is the entire OS-facing authority of Service. Mutate MUST invoke
// exactly Mutation.Path/Arguments with Mutation.Stdin as stdin, no shell, a
// cleared/minimal environment, bounded output, and the supplied context.
// Inspect MUST invoke exactly Inspection.Path/Arguments with no stdin and
// return only a parsed Observation. Implementations must not log artifacts or
// process output.
type Runner interface {
	Mutate(context.Context, Mutation) (MutationOutcome, error)
	Inspect(context.Context, Inspection) (Observation, error)
}

func inspectionFor(value capability.Value) Inspection {
	return Inspection{
		actionID:          value.ActionID,
		targetIPv4:        value.TargetIPv4,
		originalAddDigest: value.OriginalAddDigest,
		ownedSchemaDigest: value.OwnedSchemaDigest,
	}
}

func validateObservation(observation Observation, expected Inspection, maximumTTL uint64) (Observation, bool) {
	if observation.TargetIPv4 != expected.targetIPv4 ||
		observation.OwnedSchemaDigest != expected.ownedSchemaDigest {
		return mismatchObservation(expected), false
	}
	switch observation.State {
	case capability.ReadbackActive:
		if observation.RemainingTTLSeconds == 0 ||
			observation.RemainingTTLSeconds > uint64(nftvalidate.MaxTTLSeconds) ||
			(maximumTTL != 0 && observation.RemainingTTLSeconds > maximumTTL) {
			return mismatchObservation(expected), false
		}
	case capability.ReadbackAbsent, capability.ReadbackMismatch, capability.ReadbackUnavailable:
		if observation.RemainingTTLSeconds != 0 {
			return mismatchObservation(expected), false
		}
	default:
		return mismatchObservation(expected), false
	}
	return observation, true
}

func mismatchObservation(expected Inspection) Observation {
	return Observation{
		State:             capability.ReadbackMismatch,
		TargetIPv4:        expected.targetIPv4,
		OwnedSchemaDigest: expected.ownedSchemaDigest,
	}
}
