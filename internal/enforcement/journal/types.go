package journal

import (
	"sync/atomic"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
)

const (
	SchemaRecordV1 = "executor-journal-record-v1"

	MaxJournalBytes = 64 * 1024 * 1024
	MaxPayloadBytes = 32 * 1024
	MaxFrameBytes   = frameHeaderBytes + MaxPayloadBytes + checksumBytes
	MaxDeadline     = 2 * time.Second
)

// CapabilityVerifier is injected so startup recovery reauthenticates every
// persisted capability using the executor's configured dispatcher public key.
type CapabilityVerifier interface {
	Verify(capability.SignedCapability) (capability.VerifiedCapability, error)
	KeyID() string
}

// ResultVerifier is injected so startup recovery reauthenticates every exact
// terminal result with the executor result public key and identity.
type ResultVerifier interface {
	Verify(capability.SignedResult) (capability.VerifiedResult, error)
	KeyID() string
	ExecutorID() string
}

// Syncer permits deterministic failure testing of both durability barriers.
// Production callers should leave Options.Syncer nil.
type Syncer interface {
	SyncFile(file FileSyncTarget) error
	SyncDirectory(directory FileSyncTarget) error
}

// FileSyncTarget exposes only the durability operation needed by Syncer.
type FileSyncTarget interface{ Sync() error }

// Options configures one exclusively locked executor journal.
type Options struct {
	Path               string
	CapabilityVerifier CapabilityVerifier
	ResultVerifier     ResultVerifier
	Syncer             Syncer
}

// LookupState distinguishes a never-seen request from a new durable claim,
// started-only recovery, and a terminal exact retry.
type LookupState string

const (
	StateUnseen      LookupState = "unseen"
	StateNewStarted  LookupState = "new_started"
	StateStartedOnly LookupState = "started_only"
	StateTerminal    LookupState = "terminal"
)

// StartedSnapshot contains replay metadata but intentionally contains no
// command, capability, or signature bytes.
type StartedSnapshot struct {
	Sequence         uint64
	CapabilityID     string
	CapabilityDigest string
	ArtifactDigest   string
	Operation        capability.Operation
	ActionID         string
	TargetIPv4       string
	ReceivedAt       time.Time
	DeadlineAt       time.Time
}

// TerminalSnapshot exposes the exact signed result for idempotent response
// replay. Its String forms are redacted.
type TerminalSnapshot struct {
	sequence        uint64
	startedSequence uint64
	resultDigest    string
	signed          capability.SignedResult
}

func (s TerminalSnapshot) Sequence() uint64        { return s.sequence }
func (s TerminalSnapshot) StartedSequence() uint64 { return s.startedSequence }
func (s TerminalSnapshot) ResultDigest() string    { return s.resultDigest }
func (s TerminalSnapshot) SignedResult() capability.SignedResult {
	return capability.NewUntrustedSignedResult(s.signed.KeyID(), s.signed.ExecutorID(), s.signed.CanonicalBytes(), s.signed.Signature())
}
func (s TerminalSnapshot) String() string   { return "executor journal terminal [redacted]" }
func (s TerminalSnapshot) GoString() string { return s.String() }

// Outcome is an immutable Begin or Lookup result. Permit is present only for
// StateNewStarted; Recovery is present only for StateStartedOnly.
type Outcome struct {
	state    LookupState
	started  StartedSnapshot
	terminal *TerminalSnapshot
	permit   *Permit
	recovery *Recovery
}

func (o Outcome) State() LookupState       { return o.state }
func (o Outcome) Started() StartedSnapshot { return o.started }
func (o Outcome) Terminal() (TerminalSnapshot, bool) {
	if o.terminal == nil {
		return TerminalSnapshot{}, false
	}
	return cloneTerminal(*o.terminal), true
}
func (o Outcome) Permit() (*Permit, bool) {
	if o.permit == nil {
		return nil, false
	}
	return o.permit, true
}
func (o Outcome) Recovery() (*Recovery, bool) {
	if o.recovery == nil {
		return nil, false
	}
	return o.recovery, true
}
func (o Outcome) String() string   { return "executor journal outcome: " + string(o.state) }
func (o Outcome) GoString() string { return o.String() }

// Permit is returned only after a never-seen capability has passed freshness
// checks and its started frame has crossed both fsync barriers. Its Take*
// methods are single-use even under concurrency.
type Permit struct {
	verified capability.VerifiedCapability
	deadline time.Time
	used     atomic.Bool
}

func (p *Permit) Value() capability.Value {
	if p == nil {
		return capability.Value{}
	}
	return p.verified.Value()
}

func (p *Permit) TakeAddAt(now time.Time) (capability.ExecutableAdd, error) {
	if p == nil || p.verified.Value().Operation != capability.OperationAdd {
		return capability.ExecutableAdd{}, reject(ErrorOperation)
	}
	if err := p.checkAndUse(now); err != nil {
		return capability.ExecutableAdd{}, err
	}
	executable, err := p.verified.AddAt(now)
	if err != nil {
		return capability.ExecutableAdd{}, reject(ErrorFreshness)
	}
	return executable, nil
}

func (p *Permit) TakeRevokeAt(now time.Time) (capability.ExecutableRevoke, error) {
	if p == nil || p.verified.Value().Operation != capability.OperationRevoke {
		return capability.ExecutableRevoke{}, reject(ErrorOperation)
	}
	if err := p.checkAndUse(now); err != nil {
		return capability.ExecutableRevoke{}, err
	}
	executable, err := p.verified.RevokeAt(now)
	if err != nil {
		return capability.ExecutableRevoke{}, reject(ErrorFreshness)
	}
	return executable, nil
}

func (p *Permit) TakeInspectAt(now time.Time) (capability.ExecutableInspect, error) {
	if p == nil || p.verified.Value().Operation != capability.OperationInspect {
		return capability.ExecutableInspect{}, reject(ErrorOperation)
	}
	if err := p.checkAndUse(now); err != nil {
		return capability.ExecutableInspect{}, err
	}
	executable, err := p.verified.InspectAt(now)
	if err != nil {
		return capability.ExecutableInspect{}, reject(ErrorFreshness)
	}
	return executable, nil
}

func (p *Permit) checkAndUse(now time.Time) error {
	now = now.UTC()
	if !now.Before(p.deadline) {
		return reject(ErrorFreshness)
	}
	if !p.used.CompareAndSwap(false, true) {
		return reject(ErrorPermitUsed)
	}
	return nil
}

// SignResult binds a result to the verified request without releasing a second
// executable capability.
func (p *Permit) SignResult(signer capability.ResultSigner, checked capability.CheckedResult) (capability.SignedResult, error) {
	if p == nil {
		return capability.SignedResult{}, reject(ErrorOperation)
	}
	return signer.SignFor(p.verified, checked)
}

func (p *Permit) String() string   { return "executor journal permit [redacted]" }
func (p *Permit) GoString() string { return p.String() }

// Recovery can bind a result after startup read-back. It has no method that
// releases add, revoke, or inspect execution authority.
type Recovery struct{ verified capability.VerifiedCapability }

func (r *Recovery) Value() capability.Value {
	if r == nil {
		return capability.Value{}
	}
	return r.verified.Value()
}

// ExpectedAddTTLSeconds returns the verified upper bound needed to classify a
// started-only add through read-back. It exposes no mutation method or bytes.
func (r *Recovery) ExpectedAddTTLSeconds() (uint32, bool) {
	if r == nil {
		return 0, false
	}
	return r.verified.ExpectedAddTTLSeconds()
}

func (r *Recovery) SignResult(signer capability.ResultSigner, checked capability.CheckedResult) (capability.SignedResult, error) {
	if r == nil {
		return capability.SignedResult{}, reject(ErrorOperation)
	}
	result := checked.Value()
	switch r.verified.Value().Operation {
	case capability.OperationAdd:
		if result.Classification != capability.ClassificationRecoveredActive &&
			result.Classification != capability.ClassificationFailed &&
			result.Classification != capability.ClassificationIndeterminate {
			return capability.SignedResult{}, reject(ErrorOperation)
		}
		if result.NFTExitClass != nil && *result.NFTExitClass != capability.NFTExitNotInvoked {
			return capability.SignedResult{}, reject(ErrorOperation)
		}
	case capability.OperationRevoke:
		if result.Classification != capability.ClassificationRevoked &&
			result.Classification != capability.ClassificationFailed &&
			result.Classification != capability.ClassificationIndeterminate {
			return capability.SignedResult{}, reject(ErrorOperation)
		}
		if result.NFTExitClass != nil && *result.NFTExitClass != capability.NFTExitNotInvoked {
			return capability.SignedResult{}, reject(ErrorOperation)
		}
	case capability.OperationInspect:
		// Inspect is intrinsically read-only and remains constrained by the
		// capability result schema and exact request binding.
	default:
		return capability.SignedResult{}, reject(ErrorOperation)
	}
	return signer.SignFor(r.verified, checked)
}

func (r *Recovery) String() string   { return "executor journal recovery [redacted]" }
func (r *Recovery) GoString() string { return r.String() }

func cloneTerminal(input TerminalSnapshot) TerminalSnapshot {
	input.signed = capability.NewUntrustedSignedResult(input.signed.KeyID(), input.signed.ExecutorID(), input.signed.CanonicalBytes(), input.signed.Signature())
	return input
}
