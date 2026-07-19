package executor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

const MaxOperationDuration = journal.MaxDeadline

// ReplayJournal is the public journal surface used by Service. In particular,
// Service never depends on journal frame or payload layout.
type ReplayJournal interface {
	Lookup(capability.SignedCapability) (journal.Outcome, error)
	Begin(capability.SignedCapability, time.Time, time.Time) (journal.Outcome, error)
	Complete(capability.SignedResult) (journal.TerminalSnapshot, bool, error)
}

// Config assembles the isolated executor's pure state machine. Socket/process
// ownership and Linux capability setup belong to a later cmd/OS adapter.
type Config struct {
	CapabilityVerifier capability.CapabilityVerifier
	ResultSigner       capability.ResultSigner
	Journal            ReplayJournal
	Runner             Runner
	DispatchKeyID      string
}

// Service serializes target-state decisions and mutations. This prevents two
// concurrently delivered capabilities in one executor process from observing
// the same absent state and racing each other into the owned set.
type Service struct {
	verifier      capability.CapabilityVerifier
	signer        capability.ResultSigner
	journal       ReplayJournal
	runner        Runner
	dispatchKeyID string
	clock         func() time.Time
	newResultID   func() (string, error)
	gate          chan struct{}
}

func New(config Config) (*Service, error) {
	if config.Journal == nil || config.Runner == nil || config.DispatchKeyID == "" ||
		config.DispatchKeyID != config.CapabilityVerifier.KeyID() ||
		config.CapabilityVerifier.ExecutorID() == "" {
		return nil, reject(ErrorConfiguration)
	}
	service := &Service{
		verifier: config.CapabilityVerifier, signer: config.ResultSigner,
		journal: config.Journal, runner: config.Runner, dispatchKeyID: config.DispatchKeyID,
		clock: time.Now, newResultID: newUUIDv4, gate: make(chan struct{}, 1),
	}
	service.gate <- struct{}{}
	return service, nil
}

func (s *Service) String() string   { return "isolated executor service [redacted]" }
func (s *Service) GoString() string { return s.String() }

// HandlePayload adapts the strict canonical IPC envelope to Process. Framing,
// one-request-per-connection enforcement, socket deadlines, and UDS-only
// listener ownership remain package ipc/cmd responsibilities.
func (s *Service) HandlePayload(ctx context.Context, payload []byte) ([]byte, error) {
	if s == nil || ctx == nil {
		return nil, reject(ErrorConfiguration)
	}
	envelope, err := ipc.DecodeRequestEnvelope(payload)
	if err != nil {
		return nil, reject(ErrorRequest)
	}
	signed := capability.NewUntrustedSignedCapability(
		s.dispatchKeyID,
		envelope.CapabilityJCS(),
		envelope.CapabilitySignature(),
		envelope.Artifact(),
	)
	var result capability.SignedResult
	if envelope.RecoveryOnly() {
		result, err = s.ProcessRecovery(ctx, signed)
	} else {
		result, err = s.Process(ctx, signed)
	}
	if err != nil {
		return nil, err
	}
	response, err := ipc.NewResponseEnvelope(result.CanonicalBytes(), result.Signature())
	if err != nil {
		return nil, reject(ErrorResult)
	}
	encoded, err := ipc.EncodeResponseEnvelope(response)
	if err != nil {
		return nil, reject(ErrorResult)
	}
	return encoded, nil
}

// ProcessRecovery accepts only an exact capability already known to the
// authenticated journal. Terminal history is replayed; started-only history
// performs fixed read-back recovery. Unseen capability bytes fail closed
// without freshness checks, Journal.Begin, or a mutation permit.
func (s *Service) ProcessRecovery(
	ctx context.Context,
	signed capability.SignedCapability,
) (capability.SignedResult, error) {
	if s == nil || ctx == nil || s.journal == nil || s.runner == nil {
		return capability.SignedResult{}, reject(ErrorConfiguration)
	}
	verified, err := s.verifier.Verify(signed)
	if err != nil {
		return capability.SignedResult{}, reject(ErrorCapability)
	}
	value := verified.Value()
	if !exactDigest(signed.ArtifactBytes(), value.ArtifactDigest) {
		return capability.SignedResult{}, reject(ErrorArtifact)
	}
	if value.OwnedSchemaDigest != nftvalidate.PinnedLiveSchemaDigest {
		return capability.SignedResult{}, reject(ErrorSchema)
	}
	if err := s.acquire(ctx); err != nil {
		return capability.SignedResult{}, err
	}
	defer s.release()
	outcome, err := s.journal.Lookup(signed)
	if err != nil {
		return capability.SignedResult{}, classifyJournal(err)
	}
	switch outcome.State() {
	case journal.StateTerminal:
		terminal, ok := outcome.Terminal()
		if !ok {
			return capability.SignedResult{}, reject(ErrorJournal)
		}
		return terminal.SignedResult(), nil
	case journal.StateStartedOnly:
		return s.recover(ctx, outcome)
	case journal.StateUnseen:
		return capability.SignedResult{}, reject(ErrorReplay)
	default:
		return capability.SignedResult{}, reject(ErrorJournal)
	}
}

// Process verifies one signed exact-artifact capability and returns one exact
// signed terminal result. Known terminal requests are returned before any
// freshness decision; known started-only requests enter read-back-only
// recovery and can never obtain a mutation Permit.
func (s *Service) Process(ctx context.Context, signed capability.SignedCapability) (capability.SignedResult, error) {
	if s == nil || ctx == nil || s.journal == nil || s.runner == nil {
		return capability.SignedResult{}, reject(ErrorConfiguration)
	}
	verified, err := s.verifier.Verify(signed)
	if err != nil {
		return capability.SignedResult{}, reject(ErrorCapability)
	}
	value := verified.Value()
	if !exactDigest(signed.ArtifactBytes(), value.ArtifactDigest) {
		return capability.SignedResult{}, reject(ErrorArtifact)
	}
	if value.OwnedSchemaDigest != nftvalidate.PinnedLiveSchemaDigest {
		return capability.SignedResult{}, reject(ErrorSchema)
	}
	if err := s.acquire(ctx); err != nil {
		return capability.SignedResult{}, err
	}
	defer s.release()

	outcome, err := s.journal.Lookup(signed)
	if err != nil {
		return capability.SignedResult{}, classifyJournal(err)
	}
	switch outcome.State() {
	case journal.StateTerminal:
		terminal, ok := outcome.Terminal()
		if !ok {
			return capability.SignedResult{}, reject(ErrorJournal)
		}
		return terminal.SignedResult(), nil
	case journal.StateStartedOnly:
		return s.recover(ctx, outcome)
	case journal.StateUnseen:
		return s.processUnseen(ctx, signed, verified)
	default:
		return capability.SignedResult{}, reject(ErrorJournal)
	}
}

func (s *Service) processUnseen(
	ctx context.Context,
	signed capability.SignedCapability,
	verified capability.VerifiedCapability,
) (capability.SignedResult, error) {
	value := verified.Value()
	receivedAt := s.now()
	if err := checkFreshValue(value, receivedAt); err != nil {
		return capability.SignedResult{}, err
	}
	deadlineAt, err := operationDeadline(ctx, receivedAt, value.ExpiresAt)
	if err != nil {
		return capability.SignedResult{}, err
	}
	// A relative timeout gives the privileged operation a monotonic process
	// bound even though the signed/journal timestamps use canonical UTC.
	operationCtx, cancel := context.WithTimeout(ctx, deadlineAt.Sub(receivedAt))
	defer cancel()

	inspection := inspectionFor(value)
	var preflight Observation
	if value.Operation == capability.OperationAdd || value.Operation == capability.OperationRevoke {
		preflight, err = s.inspect(operationCtx, inspection, 0)
		if err != nil {
			return capability.SignedResult{}, err
		}
		if preflight.State == capability.ReadbackMismatch || preflight.State == capability.ReadbackUnavailable {
			return capability.SignedResult{}, reject(ErrorTargetState)
		}
	}

	beginAt := s.now()
	if err := checkFreshValue(value, beginAt); err != nil {
		return capability.SignedResult{}, err
	}
	beginDeadline, err := operationDeadline(operationCtx, beginAt, value.ExpiresAt)
	if err != nil {
		return capability.SignedResult{}, err
	}
	outcome, err := s.journal.Begin(signed, beginAt, beginDeadline)
	if err != nil {
		return capability.SignedResult{}, classifyJournal(err)
	}
	switch outcome.State() {
	case journal.StateTerminal:
		terminal, ok := outcome.Terminal()
		if !ok {
			return capability.SignedResult{}, reject(ErrorJournal)
		}
		return terminal.SignedResult(), nil
	case journal.StateStartedOnly:
		return s.recover(operationCtx, outcome)
	case journal.StateNewStarted:
		permit, ok := outcome.Permit()
		if !ok || permit == nil {
			return capability.SignedResult{}, reject(ErrorJournal)
		}
		return s.execute(operationCtx, outcome, permit, preflight)
	default:
		return capability.SignedResult{}, reject(ErrorJournal)
	}
}

func (s *Service) acquire(ctx context.Context) error {
	if ctx.Err() != nil {
		return reject(ErrorDeadline)
	}
	select {
	case <-ctx.Done():
		return reject(ErrorDeadline)
	case <-s.gate:
		if ctx.Err() != nil {
			s.gate <- struct{}{}
			return reject(ErrorDeadline)
		}
		return nil
	}
}

func (s *Service) release() { s.gate <- struct{}{} }

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Millisecond) }

func checkFreshValue(value capability.Value, now time.Time) error {
	if value.Operation != capability.OperationAdd && value.Operation != capability.OperationRevoke &&
		value.Operation != capability.OperationInspect {
		return reject(ErrorCapability)
	}
	if now.IsZero() || now.Before(value.IssuedAt) || now.Before(value.NotBefore) || !now.Before(value.ExpiresAt) {
		return reject(ErrorFreshness)
	}
	return nil
}

func operationDeadline(ctx context.Context, now, expiresAt time.Time) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil {
		return time.Time{}, reject(ErrorDeadline)
	}
	deadline := now.Add(MaxOperationDuration)
	if expiresAt.Before(deadline) {
		deadline = expiresAt
	}
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline.UTC().Truncate(time.Millisecond)
	}
	deadline = deadline.UTC().Truncate(time.Millisecond)
	if !deadline.After(now) || deadline.Sub(now) > MaxOperationDuration {
		return time.Time{}, reject(ErrorDeadline)
	}
	return deadline, nil
}

func exactDigest(data []byte, expected string) bool {
	sum := sha256.Sum256(data)
	return expected == "sha256:"+hex.EncodeToString(sum[:])
}

func newUUIDv4() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func classifyJournal(err error) error {
	if journalError, ok := err.(*journal.Error); ok && journalError.Code == journal.ErrorConflict {
		return reject(ErrorReplay)
	}
	return reject(ErrorJournal)
}
