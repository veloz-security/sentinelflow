package executor

import (
	"context"
	"errors"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
)

type resultAuthority interface {
	Value() capability.Value
	SignResult(capability.ResultSigner, capability.CheckedResult) (capability.SignedResult, error)
}

func (s *Service) execute(
	ctx context.Context,
	outcome journal.Outcome,
	permit *journal.Permit,
	preflight Observation,
) (capability.SignedResult, error) {
	started := outcome.Started()
	value := permit.Value()
	now := s.now()
	switch value.Operation {
	case capability.OperationAdd:
		executable, err := permit.TakeAddAt(now)
		if err != nil {
			return s.finish(ctx, started, permit, terminalFailure(value, capability.NFTExitNotInvoked,
				preflight, capability.ResultErrorDeadlineExceeded))
		}
		if preflight.State == capability.ReadbackActive {
			// Consume and journal the valid one-shot capability, but do not invoke
			// nft or refresh the already active target.
			return s.finish(ctx, started, permit, terminalFailure(value, capability.NFTExitNotInvoked,
				preflight, capability.ResultErrorTargetExists))
		}
		mutation := Mutation{operation: capability.OperationAdd, stdin: executable.CanonicalCommand()}
		outcome, runErr := s.runner.Mutate(ctx, mutation)
		exit := classifyMutation(ctx, outcome, runErr)
		observation, inspectErr := s.inspect(ctx, inspectionFor(value), uint64(executable.TTLSeconds()))
		result := addResult(value, exit, observation, inspectErr)
		return s.finish(ctx, started, permit, result)
	case capability.OperationRevoke:
		executable, err := permit.TakeRevokeAt(now)
		if err != nil {
			return s.finish(ctx, started, permit, terminalFailure(value, capability.NFTExitNotInvoked,
				preflight, capability.ResultErrorDeadlineExceeded))
		}
		if preflight.State == capability.ReadbackAbsent {
			return s.finish(ctx, started, permit, revokedResult(value, capability.NFTExitNotInvoked))
		}
		mutation := Mutation{operation: capability.OperationRevoke, stdin: executable.CanonicalDelete()}
		outcome, runErr := s.runner.Mutate(ctx, mutation)
		exit := classifyMutation(ctx, outcome, runErr)
		observation, inspectErr := s.inspect(ctx, inspectionFor(value), 0)
		result := revokeResult(value, exit, observation, inspectErr)
		return s.finish(ctx, started, permit, result)
	case capability.OperationInspect:
		if _, err := permit.TakeInspectAt(now); err != nil {
			return s.finish(ctx, started, permit, terminalFailure(value, capability.NFTExitNotInvoked,
				unavailableObservation(inspectionFor(value)), capability.ResultErrorDeadlineExceeded))
		}
		observation, inspectErr := s.inspect(ctx, inspectionFor(value), 0)
		result := inspectResult(ctx, value, observation, inspectErr)
		return s.finish(ctx, started, permit, result)
	default:
		return capability.SignedResult{}, reject(ErrorCapability)
	}
}

// recover has no path to Permit.TakeAddAt or Permit.TakeRevokeAt. It performs
// one fixed read-back and signs only a recovery classification.
func (s *Service) recover(ctx context.Context, outcome journal.Outcome) (capability.SignedResult, error) {
	recovery, ok := outcome.Recovery()
	if !ok || recovery == nil {
		return capability.SignedResult{}, reject(ErrorJournal)
	}
	started := outcome.Started()
	value := recovery.Value()
	recoveryStartedAt := s.now()
	recoveryDeadlineAt, err := operationDeadline(ctx, recoveryStartedAt, recoveryStartedAt.Add(MaxOperationDuration))
	if err != nil {
		return capability.SignedResult{}, err
	}
	recoveryCtx, cancel := context.WithTimeout(ctx, recoveryDeadlineAt.Sub(recoveryStartedAt))
	defer cancel()
	maximumTTL := uint64(0)
	if value.Operation == capability.OperationAdd {
		expectedTTL, ok := recovery.ExpectedAddTTLSeconds()
		if !ok || expectedTTL == 0 {
			return capability.SignedResult{}, reject(ErrorJournal)
		}
		maximumTTL = uint64(expectedTTL)
	}
	observation, inspectErr := s.inspect(recoveryCtx, inspectionFor(value), maximumTTL)
	var result capability.Result
	switch value.Operation {
	case capability.OperationAdd:
		result = recoveredAddResult(value, observation, inspectErr)
	case capability.OperationRevoke:
		result = recoveredRevokeResult(value, observation, inspectErr)
	case capability.OperationInspect:
		result = inspectResult(recoveryCtx, value, observation, inspectErr)
	default:
		return capability.SignedResult{}, reject(ErrorCapability)
	}
	// Recovery attests the actual read-back window, even after capability
	// expiry. The Recovery type cannot release mutation authority, while the
	// original journal sequence still binds the fresh started attempt.
	result.StartedAt = recoveryStartedAt
	result.CompletedAt = s.now()
	if recoveryCtx.Err() != nil || result.CompletedAt.After(recoveryDeadlineAt) {
		result.Classification = capability.ClassificationIndeterminate
		result.ErrorCode = capability.ResultErrorDeadlineExceeded
	}
	return s.finishPrepared(started, recovery, result)
}

func (s *Service) inspect(ctx context.Context, request Inspection, maximumTTL uint64) (Observation, error) {
	observation, err := s.runner.Inspect(ctx, request)
	if err != nil {
		return unavailableObservation(request), reject(classifyRunnerContext(ctx))
	}
	checked, valid := validateObservation(observation, request, maximumTTL)
	if !valid {
		return checked, reject(ErrorTargetState)
	}
	return checked, nil
}

func unavailableObservation(request Inspection) Observation {
	return Observation{
		State:             capability.ReadbackUnavailable,
		TargetIPv4:        request.targetIPv4,
		OwnedSchemaDigest: request.ownedSchemaDigest,
	}
}

func classifyMutation(ctx context.Context, outcome MutationOutcome, err error) capability.NFTExitClass {
	if ctx != nil && (errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled)) {
		return capability.NFTExitTimeout
	}
	switch outcome.ExitClass {
	case capability.NFTExitSuccess:
		if err == nil {
			return capability.NFTExitSuccess
		}
		return capability.NFTExitNonzero
	case capability.NFTExitNonzero, capability.NFTExitTimeout, capability.NFTExitSignaled:
		return outcome.ExitClass
	default:
		return capability.NFTExitNonzero
	}
}

func classifyRunnerContext(ctx context.Context) ErrorCode {
	if ctx != nil && (errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled)) {
		return ErrorDeadline
	}
	return ErrorRunner
}

func (s *Service) finish(
	ctx context.Context,
	started journal.StartedSnapshot,
	authority resultAuthority,
	result capability.Result,
) (capability.SignedResult, error) {
	result.StartedAt = started.ReceivedAt
	result.CompletedAt = s.now()
	if (ctx != nil && ctx.Err() != nil) || result.CompletedAt.After(started.DeadlineAt) {
		// A runner that ignores cancellation cannot turn a late mutation or
		// read-back into success. Preserve the observed state but attest only an
		// indeterminate, deadline-exceeded outcome.
		result.Classification = capability.ClassificationIndeterminate
		result.ErrorCode = capability.ResultErrorDeadlineExceeded
	}
	return s.finishPrepared(started, authority, result)
}

func (s *Service) finishPrepared(
	started journal.StartedSnapshot,
	authority resultAuthority,
	result capability.Result,
) (capability.SignedResult, error) {
	identifier, err := s.newResultID()
	if err != nil {
		return capability.SignedResult{}, reject(ErrorResult)
	}
	value := authority.Value()
	result.ResultID = identifier
	result.CapabilityID = value.CapabilityID
	result.CapabilityDigest = started.CapabilityDigest
	result.Operation = value.Operation
	result.ActionID = value.ActionID
	result.ArtifactDigest = value.ArtifactDigest
	result.TargetIPv4 = value.TargetIPv4
	result.OwnedSchemaDigest = value.OwnedSchemaDigest
	result.JournalSequence = started.Sequence
	checked, err := capability.CheckResult(result)
	if err != nil {
		return capability.SignedResult{}, reject(ErrorResult)
	}
	signed, err := authority.SignResult(s.signer, checked)
	if err != nil {
		return capability.SignedResult{}, reject(ErrorResultSigning)
	}
	terminal, appended, err := s.journal.Complete(signed)
	if err != nil {
		return capability.SignedResult{}, reject(ErrorResultDurability)
	}
	if !appended {
		return terminal.SignedResult(), nil
	}
	return signed, nil
}

func baseResult(value capability.Value) capability.Result {
	return capability.Result{
		Operation: value.Operation, ReadbackState: capability.ReadbackUnavailable,
		Classification: capability.ClassificationIndeterminate, ErrorCode: capability.ResultErrorIndeterminate,
	}
}

func addResult(value capability.Value, exit capability.NFTExitClass, observation Observation, inspectErr error) capability.Result {
	result := baseResult(value)
	result.NFTExitClass = pointer(exit)
	applyObservation(&result, observation)
	switch {
	case exit == capability.NFTExitSuccess && inspectErr == nil && observation.State == capability.ReadbackActive:
		result.Classification = capability.ClassificationApplied
		result.ErrorCode = capability.ResultErrorNone
	case observation.State == capability.ReadbackMismatch:
		result.Classification = capability.ClassificationIndeterminate
		result.ErrorCode = capability.ResultErrorReadbackMismatch
	case inspectErr != nil || observation.State == capability.ReadbackUnavailable:
		result.Classification = capability.ClassificationIndeterminate
		result.ErrorCode = capability.ResultErrorReadbackFailed
	case observation.State == capability.ReadbackActive && exit != capability.NFTExitSuccess:
		result.Classification = capability.ClassificationIndeterminate
		if exit == capability.NFTExitTimeout {
			result.ErrorCode = capability.ResultErrorDeadlineExceeded
		} else {
			result.ErrorCode = capability.ResultErrorNFTFailed
		}
	case exit == capability.NFTExitTimeout:
		result.Classification = capability.ClassificationFailed
		result.ErrorCode = capability.ResultErrorDeadlineExceeded
	case exit != capability.NFTExitSuccess:
		result.Classification = capability.ClassificationFailed
		result.ErrorCode = capability.ResultErrorNFTFailed
	default:
		result.Classification = capability.ClassificationFailed
		result.ErrorCode = capability.ResultErrorReadbackFailed
	}
	return result
}

func revokeResult(value capability.Value, exit capability.NFTExitClass, observation Observation, inspectErr error) capability.Result {
	result := baseResult(value)
	result.NFTExitClass = pointer(exit)
	applyObservation(&result, observation)
	switch {
	case exit == capability.NFTExitSuccess && inspectErr == nil && observation.State == capability.ReadbackAbsent:
		result.Classification = capability.ClassificationRevoked
		result.ErrorCode = capability.ResultErrorNone
	case observation.State == capability.ReadbackMismatch:
		result.Classification = capability.ClassificationIndeterminate
		result.ErrorCode = capability.ResultErrorReadbackMismatch
	case inspectErr != nil || observation.State == capability.ReadbackUnavailable:
		result.Classification = capability.ClassificationIndeterminate
		result.ErrorCode = capability.ResultErrorReadbackFailed
	case observation.State == capability.ReadbackAbsent && exit != capability.NFTExitSuccess:
		result.Classification = capability.ClassificationIndeterminate
		if exit == capability.NFTExitTimeout {
			result.ErrorCode = capability.ResultErrorDeadlineExceeded
		} else {
			result.ErrorCode = capability.ResultErrorNFTFailed
		}
	case exit == capability.NFTExitTimeout:
		result.Classification = capability.ClassificationFailed
		result.ErrorCode = capability.ResultErrorDeadlineExceeded
	case exit != capability.NFTExitSuccess:
		result.Classification = capability.ClassificationFailed
		result.ErrorCode = capability.ResultErrorNFTFailed
	default:
		result.Classification = capability.ClassificationFailed
		result.ErrorCode = capability.ResultErrorReadbackFailed
	}
	return result
}

func revokedResult(value capability.Value, exit capability.NFTExitClass) capability.Result {
	result := baseResult(value)
	result.NFTExitClass = pointer(exit)
	result.ReadbackState = capability.ReadbackAbsent
	result.Classification = capability.ClassificationRevoked
	result.ErrorCode = capability.ResultErrorNone
	return result
}

func inspectResult(ctx context.Context, value capability.Value, observation Observation, inspectErr error) capability.Result {
	result := baseResult(value)
	exit := capability.NFTExitSuccess
	if inspectErr != nil {
		exit = capability.NFTExitNonzero
		if ctx != nil && (errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled)) {
			exit = capability.NFTExitTimeout
		}
	}
	result.NFTExitClass = pointer(exit)
	applyObservation(&result, observation)
	switch {
	case inspectErr != nil:
		result.Classification = capability.ClassificationIndeterminate
		result.ErrorCode = capability.ResultErrorReadbackFailed
	case observation.State == capability.ReadbackActive:
		result.Classification = capability.ClassificationInspectActive
		result.ErrorCode = capability.ResultErrorNone
	case observation.State == capability.ReadbackAbsent:
		result.Classification = capability.ClassificationInspectAbsent
		result.ErrorCode = capability.ResultErrorNone
	case observation.State == capability.ReadbackMismatch:
		result.Classification = capability.ClassificationInspectMismatch
		result.ErrorCode = capability.ResultErrorNone
	default:
		result.Classification = capability.ClassificationIndeterminate
		result.ErrorCode = capability.ResultErrorReadbackFailed
	}
	return result
}

func recoveredAddResult(value capability.Value, observation Observation, inspectErr error) capability.Result {
	result := baseResult(value)
	result.NFTExitClass = pointer(capability.NFTExitNotInvoked)
	applyObservation(&result, observation)
	switch {
	case inspectErr == nil && observation.State == capability.ReadbackActive:
		result.Classification = capability.ClassificationRecoveredActive
		result.ErrorCode = capability.ResultErrorNone
	case observation.State == capability.ReadbackMismatch:
		result.ErrorCode = capability.ResultErrorReadbackMismatch
	case inspectErr != nil || observation.State == capability.ReadbackUnavailable:
		result.ErrorCode = capability.ResultErrorReadbackFailed
	default:
		result.ErrorCode = capability.ResultErrorIndeterminate
	}
	return result
}

func recoveredRevokeResult(value capability.Value, observation Observation, inspectErr error) capability.Result {
	result := baseResult(value)
	result.NFTExitClass = pointer(capability.NFTExitNotInvoked)
	applyObservation(&result, observation)
	if inspectErr == nil && observation.State == capability.ReadbackAbsent {
		result.Classification = capability.ClassificationRevoked
		result.ErrorCode = capability.ResultErrorNone
	} else if observation.State == capability.ReadbackMismatch {
		result.ErrorCode = capability.ResultErrorReadbackMismatch
	} else if inspectErr != nil || observation.State == capability.ReadbackUnavailable {
		result.ErrorCode = capability.ResultErrorReadbackFailed
	}
	return result
}

func terminalFailure(value capability.Value, exit capability.NFTExitClass, observation Observation, code capability.ResultErrorCode) capability.Result {
	result := baseResult(value)
	result.Classification = capability.ClassificationFailed
	result.NFTExitClass = pointer(exit)
	result.ErrorCode = code
	// Preflight state is enough to explain a non-invoked failure. Do not bind
	// handle/TTL values that were not produced by this capability's mutation.
	result.ReadbackState = observation.State
	return result
}

func applyObservation(result *capability.Result, observation Observation) {
	result.ReadbackState = observation.State
	if observation.State != capability.ReadbackActive {
		result.ElementHandle = nil
		result.RemainingTTLSeconds = nil
		return
	}
	ttl := observation.RemainingTTLSeconds
	// `nft --json list set` has no per-element handle. The v1 wire field is
	// retained as an explicit null and must never contain the set handle.
	result.ElementHandle = nil
	result.RemainingTTLSeconds = &ttl
}

func pointer(value capability.NFTExitClass) *capability.NFTExitClass { return &value }
