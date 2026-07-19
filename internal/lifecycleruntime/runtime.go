package lifecycleruntime

import (
	"context"
	"errors"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

type systemClock struct{}

func (systemClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type Runtime struct {
	store  Store
	config Config
	clock  Clock
	gate   chan struct{}
}

func (*Runtime) String() string     { return "lifecycleruntime.Runtime{authority:none}" }
func (r *Runtime) GoString() string { return r.String() }

func New(store Store, config Config, dependencies Dependencies) (*Runtime, error) {
	if store == nil || !validConfig(config) {
		return nil, ErrInvalidConfiguration
	}
	if dependencies.Clock == nil {
		dependencies.Clock = systemClock{}
	}
	return &Runtime{
		store: store, config: config, clock: dependencies.Clock,
		gate: make(chan struct{}, 1),
	}, nil
}

// ProcessNext claims and prepares at most one due inspection. Calls on one
// Runtime are serialized; database fencing remains authoritative across
// processes and runtime instances.
func (r *Runtime) ProcessNext(ctx context.Context) (Result, error) {
	if r == nil || r.store == nil || ctx == nil {
		return Result{outcome: OutcomeNoWork}, ErrInvalidConfiguration
	}
	select {
	case r.gate <- struct{}{}:
		defer func() { <-r.gate }()
	case <-ctx.Done():
		return Result{outcome: OutcomeNoWork}, ErrCancelled
	}
	if ctx.Err() != nil {
		return Result{outcome: OutcomeNoWork}, ErrCancelled
	}
	claim, found, err := r.store.ClaimDue(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return Result{outcome: OutcomeNoWork}, ErrCancelled
		}
		return Result{outcome: OutcomeNoWork}, ErrStoreUnavailable
	}
	if ctx.Err() != nil {
		if found {
			return r.finishFailure(ctx, claim, FailureContextCancelled, ErrCancelled)
		}
		return Result{outcome: OutcomeNoWork}, ErrCancelled
	}
	if !found {
		return Result{outcome: OutcomeNoWork}, nil
	}
	if !validClaim(claim) {
		return r.finishFailure(ctx, claim, FailureProjectionInvalid, ErrProjectionInvalid)
	}
	if ctx.Err() != nil {
		return r.finishFailure(ctx, claim, FailureContextCancelled, ErrCancelled)
	}

	inspect, err := lifecycleartifact.CheckInspectArtifact(lifecycleartifact.InspectInput{
		ActionID: claim.actionID, TargetIPv4: claim.targetIPv4,
		OriginalAddDigest: claim.originalAddDigest, OwnedSchemaDigest: claim.ownedSchemaDigest,
		Purpose: claim.purpose,
	})
	if err != nil {
		return r.finishFailure(ctx, claim, FailureContractRejected, ErrContractRejected)
	}
	authorization, err := lifecycleartifact.CheckInspectionAuthorization(
		lifecycleartifact.InspectionAuthorizationInput{
			AuthorizationID: claim.authorizationID, PolicyID: claim.policyID,
			PolicyVersion:               claim.policyVersion,
			OriginalAuthorizationDigest: claim.originalAuthorizationDigest,
			EvidenceSnapshotDigest:      claim.evidenceSnapshotDigest,
			ValidationSnapshotDigest:    claim.validationSnapshotDigest,
			SchedulerID:                 r.config.SchedulerID, RequestedAt: claim.requestedAt,
			ValidUntil: claim.validUntil, IdempotencyKeyDigest: idempotencyDigest(claim),
			Inspect: inspect,
		})
	if err != nil {
		return r.finishFailure(ctx, claim, FailureContractRejected, ErrContractRejected)
	}
	if ctx.Err() != nil {
		return r.finishFailure(ctx, claim, FailureContextCancelled, ErrCancelled)
	}
	prepared := PreparedInspection{inspect: inspect, authorization: authorization}
	disposition, err := r.store.CommitInspection(ctx, claim, prepared)
	if err != nil {
		if ctx.Err() != nil {
			return Result{outcome: OutcomeCommitUnknown}, ErrCancelled
		}
		return Result{outcome: OutcomeCommitUnknown}, ErrStoreUnavailable
	}
	switch disposition {
	case CommitCreated:
		return Result{outcome: OutcomeCommitted}, nil
	case CommitReplayed:
		return Result{outcome: OutcomeReplayed}, nil
	default:
		return Result{outcome: OutcomeCommitUnknown}, ErrStoreUnavailable
	}
}

func (r *Runtime) finishFailure(
	ctx context.Context,
	claim Claim,
	code FailureCode,
	cause error,
) (Result, error) {
	failure := checkedFailure(code)
	finishCtx := ctx
	var cancel context.CancelFunc
	if ctx == nil || ctx.Err() != nil {
		finishCtx, cancel = context.WithTimeout(context.Background(), r.config.CleanupTimeout)
		defer cancel()
	}
	if err := r.store.FinishFailure(finishCtx, claim, failure); err != nil {
		return Result{outcome: OutcomeFailed, failureCode: code}, ErrStoreUnavailable
	}
	return Result{outcome: OutcomeFailed, failureCode: code}, cause
}

// Run polls serially until cancellation. It performs no local due-time
// calculation and returns the first non-cancellation failure to the supervisor.
func (r *Runtime) Run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	for {
		result, err := r.ProcessNext(ctx)
		if ctx.Err() != nil || errors.Is(err, ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		if result.Outcome() != OutcomeNoWork {
			continue
		}
		if err := r.clock.Sleep(ctx, r.config.PollInterval); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrStoreUnavailable
		}
	}
}
