package dispatchruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/devwooops/sentinelflow/internal/dispatchstore"
	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
)

const (
	maxRuntimeAttempts = 4
	cleanupTimeout     = 2 * time.Second
)

var ownerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type Config struct {
	LeaseOwner             string
	LeaseDuration          time.Duration
	CandidateLimit         int
	PollInterval           time.Duration
	CapabilityTTL          time.Duration
	ExchangeTimeout        time.Duration
	SameLeaseAttempts      int
	ResultPersistenceTries int
	RetryBackoff           time.Duration
}

func DefaultConfig(leaseOwner string) Config {
	return Config{
		LeaseOwner: leaseOwner, LeaseDuration: dispatchstore.MaxLeaseDuration,
		CandidateLimit: dispatchstore.MaxClaimCandidates, PollInterval: 250 * time.Millisecond,
		CapabilityTTL: capability.MaxValidity, ExchangeTimeout: ipc.MaxExchangeTimeout,
		SameLeaseAttempts: 2, ResultPersistenceTries: 2,
		RetryBackoff: dispatchstore.MinRetryBackoff,
	}
}

func (c Config) valid() bool {
	return ownerPattern.MatchString(c.LeaseOwner) && c.LeaseDuration >= time.Microsecond &&
		c.LeaseDuration <= dispatchstore.MaxLeaseDuration && c.LeaseDuration%time.Microsecond == 0 &&
		c.CandidateLimit >= 1 && c.CandidateLimit <= dispatchstore.MaxClaimCandidates &&
		c.PollInterval > 0 && c.PollInterval <= time.Minute &&
		c.CapabilityTTL >= time.Second && c.CapabilityTTL <= capability.MaxValidity &&
		c.ExchangeTimeout == ipc.MaxExchangeTimeout && c.SameLeaseAttempts >= 1 &&
		c.SameLeaseAttempts <= maxRuntimeAttempts && c.ResultPersistenceTries >= 1 &&
		c.ResultPersistenceTries <= maxRuntimeAttempts &&
		c.RetryBackoff >= dispatchstore.MinRetryBackoff &&
		c.RetryBackoff <= dispatchstore.MaxRetryBackoff && c.RetryBackoff%time.Microsecond == 0
}

type Outcome string

const (
	OutcomeNoWork          Outcome = "no_work"
	OutcomeCompleted       Outcome = "completed"
	OutcomeRetry           Outcome = "retry"
	OutcomeDead            Outcome = "dead"
	OutcomeLeaseLost       Outcome = "lease_lost"
	OutcomeRecoverRequired Outcome = "recover_required"
)

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }
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

type Dependencies struct{ Clock Clock }

type Runtime struct {
	store          Store
	issuer         *Issuer
	resultVerifier capability.ResultVerifier
	client         ExchangeClient
	config         Config
	clock          Clock
}

func (*Runtime) String() string     { return "dispatchruntime.Runtime{authority:[REDACTED]}" }
func (r *Runtime) GoString() string { return r.String() }

func New(
	store Store,
	issuer *Issuer,
	resultVerifier capability.ResultVerifier,
	client ExchangeClient,
	config Config,
	dependencies Dependencies,
) (*Runtime, error) {
	if store == nil || issuer == nil || client == nil || resultVerifier.KeyID() == "" ||
		resultVerifier.ExecutorID() == "" || !config.valid() {
		return nil, ErrInvalidConfiguration
	}
	clock := dependencies.Clock
	if clock == nil {
		clock = systemClock{}
	}
	return &Runtime{
		store: store, issuer: issuer, resultVerifier: resultVerifier,
		client: client, config: config, clock: clock,
	}, nil
}

// Run keeps one dispatcher process bounded to one in-flight privileged job.
// It stops on recover-required because continuing without operator-visible
// reconciliation could repeatedly reclaim an expired or conflicting artifact.
func (r *Runtime) Run(ctx context.Context) error {
	if ctx == nil || r == nil {
		return ErrInvalidConfiguration
	}
	for {
		outcome, err := r.ProcessNext(ctx)
		if errors.Is(err, ErrRecoverRequired) {
			return ErrRecoverRequired
		}
		if ctx.Err() != nil {
			return nil
		}
		if outcome == OutcomeRetry || outcome == OutcomeDead {
			continue
		}
		if err != nil && !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrLeaseLost) {
			return err
		}
		if outcome != OutcomeNoWork && err == nil {
			continue
		}
		if sleepErr := r.clock.Sleep(ctx, r.config.PollInterval); sleepErr != nil {
			return nil
		}
	}
}

// ProcessNext claims at most one job and runs its entire fenced dispatch.
func (r *Runtime) ProcessNext(ctx context.Context) (Outcome, error) {
	if ctx == nil || r == nil || r.store == nil || r.issuer == nil || r.client == nil {
		return OutcomeNoWork, ErrInvalidConfiguration
	}
	if ctx.Err() != nil {
		return OutcomeNoWork, ErrCancelled
	}
	claimRequest := ClaimRequest{
		LeaseOwner: r.config.LeaseOwner, LeaseDuration: r.config.LeaseDuration,
		CandidateLimit: r.config.CandidateLimit,
	}
	claim, found, err := r.store.ClaimRecoveryNext(ctx, claimRequest)
	if err == nil && !found {
		claim, found, err = r.store.ClaimNext(ctx, claimRequest)
	}
	if err != nil {
		return OutcomeNoWork, classifyClaimError(err)
	}
	if !found {
		return OutcomeNoWork, nil
	}
	recovered, err := r.recover(ctx, claim)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	switch recovered.State() {
	case RecoveryResult:
		return r.finishRecoveredResult(ctx, claim, recovered)
	case RecoveryCapability:
		issued, stored, recoverErr := r.prepareRecoveredCapability(claim, recovered)
		if recoverErr != nil {
			return OutcomeRecoverRequired, ErrRecoverRequired
		}
		if claim.RecoveryOnly() {
			return r.dispatchRecoveryOnly(ctx, claim, issued, stored)
		}
		if !r.clock.Now().Before(issued.Verified.Value().ExpiresAt) {
			return r.dispatchExpiredRecovery(ctx, claim, issued, stored)
		}
		return r.dispatchPersisted(ctx, claim, issued, stored)
	case RecoveryNone:
		if claim.RecoveryOnly() {
			return OutcomeRecoverRequired, ErrRecoverRequired
		}
		// Only this state is allowed to mint new authority.
	default:
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	issued, err := r.issuer.Issue(claim, r.config.CapabilityTTL)
	if err != nil {
		switch {
		case errors.Is(err, ErrEntropyUnavailable):
			outcome, finishErr := r.finishFailure(ctx, claim, "entropy_unavailable", true)
			if finishErr != nil {
				return outcome, finishErr
			}
			return outcome, err
		default:
			return r.finishFailure(ctx, claim, "capability_contract_invalid", false)
		}
	}
	if ctx.Err() != nil {
		outcome, finishErr := r.finishFailureWithCleanup(claim, "shutdown_before_persist", true)
		if finishErr != nil {
			return outcome, finishErr
		}
		return outcome, ErrCancelled
	}
	storedCapability, err := r.store.PersistCapability(ctx, claim, issued.Signed, issued.Verified)
	if err != nil {
		return r.handleCapabilityPersistenceFailure(ctx, claim, err)
	}
	return r.dispatchPersisted(ctx, claim, issued, storedCapability)
}

func (r *Runtime) dispatchRecoveryOnly(
	ctx context.Context,
	claim Claim,
	issued IssuedCapability,
	storedCapability StoredCapability,
) (Outcome, error) {
	recoveryClient, ok := r.client.(RecoveryExchangeClient)
	if !ok || !claim.RecoveryOnly() || !r.clock.Now().Before(claim.LeaseUntil()) {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	signedResult, err := r.exchangeRecoverySameLease(ctx, claim, recoveryClient, issued.Signed)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	verifiedResult, err := r.resultVerifier.Verify(signedResult)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	if _, err = verifiedResult.BindTo(issued.Verified); err != nil ||
		!validPostExpiryResult(issued.Verified, verifiedResult) {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	storedResult, err := r.persistResult(ctx, claim, storedCapability, signedResult, verifiedResult)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	finishCtx, cancel, ok := r.persistenceContext(ctx, claim)
	if !ok {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	defer cancel()
	if err := r.store.Finish(finishCtx, claim, FinishRequest{
		Outcome: FinishCompleted, Result: &storedResult,
	}); err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	return OutcomeCompleted, nil
}

func (r *Runtime) dispatchExpiredRecovery(
	ctx context.Context,
	claim Claim,
	issued IssuedCapability,
	storedCapability StoredCapability,
) (Outcome, error) {
	recoveryClient, ok := r.client.(RecoveryExchangeClient)
	if !ok || r.clock.Now().Before(issued.Verified.Value().ExpiresAt) ||
		!r.clock.Now().Before(claim.LeaseUntil()) {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	signedResult, err := r.exchangeRecoverySameLease(ctx, claim, recoveryClient, issued.Signed)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	verifiedResult, err := r.resultVerifier.Verify(signedResult)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	if _, err = verifiedResult.BindTo(issued.Verified); err != nil ||
		!validPostExpiryResult(issued.Verified, verifiedResult) {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	storedResult, err := r.persistResult(
		ctx, claim, storedCapability, signedResult, verifiedResult,
	)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	finishCtx, cancel, ok := r.persistenceContext(ctx, claim)
	if !ok {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	defer cancel()
	if err := r.store.Finish(finishCtx, claim, FinishRequest{
		Outcome: FinishCompleted, Result: &storedResult,
	}); err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	return OutcomeCompleted, nil
}

func (r *Runtime) dispatchPersisted(
	ctx context.Context,
	claim Claim,
	issued IssuedCapability,
	storedCapability StoredCapability,
) (Outcome, error) {
	signedResult, err := r.exchangeSameLease(ctx, claim, issued)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	verifiedResult, err := r.resultVerifier.Verify(signedResult)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	if _, err = verifiedResult.BindTo(issued.Verified); err != nil ||
		!validPostExpiryResult(issued.Verified, verifiedResult) {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	storedResult, err := r.persistResult(ctx, claim, storedCapability, signedResult, verifiedResult)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	finishCtx, cancel, ok := r.persistenceContext(ctx, claim)
	if !ok {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	defer cancel()
	if err := r.store.Finish(finishCtx, claim, FinishRequest{
		Outcome: FinishCompleted, Result: &storedResult,
	}); err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	return OutcomeCompleted, nil
}

func (r *Runtime) recover(ctx context.Context, claim Claim) (RecoveredExecution, error) {
	for attempt := 1; attempt <= r.config.ResultPersistenceTries; attempt++ {
		recovered, err := r.store.Recover(ctx, claim)
		if err == nil {
			return recovered, nil
		}
		if !errors.Is(err, dispatchstore.ErrUnavailable) ||
			attempt == r.config.ResultPersistenceTries || ctx.Err() != nil {
			return RecoveredExecution{}, ErrRecoverRequired
		}
		if sleepErr := r.clock.Sleep(ctx, r.config.RetryBackoff); sleepErr != nil {
			return RecoveredExecution{}, ErrRecoverRequired
		}
	}
	return RecoveredExecution{}, ErrRecoverRequired
}

func (r *Runtime) prepareRecoveredCapability(
	claim Claim,
	recovered RecoveredExecution,
) (IssuedCapability, StoredCapability, error) {
	if recovered.state != RecoveryCapability && recovered.state != RecoveryResult {
		return IssuedCapability{}, StoredCapability{}, ErrRecoverRequired
	}
	signed := recovered.signedCapability
	verified, err := r.issuer.verifier.Verify(signed)
	if err != nil || !bindRecoveredClaim(claim, signed, verified) {
		return IssuedCapability{}, StoredCapability{}, ErrRecoverRequired
	}
	stored := recovered.capability
	stored.claim = claim
	stored.signed = signed
	stored.verified = verified
	return IssuedCapability{Signed: signed, Verified: verified}, stored, nil
}

func (r *Runtime) finishRecoveredResult(
	ctx context.Context,
	claim Claim,
	recovered RecoveredExecution,
) (Outcome, error) {
	issued, storedCapability, err := r.prepareRecoveredCapability(claim, recovered)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	verifiedResult, err := r.resultVerifier.Verify(recovered.signedResult)
	if err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	if _, err = verifiedResult.BindTo(issued.Verified); err != nil ||
		!validPostExpiryResult(issued.Verified, verifiedResult) {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	storedResult := recovered.result
	storedResult.capability = storedCapability
	storedResult.verified = verifiedResult
	finishCtx, cancel, ok := r.persistenceContext(ctx, claim)
	if !ok {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	defer cancel()
	if err := r.store.Finish(finishCtx, claim, FinishRequest{
		Outcome: FinishCompleted, Result: &storedResult,
	}); err != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	return OutcomeCompleted, nil
}

func bindRecoveredClaim(
	claim Claim,
	signed capability.SignedCapability,
	verified capability.VerifiedCapability,
) bool {
	job := claim.Job()
	value := verified.Value()
	original := ""
	if job.hasOriginalAddDigest {
		original = job.originalAddDigest
	}
	return bytes.Equal(signed.ArtifactBytes(), job.artifact) &&
		value.JobID == job.jobID && value.Operation == job.operation &&
		value.ActionID == job.actionID && value.PolicyID == job.policyID &&
		value.PolicyVersion == job.policyVersion && value.TargetIPv4 == job.targetIPv4 &&
		value.ArtifactDigest == job.artifactDigest && value.OriginalAddDigest == original &&
		value.EvidenceSnapshotDigest == job.evidenceSnapshotDigest &&
		value.ValidationSnapshotDigest == job.validationSnapshotDigest &&
		value.AuthorizationDigest == job.authorizationDigest && value.ActorID == job.actorID &&
		value.ReasonDigest == job.reasonDigest && value.OwnedSchemaDigest == job.ownedSchemaDigest &&
		!value.NotBefore.Before(job.notBefore) && !value.ExpiresAt.After(job.validUntil)
}

func (r *Runtime) handleCapabilityPersistenceFailure(
	ctx context.Context,
	claim Claim,
	err error,
) (Outcome, error) {
	if errors.Is(err, dispatchstore.ErrConflict) || errors.Is(err, dispatchstore.ErrUnavailable) ||
		contextError(err) != nil {
		return OutcomeRecoverRequired, ErrRecoverRequired
	}
	if errors.Is(err, dispatchstore.ErrLeaseLost) {
		return OutcomeLeaseLost, ErrLeaseLost
	}
	if errors.Is(err, dispatchstore.ErrContractRejected) ||
		errors.Is(err, dispatchstore.ErrPersistenceRejected) ||
		errors.Is(err, dispatchstore.ErrInvalidInput) || errors.Is(err, dispatchstore.ErrInvalidRow) {
		return r.finishFailure(ctx, claim, "capability_persistence_rejected", false)
	}
	return OutcomeRecoverRequired, ErrRecoverRequired
}

func (r *Runtime) exchangeSameLease(
	ctx context.Context,
	claim Claim,
	issued IssuedCapability,
) (capability.SignedResult, error) {
	expiresAt := issued.Verified.Value().ExpiresAt
	for attempt := 1; attempt <= r.config.SameLeaseAttempts; attempt++ {
		if ctx.Err() != nil || !r.clock.Now().Before(claim.LeaseUntil()) {
			return capability.SignedResult{}, ErrRecoverRequired
		}
		// Starting a new UDS exchange at or after expiry is forbidden. A response
		// already in flight may arrive later and is checked separately below.
		if !r.clock.Now().Before(expiresAt) {
			return capability.SignedResult{}, ErrRecoverRequired
		}
		result, err := r.client.Exchange(ctx, issued.Signed)
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, ErrTransport) || attempt == r.config.SameLeaseAttempts {
			return capability.SignedResult{}, ErrRecoverRequired
		}
		if err := r.clock.Sleep(ctx, r.config.RetryBackoff); err != nil {
			return capability.SignedResult{}, ErrRecoverRequired
		}
	}
	return capability.SignedResult{}, ErrRecoverRequired
}

func (r *Runtime) exchangeRecoverySameLease(
	ctx context.Context,
	claim Claim,
	client RecoveryExchangeClient,
	signed capability.SignedCapability,
) (capability.SignedResult, error) {
	for attempt := 1; attempt <= r.config.SameLeaseAttempts; attempt++ {
		if ctx.Err() != nil || !r.clock.Now().Before(claim.LeaseUntil()) {
			return capability.SignedResult{}, ErrRecoverRequired
		}
		result, err := client.ExchangeRecovery(ctx, signed)
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, ErrTransport) || attempt == r.config.SameLeaseAttempts {
			return capability.SignedResult{}, ErrRecoverRequired
		}
		if err := r.clock.Sleep(ctx, r.config.RetryBackoff); err != nil {
			return capability.SignedResult{}, ErrRecoverRequired
		}
	}
	return capability.SignedResult{}, ErrRecoverRequired
}

func (r *Runtime) persistResult(
	ctx context.Context,
	claim Claim,
	storedCapability StoredCapability,
	signed capability.SignedResult,
	verified capability.VerifiedResult,
) (StoredResult, error) {
	for attempt := 1; attempt <= r.config.ResultPersistenceTries; attempt++ {
		operationCtx, cancel, ok := r.persistenceContext(ctx, claim)
		if !ok {
			return StoredResult{}, ErrRecoverRequired
		}
		stored, err := r.store.PersistResult(
			operationCtx, storedCapability, signed, verified,
		)
		cancel()
		if err == nil {
			return stored, nil
		}
		if !errors.Is(err, dispatchstore.ErrUnavailable) ||
			attempt == r.config.ResultPersistenceTries {
			return StoredResult{}, ErrRecoverRequired
		}
		backoffCtx, backoffCancel, backoffOK := r.persistenceContext(ctx, claim)
		if !backoffOK {
			return StoredResult{}, ErrRecoverRequired
		}
		backoffErr := r.clock.Sleep(backoffCtx, r.config.RetryBackoff)
		backoffCancel()
		if backoffErr != nil {
			return StoredResult{}, ErrRecoverRequired
		}
	}
	return StoredResult{}, ErrRecoverRequired
}

func validPostExpiryResult(
	verifiedCapability capability.VerifiedCapability,
	verifiedResult capability.VerifiedResult,
) bool {
	capabilityValue := verifiedCapability.Value()
	result := verifiedResult.Value()
	if result.StartedAt.Before(capabilityValue.ExpiresAt) {
		return true
	}
	if capabilityValue.Operation == capability.OperationInspect {
		return true
	}
	if result.NFTExitClass == nil || *result.NFTExitClass != capability.NFTExitNotInvoked {
		return false
	}
	switch capabilityValue.Operation {
	case capability.OperationAdd:
		return result.Classification == capability.ClassificationRecoveredActive ||
			result.Classification == capability.ClassificationFailed ||
			result.Classification == capability.ClassificationIndeterminate
	case capability.OperationRevoke:
		return result.Classification == capability.ClassificationRevoked ||
			result.Classification == capability.ClassificationFailed ||
			result.Classification == capability.ClassificationIndeterminate
	default:
		return false
	}
}

func (r *Runtime) finishFailure(
	ctx context.Context,
	claim Claim,
	code string,
	retry bool,
) (Outcome, error) {
	if ctx.Err() != nil {
		return r.finishFailureWithCleanup(claim, code, retry)
	}
	return r.finishFailureContext(ctx, claim, code, retry)
}

func (r *Runtime) finishFailureWithCleanup(
	claim Claim,
	code string,
	retry bool,
) (Outcome, error) {
	ctx, cancel, ok := r.persistenceContext(context.Background(), claim)
	if !ok {
		return OutcomeLeaseLost, ErrLeaseLost
	}
	defer cancel()
	return r.finishFailureContext(ctx, claim, code, retry)
}

func (r *Runtime) finishFailureContext(
	ctx context.Context,
	claim Claim,
	code string,
	retry bool,
) (Outcome, error) {
	job := claim.Job()
	request := FinishRequest{ErrorCode: code, ErrorDigest: failureDigest(code)}
	outcome := OutcomeDead
	if retry && claim.Attempt() < job.maxAttempts {
		request.Outcome = FinishRetry
		request.RetryBackoff = retryDelay(r.config.RetryBackoff, claim.Attempt())
		outcome = OutcomeRetry
	} else {
		request.Outcome = FinishDead
	}
	if err := r.store.Finish(ctx, claim, request); err != nil {
		if errors.Is(err, dispatchstore.ErrLeaseLost) {
			return OutcomeLeaseLost, ErrLeaseLost
		}
		return outcome, ErrUnavailable
	}
	return outcome, nil
}

func (r *Runtime) persistenceContext(
	ctx context.Context,
	claim Claim,
) (context.Context, context.CancelFunc, bool) {
	now := r.clock.Now()
	if !now.Before(claim.LeaseUntil()) {
		return nil, nil, false
	}
	deadline := now.Add(cleanupTimeout)
	if claim.LeaseUntil().Before(deadline) {
		deadline = claim.LeaseUntil()
	}
	if ctx.Err() == nil {
		if existing, ok := ctx.Deadline(); ok && existing.Before(deadline) {
			deadline = existing
		}
		result, cancel := context.WithDeadline(ctx, deadline)
		return result, cancel, true
	}
	result, cancel := context.WithDeadline(context.Background(), deadline)
	return result, cancel, true
}

func classifyClaimError(err error) error {
	if contextError(err) != nil {
		return ErrCancelled
	}
	if errors.Is(err, dispatchstore.ErrLeaseLost) {
		return ErrLeaseLost
	}
	if errors.Is(err, dispatchstore.ErrInvalidInput) || errors.Is(err, dispatchstore.ErrInvalidRow) ||
		errors.Is(err, dispatchstore.ErrContractRejected) ||
		errors.Is(err, dispatchstore.ErrPersistenceRejected) {
		return ErrContractRejected
	}
	return ErrUnavailable
}

func retryDelay(base time.Duration, attempt int32) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := base
	for count := int32(1); count < attempt && delay < dispatchstore.MaxRetryBackoff; count++ {
		if delay > dispatchstore.MaxRetryBackoff/2 {
			return dispatchstore.MaxRetryBackoff
		}
		delay *= 2
	}
	if delay > dispatchstore.MaxRetryBackoff {
		return dispatchstore.MaxRetryBackoff
	}
	return delay
}

func failureDigest(code string) string {
	digest := sha256.Sum256([]byte("sentinelflow dispatcher failure-v1\n" + code))
	return "sha256:" + hex.EncodeToString(digest[:])
}
