package analysisworker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const failureDigestDomain = "sentinelflow analysis-worker-failure-v1\n"

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

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

type Runtime struct {
	store    Store
	analyzer Analyzer
	config   Config
	clock    Clock
	tokens   worker.TokenSource
	jitter   worker.JitterSource
	identity ai.ProviderIdentity
}

func New(store Store, analyzer Analyzer, config Config, dependencies Dependencies) (*Runtime, error) {
	if store == nil {
		return nil, ErrAtomicStoreMissing
	}
	identity, ok := safeAnalyzerIdentity(analyzer)
	if analyzer == nil || !ok || !validConfig(config, identity) {
		return nil, ErrInvalidConfig
	}
	if dependencies.Clock == nil {
		dependencies.Clock = systemClock{}
	}
	if dependencies.Tokens == nil {
		dependencies.Tokens = worker.CryptoTokenSource{}
	}
	if dependencies.Jitter == nil {
		dependencies.Jitter = worker.CryptoJitterSource{}
	}
	return &Runtime{
		store: store, analyzer: analyzer, config: config,
		clock: dependencies.Clock, tokens: dependencies.Tokens, jitter: dependencies.Jitter,
		identity: identity,
	}, nil
}

func validConfig(config Config, identity ai.ProviderIdentity) bool {
	if !identifierPattern.MatchString(config.LeaseOwner) ||
		config.LeaseDuration <= 0 || config.LeaseDuration > worker.MaxLeaseDuration ||
		config.PollInterval <= 0 || config.MaxConcurrency < 1 || config.MaxConcurrency > ai.MaxConcurrency {
		return false
	}
	switch identity.Kind() {
	case ai.ProviderOpenAIResponses:
		if !identifierPattern.MatchString(config.RateCardVersion) ||
			config.RateCardVersion != identity.RateCardVersion() {
			return false
		}
	case ai.ProviderDeterministicStub:
		if config.RateCardVersion != "" {
			return false
		}
	default:
		return false
	}
	_, err := config.Backoff.Delay(1, 0)
	return err == nil
}

// Run maintains the configured number of analysis loops. PostgreSQL leasing is
// the cross-process concurrency authority; this bound prevents one process from
// exceeding the frozen two-analysis OpenAI concurrency budget.
func (r *Runtime) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsCh := make(chan error, r.config.MaxConcurrency)
	var group sync.WaitGroup
	for range r.config.MaxConcurrency {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsCh <- r.loop(runCtx)
		}()
	}
	first := <-errorsCh
	cancel()
	group.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return first
}

func (r *Runtime) loop(ctx context.Context) error {
	for {
		result, err := r.RunOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ErrLeaseLost) {
				continue
			}
			return err
		}
		if result.Outcome != worker.OutcomeNoJob {
			continue
		}
		if err := r.clock.Sleep(ctx, r.config.PollInterval); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrPersistence
		}
	}
}

// RunOnce leases and atomically finalizes at most one analyze job.
func (r *Runtime) RunOnce(ctx context.Context) (Result, error) {
	if ctx == nil {
		return Result{}, ErrInvalidConfig
	}
	now := databaseTime(r.clock.Now())
	token, err := r.tokens.NewLeaseToken()
	if err != nil || !validUUIDV4(token) {
		return Result{}, ErrPersistence
	}
	leaseRequest := worker.LeaseRequest{
		Now: now, LeaseToken: token, LeaseOwner: r.config.LeaseOwner,
		LeaseExpiresAt: now.Add(r.config.LeaseDuration),
	}
	job, found, err := r.store.Lease(ctx, leaseRequest)
	if err != nil {
		return Result{}, ErrPersistence
	}
	if !found {
		return Result{Outcome: worker.OutcomeNoJob}, nil
	}
	result := Result{
		JobID: job.JobID, IncidentID: job.AggregateID, Attempt: job.Attempt,
	}
	if err := validateLease(job, leaseRequest); err != nil {
		return result, err
	}

	handlerCtx, cancel := context.WithDeadline(ctx, job.LeaseExpiresAt)
	defer cancel()
	snapshot, prepared, err := r.store.Prepare(handlerCtx, PrepareRequest{
		Job: job.Job, LeaseToken: job.LeaseToken,
	})
	if err != nil {
		if handlerCtx.Err() != nil || ctx.Err() != nil {
			return result, contextOrLeaseError(ctx)
		}
		return r.finalizeOperationalFailure(ctx, job, result, "analysis_snapshot_unavailable")
	}
	if !prepared {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	if snapshot.IncidentID != job.AggregateID || snapshot.IncidentVersion != job.AggregateVersion {
		return r.finalizeOperationalFailure(ctx, job, result, "analysis_snapshot_conflict")
	}

	input, inputFailure := buildInput(snapshot)
	if inputFailure != "" {
		return r.finalizeAnalysisFailure(ctx, job, result, snapshot, input, inputFailure, 0)
	}
	analyzed, analyzeErr := invokeAnalyzer(handlerCtx, r.analyzer, r.identity, input)
	if handlerCtx.Err() != nil || ctx.Err() != nil {
		return result, contextOrLeaseError(ctx)
	}
	if analyzeErr != nil {
		failure, ok := ai.FailureOf(analyzeErr)
		if !ok || !validFailureReason(failure.Reason) || failure.Attempts < 0 || failure.Attempts > 2 {
			return r.finalizeAnalysisFailure(ctx, job, result, snapshot, input,
				ai.FailureConfiguration, 0)
		}
		return r.finalizeAnalysisFailure(ctx, job, result, snapshot, input,
			failure.Reason, failure.Attempts)
	}
	parsed, err := parseOutput(analyzed.Output, snapshot)
	if err != nil || !validSuccessResult(analyzed) || analyzed.InputDigest != digestBytes(input) {
		return r.finalizeAnalysisFailure(ctx, job, result, snapshot, input,
			ai.FailureSchemaInvalid, analyzed.Attempts)
	}
	usage := sanitizedUsage(analyzed.Usage)
	mutation := &Mutation{
		IncidentID: snapshot.IncidentID, IncidentVersion: snapshot.IncidentVersion,
		AnalysisID: snapshot.AnalysisID, EvidenceSnapshotID: snapshot.EvidenceSnapshotID,
		EvidenceSnapshotDigest: snapshot.EvidenceSnapshotDigest, State: StateReviewReady,
		AuditAction: "analysis_succeeded", ValidationRequested: true,
		Success: &Success{
			ProviderKind: string(r.identity.Kind()), AdapterID: r.identity.AdapterID(),
			Model: r.identity.Model(), ReasoningEffort: r.identity.ReasoningEffort(),
			RateCardVersion: r.identity.RateCardVersion(), ResponseID: analyzed.ResponseID,
			Attempts: analyzed.Attempts, InputBytes: len(input), InputDigest: analyzed.InputDigest,
			InputSchemaDigest: analyzed.InputSchemaDigest, PromptDigest: analyzed.PromptDigest,
			OutputSchemaDigest: analyzed.OutputSchemaDigest, OutputDigest: parsed.outputDigest,
			AnalysisJSON: parsed.analysisJSON, PolicyJSON: parsed.policyJSON,
			CommandCandidateJSON:   parsed.candidateJSON,
			GeneratedCommandDigest: parsed.generatedCommandDigest,
			EvidenceIDs:            parsed.evidenceIDs, Usage: usage,
		},
	}
	result.State = StateReviewReady
	return r.finalizeCompleted(ctx, job, result, mutation)
}

func invokeAnalyzer(
	ctx context.Context,
	analyzer Analyzer,
	expected ai.ProviderIdentity,
	input []byte,
) (result ai.Result, err error) {
	defer func() {
		if recover() != nil {
			result = ai.Result{}
			err = ErrInvalidAnalyzer
		}
	}()
	if identity := analyzer.Identity(); !identity.Equal(expected) {
		return ai.Result{}, ErrInvalidAnalyzer
	}
	result, err = analyzer.Analyze(ctx, input)
	if identity := analyzer.Identity(); !identity.Equal(expected) {
		return ai.Result{}, ErrInvalidAnalyzer
	}
	return result, err
}

func safeAnalyzerIdentity(analyzer Analyzer) (identity ai.ProviderIdentity, ok bool) {
	if analyzer == nil {
		return ai.ProviderIdentity{}, false
	}
	defer func() {
		if recover() != nil {
			identity, ok = ai.ProviderIdentity{}, false
		}
	}()
	identity = analyzer.Identity()
	parsed, valid := ai.ParseProviderIdentity(
		string(identity.Kind()), identity.AdapterID(), identity.Model(),
		identity.ReasoningEffort(), identity.RateCardVersion(),
	)
	return identity, valid && identity.Equal(parsed)
}

func (r *Runtime) finalizeAnalysisFailure(
	ctx context.Context,
	job worker.LeasedJob,
	result Result,
	snapshot Snapshot,
	input []byte,
	reason ai.FailureReason,
	attempts int,
) (Result, error) {
	mutation := &Mutation{
		IncidentID: snapshot.IncidentID, IncidentVersion: snapshot.IncidentVersion,
		AnalysisID: snapshot.AnalysisID, EvidenceSnapshotID: snapshot.EvidenceSnapshotID,
		EvidenceSnapshotDigest: snapshot.EvidenceSnapshotDigest,
		State:                  StateAnalysisFailed, AuditAction: "analysis_failed",
		Failure: &Failure{
			Reason: reason, Attempts: attempts, RetryEligible: retryEligible(reason),
			InputBytes: len(input), InputDigest: optionalDigest(input),
		},
	}
	result.State = StateAnalysisFailed
	result.FailureReason = reason
	return r.finalizeCompleted(ctx, job, result, mutation)
}

func (r *Runtime) finalizeCompleted(
	ctx context.Context,
	job worker.LeasedJob,
	result Result,
	mutation *Mutation,
) (Result, error) {
	now := databaseTime(r.clock.Now())
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if !now.Before(job.LeaseExpiresAt) {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	request := FinalizeRequest{
		Finish: worker.FinishRequest{
			State: worker.FinishCompleted, Now: now,
			JobID: job.JobID, LeaseToken: job.LeaseToken,
		},
		Mutation: mutation,
	}
	finished, err := r.store.Finalize(ctx, request)
	if err != nil {
		return result, ErrPersistence
	}
	if !finished {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	result.Outcome = worker.OutcomeCompleted
	return result, nil
}

func (r *Runtime) finalizeOperationalFailure(
	ctx context.Context,
	job worker.LeasedJob,
	result Result,
	code string,
) (Result, error) {
	now := databaseTime(r.clock.Now())
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if !now.Before(job.LeaseExpiresAt) {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	finish := worker.FinishRequest{
		State: worker.FinishDead, ErrorCode: code, ErrorDigest: failureDigest(code),
		Now: now, JobID: job.JobID, LeaseToken: job.LeaseToken,
	}
	result.FailureCode = code
	result.Outcome = worker.OutcomeDeadLettered
	if job.Attempt < job.MaxAttempts {
		jitter, err := r.jitter.Uint64()
		if err != nil {
			return result, ErrPersistence
		}
		delay, err := r.config.Backoff.Delay(job.Attempt, jitter)
		if err != nil {
			return result, ErrInvalidConfig
		}
		retryAt := databaseTime(now.Add(delay))
		finish.State = worker.FinishRetry
		finish.RetryAt = &retryAt
		result.Outcome = worker.OutcomeRetryScheduled
		result.RetryAt = &retryAt
	}
	finished, err := r.store.Finalize(ctx, FinalizeRequest{Finish: finish})
	if err != nil {
		return result, ErrPersistence
	}
	if !finished {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	return result, nil
}

func validateLease(job worker.LeasedJob, request worker.LeaseRequest) error {
	requestedDuration := request.LeaseExpiresAt.Sub(request.Now)
	if !uuidPattern.MatchString(job.JobID) || job.Kind != worker.JobAnalyze ||
		job.AggregateType != "incident" || !uuidPattern.MatchString(job.AggregateID) ||
		job.AggregateVersion < 1 || job.State != "leased" ||
		job.LeaseToken != request.LeaseToken || job.LeaseOwner != request.LeaseOwner ||
		job.LeaseGrantedAt.IsZero() || !job.LeaseExpiresAt.After(job.LeaseGrantedAt) ||
		job.LeaseExpiresAt.Sub(job.LeaseGrantedAt) != requestedDuration ||
		requestedDuration <= 0 || requestedDuration > worker.MaxLeaseDuration ||
		job.Attempt < 1 || job.MaxAttempts < 1 || job.Attempt > job.MaxAttempts {
		if job.Kind != worker.JobAnalyze {
			return ErrUnexpectedJobKind
		}
		return ErrInvalidLease
	}
	return nil
}

func validSuccessResult(result ai.Result) bool {
	return result.Attempts >= 1 && result.Attempts <= 2 &&
		boundedIdentifier(result.ResponseID, maxResponseIDBytes) &&
		digestPattern.MatchString(result.InputDigest) &&
		digestPattern.MatchString(result.InputSchemaDigest) &&
		digestPattern.MatchString(result.PromptDigest) &&
		digestPattern.MatchString(result.OutputSchemaDigest)
}

func boundedIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func sanitizedUsage(usage ai.Usage) ai.Usage {
	if !usage.Trusted || usage.InputTokens <= 0 || usage.OutputTokens <= 0 ||
		usage.CachedInputTokens < 0 || usage.CachedInputTokens > usage.InputTokens ||
		usage.InputTokens > ai.MaxInputBytes || usage.OutputTokens > ai.MaxOutputTokens {
		return ai.Usage{}
	}
	return usage
}

func validFailureReason(reason ai.FailureReason) bool {
	switch reason {
	case ai.FailureBudgetExhausted, ai.FailureInputTooLarge, ai.FailureNetworkError,
		ai.FailureHTTP408, ai.FailureHTTP409, ai.FailureRateLimited,
		ai.FailureServerError, ai.FailureTimeout, ai.FailureRefused,
		ai.FailureIncomplete, ai.FailureSchemaInvalid, ai.FailureEvidenceInvalid,
		ai.FailureCancelled, ai.FailureConfiguration:
		return true
	default:
		return false
	}
}

func retryEligible(reason ai.FailureReason) bool {
	switch reason {
	case ai.FailureNetworkError, ai.FailureHTTP408, ai.FailureHTTP409,
		ai.FailureRateLimited, ai.FailureServerError, ai.FailureTimeout:
		return true
	default:
		return false
	}
}

func optionalDigest(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	return digestBytes(input)
}

func failureDigest(code string) string {
	return digestBytes([]byte(failureDigestDomain + code + "\n"))
}

func validUUIDV4(value string) bool {
	return uuidPattern.MatchString(value) && value[14] == '4' &&
		(value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b')
}

func databaseTime(value time.Time) time.Time {
	return time.UnixMicro(value.UTC().UnixMicro()).UTC()
}

func contextOrLeaseError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrLeaseLost
}

func (r Result) String() string {
	return fmt.Sprintf("analysis result{outcome:%s job:%s state:%s failure:%s}",
		r.Outcome, r.JobID, r.State, r.FailureReason)
}
