package detectionworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const failureDigestDomain = "sentinelflow detection-worker-failure-v1\n"

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

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
	detector *detection.Detector
	config   Config
	clock    Clock
	tokens   worker.TokenSource
	jitter   worker.JitterSource
}

func New(store Store, detector *detection.Detector, config Config, dependencies Dependencies) (*Runtime, error) {
	if store == nil || detector == nil || !validConfig(config) {
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
		store: store, detector: detector, config: config, clock: dependencies.Clock,
		tokens: dependencies.Tokens, jitter: dependencies.Jitter,
	}, nil
}

func validConfig(config Config) bool {
	if !identifierPattern.MatchString(config.LeaseOwner) || config.LeaseDuration <= 0 ||
		config.LeaseDuration > worker.MaxLeaseDuration || config.PollInterval <= 0 ||
		config.CloseLimit < 1 || config.CloseLimit > 1000 {
		return false
	}
	_, err := config.Backoff.Delay(1, 0)
	return err == nil
}

// Run uses one loop deliberately. PostgreSQL also permits only one live
// detection lease, which makes arrival-order recovery stable across multiple
// worker processes while unrelated worker domains remain parallel.
func (r *Runtime) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfig
	}
	for {
		result, err := r.RunOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, ErrLeaseLost) {
				continue
			}
			if errors.Is(err, ErrRetryablePersistence) {
				continue
			}
			return err
		}
		if result.Outcome != worker.OutcomeNoJob {
			continue
		}
		if _, err = r.store.CloseIdle(ctx, r.config.CloseLimit); err != nil {
			if errors.Is(err, ErrRetryablePersistence) {
				continue
			}
			return ErrPersistence
		}
		if err = r.clock.Sleep(ctx, r.config.PollInterval); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrPersistence
		}
	}
}

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
		if errors.Is(err, ErrRetryablePersistence) {
			return Result{}, err
		}
		return Result{}, ErrPersistence
	}
	if !found {
		return Result{Outcome: worker.OutcomeNoJob}, nil
	}
	result := Result{JobID: job.JobID, Attempt: job.Attempt}
	if !validLease(job, leaseRequest) {
		return result, ErrInvalidSnapshot
	}

	handlerCtx, cancel := context.WithDeadline(ctx, job.LeaseExpiresAt)
	defer cancel()
	snapshot, prepared, err := r.store.Prepare(handlerCtx, job)
	if err != nil {
		if handlerCtx.Err() != nil || ctx.Err() != nil {
			return result, contextOrLeaseError(ctx)
		}
		if errors.Is(err, ErrRetryablePersistence) {
			return r.fail(ctx, job, result, "detection_transaction_retry")
		}
		return r.fail(ctx, job, result, "detection_snapshot_unavailable")
	}
	if !prepared {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	if !validSnapshot(snapshot, job) {
		return r.fail(ctx, job, result, "detection_snapshot_invalid")
	}

	inputDigest, err := digestSnapshot(snapshot, r.detector.ConfigurationDigest())
	if err != nil {
		return r.fail(ctx, job, result, "detection_snapshot_invalid")
	}
	output, err := r.detector.Evaluate(snapshot.Input)
	if err != nil || output.ConfigurationDigest != r.detector.ConfigurationDigest() {
		return r.fail(ctx, job, result, "detection_input_invalid")
	}
	signals, incomplete := collectSignals(output)
	incomplete = incomplete || !snapshot.Input.GatewayHealth.Complete ||
		!snapshot.Input.AuthHealth.Complete
	// An incomplete observation window is not a terminal deterministic result
	// while the durable job still has attempts available. Source coverage is
	// asynchronous and may legitimately trail the event that caused this job.
	// Releasing the exact fenced lease through the ordinary worker backoff keeps
	// the retry durable without publishing a detector run, signal, or incident.
	// Independent complete-source signals are never delayed by an unrelated
	// incomplete source; those signals retain their own complete source-health
	// evidence and are finalized below.
	if len(signals) == 0 && incomplete && job.Attempt < job.MaxAttempts {
		result.RunOutcome = RunIncomplete
		return r.fail(ctx, job, result, "detection_source_coverage_incomplete")
	}
	outcome := RunComplete
	switch {
	case len(signals) == 0 && incomplete:
		outcome = RunIncomplete
	case len(snapshot.CandidateSourceIPs) == 0:
		outcome = RunNoCandidates
	}
	mutation := Mutation{
		ConfigurationVersion: output.ConfigurationVersion,
		ConfigurationDigest:  output.ConfigurationDigest,
		EvaluatedAt:          snapshot.EvaluatedAt,
		InputDigest:          inputDigest,
		Outcome:              outcome,
		Signals:              signals,
	}
	finishedAt := databaseTime(r.clock.Now())
	if !finishedAt.Before(job.LeaseExpiresAt) {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	finalized, ok, err := r.store.Finalize(ctx, FinalizeRequest{
		Job: job, Snapshot: snapshot, Mutation: mutation, FinishedAt: finishedAt,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidSnapshot) {
			return r.fail(ctx, job, result, "detection_finalize_invalid")
		}
		if errors.Is(err, ErrRetryablePersistence) {
			return r.fail(ctx, job, result, "detection_transaction_retry")
		}
		return result, ErrPersistence
	}
	if !ok {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	result.Outcome = worker.OutcomeCompleted
	result.RunOutcome = outcome
	result.SignalCount = len(finalized.Effects)
	result.IncidentMutations = finalized.IncidentMutations
	return result, nil
}

func (r *Runtime) fail(ctx context.Context, job worker.LeasedJob, result Result, code string) (Result, error) {
	now := databaseTime(r.clock.Now())
	finish := worker.FinishRequest{
		Now: now, JobID: job.JobID, LeaseToken: job.LeaseToken,
		ErrorCode: code, ErrorDigest: digestBytes([]byte(failureDigestDomain + code + "\n")),
	}
	if job.Attempt >= job.MaxAttempts {
		finish.State = worker.FinishDead
		result.Outcome = worker.OutcomeDeadLettered
	} else {
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
	finished, err := r.store.FinishFailure(ctx, finish)
	if err != nil {
		if errors.Is(err, ErrRetryablePersistence) {
			return result, err
		}
		return result, ErrPersistence
	}
	if !finished {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	result.FailureCode = code
	return result, nil
}

func collectSignals(output detection.Output) ([]detection.Signal, bool) {
	all := [][]detection.RuleEvaluation{
		output.PathScan, output.RequestBurst, output.LoginBruteForce, output.CredentialStuffing,
	}
	byID := make(map[string]detection.Signal)
	incomplete := false
	for _, evaluations := range all {
		for _, evaluation := range evaluations {
			incomplete = incomplete || evaluation.Decision == detection.DecisionIncomplete
			if evaluation.Signal != nil && evaluation.EnforcementSupporting {
				byID[evaluation.Signal.SignalID] = *evaluation.Signal
			}
		}
	}
	result := make([]detection.Signal, 0, len(byID))
	for _, signal := range byID {
		result = append(result, signal)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SignalID < result[j].SignalID })
	return result, incomplete
}

func validSnapshot(snapshot Snapshot, job worker.LeasedJob) bool {
	if snapshot.JobID != job.JobID || snapshot.AggregateType != job.AggregateType ||
		snapshot.AggregateID != job.AggregateID || snapshot.AggregateVersion != job.AggregateVersion ||
		!uuidPattern.MatchString(snapshot.BatchID) ||
		(snapshot.EndpointKind != "gateway" && snapshot.EndpointKind != "auth") ||
		!identifierPattern.MatchString(snapshot.ServiceLabel) || snapshot.EvaluatedAt.IsZero() ||
		!snapshot.Input.Now.Equal(snapshot.EvaluatedAt) || len(snapshot.CandidateSourceIPs) > 10000 {
		return false
	}
	previous := ""
	for _, value := range snapshot.CandidateSourceIPs {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || address.String() != value || value <= previous {
			return false
		}
		previous = value
	}
	return true
}

func validLease(job worker.LeasedJob, request worker.LeaseRequest) bool {
	requestedDuration := request.LeaseExpiresAt.Sub(request.Now)
	return job.Kind == worker.JobDetect &&
		(job.AggregateType == "ingest_batch" || job.AggregateType == "auth_binding") &&
		job.AggregateVersion == 1 && job.State == "leased" &&
		job.LeaseToken == request.LeaseToken && job.LeaseOwner == request.LeaseOwner &&
		job.Attempt >= 1 && job.Attempt <= job.MaxAttempts &&
		!job.LeaseGrantedAt.IsZero() && job.LeaseExpiresAt.After(job.LeaseGrantedAt) &&
		job.LeaseExpiresAt.Sub(job.LeaseGrantedAt) <= requestedDuration
}

func validUUIDV4(value string) bool {
	return uuidPattern.MatchString(value) && value[14] == '4' &&
		(value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b')
}

func digestSnapshot(snapshot Snapshot, configurationDigest string) (string, error) {
	if !digestPattern.MatchString(configurationDigest) {
		return "", ErrInvalidSnapshot
	}
	value := struct {
		SchemaVersion       string                   `json:"schema_version"`
		ConfigurationDigest string                   `json:"configuration_digest"`
		JobID               string                   `json:"job_id"`
		AggregateType       string                   `json:"aggregate_type"`
		AggregateID         string                   `json:"aggregate_id"`
		EvaluatedAt         time.Time                `json:"evaluated_at"`
		CandidateSourceIPs  []string                 `json:"candidate_source_ips"`
		GatewayEvents       []detection.GatewayEvent `json:"gateway_events"`
		AuthEvents          []detection.AuthEvent    `json:"auth_events"`
		GatewayHealth       detection.SourceHealth   `json:"gateway_health"`
		AuthHealth          detection.SourceHealth   `json:"auth_health"`
	}{
		"detection-input-v1", configurationDigest, snapshot.JobID, snapshot.AggregateType,
		snapshot.AggregateID, snapshot.EvaluatedAt.UTC(), snapshot.CandidateSourceIPs,
		snapshot.Input.GatewayEvents, snapshot.Input.AuthEvents,
		snapshot.Input.GatewayHealth, snapshot.Input.AuthHealth,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return digestBytes(encoded), nil
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
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
