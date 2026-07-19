package validationworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	failureDigestDomain               = "sentinelflow validation-worker-failure-v1\n"
	validationTimeoutCode             = "validation_attempt_timeout"
	validationFinalizeTimeoutCode     = "validation_finalize_timeout"
	validationFinalizeUnavailableCode = "validation_finalize_unavailable"
	maximumFinalizationReserve        = 5 * time.Second
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	nftVersionPattern = regexp.MustCompile(`^nftables v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
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
	store         Store
	config        Config
	clock         Clock
	tokens        worker.TokenSource
	jitter        worker.JitterSource
	protectedGate *validation.ProtectedGate
	syntaxChecker SyntaxChecker
	baseContract  []byte
	liveSchema    []byte
	demoHistory   *validation.VerifiedDemoHistoryBinding
}

func New(store Store, config Config, dependencies Dependencies) (*Runtime, error) {
	if store == nil {
		return nil, ErrAtomicStoreMissing
	}
	if !validConfig(config) || dependencies.ProtectedGate == nil ||
		dependencies.SyntaxChecker == nil {
		return nil, ErrInvalidConfig
	}
	proof, err := nftvalidate.ValidateOwnedSchema(dependencies.BaseContract, dependencies.LiveSchema)
	if err != nil || proof.BaseContractDigest() != nftvalidate.PinnedBaseChainRawDigest ||
		proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest {
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
	var demoHistory *validation.VerifiedDemoHistoryBinding
	demoStore, hasDemoStore := store.(VerifiedDemoHistoryStore)
	if hasDemoStore {
		binding, verified := demoStore.VerifiedDemoHistoryBinding()
		claims, claimsValid := binding.Claims()
		if !verified || !claimsValid ||
			(config.Environment == validation.EnvironmentDemo &&
				(claims.VerificationEnvironment != validation.EnvironmentDemo || claims.FixtureOnly)) {
			hasDemoStore = false
		} else {
			bindingCopy := binding
			demoHistory = &bindingCopy
		}
	}
	switch config.Environment {
	case validation.EnvironmentDemo:
		if !hasDemoStore {
			return nil, ErrInvalidConfig
		}
	case validation.EnvironmentTest:
		// Tests may exercise either retained or explicitly verified-demo mode.
	default:
		if hasDemoStore {
			return nil, ErrInvalidConfig
		}
	}
	return &Runtime{
		store: store, config: config, clock: dependencies.Clock,
		tokens: dependencies.Tokens, jitter: dependencies.Jitter,
		protectedGate: dependencies.ProtectedGate, syntaxChecker: dependencies.SyntaxChecker,
		baseContract: append([]byte(nil), dependencies.BaseContract...),
		liveSchema:   append([]byte(nil), dependencies.LiveSchema...),
		demoHistory:  demoHistory,
	}, nil
}

func validConfig(config Config) bool {
	if !identifierPattern.MatchString(config.LeaseOwner) ||
		config.LeaseDuration <= 0 || config.LeaseDuration > worker.MaxLeaseDuration ||
		config.PollInterval <= 0 || config.MaxConcurrency < 1 || config.MaxConcurrency > MaxConcurrency ||
		!digestPattern.MatchString(config.NFTBinaryDigest) ||
		!digestPattern.MatchString(config.ExpectedOutputSchemaDigest) ||
		!digestPattern.MatchString(config.ExpectedPromptDigest) ||
		!nftVersionPattern.MatchString(config.ExpectedNFTVersion) ||
		(config.Environment != validation.EnvironmentDevelopment &&
			config.Environment != validation.EnvironmentTest &&
			config.Environment != validation.EnvironmentDemo &&
			config.Environment != validation.EnvironmentProduction) {
		return false
	}
	_, err := config.Backoff.Delay(1, 0)
	return err == nil
}

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
	result := Result{JobID: job.JobID, AnalysisID: job.AggregateID, Attempt: job.Attempt}
	if err := validateLease(job, leaseRequest); err != nil {
		return result, err
	}

	// Stop dependency work before the database lease itself expires. This leaves
	// a bounded window in which the same lease token can atomically publish a
	// retry/dead outcome instead of abandoning a prepared claim in started state.
	handlerCtx, cancel := context.WithDeadline(ctx, handlerDeadline(job))
	defer cancel()
	snapshot, prepared, err := r.store.Prepare(handlerCtx, PrepareRequest{
		Job: job.Job, LeaseToken: job.LeaseToken,
	})
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if handlerCtx.Err() != nil {
			return r.finalizeOperationalFailure(ctx, job, result, validationTimeoutCode)
		}
		return r.finalizeOperationalFailure(ctx, job, result, "validation_snapshot_unavailable")
	}
	if !prepared {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	if snapshot.AnalysisID != job.AggregateID || !validPreparedSnapshot(snapshot) {
		return r.finalizeOperationalFailure(ctx, job, result, "validation_snapshot_conflict")
	}

	mutation := r.evaluate(handlerCtx, snapshot)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if handlerCtx.Err() != nil {
		return r.finalizeOperationalFailure(ctx, job, result, validationTimeoutCode)
	}
	result.State = mutation.State
	result.FailureCode = mutation.FailureCode
	if len(mutation.Gates) > 0 && !mutation.Gates[len(mutation.Gates)-1].Passed {
		result.FailedGate = mutation.Gates[len(mutation.Gates)-1].Name
	}
	return r.finalizeCompleted(ctx, job, result, &mutation)
}

func (r *Runtime) evaluate(ctx context.Context, snapshot Snapshot) (mutation Mutation) {
	mutation = Mutation{
		ValidationAttemptID: snapshot.ValidationAttemptID,
		AnalysisID:          snapshot.AnalysisID, IncidentID: snapshot.IncidentID,
		IncidentVersion: snapshot.IncidentVersion, State: StateInvalid,
		FailureCode: "validation_internal_failure", AuditAction: ValidationAuditRejected,
		EvidenceCanonicalBytes: append([]byte(nil), snapshot.EvidenceCanonicalBytes...),
	}
	defer func() {
		if recover() != nil {
			mutation = Mutation{
				ValidationAttemptID: snapshot.ValidationAttemptID,
				AnalysisID:          snapshot.AnalysisID, IncidentID: snapshot.IncidentID,
				IncidentVersion: snapshot.IncidentVersion, State: StateInvalid,
				FailureCode: "validation_internal_failure", AuditAction: ValidationAuditRejected,
				EvidenceCanonicalBytes: append([]byte(nil), snapshot.EvidenceCanonicalBytes...),
				Gates: []GateRecord{failedGate(1, validation.CheckStructuredOutput,
					"validation_internal_failure", snapshot.AnalysisOutputDigest)},
			}
		}
	}()

	staged, code := checkStructuredOutput(snapshot)
	if code != "" || snapshot.OutputSchemaDigest != r.config.ExpectedOutputSchemaDigest ||
		snapshot.PromptDigest != r.config.ExpectedPromptDigest {
		if code == "" {
			code = "analysis_contract_digest_mismatch"
		}
		mutation.FailureCode = code
		mutation.Gates = append(mutation.Gates,
			failedGate(1, validation.CheckStructuredOutput, code, snapshot.AnalysisOutputDigest))
		return mutation
	}
	mutation.Gates = append(mutation.Gates,
		passedGate(1, validation.CheckStructuredOutput, snapshot.AnalysisOutputDigest,
			digestGateResult(validation.CheckStructuredOutput, "ok", snapshot.AnalysisOutputDigest)))

	artifact, err := policy.BuildArtifact(staged.policyForParser, staged.candidate)
	if err != nil {
		code = policyFailureCode(err)
		mutation.FailureCode = code
		mutation.Gates = append(mutation.Gates,
			failedGate(2, validation.CheckCommandGrammar, code, snapshot.GeneratedCommandDigest))
		return mutation
	}
	pureArtifact, err := nftvalidate.Canonicalize(staged.candidate.GeneratedBytes, staged.policyForParser.TTLSeconds)
	if err != nil || !sameArtifacts(artifact, pureArtifact) {
		code = nftValidationFailureCode(err)
		if err == nil {
			code = "parser_contract_mismatch"
		}
		mutation.FailureCode = code
		mutation.Gates = append(mutation.Gates,
			failedGate(2, validation.CheckCommandGrammar, code, artifact.GeneratedDigest()))
		return mutation
	}
	mutation.Candidate = candidateRecord(staged, artifact)
	mutation.Policy = policyRecord(staged, snapshot)
	mutation.Gates = append(mutation.Gates,
		passedGate(2, validation.CheckCommandGrammar, artifact.GeneratedDigest(),
			digestGateResult(validation.CheckCommandGrammar, "ok", artifact.CanonicalDigest())))

	consistency := validation.CheckConsistency(validation.ConsistencyInput{
		ExpectedOutputSchemaDigest: r.config.ExpectedOutputSchemaDigest,
		SchemaGate: validation.SchemaGateBinding{
			Status:               validation.SchemaGatePassed,
			AnalysisOutputDigest: snapshot.AnalysisOutputDigest,
			OutputSchemaDigest:   snapshot.OutputSchemaDigest,
		},
		Analysis: validation.AnalysisBinding{
			AnalysisID: snapshot.AnalysisID, IncidentID: snapshot.IncidentID,
			IncidentVersion:     snapshot.IncidentVersion,
			AnalysisInputDigest: snapshot.AnalysisInputDigest,
			OutputSchemaDigest:  snapshot.OutputSchemaDigest,
			Output:              append([]byte(nil), snapshot.StructuredOutput...),
		},
		Policy: staged.checkedPolicy, Candidate: artifact,
		Evidence: consistencyEvidence(snapshot),
	})
	consistencyInput := digestGateResult(validation.CheckPolicyEvidenceCommandConsistency,
		"input", staged.checkedPolicy.Digest(), artifact.CanonicalDigest(), snapshot.EvidenceSnapshotDigest)
	if consistency.Status != validation.ConsistencyPassed {
		code = string(consistency.FailureCode)
		mutation.FailureCode = code
		mutation.Gates = append(mutation.Gates,
			failedGate(3, validation.CheckPolicyEvidenceCommandConsistency, code, consistencyInput))
		return mutation
	}
	mutation.Gates = append(mutation.Gates,
		passedGate(3, validation.CheckPolicyEvidenceCommandConsistency, consistencyInput,
			digestGateResult(validation.CheckPolicyEvidenceCommandConsistency, "ok",
				consistency.PolicyDigest, consistency.CanonicalCommandDigest)))

	protected := r.protectedGate.Check(validation.ProtectedInput{
		TargetIPv4: staged.policyForParser.TargetIPv4, Consistency: consistency,
	})
	if !protected.Allowed() {
		code = string(protected.Reason)
		mutation.FailureCode = code
		mutation.Gates = append(mutation.Gates,
			failedGate(4, validation.CheckProtectedNetwork, code,
				r.protectedGate.EffectiveConfigDigest()))
		return mutation
	}
	mutation.Gates = append(mutation.Gates,
		passedGate(4, validation.CheckProtectedNetwork, protected.EffectiveConfigDigest,
			digestGateResult(validation.CheckProtectedNetwork, "ok",
				protected.StaticContractDigest, protected.EffectiveConfigDigest, protected.TargetIPv4)))

	validated, err := nftvalidate.Validate(nftvalidate.Input{
		GeneratedCandidate: staged.candidate.GeneratedBytes,
		PolicyTTLSeconds:   staged.policyForParser.TTLSeconds,
		AuthorizeTarget: func(address netip.Addr) bool {
			return protected.Allowed() && address.String() == protected.TargetIPv4
		},
		BaseContract: r.baseContract, LiveSchema: r.liveSchema,
	})
	if err != nil || !sameArtifacts(artifact, validated.Artifact()) {
		code = nftValidationFailureCode(err)
		if err == nil {
			code = "owned_schema_artifact_mismatch"
		}
		mutation.FailureCode = code
		mutation.Gates = append(mutation.Gates,
			failedGate(5, validation.CheckOwnedSchemaSyntax, code, artifact.CanonicalDigest()))
		return mutation
	}
	syntaxEvidence, syntaxErr := r.syntaxChecker.Check(ctx, nftcheck.Input{
		CanonicalBytes: artifact.CanonicalBytes(), CanonicalDigest: artifact.CanonicalDigest(),
		BaseContract: r.baseContract, BaseContractDigest: nftcheck.PinnedBaseContractDigest,
	})
	if syntaxErr != nil || syntaxEvidence.NFTVersion != r.config.ExpectedNFTVersion {
		code = nftCheckFailureCode(syntaxErr)
		if syntaxErr == nil {
			code = "nft_version_mismatch"
		}
		mutation.FailureCode = code
		mutation.Gates = append(mutation.Gates,
			failedGateWithResult(5, validation.CheckOwnedSchemaSyntax, code,
				artifact.CanonicalDigest(), digestSafeValue(syntaxEvidence)))
		return mutation
	}
	schemaProof := validated.Schema()
	syntaxResultDigest := digestSafeValue(syntaxEvidence)
	mutation.Gates = append(mutation.Gates,
		passedGate(5, validation.CheckOwnedSchemaSyntax, artifact.CanonicalDigest(), syntaxResultDigest))

	history := evaluateHistory(snapshot, r.config.Environment, staged.policyForParser.TargetIPv4, r.demoHistory)
	historyValue := history.Value()
	historyInputDigest := historyValue.InputDigest
	if !digestPattern.MatchString(historyInputDigest) {
		historyInputDigest = history.Digest()
	}
	if !history.Allowed() {
		code = string(historyValue.ReasonCode)
		if code == "" {
			code = "history_input_invalid"
		}
		mutation.FailureCode = code
		mutation.Gates = append(mutation.Gates,
			failedGateWithResult(6, validation.CheckHistoricalImpact, code,
				historyInputDigest, history.Digest()))
		return mutation
	}
	mutation.Gates = append(mutation.Gates,
		passedGate(6, validation.CheckHistoricalImpact, historyInputDigest, history.Digest()))

	checks := make([]validation.ValidationCheck, len(mutation.Gates))
	for index, gate := range mutation.Gates {
		checks[index] = validation.ValidationCheck{
			CheckID: gate.Name, Result: "pass", ReasonCode: "ok", InputDigest: gate.InputDigest,
		}
	}
	nftVersion := strings.TrimPrefix(syntaxEvidence.NFTVersion, "nftables v")
	checkedSnapshot, err := validation.CheckValidationSnapshot(validation.ValidationSnapshot{
		SchemaVersion:                      validation.ValidationSnapshotSchemaVersion,
		ValidationID:                       snapshot.ValidationID,
		PolicyDigest:                       staged.checkedPolicy.Digest(),
		EvidenceSnapshotDigest:             snapshot.EvidenceSnapshotDigest,
		AnalysisInputDigest:                snapshot.AnalysisInputDigest,
		AnalysisOutputSchemaDigest:         snapshot.OutputSchemaDigest,
		PromptDigest:                       snapshot.PromptDigest,
		GeneratedCandidateDigest:           artifact.GeneratedDigest(),
		CanonicalArtifactDigest:            artifact.CanonicalDigest(),
		GrammarVersion:                     policy.CandidateSchemaVersion,
		ParserVersion:                      ValidationParserVersion,
		ValidatorVersion:                   ValidationValidatorVersion,
		BaseChainContractRawDigest:         schemaProof.BaseContractDigest(),
		LiveOwnedSchemaDigest:              schemaProof.LiveSchemaDigest(),
		ProtectedIPv4StaticDigest:          protected.StaticContractDigest,
		ProtectedIPv4EffectiveConfigDigest: protected.EffectiveConfigDigest,
		NFTBinaryDigest:                    r.config.NFTBinaryDigest,
		NFTVersion:                         nftVersion,
		HistoricalImpactDigest:             history.Digest(),
		Checks:                             checks, CreatedAt: snapshot.GeneratedAt,
		ValidUntil: snapshot.GeneratedAt.Add(validation.ValidationSnapshotLifetime),
	})
	if err != nil {
		mutation.FailureCode = "validation_snapshot_invalid"
		mutation.Gates[len(mutation.Gates)-1] = failedGateWithResult(6,
			validation.CheckHistoricalImpact, mutation.FailureCode, historyInputDigest, history.Digest())
		return mutation
	}
	mutation.State = StateValid
	mutation.FailureCode = ValidationFailureNone
	mutation.AuditAction = ValidationAuditSucceeded
	mutation.Validation = &ValidationRecord{
		CanonicalBytes: checkedSnapshot.CanonicalBytes(), SnapshotDigest: checkedSnapshot.Digest(),
		PolicyDigest:               staged.checkedPolicy.Digest(),
		EvidenceSnapshotDigest:     snapshot.EvidenceSnapshotDigest,
		AnalysisInputDigest:        snapshot.AnalysisInputDigest,
		AnalysisOutputSchemaDigest: snapshot.OutputSchemaDigest,
		PromptDigest:               snapshot.PromptDigest,
		GeneratedCandidateDigest:   artifact.GeneratedDigest(),
		CanonicalArtifactDigest:    artifact.CanonicalDigest(),
		GrammarVersion:             policy.CandidateSchemaVersion,
		ParserVersion:              ValidationParserVersion, ValidatorVersion: ValidationValidatorVersion,
		BaseChainContractRawDigest:         schemaProof.BaseContractDigest(),
		LiveOwnedSchemaDigest:              schemaProof.LiveSchemaDigest(),
		ProtectedIPv4StaticDigest:          protected.StaticContractDigest,
		ProtectedIPv4EffectiveConfigDigest: protected.EffectiveConfigDigest,
		NFTBinaryDigest:                    r.config.NFTBinaryDigest, NFTVersion: nftVersion,
		HistoricalImpactDigest: history.Digest(), TargetIPv4: protected.TargetIPv4,
		TTLSeconds: artifact.AST().TTLSeconds(), SourceHealthStatus: validation.SourceHealthComplete,
		CreatedAt:  snapshot.GeneratedAt,
		ValidUntil: snapshot.GeneratedAt.Add(validation.ValidationSnapshotLifetime),
	}
	return mutation
}

func evaluateHistory(
	snapshot Snapshot,
	environment validation.Environment,
	target string,
	demoHistory *validation.VerifiedDemoHistoryBinding,
) validation.CheckedHistoricalImpact {
	if !snapshot.History.WindowStart.Equal(snapshot.History.Cutoff.Add(-validation.HistoricalImpactLookback)) {
		return validation.EvaluateHistoricalImpact(validation.HistoricalImpactInput{})
	}
	mode := validation.HistoryModeRetained
	var cutoff validation.HistoryCutoff
	if demoHistory != nil {
		mode = validation.HistoryModeVerifiedDemo
		cutoff = demoHistory.HistoryCutoff()
		if cutoff.At().IsZero() || !cutoff.At().Equal(snapshot.History.Cutoff) {
			return validation.EvaluateHistoricalImpact(validation.HistoricalImpactInput{})
		}
	} else {
		var err error
		cutoff, err = validation.SealDatabaseHistoryCutoff(snapshot.History.Cutoff)
		if err != nil || !snapshot.History.Cutoff.Equal(snapshot.GeneratedAt) {
			return validation.EvaluateHistoricalImpact(validation.HistoricalImpactInput{})
		}
	}
	status := validation.HistoryQueryComplete
	if !snapshot.History.CoverageComplete {
		status = validation.HistoryQueryIncomplete
	}
	return validation.EvaluateHistoricalImpact(validation.HistoricalImpactInput{
		Environment: environment, Mode: mode,
		Clock: cutoff, TargetIPv4: target,
		Coverage: validation.HistoryCoverage{
			GatewayStatus: status, AuthStatus: status,
			SourceHealthStatus: status, ReceiverGapStatus: status,
			RetainedFrom: snapshot.History.WindowStart, RetainedThrough: snapshot.History.Cutoff,
		},
		GatewayRecords: append([]validation.HistoricalGatewayRecord(nil), snapshot.History.GatewayRecords...),
		AuthRecords:    append([]validation.HistoricalAuthRecord(nil), snapshot.History.AuthRecords...),
		GatewayHealth: detection.SourceHealth{
			Source: detection.SourceGateway, Complete: snapshot.History.CoverageComplete,
			CoverageStart: snapshot.History.WindowStart, CoverageEnd: snapshot.History.Cutoff,
		},
		AuthHealth: detection.SourceHealth{
			Source: detection.SourceAuth, Complete: snapshot.History.CoverageComplete,
			CoverageStart: snapshot.History.WindowStart, CoverageEnd: snapshot.History.Cutoff,
		},
		DemoHistory: demoHistory,
	})
}

func consistencyEvidence(snapshot Snapshot) validation.EvidenceSnapshotBinding {
	signals := make([]validation.SignalEvidenceBinding, len(snapshot.Evidence.Signals))
	for index, signal := range snapshot.Evidence.Signals {
		signals[index] = validation.SignalEvidenceBinding{
			SignalID: signal.SignalID, SignalDigest: signal.SignalDigest,
			SourceIPv4: signal.SourceIPv4, EventIDs: append([]string(nil), signal.EventIDs...),
			ThresholdReproduced: signal.ThresholdReproduced,
			SourceHealthStatus:  signal.SourceHealthStatus,
		}
	}
	return validation.EvidenceSnapshotBinding{
		SnapshotDigest: snapshot.EvidenceSnapshotDigest,
		IncidentID:     snapshot.IncidentID, IncidentVersion: snapshot.IncidentVersion,
		AnalysisInputDigest: snapshot.AnalysisInputDigest,
		SourceIPv4:          snapshot.Evidence.SourceIPv4,
		SourceHealthDigest:  snapshot.Evidence.SourceHealthDigest,
		SourceHealthStatus:  snapshot.Evidence.SourceHealthStatus,
		SignalIDs:           append([]string(nil), snapshot.Evidence.SignalIDs...),
		EventIDs:            append([]string(nil), snapshot.Evidence.EventIDs...), Signals: signals,
	}
}

func candidateRecord(staged stagedOutput, artifact policy.Artifact) *CandidateRecord {
	return &CandidateRecord{
		SchemaVersion: policy.CandidateSchemaVersion,
		TargetIPv4:    artifact.AST().TargetIPv4(), TimeoutToken: staged.candidate.TimeoutToken,
		TTLSeconds: artifact.AST().TTLSeconds(), GeneratedBytes: artifact.GeneratedBytes(),
		GeneratedDigest: artifact.GeneratedDigest(), CanonicalBytes: artifact.CanonicalBytes(),
		CanonicalDigest: artifact.CanonicalDigest(),
	}
}

func policyRecord(staged stagedOutput, snapshot Snapshot) *PolicyRecord {
	value := staged.checkedPolicy.Value()
	return &PolicyRecord{
		SchemaVersion: value.SchemaVersion, PolicyID: snapshot.PolicyID,
		PolicyVersion: value.PolicyVersion, CanonicalBytes: staged.checkedPolicy.CanonicalBytes(),
		PolicyDigest: staged.checkedPolicy.Digest(), TargetIPv4: value.TargetIPv4,
		TTLSeconds: value.TTLSeconds, Rationale: staged.rationale,
	}
}

func sameArtifacts(left policy.Artifact, right nftvalidate.Artifact) bool {
	return left.GeneratedDigest() == right.GeneratedDigest() &&
		left.CanonicalDigest() == right.CanonicalDigest() &&
		left.AST().TargetIPv4() == right.TargetIPv4() &&
		left.AST().TTLSeconds() == right.TTLSeconds() &&
		left.AST().InputTTLToken() == right.InputTTLToken() &&
		left.CanonicalTTLToken() == right.CanonicalTTLToken() &&
		string(left.GeneratedBytes()) == string(right.GeneratedBytes()) &&
		string(left.CanonicalBytes()) == string(right.CanonicalBytes())
}

func passedGate(order uint8, name validation.ValidationCheckID, inputDigest, resultDigest string) GateRecord {
	return GateRecord{Order: order, Name: name, Passed: true, ResultCode: "ok", InputDigest: inputDigest, ResultDigest: resultDigest}
}

func failedGate(order uint8, name validation.ValidationCheckID, code, inputDigest string) GateRecord {
	return failedGateWithResult(order, name, code, inputDigest,
		digestGateResult(name, code, inputDigest))
}

func failedGateWithResult(order uint8, name validation.ValidationCheckID, code, inputDigest, resultDigest string) GateRecord {
	if !digestPattern.MatchString(inputDigest) {
		inputDigest = digestBytes(nil)
	}
	if !digestPattern.MatchString(resultDigest) {
		resultDigest = digestGateResult(name, code, inputDigest)
	}
	return GateRecord{Order: order, Name: name, Passed: false, ResultCode: sanitizeCode(code), InputDigest: inputDigest, ResultDigest: resultDigest}
}

func digestGateResult(name validation.ValidationCheckID, values ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("sentinelflow-validation-gate-result-v1\x00"))
	_, _ = hash.Write([]byte(name))
	for _, value := range values {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func digestSafeValue(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return digestBytes(nil)
	}
	return digestBytes(data)
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sanitizeCode(value string) string {
	if identifierPattern.MatchString(value) {
		return value
	}
	return "validation_failure"
}

func policyFailureCode(err error) string {
	var typed *policy.Error
	if errors.As(err, &typed) && typed != nil {
		return sanitizeCode(string(typed.Code))
	}
	return "command_grammar_invalid"
}

func nftValidationFailureCode(err error) string {
	var typed *nftvalidate.Error
	if errors.As(err, &typed) && typed != nil {
		return sanitizeCode(string(typed.Code))
	}
	return "owned_schema_validation_failed"
}

func nftCheckFailureCode(err error) string {
	var typed *nftcheck.Error
	if errors.As(err, &typed) && typed != nil {
		return sanitizeCode(string(typed.Code))
	}
	return "nft_syntax_check_failed"
}

func validPreparedSnapshot(snapshot Snapshot) bool {
	if !uuidPattern.MatchString(snapshot.ValidationAttemptID) ||
		!uuidPattern.MatchString(snapshot.PolicyID) || !uuidPattern.MatchString(snapshot.ValidationID) ||
		!uuidPattern.MatchString(snapshot.CommandCandidateID) ||
		!uuidPattern.MatchString(snapshot.AnalysisID) || !uuidPattern.MatchString(snapshot.IncidentID) ||
		snapshot.IncidentVersion == 0 || snapshot.GeneratedAt.IsZero() ||
		!uuidPattern.MatchString(snapshot.EvidenceSnapshotID) ||
		!digestPattern.MatchString(snapshot.EvidenceSnapshotDigest) ||
		!digestPattern.MatchString(snapshot.AnalysisInputDigest) ||
		!digestPattern.MatchString(snapshot.OutputSchemaDigest) ||
		!digestPattern.MatchString(snapshot.PromptDigest) ||
		!digestPattern.MatchString(snapshot.AnalysisOutputDigest) ||
		!digestPattern.MatchString(snapshot.GeneratedCommandDigest) ||
		!digestPattern.MatchString(snapshot.Evidence.SourceHealthDigest) ||
		(snapshot.Evidence.SourceHealthStatus != validation.SourceHealthComplete &&
			snapshot.Evidence.SourceHealthStatus != "incomplete") ||
		!validEvidenceIDs(snapshot.Evidence.SignalIDs) || len(snapshot.Evidence.Signals) != len(snapshot.Evidence.SignalIDs) ||
		!validOrderedUUIDs(snapshot.Evidence.EventIDs, 0) ||
		len(snapshot.History.GatewayRecords) > MaxHistoricalGatewayRows ||
		len(snapshot.History.AuthRecords) > MaxHistoricalAuthRows ||
		snapshot.History.Cutoff.IsZero() ||
		!snapshot.History.WindowStart.Equal(snapshot.History.Cutoff.Add(-validation.HistoricalImpactLookback)) {
		return false
	}
	checkedEvidence, err := validation.ParseCanonicalEvidenceSnapshot(snapshot.EvidenceCanonicalBytes)
	if err != nil || checkedEvidence.Digest() != snapshot.EvidenceSnapshotDigest {
		return false
	}
	evidence := checkedEvidence.Value()
	if evidence.SnapshotID != snapshot.EvidenceSnapshotID ||
		evidence.IncidentID != snapshot.IncidentID ||
		evidence.IncidentVersion != snapshot.IncidentVersion ||
		evidence.SourceIPv4 != snapshot.Evidence.SourceIPv4 ||
		evidence.ServiceLabel != snapshot.Evidence.ServiceLabel ||
		evidence.SourceHealthDigest != snapshot.Evidence.SourceHealthDigest ||
		!equalStrings(evidence.SignalIDs, snapshot.Evidence.SignalIDs) ||
		!equalStrings(evidence.EventIDs, snapshot.Evidence.EventIDs) {
		return false
	}
	for index, signal := range snapshot.Evidence.Signals {
		if signal.SignalID != snapshot.Evidence.SignalIDs[index] ||
			!digestPattern.MatchString(signal.SignalDigest) ||
			signal.SourceIPv4 != snapshot.Evidence.SourceIPv4 ||
			!validOrderedUUIDs(signal.EventIDs, 0) ||
			(signal.SourceHealthStatus != validation.SourceHealthComplete &&
				signal.SourceHealthStatus != "incomplete") {
			return false
		}
	}
	return true
}

func (r *Runtime) finalizeCompleted(ctx context.Context, job worker.LeasedJob, result Result, mutation *Mutation) (Result, error) {
	now := databaseTime(r.clock.Now())
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if !now.Before(job.LeaseExpiresAt) {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	finalizeCtx, cancel := context.WithDeadline(ctx, handlerDeadline(job))
	defer cancel()
	finished, err := r.store.Finalize(finalizeCtx, FinalizeRequest{
		Finish: worker.FinishRequest{
			State: worker.FinishCompleted, Now: now, JobID: job.JobID, LeaseToken: job.LeaseToken,
		},
		Mutation: mutation,
	})
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if finalizeCtx.Err() != nil {
			return r.finalizeAfterAmbiguousCompleted(
				ctx, job, result, validationFinalizeTimeoutCode,
			)
		}
		if errors.Is(err, ErrRetryablePersistence) {
			return r.finalizeAfterAmbiguousCompleted(
				ctx, job, result, validationFinalizeUnavailableCode,
			)
		}
		return result, ErrPersistence
	}
	if !finished {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	result.Outcome = worker.OutcomeCompleted
	return result, nil
}

// finalizeAfterAmbiguousCompleted tries to publish a mutation-free terminal
// outcome after the mutation-bearing Finalize returned an error. That first
// result is commit-ambiguous: if the fallback cannot prove that it won the same
// lease, report lease loss rather than treating either mutation as unpublished.
func (r *Runtime) finalizeAfterAmbiguousCompleted(
	ctx context.Context,
	job worker.LeasedJob,
	result Result,
	code string,
) (Result, error) {
	fallback, err := r.finalizeOperationalFailure(ctx, job, result, code)
	if err == nil || ctx.Err() != nil {
		return fallback, err
	}
	fallback.Outcome = worker.OutcomeLeaseLost
	return fallback, ErrLeaseLost
}

func (r *Runtime) finalizeOperationalFailure(ctx context.Context, job worker.LeasedJob, result Result, code string) (Result, error) {
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
	result.State = ""
	result.FailedGate = ""
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
	finalizeCtx, cancel := context.WithDeadline(ctx, job.LeaseExpiresAt)
	defer cancel()
	finished, err := r.store.Finalize(finalizeCtx, FinalizeRequest{Finish: finish})
	if err != nil {
		if finalizeCtx.Err() != nil {
			return result, contextOrLeaseError(ctx)
		}
		return result, ErrPersistence
	}
	if !finished {
		result.Outcome = worker.OutcomeLeaseLost
		return result, ErrLeaseLost
	}
	return result, nil
}

func handlerDeadline(job worker.LeasedJob) time.Time {
	duration := job.LeaseExpiresAt.Sub(job.LeaseGrantedAt)
	reserve := duration / 5
	if reserve <= 0 {
		reserve = duration
	}
	if reserve > maximumFinalizationReserve {
		reserve = maximumFinalizationReserve
	}
	return job.LeaseExpiresAt.Add(-reserve)
}

func validateLease(job worker.LeasedJob, request worker.LeaseRequest) error {
	duration := request.LeaseExpiresAt.Sub(request.Now)
	if !uuidPattern.MatchString(job.JobID) || job.Kind != worker.JobValidate ||
		job.AggregateType != ValidationAggregateType || !uuidPattern.MatchString(job.AggregateID) ||
		job.AggregateVersion != 1 || job.State != "leased" || job.LeaseToken != request.LeaseToken ||
		job.LeaseOwner != request.LeaseOwner || job.LeaseGrantedAt.IsZero() ||
		!job.LeaseExpiresAt.After(job.LeaseGrantedAt) ||
		job.LeaseExpiresAt.Sub(job.LeaseGrantedAt) != duration || duration <= 0 ||
		duration > worker.MaxLeaseDuration || job.Attempt < 1 || job.MaxAttempts < 1 ||
		job.Attempt > job.MaxAttempts {
		if job.Kind != worker.JobValidate {
			return ErrUnexpectedJobKind
		}
		return ErrInvalidLease
	}
	return nil
}

func validUUIDV4(value string) bool {
	return uuidPattern.MatchString(value) && value[14] == '4' &&
		(value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b')
}

func databaseTime(value time.Time) time.Time {
	return time.UnixMicro(value.UTC().UnixMicro()).UTC()
}

func failureDigest(code string) string {
	return digestBytes([]byte(failureDigestDomain + code + "\n"))
}

func contextOrLeaseError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrLeaseLost
}

func (r Result) String() string {
	return fmt.Sprintf("validation result{outcome:%s job:%s state:%s failure:%s}",
		r.Outcome, r.JobID, r.State, r.FailureCode)
}
