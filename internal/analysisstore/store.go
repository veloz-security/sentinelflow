// Package analysisstore implements the PostgreSQL persistence boundary for
// asynchronous OpenAI incident analysis.
package analysisstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/worker"
)

const (
	leaseSQL = `
SELECT job_id::text, kind, aggregate_type, aggregate_id::text,
    aggregate_version, state, available_at, lease_token::text,
    lease_owner, updated_at, lease_expires_at, attempts, max_attempts
FROM sentinelflow.lease_analysis_outbox_job($1, $2::uuid, $3, $4)`
	prepareSQL = `
SELECT status, snapshot
FROM sentinelflow.prepare_analysis_attempt($1::uuid, $2::uuid)`
	prepareVerifiedDemoSQL = `
SELECT status, snapshot
FROM sentinelflow.prepare_analysis_attempt_verified_demo_000030(
    $1::uuid, $2::uuid, $3::bytea,
    $4::uuid, $5::uuid, $6::uuid,
    $7, $8, $9, $10, $11, $12, $13, $14, $15,
    $16::timestamptz, $17::timestamptz, $18::timestamptz, $19::timestamptz,
    $20, $21
)`
	finalizeSQL = `
SELECT job_id::text, state
FROM sentinelflow.finalize_analysis_attempt(
    $1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::jsonb
)`
)

var (
	uuidPattern           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	asciiIDPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	digestPattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	servicePattern        = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	rulePattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	responseIDPattern     = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,128}$`)
	stubResponseIDPattern = regexp.MustCompile(`^stub_[0-9a-f]{64}$`)

	// ErrInvalidRequest contains no request data and is safe to expose to the
	// worker runtime or ordinary logs.
	ErrInvalidRequest = errors.New("analysis store: invalid request")
	// ErrPersistence deliberately does not wrap the PostgreSQL error, whose
	// detail could contain persisted identifiers or output fragments.
	ErrPersistence = errors.New("analysis store: persistence unavailable")
	ErrInvalidRow  = errors.New("analysis store: invalid persistence result")

	ruleClassifications = map[string]string{
		"path_scan.v1": "path_scan", "request_burst.v1": "request_burst",
		"login_bruteforce.v1":    "brute_force",
		"credential_stuffing.v1": "credential_stuffing",
	}
)

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// PostgreSQLStore accesses analysis state exclusively through narrow
// SECURITY DEFINER functions. It never issues direct table mutations.
type PostgreSQLStore struct {
	db             queryRower
	demoActivation *validation.ActivatedDemoHistoryBinding
	demoClaims     validation.DemoHistoryBindingClaims
}

func (s *PostgreSQLStore) String() string {
	if s == nil {
		return "analysisstore.PostgreSQLStore[INVALID]"
	}
	return "analysisstore.PostgreSQLStore[REDACTED]"
}

func (s *PostgreSQLStore) GoString() string { return s.String() }
func (s *PostgreSQLStore) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(s.String()))
}

// NewPostgreSQLActivatedDemoStore accepts only an opaque, HMAC-bound,
// database-receipted analysis activation. The production two-argument prepare
// path remains unchanged and is never selected from public proof claims alone.
func NewPostgreSQLActivatedDemoStore(
	db queryRower,
	activation validation.ActivatedDemoHistoryBinding,
) (*PostgreSQLStore, error) {
	if db == nil || activation.Consumer() != validation.DemoHistoryConsumerAnalysis {
		return nil, ErrInvalidRequest
	}
	claims, claimsOK := activation.Claims()
	secret, secretOK := activation.ActivationSecret()
	clear(secret)
	if !claimsOK || !secretOK || !validDemoClaims(claims) {
		return nil, ErrInvalidRequest
	}
	activationCopy := activation
	return &PostgreSQLStore{db: db, demoActivation: &activationCopy, demoClaims: claims}, nil
}

func NewPostgreSQLStore(db queryRower) (*PostgreSQLStore, error) {
	if db == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgreSQLStore{db: db}, nil
}

var _ analysisworker.Store = (*PostgreSQLStore)(nil)

func (s *PostgreSQLStore) Lease(
	ctx context.Context,
	request worker.LeaseRequest,
) (worker.LeasedJob, bool, error) {
	if ctx == nil || !validLeaseRequest(request) {
		return worker.LeasedJob{}, false, ErrInvalidRequest
	}
	var job worker.LeasedJob
	var kind, token string
	err := s.db.QueryRow(ctx, leaseSQL,
		request.Now.UTC(), request.LeaseToken, request.LeaseOwner,
		request.LeaseExpiresAt.UTC(),
	).Scan(
		&job.JobID, &kind, &job.AggregateType, &job.AggregateID,
		&job.AggregateVersion, &job.State, &job.AvailableAt, &token,
		&job.LeaseOwner, &job.LeaseGrantedAt, &job.LeaseExpiresAt,
		&job.Attempt, &job.MaxAttempts,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return worker.LeasedJob{}, false, nil
	}
	if err != nil {
		return worker.LeasedJob{}, false, ErrPersistence
	}
	job.Kind = worker.JobKind(kind)
	job.LeaseToken = token
	if !validLeasedRow(job, request) {
		return worker.LeasedJob{}, false, ErrInvalidRow
	}
	return job, true, nil
}

func (s *PostgreSQLStore) Prepare(
	ctx context.Context,
	request analysisworker.PrepareRequest,
) (analysisworker.Snapshot, bool, error) {
	if ctx == nil || !validPrepareRequest(request) {
		return analysisworker.Snapshot{}, false, ErrInvalidRequest
	}
	query := prepareSQL
	arguments := []any{request.Job.JobID, request.LeaseToken}
	if s.demoActivation != nil {
		secret, ok := s.demoActivation.ActivationSecret()
		claimsDigest, digestOK := s.demoActivation.ClaimsDigest()
		if !ok || !digestOK || s.demoActivation.Consumer() != validation.DemoHistoryConsumerAnalysis {
			return analysisworker.Snapshot{}, false, ErrInvalidRequest
		}
		defer clear(secret)
		query = prepareVerifiedDemoSQL
		arguments = append(arguments, secret)
		arguments = append(arguments, demoPrepareArguments(s.demoClaims)...)
		arguments = append(arguments, claimsDigest)
	}
	var status string
	var document []byte
	err := s.db.QueryRow(ctx, query, arguments...).
		Scan(&status, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		return analysisworker.Snapshot{}, false, nil
	}
	if err != nil {
		return analysisworker.Snapshot{}, false, ErrPersistence
	}
	if status != "prepared" {
		if status == "interrupted" || status == "no_call" || status == "terminal" {
			return analysisworker.Snapshot{}, false, nil
		}
		return analysisworker.Snapshot{}, false, ErrInvalidRow
	}
	var snapshot analysisworker.Snapshot
	if s.demoActivation == nil {
		snapshot, err = decodeSnapshot(document)
	} else {
		snapshot, err = decodeDemoSnapshot(document, s.demoClaims)
	}
	if err != nil || snapshot.IncidentID != request.Job.AggregateID ||
		snapshot.IncidentVersion != request.Job.AggregateVersion {
		return analysisworker.Snapshot{}, false, ErrInvalidRow
	}
	return snapshot, true, nil
}

func (s *PostgreSQLStore) Finalize(
	ctx context.Context,
	request analysisworker.FinalizeRequest,
) (bool, error) {
	if ctx == nil || !validFinish(request.Finish) || !validMutation(request.Mutation) ||
		(request.Mutation == nil) == (request.Finish.State == worker.FinishCompleted) {
		return false, ErrInvalidRequest
	}
	payload, err := encodeMutation(request.Mutation)
	if err != nil {
		return false, ErrInvalidRequest
	}
	var retryAt any
	if request.Finish.RetryAt != nil {
		retryAt = request.Finish.RetryAt.UTC()
	}
	var code, digest any
	if request.Finish.State != worker.FinishCompleted {
		code, digest = request.Finish.ErrorCode, request.Finish.ErrorDigest
	}
	var jobID, state string
	err = s.db.QueryRow(ctx, finalizeSQL,
		request.Finish.JobID, request.Finish.LeaseToken,
		string(request.Finish.State), retryAt, request.Finish.Now.UTC(),
		code, digest, payload,
	).Scan(&jobID, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, ErrPersistence
	}
	if jobID != request.Finish.JobID || state != string(request.Finish.State) {
		return false, ErrInvalidRow
	}
	return true, nil
}

type snapshotDocument struct {
	IncidentID             string           `json:"incident_id"`
	IncidentVersion        int32            `json:"incident_version"`
	AnalysisID             string           `json:"analysis_id"`
	GeneratedAt            time.Time        `json:"generated_at"`
	EvidenceSnapshotID     string           `json:"evidence_snapshot_id"`
	EvidenceSnapshotDigest string           `json:"evidence_snapshot_digest"`
	SourceIP               string           `json:"source_ip"`
	ServiceLabel           string           `json:"service_label"`
	WindowStart            time.Time        `json:"window_start"`
	WindowEnd              time.Time        `json:"window_end"`
	DetectorConfigVersion  string           `json:"detector_config_version"`
	Signals                []signalDocument `json:"signals"`
	HistoricalImpact       struct {
		LookbackStart time.Time `json:"lookback_start"`
		LookbackEnd   time.Time `json:"lookback_end"`
		ImpactDigest  string    `json:"impact_digest"`
	} `json:"historical_impact"`
}

type signalDocument struct {
	SignalID                    string    `json:"signal_id"`
	RuleID                      string    `json:"rule_id"`
	Classification              string    `json:"classification"`
	WindowStart                 time.Time `json:"window_start"`
	WindowEnd                   time.Time `json:"window_end"`
	EventCount                  int64     `json:"event_count"`
	DistinctAccountCount        int64     `json:"distinct_account_count"`
	DistinctSuspiciousPathCount int64     `json:"distinct_suspicious_path_count"`
	EvidenceDigest              string    `json:"evidence_digest"`
}

func decodeSnapshot(document []byte) (analysisworker.Snapshot, error) {
	return decodeSnapshotForHistory(document, nil)
}

func decodeDemoSnapshot(
	document []byte,
	claims validation.DemoHistoryBindingClaims,
) (analysisworker.Snapshot, error) {
	return decodeSnapshotForHistory(document, &claims)
}

func decodeSnapshotForHistory(
	document []byte,
	demoClaims *validation.DemoHistoryBindingClaims,
) (analysisworker.Snapshot, error) {
	if len(document) < 2 || len(document) > 64*1024 || !utf8.Valid(document) {
		return analysisworker.Snapshot{}, ErrInvalidRow
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var decoded snapshotDocument
	if err := decoder.Decode(&decoded); err != nil {
		return analysisworker.Snapshot{}, ErrInvalidRow
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return analysisworker.Snapshot{}, ErrInvalidRow
	}
	signals := make([]analysisworker.Signal, len(decoded.Signals))
	for index, signal := range decoded.Signals {
		signals[index] = analysisworker.Signal{
			SignalID: signal.SignalID, RuleID: signal.RuleID,
			Classification: signal.Classification, WindowStart: signal.WindowStart.UTC(),
			WindowEnd: signal.WindowEnd.UTC(), EventCount: signal.EventCount,
			DistinctAccountCount:        signal.DistinctAccountCount,
			DistinctSuspiciousPathCount: signal.DistinctSuspiciousPathCount,
			EvidenceDigest:              signal.EvidenceDigest,
		}
	}
	snapshot := analysisworker.Snapshot{
		IncidentID: decoded.IncidentID, IncidentVersion: decoded.IncidentVersion,
		AnalysisID: decoded.AnalysisID, GeneratedAt: decoded.GeneratedAt.UTC(),
		EvidenceSnapshotID:     decoded.EvidenceSnapshotID,
		EvidenceSnapshotDigest: decoded.EvidenceSnapshotDigest,
		SourceIP:               decoded.SourceIP, ServiceLabel: decoded.ServiceLabel,
		WindowStart: decoded.WindowStart.UTC(), WindowEnd: decoded.WindowEnd.UTC(),
		DetectorConfigVersion: decoded.DetectorConfigVersion,
		Signals:               signals,
		HistoricalImpact: analysisworker.HistoricalImpact{
			LookbackStart: decoded.HistoricalImpact.LookbackStart.UTC(),
			LookbackEnd:   decoded.HistoricalImpact.LookbackEnd.UTC(),
			ImpactDigest:  decoded.HistoricalImpact.ImpactDigest,
		},
	}
	if !validSnapshotForHistory(snapshot, demoClaims) {
		return analysisworker.Snapshot{}, ErrInvalidRow
	}
	return snapshot, nil
}

func validSnapshotForHistory(
	snapshot analysisworker.Snapshot,
	demoClaims *validation.DemoHistoryBindingClaims,
) bool {
	historyShapeValid := snapshot.HistoricalImpact.LookbackEnd.Equal(snapshot.GeneratedAt)
	if demoClaims != nil {
		historyShapeValid = validDemoClaims(*demoClaims) &&
			snapshot.HistoricalImpact.LookbackStart.Equal(demoClaims.CoverageStart) &&
			snapshot.HistoricalImpact.LookbackEnd.Equal(demoClaims.CoverageEnd)
	}
	address, err := netip.ParseAddr(snapshot.SourceIP)
	if err != nil || !address.Is4() || address.String() != snapshot.SourceIP ||
		!uuidPattern.MatchString(snapshot.IncidentID) || snapshot.IncidentVersion < 1 ||
		!uuidPattern.MatchString(snapshot.AnalysisID) ||
		!uuidPattern.MatchString(snapshot.EvidenceSnapshotID) ||
		!digestPattern.MatchString(snapshot.EvidenceSnapshotDigest) ||
		!servicePattern.MatchString(snapshot.ServiceLabel) ||
		!asciiIDPattern.MatchString(snapshot.DetectorConfigVersion) ||
		snapshot.GeneratedAt.IsZero() || snapshot.WindowStart.IsZero() ||
		snapshot.WindowEnd.Before(snapshot.WindowStart) || snapshot.WindowEnd.After(snapshot.GeneratedAt) ||
		len(snapshot.Signals) < 1 ||
		len(snapshot.Signals) > analysisworker.MaxSignals ||
		snapshot.HistoricalImpact.LookbackStart.IsZero() ||
		!snapshot.HistoricalImpact.LookbackEnd.After(snapshot.HistoricalImpact.LookbackStart) ||
		!historyShapeValid ||
		snapshot.HistoricalImpact.LookbackEnd.Sub(snapshot.HistoricalImpact.LookbackStart) != 24*time.Hour ||
		!digestPattern.MatchString(snapshot.HistoricalImpact.ImpactDigest) {
		return false
	}
	previous := ""
	for _, signal := range snapshot.Signals {
		if !uuidPattern.MatchString(signal.SignalID) || signal.SignalID <= previous ||
			!rulePattern.MatchString(signal.RuleID) || !validRuleClassification(signal.RuleID, signal.Classification) ||
			signal.WindowStart.IsZero() || signal.WindowEnd.Before(signal.WindowStart) ||
			signal.WindowStart.Before(snapshot.WindowStart) || signal.WindowEnd.After(snapshot.WindowEnd) ||
			signal.EventCount < 1 || signal.EventCount > 1_000_000 ||
			signal.DistinctAccountCount < 0 || signal.DistinctAccountCount > 1_000_000 ||
			signal.DistinctSuspiciousPathCount < 0 || signal.DistinctSuspiciousPathCount > 8 ||
			!digestPattern.MatchString(signal.EvidenceDigest) {
			return false
		}
		previous = signal.SignalID
	}
	return true
}

func validDemoClaims(value validation.DemoHistoryBindingClaims) bool {
	return value.SchemaVersion == validation.DemoHistoryManifestSchemaVersion &&
		value.Profile == validation.DemoHistoryProfile && !value.FixtureOnly &&
		value.VerificationEnvironment == validation.EnvironmentDemo &&
		uuidPattern.MatchString(value.ManifestID) &&
		value.DatasetID == validation.PinnedDemoHistoryDatasetID &&
		uuidPattern.MatchString(value.ImportID) &&
		value.DatasetSchemaVersion == validation.DemoHistoryDatasetSchemaVersion &&
		value.DatasetLocator == validation.DemoHistoryDatasetLocator &&
		value.PathCatalogVersion == "path-catalog-v1" &&
		value.DatasetRecordCount == validation.PinnedDemoHistoryDatasetRecordCount &&
		value.RawFileDigest == validation.PinnedDemoHistoryRawFileDigest &&
		value.DatasetDigest == validation.PinnedDemoHistoryDatasetDigest &&
		value.ImportedRowsDigest == validation.PinnedDemoHistoryImportedRowsDigest &&
		value.ManifestSourceHealthDigest == validation.PinnedDemoHistorySourceHealthDigest &&
		value.ImpactSourceHealthDigest == validation.PinnedDemoHistoryImpactSourceHealthDigest &&
		digestPattern.MatchString(value.ManifestDigest) && digestPattern.MatchString(value.RunScopeDigest) &&
		digestPattern.MatchString(value.PublicKeyDigest) && digestPattern.MatchString(value.SignatureVerificationDigest) &&
		!value.ClockAt.IsZero() && value.ClockAt.Equal(value.CoverageEnd) &&
		value.CoverageStart.Equal(value.ClockAt.Add(-validation.HistoricalImpactLookback)) &&
		!value.IssuedAt.IsZero() && !value.IssuedAt.Before(value.CoverageEnd)
}

func demoPrepareArguments(value validation.DemoHistoryBindingClaims) []any {
	return []any{
		value.ImportID, value.ManifestID, value.DatasetID,
		value.RawFileDigest, value.DatasetDigest, value.ImportedRowsDigest,
		value.DatasetRecordCount, value.ManifestSourceHealthDigest, value.ManifestDigest,
		value.RunScopeDigest, value.PublicKeyDigest, value.SignatureVerificationDigest,
		value.ClockAt.Round(0).UTC(), value.IssuedAt.Round(0).UTC(),
		value.CoverageStart.Round(0).UTC(), value.CoverageEnd.Round(0).UTC(),
		value.ImpactSourceHealthDigest,
	}
}

func validRuleClassification(rule, classification string) bool {
	return validClassification(classification) && ruleClassifications[rule] == classification
}

func validClassification(value string) bool {
	switch value {
	case "credential_stuffing", "brute_force", "path_scan", "request_burst":
		return true
	default:
		return false
	}
}

func validLeaseRequest(request worker.LeaseRequest) bool {
	duration := request.LeaseExpiresAt.Sub(request.Now)
	return !request.Now.IsZero() && duration > 0 && duration <= worker.MaxLeaseDuration &&
		validUUIDV4(request.LeaseToken) && asciiIDPattern.MatchString(request.LeaseOwner)
}

func validLeasedRow(job worker.LeasedJob, request worker.LeaseRequest) bool {
	return uuidPattern.MatchString(job.JobID) && job.Kind == worker.JobAnalyze &&
		job.AggregateType == "incident" && uuidPattern.MatchString(job.AggregateID) &&
		job.AggregateVersion > 0 && job.State == "leased" &&
		job.LeaseToken == request.LeaseToken && job.LeaseOwner == request.LeaseOwner &&
		!job.LeaseGrantedAt.IsZero() &&
		job.LeaseExpiresAt.Sub(job.LeaseGrantedAt) == request.LeaseExpiresAt.Sub(request.Now) &&
		job.Attempt > 0 && job.Attempt <= job.MaxAttempts
}

func validPrepareRequest(request analysisworker.PrepareRequest) bool {
	return uuidPattern.MatchString(request.Job.JobID) && request.Job.Kind == worker.JobAnalyze &&
		request.Job.AggregateType == "incident" && uuidPattern.MatchString(request.Job.AggregateID) &&
		request.Job.AggregateVersion > 0 && request.Job.Attempt > 0 &&
		request.Job.Attempt <= request.Job.MaxAttempts && validUUIDV4(request.LeaseToken)
}

func validFinish(finish worker.FinishRequest) bool {
	if finish.Now.IsZero() || !uuidPattern.MatchString(finish.JobID) ||
		!validUUIDV4(finish.LeaseToken) {
		return false
	}
	switch finish.State {
	case worker.FinishCompleted:
		return finish.RetryAt == nil && finish.ErrorCode == "" && finish.ErrorDigest == ""
	case worker.FinishRetry:
		return finish.RetryAt != nil && !finish.RetryAt.Before(finish.Now) &&
			asciiIDPattern.MatchString(finish.ErrorCode) && digestPattern.MatchString(finish.ErrorDigest)
	case worker.FinishDead:
		return finish.RetryAt == nil && asciiIDPattern.MatchString(finish.ErrorCode) &&
			digestPattern.MatchString(finish.ErrorDigest)
	default:
		return false
	}
}

func validMutation(mutation *analysisworker.Mutation) bool {
	if mutation == nil {
		return true
	}
	if !uuidPattern.MatchString(mutation.IncidentID) || mutation.IncidentVersion < 1 ||
		!uuidPattern.MatchString(mutation.AnalysisID) ||
		!uuidPattern.MatchString(mutation.EvidenceSnapshotID) ||
		!digestPattern.MatchString(mutation.EvidenceSnapshotDigest) ||
		!asciiIDPattern.MatchString(mutation.AuditAction) ||
		(mutation.Success == nil) == (mutation.Failure == nil) {
		return false
	}
	if mutation.Success != nil {
		return mutation.State == analysisworker.StateReviewReady &&
			mutation.AuditAction == "analysis_succeeded" && mutation.ValidationRequested &&
			validSuccess(mutation.Success)
	}
	return mutation.State == analysisworker.StateAnalysisFailed &&
		mutation.AuditAction == "analysis_failed" && !mutation.ValidationRequested &&
		validFailure(mutation.Failure)
}

func validSuccess(success *analysisworker.Success) bool {
	identity, validIdentity := ai.ParseProviderIdentity(
		success.ProviderKind, success.AdapterID, success.Model,
		success.ReasoningEffort, success.RateCardVersion,
	)
	if !validIdentity ||
		!responseIDPattern.MatchString(success.ResponseID) || strings.TrimSpace(success.ResponseID) != success.ResponseID ||
		success.Attempts < 1 || success.Attempts > 2 ||
		success.InputBytes < 2 || success.InputBytes > ai.MaxInputBytes ||
		!digestPattern.MatchString(success.InputDigest) ||
		!digestPattern.MatchString(success.InputSchemaDigest) ||
		!digestPattern.MatchString(success.PromptDigest) ||
		!digestPattern.MatchString(success.OutputSchemaDigest) ||
		!digestPattern.MatchString(success.OutputDigest) ||
		!digestPattern.MatchString(success.GeneratedCommandDigest) ||
		len(success.AnalysisJSON) < 2 || len(success.AnalysisJSON) > 1<<20 ||
		len(success.PolicyJSON) < 2 || len(success.PolicyJSON) > 64*1024 ||
		len(success.CommandCandidateJSON) < 2 || len(success.CommandCandidateJSON) > 64*1024 ||
		len(success.EvidenceIDs) < 1 || len(success.EvidenceIDs) > ai.MaxEvidenceRefs {
		return false
	}
	if strictJSONObject(success.AnalysisJSON) != nil || strictJSONObject(success.PolicyJSON) != nil ||
		strictJSONObject(success.CommandCandidateJSON) != nil ||
		sha256Digest(success.AnalysisJSON) != success.OutputDigest {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(success.CommandCandidateJSON))
	decoder.DisallowUnknownFields()
	var candidate struct {
		SchemaVersion string   `json:"schema_version"`
		TargetIP      string   `json:"target_ip"`
		Timeout       string   `json:"timeout"`
		EvidenceIDs   []string `json:"evidence_ids"`
		Command       string   `json:"command"`
	}
	if decoder.Decode(&candidate) != nil || candidate.SchemaVersion != "nft-blacklist-v1" ||
		candidate.Command == "" || sha256Digest([]byte(candidate.Command)) != success.GeneratedCommandDigest ||
		!equalStrings(candidate.EvidenceIDs, success.EvidenceIDs) {
		return false
	}
	previous := ""
	for _, id := range success.EvidenceIDs {
		if !uuidPattern.MatchString(id) || id <= previous {
			return false
		}
		previous = id
	}
	usage := success.Usage
	validUsage := (!usage.Trusted && usage.InputTokens == 0 && usage.CachedInputTokens == 0 && usage.OutputTokens == 0) ||
		(usage.Trusted && usage.InputTokens > 0 && usage.InputTokens <= ai.MaxInputBytes &&
			usage.CachedInputTokens >= 0 && usage.CachedInputTokens <= usage.InputTokens &&
			usage.OutputTokens > 0 && usage.OutputTokens <= ai.MaxOutputTokens)
	if !validUsage {
		return false
	}
	if identity.Kind() == ai.ProviderDeterministicStub {
		return !usage.Trusted && usage.InputTokens == 0 &&
			usage.CachedInputTokens == 0 && usage.OutputTokens == 0 &&
			stubResponseIDPattern.MatchString(success.ResponseID)
	}
	return true
}

func strictJSONObject(document []byte) error {
	if !utf8.Valid(document) {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') || consumeStrictJSON(decoder, token) != nil {
		return ErrInvalidRequest
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func consumeStrictJSON(decoder *json.Decoder, token json.Token) error {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrInvalidRequest
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidRequest
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidRequest
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil || consumeStrictJSON(decoder, value) != nil {
				return ErrInvalidRequest
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidRequest
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil || consumeStrictJSON(decoder, value) != nil {
				return ErrInvalidRequest
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validFailure(failure *analysisworker.Failure) bool {
	if failure == nil || failure.Attempts < 0 || failure.Attempts > 2 ||
		failure.InputBytes < 0 || failure.InputBytes > ai.MaxInputBytes ||
		(failure.InputBytes == 0) != (failure.InputDigest == "") ||
		(failure.InputDigest != "" && !digestPattern.MatchString(failure.InputDigest)) {
		return false
	}
	validReason := false
	switch failure.Reason {
	case ai.FailureBudgetExhausted, ai.FailureInputTooLarge, ai.FailureNetworkError,
		ai.FailureHTTP408, ai.FailureHTTP409, ai.FailureRateLimited, ai.FailureServerError,
		ai.FailureTimeout, ai.FailureRefused, ai.FailureIncomplete, ai.FailureSchemaInvalid,
		ai.FailureEvidenceInvalid, ai.FailureCancelled, ai.FailureConfiguration:
		validReason = true
	default:
		return false
	}
	retryExpected := false
	switch failure.Reason {
	case ai.FailureNetworkError, ai.FailureHTTP408, ai.FailureHTTP409,
		ai.FailureRateLimited, ai.FailureServerError, ai.FailureTimeout:
		retryExpected = true
	}
	return validReason && failure.RetryEligible == retryExpected
}

type mutationWire struct {
	IncidentID             string       `json:"incident_id"`
	IncidentVersion        int32        `json:"incident_version"`
	AnalysisID             string       `json:"analysis_id"`
	EvidenceSnapshotID     string       `json:"evidence_snapshot_id"`
	EvidenceSnapshotDigest string       `json:"evidence_snapshot_digest"`
	State                  string       `json:"state"`
	AuditAction            string       `json:"audit_action"`
	ValidationRequested    bool         `json:"validation_requested"`
	Success                *successWire `json:"success"`
	Failure                *failureWire `json:"failure"`
}

type successWire struct {
	ProviderKind           string    `json:"provider_kind"`
	AdapterID              string    `json:"adapter_id"`
	Model                  string    `json:"model"`
	ReasoningEffort        string    `json:"reasoning_effort"`
	RateCardVersion        string    `json:"rate_card_version"`
	ResponseID             string    `json:"response_id"`
	Attempts               int       `json:"attempts"`
	InputBytes             int       `json:"input_bytes"`
	InputDigest            string    `json:"input_digest"`
	InputSchemaDigest      string    `json:"input_schema_digest"`
	PromptDigest           string    `json:"prompt_digest"`
	OutputSchemaDigest     string    `json:"output_schema_digest"`
	OutputDigest           string    `json:"output_digest"`
	AnalysisHex            string    `json:"analysis_hex"`
	PolicyHex              string    `json:"policy_hex"`
	CommandCandidateHex    string    `json:"command_candidate_hex"`
	GeneratedCommandDigest string    `json:"generated_command_digest"`
	EvidenceIDs            []string  `json:"evidence_ids"`
	Usage                  usageWire `json:"usage"`
}

type usageWire struct {
	InputTokens       int64 `json:"input_tokens"`
	CachedInputTokens int64 `json:"cached_input_tokens"`
	OutputTokens      int64 `json:"output_tokens"`
	Trusted           bool  `json:"trusted"`
}

type failureWire struct {
	Reason        string `json:"reason"`
	Attempts      int    `json:"attempts"`
	RetryEligible bool   `json:"retry_eligible"`
	InputBytes    int    `json:"input_bytes"`
	InputDigest   string `json:"input_digest"`
}

func encodeMutation(mutation *analysisworker.Mutation) ([]byte, error) {
	if mutation == nil {
		return []byte("null"), nil
	}
	wire := mutationWire{
		IncidentID: mutation.IncidentID, IncidentVersion: mutation.IncidentVersion,
		AnalysisID: mutation.AnalysisID, EvidenceSnapshotID: mutation.EvidenceSnapshotID,
		EvidenceSnapshotDigest: mutation.EvidenceSnapshotDigest, State: string(mutation.State),
		AuditAction: mutation.AuditAction, ValidationRequested: mutation.ValidationRequested,
	}
	if mutation.Success != nil {
		success := mutation.Success
		wire.Success = &successWire{
			ProviderKind: success.ProviderKind, AdapterID: success.AdapterID,
			Model: success.Model, ReasoningEffort: success.ReasoningEffort,
			RateCardVersion: success.RateCardVersion, ResponseID: success.ResponseID,
			Attempts: success.Attempts, InputBytes: success.InputBytes,
			InputDigest: success.InputDigest, InputSchemaDigest: success.InputSchemaDigest,
			PromptDigest: success.PromptDigest, OutputSchemaDigest: success.OutputSchemaDigest,
			OutputDigest: success.OutputDigest, AnalysisHex: hex.EncodeToString(success.AnalysisJSON),
			PolicyHex:              hex.EncodeToString(success.PolicyJSON),
			CommandCandidateHex:    hex.EncodeToString(success.CommandCandidateJSON),
			GeneratedCommandDigest: success.GeneratedCommandDigest,
			EvidenceIDs:            append([]string(nil), success.EvidenceIDs...),
			Usage: usageWire{
				InputTokens:       success.Usage.InputTokens,
				CachedInputTokens: success.Usage.CachedInputTokens,
				OutputTokens:      success.Usage.OutputTokens, Trusted: success.Usage.Trusted,
			},
		}
	} else {
		failure := mutation.Failure
		wire.Failure = &failureWire{
			Reason: string(failure.Reason), Attempts: failure.Attempts,
			RetryEligible: failure.RetryEligible, InputBytes: failure.InputBytes,
			InputDigest: failure.InputDigest,
		}
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > 3<<20 || strings.Contains(string(encoded), "\\u0000") {
		return nil, fmt.Errorf("encode mutation: %w", ErrInvalidRequest)
	}
	return encoded, nil
}

func validUUIDV4(value string) bool {
	return uuidPattern.MatchString(value) && value[14] == '4' &&
		strings.ContainsRune("89ab", rune(value[19]))
}
