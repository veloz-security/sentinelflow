package validation

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
	"github.com/devwooops/sentinelflow/internal/events"
)

const (
	HistoricalImpactSchemaVersion = "historical-impact-v1"
	HistoricalImpactLookback      = 24 * time.Hour
	HistoricalImpactLookbackSecs  = uint32(HistoricalImpactLookback / time.Second)

	PinnedDemoHistoryRawFileDigest            = "sha256:fe1b9e9ed59c74b1522acb63e1c0239cc3defb53f56fbe6125894403b3d341f9"
	PinnedDemoHistoryDatasetDigest            = "sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00"
	PinnedDemoHistoryImpactSourceHealthDigest = "sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3"
	DemoHistoryDatasetLocator                 = "contracts/fixtures/demo_history_dataset_v1.json"

	maxHistoricalGatewayRecords  = 1_000_000
	maxHistoricalAuthRecords     = 1_000_000
	maxHistoricalHealthIntervals = 100_000
	maxHistoricalReceiverGaps    = 100_000
	maxHistoricalSafeInteger     = uint64(9_007_199_254_740_991)
)

// HistoryMode identifies whether the gate is using retained production-shaped
// history or an independently verified, signed demo import. The gate never
// upgrades retained rows into a signed-demo assertion.
type HistoryMode string

const (
	HistoryModeRetained     HistoryMode = "retained"
	HistoryModeVerifiedDemo HistoryMode = "verified_demo"
)

// HistoryClockAuthority is provenance, not a caller-selected time source.
// Production accepts only realtime. The verified-demo value is accepted only
// for the demo/test profile and only with a sealed signed-manifest binding.
type HistoryClockAuthority string

const (
	HistoryClockRealtime     HistoryClockAuthority = "realtime"
	HistoryClockVerifiedDemo HistoryClockAuthority = "verified_demo"
)

// HistoryCutoff is an opaque clock-authority token captured before the caller
// queries the exact lookback window. Production callers cannot manufacture a
// deterministic timestamp and label it realtime by mutating fields directly.
// Live callers use CaptureRealtimeHistoryCutoff; the PostgreSQL adapter uses
// SealDatabaseHistoryCutoff with its transaction-scoped server timestamp.
type HistoryCutoff struct {
	at        time.Time
	authority HistoryClockAuthority
	sealed    bool
}

// ErrInvalidDatabaseHistoryCutoff is returned when the persistence boundary
// cannot provide a usable PostgreSQL clock_timestamp() value.
var ErrInvalidDatabaseHistoryCutoff = errors.New("validation: invalid database history cutoff")

func CaptureRealtimeHistoryCutoff() HistoryCutoff {
	return HistoryCutoff{at: time.Now().Round(0).UTC(), authority: HistoryClockRealtime, sealed: true}
}

// SealDatabaseHistoryCutoff converts the server timestamp returned in the
// same database transaction that reads the history window into the opaque
// realtime token consumed by the historical-impact gate. Callers must not use
// an application clock here; this boundary exists so a separately packaged
// PostgreSQL adapter can preserve one database-clock cutoff across its queries.
func SealDatabaseHistoryCutoff(at time.Time) (HistoryCutoff, error) {
	at = at.Round(0).UTC()
	if !validSnapshotTime(at) {
		return HistoryCutoff{}, ErrInvalidDatabaseHistoryCutoff
	}
	return HistoryCutoff{at: at, authority: HistoryClockRealtime, sealed: true}, nil
}

func (c HistoryCutoff) At() time.Time {
	if !c.sealed {
		return time.Time{}
	}
	return c.at
}

type HistoryQueryStatus string

const (
	HistoryQueryComplete    HistoryQueryStatus = "complete"
	HistoryQueryIncomplete  HistoryQueryStatus = "incomplete"
	HistoryQueryUnavailable HistoryQueryStatus = "unavailable"
)

type HistoryCoverage struct {
	GatewayStatus      HistoryQueryStatus
	AuthStatus         HistoryQueryStatus
	SourceHealthStatus HistoryQueryStatus
	ReceiverGapStatus  HistoryQueryStatus
	RetainedFrom       time.Time
	RetainedThrough    time.Time
}

// HistoricalGatewayRecord is the minimum retained Gateway projection used by
// impact analysis. It cannot carry a path, query, body, header, cookie, host,
// account, or other free-form request material.
type HistoricalGatewayRecord struct {
	EventID        string
	OccurredAt     time.Time
	SourceIPv4     string
	StatusCode     int
	TimestampTrust detection.TimestampTrust
}

// HistoricalAuthRecord intentionally excludes account_hash. Historical
// impact needs only the typed outcome and ingestion-owned trust/binding state.
type HistoricalAuthRecord struct {
	EventID        string
	OccurredAt     time.Time
	SourceIPv4     string
	Outcome        events.AuthOutcome
	TimestampTrust detection.TimestampTrust
	Binding        detection.BindingState
}

type ReceiverGapResolution string

const (
	ReceiverGapResolvedExact ReceiverGapResolution = "resolved_exact"
	ReceiverGapUnresolved    ReceiverGapResolution = "unresolved"
	ReceiverGapPermanentLoss ReceiverGapResolution = "permanent_loss"
)

// HistoricalReceiverGap is the typed receiver-side sequence gap projection.
// A zero ImpactEnd means the affected time remains open or unknown. Complete
// query coverage is still required when the slice is empty.
type HistoricalReceiverGap struct {
	GapID         string
	Source        detection.SourceKind
	SequenceStart uint64
	SequenceEnd   uint64
	ImpactStart   time.Time
	ImpactEnd     time.Time
	Resolution    ReceiverGapResolution
}

// DemoHistoryVerificationInput is the boundary for the separately owned
// strict-schema, Ed25519, dataset, and transactional-import verifier. This
// package deliberately provides no permissive constructor or signature stub.
type DemoHistoryVerificationInput struct {
	SignedManifestEnvelope []byte
	ImportedRowsDigest     string
	ImportedRecordCount    uint64
}

// DemoHistoryManifestVerifier must be implemented by the future signed import
// verifier in this package. Code outside validation cannot construct a valid
// VerifiedDemoHistoryBinding because its seal and fields are private.
type DemoHistoryManifestVerifier interface {
	VerifyDemoHistory(context.Context, DemoHistoryVerificationInput) (VerifiedDemoHistoryBinding, error)
}

// VerifiedDemoHistoryBinding is an opaque output of the separately verified
// signed-manifest/import path. It contains no private signing material.
type VerifiedDemoHistoryBinding struct {
	verified                    bool
	verificationEnvironment     Environment
	fixtureOnly                 bool
	schemaVersion               string
	profile                     string
	manifestID                  string
	datasetID                   string
	datasetSchemaVersion        string
	datasetLocator              string
	importID                    string
	clockAt                     time.Time
	coverageStart               time.Time
	coverageEnd                 time.Time
	issuedAt                    time.Time
	pathCatalogVersion          string
	datasetRecordCount          uint64
	rawFileDigest               string
	datasetDigest               string
	manifestDigest              string
	importedRowsDigest          string
	manifestSourceHealthDigest  string
	impactSourceHealthDigest    string
	runScopeDigest              string
	publicKeyDigest             string
	signatureVerificationDigest string
}

// DemoHistoryBindingClaims is a read-only copy of the public proof material
// required by the PostgreSQL validation boundary. It contains no signature,
// private key, envelope bytes, imported event content, or capability material.
// A value constructed by a caller cannot mint a VerifiedDemoHistoryBinding.
type DemoHistoryBindingClaims struct {
	VerificationEnvironment     Environment
	FixtureOnly                 bool
	SchemaVersion               string
	Profile                     string
	ManifestID                  string
	DatasetID                   string
	DatasetSchemaVersion        string
	DatasetLocator              string
	ImportID                    string
	ClockAt                     time.Time
	CoverageStart               time.Time
	CoverageEnd                 time.Time
	IssuedAt                    time.Time
	PathCatalogVersion          string
	DatasetRecordCount          uint64
	RawFileDigest               string
	DatasetDigest               string
	ManifestDigest              string
	ImportedRowsDigest          string
	ManifestSourceHealthDigest  string
	ImpactSourceHealthDigest    string
	RunScopeDigest              string
	PublicKeyDigest             string
	SignatureVerificationDigest string
}

// HistoryCutoff returns a sealed deterministic cutoff only after the separate
// signed-manifest verifier has produced a non-zero binding.
func (b VerifiedDemoHistoryBinding) HistoryCutoff() HistoryCutoff {
	if !b.verified || !validSnapshotTime(b.clockAt) {
		return HistoryCutoff{}
	}
	return HistoryCutoff{at: b.clockAt.Round(0).UTC(), authority: HistoryClockVerifiedDemo, sealed: true}
}

// Claims returns public, immutable verification claims only for a binding
// minted by StrictDemoHistoryManifestVerifier.
func (b VerifiedDemoHistoryBinding) Claims() (DemoHistoryBindingClaims, bool) {
	if !b.verified || !validSnapshotTime(b.clockAt) || !validSnapshotTime(b.coverageStart) ||
		!validSnapshotTime(b.coverageEnd) || !validSnapshotTime(b.issuedAt) {
		return DemoHistoryBindingClaims{}, false
	}
	return DemoHistoryBindingClaims{
		VerificationEnvironment: b.verificationEnvironment, FixtureOnly: b.fixtureOnly,
		SchemaVersion: b.schemaVersion, Profile: b.profile,
		ManifestID: b.manifestID, DatasetID: b.datasetID,
		DatasetSchemaVersion: b.datasetSchemaVersion, DatasetLocator: b.datasetLocator,
		ImportID: b.importID, ClockAt: b.clockAt.Round(0).UTC(),
		CoverageStart: b.coverageStart.Round(0).UTC(), CoverageEnd: b.coverageEnd.Round(0).UTC(),
		IssuedAt: b.issuedAt.Round(0).UTC(), PathCatalogVersion: b.pathCatalogVersion,
		DatasetRecordCount: b.datasetRecordCount, RawFileDigest: b.rawFileDigest,
		DatasetDigest: b.datasetDigest, ManifestDigest: b.manifestDigest,
		ImportedRowsDigest:         b.importedRowsDigest,
		ManifestSourceHealthDigest: b.manifestSourceHealthDigest,
		ImpactSourceHealthDigest:   b.impactSourceHealthDigest,
		RunScopeDigest:             b.runScopeDigest, PublicKeyDigest: b.publicKeyDigest,
		SignatureVerificationDigest: b.signatureVerificationDigest,
	}, true
}

type HistoricalImpactInput struct {
	Environment    Environment
	Mode           HistoryMode
	Clock          HistoryCutoff
	TargetIPv4     string
	Coverage       HistoryCoverage
	GatewayRecords []HistoricalGatewayRecord
	AuthRecords    []HistoricalAuthRecord
	GatewayHealth  detection.SourceHealth
	AuthHealth     detection.SourceHealth
	ReceiverGaps   []HistoricalReceiverGap
	DemoHistory    *VerifiedDemoHistoryBinding
}

type HistoricalImpactDecision string

const (
	HistoricalImpactAllowed HistoricalImpactDecision = "allowed"
	HistoricalImpactBlocked HistoricalImpactDecision = "blocked"
)

type HistoricalImpactReason string

const (
	HistoryReasonOK                      HistoricalImpactReason = "ok"
	HistoryReasonInputInvalid            HistoricalImpactReason = "history_input_invalid"
	HistoryReasonClockNotAllowed         HistoricalImpactReason = "history_clock_not_allowed"
	HistoryReasonInputUnavailable        HistoricalImpactReason = "history_input_unavailable"
	HistoryReasonCoverageIncomplete      HistoricalImpactReason = "history_coverage_incomplete"
	HistoryReasonRetentionMissing        HistoricalImpactReason = "history_retention_boundary_missing"
	HistoryReasonSourceDegraded          HistoricalImpactReason = "history_source_degraded"
	HistoryReasonSourceUnknownLoss       HistoricalImpactReason = "history_source_unknown_loss"
	HistoryReasonGapUnresolved           HistoricalImpactReason = "history_receiver_gap_unresolved"
	HistoryReasonGapPermanentLoss        HistoricalImpactReason = "history_receiver_gap_permanent_loss"
	HistoryReasonTimestampUntrusted      HistoricalImpactReason = "history_timestamp_untrusted"
	HistoryReasonAuthSucceeded           HistoricalImpactReason = "history_auth_succeeded"
	HistoryReasonAuthBindingPending      HistoricalImpactReason = "history_auth_binding_pending"
	HistoryReasonAuthBindingUntrusted    HistoricalImpactReason = "history_auth_binding_untrusted"
	HistoryReasonDemoVerificationMissing HistoricalImpactReason = "history_demo_verification_missing"
	HistoryReasonDemoBindingMismatch     HistoricalImpactReason = "history_demo_binding_mismatch"
)

// HistoricalImpactReport is deliberately content-free. It retains only typed
// decisions/reasons, bounded counts, and digests. Target IPs, event IDs,
// sender IDs, account hashes, and request material are absent.
type HistoricalImpactReport struct {
	SchemaVersion           string
	Decision                HistoricalImpactDecision
	ReasonCode              HistoricalImpactReason
	LookbackSeconds         uint32
	GatewayRecordCount      uint64
	Gateway2xxCount         uint64
	Gateway3xxCount         uint64
	Gateway4xxCount         uint64
	Gateway5xxCount         uint64
	AuthRecordCount         uint64
	VerifiedFailedAuthCount uint64
	SucceededAuthCount      uint64
	GatewayDigest           string
	AuthDigest              string
	SourceHealthDigest      string
	ReceiverGapDigest       string
	CoverageDigest          string
	DemoBindingDigest       string
	InputDigest             string
}

type CheckedHistoricalImpact struct {
	value     HistoricalImpactReport
	canonical []byte
	digest    string
}

func (r CheckedHistoricalImpact) Value() HistoricalImpactReport { return r.value }
func (r CheckedHistoricalImpact) CanonicalBytes() []byte        { return bytes.Clone(r.canonical) }
func (r CheckedHistoricalImpact) DigestInput() []byte           { return bytes.Clone(r.canonical) }
func (r CheckedHistoricalImpact) Digest() string                { return r.digest }
func (r CheckedHistoricalImpact) Allowed() bool {
	return len(r.canonical) != 0 && r.value.Decision == HistoricalImpactAllowed && r.value.ReasonCode == HistoryReasonOK
}

type historyGatewayWire struct {
	EventID        string `json:"event_id"`
	OccurredAt     string `json:"occurred_at"`
	SourceIPv4     string `json:"source_ipv4"`
	StatusCode     int    `json:"status_code"`
	TimestampTrust string `json:"timestamp_trust"`
}

type historyAuthWire struct {
	EventID        string `json:"event_id"`
	OccurredAt     string `json:"occurred_at"`
	SourceIPv4     string `json:"source_ipv4"`
	Outcome        string `json:"outcome"`
	TimestampTrust string `json:"timestamp_trust"`
	Binding        string `json:"binding"`
}

type historyHealthIntervalWire struct {
	State        string `json:"state"`
	Start        string `json:"start"`
	End          string `json:"end"`
	DroppedCount uint64 `json:"dropped_count"`
}

type historySourceHealthWire struct {
	Source        string                      `json:"source"`
	Complete      bool                        `json:"complete"`
	CoverageStart string                      `json:"coverage_start"`
	CoverageEnd   string                      `json:"coverage_end"`
	Intervals     []historyHealthIntervalWire `json:"intervals"`
}

type historyGapWire struct {
	GapID         string `json:"gap_id"`
	Source        string `json:"source"`
	SequenceStart uint64 `json:"sequence_start"`
	SequenceEnd   uint64 `json:"sequence_end"`
	ImpactStart   string `json:"impact_start"`
	ImpactEnd     string `json:"impact_end"`
	Resolution    string `json:"resolution"`
}

type historyCoverageWire struct {
	GatewayStatus      string `json:"gateway_status"`
	AuthStatus         string `json:"auth_status"`
	SourceHealthStatus string `json:"source_health_status"`
	ReceiverGapStatus  string `json:"receiver_gap_status"`
	RetainedFrom       string `json:"retained_from"`
	RetainedThrough    string `json:"retained_through"`
}

type historyInputBindingWire struct {
	SchemaVersion      string `json:"schema_version"`
	Environment        string `json:"environment"`
	Mode               string `json:"mode"`
	ClockAuthority     string `json:"clock_authority"`
	At                 string `json:"at"`
	WindowStart        string `json:"window_start"`
	TargetIPv4         string `json:"target_ipv4"`
	GatewayDigest      string `json:"gateway_digest"`
	AuthDigest         string `json:"auth_digest"`
	SourceHealthDigest string `json:"source_health_digest"`
	ReceiverGapDigest  string `json:"receiver_gap_digest"`
	CoverageDigest     string `json:"coverage_digest"`
	DemoBindingDigest  string `json:"demo_binding_digest"`
}

type historicalImpactReportWire struct {
	SchemaVersion           string                   `json:"schema_version"`
	Decision                HistoricalImpactDecision `json:"decision"`
	ReasonCode              HistoricalImpactReason   `json:"reason_code"`
	LookbackSeconds         uint32                   `json:"lookback_seconds"`
	GatewayRecordCount      uint64                   `json:"gateway_record_count"`
	Gateway2xxCount         uint64                   `json:"gateway_2xx_count"`
	Gateway3xxCount         uint64                   `json:"gateway_3xx_count"`
	Gateway4xxCount         uint64                   `json:"gateway_4xx_count"`
	Gateway5xxCount         uint64                   `json:"gateway_5xx_count"`
	AuthRecordCount         uint64                   `json:"auth_record_count"`
	VerifiedFailedAuthCount uint64                   `json:"verified_failed_auth_count"`
	SucceededAuthCount      uint64                   `json:"succeeded_auth_count"`
	GatewayDigest           string                   `json:"gateway_digest"`
	AuthDigest              string                   `json:"auth_digest"`
	SourceHealthDigest      string                   `json:"source_health_digest"`
	ReceiverGapDigest       string                   `json:"receiver_gap_digest"`
	CoverageDigest          string                   `json:"coverage_digest"`
	DemoBindingDigest       string                   `json:"demo_binding_digest"`
	InputDigest             string                   `json:"input_digest"`
}

// EvaluateHistoricalImpact applies the exact inclusive [At-24h, At] window.
// It never sorts or repairs caller-owned data in place and never returns raw
// input content. Structural ambiguity and missing proof fail closed.
func EvaluateHistoricalImpact(input HistoricalImpactInput) CheckedHistoricalImpact {
	report := emptyHistoricalImpactReport()
	at, windowStart, reason := validateHistoryEnvelope(input)
	if reason != HistoryReasonOK {
		report.ReasonCode = reason
		return sealHistoricalImpactReport(report)
	}

	coverageWire, reason := normalizeHistoryCoverage(input.Coverage, windowStart, at)
	if reason != HistoryReasonOK {
		report.ReasonCode = reason
		return sealHistoricalImpactReport(report)
	}
	report.CoverageDigest = digestHistoryValue(coverageWire)

	gatewayWire, gatewayCounts, gatewayReason := normalizeHistoryGateway(input.GatewayRecords, input.TargetIPv4, windowStart, at)
	authWire, authCounts, authReason := normalizeHistoryAuth(input.AuthRecords, input.TargetIPv4, windowStart, at)
	healthWire, healthReason := normalizeHistoryHealth(input.GatewayHealth, input.AuthHealth, windowStart, at)
	gapWire, gapReason := normalizeHistoryGaps(input.ReceiverGaps, windowStart, at)
	if gatewayReason == HistoryReasonInputInvalid || authReason == HistoryReasonInputInvalid ||
		healthReason == HistoryReasonInputInvalid || gapReason == HistoryReasonInputInvalid {
		report.ReasonCode = HistoryReasonInputInvalid
		return sealHistoricalImpactReport(report)
	}

	report.GatewayRecordCount = gatewayCounts.total
	report.Gateway2xxCount = gatewayCounts.status2xx
	report.Gateway3xxCount = gatewayCounts.status3xx
	report.Gateway4xxCount = gatewayCounts.status4xx
	report.Gateway5xxCount = gatewayCounts.status5xx
	report.AuthRecordCount = authCounts.total
	report.VerifiedFailedAuthCount = authCounts.verifiedFailed
	report.SucceededAuthCount = authCounts.succeeded
	report.GatewayDigest = digestHistoryValue(gatewayWire)
	report.AuthDigest = digestHistoryValue(authWire)
	report.SourceHealthDigest = digestHistoryValue(healthWire)
	report.ReceiverGapDigest = digestHistoryValue(gapWire)

	demoDigest, demoReason := validateDemoHistoryBinding(input, at, windowStart, report)
	if demoReason != HistoryReasonOK {
		report.ReasonCode = demoReason
		return sealHistoricalImpactReport(report)
	}
	report.DemoBindingDigest = demoDigest
	report.InputDigest = digestHistoryValue(historyInputBindingWire{
		SchemaVersion:      HistoricalImpactSchemaVersion,
		Environment:        string(input.Environment),
		Mode:               string(input.Mode),
		ClockAuthority:     string(input.Clock.authority),
		At:                 historyTime(at),
		WindowStart:        historyTime(windowStart),
		TargetIPv4:         input.TargetIPv4,
		GatewayDigest:      report.GatewayDigest,
		AuthDigest:         report.AuthDigest,
		SourceHealthDigest: report.SourceHealthDigest,
		ReceiverGapDigest:  report.ReceiverGapDigest,
		CoverageDigest:     report.CoverageDigest,
		DemoBindingDigest:  report.DemoBindingDigest,
	})

	// A success blocks regardless of verified, pending, or untrusted binding.
	// This precedence is deliberate and conservative.
	reason = firstHistoryFailure(
		healthReason,
		gapReason,
		authReason,
		gatewayReason,
	)
	if reason != HistoryReasonOK {
		report.ReasonCode = reason
		return sealHistoricalImpactReport(report)
	}
	report.Decision = HistoricalImpactAllowed
	report.ReasonCode = HistoryReasonOK
	return sealHistoricalImpactReport(report)
}

type historyGatewayCounts struct {
	total, status2xx, status3xx, status4xx, status5xx uint64
}

type historyAuthCounts struct {
	total, verifiedFailed, succeeded uint64
}

func validateHistoryEnvelope(input HistoricalImpactInput) (time.Time, time.Time, HistoricalImpactReason) {
	if input.Environment != EnvironmentDevelopment && input.Environment != EnvironmentTest &&
		input.Environment != EnvironmentDemo && input.Environment != EnvironmentProduction {
		return time.Time{}, time.Time{}, HistoryReasonInputInvalid
	}
	if !input.Clock.sealed || !validSnapshotTime(input.Clock.at) {
		return time.Time{}, time.Time{}, HistoryReasonInputInvalid
	}
	at := input.Clock.at.Round(0).UTC()
	windowStart := at.Add(-HistoricalImpactLookback)
	if !validSnapshotTime(windowStart) {
		return time.Time{}, time.Time{}, HistoryReasonInputInvalid
	}
	address, err := netip.ParseAddr(input.TargetIPv4)
	if err != nil || !address.Is4() || address.String() != input.TargetIPv4 {
		return time.Time{}, time.Time{}, HistoryReasonInputInvalid
	}
	switch input.Mode {
	case HistoryModeRetained:
		if input.Clock.authority != HistoryClockRealtime || input.DemoHistory != nil {
			return time.Time{}, time.Time{}, HistoryReasonClockNotAllowed
		}
	case HistoryModeVerifiedDemo:
		if input.Environment == EnvironmentProduction || input.Environment == EnvironmentDevelopment ||
			input.Clock.authority != HistoryClockVerifiedDemo {
			return time.Time{}, time.Time{}, HistoryReasonClockNotAllowed
		}
	default:
		return time.Time{}, time.Time{}, HistoryReasonInputInvalid
	}
	return at, windowStart, HistoryReasonOK
}

func normalizeHistoryCoverage(value HistoryCoverage, windowStart, at time.Time) (historyCoverageWire, HistoricalImpactReason) {
	statuses := [...]HistoryQueryStatus{value.GatewayStatus, value.AuthStatus, value.SourceHealthStatus, value.ReceiverGapStatus}
	for _, status := range statuses {
		if status != HistoryQueryComplete && status != HistoryQueryIncomplete && status != HistoryQueryUnavailable {
			return historyCoverageWire{}, HistoryReasonInputInvalid
		}
	}
	for _, status := range statuses {
		if status == HistoryQueryUnavailable {
			return historyCoverageWire{}, HistoryReasonInputUnavailable
		}
	}
	for _, status := range statuses {
		if status == HistoryQueryIncomplete {
			return historyCoverageWire{}, HistoryReasonCoverageIncomplete
		}
	}
	if !validSnapshotTime(value.RetainedFrom) || !validSnapshotTime(value.RetainedThrough) ||
		value.RetainedThrough.Before(value.RetainedFrom) {
		return historyCoverageWire{}, HistoryReasonRetentionMissing
	}
	retainedFrom := value.RetainedFrom.Round(0).UTC()
	retainedThrough := value.RetainedThrough.Round(0).UTC()
	if retainedFrom.After(windowStart) {
		return historyCoverageWire{}, HistoryReasonRetentionMissing
	}
	if retainedThrough.Before(at) {
		return historyCoverageWire{}, HistoryReasonCoverageIncomplete
	}
	return historyCoverageWire{
		GatewayStatus:      string(value.GatewayStatus),
		AuthStatus:         string(value.AuthStatus),
		SourceHealthStatus: string(value.SourceHealthStatus),
		ReceiverGapStatus:  string(value.ReceiverGapStatus),
		RetainedFrom:       historyTime(retainedFrom),
		RetainedThrough:    historyTime(retainedThrough),
	}, HistoryReasonOK
}

func normalizeHistoryGateway(values []HistoricalGatewayRecord, target string, windowStart, at time.Time) ([]historyGatewayWire, historyGatewayCounts, HistoricalImpactReason) {
	if len(values) > maxHistoricalGatewayRecords {
		return nil, historyGatewayCounts{}, HistoryReasonInputInvalid
	}
	result := make([]historyGatewayWire, len(values))
	counts := historyGatewayCounts{total: uint64(len(values))}
	reason := HistoryReasonOK
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if !consistencyUUIDPattern.MatchString(value.EventID) {
			return nil, historyGatewayCounts{}, HistoryReasonInputInvalid
		}
		if _, duplicate := seen[value.EventID]; duplicate {
			return nil, historyGatewayCounts{}, HistoryReasonInputInvalid
		}
		seen[value.EventID] = struct{}{}
		occurredAt := value.OccurredAt.Round(0).UTC()
		if !validSnapshotTime(value.OccurredAt) || occurredAt.Before(windowStart) || occurredAt.After(at) ||
			value.SourceIPv4 != target || value.StatusCode < 100 || value.StatusCode > 599 ||
			(value.TimestampTrust != detection.TimestampTrusted && value.TimestampTrust != detection.TimestampUntrusted) {
			return nil, historyGatewayCounts{}, HistoryReasonInputInvalid
		}
		if value.TimestampTrust == detection.TimestampUntrusted {
			reason = HistoryReasonTimestampUntrusted
		}
		switch value.StatusCode / 100 {
		case 2:
			counts.status2xx++
		case 3:
			counts.status3xx++
		case 4:
			counts.status4xx++
		case 5:
			counts.status5xx++
		}
		result[index] = historyGatewayWire{
			EventID:        value.EventID,
			OccurredAt:     historyTime(occurredAt),
			SourceIPv4:     value.SourceIPv4,
			StatusCode:     value.StatusCode,
			TimestampTrust: string(value.TimestampTrust),
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].OccurredAt == result[j].OccurredAt {
			return result[i].EventID < result[j].EventID
		}
		return result[i].OccurredAt < result[j].OccurredAt
	})
	return result, counts, reason
}

func normalizeHistoryAuth(values []HistoricalAuthRecord, target string, windowStart, at time.Time) ([]historyAuthWire, historyAuthCounts, HistoricalImpactReason) {
	if len(values) > maxHistoricalAuthRecords {
		return nil, historyAuthCounts{}, HistoryReasonInputInvalid
	}
	result := make([]historyAuthWire, len(values))
	counts := historyAuthCounts{total: uint64(len(values))}
	hasSuccess := false
	hasPending := false
	hasUntrustedBinding := false
	hasUntrustedTimestamp := false
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if !consistencyUUIDPattern.MatchString(value.EventID) {
			return nil, historyAuthCounts{}, HistoryReasonInputInvalid
		}
		if _, duplicate := seen[value.EventID]; duplicate {
			return nil, historyAuthCounts{}, HistoryReasonInputInvalid
		}
		seen[value.EventID] = struct{}{}
		occurredAt := value.OccurredAt.Round(0).UTC()
		if !validSnapshotTime(value.OccurredAt) || occurredAt.Before(windowStart) || occurredAt.After(at) ||
			value.SourceIPv4 != target ||
			(value.Outcome != events.AuthOutcomeFailed && value.Outcome != events.AuthOutcomeSucceeded) ||
			(value.TimestampTrust != detection.TimestampTrusted && value.TimestampTrust != detection.TimestampUntrusted) ||
			(value.Binding != detection.BindingVerified && value.Binding != detection.BindingPending && value.Binding != detection.BindingUntrusted) {
			return nil, historyAuthCounts{}, HistoryReasonInputInvalid
		}
		if value.Outcome == events.AuthOutcomeSucceeded {
			counts.succeeded++
			hasSuccess = true
		}
		if value.Binding == detection.BindingPending {
			hasPending = true
		}
		if value.Binding == detection.BindingUntrusted {
			hasUntrustedBinding = true
		}
		if value.TimestampTrust == detection.TimestampUntrusted {
			hasUntrustedTimestamp = true
		}
		if value.Outcome == events.AuthOutcomeFailed && value.Binding == detection.BindingVerified &&
			value.TimestampTrust == detection.TimestampTrusted {
			counts.verifiedFailed++
		}
		result[index] = historyAuthWire{
			EventID:        value.EventID,
			OccurredAt:     historyTime(occurredAt),
			SourceIPv4:     value.SourceIPv4,
			Outcome:        string(value.Outcome),
			TimestampTrust: string(value.TimestampTrust),
			Binding:        string(value.Binding),
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].OccurredAt == result[j].OccurredAt {
			return result[i].EventID < result[j].EventID
		}
		return result[i].OccurredAt < result[j].OccurredAt
	})
	switch {
	case hasSuccess:
		return result, counts, HistoryReasonAuthSucceeded
	case hasPending:
		return result, counts, HistoryReasonAuthBindingPending
	case hasUntrustedBinding:
		return result, counts, HistoryReasonAuthBindingUntrusted
	case hasUntrustedTimestamp:
		return result, counts, HistoryReasonTimestampUntrusted
	default:
		return result, counts, HistoryReasonOK
	}
}

func normalizeHistoryHealth(gateway, auth detection.SourceHealth, windowStart, at time.Time) ([]historySourceHealthWire, HistoricalImpactReason) {
	values := []detection.SourceHealth{gateway, auth}
	expected := []detection.SourceKind{detection.SourceGateway, detection.SourceAuth}
	result := make([]historySourceHealthWire, len(values))
	reason := HistoryReasonOK
	for valueIndex, value := range values {
		if value.Source != expected[valueIndex] || !validSnapshotTime(value.CoverageStart) ||
			!validSnapshotTime(value.CoverageEnd) || value.CoverageEnd.Before(value.CoverageStart) {
			return nil, HistoryReasonInputInvalid
		}
		coverageStart := value.CoverageStart.Round(0).UTC()
		coverageEnd := value.CoverageEnd.Round(0).UTC()
		if !value.Complete || coverageStart.After(windowStart) || coverageEnd.Before(at) {
			return nil, HistoryReasonCoverageIncomplete
		}
		if len(value.Intervals) > maxHistoricalHealthIntervals {
			return nil, HistoryReasonInputInvalid
		}
		intervals := make([]historyHealthIntervalWire, len(value.Intervals))
		for index, interval := range value.Intervals {
			if !validHistoryHealthState(interval.State) || !validSnapshotTime(interval.Start) || interval.DroppedCount > maxHistoricalSafeInteger {
				return nil, HistoryReasonInputInvalid
			}
			start := interval.Start.Round(0).UTC()
			end := time.Time{}
			if !interval.End.IsZero() {
				if !validSnapshotTime(interval.End) || interval.End.Before(interval.Start) {
					return nil, HistoryReasonInputInvalid
				}
				end = interval.End.Round(0).UTC()
			}
			if historyIntervalOverlaps(start, end, windowStart, at) {
				if interval.State == detection.HealthUnknownLoss {
					reason = HistoryReasonSourceUnknownLoss
				} else if reason == HistoryReasonOK {
					reason = HistoryReasonSourceDegraded
				}
			}
			intervals[index] = historyHealthIntervalWire{
				State:        string(interval.State),
				Start:        historyTime(start),
				End:          historyOptionalTime(end),
				DroppedCount: interval.DroppedCount,
			}
		}
		sort.Slice(intervals, func(i, j int) bool {
			if intervals[i].Start != intervals[j].Start {
				return intervals[i].Start < intervals[j].Start
			}
			if intervals[i].End != intervals[j].End {
				return intervals[i].End < intervals[j].End
			}
			if intervals[i].State != intervals[j].State {
				return intervals[i].State < intervals[j].State
			}
			return intervals[i].DroppedCount < intervals[j].DroppedCount
		})
		for index := 1; index < len(intervals); index++ {
			if intervals[index] == intervals[index-1] {
				return nil, HistoryReasonInputInvalid
			}
		}
		result[valueIndex] = historySourceHealthWire{
			Source:        string(value.Source),
			Complete:      true,
			CoverageStart: historyTime(coverageStart),
			CoverageEnd:   historyTime(coverageEnd),
			Intervals:     intervals,
		}
	}
	return result, reason
}

func normalizeHistoryGaps(values []HistoricalReceiverGap, windowStart, at time.Time) ([]historyGapWire, HistoricalImpactReason) {
	if len(values) > maxHistoricalReceiverGaps {
		return nil, HistoryReasonInputInvalid
	}
	result := make([]historyGapWire, len(values))
	reason := HistoryReasonOK
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		if !consistencyUUIDPattern.MatchString(value.GapID) ||
			(value.Source != detection.SourceGateway && value.Source != detection.SourceAuth) ||
			value.SequenceStart == 0 || value.SequenceEnd < value.SequenceStart || value.SequenceEnd > maxHistoricalSafeInteger ||
			!validSnapshotTime(value.ImpactStart) ||
			(value.Resolution != ReceiverGapResolvedExact && value.Resolution != ReceiverGapUnresolved && value.Resolution != ReceiverGapPermanentLoss) {
			return nil, HistoryReasonInputInvalid
		}
		if _, duplicate := seen[value.GapID]; duplicate {
			return nil, HistoryReasonInputInvalid
		}
		seen[value.GapID] = struct{}{}
		start := value.ImpactStart.Round(0).UTC()
		end := time.Time{}
		if !value.ImpactEnd.IsZero() {
			if !validSnapshotTime(value.ImpactEnd) || value.ImpactEnd.Before(value.ImpactStart) {
				return nil, HistoryReasonInputInvalid
			}
			end = value.ImpactEnd.Round(0).UTC()
		}
		if value.Resolution == ReceiverGapResolvedExact && end.IsZero() {
			return nil, HistoryReasonInputInvalid
		}
		if historyIntervalOverlaps(start, end, windowStart, at) {
			switch value.Resolution {
			case ReceiverGapPermanentLoss:
				reason = HistoryReasonGapPermanentLoss
			case ReceiverGapUnresolved:
				if reason == HistoryReasonOK {
					reason = HistoryReasonGapUnresolved
				}
			}
		}
		result[index] = historyGapWire{
			GapID:         value.GapID,
			Source:        string(value.Source),
			SequenceStart: value.SequenceStart,
			SequenceEnd:   value.SequenceEnd,
			ImpactStart:   historyTime(start),
			ImpactEnd:     historyOptionalTime(end),
			Resolution:    string(value.Resolution),
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ImpactStart != result[j].ImpactStart {
			return result[i].ImpactStart < result[j].ImpactStart
		}
		return result[i].GapID < result[j].GapID
	})
	return result, reason
}

func validateDemoHistoryBinding(input HistoricalImpactInput, at, windowStart time.Time, report HistoricalImpactReport) (string, HistoricalImpactReason) {
	if input.Mode == HistoryModeRetained {
		return digestHistoryValue(nil), HistoryReasonOK
	}
	if input.DemoHistory == nil || !input.DemoHistory.verified {
		return digestHistoryValue(nil), HistoryReasonDemoVerificationMissing
	}
	binding := input.DemoHistory
	if (input.Environment == EnvironmentDemo &&
		(binding.verificationEnvironment != EnvironmentDemo || binding.fixtureOnly)) ||
		(input.Environment == EnvironmentTest &&
			(binding.verificationEnvironment != EnvironmentTest && binding.verificationEnvironment != EnvironmentDemo)) ||
		binding.schemaVersion != "demo-history-v1" || binding.profile != "isolated-demo" ||
		binding.datasetSchemaVersion != "demo-history-dataset-v1" || binding.datasetLocator != DemoHistoryDatasetLocator ||
		binding.pathCatalogVersion != events.PathCatalogV1 ||
		!consistencyUUIDPattern.MatchString(binding.manifestID) || !consistencyUUIDPattern.MatchString(binding.datasetID) ||
		!consistencyUUIDPattern.MatchString(binding.importID) ||
		!validDigest(binding.datasetDigest) || binding.datasetDigest != PinnedDemoHistoryDatasetDigest ||
		binding.rawFileDigest != PinnedDemoHistoryRawFileDigest ||
		!validDigest(binding.manifestDigest) || !validDigest(binding.importedRowsDigest) ||
		!validDigest(binding.manifestSourceHealthDigest) || !validDigest(binding.impactSourceHealthDigest) ||
		binding.impactSourceHealthDigest != PinnedDemoHistoryImpactSourceHealthDigest ||
		!validDigest(binding.runScopeDigest) || !validDigest(binding.publicKeyDigest) ||
		!validDigest(binding.signatureVerificationDigest) ||
		binding.datasetRecordCount == 0 || binding.datasetRecordCount > 100_000 ||
		binding.datasetRecordCount != report.GatewayRecordCount+report.AuthRecordCount ||
		binding.impactSourceHealthDigest != report.SourceHealthDigest ||
		!binding.clockAt.Round(0).UTC().Equal(at) ||
		!binding.coverageStart.Round(0).UTC().Equal(windowStart) ||
		!binding.coverageEnd.Round(0).UTC().Equal(at) ||
		!validSnapshotTime(binding.issuedAt) {
		return digestHistoryValue(nil), HistoryReasonDemoBindingMismatch
	}
	bindingWire := map[string]any{
		"verification_environment":      binding.verificationEnvironment,
		"fixture_only":                  binding.fixtureOnly,
		"schema_version":                binding.schemaVersion,
		"profile":                       binding.profile,
		"manifest_id":                   binding.manifestID,
		"dataset_id":                    binding.datasetID,
		"dataset_schema_version":        binding.datasetSchemaVersion,
		"dataset_locator":               binding.datasetLocator,
		"import_id":                     binding.importID,
		"clock_at":                      historyTime(at),
		"coverage_start":                historyTime(windowStart),
		"coverage_end":                  historyTime(at),
		"issued_at":                     historyTime(binding.issuedAt.Round(0).UTC()),
		"path_catalog_version":          binding.pathCatalogVersion,
		"dataset_record_count":          binding.datasetRecordCount,
		"raw_file_digest":               binding.rawFileDigest,
		"dataset_digest":                binding.datasetDigest,
		"manifest_digest":               binding.manifestDigest,
		"imported_rows_digest":          binding.importedRowsDigest,
		"manifest_source_health_digest": binding.manifestSourceHealthDigest,
		"impact_source_health_digest":   binding.impactSourceHealthDigest,
		"run_scope_digest":              binding.runScopeDigest,
		"public_key_digest":             binding.publicKeyDigest,
		"signature_verification_digest": binding.signatureVerificationDigest,
	}
	return digestHistoryValue(bindingWire), HistoryReasonOK
}

func firstHistoryFailure(values ...HistoricalImpactReason) HistoricalImpactReason {
	for _, value := range values {
		if value != HistoryReasonOK {
			return value
		}
	}
	return HistoryReasonOK
}

func validHistoryHealthState(value detection.HealthIntervalState) bool {
	return value == detection.HealthDegraded || value == detection.HealthLost || value == detection.HealthGapped ||
		value == detection.HealthUnknownLoss || value == detection.HealthRecovered
}

func historyIntervalOverlaps(start, end, windowStart, windowEnd time.Time) bool {
	if start.After(windowEnd) {
		return false
	}
	return end.IsZero() || !end.Before(windowStart)
}

func emptyHistoricalImpactReport() HistoricalImpactReport {
	emptyDigest := digestHistoryValue([]any{})
	return HistoricalImpactReport{
		SchemaVersion:      HistoricalImpactSchemaVersion,
		Decision:           HistoricalImpactBlocked,
		ReasonCode:         HistoryReasonInputInvalid,
		LookbackSeconds:    HistoricalImpactLookbackSecs,
		GatewayDigest:      emptyDigest,
		AuthDigest:         emptyDigest,
		SourceHealthDigest: emptyDigest,
		ReceiverGapDigest:  emptyDigest,
		CoverageDigest:     emptyDigest,
		DemoBindingDigest:  digestHistoryValue(nil),
		InputDigest:        emptyDigest,
	}
}

func sealHistoricalImpactReport(value HistoricalImpactReport) CheckedHistoricalImpact {
	wire := historicalImpactReportWire(value)
	canonical, err := marshalSnapshotJCS(wire)
	if err != nil {
		return CheckedHistoricalImpact{}
	}
	return CheckedHistoricalImpact{value: value, canonical: canonical, digest: digestBytes(canonical)}
}

func digestHistoryValue(value any) string {
	canonical, err := marshalSnapshotJCS(value)
	if err != nil {
		return digestBytes(nil)
	}
	return digestBytes(canonical)
}

func historyTime(value time.Time) string {
	return value.Round(0).UTC().Format(time.RFC3339Nano)
}

func historyOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return historyTime(value)
}
