package investigationstore

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/ai"
)

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	asciiIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	labelPattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	methodPattern     = regexp.MustCompile(`^[A-Z]{1,16}$`)
	timeoutPattern    = regexp.MustCompile(`^[1-9][0-9]{0,4}[smh]$`)
	confidencePattern = regexp.MustCompile(`^(?:0(?:\.[0-9]+)?|1(?:\.0+)?)$`)
)

var incidentStates = allowed("open", "analyzing", "review_ready", "analysis_failed", "closed")
var incidentKinds = allowed("credential_stuffing", "brute_force", "path_scan", "request_burst", "mixed", "unknown")
var policyStates = allowed("draft", "validating", "valid", "invalid", "stale", "approved", "rejected", "queued", "active", "expired", "failed", "revoked", "indeterminate")
var actionStates = allowed("approved", "queued", "active", "expired", "failed", "revoked", "indeterminate")
var analysisStates = allowed("started", "succeeded", "failed")
var validationStates = allowed("draft", "valid", "invalid", "stale")
var auditActorTypes = allowed("administrator", "system", "dispatcher", "executor")
var auditOutcomes = allowed("accepted", "rejected", "succeeded", "failed", "indeterminate")
var eventKinds = allowed("gateway", "auth", "source_health")
var trustStates = allowed("trusted", "untrusted")
var sourceHealthStates = allowed("complete", "incomplete")
var executionOperations = allowed("add", "revoke", "inspect")
var executionClassifications = allowed("applied", "recovered_active", "revoked", "inspect_active", "inspect_absent", "inspect_mismatch", "failed", "indeterminate")
var readbackStates = allowed("active", "absent", "mismatch", "unavailable")
var analysisFailureCodes = allowed(
	"budget_exhausted", "input_too_large", "network_error", "http_408", "http_409",
	"rate_limited", "server_error", "timeout", "refused", "incomplete", "schema_invalid",
	"evidence_invalid", "unsupported_action", "cancelled", "configuration_error",
)
var candidateParseStates = allowed("canonical", "validating", "valid", "stale")
var suspiciousPathIDs = allowed(
	"none", "admin_console", "env_file", "git_config", "wp_admin", "phpmyadmin",
	"server_status", "actuator_env", "backup_archive",
)
var bindingStates = allowed("pending", "verified", "untrusted")
var sourceEventStates = allowed("degraded", "lost", "recovered")
var sourceEventCauses = allowed(
	"queue_overflow", "delivery_outage", "rejected_batch", "sequence_gap",
	"permanent_loss", "unclean_restart", "unknown_loss", "recovered",
)
var executionErrorCodes = allowed(
	"none", "capability_invalid", "artifact_mismatch", "schema_mismatch", "target_exists",
	"target_absent", "nft_failed", "readback_failed", "readback_mismatch", "journal_failed",
	"deadline_exceeded", "replay_conflict", "indeterminate",
)
var validationGateNames = [...]string{
	"structured_output", "command_grammar", "policy_evidence_command_consistency",
	"protected_network", "owned_schema_syntax", "historical_impact",
}

func allowed(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func member(value string, set map[string]struct{}) bool {
	_, ok := set[value]
	return ok
}

func validUUID(value string) bool    { return uuidPattern.MatchString(value) }
func validDigest(value string) bool  { return digestPattern.MatchString(value) }
func validASCIIID(value string) bool { return asciiIDPattern.MatchString(value) }
func validLabel(value string) bool   { return labelPattern.MatchString(value) }

func validIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

func validFiniteTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 2000 && value.Year() <= 9999
}

func validOptionalTime(value *time.Time) bool {
	return value == nil || validFiniteTime(*value)
}

func normalizeLimit(value int) (int, bool) {
	if value == 0 {
		return DefaultPageLimit, true
	}
	return value, value >= 1 && value <= MaxPageLimit
}

func validIncidentQuery(query IncidentQuery) bool {
	if query.State != "" && !member(query.State, incidentStates) {
		return false
	}
	if query.Kind != "" && !member(query.Kind, incidentKinds) {
		return false
	}
	if query.SourceIP != "" && !validIPv4(query.SourceIP) {
		return false
	}
	if query.ServiceLabel != "" && !validLabel(query.ServiceLabel) {
		return false
	}
	if !validOptionalTime(query.From) || !validOptionalTime(query.Until) ||
		(query.From != nil && query.Until != nil && query.Until.Before(*query.From)) {
		return false
	}
	if query.Cursor.set && (!validFiniteTime(query.Cursor.time) || !validUUID(query.Cursor.id)) {
		return false
	}
	_, ok := normalizeLimit(query.Limit)
	return ok
}

func validIncident(value IncidentSummary) bool {
	if !validUUID(value.IncidentID) || !member(value.Kind, incidentKinds) ||
		!member(value.State, incidentStates) || !validIPv4(value.SourceIP) ||
		!validLabel(value.ServiceLabel) || value.Version < 1 ||
		!validFiniteTime(value.FirstSeen) || !validFiniteTime(value.LastSeen) ||
		!validFiniteTime(value.CreatedAt) || !validFiniteTime(value.UpdatedAt) ||
		value.LastSeen.Before(value.FirstSeen) || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	if (value.State == "closed") != (value.ClosedAt != nil) || !validOptionalTime(value.ClosedAt) {
		return false
	}
	if (value.State == "analysis_failed") != (value.AnalysisFailureCode != nil) {
		return false
	}
	if value.AnalysisFailureCode != nil && !member(*value.AnalysisFailureCode, analysisFailureCodes) {
		return false
	}
	score, err := strconv.ParseFloat(value.DeterministicScore, 64)
	return err == nil && score >= 0 && score <= 1
}

func validSignal(value SignalSummary) bool {
	return validUUID(value.SignalID) && validASCIIID(value.RuleID) && value.RuleVersion >= 1 &&
		member(value.Kind, incidentKinds) && value.Kind != "mixed" && value.Kind != "unknown" &&
		validFiniteTime(value.WindowStart) && validFiniteTime(value.WindowEnd) &&
		!value.WindowEnd.Before(value.WindowStart) && value.ObservedCount >= 1 &&
		(value.DistinctCount == nil || *value.DistinctCount >= 1) && value.ThresholdCount >= 1 &&
		(value.ThresholdDistinct == nil || *value.ThresholdDistinct >= 1) &&
		member(value.SourceHealth, sourceHealthStates) &&
		validDigest(value.EvidenceDigest)
}

func validAnalysis(value AnalysisSummary) bool {
	switch value.ProviderKind {
	case string(ai.ProviderOpenAIResponses):
		if value.Model == nil || value.ReasoningEffort == nil || value.RateCardVersion == nil {
			return false
		}
	case string(ai.ProviderDeterministicStub):
		if value.Model != nil || value.ReasoningEffort != nil || value.RateCardVersion != nil {
			return false
		}
	}
	model, reasoning, rateCard := "", "", ""
	if value.Model != nil {
		model = *value.Model
	}
	if value.ReasoningEffort != nil {
		reasoning = *value.ReasoningEffort
	}
	if value.RateCardVersion != nil {
		rateCard = *value.RateCardVersion
	}
	if _, ok := ai.ParseProviderIdentity(
		value.ProviderKind, value.AdapterID, model, reasoning, rateCard,
	); !ok || !validUUID(value.AnalysisID) || value.IncidentVersion < 1 ||
		!member(value.ResultState, analysisStates) || !validFiniteTime(value.StartedAt) ||
		!validOptionalTime(value.CompletedAt) || !validFalsePositiveFactors(value.FalsePositives) {
		return false
	}
	if value.ResultState == "started" {
		return value.CompletedAt == nil && value.FailureCode == nil && !hasAnalysisSuccessFields(value)
	}
	if value.CompletedAt == nil || value.CompletedAt.Before(value.StartedAt) {
		return false
	}
	if value.ResultState == "failed" {
		return value.FailureCode != nil && member(*value.FailureCode, analysisFailureCodes) &&
			!hasAnalysisSuccessFields(value)
	}
	if value.FailureCode != nil || value.OutputDigest == nil || !validDigest(*value.OutputDigest) ||
		value.Summary == nil || value.Classification == nil || value.Confidence == nil || value.Uncertainty == nil {
		return false
	}
	return len(*value.Confidence) <= 64 && confidencePattern.MatchString(*value.Confidence) &&
		member(*value.Classification, incidentKinds) && utf8.ValidString(*value.Summary) &&
		utf8.RuneCountInString(*value.Summary) >= 1 && utf8.RuneCountInString(*value.Summary) <= 1600 &&
		utf8.ValidString(*value.Uncertainty) && utf8.RuneCountInString(*value.Uncertainty) <= 800
}

func hasAnalysisSuccessFields(value AnalysisSummary) bool {
	return value.OutputDigest != nil || value.Summary != nil || value.Classification != nil ||
		value.Confidence != nil || value.Uncertainty != nil
}

func validFalsePositiveFactors(values []string) bool {
	if values == nil || len(values) > 5 {
		return false
	}
	for _, value := range values {
		if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 1 ||
			utf8.RuneCountInString(value) > 240 {
			return false
		}
	}
	return true
}

func validPolicySummary(value PolicySummary) bool {
	return validUUID(value.PolicyID) && value.Version >= 1 && value.IncidentVersion >= 1 &&
		member(value.State, policyStates) && value.StateRevision >= 1 && validIPv4(value.TargetIPv4) &&
		value.TTLSeconds >= 60 && value.TTLSeconds <= 86400 && validDigest(value.PolicyDigest) &&
		validDigest(value.EvidenceSnapshotDigest) && validFiniteTime(value.UpdatedAt)
}

func validIncidentEvent(value IncidentEvent) bool {
	if !validUUID(value.IncidentEventID) || !validUUID(value.EventID) || value.IncidentVersion < 1 ||
		!member(value.Kind, eventKinds) || !validFiniteTime(value.OccurredAt) ||
		!member(value.TrustState, trustStates) || !validASCIIID(value.RelationReason) ||
		value.TrustReason == "" || !validASCIIID(value.TrustReason) {
		return false
	}
	if value.TraceID != nil && !validUUID(*value.TraceID) || value.SourceIP != nil && !validIPv4(*value.SourceIP) ||
		value.ServiceLabel != nil && !validLabel(*value.ServiceLabel) || value.RouteLabel != nil && !validLabel(*value.RouteLabel) {
		return false
	}
	if value.TrustState == "trusted" && value.TrustReason != "none" ||
		value.TrustState == "untrusted" && value.TrustReason == "none" {
		return false
	}
	switch value.Kind {
	case "gateway":
		return value.SourceIP != nil && value.ServiceLabel != nil && value.RouteLabel != nil &&
			value.TraceID != nil && value.Method != nil && methodPattern.MatchString(*value.Method) &&
			value.StatusCode != nil && *value.StatusCode >= 100 && *value.StatusCode <= 599 &&
			value.SuspiciousPathID != nil && member(*value.SuspiciousPathID, suspiciousPathIDs) &&
			value.AuthOutcome == nil && value.BindingState == nil && value.HealthState == nil &&
			value.HealthCause == nil && value.DroppedCount == nil
	case "auth":
		return value.SourceIP != nil && value.ServiceLabel != nil && value.RouteLabel != nil &&
			value.TraceID != nil && value.AuthOutcome != nil && member(*value.AuthOutcome, allowed("failed", "succeeded")) &&
			value.BindingState != nil && member(*value.BindingState, bindingStates) && value.Method == nil &&
			value.StatusCode == nil && value.SuspiciousPathID == nil && value.HealthState == nil &&
			value.HealthCause == nil && value.DroppedCount == nil
	case "source_health":
		return value.HealthState != nil && member(*value.HealthState, sourceEventStates) &&
			value.HealthCause != nil && member(*value.HealthCause, sourceEventCauses) &&
			value.DroppedCount != nil && *value.DroppedCount >= 0 && value.TraceID == nil &&
			value.SourceIP == nil && value.ServiceLabel == nil && value.RouteLabel == nil &&
			value.Method == nil && value.StatusCode == nil && value.SuspiciousPathID == nil &&
			value.AuthOutcome == nil && value.BindingState == nil
	default:
		return false
	}
}

func validPolicy(value PolicyDetail) bool {
	if !validUUID(value.PolicyID) || value.Version < 1 || !validUUID(value.IncidentID) ||
		value.IncidentVersion < 1 || !validUUID(value.AnalysisID) || !validUUID(value.CommandCandidateID) ||
		!member(value.State, policyStates) || value.StateRevision < 1 || !validIPv4(value.TargetIPv4) ||
		value.Action != "block_ip" || value.TTLSeconds < 60 || value.TTLSeconds > 86400 ||
		!validDigest(value.PolicyDigest) || !validDigest(value.EvidenceSnapshotDigest) ||
		!validDigest(value.GeneratedDigest) || !validDigest(value.CanonicalDigest) ||
		!validFiniteTime(value.CreatedAt) || !validFiniteTime(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.CreatedAt) || !utf8.ValidString(value.GeneratedCommand) ||
		!utf8.ValidString(value.CanonicalCommand) || utf8.RuneCountInString(value.GeneratedCommand) > 256 ||
		len(value.CanonicalCommand) > 257 || strings.ContainsRune(value.GeneratedCommand, 0) ||
		strings.ContainsRune(value.CanonicalCommand, 0) || !strings.HasSuffix(value.CanonicalCommand, "\n") ||
		strings.HasSuffix(value.CanonicalCommand, "\n\n") || strings.Contains(value.CanonicalCommand, "\r") {
		return false
	}
	return timeoutPattern.MatchString(value.TimeoutToken) && value.Rationale != "" &&
		utf8.ValidString(value.Rationale) && utf8.RuneCountInString(value.Rationale) <= 800 &&
		member(value.ParseState, candidateParseStates) && value.ParseErrorCode == nil
}

func validValidation(value ValidationSummary) bool {
	if !validUUID(value.ValidationSnapshotID) || !validDigest(value.SnapshotDigest) ||
		!member(value.State, validationStates) || !member(value.SourceHealthStatus, sourceHealthStates) ||
		!validDigest(value.BaseChainRawDigest) || !validDigest(value.LiveOwnedSchemaDigest) ||
		!validDigest(value.ProtectedStaticDigest) || !validDigest(value.ProtectedEffectiveDigest) ||
		!validDigest(value.HistoricalImpactDigest) || !validFiniteTime(value.CreatedAt) ||
		!validFiniteTime(value.ValidUntil) || !value.ValidUntil.After(value.CreatedAt) {
		return false
	}
	if value.FailureCode != nil && !validASCIIID(*value.FailureCode) {
		return false
	}
	if value.HistoryDatasetDigest != nil && !validDigest(*value.HistoryDatasetDigest) ||
		value.HistoryManifestDigest != nil && !validDigest(*value.HistoryManifestDigest) {
		return false
	}
	if len(value.Gates) > len(validationGateNames) {
		return false
	}
	failed := false
	for index, gate := range value.Gates {
		if gate.Order != int16(index+1) || gate.Order < 1 || gate.Order > 6 ||
			gate.Name != validationGateNames[index] || !validASCIIID(gate.ResultCode) ||
			!validDigest(gate.InputDigest) || !validDigest(gate.ResultDigest) ||
			!validFiniteTime(gate.CheckedAt) {
			return false
		}
		if gate.Passed {
			if failed || gate.ResultCode != "ok" {
				return false
			}
			continue
		}
		if gate.ResultCode == "ok" || index != len(value.Gates)-1 {
			return false
		}
		failed = true
	}

	if failed != (value.FailureCode != nil) ||
		failed && *value.FailureCode != value.Gates[len(value.Gates)-1].ResultCode {
		return false
	}
	switch value.State {
	case "valid":
		return !failed && value.FailureCode == nil &&
			value.SourceHealthStatus == "complete" &&
			len(value.Gates) == len(validationGateNames)
	case "invalid":
		return failed
	case "draft", "stale":
		return true
	default:
		return false
	}
}

func validValidationAttempt(value ValidationAttemptSummary) bool {
	if !validUUID(value.ValidationAttemptID) || !validUUID(value.PolicyID) ||
		!validUUID(value.AnalysisID) || !validUUID(value.IncidentID) || value.IncidentVersion < 1 ||
		!member(value.State, allowed("valid", "invalid", "interrupted")) ||
		!validDigest(value.PreparedSnapshotDigest) || !validFiniteTime(value.CompletedAt) ||
		len(value.Gates) > len(validationGateNames) {
		return false
	}
	if value.FailureCode != nil && !validASCIIID(*value.FailureCode) ||
		value.FailedGate != nil && !member(*value.FailedGate, allowed(validationGateNames[:]...)) {
		return false
	}
	if value.TerminalMutationDigest != nil && !validDigest(*value.TerminalMutationDigest) {
		return false
	}
	failedIndex := -1
	for index, gate := range value.Gates {
		if gate.Order != int16(index+1) || gate.Name != validationGateNames[index] ||
			!member(gate.State, allowed("passed", "failed")) ||
			!validASCIIID(gate.ResultCode) || !validDigest(gate.ArtifactDigest) {
			return false
		}
		if gate.State == "passed" {
			if failedIndex >= 0 || gate.ResultCode != "ok" {
				return false
			}
			continue
		}
		if gate.ResultCode == "ok" || index != len(value.Gates)-1 || failedIndex >= 0 {
			return false
		}
		failedIndex = index
	}
	switch value.State {
	case "valid":
		return len(value.Gates) == len(validationGateNames) && failedIndex < 0 &&
			value.FailureCode == nil && value.FailedGate == nil && value.TerminalMutationDigest != nil
	case "invalid":
		return failedIndex >= 0 && value.FailureCode != nil && value.FailedGate != nil &&
			value.TerminalMutationDigest != nil &&
			*value.FailureCode == value.Gates[failedIndex].ResultCode &&
			*value.FailedGate == value.Gates[failedIndex].Name
	case "interrupted":
		return failedIndex < 0 && value.FailureCode != nil && value.FailedGate == nil &&
			value.TerminalMutationDigest == nil
	default:
		return false
	}
}

// validPolicyTerminalBinding makes the database read boundary reject a
// contradictory policy, validation snapshot, validation attempt, or HIL
// decision. A valid attempt remains the immutable origin for every later HIL
// and enforcement lifecycle state; invalid and interrupted attempts can never
// be review-ready or carry decision authority.
func validPolicyTerminalBinding(value PolicyDetail) bool {
	if value.ValidationAttempt == nil {
		return true
	}
	attempt := value.ValidationAttempt
	if attempt.PolicyID != value.PolicyID || attempt.AnalysisID != value.AnalysisID ||
		attempt.IncidentID != value.IncidentID || attempt.IncidentVersion != value.IncidentVersion {
		return false
	}
	switch attempt.State {
	case "invalid":
		return value.State == "invalid" && value.Validation == nil && value.Decision == nil
	case "interrupted":
		return member(value.State, allowed("invalid", "stale")) &&
			value.Validation == nil && value.Decision == nil
	case "valid":
		if value.Validation == nil {
			return false
		}
		if value.State == "stale" {
			if !member(value.Validation.State, allowed("valid", "stale")) {
				return false
			}
		} else if value.Validation.State != "valid" {
			return false
		}
		switch value.State {
		case "valid":
			return value.Decision == nil
		case "rejected":
			return value.Decision != nil && value.Decision.Decision == "rejected"
		case "approved", "queued", "active", "expired", "failed", "revoked", "indeterminate":
			return value.Decision != nil && value.Decision.Decision == "approved"
		case "stale":
			return value.Decision == nil || value.Decision.Decision == "approved"
		default:
			return false
		}
	default:
		return false
	}
}

func validDecision(value DecisionSummary) bool {
	return validUUID(value.DecisionID) && member(value.Decision, allowed("approved", "rejected", "revoked")) &&
		validASCIIID(value.ActorID) && validDigest(value.ReasonDigest) && validFiniteTime(value.DecidedAt)
}

func validAction(value EnforcementActionDetail) bool {
	if !validUUID(value.ActionID) || !validUUID(value.PolicyID) || value.PolicyVersion < 1 ||
		!validUUID(value.ValidationSnapshotID) || !validDigest(value.EvidenceSnapshotDigest) ||
		!validIPv4(value.TargetIPv4) || !validDigest(value.CanonicalDigest) || value.TTLSeconds < 60 ||
		value.TTLSeconds > 86400 || !member(value.State, actionStates) || !validFiniteTime(value.ApprovedAt) ||
		!validOptionalTime(value.QueuedAt) || !validOptionalTime(value.AppliedAt) ||
		!validOptionalTime(value.ExpectedExpiresAt) || !validOptionalTime(value.FinishedAt) || value.Version < 1 ||
		!validFiniteTime(value.CreatedAt) || !validFiniteTime(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	if value.QueuedAt != nil && value.QueuedAt.Before(value.ApprovedAt) ||
		value.ExpectedExpiresAt != nil && (value.AppliedAt == nil || !value.ExpectedExpiresAt.After(*value.AppliedAt)) {
		return false
	}
	return value.State != "active" || value.AppliedAt != nil && value.ExpectedExpiresAt != nil
}

func validExecutionResult(value ExecutionResultSummary) bool {
	if !validUUID(value.ResultID) || !member(value.Operation, executionOperations) ||
		!member(value.Classification, executionClassifications) || !member(value.ReadbackState, readbackStates) ||
		value.RemainingTTLSeconds != nil && (*value.RemainingTTLSeconds < 1 || *value.RemainingTTLSeconds > 86400) ||
		value.JournalSequence < 1 || !member(value.ErrorCode, executionErrorCodes) ||
		!validDigest(value.ResultDigest) || !validFiniteTime(value.PersistedAt) {
		return false
	}
	switch value.Operation {
	case "add":
		if !member(value.Classification, allowed("applied", "recovered_active", "failed", "indeterminate")) {
			return false
		}
	case "revoke":
		if !member(value.Classification, allowed("revoked", "failed", "indeterminate")) {
			return false
		}
	case "inspect":
		if !member(value.Classification, allowed("inspect_active", "inspect_absent", "inspect_mismatch", "failed", "indeterminate")) {
			return false
		}
	default:
		return false
	}
	if member(value.Classification, allowed("failed", "indeterminate")) {
		return value.ErrorCode != "none"
	}
	if value.ErrorCode != "none" {
		return false
	}
	switch value.Classification {
	case "applied", "recovered_active", "inspect_active":
		return value.ReadbackState == "active" && value.RemainingTTLSeconds != nil
	case "revoked", "inspect_absent":
		return value.ReadbackState == "absent" && value.RemainingTTLSeconds == nil
	case "inspect_mismatch":
		return value.ReadbackState == "mismatch"
	default:
		return false
	}
}

func validAuditQuery(query AuditQuery) bool {
	if query.IncidentID != "" && !validUUID(query.IncidentID) || query.PolicyID != "" && !validUUID(query.PolicyID) ||
		query.ActionID != "" && !validUUID(query.ActionID) ||
		query.ActorType != "" && !member(query.ActorType, auditActorTypes) ||
		query.ActorID != "" && !validASCIIID(query.ActorID) ||
		query.ObjectType != "" && !validASCIIID(query.ObjectType) ||
		query.ObjectID != "" && !validUUID(query.ObjectID) || query.TraceID != "" && !validUUID(query.TraceID) ||
		!validOptionalTime(query.From) ||
		!validOptionalTime(query.Until) || query.From != nil && query.Until != nil && query.Until.Before(*query.From) ||
		query.Cursor.set && query.Cursor.sequence <= 0 {
		return false
	}
	_, ok := normalizeLimit(query.Limit)
	return ok
}

func validAuditEvent(value AuditEvent) bool {
	if value.Sequence < 1 || !validUUID(value.EventID) || !member(value.ActorType, auditActorTypes) ||
		!validASCIIID(value.ActorID) || !validASCIIID(value.Action) || !validASCIIID(value.ObjectType) ||
		!member(value.Outcome, auditOutcomes) || !validFiniteTime(value.OccurredAt) || !validFiniteTime(value.RecordedAt) {
		return false
	}
	for _, id := range []*string{value.ObjectID, value.IncidentID, value.PolicyID, value.EnforcementActionID, value.TraceID} {
		if id != nil && !validUUID(*id) {
			return false
		}
	}
	for _, digest := range []*string{value.PrimaryDigest, value.SecondaryDigest} {
		if digest != nil && !validDigest(*digest) {
			return false
		}
	}
	return (value.PolicyID == nil) == (value.PolicyVersion == nil) &&
		(value.PolicyVersion == nil || *value.PolicyVersion >= 1) && !value.RecordedAt.Before(value.OccurredAt)
}
