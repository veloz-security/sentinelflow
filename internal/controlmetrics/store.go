package controlmetrics

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

const sampleQuery = `SELECT metric_name, label_1_name, label_1_value,
       label_2_name, label_2_value, sample_value
FROM sentinelflow.control_observability_samples_000028()`

var (
	ErrMetricsUnavailable = errors.New("control metrics unavailable")
	ErrInvalidSample      = errors.New("control metrics aggregate rejected")
)

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type Sample struct {
	Name        string
	Label1Name  string
	Label1Value string
	Label2Name  string
	Label2Value string
	Value       float64
}

type Store struct{ database queryer }

func NewStore(database queryer) (*Store, error) {
	if database == nil {
		return nil, ErrMetricsUnavailable
	}
	return &Store{database: database}, nil
}

func (s *Store) Collect(ctx context.Context) ([]Sample, error) {
	if s == nil || s.database == nil || ctx == nil {
		return nil, ErrMetricsUnavailable
	}
	rows, err := s.database.Query(ctx, sampleQuery)
	if err != nil {
		return nil, ErrMetricsUnavailable
	}
	defer rows.Close()
	samples := make([]Sample, 0, expectedSampleCount)
	for rows.Next() {
		var sample Sample
		var label1Name, label1Value, label2Name, label2Value *string
		if err := rows.Scan(&sample.Name, &label1Name, &label1Value, &label2Name, &label2Value, &sample.Value); err != nil {
			return nil, ErrMetricsUnavailable
		}
		if (label1Name == nil) != (label1Value == nil) ||
			(label2Name == nil) != (label2Value == nil) {
			return nil, ErrInvalidSample
		}
		sample.Label1Name, sample.Label1Value = nullablePair(label1Name, label1Value)
		sample.Label2Name, sample.Label2Value = nullablePair(label2Name, label2Value)
		samples = append(samples, sample)
		if len(samples) > 512 {
			return nil, ErrInvalidSample
		}
	}
	if rows.Err() != nil {
		return nil, ErrMetricsUnavailable
	}
	return validateCompleteSamples(samples)
}

func nullablePair(name, value *string) (string, string) {
	if name == nil || value == nil {
		return "", ""
	}
	return *name, *value
}

func sampleKey(sample Sample) string {
	return strings.Join([]string{sample.Name, sample.Label1Name, sample.Label1Value, sample.Label2Name, sample.Label2Value}, "\x00")
}

type labelContract struct {
	firstName    string
	firstValues  map[string]struct{}
	secondName   string
	secondValues map[string]struct{}
}

func values(items ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(items))
	for _, item := range items {
		result[item] = struct{}{}
	}
	return result
}

var contracts = map[string]labelContract{
	"sentinelflow_control_source_health_events_retained":       {"state", values("degraded", "lost", "recovered"), "cause", values("queue_overflow", "delivery_outage", "rejected_batch", "sequence_gap", "permanent_loss", "unclean_restart", "unknown_loss", "recovered")},
	"sentinelflow_control_source_dropped_records_retained":     {"cause", values("queue_overflow", "delivery_outage", "rejected_batch", "sequence_gap", "permanent_loss", "unclean_restart", "unknown_loss", "recovered"), "", nil},
	"sentinelflow_control_sources_current":                     {"state", values("degraded", "lost", "recovered"), "", nil},
	"sentinelflow_control_source_health_untrusted_retained":    {"reason", values("timestamp_skew", "batch_conflict"), "", nil},
	"sentinelflow_control_expected_sources":                    {"endpoint", values("gateway", "auth"), "state", values("healthy", "missing_report", "open_gap", "checkpoint_stale", "degraded", "lost")},
	"sentinelflow_control_event_last_seen_available":           {"endpoint", values("gateway", "auth"), "", nil},
	"sentinelflow_control_event_lag_seconds":                   {"endpoint", values("gateway", "auth"), "", nil},
	"sentinelflow_control_auth_bindings_retained":              {"state", values("pending", "verified", "untrusted"), "", nil},
	"sentinelflow_control_auth_binding_overdue":                {},
	"sentinelflow_control_signals_retained":                    {"kind", values("path_scan", "request_burst", "brute_force", "credential_stuffing"), "source_health", values("complete", "incomplete")},
	"sentinelflow_control_incidents_current":                   {"kind", values("credential_stuffing", "brute_force", "path_scan", "request_burst", "mixed", "unknown"), "state", values("open", "analyzing", "review_ready", "analysis_failed", "closed")},
	"sentinelflow_control_ingest_gaps_open":                    {},
	"sentinelflow_control_sender_checkpoint_stale_seconds":     {},
	"sentinelflow_control_outbox_jobs":                         {"kind", values("detect", "correlate", "analyze", "validate", "dispatch_add", "dispatch_revoke", "dispatch_inspect", "reconcile", "retention", "audit_recovery"), "state", values("pending", "leased", "retry", "completed", "dead")},
	"sentinelflow_control_outbox_oldest_ready_age_seconds":     {"kind", values("detect", "correlate", "analyze", "validate", "dispatch_add", "dispatch_revoke", "dispatch_inspect", "reconcile", "retention", "audit_recovery"), "", nil},
	"sentinelflow_control_outbox_lease_expiry_lag_seconds":     {"kind", values("detect", "correlate", "analyze", "validate", "dispatch_add", "dispatch_revoke", "dispatch_inspect", "reconcile", "retention", "audit_recovery"), "", nil},
	"sentinelflow_control_dead_letters_unresolved":             {"kind", values("detect", "correlate", "analyze", "validate", "dispatch_add", "dispatch_revoke", "dispatch_inspect", "reconcile", "retention", "audit_recovery"), "", nil},
	"sentinelflow_control_analysis_attempts_retained":          {"state", values("started", "succeeded", "failed", "interrupted", "no_call"), "", nil},
	"sentinelflow_control_analysis_success_retained":           {"provider", values("openai_responses", "deterministic_stub"), "", nil},
	"sentinelflow_control_ai_failures_5m":                      {},
	"sentinelflow_control_ai_started_stale":                    {},
	"sentinelflow_control_ai_budget_micro_usd":                 {"kind", values("limit", "reserved", "consumed", "remaining"), "", nil},
	"sentinelflow_control_ai_reservations":                     {"state", values("active", "settled", "expired"), "", nil},
	"sentinelflow_control_ai_latency_seconds":                  {"statistic", values("average", "p95", "maximum"), "", nil},
	"sentinelflow_control_ai_tokens_retained":                  {"kind", values("input", "cached_input", "output"), "", nil},
	"sentinelflow_control_ai_errors_retained":                  {"reason", values("budget_exhausted", "input_too_large", "network_error", "http_408", "http_409", "rate_limited", "server_error", "timeout", "refused", "incomplete", "schema_invalid", "evidence_invalid", "cancelled", "configuration_error", "analysis_interrupted", "source_health_incomplete", "history_incomplete", "snapshot_incomplete"), "", nil},
	"sentinelflow_control_validation_attempts_retained":        {"state", values("started", "valid", "invalid", "interrupted"), "", nil},
	"sentinelflow_control_validation_gates_retained":           {"gate", values("structured_output", "command_grammar", "policy_evidence_command_consistency", "protected_network", "owned_schema_syntax", "historical_impact"), "result", values("passed", "failed")},
	"sentinelflow_control_validation_started_stale":            {},
	"sentinelflow_control_validation_failures_5m":              {},
	"sentinelflow_control_validation_failures_retained":        {"reason", values("structured_output", "command_grammar", "policy_evidence_command_consistency", "protected_network", "owned_schema_syntax", "historical_impact", "interrupted"), "", nil},
	"sentinelflow_control_hil_challenges":                      {"operation", values("approve", "reject", "revoke"), "state", values("pending", "expired", "consumed")},
	"sentinelflow_control_hil_decisions_retained":              {"decision", values("approved", "rejected", "revoked"), "", nil},
	"sentinelflow_control_approval_latency_seconds":            {"statistic", values("average", "p95", "maximum"), "", nil},
	"sentinelflow_control_hil_expired_recent_5m":               {},
	"sentinelflow_control_revocations":                         {"state", values("authorized", "queued", "revoked", "failed", "indeterminate"), "", nil},
	"sentinelflow_control_dispatch_jobs":                       {"operation", values("add", "revoke", "inspect"), "state", values("pending", "leased", "retry", "completed", "dead")},
	"sentinelflow_control_execution_capabilities":              {"operation", values("add", "revoke", "inspect"), "state", values("consumed", "unconsumed_valid", "unconsumed_expired")},
	"sentinelflow_control_execution_results_retained":          {"operation", values("add", "revoke", "inspect"), "classification", values("applied", "recovered_active", "revoked", "inspect_active", "inspect_absent", "inspect_mismatch", "failed", "indeterminate")},
	"sentinelflow_control_execution_replay_conflicts_retained": {},
	"sentinelflow_control_enforcement_actions":                 {"state", values("approved", "queued", "active", "expired", "failed", "revoked", "indeterminate"), "", nil},
	"sentinelflow_control_enforcement_expiry_lag_seconds":      {},
	"sentinelflow_control_enforcement_early_missing":           {},
	"sentinelflow_control_dispatch_failures_5m":                {},
	"sentinelflow_control_lifecycle_schedules":                 {"purpose", values("reconciliation", "expiry_confirmation", "operator_status"), "state", values("pending", "leased", "retry", "dispatched", "completed", "dead")},
	"sentinelflow_control_lifecycle_oldest_due_age_seconds":    {"purpose", values("reconciliation", "expiry_confirmation", "operator_status"), "", nil},
	"sentinelflow_control_lifecycle_lease_expiry_lag_seconds":  {"purpose", values("reconciliation", "expiry_confirmation", "operator_status"), "", nil},
	"sentinelflow_control_audit_events_retained":               {"outcome", values("accepted", "rejected", "succeeded", "failed", "indeterminate"), "", nil},
	"sentinelflow_control_audit_latest_age_seconds":            {},
	"sentinelflow_control_audit_recovery_jobs":                 {"state", values("pending", "leased", "retry", "completed", "dead"), "", nil},
	"sentinelflow_control_sse_latest_age_seconds":              {},
	"sentinelflow_control_sse_replay_span":                     {},
	"sentinelflow_control_sse_watermark_lag":                   {},
	"sentinelflow_control_sse_clients":                         {},
	"sentinelflow_control_sse_clients_observable":              {},
}

var expectedSampleCount = contractSampleCount()

func validateCompleteSamples(samples []Sample) ([]Sample, error) {
	if len(samples) != expectedSampleCount || len(samples) > 512 {
		return nil, ErrInvalidSample
	}
	ordered := append([]Sample(nil), samples...)
	seen := make(map[string]struct{}, len(ordered))
	for _, sample := range ordered {
		if !validSample(sample) {
			return nil, ErrInvalidSample
		}
		key := sampleKey(sample)
		if _, exists := seen[key]; exists {
			return nil, ErrInvalidSample
		}
		seen[key] = struct{}{}
	}
	sort.Slice(ordered, func(i, j int) bool {
		return sampleKey(ordered[i]) < sampleKey(ordered[j])
	})
	return ordered, nil
}

func contractSampleCount() int {
	total := 0
	for _, contract := range contracts {
		if contract.firstName == "" {
			total++
			continue
		}
		count := len(contract.firstValues)
		if contract.secondName != "" {
			count *= len(contract.secondValues)
		}
		total += count
	}
	return total
}

func validSample(sample Sample) bool {
	contract, ok := contracts[sample.Name]
	if !ok || math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value < 0 {
		return false
	}
	if contract.firstName == "" {
		return sample.Label1Name == "" && sample.Label1Value == "" &&
			sample.Label2Name == "" && sample.Label2Value == ""
	}
	if sample.Label1Name != contract.firstName {
		return false
	}
	if _, ok := contract.firstValues[sample.Label1Value]; !ok {
		return false
	}
	if contract.secondName == "" {
		return sample.Label2Name == "" && sample.Label2Value == ""
	}
	if sample.Label2Name != contract.secondName {
		return false
	}
	_, ok = contract.secondValues[sample.Label2Value]
	return ok
}
