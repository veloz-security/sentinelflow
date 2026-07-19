package controlmetrics

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestControlPlaneAlertRulesAreFixedActionableAndIdentifierFree(t *testing.T) {
	t.Parallel()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path unavailable")
	}
	path := filepath.Join(filepath.Dir(currentFile), "..", "..", "deployments", "observability", "control-plane-alerts.yaml")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	alerts := []string{
		"SentinelFlowControlMetricsTargetUnavailable",
		"SentinelFlowGatewayMetricsTargetUnavailable",
		"SentinelFlowOutboxReadyBacklog", "SentinelFlowDeadLetterUnresolved",
		"SentinelFlowLifecycleScheduleOverdue", "SentinelFlowLifecycleScheduleRetrying",
		"SentinelFlowLifecycleScheduleDead",
		"SentinelFlowSourceCoverageDegraded", "SentinelFlowEventStreamUnavailable",
		"SentinelFlowEventLag", "SentinelFlowAuthBindingOverdue",
		"SentinelFlowGatewayEventDrop", "SentinelFlowGatewayEventQueueSaturation",
		"SentinelFlowEventDeliveryFailure",
		"SentinelFlowGatewayLatencySLOBreach",
		"SentinelFlowGatewayOriginFailure",
		"SentinelFlowAIProviderOutage", "SentinelFlowValidationFailure",
		"SentinelFlowAIBudgetExhausted",
		"SentinelFlowApprovalBacklog", "SentinelFlowApprovalExpired",
		"SentinelFlowDispatchFailure", "SentinelFlowExecutionReplayConflict",
		"SentinelFlowCapabilityExpiredUnused", "SentinelFlowRevocationFailure",
		"SentinelFlowEnforcementFailure", "SentinelFlowEnforcementExpiryLag",
		"SentinelFlowEnforcementEarlyMissing", "SentinelFlowAuditRecoveryStalled",
		"SentinelFlowSSELedgerStale", "SentinelFlowSSEClientObservabilityUnavailable",
		"SentinelFlowSSEClientCapacity",
	}
	for _, alert := range alerts {
		if strings.Count(text, "- alert: "+alert+"\n") != 1 {
			t.Fatalf("alert %s missing or duplicated", alert)
		}
	}
	if strings.Count(text, "      - alert:") != len(alerts) ||
		strings.Count(text, "        expr:") != len(alerts) ||
		strings.Count(text, "        for:") != len(alerts) ||
		strings.Count(text, "          severity:") != len(alerts) {
		t.Fatal("alert structure is incomplete")
	}
	for _, forbidden := range []string{
		"incident_id", "policy_id", "action_id", "request_id", "trace_id",
		"source_ip", "target_ipv4", "actor_id", "account", "digest", "path=",
		"{{", "}}", "$labels", "$value",
	} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("alert rules contain forbidden identifier/template %q", forbidden)
		}
	}
}

func TestQueueAndDispatchAlertsTrackCurrentRecoverableState(t *testing.T) {
	t.Parallel()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path unavailable")
	}
	payload, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "..", "..", "deployments", "observability", "control-plane-alerts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, required := range []string{
		"sentinelflow_event_queue_depth / sentinelflow_event_queue_capacity >= 0.8",
		`sentinelflow_control_dead_letters_unresolved{kind=~"dispatch_add|dispatch_revoke|dispatch_inspect|reconcile"}`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("current-state alert contract missing %q", required)
		}
	}
	if strings.Contains(text, `sentinelflow_control_dispatch_jobs{state="dead"}`) {
		t.Fatal("historical dead dispatch jobs still create a permanent alert")
	}
}

func TestIdleHealthyLedgersDoNotTriggerStalenessAlerts(t *testing.T) {
	t.Parallel()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path unavailable")
	}
	payload, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "..", "..", "deployments", "observability", "control-plane-alerts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	if strings.Contains(text, "sentinelflow_control_sse_latest_age_seconds >") ||
		!strings.Contains(text, "sum(sentinelflow_control_audit_recovery_jobs{state=~\"pending|retry|leased\"}) > 0 and sentinelflow_control_audit_latest_age_seconds > 600") ||
		!strings.Contains(text, "sentinelflow_control_dead_letters_unresolved{kind=\"audit_recovery\"}") ||
		strings.Contains(text, "sentinelflow_control_audit_recovery_jobs{state=\"dead\"}") ||
		!strings.Contains(text, "expr: sentinelflow_control_sse_watermark_lag > 0") ||
		!strings.Contains(text, "expr: sentinelflow_control_hil_expired_recent_5m > 0") ||
		strings.Contains(text, "hil_challenges{state=\"expired\"") {
		t.Fatal("idle healthy audit or SSE ledgers would trigger a false-positive alert")
	}
}
