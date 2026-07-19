package investigationstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestValidValidationAcceptsStateSpecificOrderedGateShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		state       string
		passedCount int
		failureCode string
		source      string
	}{
		{name: "valid has all six passed gates", state: "valid", passedCount: 6, source: "complete"},
		{name: "invalid may fail first gate", state: "invalid", failureCode: "schema_invalid", source: "incomplete"},
		{name: "invalid may fail after passed prefix", state: "invalid", passedCount: 3, failureCode: "protected_target", source: "complete"},
		{name: "invalid may fail final gate", state: "invalid", passedCount: 5, failureCode: "history_incomplete", source: "incomplete"},
		{name: "draft may have no gates", state: "draft", source: "incomplete"},
		{name: "draft may expose passed prefix", state: "draft", passedCount: 3, source: "complete"},
		{name: "draft may expose terminal failure", state: "draft", passedCount: 1, failureCode: "grammar_invalid", source: "complete"},
		{name: "stale may retain all successful gates", state: "stale", passedCount: 6, source: "complete"},
		{name: "stale may retain partial prefix", state: "stale", passedCount: 2, source: "incomplete"},
		{name: "stale may retain terminal failure", state: "stale", passedCount: 4, failureCode: "nft_check_failed", source: "complete"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validationSummary(test.state, test.passedCount, test.failureCode)
			value.SourceHealthStatus = test.source
			if !validValidation(value) {
				t.Fatalf("validValidation(%s, gates=%d, failure=%q) = false", test.state, len(value.Gates), test.failureCode)
			}
		})
	}
}

func TestValidValidationRejectsMalformedGateSequences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		base   ValidationSummary
		mutate func(*ValidationSummary)
	}{
		{
			name: "valid missing gate",
			base: validationSummary("valid", 6, ""),
			mutate: func(value *ValidationSummary) {
				value.Gates = value.Gates[:5]
			},
		},
		{
			name: "valid failed gate",
			base: validationSummary("valid", 6, ""),
			mutate: func(value *ValidationSummary) {
				failure := "history_incomplete"
				value.Gates[5].Passed = false
				value.Gates[5].ResultCode = failure
				value.FailureCode = &failure
			},
		},
		{
			name: "valid incomplete source health",
			base: validationSummary("valid", 6, ""),
			mutate: func(value *ValidationSummary) {
				value.SourceHealthStatus = "incomplete"
			},
		},
		{
			name: "invalid missing failure gate",
			base: validationSummary("invalid", 2, "grammar_invalid"),
			mutate: func(value *ValidationSummary) {
				value.Gates = value.Gates[:2]
			},
		},
		{
			name: "invalid missing failure code",
			base: validationSummary("invalid", 2, "grammar_invalid"),
			mutate: func(value *ValidationSummary) {
				value.FailureCode = nil
			},
		},
		{
			name: "invalid mismatched failure code",
			base: validationSummary("invalid", 2, "grammar_invalid"),
			mutate: func(value *ValidationSummary) {
				failure := "different_failure"
				value.FailureCode = &failure
			},
		},
		{
			name: "invalid without any gates",
			base: validationSummary("invalid", 0, "schema_invalid"),
			mutate: func(value *ValidationSummary) {
				value.Gates = nil
			},
		},
		{
			name: "passed gate after failure",
			base: validationSummary("invalid", 2, "grammar_invalid"),
			mutate: func(value *ValidationSummary) {
				value.Gates = append(value.Gates, validationGate(4, true, "ok"))
			},
		},
		{
			name: "failed gate is not terminal",
			base: validationSummary("invalid", 2, "grammar_invalid"),
			mutate: func(value *ValidationSummary) {
				value.Gates = append(value.Gates, validationGate(4, false, "later_failure"))
			},
		},
		{
			name: "failed gate reports ok",
			base: validationSummary("invalid", 2, "grammar_invalid"),
			mutate: func(value *ValidationSummary) {
				value.Gates[2].ResultCode = "ok"
			},
		},
		{
			name: "passed gate reports failure",
			base: validationSummary("draft", 2, ""),
			mutate: func(value *ValidationSummary) {
				value.Gates[1].ResultCode = "unexpected"
			},
		},
		{
			name: "failure code without failed gate",
			base: validationSummary("stale", 6, ""),
			mutate: func(value *ValidationSummary) {
				failure := "leftover_failure"
				value.FailureCode = &failure
			},
		},
		{
			name: "skipped gate order",
			base: validationSummary("draft", 3, ""),
			mutate: func(value *ValidationSummary) {
				value.Gates[2].Order = 4
			},
		},
		{
			name: "reordered gate name",
			base: validationSummary("draft", 3, ""),
			mutate: func(value *ValidationSummary) {
				value.Gates[1].Name, value.Gates[2].Name = value.Gates[2].Name, value.Gates[1].Name
			},
		},
		{
			name: "duplicate gate name",
			base: validationSummary("draft", 3, ""),
			mutate: func(value *ValidationSummary) {
				value.Gates[2].Name = value.Gates[1].Name
			},
		},
		{
			name: "too many gates",
			base: validationSummary("draft", 6, ""),
			mutate: func(value *ValidationSummary) {
				value.Gates = append(value.Gates, validationGate(7, true, "ok"))
			},
		},
		{
			name: "malformed gate digest",
			base: validationSummary("draft", 1, ""),
			mutate: func(value *ValidationSummary) {
				value.Gates[0].ResultDigest = "bad"
			},
		},
		{
			name: "zero gate time",
			base: validationSummary("draft", 1, ""),
			mutate: func(value *ValidationSummary) {
				value.Gates[0].CheckedAt = time.Time{}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := test.base
			value.Gates = append([]ValidationGate(nil), test.base.Gates...)
			if test.mutate != nil {
				test.mutate(&value)
			}
			if validValidation(value) {
				t.Fatalf("malformed validation accepted: state=%s failure=%v gates=%+v", value.State, value.FailureCode, value.Gates)
			}
		})
	}
}

func TestLatestValidationReturnsInvalidSnapshotWithFailedGatePrefix(t *testing.T) {
	t.Parallel()

	failure := "protected_target"
	db := &queryStub{
		queryRow: func(query string, args []any) pgx.Row {
			if query != latestValidationSQL || len(args) != 2 || args[0] != testPolicyID || args[1] != int32(1) {
				t.Fatalf("query=%q args=%#v", query, args)
			}
			return valuesRow(
				testValidationID, testDigest, "invalid", failure, "complete",
				testDigest, testDigest, testDigest, testDigest, testDigest,
				nil, nil, testNow, testNow.Add(5*time.Minute),
			)
		},
		query: func(query string, args []any) (pgx.Rows, error) {
			if query != validationGatesSQL || len(args) != 1 || args[0] != testValidationID {
				t.Fatalf("query=%q args=%#v", query, args)
			}
			gates := validationSummary("invalid", 3, failure).Gates
			rows := make([][]any, len(gates))
			for index, gate := range gates {
				rows[index] = []any{
					gate.Order, gate.Name, gate.Passed, gate.ResultCode,
					gate.InputDigest, gate.ResultDigest, gate.CheckedAt,
				}
			}
			return rowsOf(rows...), nil
		},
	}
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}

	value, err := store.latestValidation(context.Background(), testPolicyID, 1)
	if err != nil {
		t.Fatalf("latestValidation() error = %v", err)
	}
	if value.State != "invalid" || value.FailureCode == nil || *value.FailureCode != failure ||
		len(value.Gates) != 4 || value.Gates[3].Passed {
		t.Fatalf("latestValidation() = %+v", value)
	}
}

func TestValidValidationAttemptAcceptsTerminalShapes(t *testing.T) {
	t.Parallel()

	valid := validationAttempt("valid", 6, "")
	invalid := validationAttempt("invalid", 5, "history_demo_binding_mismatch")
	interrupted := validationAttempt("interrupted", 3, "validation_attempt_timeout")
	for _, value := range []ValidationAttemptSummary{valid, invalid, interrupted} {
		if !validValidationAttempt(value) {
			t.Fatalf("validValidationAttempt(%s) = false: %+v", value.State, value)
		}
	}
}

func TestValidValidationAttemptRejectsInconsistentTerminalEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		value  ValidationAttemptSummary
		mutate func(*ValidationAttemptSummary)
	}{
		{name: "valid missing gate", value: validationAttempt("valid", 6, ""), mutate: func(value *ValidationAttemptSummary) { value.Gates = value.Gates[:5] }},
		{name: "invalid failure mismatch", value: validationAttempt("invalid", 5, "history_demo_binding_mismatch"), mutate: func(value *ValidationAttemptSummary) { failure := "different_failure"; value.FailureCode = &failure }},
		{name: "invalid failed gate mismatch", value: validationAttempt("invalid", 5, "history_demo_binding_mismatch"), mutate: func(value *ValidationAttemptSummary) { gate := "protected_network"; value.FailedGate = &gate }},
		{name: "interrupted failed gate", value: validationAttempt("interrupted", 3, "validation_attempt_timeout"), mutate: func(value *ValidationAttemptSummary) { gate := "protected_network"; value.FailedGate = &gate }},
		{name: "interrupted terminal failed gate evidence", value: validationAttempt("interrupted", 3, "validation_attempt_timeout"), mutate: func(value *ValidationAttemptSummary) {
			value.Gates[2].State = "failed"
			value.Gates[2].ResultCode = "timeout"
		}},
		{name: "skipped prefix", value: validationAttempt("interrupted", 3, "validation_attempt_timeout"), mutate: func(value *ValidationAttemptSummary) { value.Gates[1].Order = 3 }},
		{name: "malformed digest", value: validationAttempt("valid", 6, ""), mutate: func(value *ValidationAttemptSummary) { value.PreparedSnapshotDigest = "secret" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := test.value
			value.Gates = append([]ValidationAttemptGate(nil), value.Gates...)
			test.mutate(&value)
			if validValidationAttempt(value) {
				t.Fatalf("malformed attempt accepted: %+v", value)
			}
		})
	}
}

func TestValidPolicyTerminalBindingAcceptsExactLifecycleStates(t *testing.T) {
	t.Parallel()
	approved := DecisionSummary{Decision: "approved"}
	rejected := DecisionSummary{Decision: "rejected"}
	validSnapshot := ValidationSummary{State: "valid"}
	staleSnapshot := ValidationSummary{State: "stale"}
	for _, test := range []struct {
		name       string
		state      string
		validation *ValidationSummary
		decision   *DecisionSummary
	}{
		{name: "review ready", state: "valid", validation: &validSnapshot},
		{name: "approved", state: "approved", validation: &validSnapshot, decision: &approved},
		{name: "active", state: "active", validation: &validSnapshot, decision: &approved},
		{name: "expired", state: "expired", validation: &validSnapshot, decision: &approved},
		{name: "rejected", state: "rejected", validation: &validSnapshot, decision: &rejected},
		{name: "stale before decision", state: "stale", validation: &validSnapshot},
		{name: "stale after approval", state: "stale", validation: &staleSnapshot, decision: &approved},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := policyWithValidationAttempt("valid", test.state)
			policy.Validation = test.validation
			policy.Decision = test.decision
			if !validPolicyTerminalBinding(policy) {
				t.Fatalf("binding rejected: %+v", policy)
			}
		})
	}

	invalid := policyWithValidationAttempt("invalid", "invalid")
	if !validPolicyTerminalBinding(invalid) {
		t.Fatalf("invalid fail-closed binding rejected: %+v", invalid)
	}
	interrupted := policyWithValidationAttempt("interrupted", "stale")
	if !validPolicyTerminalBinding(interrupted) {
		t.Fatalf("interrupted fail-closed binding rejected: %+v", interrupted)
	}
}

func TestValidPolicyTerminalBindingRejectsContradictoryAuthority(t *testing.T) {
	t.Parallel()
	approved := DecisionSummary{Decision: "approved"}
	rejected := DecisionSummary{Decision: "rejected"}
	validSnapshot := ValidationSummary{State: "valid"}
	for _, test := range []struct {
		name   string
		policy PolicyDetail
	}{
		{name: "valid attempt without snapshot", policy: policyWithValidationAttempt("valid", "valid")},
		{name: "invalid attempt review ready", policy: policyWithValidationAttempt("invalid", "valid")},
		{name: "interrupted attempt review ready", policy: policyWithValidationAttempt("interrupted", "valid")},
		{name: "invalid attempt with snapshot", policy: func() PolicyDetail {
			value := policyWithValidationAttempt("invalid", "invalid")
			value.Validation = &validSnapshot
			return value
		}()},
		{name: "interrupted attempt with decision", policy: func() PolicyDetail {
			value := policyWithValidationAttempt("interrupted", "stale")
			value.Decision = &approved
			return value
		}()},
		{name: "approved without decision", policy: func() PolicyDetail {
			value := policyWithValidationAttempt("valid", "approved")
			value.Validation = &validSnapshot
			return value
		}()},
		{name: "approved with rejection", policy: func() PolicyDetail {
			value := policyWithValidationAttempt("valid", "approved")
			value.Validation, value.Decision = &validSnapshot, &rejected
			return value
		}()},
		{name: "cross incident attempt", policy: func() PolicyDetail {
			value := policyWithValidationAttempt("invalid", "invalid")
			value.ValidationAttempt.IncidentID = testIncidentID2
			return value
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if validPolicyTerminalBinding(test.policy) {
				t.Fatalf("contradictory binding accepted: %+v", test.policy)
			}
		})
	}
}

func policyWithValidationAttempt(attemptState, policyState string) PolicyDetail {
	attempt := validationAttempt(attemptState, 0, "validation_attempt_timeout")
	if attemptState == "valid" {
		attempt = validationAttempt("valid", 6, "")
	} else if attemptState == "invalid" {
		attempt = validationAttempt("invalid", 5, "history_demo_binding_mismatch")
	}
	return PolicyDetail{
		PolicyID: testPolicyID, IncidentID: testIncidentID, IncidentVersion: 2,
		AnalysisID: testAnalysisID, State: policyState, ValidationAttempt: &attempt,
	}
}

func TestLatestValidationAttemptReturnsInvalidFailureEvidence(t *testing.T) {
	t.Parallel()

	failure := "history_demo_binding_mismatch"
	failedGate := "historical_impact"
	db := &queryStub{
		query: func(query string, args []any) (pgx.Rows, error) {
			if query != latestValidationAttemptSQL || len(args) != 1 || args[0] != testPolicyID {
				t.Fatalf("query=%q args=%#v", query, args)
			}
			attempt := validationAttempt("invalid", 5, failure)
			gates := attempt.Gates
			rows := make([][]any, len(gates))
			for index, gate := range gates {
				rows[index] = validationAttemptRow(attempt, &gate)
			}
			return rowsOf(rows...), nil
		},
	}
	store, _ := NewPostgreSQLStore(db)
	value, err := store.latestValidationAttempt(context.Background(), testPolicyID)
	if err != nil || value.State != "invalid" || value.FailureCode == nil ||
		*value.FailureCode != failure || value.FailedGate == nil || *value.FailedGate != failedGate ||
		len(value.Gates) != 6 || value.Gates[5].State != "failed" || value.TerminalMutationDigest == nil {
		t.Fatalf("attempt=%+v err=%v", value, err)
	}
}

func TestLatestValidationAttemptReturnsInterruptedWithoutGateOrMutation(t *testing.T) {
	t.Parallel()
	attempt := validationAttempt("interrupted", 0, "validation_attempt_timeout")
	db := &queryStub{query: func(query string, args []any) (pgx.Rows, error) {
		if query != latestValidationAttemptSQL || len(args) != 1 || args[0] != testPolicyID {
			t.Fatalf("query=%q args=%#v", query, args)
		}
		return rowsOf(validationAttemptRow(attempt, nil)), nil
	}}
	store, _ := NewPostgreSQLStore(db)
	value, err := store.latestValidationAttempt(context.Background(), testPolicyID)
	if err != nil || value.State != "interrupted" || value.FailureCode == nil ||
		value.FailedGate != nil || value.TerminalMutationDigest != nil || len(value.Gates) != 0 {
		t.Fatalf("attempt=%+v err=%v", value, err)
	}
}

func TestLatestValidationAttemptSanitizesDatabaseFailures(t *testing.T) {
	t.Parallel()
	secret := errors.New("postgresql://admin:secret@10.0.0.8")
	store, _ := NewPostgreSQLStore(&queryStub{query: func(string, []any) (pgx.Rows, error) { return nil, secret }})
	_, err := store.latestValidationAttempt(context.Background(), testPolicyID)
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "10.0.0.8") {
		t.Fatalf("unsanitized error=%v", err)
	}
}

func validationAttempt(state string, passedCount int, failureCode string) ValidationAttemptSummary {
	value := ValidationAttemptSummary{
		ValidationAttemptID:    testValidationID,
		PolicyID:               testPolicyID,
		AnalysisID:             testAnalysisID,
		IncidentID:             testIncidentID,
		IncidentVersion:        2,
		State:                  state,
		PreparedSnapshotDigest: testDigest,
		CompletedAt:            testNow,
		Gates:                  make([]ValidationAttemptGate, 0, passedCount+1),
	}
	if state != "interrupted" {
		terminalDigest := testDigest
		value.TerminalMutationDigest = &terminalDigest
	}
	for index := 0; index < passedCount; index++ {
		value.Gates = append(value.Gates, validationAttemptGate(index+1, "passed", "ok"))
	}
	if failureCode != "" {
		value.FailureCode = &failureCode
		if state == "invalid" {
			gate := validationAttemptGate(passedCount+1, "failed", failureCode)
			value.FailedGate = &gate.Name
			value.Gates = append(value.Gates, gate)
		}
	}
	return value
}

func validationAttemptGate(order int, state, resultCode string) ValidationAttemptGate {
	name := "invalid"
	if order >= 1 && order <= len(validationGateNames) {
		name = validationGateNames[order-1]
	}
	return ValidationAttemptGate{
		Order: int16(order), Name: name, State: state, ResultCode: resultCode,
		ArtifactDigest: testDigest,
	}
}

func validationAttemptRow(attempt ValidationAttemptSummary, gate *ValidationAttemptGate) []any {
	values := []any{
		attempt.ValidationAttemptID, attempt.PolicyID, attempt.AnalysisID,
		attempt.IncidentID, attempt.IncidentVersion, attempt.State,
		attempt.FailureCode, attempt.FailedGate, attempt.PreparedSnapshotDigest,
		attempt.TerminalMutationDigest, attempt.CompletedAt,
	}
	if gate == nil {
		return append(values, nil, nil, nil, nil, nil)
	}
	return append(values, gate.Order, gate.Name, gate.State, gate.ResultCode, gate.ArtifactDigest)
}

func validationSummary(state string, passedCount int, failureCode string) ValidationSummary {
	value := ValidationSummary{
		ValidationSnapshotID:     testValidationID,
		SnapshotDigest:           testDigest,
		State:                    state,
		SourceHealthStatus:       "complete",
		BaseChainRawDigest:       testDigest,
		LiveOwnedSchemaDigest:    testDigest,
		ProtectedStaticDigest:    testDigest,
		ProtectedEffectiveDigest: testDigest,
		HistoricalImpactDigest:   testDigest,
		CreatedAt:                testNow,
		ValidUntil:               testNow.Add(5 * time.Minute),
		Gates:                    make([]ValidationGate, 0, passedCount+1),
	}
	for index := 0; index < passedCount; index++ {
		value.Gates = append(value.Gates, validationGate(index+1, true, "ok"))
	}
	if failureCode != "" {
		value.FailureCode = &failureCode
		value.Gates = append(value.Gates, validationGate(passedCount+1, false, failureCode))
	}
	return value
}

func validationGate(order int, passed bool, resultCode string) ValidationGate {
	name := "invalid"
	if order >= 1 && order <= len(validationGateNames) {
		name = validationGateNames[order-1]
	}
	return ValidationGate{
		Order:        int16(order),
		Name:         name,
		Passed:       passed,
		ResultCode:   resultCode,
		InputDigest:  testDigest,
		ResultDigest: testDigest,
		CheckedAt:    testNow.Add(time.Duration(order) * time.Second),
	}
}
