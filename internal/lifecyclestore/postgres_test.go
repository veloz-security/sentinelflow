package lifecyclestore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type inertBeginner struct{}

func (inertBeginner) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not used")
}

func TestConfigAndProjectionValidationFailClosed(t *testing.T) {
	valid := DefaultConfig("lifecycle-v1", "worker-1")
	if !validConfig(valid) {
		t.Fatal("default configuration was rejected")
	}
	for name, mutate := range map[string]func(*Config){
		"scheduler grammar": func(value *Config) { value.SchedulerID = "BAD" },
		"owner grammar":     func(value *Config) { value.LeaseOwner = "bad owner" },
		"subsecond lease":   func(value *Config) { value.LeaseDuration = 1500 * time.Millisecond },
		"long lease":        func(value *Config) { value.LeaseDuration = MaxLeaseDuration + time.Second },
		"zero retry":        func(value *Config) { value.RetryBackoff = 0 },
		"long retry":        func(value *Config) { value.RetryBackoff = MaxRetryBackoff + time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			changed := valid
			mutate(&changed)
			if validConfig(changed) {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}

	requested := time.Date(2026, 7, 18, 10, 0, 0, 123000000, time.UTC)
	projection := claimProjection{
		scheduleIdentity:            "019f0000-0000-7000-8000-000000000001",
		leaseIdentity:               "019f0000-0000-4000-8000-000000000002",
		authorizationID:             "019f0000-0000-7000-8000-000000000003",
		actionID:                    "019f0000-0000-7000-8000-000000000004",
		actionVersion:               2,
		policyID:                    "019f0000-0000-7000-8000-000000000005",
		policyVersion:               1,
		targetIPv4:                  "203.0.113.30",
		originalAddDigest:           testDigest("a"),
		originalAuthorizationDigest: testDigest("b"),
		evidenceSnapshotDigest:      testDigest("c"),
		validationSnapshotDigest:    testDigest("d"),
		ownedSchemaDigest:           testDigest("e"),
		purpose:                     "reconciliation",
		requestedAt:                 requested,
		validUntil:                  requested.Add(5 * time.Minute),
	}
	if !validProjection(projection) {
		t.Fatal("valid projection was rejected")
	}
	for name, mutate := range map[string]func(*claimProjection){
		"schedule": func(value *claimProjection) { value.scheduleIdentity = "not-a-uuid" },
		"target":   func(value *claimProjection) { value.targetIPv4 = "203.0.113.030" },
		"digest":   func(value *claimProjection) { value.originalAddDigest = "sha256:ABC" },
		"purpose":  func(value *claimProjection) { value.purpose = "mutate" },
		"version":  func(value *claimProjection) { value.actionVersion = 0 },
		"validity": func(value *claimProjection) { value.validUntil = requested.Add(5*time.Minute + time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := projection
			mutate(&changed)
			if validProjection(changed) {
				t.Fatal("unsafe projection accepted")
			}
		})
	}
	claim := projection.claim()
	schedule, lease := claim.StoreIdentity()
	if schedule != projection.scheduleIdentity || lease != projection.leaseIdentity ||
		claim.ActionVersion() != uint32(projection.actionVersion) {
		t.Fatal("projection changed opaque store fencing fields")
	}
}

func TestStoreSurfaceAndErrorsAreRedacted(t *testing.T) {
	if _, err := NewPostgreSQLStore(nil, DefaultConfig("scheduler", "owner")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil database error = %v", err)
	}
	store, err := NewPostgreSQLStore(inertBeginner{}, DefaultConfig("scheduler-secret", "owner-secret"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{store.String(), store.GoString(), store.config.String(), store.config.GoString()} {
		if strings.Contains(value, "scheduler-secret") || strings.Contains(value, "owner-secret") {
			t.Fatalf("identity leaked through diagnostic output: %q", value)
		}
	}
	for _, test := range []struct {
		err  error
		want error
	}{
		{&pgconn.PgError{Code: "23505", Message: "secret-target"}, ErrConflict},
		{&pgconn.PgError{Code: "23514", Message: "secret-target"}, ErrConflict},
		{&pgconn.PgError{Code: "42501", Message: "secret-target"}, ErrLeaseLost},
		{&pgconn.PgError{Code: "55000", Message: "secret-target"}, ErrLeaseLost},
		{&pgconn.PgError{Code: "XX000", Message: "secret-target"}, ErrUnavailable},
		{errors.New("driver secret-target"), ErrUnavailable},
		{context.Canceled, ErrUnavailable},
	} {
		got := classifyDatabaseError(test.err)
		if !errors.Is(got, test.want) || strings.Contains(got.Error(), "secret-target") {
			t.Fatalf("classification = %v, want %v", got, test.want)
		}
	}
	for _, typed := range []*Error{
		ErrInvalidInput, ErrUnavailable, ErrConflict, ErrLeaseLost,
		ErrProjectionInvalid, ErrContractRejected,
	} {
		if typed.Code() == "" || !IsCode(typed, typed.Code()) || strings.Contains(typed.Error(), "postgres") {
			t.Fatalf("unsafe typed error: %v", typed)
		}
	}
}

func TestSQLSurfaceContainsOnlyFrozenSecurityDefinerCalls(t *testing.T) {
	for name, query := range map[string]string{
		"claim":  claimScheduleSQL,
		"commit": commitInspectionSQL,
		"finish": finishFailureSQL,
	} {
		upper := strings.ToUpper(query)
		if !strings.Contains(query, "sentinelflow.") ||
			strings.Contains(upper, " INSERT ") || strings.Contains(upper, " UPDATE ") ||
			strings.Contains(upper, " DELETE ") || strings.Contains(upper, " FROM SENTINELFLOW.LIFECYCLE_") {
			t.Fatalf("%s bypasses the frozen function-only authority: %q", name, query)
		}
	}
}

func testDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
