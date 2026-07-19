package ai

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const budgetTestReservationID = "00000000-0000-4000-8000-000000000801"

func TestPostgreSQLBudgetGateReservesWorstCaseAndSettlesTrustedUsage(t *testing.T) {
	t.Parallel()
	db := &budgetQueryStub{rows: []pgx.Row{
		budgetScanRow(func(dest ...any) error {
			*dest[0].(*string) = budgetTestReservationID
			*dest[1].(*int64) = 16_384
			*dest[2].(*string) = "active"
			return nil
		}),
		budgetScanRow(func(dest ...any) error {
			*dest[0].(*string) = budgetTestReservationID
			*dest[1].(*int64) = 110
			*dest[2].(*string) = "settled"
			return nil
		}),
	}}
	gate := newTestPostgreSQLBudgetGate(t, db)
	gate.newReservationID = func() (string, error) { return budgetTestReservationID, nil }

	reservation, err := gate.Reserve(context.Background(), validBudgetRequest())
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := reservation.Settle(context.Background(), Usage{
		InputTokens: 100, CachedInputTokens: 20, OutputTokens: 10, Trusted: true,
	}, false); err != nil {
		t.Fatalf("Settle: %v", err)
	}

	calls := db.snapshot()
	if len(calls) != 2 || !strings.Contains(calls[0].query, "sentinelflow.reserve_ai_budget") ||
		strings.Contains(calls[0].query, "INSERT INTO") || !strings.Contains(calls[1].query, "sentinelflow.settle_ai_budget") ||
		strings.Contains(calls[1].query, "UPDATE") {
		t.Fatalf("budget boundary bypassed stored functions: %+v", calls)
	}
	if len(calls[0].args) != 5 || calls[0].args[0] != budgetTestReservationID ||
		calls[0].args[1] != Model || calls[0].args[2] != "operator-v1" ||
		calls[0].args[3] != int64(10_000_000) || calls[0].args[4] != int64(16_384) {
		t.Fatalf("reserve arguments = %#v", calls[0].args)
	}
	if len(calls[1].args) != 2 || calls[1].args[0] != budgetTestReservationID || calls[1].args[1] != int64(110) {
		t.Fatalf("settle arguments = %#v", calls[1].args)
	}
}

func TestPostgreSQLBudgetGateChargesFullOnFailureOrUntrustedUsage(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		usage      Usage
		fullCharge bool
		wantError  bool
	}{
		{name: "explicit full charge", fullCharge: true},
		{name: "untrusted usage", usage: Usage{}, fullCharge: false, wantError: true},
		{name: "usage over reservation bound", usage: Usage{
			InputTokens: MaxInputBytes + 1, OutputTokens: 1, Trusted: true,
		}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := &budgetQueryStub{rows: []pgx.Row{
				budgetScanRow(func(dest ...any) error {
					*dest[0].(*string) = budgetTestReservationID
					*dest[1].(*int64) = 16_384
					*dest[2].(*string) = "settled"
					return nil
				}),
			}}
			gate := newTestPostgreSQLBudgetGate(t, db)
			reservation := &postgresBudgetReservation{
				gate: gate, reservationID: budgetTestReservationID, reservedMicroUSD: 16_384,
			}
			err := reservation.Settle(context.Background(), test.usage, test.fullCharge)
			if (err != nil) != test.wantError {
				t.Fatalf("Settle error = %v, wantError=%v", err, test.wantError)
			}
			calls := db.snapshot()
			if len(calls) != 1 || calls[0].args[1] != int64(16_384) {
				t.Fatalf("unsafe full charge calls: %+v", calls)
			}
		})
	}
}

func TestPostgreSQLBudgetGateMapsExhaustionAndRejectsStoreMismatch(t *testing.T) {
	t.Parallel()
	for name, row := range map[string]pgx.Row{
		"exhausted": budgetScanRow(func(...any) error { return pgx.ErrNoRows }),
		"mismatched row": budgetScanRow(func(dest ...any) error {
			*dest[0].(*string) = "00000000-0000-4000-8000-000000000999"
			*dest[1].(*int64) = 16_384
			*dest[2].(*string) = "active"
			return nil
		}),
	} {
		t.Run(name, func(t *testing.T) {
			db := &budgetQueryStub{rows: []pgx.Row{row}}
			gate := newTestPostgreSQLBudgetGate(t, db)
			gate.newReservationID = func() (string, error) { return budgetTestReservationID, nil }
			reservation, err := gate.Reserve(context.Background(), validBudgetRequest())
			if reservation != nil {
				t.Fatal("rejected reservation returned authority")
			}
			if name == "exhausted" && !errors.Is(err, ErrBudgetExhausted) {
				t.Fatalf("error = %v, want budget exhaustion", err)
			}
			if name != "exhausted" && !errors.Is(err, errBudgetPersistence) {
				t.Fatalf("error = %v, want sanitized persistence error", err)
			}
		})
	}
}

func TestPostgreSQLBudgetGateValidatesFrozenContractBeforeQuery(t *testing.T) {
	t.Parallel()
	db := &budgetQueryStub{}
	gate := newTestPostgreSQLBudgetGate(t, db)
	gate.newReservationID = func() (string, error) { return budgetTestReservationID, nil }
	for name, mutate := range map[string]func(*BudgetRequest){
		"wrong model":               func(r *BudgetRequest) { r.Model = "other" },
		"wrong rate card":           func(r *BudgetRequest) { r.RateCardVersion = "operator-v2" },
		"zero time":                 func(r *BudgetRequest) { r.ReservedAt = time.Time{} },
		"smaller input reservation": func(r *BudgetRequest) { r.MaxInputTokenUnits-- },
		"larger output reservation": func(r *BudgetRequest) { r.MaxOutputTokens++ },
	} {
		t.Run(name, func(t *testing.T) {
			request := validBudgetRequest()
			mutate(&request)
			if reservation, err := gate.Reserve(context.Background(), request); reservation != nil || !errors.Is(err, errBudgetPersistence) {
				t.Fatalf("invalid request returned reservation=%v err=%v", reservation, err)
			}
		})
	}
	if calls := db.snapshot(); len(calls) != 0 {
		t.Fatalf("invalid input reached PostgreSQL: %+v", calls)
	}
}

func TestBudgetFixedPointConversionsAndCeiling(t *testing.T) {
	t.Parallel()
	if value, err := MicroUSDPerMillion(0.0000001); err != nil || value != 1 {
		t.Fatalf("rate conversion = %d, %v", value, err)
	}
	if value, err := DailyLimitMicroUSD(10); err != nil || value != 10_000_000 {
		t.Fatalf("limit conversion = %d, %v", value, err)
	}
	if value, err := roundedMicroUSDCost([]costTerm{{units: 1, rate: 1}}); err != nil || value != 1 {
		t.Fatalf("ceiling cost = %d, %v", value, err)
	}
	for _, invalid := range []float64{0, -1} {
		if _, err := MicroUSDPerMillion(invalid); err == nil {
			t.Fatalf("invalid rate %v accepted", invalid)
		}
		if _, err := DailyLimitMicroUSD(invalid); err == nil {
			t.Fatalf("invalid limit %v accepted", invalid)
		}
	}
}

func TestBudgetReservationIDsAreUUIDv4(t *testing.T) {
	t.Parallel()
	for range 100 {
		value, err := newBudgetReservationID()
		if err != nil || !stableIDPattern.MatchString(value) || value[14] != '4' || !strings.Contains("89ab", value[19:20]) {
			t.Fatalf("invalid reservation id %q: %v", value, err)
		}
	}
}

func newTestPostgreSQLBudgetGate(t *testing.T, db budgetQueryRower) *PostgreSQLBudgetGate {
	t.Helper()
	gate, err := NewPostgreSQLBudgetGate(db, PostgreSQLBudgetConfig{
		Model: Model, RateCardVersion: "operator-v1", DailyLimitMicroUSD: 10_000_000,
		InputMicroUSDPerMillion: 1_000_000, CachedInputMicroUSDPerMillion: 500_000,
		OutputMicroUSDPerMillion: 2_000_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func validBudgetRequest() BudgetRequest {
	return BudgetRequest{
		Model: Model, RateCardVersion: "operator-v1",
		MaxInputTokenUnits: MaxInputBytes, MaxOutputTokens: MaxOutputTokens,
		ReservedAt: time.Now().UTC(),
	}
}

type budgetScanRow func(...any) error

func (row budgetScanRow) Scan(dest ...any) error { return row(dest...) }

type budgetQueryCall struct {
	query string
	args  []any
}

type budgetQueryStub struct {
	mu    sync.Mutex
	rows  []pgx.Row
	calls []budgetQueryCall
}

func (db *budgetQueryStub) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.calls = append(db.calls, budgetQueryCall{query: query, args: append([]any(nil), args...)})
	if len(db.rows) == 0 {
		return budgetScanRow(func(...any) error { return errors.New("unexpected query") })
	}
	row := db.rows[0]
	db.rows = db.rows[1:]
	return row
}

func (db *budgetQueryStub) snapshot() []budgetQueryCall {
	db.mu.Lock()
	defer db.mu.Unlock()
	result := make([]budgetQueryCall, len(db.calls))
	copy(result, db.calls)
	return result
}
