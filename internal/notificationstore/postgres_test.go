package notificationstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/investigationapi"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	testSessionID  = "019b0000-0000-7000-8000-00000000f001"
	testIncidentID = "019b0000-0000-7000-8000-00000000f002"
	testResourceID = "019b0000-0000-7000-8000-00000000f003"
	testTraceID    = "019b0000-0000-7000-8000-00000000f004"
)

var testNow = time.Date(2026, 7, 18, 9, 0, 0, 123000000, time.UTC)

func TestCursorAndTailUseCanonicalSequenceOrder(t *testing.T) {
	t.Parallel()
	store, err := NewPostgreSQLStore(&queryStub{queryRow: func(query string, args []any) pgx.Row {
		if query != readWindowSQL || len(args) != 0 {
			t.Fatalf("query=%q args=%#v", query, args)
		}
		return valuesRow(int64(3), int64(19))
	}})
	if err != nil {
		t.Fatal(err)
	}
	window, err := store.Tail(context.Background(), validTestPrincipal())
	if err != nil || window.Floor != "s1.0000000000000003" || window.Watermark != "s1.0000000000000013" {
		t.Fatalf("window=%+v err=%v", window, err)
	}
	parsed, err := store.ParseCursor("s1.000000000000000a")
	if err != nil || parsed != "s1.000000000000000a" {
		t.Fatalf("parsed=%q err=%v", parsed, err)
	}
	if comparison, err := store.CompareCursor("s1.000000000000000a", "s1.0000000000000010"); err != nil || comparison != -1 {
		t.Fatalf("comparison=%d err=%v", comparison, err)
	}
	for _, value := range []string{"", "s1.1", "s1.000000000000000A", "s1.8000000000000000"} {
		if _, err := store.ParseCursor(value); !errors.Is(err, investigationapi.ErrInvalidCursor) {
			t.Errorf("ParseCursor(%q) error=%v", value, err)
		}
	}
}

func TestLeaseFunctionsUseExactBoundedDatabaseBoundary(t *testing.T) {
	t.Parallel()
	leaseID := "019b0000-0000-4000-8000-00000000f010"
	processInstance := "019b0000-0000-4000-8000-00000000f011"
	queries := []string{registerLeaseSQL, touchLeaseSQL, unregisterLeaseSQL}
	index := 0
	db := &queryStub{queryRow: func(query string, args []any) pgx.Row {
		if index >= len(queries) || query != queries[index] ||
			!reflect.DeepEqual(args, []any{leaseID, processInstance}) {
			t.Fatalf("index=%d query=%q args=%#v", index, query, args)
		}
		index++
		if query == unregisterLeaseSQL {
			return valuesRow(true)
		}
		return valuesRow(testNow.Add(45 * time.Second))
	}}
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.RegisterLease(context.Background(), leaseID, processInstance); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err = store.TouchLease(context.Background(), leaseID, processInstance); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if err = store.UnregisterLease(context.Background(), leaseID, processInstance); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if index != len(queries) {
		t.Fatalf("lease query count=%d", index)
	}

	for name, values := range map[string][2]string{
		"nil uuid":     {"00000000-0000-0000-0000-000000000000", processInstance},
		"bad uuid":     {"not-a-uuid", processInstance},
		"long process": {leaseID, strings.Repeat("a", 65)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.RegisterLease(context.Background(), values[0], values[1]); !errors.Is(err, investigationapi.ErrSourceUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestPollMapsAllowlistedEventsAndAllowsSequenceGaps(t *testing.T) {
	t.Parallel()
	db := &queryStub{query: func(query string, args []any) (pgx.Rows, error) {
		if query != readPageSQL || !reflect.DeepEqual(args, []any{int64(0), 64}) {
			t.Fatalf("query=%q args=%#v", query, args)
		}
		return rowsOf(
			pageValues(0, 9, 2, "incident.updated", "incident", testIncidentID, 4,
				"review_ready", "incident_updated", pointer(testIncidentID), pointer(testTraceID)),
			pageValues(0, 9, 7, "policy.validation_updated", "policy", testResourceID, 3,
				"valid", "policy_validation_updated", pointer(testIncidentID), nil),
		), nil
	}}
	store, _ := NewPostgreSQLStore(db)
	page, err := store.Poll(context.Background(), validTestPrincipal(), "s1.0000000000000000", 64)
	if err != nil || page.Gap || len(page.Events) != 2 || page.Next != "s1.0000000000000007" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	incident := page.Events[0]
	if incident.IncidentID == nil || *incident.IncidentID != testIncidentID || incident.PolicyID != nil ||
		incident.ActionID != nil || incident.TraceID == nil || !incident.OccurredAt.Equal(testNow) {
		t.Fatalf("incident event=%+v", incident)
	}
	policy := page.Events[1]
	if policy.PolicyID == nil || *policy.PolicyID != testResourceID ||
		policy.IncidentID == nil || *policy.IncidentID != testIncidentID || policy.ActionID != nil {
		t.Fatalf("policy event=%+v", policy)
	}
}

func TestPollMapsApprovalAndEnforcementResourceSemantics(t *testing.T) {
	t.Parallel()
	db := &queryStub{query: func(string, []any) (pgx.Rows, error) {
		return rowsOf(
			pageValues(0, 2, 1, "approval.recorded", "policy", testResourceID, 2,
				"approved", "approval_recorded", pointer(testIncidentID), nil),
			pageValues(0, 2, 2, "approval.recorded", "enforcement_action", testResourceID, 5,
				"revoked", "approval_recorded", pointer(testIncidentID), nil),
		), nil
	}}
	store, _ := NewPostgreSQLStore(db)
	page, err := store.Poll(context.Background(), validTestPrincipal(), "s1.0000000000000000", 2)
	if err != nil || len(page.Events) != 2 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if page.Events[0].PolicyID == nil || page.Events[0].ActionID != nil ||
		page.Events[1].PolicyID != nil || page.Events[1].ActionID == nil {
		t.Fatalf("resource mapping=%+v", page.Events)
	}
}

func TestPollReportsRetainedFloorGapAndFutureCursor(t *testing.T) {
	t.Parallel()
	store, _ := NewPostgreSQLStore(&queryStub{query: func(string, []any) (pgx.Rows, error) {
		return rowsOf(metadataOnlyValues(4, 8, true, false)), nil
	}})
	page, err := store.Poll(context.Background(), validTestPrincipal(), "s1.0000000000000001", 10)
	if !errors.Is(err, investigationapi.ErrReplayGap) || !page.Gap || len(page.Events) != 0 ||
		page.Next != "s1.0000000000000001" || page.ReplayWindow.Floor != "s1.0000000000000004" {
		t.Fatalf("gap page=%+v err=%v", page, err)
	}

	store, _ = NewPostgreSQLStore(&queryStub{query: func(string, []any) (pgx.Rows, error) {
		return rowsOf(metadataOnlyValues(4, 8, false, true)), nil
	}})
	_, err = store.Poll(context.Background(), validTestPrincipal(), "s1.0000000000000009", 10)
	if !errors.Is(err, investigationapi.ErrInvalidCursor) {
		t.Fatalf("future cursor error=%v", err)
	}
}

func TestStoreFailsClosedOnPrincipalRowsAndDriverErrors(t *testing.T) {
	t.Parallel()
	db := &queryStub{
		query: func(string, []any) (pgx.Rows, error) {
			return rowsOf(pageValues(0, 1, 1, "approval.recorded", "approval_decision", testResourceID, 1,
				"approved", "approval_recorded", pointer(testIncidentID), nil)), nil
		},
		queryRow: func(string, []any) pgx.Row { return valuesRow(int64(0), int64(0)) },
	}
	store, _ := NewPostgreSQLStore(db)
	if _, err := store.Poll(context.Background(), validTestPrincipal(), "s1.0000000000000000", 1); !errors.Is(err, investigationapi.ErrSourceUnavailable) {
		t.Fatalf("invalid row error=%v", err)
	}

	expired := validTestPrincipal()
	expired.ExpiresAt = time.Now().Add(-time.Second).UTC()
	if _, err := store.Tail(context.Background(), expired); !errors.Is(err, investigationapi.ErrSourceUnavailable) {
		t.Fatalf("expired principal error=%v", err)
	}
	future := validTestPrincipal()
	future.ValidatedAt = time.Now().Add(time.Minute).UTC()
	future.ExpiresAt = future.ValidatedAt.Add(time.Minute)
	if _, err := store.Tail(context.Background(), future); !errors.Is(err, investigationapi.ErrSourceUnavailable) {
		t.Fatalf("future principal error=%v", err)
	}
	tooLong := validTestPrincipal()
	tooLong.ActorID = strings.Repeat("a", 129)
	if _, err := store.Tail(context.Background(), tooLong); !errors.Is(err, investigationapi.ErrSourceUnavailable) {
		t.Fatalf("long actor error=%v", err)
	}
	accepted := validTestPrincipal()
	accepted.ActorID = strings.Repeat("a", 128)
	if _, err := store.Tail(context.Background(), accepted); err != nil {
		t.Fatalf("128-byte actor error=%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store, _ = NewPostgreSQLStore(&queryStub{queryRow: func(string, []any) pgx.Row {
		return errorRow(errors.New("postgres secret token"))
	}})
	_, err := store.Tail(ctx, validTestPrincipal())
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("cancellation error=%v", err)
	}
}

func validTestPrincipal() investigationapi.Principal {
	now := time.Now().UTC()
	return investigationapi.Principal{
		ActorID: "admin", SessionID: testSessionID,
		ValidatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
}

func pageValues(
	floor, watermark, cursor int64,
	eventType, resourceType, resourceID string,
	resourceVersion int64,
	state, summary string,
	incidentID, traceID *string,
) []any {
	return []any{
		floor, watermark, false, false, pointer(cursor), pointer(eventType), pointer(resourceType),
		pointer(resourceID), pointer(resourceVersion), pointer(state), pointer(summary),
		incidentID, traceID, pointer(testNow),
	}
}

func metadataOnlyValues(floor, watermark int64, gap, future bool) []any {
	return []any{floor, watermark, gap, future, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil}
}

func pointer[T any](value T) *T { return &value }

type queryStub struct {
	query    func(string, []any) (pgx.Rows, error)
	queryRow func(string, []any) pgx.Row
}

func (stub *queryStub) Query(_ context.Context, query string, args ...any) (pgx.Rows, error) {
	if stub.query == nil {
		return nil, errors.New("unexpected query")
	}
	return stub.query(query, append([]any(nil), args...))
}

func (stub *queryStub) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	if stub.queryRow == nil {
		return errorRow(errors.New("unexpected query row"))
	}
	return stub.queryRow(query, append([]any(nil), args...))
}

type scriptedRows struct {
	rows   [][]any
	index  int
	closed bool
	err    error
}

func rowsOf(values ...[]any) pgx.Rows                                   { return &scriptedRows{rows: values} }
func (rows *scriptedRows) Close()                                       { rows.closed = true }
func (rows *scriptedRows) Err() error                                   { return rows.err }
func (rows *scriptedRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT") }
func (rows *scriptedRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *scriptedRows) Next() bool {
	if rows.index >= len(rows.rows) {
		rows.closed = true
		return false
	}
	rows.index++
	return true
}
func (rows *scriptedRows) Scan(dest ...any) error {
	if rows.index == 0 || rows.index > len(rows.rows) {
		return errors.New("scan outside row")
	}
	return assignValues(dest, rows.rows[rows.index-1])
}
func (rows *scriptedRows) Values() ([]any, error) {
	if rows.index == 0 || rows.index > len(rows.rows) {
		return nil, errors.New("values outside row")
	}
	return append([]any(nil), rows.rows[rows.index-1]...), nil
}
func (*scriptedRows) RawValues() [][]byte { return nil }
func (*scriptedRows) Conn() *pgx.Conn     { return nil }

type valueRow struct {
	values []any
	err    error
}

func valuesRow(values ...any) pgx.Row { return valueRow{values: values} }
func errorRow(err error) pgx.Row      { return valueRow{err: err} }
func (row valueRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	return assignValues(dest, row.values)
}

func assignValues(dest, values []any) error {
	if len(dest) != len(values) {
		return errors.New("scan arity")
	}
	for index, value := range values {
		target := reflect.ValueOf(dest[index])
		if target.Kind() != reflect.Pointer || target.IsNil() {
			return errors.New("invalid destination")
		}
		target = target.Elem()
		if value == nil {
			target.Set(reflect.Zero(target.Type()))
			continue
		}
		source := reflect.ValueOf(value)
		if source.Type().AssignableTo(target.Type()) {
			target.Set(source)
			continue
		}
		if target.Kind() == reflect.Pointer && source.Type().AssignableTo(target.Type().Elem()) {
			allocated := reflect.New(target.Type().Elem())
			allocated.Elem().Set(source)
			target.Set(allocated)
			continue
		}
		if source.Type().ConvertibleTo(target.Type()) {
			target.Set(source.Convert(target.Type()))
			continue
		}
		return errors.New("scan type")
	}
	return nil
}
