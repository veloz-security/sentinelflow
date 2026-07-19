package authbinding

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var testNow = time.Date(2026, 7, 18, 2, 3, 4, 0, time.UTC)

func TestReconcileExactMatchUsesDatabaseClockAndCommits(t *testing.T) {
	db := newFakeDatabase()
	auth := validAuth("auth-1")
	db.addAuth(auth)
	db.gateways = append(db.gateways, validGateway(auth))

	result, err := newReconciler(db, 10).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result != (Result{Examined: 1, Verified: 1}) {
		t.Fatalf("Reconcile() = %+v", result)
	}
	record := db.authRecord(auth.eventID)
	if record.state != "verified" || record.reason != "verified" || record.boundID != "gateway-auth-1" {
		t.Fatalf("binding = %+v", record)
	}
	if db.commits != 1 || db.rollbacks != 0 {
		t.Fatalf("commits=%d rollbacks=%d", db.commits, db.rollbacks)
	}
	if db.clockReads != 1 {
		t.Fatalf("database clock reads = %d", db.clockReads)
	}
	if !strings.Contains(db.lastPendingSQL, "FOR UPDATE OF auth_event SKIP LOCKED") ||
		!strings.Contains(db.lastPendingSQL, "LIMIT $1") {
		t.Fatalf("pending SQL is not bounded/skip-locked: %s", db.lastPendingSQL)
	}
	if db.lastLimit != 10 {
		t.Fatalf("pending limit = %d", db.lastLimit)
	}
}

func TestReconcileRejectsNilContextAndInvalidDatabaseClock(t *testing.T) {
	var nilContext context.Context
	db := newFakeDatabase()
	if result, err := newReconciler(db, 1).Reconcile(nilContext); result != (Result{}) || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("nil-context result=%+v error=%v", result, err)
	}

	db = newFakeDatabase()
	db.now = time.Time{}
	if result, err := newReconciler(db, 1).Reconcile(context.Background()); result != (Result{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("zero-clock result=%+v error=%v", result, err)
	}
	if db.commits != 0 || db.rollbacks != 1 {
		t.Fatalf("zero-clock commits=%d rollbacks=%d", db.commits, db.rollbacks)
	}
}

func TestReconcileMismatchPriorityIsTerminal(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*gatewayEvent)
		want   string
	}{
		{
			name: "trace wins over every lower dimension",
			mutate: func(g *gatewayEvent) {
				g.traceID = "trace-other"
				g.sourceIP = "203.0.113.99"
				g.serviceLabel = "other-service"
				g.routeLabel = "other-route"
			},
			want: "trace_mismatch",
		},
		{
			name: "source wins over service and route",
			mutate: func(g *gatewayEvent) {
				g.sourceIP = "203.0.113.99"
				g.serviceLabel = "other-service"
				g.routeLabel = "other-route"
			},
			want: "source_mismatch",
		},
		{
			name: "service wins over route",
			mutate: func(g *gatewayEvent) {
				g.serviceLabel = "other-service"
				g.routeLabel = "other-route"
			},
			want: "service_mismatch",
		},
		{
			name:   "auth service must be demo app",
			mutate: func(_ *gatewayEvent) {},
			want:   "service_mismatch",
		},
		{
			name:   "route",
			mutate: func(g *gatewayEvent) { g.routeLabel = "other-route" },
			want:   "route_mismatch",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := newFakeDatabase()
			auth := validAuth("auth-1")
			if test.name == "auth service must be demo app" {
				auth.serviceLabel = "other-service"
			}
			db.addAuth(auth)
			gateway := validGateway(auth)
			if test.name == "auth service must be demo app" {
				gateway.serviceLabel = demoServiceLabel
			}
			test.mutate(&gateway)
			db.gateways = append(db.gateways, gateway)

			result, err := newReconciler(db, 1).Reconcile(context.Background())
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			if result != (Result{Examined: 1, Untrusted: 1}) {
				t.Fatalf("Reconcile() = %+v", result)
			}
			record := db.authRecord(auth.eventID)
			if record.state != "untrusted" || record.reason != test.want || record.boundID != "" {
				t.Fatalf("binding = %+v, want reason %q", record, test.want)
			}
		})
	}
}

func TestRequestMismatchRequiresUniqueTrustedTraceAndOtherExactFields(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*fakeDatabase, pendingAuth)
		want    Result
		reason  string
	}{
		{
			name: "unique exact trace dimensions justify request mismatch",
			prepare: func(db *fakeDatabase, auth pendingAuth) {
				gateway := validGateway(auth)
				gateway.requestID = "request-other"
				db.gateways = append(db.gateways, gateway)
			},
			want:   Result{Examined: 1, Untrusted: 1},
			reason: "request_mismatch",
		},
		{
			name:    "no candidate remains pending",
			prepare: func(_ *fakeDatabase, _ pendingAuth) {},
			want:    Result{Examined: 1, Pending: 1},
			reason:  "awaiting_gateway_event",
		},
		{
			name: "coincidental trace with source mismatch remains pending",
			prepare: func(db *fakeDatabase, auth pendingAuth) {
				gateway := validGateway(auth)
				gateway.requestID = "request-other"
				gateway.sourceIP = "203.0.113.99"
				db.gateways = append(db.gateways, gateway)
			},
			want:   Result{Examined: 1, Pending: 1},
			reason: "awaiting_gateway_event",
		},
		{
			name: "ambiguous trusted trace remains pending",
			prepare: func(db *fakeDatabase, auth pendingAuth) {
				first := validGateway(auth)
				first.requestID = "request-other-1"
				second := first
				second.eventID = "gateway-other-2"
				second.requestID = "request-other-2"
				db.gateways = append(db.gateways, first, second)
			},
			want:   Result{Examined: 1, Pending: 1},
			reason: "awaiting_gateway_event",
		},
		{
			name: "untrusted trace candidate remains pending",
			prepare: func(db *fakeDatabase, auth pendingAuth) {
				gateway := validGateway(auth)
				gateway.requestID = "request-other"
				gateway.trustState = "untrusted"
				gateway.trustReason = "timestamp_skew"
				db.gateways = append(db.gateways, gateway)
			},
			want:   Result{Examined: 1, Pending: 1},
			reason: "awaiting_gateway_event",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := newFakeDatabase()
			auth := validAuth("auth-1")
			db.addAuth(auth)
			test.prepare(db, auth)
			result, err := newReconciler(db, 1).Reconcile(context.Background())
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			if result != test.want {
				t.Fatalf("Reconcile() = %+v, want %+v", result, test.want)
			}
			if got := db.authRecord(auth.eventID).reason; got != test.reason {
				t.Fatalf("reason = %q, want %q", got, test.reason)
			}
		})
	}
}

func TestDeadlineAndTrustFailClosed(t *testing.T) {
	tests := []struct {
		name       string
		mutateAuth func(*pendingAuth)
		mutateGW   func(*gatewayEvent)
		withGW     bool
		want       Result
		state      string
		reason     string
	}{
		{
			name:       "expired no match",
			mutateAuth: func(a *pendingAuth) { a.bindingDeadline = testNow.Add(-time.Nanosecond) },
			want:       Result{Examined: 1, Untrusted: 1, Expired: 1},
			state:      "untrusted", reason: "expired",
		},
		{
			name:       "equal deadline remains eligible",
			mutateAuth: func(a *pendingAuth) { a.bindingDeadline = testNow },
			withGW:     true, want: Result{Examined: 1, Verified: 1},
			state: "verified", reason: "verified",
		},
		{
			name: "untrusted auth never binds",
			mutateAuth: func(a *pendingAuth) {
				a.trustState = "untrusted"
				a.trustReason = "timestamp_skew"
			},
			withGW: true, want: Result{Examined: 1, Pending: 1},
			state: "pending", reason: "awaiting_gateway_event",
		},
		{
			name:       "untrusted gateway never binds",
			mutateAuth: func(_ *pendingAuth) {},
			mutateGW: func(g *gatewayEvent) {
				g.trustState = "untrusted"
				g.trustReason = "source_degraded"
			},
			withGW: true, want: Result{Examined: 1, Pending: 1},
			state: "pending", reason: "awaiting_gateway_event",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := newFakeDatabase()
			auth := validAuth("auth-1")
			test.mutateAuth(&auth)
			db.addAuth(auth)
			if test.withGW {
				gateway := validGateway(auth)
				if test.mutateGW != nil {
					test.mutateGW(&gateway)
				}
				db.gateways = append(db.gateways, gateway)
			}
			result, err := newReconciler(db, 1).Reconcile(context.Background())
			if err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			if result != test.want {
				t.Fatalf("Reconcile() = %+v, want %+v", result, test.want)
			}
			record := db.authRecord(auth.eventID)
			if record.state != test.state || record.reason != test.reason {
				t.Fatalf("binding = %+v", record)
			}
		})
	}
}

func TestDeadlineCrossingDuringTransactionExpiresInsteadOfBinding(t *testing.T) {
	db := newFakeDatabase()
	auth := validAuth("auth-crossed-deadline")
	auth.bindingDeadline = testNow.Add(time.Nanosecond)
	db.addAuth(auth)
	db.gateways = append(db.gateways, validGateway(auth))
	db.advanceOnExec = 2 * time.Nanosecond

	result, err := newReconciler(db, 1).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result != (Result{Examined: 1, Untrusted: 1, Expired: 1}) {
		t.Fatalf("Reconcile() = %+v", result)
	}
	record := db.authRecord(auth.eventID)
	if record.state != "untrusted" || record.reason != "expired" || record.boundID != "" {
		t.Fatalf("late binding did not fail closed: %+v", record)
	}
}

func TestConcurrentReconcilersSkipLockedRows(t *testing.T) {
	db := newFakeDatabase()
	db.afterSelect = make(chan struct{}, 2)
	db.releaseSelect = make(chan struct{})
	first := validAuth("auth-1")
	second := validAuth("auth-2")
	second.bindingDeadline = first.bindingDeadline.Add(time.Second)
	db.addAuth(first)
	db.addAuth(second)
	db.gateways = append(db.gateways, validGateway(first), validGateway(second))

	type answer struct {
		result Result
		err    error
	}
	answers := make(chan answer, 2)
	for range 2 {
		go func() {
			result, err := newReconciler(db, 1).Reconcile(context.Background())
			answers <- answer{result: result, err: err}
		}()
	}
	for range 2 {
		select {
		case <-db.afterSelect:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent selection did not make progress")
		}
	}
	close(db.releaseSelect)
	for range 2 {
		answer := <-answers
		if answer.err != nil || answer.result != (Result{Examined: 1, Verified: 1}) {
			t.Fatalf("concurrent result = %+v, err=%v", answer.result, answer.err)
		}
	}
	if db.authRecord(first.eventID).state != "verified" || db.authRecord(second.eventID).state != "verified" {
		t.Fatalf("not all independently locked rows were verified")
	}
}

func TestFailuresRollbackAndExposeOnlyGenericErrors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*fakeDatabase)
	}{
		{"begin", func(db *fakeDatabase) { db.beginErr = errors.New("secret begin detail") }},
		{"clock", func(db *fakeDatabase) { db.clockErr = errors.New("secret clock detail") }},
		{"select", func(db *fakeDatabase) { db.queryErr = errors.New("secret select detail") }},
		{"constraint", func(db *fakeDatabase) { db.execErr = errors.New("auth_events_constraint secret id") }},
		{"commit", func(db *fakeDatabase) { db.commitErr = errors.New("secret commit detail") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := newFakeDatabase()
			auth := validAuth("auth-secret")
			db.addAuth(auth)
			db.gateways = append(db.gateways, validGateway(auth))
			test.setup(db)
			result, err := newReconciler(db, 1).Reconcile(context.Background())
			if result != (Result{}) || !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if test.name != "begin" && db.rollbacks != 1 {
				t.Fatalf("rollbacks = %d", db.rollbacks)
			}
			if db.authRecord(auth.eventID).state != "pending" {
				t.Fatalf("failed transaction persisted a transition")
			}
		})
	}
}

func TestContextCancellationAndNoRows(t *testing.T) {
	db := newFakeDatabase()
	result, err := newReconciler(db, 3).Reconcile(context.Background())
	if err != nil || result != (Result{}) || db.commits != 1 {
		t.Fatalf("empty result=%+v err=%v commits=%d", result, err, db.commits)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	db = newFakeDatabase()
	db.beginErr = errors.New("driver cancellation")
	_, err = newReconciler(db, 1).Reconcile(cancelled)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

func TestBoundsAndNilReceivers(t *testing.T) {
	for _, limit := range []int{-1, 0, MaxBatchSize + 1} {
		if reconciler, err := NewPostgreSQLReconciler(nil, limit); reconciler != nil || !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("NewPostgreSQLReconciler(nil, %d) = %#v, %v", limit, reconciler, err)
		}
		if _, err := newReconciler(newFakeDatabase(), limit).Reconcile(context.Background()); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("core limit %d error = %v", limit, err)
		}
	}
	var production *PostgreSQLReconciler
	if _, err := production.Reconcile(context.Background()); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("nil production receiver error = %v", err)
	}
	var core *reconciler
	if _, err := core.Reconcile(context.Background()); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("nil core receiver error = %v", err)
	}
}

func TestProductionPGXAdapterDelegatesTransaction(t *testing.T) {
	db := newFakeDatabase()
	auth := validAuth("auth-production")
	db.addAuth(auth)
	db.gateways = append(db.gateways, validGateway(auth))
	production, err := NewPostgreSQLReconciler(fakePGXBeginner{db: db}, 1)
	if err != nil {
		t.Fatalf("NewPostgreSQLReconciler() error = %v", err)
	}
	result, err := production.Reconcile(context.Background())
	if err != nil || result != (Result{Examined: 1, Verified: 1}) {
		t.Fatalf("production result=%+v err=%v", result, err)
	}

	db = newFakeDatabase()
	auth = validAuth("auth-production-failure")
	db.addAuth(auth)
	db.gateways = append(db.gateways, validGateway(auth))
	db.execErr = errors.New("driver detail")
	production, err = NewPostgreSQLReconciler(fakePGXBeginner{db: db}, 1)
	if err != nil {
		t.Fatalf("NewPostgreSQLReconciler() error = %v", err)
	}
	if _, err = production.Reconcile(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("production failure = %v", err)
	}
	if db.rollbacks != 1 {
		t.Fatalf("production rollback count = %d", db.rollbacks)
	}
}

func TestSQLRetainsDatabaseGuards(t *testing.T) {
	checks := map[string][]string{
		"clock":   {databaseClockSQL, "clock_timestamp()"},
		"pending": {lockPendingSQL, "binding_state = 'pending'", "LIMIT $1", "SKIP LOCKED"},
		"verify": {
			verifyBindingSQL, "binding_deadline >= clock_timestamp()", "trust_state = 'trusted'",
			"service_label = 'demo-app'", "gateway_event.request_id = auth_event.gateway_request_id",
		},
		"trace":  {gatewayByTraceSQL, "NOT EXISTS", "trust_state = 'trusted'"},
		"expire": {expireBindingSQL, "binding_deadline < clock_timestamp()"},
	}
	for name, values := range checks {
		for _, fragment := range values[1:] {
			if !strings.Contains(values[0], fragment) {
				t.Fatalf("%s SQL missing %q", name, fragment)
			}
		}
	}
}

func TestPendingScannerEnforcesApplicationBound(t *testing.T) {
	value := validAuth("auth-overflow")
	row := []any{
		value.eventID, value.gatewayRequestID, value.traceID, value.occurredAt,
		value.sourceIP, value.serviceLabel, value.routeLabel, value.receivedAt,
		value.trustState, value.trustReason, value.bindingDeadline,
	}
	rows := &fakeRows{values: [][]any{row, row}}
	if values, err := scanPending(rows, 1); values != nil || err == nil {
		t.Fatalf("scanPending() values=%v err=%v", values, err)
	}
	if !rows.closed {
		t.Fatal("overflowing rows were not closed")
	}
}

type fakeDatabase struct {
	mu             sync.Mutex
	now            time.Time
	auth           map[string]*fakeAuthRecord
	gateways       []gatewayEvent
	nextTx         int
	commits        int
	rollbacks      int
	clockReads     int
	lastPendingSQL string
	lastLimit      int
	beginErr       error
	clockErr       error
	queryErr       error
	execErr        error
	commitErr      error
	advanceOnExec  time.Duration
	afterSelect    chan struct{}
	releaseSelect  chan struct{}
}

type fakePGXBeginner struct {
	db *fakeDatabase
}

func (beginner fakePGXBeginner) BeginTx(ctx context.Context, _ pgx.TxOptions) (pgx.Tx, error) {
	value, err := beginner.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &fakePGXTx{delegate: value.(*fakeTx)}, nil
}

// Embedding pgx.Tx supplies the methods outside this package's intentionally
// narrow adapter surface. Calling one of them in production code would panic
// this test and expose an accidental dependency expansion.
type fakePGXTx struct {
	pgx.Tx
	delegate *fakeTx
}

func (tx *fakePGXTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	value, err := tx.delegate.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return &fakePGXRows{delegate: value.(*fakeRows)}, nil
}

func (tx *fakePGXTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return tx.delegate.QueryRow(ctx, sql, args...)
}

func (tx *fakePGXTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tag, err := tx.delegate.Exec(ctx, sql, args...)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	return pgconn.NewCommandTag(fmt.Sprintf("UPDATE %d", tag.RowsAffected())), nil
}

func (tx *fakePGXTx) Commit(ctx context.Context) error   { return tx.delegate.Commit(ctx) }
func (tx *fakePGXTx) Rollback(ctx context.Context) error { return tx.delegate.Rollback(ctx) }

type fakePGXRows struct {
	pgx.Rows
	delegate *fakeRows
}

func (rows *fakePGXRows) Close()                 { rows.delegate.Close() }
func (rows *fakePGXRows) Err() error             { return rows.delegate.Err() }
func (rows *fakePGXRows) Next() bool             { return rows.delegate.Next() }
func (rows *fakePGXRows) Scan(dest ...any) error { return rows.delegate.Scan(dest...) }

type fakeAuthRecord struct {
	value    pendingAuth
	state    string
	reason   string
	boundID  string
	lockedBy int
}

func newFakeDatabase() *fakeDatabase {
	return &fakeDatabase{now: testNow, auth: make(map[string]*fakeAuthRecord)}
}

func (db *fakeDatabase) addAuth(value pendingAuth) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.auth[value.eventID] = &fakeAuthRecord{value: value, state: "pending", reason: "awaiting_gateway_event"}
}

func (db *fakeDatabase) authRecord(id string) fakeAuthRecord {
	db.mu.Lock()
	defer db.mu.Unlock()
	return *db.auth[id]
}

func (db *fakeDatabase) Begin(context.Context) (transaction, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.beginErr != nil {
		return nil, db.beginErr
	}
	db.nextTx++
	return &fakeTx{db: db, id: db.nextTx, staged: make(map[string]fakeTransition)}, nil
}

type fakeTransition struct {
	state   string
	reason  string
	boundID string
}

type fakeTx struct {
	db       *fakeDatabase
	id       int
	locked   []string
	staged   map[string]fakeTransition
	finished bool
}

func (tx *fakeTx) QueryRow(_ context.Context, statement string, args ...any) row {
	tx.db.mu.Lock()
	defer tx.db.mu.Unlock()
	switch statement {
	case databaseClockSQL:
		tx.db.clockReads++
		if tx.db.clockErr != nil {
			return fakeRow{err: tx.db.clockErr}
		}
		return fakeRow{values: []any{tx.db.now}}
	case gatewayByRequestSQL:
		requestID := args[0].(string)
		for _, gateway := range tx.db.gateways {
			if gateway.requestID == requestID {
				return gatewayRow(gateway)
			}
		}
		return fakeRow{err: pgx.ErrNoRows}
	case gatewayByTraceSQL:
		traceID := args[0].(string)
		matches := make([]gatewayEvent, 0, 2)
		for _, gateway := range tx.db.gateways {
			if gateway.traceID == traceID && trusted(gateway.trustState, gateway.trustReason) {
				matches = append(matches, gateway)
			}
		}
		if len(matches) != 1 {
			return fakeRow{err: pgx.ErrNoRows}
		}
		return gatewayRow(matches[0])
	default:
		return fakeRow{err: fmt.Errorf("unexpected row query")}
	}
}

func gatewayRow(gateway gatewayEvent) row {
	return fakeRow{values: []any{
		gateway.eventID, gateway.requestID, gateway.traceID, gateway.sourceIP,
		gateway.serviceLabel, gateway.routeLabel, gateway.trustState, gateway.trustReason,
	}}
}

func (tx *fakeTx) Query(_ context.Context, statement string, args ...any) (rows, error) {
	tx.db.mu.Lock()
	if tx.db.queryErr != nil {
		err := tx.db.queryErr
		tx.db.mu.Unlock()
		return nil, err
	}
	if statement != lockPendingSQL {
		tx.db.mu.Unlock()
		return nil, errors.New("unexpected rows query")
	}
	limit := args[0].(int)
	tx.db.lastPendingSQL = statement
	tx.db.lastLimit = limit
	ids := make([]string, 0, len(tx.db.auth))
	for id, record := range tx.db.auth {
		if record.state == "pending" && record.lockedBy == 0 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		left, right := tx.db.auth[ids[i]], tx.db.auth[ids[j]]
		if left.value.bindingDeadline.Equal(right.value.bindingDeadline) {
			return left.value.eventID < right.value.eventID
		}
		return left.value.bindingDeadline.Before(right.value.bindingDeadline)
	})
	if len(ids) > limit {
		ids = ids[:limit]
	}
	values := make([][]any, 0, len(ids))
	for _, id := range ids {
		record := tx.db.auth[id]
		record.lockedBy = tx.id
		tx.locked = append(tx.locked, id)
		value := record.value
		values = append(values, []any{
			value.eventID, value.gatewayRequestID, value.traceID, value.occurredAt,
			value.sourceIP, value.serviceLabel, value.routeLabel, value.receivedAt,
			value.trustState, value.trustReason, value.bindingDeadline,
		})
	}
	afterSelect, releaseSelect := tx.db.afterSelect, tx.db.releaseSelect
	tx.db.mu.Unlock()
	if afterSelect != nil {
		afterSelect <- struct{}{}
		<-releaseSelect
	}
	return &fakeRows{values: values}, nil
}

func (tx *fakeTx) Exec(_ context.Context, statement string, args ...any) (commandTag, error) {
	tx.db.mu.Lock()
	defer tx.db.mu.Unlock()
	if tx.db.advanceOnExec != 0 {
		tx.db.now = tx.db.now.Add(tx.db.advanceOnExec)
		tx.db.advanceOnExec = 0
	}
	if tx.db.execErr != nil {
		return fakeTag(0), tx.db.execErr
	}
	id := args[0].(string)
	record, ok := tx.db.auth[id]
	if !ok || record.lockedBy != tx.id || record.state != "pending" {
		return fakeTag(0), nil
	}
	switch statement {
	case verifyBindingSQL:
		gatewayID := args[1].(string)
		gateway, found := tx.gatewayByID(gatewayID)
		if !found || record.value.bindingDeadline.Before(tx.db.now) ||
			!trusted(record.value.trustState, record.value.trustReason) ||
			mismatchReason(record.value, gateway, true) != "" ||
			!trusted(gateway.trustState, gateway.trustReason) {
			return fakeTag(0), nil
		}
		tx.staged[id] = fakeTransition{state: "verified", reason: "verified", boundID: gatewayID}
	case markUntrustedSQL:
		reason := args[1].(string)
		allowed := map[string]bool{
			"request_mismatch": true, "trace_mismatch": true, "source_mismatch": true,
			"service_mismatch": true, "route_mismatch": true,
		}
		if !allowed[reason] || record.value.bindingDeadline.Before(tx.db.now) {
			return fakeTag(0), nil
		}
		tx.staged[id] = fakeTransition{state: "untrusted", reason: reason}
	case expireBindingSQL:
		if !record.value.bindingDeadline.Before(tx.db.now) {
			return fakeTag(0), nil
		}
		tx.staged[id] = fakeTransition{state: "untrusted", reason: "expired"}
	default:
		return fakeTag(0), errors.New("unexpected exec")
	}
	return fakeTag(1), nil
}

func (tx *fakeTx) gatewayByID(id string) (gatewayEvent, bool) {
	for _, gateway := range tx.db.gateways {
		if gateway.eventID == id {
			return gateway, true
		}
	}
	return gatewayEvent{}, false
}

func (tx *fakeTx) Commit(context.Context) error {
	tx.db.mu.Lock()
	defer tx.db.mu.Unlock()
	if tx.db.commitErr != nil {
		return tx.db.commitErr
	}
	for id, transition := range tx.staged {
		record := tx.db.auth[id]
		record.state = transition.state
		record.reason = transition.reason
		record.boundID = transition.boundID
	}
	tx.releaseLocks()
	tx.finished = true
	tx.db.commits++
	return nil
}

func (tx *fakeTx) Rollback(context.Context) error {
	tx.db.mu.Lock()
	defer tx.db.mu.Unlock()
	if tx.finished {
		return nil
	}
	tx.releaseLocks()
	tx.finished = true
	tx.db.rollbacks++
	return nil
}

func (tx *fakeTx) releaseLocks() {
	for _, id := range tx.locked {
		if record := tx.db.auth[id]; record.lockedBy == tx.id {
			record.lockedBy = 0
		}
	}
}

type fakeTag int64

func (tag fakeTag) RowsAffected() int64 { return int64(tag) }

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(destinations ...any) error {
	if r.err != nil {
		return r.err
	}
	return scanValues(destinations, r.values)
}

type fakeRows struct {
	values [][]any
	index  int
	err    error
	closed bool
}

func (r *fakeRows) Close()     { r.closed = true }
func (r *fakeRows) Err() error { return r.err }
func (r *fakeRows) Next() bool { return r.index < len(r.values) }
func (r *fakeRows) Scan(dest ...any) error {
	if r.index >= len(r.values) {
		return errors.New("scan without row")
	}
	err := scanValues(dest, r.values[r.index])
	r.index++
	return err
}

func scanValues(destinations, values []any) error {
	if len(destinations) != len(values) {
		return fmt.Errorf("scan arity mismatch")
	}
	for index, destination := range destinations {
		switch pointer := destination.(type) {
		case *string:
			value, ok := values[index].(string)
			if !ok {
				return fmt.Errorf("scan string mismatch")
			}
			*pointer = value
		case *time.Time:
			value, ok := values[index].(time.Time)
			if !ok {
				return fmt.Errorf("scan time mismatch")
			}
			*pointer = value
		default:
			return fmt.Errorf("unsupported scan destination")
		}
	}
	return nil
}

func validAuth(id string) pendingAuth {
	return pendingAuth{
		eventID:          id,
		gatewayRequestID: "request-" + id,
		traceID:          "trace-" + id,
		occurredAt:       testNow.Add(-time.Minute),
		sourceIP:         "203.0.113.10",
		serviceLabel:     demoServiceLabel,
		routeLabel:       "login",
		receivedAt:       testNow.Add(-time.Minute),
		trustState:       "trusted",
		trustReason:      "none",
		bindingDeadline:  testNow.Add(4 * time.Minute),
	}
}

func validGateway(auth pendingAuth) gatewayEvent {
	return gatewayEvent{
		eventID:      "gateway-" + auth.eventID,
		requestID:    auth.gatewayRequestID,
		traceID:      auth.traceID,
		sourceIP:     auth.sourceIP,
		serviceLabel: demoServiceLabel,
		routeLabel:   auth.routeLabel,
		trustState:   "trusted",
		trustReason:  "none",
	}
}
