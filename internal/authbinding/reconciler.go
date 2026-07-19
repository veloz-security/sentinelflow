// Package authbinding reconciles authenticated application events with the
// minimized Gateway evidence that carried the corresponding request.
package authbinding

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// MaxBatchSize is deliberately small so one reconciliation transaction
	// cannot monopolize the pending-binding index or retain row locks without a
	// strict bound.
	MaxBatchSize     = 100
	rollbackTimeout  = 5 * time.Second
	demoServiceLabel = "demo-app"
)

var (
	// ErrInvalidConfiguration contains no database or event details and is safe
	// to expose as an operator-facing classification.
	ErrInvalidConfiguration = errors.New("auth binding reconciler configuration is invalid")
	// ErrUnavailable deliberately hides PostgreSQL, row, and event details.
	ErrUnavailable = errors.New("auth binding reconciliation unavailable")
)

// Result contains bounded aggregate metadata only. Event, request, trace,
// source, service, and route identifiers never leave the reconciler.
type Result struct {
	Examined  int
	Verified  int
	Untrusted int
	Expired   int
	Pending   int
}

// PostgreSQLReconciler owns the production pgx adapter. The accepted interface
// is implemented by pgxpool.Pool and pgx.Conn.
type PostgreSQLReconciler struct {
	core *reconciler
}

// TransactionBeginner is the smallest production pgx transaction contract.
type TransactionBeginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// NewPostgreSQLReconciler creates a bounded reconciler. A batch limit outside
// 1..MaxBatchSize is rejected rather than silently clamped.
func NewPostgreSQLReconciler(db TransactionBeginner, batchLimit int) (*PostgreSQLReconciler, error) {
	if db == nil || batchLimit < 1 || batchLimit > MaxBatchSize {
		return nil, ErrInvalidConfiguration
	}
	return &PostgreSQLReconciler{
		core: newReconciler(pgxBeginner{db: db}, batchLimit),
	}, nil
}

// Reconcile performs one bounded transaction. PostgreSQL supplies the only
// authorization clock; no caller-supplied timestamp is accepted.
func (r *PostgreSQLReconciler) Reconcile(ctx context.Context) (Result, error) {
	if ctx == nil || r == nil || r.core == nil {
		return Result{}, ErrInvalidConfiguration
	}
	return r.core.Reconcile(ctx)
}

type reconciler struct {
	db         transactionBeginner
	batchLimit int
}

func newReconciler(db transactionBeginner, batchLimit int) *reconciler {
	return &reconciler{db: db, batchLimit: batchLimit}
}

func (r *reconciler) Reconcile(ctx context.Context) (Result, error) {
	if ctx == nil || r == nil || r.db == nil || r.batchLimit < 1 || r.batchLimit > MaxBatchSize {
		return Result{}, ErrInvalidConfiguration
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Result{}, classifyError(ctx)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	var databaseNow time.Time
	if err = tx.QueryRow(ctx, databaseClockSQL).Scan(&databaseNow); err != nil {
		return Result{}, classifyError(ctx)
	}
	if databaseNow.IsZero() || databaseNow.Year() < 1 || databaseNow.Year() > 9999 {
		return Result{}, ErrUnavailable
	}
	databaseNow = databaseNow.UTC()

	rows, err := tx.Query(ctx, lockPendingSQL, r.batchLimit)
	if err != nil {
		return Result{}, classifyError(ctx)
	}
	pending, err := scanPending(rows, r.batchLimit)
	if err != nil {
		return Result{}, classifyError(ctx)
	}

	result := Result{Examined: len(pending)}
	for i := range pending {
		disposition, reconcileErr := reconcileOne(ctx, tx, pending[i], databaseNow)
		if reconcileErr != nil {
			return Result{}, classifyError(ctx)
		}
		switch disposition {
		case dispositionVerified:
			result.Verified++
		case dispositionUntrusted:
			result.Untrusted++
		case dispositionExpired:
			result.Untrusted++
			result.Expired++
		case dispositionPending:
			result.Pending++
		default:
			return Result{}, ErrUnavailable
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return Result{}, classifyError(ctx)
	}
	committed = true
	return result, nil
}

func classifyError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnavailable
}

type disposition uint8

const (
	dispositionPending disposition = iota
	dispositionVerified
	dispositionUntrusted
	dispositionExpired
)

type pendingAuth struct {
	eventID          string
	gatewayRequestID string
	traceID          string
	occurredAt       time.Time
	sourceIP         string
	serviceLabel     string
	routeLabel       string
	receivedAt       time.Time
	trustState       string
	trustReason      string
	bindingDeadline  time.Time
}

type gatewayEvent struct {
	eventID      string
	requestID    string
	traceID      string
	sourceIP     string
	serviceLabel string
	routeLabel   string
	trustState   string
	trustReason  string
}

func scanPending(rows rows, limit int) ([]pendingAuth, error) {
	defer rows.Close()
	values := make([]pendingAuth, 0, limit)
	for rows.Next() {
		if len(values) >= limit {
			return nil, errors.New("pending binding query exceeded its strict limit")
		}
		var value pendingAuth
		if err := rows.Scan(
			&value.eventID,
			&value.gatewayRequestID,
			&value.traceID,
			&value.occurredAt,
			&value.sourceIP,
			&value.serviceLabel,
			&value.routeLabel,
			&value.receivedAt,
			&value.trustState,
			&value.trustReason,
			&value.bindingDeadline,
		); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func reconcileOne(ctx context.Context, tx transaction, auth pendingAuth, databaseNow time.Time) (disposition, error) {
	if auth.bindingDeadline.Before(databaseNow) {
		changed, err := transition(ctx, tx, expireBindingSQL, auth.eventID)
		if err != nil || !changed {
			if err == nil {
				err = errors.New("expired binding transition was rejected")
			}
			return 0, err
		}
		return dispositionExpired, nil
	}

	// Ingest trust is a prerequisite, not something a binding reason can
	// reinterpret. The existing schema has no binding reason for source trust,
	// so an untrusted record remains visibly pending until its bounded expiry.
	if !trusted(auth.trustState, auth.trustReason) {
		return dispositionPending, nil
	}

	gateway, found, err := gatewayByRequest(ctx, tx, auth.gatewayRequestID)
	if err != nil {
		return 0, err
	}
	if found {
		if !trusted(gateway.trustState, gateway.trustReason) {
			return dispositionPending, nil
		}
		if reason := mismatchReason(auth, gateway, true); reason != "" {
			return transitionBeforeDeadline(ctx, tx, markUntrustedSQL, dispositionUntrusted, auth.eventID, reason)
		}
		return transitionBeforeDeadline(ctx, tx, verifyBindingSQL, dispositionVerified, auth.eventID, gateway.eventID)
	}

	// A request mismatch is only justified by a trusted Gateway event carrying
	// the exact trace and all remaining binding dimensions. A coincidental trace
	// with another mismatch is not converted into an invented terminal reason.
	gateway, found, err = gatewayByTrace(ctx, tx, auth.traceID)
	if err != nil {
		return 0, err
	}
	if found && trusted(gateway.trustState, gateway.trustReason) &&
		mismatchReason(auth, gateway, false) == "request_mismatch" {
		return transitionBeforeDeadline(
			ctx, tx, markUntrustedSQL, dispositionUntrusted, auth.eventID, "request_mismatch",
		)
	}
	return dispositionPending, nil
}

// transitionBeforeDeadline lets the mutation statement recheck the live
// PostgreSQL clock. If the deadline crossed after the transaction's initial
// clock read, expiry is the only allowed fallback.
func transitionBeforeDeadline(
	ctx context.Context,
	tx transaction,
	statement string,
	success disposition,
	arguments ...any,
) (disposition, error) {
	changed, err := transition(ctx, tx, statement, arguments...)
	if err != nil {
		return 0, err
	}
	if changed {
		return success, nil
	}
	expired, err := transition(ctx, tx, expireBindingSQL, arguments[0])
	if err != nil {
		return 0, err
	}
	if expired {
		return dispositionExpired, nil
	}
	return 0, errors.New("binding transition was rejected")
}

func trusted(state, reason string) bool {
	return state == "trusted" && reason == "none"
}

// mismatchReason is deliberately ordered from the strongest correlation key
// through the remaining exact dimensions. requestKnown means the lookup used
// the unique request_id and therefore request mismatch is impossible.
func mismatchReason(auth pendingAuth, gateway gatewayEvent, requestKnown bool) string {
	if !requestKnown && gateway.requestID != auth.gatewayRequestID {
		// A trace lookup justifies request_mismatch only if every other dimension
		// agrees; otherwise the trace is insufficient to identify this request.
		if gateway.traceID == auth.traceID &&
			gateway.sourceIP == auth.sourceIP &&
			auth.serviceLabel == demoServiceLabel &&
			gateway.serviceLabel == demoServiceLabel &&
			gateway.routeLabel == auth.routeLabel {
			return "request_mismatch"
		}
		return ""
	}
	if gateway.traceID != auth.traceID {
		return "trace_mismatch"
	}
	if gateway.sourceIP != auth.sourceIP {
		return "source_mismatch"
	}
	if auth.serviceLabel != demoServiceLabel || gateway.serviceLabel != demoServiceLabel ||
		gateway.serviceLabel != auth.serviceLabel {
		return "service_mismatch"
	}
	if gateway.routeLabel != auth.routeLabel {
		return "route_mismatch"
	}
	return ""
}

func gatewayByRequest(ctx context.Context, tx transaction, requestID string) (gatewayEvent, bool, error) {
	return scanGateway(tx.QueryRow(ctx, gatewayByRequestSQL, requestID))
}

func gatewayByTrace(ctx context.Context, tx transaction, traceID string) (gatewayEvent, bool, error) {
	return scanGateway(tx.QueryRow(ctx, gatewayByTraceSQL, traceID))
}

func scanGateway(row row) (gatewayEvent, bool, error) {
	var value gatewayEvent
	err := row.Scan(
		&value.eventID,
		&value.requestID,
		&value.traceID,
		&value.sourceIP,
		&value.serviceLabel,
		&value.routeLabel,
		&value.trustState,
		&value.trustReason,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return gatewayEvent{}, false, nil
	}
	return value, err == nil, err
}

func transition(ctx context.Context, tx transaction, statement string, arguments ...any) (bool, error) {
	tag, err := tx.Exec(ctx, statement, arguments...)
	if err != nil {
		return false, err
	}
	switch tag.RowsAffected() {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("binding transition affected multiple rows")
	}
}
