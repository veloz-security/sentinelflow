package adminstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var testDatabaseNow = time.Date(2026, 7, 18, 6, 0, 0, 123000000, time.UTC)

func TestErrorValuesAreTypedAndDetailFree(t *testing.T) {
	if _, err := NewPostgreSQLStore(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil database error = %v", err)
	}
	for _, test := range []struct {
		err  *Error
		code ErrorCode
	}{
		{ErrNotFound, CodeNotFound},
		{ErrConflict, CodeConflict},
		{ErrUnavailable, CodeUnavailable},
	} {
		if test.err.Code() != test.code || strings.Contains(test.err.Error(), "postgres") {
			t.Fatalf("unsafe error classification: code=%q message=%q", test.err.Code(), test.err.Error())
		}
	}
	var nilError *Error
	if nilError.Code() != CodeUnavailable || !strings.Contains(nilError.Error(), "unavailable") {
		t.Fatal("nil typed error did not fail closed")
	}
}

func TestLoadByIDIsBoundedReadCommittedAndDefensive(t *testing.T) {
	record := testLoginRecord(1, testDatabaseNow.Add(-time.Minute))
	tx := &scriptedTx{rows: []pgx.Row{recordRow(record), timeRow(testDatabaseNow)}}
	db := &scriptedDB{transactions: []*scriptedTx{tx}}
	store := mustStore(t, db)

	loaded, err := store.LoadByID(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !exactRecord(loaded, record) || !tx.committed || tx.rolledBack {
		t.Fatalf("load mismatch or transaction failure: loaded=%+v", loaded)
	}
	if len(db.options) != 1 || db.options[0].IsoLevel != pgx.ReadCommitted {
		t.Fatalf("wrong transaction isolation: %+v", db.options)
	}
	if len(tx.calls) != 2 || tx.calls[0].query != loadSessionSQL || len(tx.calls[0].args) != 1 ||
		tx.calls[1].query != databaseClockSQL {
		t.Fatalf("load was not one bounded primary-key query: %+v", tx.calls)
	}

	parent := testSessionID(9)
	child := testLoginRecord(2, testDatabaseNow.Add(-time.Minute))
	child.RotationParentID = &parent
	tx = &scriptedTx{rows: []pgx.Row{recordRow(child), timeRow(testDatabaseNow)}}
	store = mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	loaded, err = store.LoadByID(context.Background(), child.ID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.RotationParentID[0] ^= 0xff
	if *child.RotationParentID != parent {
		t.Fatal("returned parent pointer aliases stored input")
	}
}

func TestLoadByIDNotFoundExpiredAndMalformedFailClosed(t *testing.T) {
	valid := testLoginRecord(3, testDatabaseNow.Add(-time.Minute))
	for name, test := range map[string]struct {
		row  pgx.Row
		want error
	}{
		"missing":          {errorRow(pgx.ErrNoRows), ErrNotFound},
		"database error":   {errorRow(errors.New("postgres detail session-secret")), ErrUnavailable},
		"malformed uuid":   {malformedRecordRow(valid, 0, "not-a-uuid"), ErrUnavailable},
		"malformed digest": {malformedRecordRow(valid, 2, "sha256:XYZ"), ErrUnavailable},
		"malformed parent": {malformedRecordRow(valid, 9, "not-a-uuid"), ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			tx := &scriptedTx{rows: []pgx.Row{test.row}}
			store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
			if _, err := store.LoadByID(context.Background(), valid.ID); !errors.Is(err, test.want) || strings.Contains(err.Error(), "session-secret") {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if !tx.rolledBack || tx.committed {
				t.Fatal("failed load did not roll back")
			}
		})
	}

	expired := valid
	expired.CreatedAt = testDatabaseNow.Add(-adminauth.SessionAbsoluteLifetime)
	expired.AuthenticatedAt = expired.CreatedAt
	expired.LastSeenAt = testDatabaseNow.Add(-time.Minute)
	expired.ExpiresAt = testDatabaseNow
	tx := &scriptedTx{rows: []pgx.Row{recordRow(expired), timeRow(testDatabaseNow)}}
	store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	if _, err := store.LoadByID(context.Background(), expired.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired load error = %v", err)
	}

	var nilContext context.Context
	if _, err := store.LoadByID(nilContext, valid.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := store.LoadByID(context.Background(), adminauth.SessionID{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zero id error = %v", err)
	}
}

func TestLoadRevokedDecisionReplayParentUsesLockedDatabaseClockBoundary(t *testing.T) {
	parent := testLoginRecord(24, testDatabaseNow.Add(-time.Minute))
	revokedAt := testDatabaseNow.Add(-time.Second)
	parent.RevokedAt = &revokedAt
	child := testReplacementRecord(25, parent, revokedAt)
	tx := &scriptedTx{rows: []pgx.Row{replayParentPairRow(parent, child), timeRow(testDatabaseNow)}}
	store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	loaded, err := store.LoadRevokedDecisionReplayParent(context.Background(), parent.ID)
	if err != nil || !exactRecord(loaded, parent) || !tx.committed || tx.rolledBack {
		t.Fatalf("replay parent load failed: loaded=%+v err=%v", loaded, err)
	}
	if len(tx.calls) != 2 || tx.calls[0].query != loadRevokedDecisionReplayParentSQL ||
		tx.calls[1].query != databaseClockSQL ||
		len(tx.calls[0].args) != 1 || tx.calls[0].args[0] != parent.ID.String() {
		t.Fatalf("unexpected replay query: %+v", tx.calls)
	}

	tooLate := revokedAt.Add(adminauth.PrivilegedDecisionReplayLifetime)
	tx = &scriptedTx{rows: []pgx.Row{replayParentPairRow(parent, child), timeRow(tooLate)}}
	store = mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	if _, err := store.LoadRevokedDecisionReplayParent(context.Background(), parent.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay accepted at strict boundary: %v", err)
	}
	if !tx.rolledBack || tx.committed {
		t.Fatal("expired replay parent transaction did not roll back")
	}

	for name, mutate := range map[string]func(*adminauth.SessionRecord, *adminauth.SessionRecord, *time.Time){
		"child logout": func(_ *adminauth.SessionRecord, child *adminauth.SessionRecord, now *time.Time) {
			revoked := now.UTC()
			child.RevokedAt = &revoked
		},
		"child second rotation": func(_ *adminauth.SessionRecord, child *adminauth.SessionRecord, now *time.Time) {
			revoked := now.UTC()
			child.RevokedAt = &revoked
		},
		"child expiry": func(_ *adminauth.SessionRecord, child *adminauth.SessionRecord, now *time.Time) {
			child.ExpiresAt = now.UTC()
		},
		"child actor mismatch": func(_ *adminauth.SessionRecord, child *adminauth.SessionRecord, _ *time.Time) {
			child.ActorID = "other-administrator"
		},
		"child authentication mismatch": func(parent *adminauth.SessionRecord, child *adminauth.SessionRecord, _ *time.Time) {
			child.AuthenticatedAt = parent.AuthenticatedAt.Add(time.Microsecond)
		},
		"parent replay window expiry": func(parent *adminauth.SessionRecord, _ *adminauth.SessionRecord, now *time.Time) {
			*now = parent.RevokedAt.Add(adminauth.PrivilegedDecisionReplayLifetime)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedParent, changedChild, changedNow := cloneRecord(parent), cloneRecord(child), testDatabaseNow
			mutate(&changedParent, &changedChild, &changedNow)
			tx := &scriptedTx{rows: []pgx.Row{replayParentPairRow(changedParent, changedChild), timeRow(changedNow)}}
			store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
			if _, err := store.LoadRevokedDecisionReplayParent(context.Background(), changedParent.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("unsafe replay state accepted: %v", err)
			}
			if !tx.rolledBack || tx.committed {
				t.Fatal("unsafe replay state did not roll back")
			}
		})
	}

	for name, rows := range map[string][]pgx.Row{
		"missing": {errorRow(pgx.ErrNoRows)},
		"active parent returned by database": func() []pgx.Row {
			active := cloneRecord(parent)
			active.RevokedAt = nil
			return []pgx.Row{replayParentPairRow(active, child), timeRow(testDatabaseNow)}
		}(),
		"driver detail": {errorRow(errors.New("secret database detail"))},
	} {
		t.Run(name, func(t *testing.T) {
			tx := &scriptedTx{rows: rows}
			store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
			_, err := store.LoadRevokedDecisionReplayParent(context.Background(), parent.ID)
			if name == "missing" || name == "active parent returned by database" {
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("missing error=%v", err)
				}
			} else if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe replay load error=%v", err)
			}
		})
	}
}

func TestInsertLoginPersistsOnlyDigestsAndClassifiesWrites(t *testing.T) {
	record := testLoginRecord(4, testDatabaseNow.Add(-time.Second))
	tx := &scriptedTx{rows: []pgx.Row{timeRow(testDatabaseNow), recordRow(record), timeRow(testDatabaseNow)}}
	store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	inserted, err := store.InsertLogin(context.Background(), record)
	if err != nil || !exactRecord(inserted, record) || !tx.committed {
		t.Fatalf("insert failed: record=%+v err=%v", inserted, err)
	}
	if len(tx.calls) != 3 || tx.calls[1].query != insertSessionSQL || len(tx.calls[1].args) != 10 ||
		tx.calls[2].query != databaseClockSQL {
		t.Fatalf("unexpected insert: %+v", tx.calls)
	}
	rawSession := "raw-session-token-must-never-appear"
	rawCSRF := "raw-csrf-token-must-never-appear"
	for _, arg := range tx.calls[1].args {
		text := fmt.Sprint(arg)
		if strings.Contains(text, rawSession) || strings.Contains(text, rawCSRF) {
			t.Fatal("raw secret reached PostgreSQL arguments")
		}
	}
	if tx.calls[1].args[2] != record.TokenDigest.String() || tx.calls[1].args[3] != record.CSRFDigest.String() {
		t.Fatal("insert did not persist strict digest strings")
	}

	for name, test := range map[string]struct {
		row  pgx.Row
		want error
	}{
		"unique conflict": {errorRow(&pgconn.PgError{Code: "23505", Message: rawSession}), ErrConflict},
		"unavailable":     {errorRow(errors.New("database: " + rawCSRF)), ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			tx := &scriptedTx{rows: []pgx.Row{timeRow(testDatabaseNow), test.row}}
			store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
			_, err := store.InsertLogin(context.Background(), record)
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), rawSession) || strings.Contains(err.Error(), rawCSRF) {
				t.Fatalf("unsafe classified error: %v", err)
			}
		})
	}
}

func TestInsertLoginRejectsCallerTimeAndMalformedShape(t *testing.T) {
	base := testLoginRecord(5, testDatabaseNow.Add(-time.Minute))
	tests := map[string]func(*adminauth.SessionRecord){
		"future": func(record *adminauth.SessionRecord) {
			record.AuthenticatedAt = testDatabaseNow.Add(time.Second)
			record.CreatedAt = record.AuthenticatedAt
			record.LastSeenAt = record.CreatedAt
			record.ExpiresAt = record.CreatedAt.Add(adminauth.SessionAbsoluteLifetime)
		},
		"parent": func(record *adminauth.SessionRecord) {
			parent := testSessionID(12)
			record.RotationParentID = &parent
		},
		"reused digests":   func(record *adminauth.SessionRecord) { record.CSRFDigest = record.TokenDigest },
		"non-schema actor": func(record *adminauth.SessionRecord) { record.ActorID = "Admin@Example" },
		"short lifetime":   func(record *adminauth.SessionRecord) { record.ExpiresAt = record.CreatedAt.Add(time.Hour) },
		"nanosecond time":  func(record *adminauth.SessionRecord) { record.CreatedAt = record.CreatedAt.Add(time.Nanosecond) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := cloneRecord(base)
			mutate(&record)
			tx := &scriptedTx{rows: []pgx.Row{timeRow(testDatabaseNow)}}
			store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
			if _, err := store.InsertLogin(context.Background(), record); !errors.Is(err, ErrConflict) {
				t.Fatalf("malformed login error = %v", err)
			}
			if len(tx.calls) > 1 {
				t.Fatal("malformed login reached insert")
			}
		})
	}
}

func TestTouchUsesDatabaseClockAndExactCAS(t *testing.T) {
	expected := testLoginRecord(6, testDatabaseNow.Add(-time.Minute))
	updated := cloneRecord(expected)
	updated.LastSeenAt = testDatabaseNow
	tx := &scriptedTx{rows: []pgx.Row{recordRow(expected), timeRow(testDatabaseNow), recordRow(updated)}}
	store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	got, err := store.Touch(context.Background(), expected)
	if err != nil || !exactRecord(got, updated) || !tx.committed {
		t.Fatalf("touch failed: got=%+v err=%v", got, err)
	}
	if len(tx.calls) != 3 || tx.calls[0].query != lockSessionSQL || tx.calls[1].query != databaseClockSQL ||
		tx.calls[2].query != touchSessionSQL ||
		!tx.calls[2].args[10].(time.Time).Equal(testDatabaseNow) {
		t.Fatalf("touch did not use locked row and database clock: %+v", tx.calls)
	}

	current := cloneRecord(expected)
	current.LastSeenAt = current.LastSeenAt.Add(time.Second)
	tx = &scriptedTx{rows: []pgx.Row{recordRow(current), timeRow(testDatabaseNow)}}
	store = mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	if _, err := store.Touch(context.Background(), expected); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale touch error = %v", err)
	}
	if len(tx.calls) != 2 || !tx.rolledBack {
		t.Fatal("stale record reached update or was not rolled back")
	}
}

func TestRotateAndRevokeUseLockedExactLiveRecord(t *testing.T) {
	old := testLoginRecord(7, testDatabaseNow.Add(-time.Minute))
	replacement := testReplacementRecord(8, old, testDatabaseNow)
	revoked := cloneRecord(old)
	revokedAt := testDatabaseNow
	revoked.RevokedAt = &revokedAt
	tx := &scriptedTx{rows: []pgx.Row{
		recordRow(old), timeRow(testDatabaseNow), recordRow(revoked), recordRow(replacement), timeRow(testDatabaseNow),
	}}
	store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	got, err := store.Rotate(context.Background(), old, replacement)
	if err != nil || !exactRecord(got, replacement) || !tx.committed {
		t.Fatalf("rotation failed: got=%+v err=%v", got, err)
	}
	if len(tx.calls) != 5 || tx.calls[0].query != lockSessionSQL || tx.calls[1].query != databaseClockSQL ||
		tx.calls[2].query != revokeSessionSQL || tx.calls[3].query != insertSessionSQL {
		t.Fatalf("rotation did not lock/revoke/insert in order: %+v", tx.calls)
	}

	tx = &scriptedTx{rows: []pgx.Row{recordRow(old), timeRow(testDatabaseNow), recordRow(revoked)}}
	store = mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	got, err = store.Revoke(context.Background(), old)
	if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(testDatabaseNow) {
		t.Fatalf("revoke failed: got=%+v err=%v", got, err)
	}

	expired := cloneRecord(old)
	expired.CreatedAt = testDatabaseNow.Add(-adminauth.SessionAbsoluteLifetime)
	expired.AuthenticatedAt = expired.CreatedAt
	expired.LastSeenAt = testDatabaseNow.Add(-time.Minute)
	expired.ExpiresAt = testDatabaseNow
	tx = &scriptedTx{rows: []pgx.Row{recordRow(expired), timeRow(testDatabaseNow)}}
	store = mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	if _, err = store.Revoke(context.Background(), expired); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired revoke error = %v", err)
	}
}

func TestRotateRejectsInvalidReplacementWithoutRevokingOld(t *testing.T) {
	old := testLoginRecord(9, testDatabaseNow.Add(-time.Minute))
	tests := map[string]func(*adminauth.SessionRecord){
		"wrong parent": func(record *adminauth.SessionRecord) {
			parent := testSessionID(20)
			record.RotationParentID = &parent
		},
		"wrong actor":        func(record *adminauth.SessionRecord) { record.ActorID = "other" },
		"reused token":       func(record *adminauth.SessionRecord) { record.TokenDigest = old.TokenDigest },
		"invented auth time": func(record *adminauth.SessionRecord) { record.AuthenticatedAt = record.CreatedAt.Add(-time.Second) },
		"future created": func(record *adminauth.SessionRecord) {
			record.CreatedAt = testDatabaseNow.Add(time.Second)
			record.LastSeenAt = record.CreatedAt
			record.AuthenticatedAt = record.CreatedAt
			record.ExpiresAt = record.CreatedAt.Add(adminauth.SessionAbsoluteLifetime)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			replacement := testReplacementRecord(10, old, testDatabaseNow)
			mutate(&replacement)
			tx := &scriptedTx{rows: []pgx.Row{recordRow(old), timeRow(testDatabaseNow)}}
			store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
			if _, err := store.Rotate(context.Background(), old, replacement); !errors.Is(err, ErrConflict) {
				t.Fatalf("invalid replacement error = %v", err)
			}
			if len(tx.calls) > 2 || !tx.rolledBack {
				t.Fatal("invalid replacement revoked the old session")
			}
		})
	}
}

func TestCommitUncertaintyReturnsUnavailableAndAttemptsRollback(t *testing.T) {
	record := testLoginRecord(11, testDatabaseNow.Add(-time.Second))
	secretDetail := "raw-token-in-driver-error"
	tx := &scriptedTx{
		rows:      []pgx.Row{timeRow(testDatabaseNow), recordRow(record), timeRow(testDatabaseNow)},
		commitErr: errors.New(secretDetail),
	}
	store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	if _, err := store.InsertLogin(context.Background(), record); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), secretDetail) {
		t.Fatalf("commit uncertainty leaked detail: %v", err)
	}
	if !tx.commitCalled || !tx.rolledBack {
		t.Fatal("uncertain commit did not trigger bounded rollback attempt")
	}

	db := &scriptedDB{beginErr: errors.New("dsn-with-secret")}
	store = mustStore(t, db)
	if _, err := store.InsertLogin(context.Background(), record); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "dsn") {
		t.Fatalf("begin error leaked detail: %v", err)
	}
}

func TestPostLockAndPostInsertDatabaseClockCannotReviveStaleSessions(t *testing.T) {
	login := testLoginRecord(21, testDatabaseNow)
	staleAfterInsert := login.LastSeenAt.Add(adminauth.SessionIdleLifetime)
	tx := &scriptedTx{rows: []pgx.Row{
		timeRow(testDatabaseNow), recordRow(login), timeRow(staleAfterInsert),
	}}
	store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	if _, err := store.InsertLogin(context.Background(), login); !errors.Is(err, ErrConflict) {
		t.Fatalf("login stale after insert error = %v", err)
	}
	if !tx.rolledBack || tx.committed {
		t.Fatal("stale post-insert login was committed")
	}

	old := testLoginRecord(22, testDatabaseNow.Add(-time.Minute))
	replacement := testReplacementRecord(23, old, testDatabaseNow)
	revoked := cloneRecord(old)
	revokedAt := testDatabaseNow
	revoked.RevokedAt = &revokedAt
	staleAfterRotation := replacement.LastSeenAt.Add(adminauth.SessionIdleLifetime)
	tx = &scriptedTx{rows: []pgx.Row{
		recordRow(old), timeRow(testDatabaseNow), recordRow(revoked), recordRow(replacement),
		timeRow(staleAfterRotation),
	}}
	store = mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	if _, err := store.Rotate(context.Background(), old, replacement); !errors.Is(err, ErrConflict) {
		t.Fatalf("rotation stale after insert error = %v", err)
	}
	if !tx.rolledBack || tx.committed {
		t.Fatal("stale post-insert rotation was committed")
	}
}

func TestDeleteExpiredIsStrictlyBounded(t *testing.T) {
	for _, limit := range []int{-1, 0, MaxDeleteBatch + 1} {
		store := mustStore(t, &scriptedDB{})
		if _, err := store.DeleteExpired(context.Background(), limit); !errors.Is(err, ErrConflict) {
			t.Fatalf("limit %d error = %v", limit, err)
		}
	}
	tx := &scriptedTx{rows: []pgx.Row{integerRow(7)}}
	store := mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	deleted, err := store.DeleteExpired(context.Background(), 10)
	if err != nil || deleted != 7 || !tx.committed || len(tx.calls) != 1 || tx.calls[0].query != deleteExpiredSQL {
		t.Fatalf("delete failed: deleted=%d err=%v calls=%+v", deleted, err, tx.calls)
	}

	tx = &scriptedTx{rows: []pgx.Row{integerRow(11)}}
	store = mustStore(t, &scriptedDB{transactions: []*scriptedTx{tx}})
	if _, err := store.DeleteExpired(context.Background(), 10); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("over-limit result error = %v", err)
	}
	if !tx.rolledBack {
		t.Fatal("over-limit cleanup result did not roll back")
	}
}

func TestConcurrentRotateAndRevokeOnlyOneSucceeds(t *testing.T) {
	old := testLoginRecord(13, testDatabaseNow.Add(-time.Minute))
	replacement := testReplacementRecord(14, old, testDatabaseNow)
	db := newStateDB(old, testDatabaseNow)
	store := mustStore(t, db)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		<-start
		_, err := store.Rotate(context.Background(), old, replacement)
		results <- err
	}()
	go func() {
		defer wait.Done()
		<-start
		_, err := store.Revoke(context.Background(), old)
		results <- err
	}()
	close(start)
	wait.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent outcomes: success=%d conflict=%d", successes, conflicts)
	}
}

func TestRecordParsersAndExactOptionalValues(t *testing.T) {
	id := testSessionID(15)
	parsed, ok := parseSessionID(id.String())
	if !ok || parsed != id {
		t.Fatal("valid session id did not round trip")
	}
	for _, value := range []string{"", strings.ToUpper(id.String()), "00000000-0000-0000-0000-000000000000", "11111111-1111-1111-1111-111111111111"} {
		if _, ok := parseSessionID(value); ok {
			t.Fatalf("invalid session id accepted: %q", value)
		}
	}
	digest := testDigest(16)
	parsedDigest, ok := parseDigest(digest.String())
	if !ok || parsedDigest != digest {
		t.Fatal("valid digest did not round trip")
	}
	for _, value := range []string{"", "sha256:" + strings.Repeat("0", 64), "SHA256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64)} {
		if _, ok := parseDigest(value); ok {
			t.Fatalf("invalid digest accepted: %q", value)
		}
	}
	if validActorID("Admin") || validActorID("-admin") || validActorID("admin@example") || !validActorID("admin.one-2") {
		t.Fatal("actor ID validation disagrees with ascii_id domain")
	}
}

func mustStore(t *testing.T, db TransactionBeginner) *PostgreSQLStore {
	t.Helper()
	store, err := NewPostgreSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testSessionID(seed byte) adminauth.SessionID {
	var id adminauth.SessionID
	for index := range id {
		id[index] = seed + byte(index)
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return id
}

func testDigest(seed byte) adminauth.Digest {
	var digest adminauth.Digest
	for index := range digest {
		digest[index] = seed + byte(index)
	}
	return digest
}

func testLoginRecord(seed byte, created time.Time) adminauth.SessionRecord {
	return adminauth.SessionRecord{
		ID:              testSessionID(seed),
		ActorID:         "administrator",
		TokenDigest:     testDigest(seed),
		CSRFDigest:      testDigest(seed + 40),
		AuthenticatedAt: created.UTC(),
		CreatedAt:       created.UTC(),
		LastSeenAt:      created.UTC(),
		ExpiresAt:       created.UTC().Add(adminauth.SessionAbsoluteLifetime),
	}
}

func testReplacementRecord(seed byte, old adminauth.SessionRecord, created time.Time) adminauth.SessionRecord {
	parent := old.ID
	record := testLoginRecord(seed, created)
	record.ActorID = old.ActorID
	record.AuthenticatedAt = old.AuthenticatedAt
	record.RotationParentID = &parent
	return record
}

type rowFunc func(...any) error

func (function rowFunc) Scan(destinations ...any) error { return function(destinations...) }

func timeRow(value time.Time) pgx.Row {
	return rowFunc(func(destinations ...any) error {
		if len(destinations) != 1 {
			return errors.New("wrong time scan shape")
		}
		*destinations[0].(*time.Time) = value
		return nil
	})
}

func integerRow(value int) pgx.Row {
	return rowFunc(func(destinations ...any) error {
		if len(destinations) != 1 {
			return errors.New("wrong integer scan shape")
		}
		*destinations[0].(*int) = value
		return nil
	})
}

func errorRow(err error) pgx.Row {
	return rowFunc(func(...any) error { return err })
}

func recordRow(record adminauth.SessionRecord) pgx.Row {
	return rowFunc(func(destinations ...any) error {
		return scanRecordDestinations(destinations, record, nil)
	})
}

func replayParentPairRow(parent, child adminauth.SessionRecord) pgx.Row {
	return rowFunc(func(destinations ...any) error {
		if len(destinations) != 20 {
			return errors.New("wrong replay pair scan shape")
		}
		if err := scanRecordDestinations(destinations[:10], parent, nil); err != nil {
			return err
		}
		return scanRecordDestinations(destinations[10:], child, nil)
	})
}

func malformedRecordRow(record adminauth.SessionRecord, field int, value string) pgx.Row {
	return rowFunc(func(destinations ...any) error {
		return scanRecordDestinations(destinations, record, func(values []any) { values[field] = value })
	})
}

func scanRecordDestinations(destinations []any, record adminauth.SessionRecord, mutate func([]any)) error {
	if len(destinations) != 10 {
		return errors.New("wrong session scan shape")
	}
	var revokedAt *time.Time
	if record.RevokedAt != nil {
		value := record.RevokedAt.UTC()
		revokedAt = &value
	}
	var parent *string
	if record.RotationParentID != nil {
		value := record.RotationParentID.String()
		parent = &value
	}
	values := []any{
		record.ID.String(), record.ActorID, record.TokenDigest.String(), record.CSRFDigest.String(),
		record.AuthenticatedAt, record.CreatedAt, record.LastSeenAt, record.ExpiresAt, revokedAt, parent,
	}
	if mutate != nil {
		mutate(values)
	}
	*destinations[0].(*string) = values[0].(string)
	*destinations[1].(*string) = values[1].(string)
	*destinations[2].(*string) = values[2].(string)
	*destinations[3].(*string) = values[3].(string)
	*destinations[4].(*time.Time) = values[4].(time.Time)
	*destinations[5].(*time.Time) = values[5].(time.Time)
	*destinations[6].(*time.Time) = values[6].(time.Time)
	*destinations[7].(*time.Time) = values[7].(time.Time)
	*destinations[8].(**time.Time) = values[8].(*time.Time)
	if values[9] == nil {
		*destinations[9].(**string) = nil
	} else if text, ok := values[9].(string); ok {
		*destinations[9].(**string) = &text
	} else {
		*destinations[9].(**string) = values[9].(*string)
	}
	return nil
}

type queryCall struct {
	query string
	args  []any
}

type scriptedTx struct {
	pgx.Tx
	mu           sync.Mutex
	rows         []pgx.Row
	calls        []queryCall
	commitErr    error
	commitCalled bool
	committed    bool
	rolledBack   bool
}

func (tx *scriptedTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	arguments := append([]any(nil), args...)
	tx.calls = append(tx.calls, queryCall{query: query, args: arguments})
	if len(tx.rows) == 0 {
		return errorRow(errors.New("unexpected query"))
	}
	row := tx.rows[0]
	tx.rows = tx.rows[1:]
	return row
}

func (tx *scriptedTx) Commit(context.Context) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.commitCalled = true
	if tx.commitErr != nil {
		return tx.commitErr
	}
	tx.committed = true
	return nil
}

func (tx *scriptedTx) Rollback(context.Context) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.rolledBack = true
	return nil
}

type scriptedDB struct {
	mu           sync.Mutex
	transactions []*scriptedTx
	options      []pgx.TxOptions
	beginErr     error
}

func (db *scriptedDB) BeginTx(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.options = append(db.options, options)
	if db.beginErr != nil {
		return nil, db.beginErr
	}
	if len(db.transactions) == 0 {
		return nil, errors.New("no scripted transaction")
	}
	tx := db.transactions[0]
	db.transactions = db.transactions[1:]
	return tx, nil
}

// stateDB is a deterministic pgx transaction fake with a real per-row lock.
// It lets the race test prove that Rotate and Revoke cannot both commit.
type stateDB struct {
	rowMu  sync.Mutex
	mu     sync.Mutex
	old    adminauth.SessionRecord
	now    time.Time
	issued map[adminauth.SessionID]adminauth.SessionRecord
}

func newStateDB(old adminauth.SessionRecord, now time.Time) *stateDB {
	return &stateDB{old: cloneRecord(old), now: now.UTC(), issued: make(map[adminauth.SessionID]adminauth.SessionRecord)}
}

func (db *stateDB) BeginTx(_ context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	if options.IsoLevel != pgx.ReadCommitted {
		return nil, errors.New("wrong isolation")
	}
	return &stateTx{db: db}, nil
}

type stateTx struct {
	pgx.Tx
	db       *stateDB
	locked   bool
	finished bool
}

func (tx *stateTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	switch query {
	case databaseClockSQL:
		return timeRow(tx.db.now)
	case lockSessionSQL:
		if !tx.locked {
			tx.db.rowMu.Lock()
			tx.locked = true
		}
		tx.db.mu.Lock()
		record := cloneRecord(tx.db.old)
		tx.db.mu.Unlock()
		if len(args) != 1 || args[0] != record.ID.String() {
			return errorRow(pgx.ErrNoRows)
		}
		return recordRow(record)
	case revokeSessionSQL:
		tx.db.mu.Lock()
		defer tx.db.mu.Unlock()
		if tx.db.old.RevokedAt != nil {
			return errorRow(pgx.ErrNoRows)
		}
		value := tx.db.now
		tx.db.old.RevokedAt = &value
		return recordRow(tx.db.old)
	case insertSessionSQL:
		record, ok := recordFromArguments(args)
		if !ok {
			return errorRow(errors.New("invalid insert arguments"))
		}
		tx.db.mu.Lock()
		tx.db.issued[record.ID] = cloneRecord(record)
		tx.db.mu.Unlock()
		return recordRow(record)
	default:
		return errorRow(errors.New("unexpected state query"))
	}
}

func (tx *stateTx) Commit(context.Context) error {
	tx.finish()
	return nil
}

func (tx *stateTx) Rollback(context.Context) error {
	tx.finish()
	return nil
}

func (tx *stateTx) finish() {
	if tx.finished {
		return
	}
	tx.finished = true
	if tx.locked {
		tx.db.rowMu.Unlock()
		tx.locked = false
	}
}

func recordFromArguments(arguments []any) (adminauth.SessionRecord, bool) {
	if len(arguments) != 10 {
		return adminauth.SessionRecord{}, false
	}
	id, ok := parseSessionID(arguments[0].(string))
	if !ok {
		return adminauth.SessionRecord{}, false
	}
	token, ok := parseDigest(arguments[2].(string))
	if !ok {
		return adminauth.SessionRecord{}, false
	}
	csrf, ok := parseDigest(arguments[3].(string))
	if !ok {
		return adminauth.SessionRecord{}, false
	}
	record := adminauth.SessionRecord{
		ID: id, ActorID: arguments[1].(string), TokenDigest: token, CSRFDigest: csrf,
		AuthenticatedAt: arguments[4].(time.Time), CreatedAt: arguments[5].(time.Time),
		LastSeenAt: arguments[6].(time.Time), ExpiresAt: arguments[7].(time.Time),
	}
	if arguments[8] != nil {
		value := arguments[8].(time.Time)
		record.RevokedAt = &value
	}
	if arguments[9] != nil {
		parent, valid := parseSessionID(arguments[9].(string))
		if !valid {
			return adminauth.SessionRecord{}, false
		}
		record.RotationParentID = &parent
	}
	return record, validRecord(record)
}
