package hilstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestCommitUsesCoordinatorAndStrictlyRebindsApproval(t *testing.T) {
	issuedAt := fixtureTime()
	lookup := fixtureDecisionLookup(t, issuedAt, hil.OperationApprove)
	commit := fixturePrivilegedCommit(t, lookup, issuedAt.Add(500*time.Millisecond))
	databaseNow := issuedAt.Add(time.Second)
	tx := &scriptedTx{}
	// Capture the coordinator arguments for the subsequent exact projection.
	var captured []any
	tx.query = func(query string, arguments []any) pgx.Row {
		switch query {
		case databaseClockSQL:
			return valuesRow(databaseNow)
		case commitDecisionSQL:
			if len(arguments) != 54 || arguments[6] != lookup.Challenge.Value().ChallengeID ||
				arguments[7].([]byte) == nil || arguments[8] != lookup.Challenge.Digest() ||
				arguments[28].([]byte) == nil || arguments[33].([]byte) == nil ||
				arguments[38].([]byte) == nil ||
				arguments[41] != lookup.Browser.session.CreatedAt ||
				arguments[45] != commit.replacement.ID.String() {
				t.Fatal("coordinator did not receive exact checked JCS bindings")
			}
			captured = append([]any(nil), arguments...)
			return valuesRow(arguments[30].(string), false, true)
		case lookupDecisionSQL:
			return valuesRow(storedCommitValues(lookup, captured, databaseNow, true)...)
		default:
			return errorRow(errors.New("unexpected query"))
		}
	}
	store := storeWithTransaction(tx, deterministicEntropy(256))
	stored, err := store.Commit(context.Background(), commit)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if tx.options.IsoLevel != pgx.ReadCommitted || tx.commits != 1 || tx.rollbacks != 0 ||
		stored.Decision().Value().Decision != hil.DecisionApproved || stored.ActionID() == "" ||
		stored.AuthorizationDigest() == "" || stored.OutboxJobID() == "" || !stored.SessionRotated() {
		t.Fatalf("unexpected stored projection: %v", stored)
	}
}

func TestBindPrivilegedDecisionCommitRejectsMisbindingAndNoncanonicalRotation(t *testing.T) {
	now := fixtureTime()
	lookup := fixtureDecisionLookup(t, now, hil.OperationApprove)
	checked := fixturePrivilegedCommit(t, lookup, now.Add(time.Second))
	rotationFrom := func(value PrivilegedDecisionCommit) adminauth.SessionRotation {
		revoked := cloneSession(value.expected)
		revoked.LastSeenAt = value.rotationAt
		revokedAt := value.rotationAt
		revoked.RevokedAt = &revokedAt
		return adminauth.SessionRotation{
			Revoked: revoked,
			Issued:  adminauth.IssuedSession{Record: cloneSession(value.replacement)},
		}
	}
	tests := map[string]func(*adminauth.SessionRecord, *adminauth.SessionRotation){
		"lookup-session": func(expected *adminauth.SessionRecord, _ *adminauth.SessionRotation) {
			expected.ID[15] ^= 1
		},
		"actor": func(_ *adminauth.SessionRecord, rotation *adminauth.SessionRotation) {
			rotation.Issued.Record.ActorID = "other-admin"
		},
		"token-digest": func(expected *adminauth.SessionRecord, rotation *adminauth.SessionRotation) {
			rotation.Issued.Record.TokenDigest = expected.TokenDigest
		},
		"csrf-digest": func(expected *adminauth.SessionRecord, rotation *adminauth.SessionRotation) {
			rotation.Issued.Record.CSRFDigest = expected.CSRFDigest
		},
		"parent": func(_ *adminauth.SessionRecord, rotation *adminauth.SessionRotation) {
			rotation.Issued.Record.RotationParentID = nil
		},
		"authenticated-at": func(_ *adminauth.SessionRecord, rotation *adminauth.SessionRotation) {
			rotation.Issued.Record.AuthenticatedAt = rotation.Issued.Record.AuthenticatedAt.Add(time.Microsecond)
		},
		"expiry": func(_ *adminauth.SessionRecord, rotation *adminauth.SessionRotation) {
			rotation.Issued.Record.ExpiresAt = rotation.Issued.Record.ExpiresAt.Add(time.Microsecond)
		},
		"rotation-time": func(_ *adminauth.SessionRecord, rotation *adminauth.SessionRotation) {
			changed := rotation.Revoked.RevokedAt.Add(time.Nanosecond)
			rotation.Revoked.RevokedAt = &changed
			rotation.Revoked.LastSeenAt = changed
			rotation.Issued.Record.CreatedAt = changed
			rotation.Issued.Record.LastSeenAt = changed
			rotation.Issued.Record.ExpiresAt = changed.Add(adminauth.SessionAbsoluteLifetime)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			expected := cloneSession(checked.expected)
			rotation := rotationFrom(checked)
			mutate(&expected, &rotation)
			if _, err := BindPrivilegedDecisionCommit(lookup, expected, rotation); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCommitExpiredExactReplayReturnsOriginalWithoutSecondRotation(t *testing.T) {
	now := fixtureTime()
	lookup := fixtureDecisionLookup(t, now, hil.OperationReject)
	commit := fixturePrivilegedCommit(t, lookup, now.Add(time.Second))
	databaseNow := lookup.Challenge.Value().ExpiresAt.Add(time.Hour)
	var captured []any
	tx := &scriptedTx{query: func(query string, arguments []any) pgx.Row {
		switch query {
		case databaseClockSQL:
			return valuesRow(databaseNow)
		case commitDecisionSQL:
			captured = append([]any(nil), arguments...)
			return valuesRow(arguments[30].(string), true, false)
		case verifyRetainedRotationChildSQL:
			if len(arguments) != 9 || arguments[0] != commit.replacement.ID.String() ||
				arguments[8] != commit.replacement.RotationParentID.String() {
				t.Fatal("retained replay child verification lost exact rotation binding")
			}
			return valuesRow(true)
		case lookupDecisionSQL:
			return valuesRow(storedCommitValues(lookup, captured, databaseNow, false)...)
		default:
			return errorRow(errors.New("unexpected query"))
		}
	}}
	stored, err := storeWithTransaction(tx, deterministicEntropy(256)).Commit(context.Background(), commit)
	if err != nil || stored.SessionRotated() || stored.Decision().Value().Decision != hil.DecisionRejected ||
		tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("stored=%v err=%v commits=%d rollbacks=%d", stored, err, tx.commits, tx.rollbacks)
	}
}

func TestCommitExactReplayRejectsInactiveOrUnverifiableRetainedChild(t *testing.T) {
	now := fixtureTime()
	lookup := fixtureDecisionLookup(t, now, hil.OperationApprove)
	commit := fixturePrivilegedCommit(t, lookup, now.Add(time.Second))
	for _, test := range []struct {
		name string
		row  pgx.Row
		want error
	}{
		{name: "logged out or second rotation", row: valuesRow(false), want: ErrAuthentication},
		{name: "database unavailable", row: errorRow(errors.New("secret driver detail")), want: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &scriptedTx{query: func(query string, arguments []any) pgx.Row {
				switch query {
				case databaseClockSQL:
					return valuesRow(now.Add(2 * time.Second))
				case commitDecisionSQL:
					return valuesRow(arguments[30].(string), true, false)
				case verifyRetainedRotationChildSQL:
					return test.row
				default:
					t.Fatalf("inactive child crossed into query %q", query)
					return errorRow(errors.New("unexpected query"))
				}
			}}
			stored, err := storeWithTransaction(tx, deterministicEntropy(256)).Commit(context.Background(), commit)
			if !errors.Is(err, test.want) || stored.Decision().Digest() != "" || tx.commits != 0 || tx.rollbacks != 1 {
				t.Fatalf("stored=%v err=%v commits=%d rollbacks=%d", stored, err, tx.commits, tx.rollbacks)
			}
		})
	}
}

func TestCommitDelegatesExpiredFreshDecisionToLockedCoordinator(t *testing.T) {
	now := fixtureTime()
	lookup := fixtureDecisionLookup(t, now, hil.OperationReject)
	commit := fixturePrivilegedCommit(t, lookup, now.Add(time.Millisecond))
	tx := &scriptedTx{query: func(query string, _ []any) pgx.Row {
		switch query {
		case databaseClockSQL:
			return valuesRow(lookup.Challenge.Value().ExpiresAt)
		case commitDecisionSQL:
			return errorRow(&pgconn.PgError{Code: "SF006", Message: "challenge_expired"})
		default:
			t.Fatalf("unexpected query %q", query)
			return errorRow(errors.New("unexpected query"))
		}
	}}
	_, err := storeWithTransaction(tx, deterministicEntropy(128)).Commit(context.Background(), commit)
	if !errors.Is(err, ErrChallengeExpired) || tx.commits != 0 || tx.rollbacks != 1 {
		t.Fatalf("err=%v commits=%d rollbacks=%d", err, tx.commits, tx.rollbacks)
	}
}

func TestCoordinatorSQLStateClassificationIsDetailFree(t *testing.T) {
	for _, test := range []struct {
		code string
		want error
	}{
		{"SF001", ErrInvalidInput}, {"SF002", ErrAuthentication},
		{"SF003", ErrStepUpRequired}, {"SF004", ErrValidationFailed},
		{"SF005", ErrValidationStale}, {"SF006", ErrChallengeExpired},
		{"SF007", ErrNotFound}, {"SF008", ErrConflict}, {"23505", ErrConflict},
		{"XX000", ErrUnavailable},
	} {
		err := classifyCoordinatorError(&pgconn.PgError{Code: test.code, Message: "secret database detail"})
		if !errors.Is(err, test.want) || err.Error() == "secret database detail" {
			t.Fatalf("code=%s err=%v", test.code, err)
		}
	}
}

func storedCommitValues(lookup DecisionLookup, arguments []any, now time.Time, approved bool) []any {
	values := storedDecisionValues(lookup, now, approved)
	decisionID := arguments[30].(string)
	decidedAt := arguments[31].(time.Time)
	validUntil := arguments[32].(time.Time)
	values[1] = decisionID
	values[20] = decidedAt
	values[21] = validUntil
	consumedAt := decidedAt
	values[27] = &consumedAt
	values[28] = &decisionID
	values[46] = arguments[33].([]byte)
	values[47] = arguments[34].(string)
	if approved {
		authorizationID := arguments[35].(string)
		actionID := arguments[36].(string)
		outboxID := arguments[37].(string)
		authorizationDigest := arguments[39].(string)
		values[37] = &authorizationDigest
		values[38] = &actionID
		values[39] = &actionID
		values[41] = &outboxID
		values[48] = arguments[38].([]byte)
		values[49] = &authorizationID
		values[50] = &decidedAt
		values[51] = &validUntil
	}
	return values
}
