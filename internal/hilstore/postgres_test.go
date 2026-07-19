package hilstore

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/adminauth"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/policy"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/jackc/pgx/v5"
)

func TestCheckedInputsRetainOnlyDigestsAndRedactFormatting(t *testing.T) {
	rawKey := []byte("0123456789abcdef-production-retry-key")
	key, err := CheckIdempotencyKey(rawKey)
	if err != nil || key.digest != digestBytes(rawKey) {
		t.Fatalf("checked key err=%v", err)
	}
	if strings.Contains(key.String(), key.digest) || strings.Contains(key.GoString(), string(rawKey)) {
		t.Fatal("idempotency formatting exposed material")
	}
	if _, err := CheckIdempotencyKey(make([]byte, minimumIdempotencyBytes-1)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("short idempotency key: %v", err)
	}
	if _, err := CheckIdempotencyKey(make([]byte, maximumIdempotencyBytes+1)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("long idempotency key: %v", err)
	}

	nonceBytes := bytes.Repeat([]byte{0x5a}, decisionNonceBytes)
	encoded := rawURL(nonceBytes)
	nonce, err := CheckDecisionNonce(encoded)
	if err != nil || nonce.digest != digestBytes(nonceBytes) {
		t.Fatalf("checked nonce err=%v", err)
	}
	if strings.Contains(nonce.String(), nonce.digest) || strings.Contains(nonce.GoString(), encoded) {
		t.Fatal("nonce formatting exposed material")
	}
	for _, malformed := range []string{"", encoded + "=", encoded[:len(encoded)-1], strings.Repeat("!", len(encoded))} {
		if _, err := CheckDecisionNonce(malformed); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("malformed nonce %q: %v", malformed, err)
		}
	}

	now := fixtureTime()
	record := fixtureSession(now)
	browser, err := BindValidatedBrowserRequest(record, key)
	if err != nil {
		t.Fatal(err)
	}
	record.ActorID = "mutated"
	if browser.session.ActorID == record.ActorID {
		t.Fatal("browser binding aliased caller session")
	}
	if !strings.Contains(browser.String(), "REDACTED") || !strings.Contains((IssueRequest{}).String(), "REDACTED") {
		t.Fatal("request formatting is not redacted")
	}

	bad := fixtureSession(now)
	bad.RevokedAt = &now
	if _, err := BindValidatedBrowserRequest(bad, key); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("revoked browser projection: %v", err)
	}
	if _, err := BindValidatedBrowserRequest(fixtureSession(now), IdempotencyKey{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero idempotency projection: %v", err)
	}
}

func TestIssueUsesOneReadCommittedTransactionAndDatabaseClock(t *testing.T) {
	now := fixtureTime()
	request := fixtureIssueRequest(t, now, hil.OperationApprove)
	tx := &scriptedTx{}
	tx.query = func(query string, args []any) pgx.Row {
		switch query {
		case issueChallengeSQL:
			if len(args) != 23 {
				t.Fatalf("issue arguments=%d", len(args))
			}
			if args[17] != request.Browser.idempotency.digest {
				t.Fatal("idempotency digest missing")
			}
			for _, argument := range args {
				if raw, ok := argument.([]byte); ok && bytes.Equal(raw, []byte("0123456789abcdef-production-retry-key")) {
					t.Fatal("raw idempotency key reached PostgreSQL")
				}
			}
			return challengeRow(request, args, now)
		case databaseClockSQL:
			return valuesRow(now.Add(time.Second))
		default:
			t.Fatalf("unexpected query %q", query)
			return errorRow(errors.New("unreachable"))
		}
	}
	store := storeWithTransaction(tx, deterministicEntropy(64))
	issued, err := store.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if tx.options.IsoLevel != pgx.ReadCommitted || tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("transaction options=%+v commits=%d rollbacks=%d", tx.options, tx.commits, tx.rollbacks)
	}
	challenge := issued.Challenge().Value()
	if !challenge.IssuedAt.Equal(now) || challenge.Operation != hil.OperationApprove ||
		challenge.PolicyDigest != request.Artifact.PolicyDigest() ||
		challenge.ExpiresAt.After(request.Artifact.ValidationValidUntil()) {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}
	nonce, err := issued.TakeNonce()
	if err != nil {
		t.Fatal(err)
	}
	checkedNonce, err := CheckDecisionNonce(nonce)
	if err != nil || checkedNonce.digest != challenge.NonceDigest {
		t.Fatalf("nonce binding err=%v", err)
	}
	if _, err := issued.TakeNonce(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nonce replay: %v", err)
	}
	if !strings.Contains(issued.String(), "REDACTED") || !strings.Contains(store.String(), "REDACTED") {
		t.Fatal("store formatting exposed state")
	}
}

func TestIssueClassifiesFailClosedOutcomes(t *testing.T) {
	now := fixtureTime()
	cases := []struct {
		name string
		code string
		want error
	}{
		{"authentication", string(CodeAuthentication), ErrAuthentication},
		{"step-up", string(CodeStepUpRequired), ErrStepUpRequired},
		{"conflict", string(CodeConflict), ErrConflict},
		{"stale", string(CodeValidationStale), ErrValidationStale},
		{"validation", string(CodeValidationFailed), ErrValidationFailed},
		{"unknown-fails-validation", "unexpected", ErrValidationFailed},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			tx := &scriptedTx{}
			tx.query = func(query string, _ []any) pgx.Row {
				switch query {
				case issueChallengeSQL:
					return errorRow(pgx.ErrNoRows)
				case classifyIssueFailureSQL:
					return valuesRow(test.code)
				default:
					return errorRow(errors.New("unexpected query"))
				}
			}
			store := storeWithTransaction(tx, deterministicEntropy(64))
			_, err := store.Issue(context.Background(), fixtureIssueRequest(t, now, hil.OperationReject))
			if !errors.Is(err, test.want) || tx.commits != 0 || tx.rollbacks != 1 {
				t.Fatalf("err=%v commits=%d rollbacks=%d", err, tx.commits, tx.rollbacks)
			}
		})
	}
}

func TestIssueRollsBackDriverMalformedStaleAndCommitFailures(t *testing.T) {
	now := fixtureTime()
	request := fixtureIssueRequest(t, now, hil.OperationApprove)
	tests := []struct {
		name   string
		query  func(string, []any) pgx.Row
		commit error
		want   error
	}{
		{
			name:  "driver",
			query: func(string, []any) pgx.Row { return errorRow(errors.New("driver detail must be dropped")) },
			want:  ErrUnavailable,
		},
		{
			name: "malformed-return",
			query: func(query string, args []any) pgx.Row {
				if query == issueChallengeSQL {
					row := challengeValues(request, args, now)
					row[1] = "wrong-schema"
					return valuesRow(row...)
				}
				return valuesRow(now)
			},
			want: ErrUnavailable,
		},
		{
			name: "aged-before-commit",
			query: func(query string, args []any) pgx.Row {
				if query == issueChallengeSQL {
					return challengeRow(request, args, now)
				}
				return valuesRow(request.Artifact.ValidationValidUntil())
			},
			want: ErrValidationStale,
		},
		{
			name: "commit-uncertain",
			query: func(query string, args []any) pgx.Row {
				if query == issueChallengeSQL {
					return challengeRow(request, args, now)
				}
				return valuesRow(now.Add(time.Second))
			},
			commit: errors.New("commit uncertainty detail"),
			want:   ErrUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := &scriptedTx{query: test.query, commitErr: test.commit}
			store := storeWithTransaction(tx, deterministicEntropy(64))
			issued, err := store.Issue(context.Background(), request)
			if issued != nil || !errors.Is(err, test.want) || tx.rollbacks != 1 {
				t.Fatalf("issued=%v err=%v rollbacks=%d", issued, err, tx.rollbacks)
			}
		})
	}
}

func TestIssueRejectsInvalidCompositionEntropyAndBeginFailures(t *testing.T) {
	now := fixtureTime()
	valid := fixtureIssueRequest(t, now, hil.OperationApprove)
	store := storeWithTransaction(&scriptedTx{}, deterministicEntropy(64))
	for _, request := range []IssueRequest{
		{},
		{Operation: "execute", Browser: valid.Browser, Artifact: valid.Artifact},
		{Operation: valid.Operation, Artifact: valid.Artifact},
		{Operation: valid.Operation, Browser: valid.Browser},
	} {
		if _, err := store.Issue(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid request err=%v", err)
		}
	}
	var missingContext context.Context
	if _, err := store.Issue(missingContext, valid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context: %v", err)
	}
	if _, err := (*PostgreSQLStore)(nil).Issue(context.Background(), valid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil store: %v", err)
	}
	if _, err := NewPostgreSQLStore(nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil database: %v", err)
	}

	entropyStore := storeWithTransaction(&scriptedTx{}, bytes.NewReader(make([]byte, 15)))
	if _, err := entropyStore.Issue(context.Background(), valid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("short entropy: %v", err)
	}
	beginStore := &PostgreSQLStore{
		entropy: deterministicEntropy(64),
		begin: func(context.Context, pgx.TxOptions) (transaction, error) {
			return nil, errors.New("database detail")
		},
	}
	if _, err := beginStore.Issue(context.Background(), valid); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("begin failure: %v", err)
	}
}

func TestIssuedNonceConcurrentExactlyOnce(t *testing.T) {
	issued := &IssuedChallenge{nonce: bytes.Repeat([]byte{1}, decisionNonceBytes)}
	const workers = 32
	var wait sync.WaitGroup
	wait.Add(workers)
	results := make(chan error, workers)
	for range workers {
		go func() {
			defer wait.Done()
			_, err := issued.TakeNonce()
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	var successes int
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrNotFound) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("nonce successes=%d", successes)
	}
}

func TestErrorClassificationsAreStableAndDetailFree(t *testing.T) {
	values := []*Error{
		ErrInvalidInput, ErrAuthentication, ErrStepUpRequired, ErrValidationFailed,
		ErrValidationStale, ErrChallengeExpired, ErrNotFound, ErrConflict, ErrUnavailable, nil,
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value.Error()), "postgres") ||
			strings.Contains(value.Error(), "sha256:") {
			t.Fatalf("unsafe error %q", value.Error())
		}
	}
	if ErrConflict.Code() != CodeConflict || (*Error)(nil).Code() != CodeUnavailable ||
		!errors.Is(ErrConflict, &Error{code: CodeConflict}) || isCode(ErrConflict, CodeUnavailable) {
		t.Fatal("error classification mismatch")
	}
}

func fixtureTime() time.Time {
	return time.Date(2026, 7, 18, 12, 0, 0, 123_000_000, time.UTC)
}

func fixtureSession(now time.Time) adminauth.SessionRecord {
	var id adminauth.SessionID
	for index := range id {
		id[index] = byte(index + 1)
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	var token, csrf adminauth.Digest
	for index := range token {
		token[index] = byte(index + 11)
		csrf[index] = byte(index + 51)
	}
	created := now.Add(-5 * time.Minute)
	return adminauth.SessionRecord{
		ID: id, ActorID: "admin-test", TokenDigest: token, CSRFDigest: csrf,
		AuthenticatedAt: created, CreatedAt: created, LastSeenAt: now.Add(-time.Minute),
		ExpiresAt: created.Add(adminauth.SessionAbsoluteLifetime),
	}
}

func fixturePrivilegedCommit(t *testing.T, lookup DecisionLookup, rotationAt time.Time) PrivilegedDecisionCommit {
	t.Helper()
	expected := cloneSession(lookup.Browser.session)
	rotationAt = rotationAt.UTC().Truncate(time.Microsecond)
	revoked := cloneSession(expected)
	revoked.LastSeenAt = rotationAt
	revokedAt := rotationAt
	revoked.RevokedAt = &revokedAt
	replacement := cloneSession(expected)
	replacement.ID[15] ^= 0x5a
	replacement.TokenDigest[0] ^= 0x5a
	replacement.CSRFDigest[0] ^= 0xa5
	replacement.CreatedAt = rotationAt
	replacement.LastSeenAt = rotationAt
	replacement.ExpiresAt = rotationAt.Add(adminauth.SessionAbsoluteLifetime)
	replacement.RevokedAt = nil
	parent := expected.ID
	replacement.RotationParentID = &parent
	commit, err := BindPrivilegedDecisionCommit(
		lookup, expected,
		adminauth.SessionRotation{
			Revoked: revoked,
			Issued:  adminauth.IssuedSession{Record: replacement},
		},
	)
	if err != nil {
		t.Fatalf("bind privileged commit: %v", err)
	}
	return commit
}

func fixtureIssueRequest(t *testing.T, now time.Time, operation hil.Operation) IssueRequest {
	t.Helper()
	key, err := CheckIdempotencyKey([]byte("0123456789abcdef-production-retry-key"))
	if err != nil {
		t.Fatal(err)
	}
	browser, err := BindValidatedBrowserRequest(fixtureSession(now), key)
	if err != nil {
		t.Fatal(err)
	}
	return IssueRequest{Operation: operation, Browser: browser, Artifact: fixtureExact(t, now)}
}

func fixtureExact(t *testing.T, now time.Time) hil.ExactArtifact {
	t.Helper()
	evidence, err := validation.CheckEvidenceSnapshot(validation.EvidenceSnapshot{
		SchemaVersion:      validation.EvidenceSnapshotSchemaVersion,
		SnapshotID:         "019b0000-0000-4000-8000-000000000108",
		IncidentID:         "019b0000-0000-4000-8000-000000000101",
		IncidentVersion:    1,
		SourceIPv4:         "203.0.113.20",
		ServiceLabel:       "demo-app",
		WindowStart:        now.Add(-10 * time.Minute),
		WindowEnd:          now.Add(-2 * time.Minute),
		SourceHealthDigest: testDigest('b'),
		EventIDs:           []string{"019b0000-0000-4000-8000-000000000107"},
		SignalIDs:          []string{"019b0000-0000-4000-8000-000000000106"},
		CreatedAt:          now.Add(-2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	checkedPolicy, err := policy.CheckResponsePolicy(policy.ResponsePolicy{
		SchemaVersion:          policy.PolicySchemaVersion,
		PolicyID:               "019b0000-0000-4000-8000-000000000102",
		PolicyVersion:          3,
		IncidentID:             "019b0000-0000-4000-8000-000000000101",
		AnalysisID:             "019b0000-0000-4000-8000-000000000103",
		Action:                 policy.ActionBlockIP,
		TargetIPv4:             "203.0.113.20",
		TTLSeconds:             1800,
		EvidenceSnapshotDigest: evidence.Digest(),
		EvidenceIDs:            []string{"019b0000-0000-4000-8000-000000000106"},
		RationaleDigest:        testDigest('c'),
		CreatedAt:              now.Add(-90 * time.Second),
	})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	command, err := nftvalidate.Canonicalize([]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1800s }\n"), 1800)
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	checks := []validation.ValidationCheck{
		{CheckID: validation.CheckStructuredOutput, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('d')},
		{CheckID: validation.CheckCommandGrammar, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('e')},
		{CheckID: validation.CheckPolicyEvidenceCommandConsistency, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('f')},
		{CheckID: validation.CheckProtectedNetwork, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('1')},
		{CheckID: validation.CheckOwnedSchemaSyntax, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('2')},
		{CheckID: validation.CheckHistoricalImpact, Result: "pass", ReasonCode: "ok", InputDigest: testDigest('3')},
	}
	checkedValidation, err := validation.CheckValidationSnapshot(validation.ValidationSnapshot{
		SchemaVersion:                      validation.ValidationSnapshotSchemaVersion,
		ValidationID:                       "019b0000-0000-4000-8000-000000000104",
		PolicyDigest:                       checkedPolicy.Digest(),
		EvidenceSnapshotDigest:             evidence.Digest(),
		AnalysisInputDigest:                testDigest('4'),
		AnalysisOutputSchemaDigest:         testDigest('5'),
		PromptDigest:                       testDigest('6'),
		GeneratedCandidateDigest:           command.GeneratedDigest(),
		CanonicalArtifactDigest:            command.CanonicalDigest(),
		GrammarVersion:                     nftvalidate.GrammarVersion,
		ParserVersion:                      nftvalidate.ParserVersion,
		ValidatorVersion:                   nftvalidate.ValidatorVersion,
		BaseChainContractRawDigest:         nftvalidate.PinnedBaseChainRawDigest,
		LiveOwnedSchemaDigest:              nftvalidate.PinnedLiveSchemaDigest,
		ProtectedIPv4StaticDigest:          validation.PinnedProtectedIPv4Digest,
		ProtectedIPv4EffectiveConfigDigest: testDigest('8'),
		NFTBinaryDigest:                    testDigest('9'),
		NFTVersion:                         "1.1.0",
		HistoricalImpactDigest:             testDigest('0'),
		Checks:                             checks,
		CreatedAt:                          now.Add(-time.Minute),
		ValidUntil:                         now.Add(4 * time.Minute),
	})
	if err != nil {
		t.Fatalf("validation: %v", err)
	}
	exact, err := hil.CheckExactArtifact(hil.ExactArtifactInput{
		Policy: checkedPolicy, Command: command, Evidence: evidence, Validation: checkedValidation,
	})
	if err != nil {
		t.Fatalf("exact artifact: %v", err)
	}
	return exact
}

func testDigest(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func rawURL(value []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var result strings.Builder
	for index := 0; index < len(value); index += 3 {
		remaining := len(value) - index
		block := uint32(value[index]) << 16
		if remaining > 1 {
			block |= uint32(value[index+1]) << 8
		}
		if remaining > 2 {
			block |= uint32(value[index+2])
		}
		result.WriteByte(alphabet[(block>>18)&63])
		result.WriteByte(alphabet[(block>>12)&63])
		if remaining > 1 {
			result.WriteByte(alphabet[(block>>6)&63])
		}
		if remaining > 2 {
			result.WriteByte(alphabet[block&63])
		}
	}
	return result.String()
}

func deterministicEntropy(length int) *bytes.Reader {
	value := make([]byte, length)
	for index := range value {
		value[index] = byte(index + 1)
	}
	return bytes.NewReader(value)
}

func storeWithTransaction(tx *scriptedTx, entropy *bytes.Reader) *PostgreSQLStore {
	return &PostgreSQLStore{
		entropy: entropy,
		begin: func(_ context.Context, options pgx.TxOptions) (transaction, error) {
			tx.options = options
			return tx, nil
		},
	}
}

type rowFunc func(...any) error

func (function rowFunc) Scan(destinations ...any) error { return function(destinations...) }

func valuesRow(values ...any) pgx.Row {
	return rowFunc(func(destinations ...any) error {
		if len(destinations) != len(values) {
			return errors.New("scan destination count")
		}
		for index, value := range values {
			destination := reflect.ValueOf(destinations[index])
			if destination.Kind() != reflect.Pointer || destination.IsNil() {
				return errors.New("scan destination shape")
			}
			incoming := reflect.ValueOf(value)
			if !incoming.IsValid() {
				destination.Elem().Set(reflect.Zero(destination.Elem().Type()))
				continue
			}
			if !incoming.Type().AssignableTo(destination.Elem().Type()) {
				return errors.New("scan value type")
			}
			destination.Elem().Set(incoming)
		}
		return nil
	})
}

func errorRow(err error) pgx.Row {
	return rowFunc(func(...any) error { return err })
}

func challengeRow(request IssueRequest, args []any, now time.Time) pgx.Row {
	return valuesRow(challengeValues(request, args, now)...)
}

func challengeValues(request IssueRequest, args []any, now time.Time) []any {
	artifact := request.Artifact
	session := request.Browser.session
	expires := now.Add(hil.ChallengeLifetime)
	if artifact.ValidationValidUntil().Before(expires) {
		expires = artifact.ValidationValidUntil()
	}
	if session.ExpiresAt.Before(expires) {
		expires = session.ExpiresAt
	}
	checked, _ := hil.CheckChallenge(hil.Challenge{
		SchemaVersion: hil.ChallengeSchemaVersion, ChallengeID: args[0].(string),
		SessionDigest: session.TokenDigest.String(), Operation: request.Operation,
		ResourceType: hil.ResourcePolicy, ResourceID: artifact.PolicyID(),
		ResourceVersion: artifact.PolicyVersion(), TargetIPv4: artifact.TargetIPv4(),
		PolicyDigest: artifact.PolicyDigest(), GeneratedArtifactDigest: artifact.GeneratedArtifactDigest(),
		CanonicalArtifactDigest:  artifact.CanonicalArtifactDigest(),
		EvidenceSnapshotDigest:   artifact.EvidenceSnapshotDigest(),
		ValidationSnapshotDigest: artifact.ValidationSnapshotDigest(),
		ValidationValidUntil:     artifact.ValidationValidUntil(), NonceDigest: args[1].(string),
		AuthenticatedAt:            session.AuthenticatedAt,
		ReauthRequiredAfterSeconds: uint32(hil.ReauthAfter / time.Second),
		IssuedAt:                   now, ExpiresAt: expires,
	})
	return []any{
		args[0].(string), hil.ChallengeSchemaVersion, args[1].(string),
		session.ID.String(), session.TokenDigest.String(), session.ActorID,
		string(request.Operation), hil.ResourcePolicy, artifact.PolicyID(),
		int64(artifact.PolicyVersion()), artifact.TargetIPv4(), artifact.PolicyDigest(),
		artifact.EvidenceSnapshotDigest(), artifact.GeneratedArtifactDigest(),
		artifact.CanonicalArtifactDigest(), (*string)(nil), artifact.ValidationSnapshotDigest(),
		artifact.ValidationValidUntil(), request.Browser.idempotency.digest,
		session.AuthenticatedAt, int64(hil.ReauthAfter / time.Second), now, expires,
		checked.CanonicalBytes(), checked.Digest(),
	}
}

type scriptedTx struct {
	query     func(string, []any) pgx.Row
	options   pgx.TxOptions
	commitErr error
	commits   int
	rollbacks int
}

func (tx *scriptedTx) QueryRow(_ context.Context, query string, arguments ...any) pgx.Row {
	if tx.query == nil {
		return errorRow(errors.New("query not scripted"))
	}
	return tx.query(query, arguments)
}

func (tx *scriptedTx) Commit(context.Context) error {
	tx.commits++
	return tx.commitErr
}

func (tx *scriptedTx) Rollback(context.Context) error {
	tx.rollbacks++
	return nil
}
