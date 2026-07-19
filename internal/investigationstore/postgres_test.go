package investigationstore

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	testIncidentID   = "019b0000-0000-7000-8000-000000009001"
	testIncidentID2  = "019b0000-0000-7000-8000-000000009002"
	testIncidentID3  = "019b0000-0000-7000-8000-000000009003"
	testEventID      = "019b0000-0000-7000-8000-000000009101"
	testLinkID       = "019b0000-0000-7000-8000-000000009102"
	testPolicyID     = "019b0000-0000-7000-8000-000000009201"
	testAnalysisID   = "019b0000-0000-4000-8000-000000009202"
	testCandidateID  = "019b0000-0000-7000-8000-000000009203"
	testValidationID = "019b0000-0000-7000-8000-000000009204"
	testActionID     = "019b0000-0000-7000-8000-000000009301"
	testResultID     = "019b0000-0000-7000-8000-000000009302"
	testDigest       = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var testNow = time.Date(2026, 7, 18, 8, 0, 0, 123000000, time.UTC)

func TestCursorRoundTripAndTypeSeparation(t *testing.T) {
	t.Parallel()
	incident := newIncidentCursor(testNow, testIncidentID)
	parsedIncident, err := ParseIncidentCursor(incident.String())
	if err != nil || parsedIncident.time != testNow || parsedIncident.id != testIncidentID {
		t.Fatalf("incident cursor=%+v err=%v", parsedIncident, err)
	}
	event := newEventCursor(testNow, testLinkID)
	parsedEvent, err := ParseEventCursor(event.String())
	if err != nil || parsedEvent.time != testNow || parsedEvent.id != testLinkID {
		t.Fatalf("event cursor=%+v err=%v", parsedEvent, err)
	}
	audit := newAuditCursor(42)
	parsedAudit, err := ParseAuditCursor(audit.String())
	if err != nil || parsedAudit.sequence != 42 {
		t.Fatalf("audit cursor=%+v err=%v", parsedAudit, err)
	}
	if _, err = ParseIncidentCursor(event.String()); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("cross-type cursor error=%v", err)
	}
	alias := audit.String()[:len(audit.String())-1] + "p"
	if _, err = ParseAuditCursor(alias); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("non-canonical audit cursor alias accepted: %q", alias)
	}
	for _, value := range []string{"", "i1.", "i1.%%%", incident.String() + "x", "a1.AAAAAAAAAAA"} {
		if _, err = ParseIncidentCursor(value); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("ParseIncidentCursor(%q) error=%v", value, err)
		}
	}
}

func TestListIncidentsUsesStableKeysetAndBoundedPage(t *testing.T) {
	t.Parallel()
	db := &queryStub{query: func(query string, args []any) (pgx.Rows, error) {
		if query != listIncidentsSQL || len(args) != 9 || args[8] != 3 {
			t.Fatalf("query=%q args=%#v", query, args)
		}
		return rowsOf(
			incidentValues(testIncidentID, testNow),
			incidentValues(testIncidentID2, testNow.Add(-time.Second)),
			incidentValues(testIncidentID3, testNow.Add(-2*time.Second)),
		), nil
	}}
	store, _ := NewPostgreSQLStore(db)
	page, err := store.ListIncidents(context.Background(), IncidentQuery{State: "open", Limit: 2})
	if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	cursor, err := ParseIncidentCursor(page.NextCursor)
	if err != nil || cursor.id != testIncidentID2 || !cursor.time.Equal(testNow.Add(-time.Second)) {
		t.Fatalf("next cursor=%+v err=%v", cursor, err)
	}
}

func TestListAuditUsesSequenceCursorAndSanitizesDriverFailure(t *testing.T) {
	t.Parallel()
	db := &queryStub{query: func(query string, args []any) (pgx.Rows, error) {
		if query != listAuditSQL || len(args) != 12 || args[11] != 2 {
			t.Fatalf("query=%q args=%#v", query, args)
		}
		for index := 0; index < 8; index++ {
			if args[index] != "" {
				t.Fatalf("unexpected filter arg[%d]=%#v", index, args[index])
			}
		}
		return rowsOf(auditValues(20), auditValues(19)), nil
	}}
	store, _ := NewPostgreSQLStore(db)
	page, err := store.ListAuditEvents(context.Background(), AuditQuery{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].Sequence != 20 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	cursor, err := ParseAuditCursor(page.NextCursor)
	if err != nil || cursor.sequence != 20 {
		t.Fatalf("cursor=%+v err=%v", cursor, err)
	}

	secret := errors.New("postgres at 10.0.0.8 exposed token secret")
	store, _ = NewPostgreSQLStore(&queryStub{query: func(string, []any) (pgx.Rows, error) { return nil, secret }})
	_, err = store.ListAuditEvents(context.Background(), AuditQuery{})
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "10.0.0.8") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsanitized error=%v", err)
	}
}

func TestInvalidRequestsNeverReachDatabase(t *testing.T) {
	t.Parallel()
	db := &queryStub{
		query:    func(string, []any) (pgx.Rows, error) { t.Fatal("Query called"); return nil, nil },
		queryRow: func(string, []any) pgx.Row { t.Fatal("QueryRow called"); return errorRow(nil) },
	}
	store, _ := NewPostgreSQLStore(db)
	if _, err := store.ListIncidents(context.Background(), IncidentQuery{SourceIP: "10.0.0.01"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("source error=%v", err)
	}
	if _, err := store.GetIncident(context.Background(), "INVALID"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("incident error=%v", err)
	}
	if _, err := store.ListAuditEvents(context.Background(), AuditQuery{Limit: 101}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("audit error=%v", err)
	}
	if _, err := store.ListAuditEvents(context.Background(), AuditQuery{ActorType: "root"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("audit actor type error=%v", err)
	}
}

func TestReadSQLAndDTOsExcludeSecretBearingMaterial(t *testing.T) {
	t.Parallel()
	statements := []string{
		listIncidentsSQL, getIncidentSQL, listIncidentSignalsSQL, latestIncidentAnalysisSQL,
		analysisFalsePositivesSQL, incidentPoliciesSQL, listIncidentEventsSQL, getPolicySQL,
		latestValidationSQL, validationGatesSQL, latestValidationAttemptSQL, policyDecisionSQL,
		getActionSQL, listAuditSQL,
	}
	for _, statement := range statements {
		lower := strings.ToLower(statement)
		for _, prohibited := range []string{
			"account_hash", "token_digest", "csrf_digest", "session_digest",
			"challenge_nonce_digest", "idempotency_key_digest", "capability_jcs",
			"capability_signature", "result_jcs", "result_signature",
		} {
			if strings.Contains(lower, prohibited) {
				t.Errorf("read SQL exposes %s: %s", prohibited, statement)
			}
		}
	}
	payload, err := json.Marshal(IncidentEvent{
		IncidentEventID: testLinkID, EventID: testEventID, IncidentVersion: 1,
		Kind: "auth", OccurredAt: testNow, TrustState: "trusted", TrustReason: "none",
		RelationReason: "same_source_overlap",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"account_hash", "exact_path", "query", "cookie", "authorization", "raw_headers"} {
		if strings.Contains(strings.ToLower(string(payload)), prohibited) {
			t.Fatalf("DTO leaked %q: %s", prohibited, payload)
		}
	}
}

func TestLatestIncidentAnalysisIsBoundToCurrentEvidenceVersion(t *testing.T) {
	t.Parallel()
	normalized := strings.Join(strings.Fields(latestIncidentAnalysisSQL), " ")
	for _, required := range []string{
		"WHERE analysis.incident_id = $1::uuid",
		"analysis.incident_version = $2::integer",
		"ORDER BY analysis.attempt DESC, analysis.analysis_id DESC",
	} {
		if !strings.Contains(normalized, required) {
			t.Fatalf("latest analysis query lacks %q: %s", required, normalized)
		}
	}
	if strings.Contains(normalized, "ORDER BY incident_version DESC") ||
		strings.Contains(normalized, "JOIN sentinelflow.incidents") {
		t.Fatalf("latest analysis query uses aggregate/latest-version semantics: %s", normalized)
	}
	base := strings.Join(strings.Fields(getIncidentSQL), " ")
	if !strings.Contains(base, "updated_at, evidence_version") {
		t.Fatalf("incident detail base does not capture evidence version: %s", base)
	}
}

func TestGetIncidentBindsAnalysisToEvidenceVersionCapturedByBaseRead(t *testing.T) {
	t.Parallel()
	currentEvidenceVersion := int32(7)
	baseValues := incidentValues(testIncidentID, testNow)
	baseValues[9] = int32(8)
	baseValues = append(baseValues, currentEvidenceVersion)
	db := &queryStub{
		queryRow: func(query string, args []any) pgx.Row {
			switch query {
			case getIncidentSQL:
				if len(args) != 1 || args[0] != testIncidentID {
					t.Fatalf("base args=%#v", args)
				}
				return valuesRow(baseValues...)
			case latestIncidentAnalysisSQL:
				if currentEvidenceVersion != 8 {
					t.Fatalf("test did not simulate evidence drift: %d", currentEvidenceVersion)
				}
				if len(args) != 2 || args[0] != testIncidentID || args[1] != int32(7) {
					t.Fatalf("analysis not bound to captured evidence version: args=%#v", args)
				}
				return valuesRow(
					testAnalysisID, int32(7), "deterministic_stub",
					"sentinelflow-deterministic-ai-stub-v1", nil, nil, nil,
					"succeeded", nil, testDigest, "Synthetic captured analysis",
					"request_burst", "0.90000", "", testNow, testNow,
				)
			default:
				t.Fatalf("unexpected QueryRow: %s", query)
				return errorRow(errors.New("unexpected query"))
			}
		},
		query: func(query string, _ []any) (pgx.Rows, error) {
			switch query {
			case listIncidentSignalsSQL:
				currentEvidenceVersion = 8
				return rowsOf(), nil
			case analysisFalsePositivesSQL, incidentPoliciesSQL:
				return rowsOf(), nil
			default:
				return nil, errors.New("unexpected query")
			}
		},
	}
	store, _ := NewPostgreSQLStore(db)
	detail, err := store.GetIncident(context.Background(), testIncidentID)
	if err != nil || detail.Incident.Version != 8 || detail.Analysis == nil ||
		detail.Analysis.IncidentVersion != 7 {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}
}

func TestGetIncidentWithNullEvidenceVersionUsesTypedNullAndOmitsAnalysis(t *testing.T) {
	t.Parallel()
	baseValues := incidentValues(testIncidentID, testNow)
	baseValues = append(baseValues, nil)
	db := &queryStub{
		queryRow: func(query string, args []any) pgx.Row {
			switch query {
			case getIncidentSQL:
				return valuesRow(baseValues...)
			case latestIncidentAnalysisSQL:
				if len(args) != 2 || args[0] != testIncidentID || args[1] != nil {
					t.Fatalf("nullable evidence version args=%#v", args)
				}
				return errorRow(pgx.ErrNoRows)
			default:
				t.Fatalf("unexpected QueryRow: %s", query)
				return errorRow(errors.New("unexpected query"))
			}
		},
		query: func(query string, _ []any) (pgx.Rows, error) {
			switch query {
			case listIncidentSignalsSQL, incidentPoliciesSQL:
				return rowsOf(), nil
			default:
				return nil, errors.New("unexpected query")
			}
		},
	}
	store, _ := NewPostgreSQLStore(db)
	detail, err := store.GetIncident(context.Background(), testIncidentID)
	if err != nil || detail.Analysis != nil {
		t.Fatalf("nullable current evidence detail=%+v err=%v", detail, err)
	}
}

func TestAnalysisSummaryExposesTruthfulProviderProvenance(t *testing.T) {
	t.Parallel()
	openAI, err := scanAnalysis(valuesRow(
		testAnalysisID, int32(1), "openai_responses", "openai-responses-v1",
		"gpt-5.6-sol", "medium", "operator-v1", "succeeded", nil, testDigest,
		"Synthetic analysis", "path_scan", "0.90000", "", testNow, testNow,
	))
	if err != nil || openAI.Model == nil || *openAI.Model != "gpt-5.6-sol" ||
		openAI.RateCardVersion == nil || *openAI.RateCardVersion != "operator-v1" {
		t.Fatalf("OpenAI analysis=%+v err=%v", openAI, err)
	}

	stub, err := scanAnalysis(valuesRow(
		testAnalysisID, int32(1), "deterministic_stub",
		"sentinelflow-deterministic-ai-stub-v1", nil, nil, nil,
		"succeeded", nil, testDigest, "Synthetic analysis", "path_scan",
		"0.90000", "", testNow, testNow,
	))
	if err != nil || stub.Model != nil || stub.ReasoningEffort != nil ||
		stub.RateCardVersion != nil {
		t.Fatalf("stub analysis=%+v err=%v", stub, err)
	}
	payload, err := json.Marshal(stub)
	if err != nil || !strings.Contains(string(payload), `"provider_kind":"deterministic_stub"`) ||
		!strings.Contains(string(payload), `"model":null`) ||
		strings.Contains(string(payload), "gpt-5.6-sol") ||
		strings.Contains(string(payload), "operator-v1") {
		t.Fatalf("stub API payload=%s err=%v", payload, err)
	}

	_, err = scanAnalysis(valuesRow(
		testAnalysisID, int32(1), "deterministic_stub",
		"sentinelflow-deterministic-ai-stub-v1", "gpt-5.6-sol", nil, nil,
		"succeeded", nil, testDigest, "Synthetic analysis", "path_scan",
		"0.90000", "", testNow, testNow,
	))
	if !errors.Is(err, ErrInvalidRow) {
		t.Fatalf("spoofed stub provenance error=%v", err)
	}
}

func TestListIncidentEventsRejectsPartialJoinRow(t *testing.T) {
	t.Parallel()
	values := []any{
		testLinkID, testEventID, int32(1), "gateway", testNow,
		testIncidentID, "203.0.113.20", "demo", "login", nil, nil, nil,
		nil, nil, nil, nil, nil, "trusted", "none", "same_source_overlap",
	}
	store, _ := NewPostgreSQLStore(&queryStub{query: func(string, []any) (pgx.Rows, error) {
		return rowsOf(values), nil
	}})
	_, err := store.ListIncidentEvents(context.Background(), IncidentEventQuery{IncidentID: testIncidentID})
	if !errors.Is(err, ErrInvalidRow) {
		t.Fatalf("partial join error=%v", err)
	}
}

func TestGetPolicyReturnsReviewArtifactsWithoutAuthorityMaterial(t *testing.T) {
	t.Parallel()
	generated := "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }"
	canonical := generated + "\n"
	db := &queryStub{queryRow: func(query string, args []any) pgx.Row {
		switch query {
		case getPolicySQL:
			if len(args) != 1 || args[0] != testPolicyID {
				t.Fatalf("policy args=%#v", args)
			}
			return valuesRow(
				testPolicyID, int32(1), testIncidentID, int32(2), testAnalysisID,
				testCandidateID, "valid", int64(3), "203.0.113.20", "block_ip",
				int32(1800), "30m", "evidence-bound review", testDigest, testDigest,
				generated, testDigest, canonical, testDigest, "valid", nil, testNow, testNow,
			)
		case latestValidationSQL, policyDecisionSQL:
			return errorRow(pgx.ErrNoRows)
		default:
			t.Fatalf("unexpected QueryRow: %s", query)
			return errorRow(errors.New("unexpected"))
		}
	}, query: func(query string, args []any) (pgx.Rows, error) {
		if query != latestValidationAttemptSQL || len(args) != 1 || args[0] != testPolicyID {
			t.Fatalf("query=%q args=%#v", query, args)
		}
		return rowsOf(), nil
	}}
	store, _ := NewPostgreSQLStore(db)
	policy, err := store.GetPolicy(context.Background(), testPolicyID)
	if err != nil || policy.GeneratedCommand != generated || policy.CanonicalCommand != canonical ||
		policy.Validation != nil || policy.ValidationAttempt != nil || policy.Decision != nil {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	payload, _ := json.Marshal(policy)
	for _, prohibited := range []string{"signature", "session_digest", "nonce", "capability_jcs", "private_key"} {
		if strings.Contains(strings.ToLower(string(payload)), prohibited) {
			t.Fatalf("policy JSON exposed %q: %s", prohibited, payload)
		}
	}
}

func TestGetPolicySanitizesValidationAttemptTerminalBindingFailure(t *testing.T) {
	t.Parallel()
	generated := "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }"
	canonical := generated + "\n"
	db := &queryStub{
		queryRow: func(query string, _ []any) pgx.Row {
			switch query {
			case getPolicySQL:
				return valuesRow(
					testPolicyID, int32(1), testIncidentID, int32(2), testAnalysisID,
					testCandidateID, "valid", int64(3), "203.0.113.20", "block_ip",
					int32(1800), "30m", "evidence-bound review", testDigest, testDigest,
					generated, testDigest, canonical, testDigest, "valid", nil, testNow, testNow,
				)
			case latestValidationSQL:
				return errorRow(pgx.ErrNoRows)
			default:
				return errorRow(errors.New("unexpected query row"))
			}
		},
		query: func(query string, _ []any) (pgx.Rows, error) {
			if query != latestValidationAttemptSQL {
				return nil, errors.New("unexpected query")
			}
			return nil, &pgconn.PgError{
				Code: "55000", Message: "validation attempt terminal binding mismatch",
				Detail: "terminal_private must not leak",
			}
		},
	}
	store, _ := NewPostgreSQLStore(db)
	_, err := store.GetPolicy(context.Background(), testPolicyID)
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "terminal_private") ||
		strings.Contains(err.Error(), "terminal binding mismatch") {
		t.Fatalf("unsanitized terminal-binding error=%v", err)
	}
}

func TestGetPolicyRejectsCrossPolicyValidationAttemptProjection(t *testing.T) {
	t.Parallel()
	generated := "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }"
	canonical := generated + "\n"
	attempt := validationAttempt("invalid", 5, "history_demo_binding_mismatch")
	attempt.PolicyID = testIncidentID2
	db := &queryStub{
		queryRow: func(query string, _ []any) pgx.Row {
			switch query {
			case getPolicySQL:
				return valuesRow(
					testPolicyID, int32(1), testIncidentID, int32(2), testAnalysisID,
					testCandidateID, "valid", int64(3), "203.0.113.20", "block_ip",
					int32(1800), "30m", "evidence-bound review", testDigest, testDigest,
					generated, testDigest, canonical, testDigest, "valid", nil, testNow, testNow,
				)
			case latestValidationSQL, policyDecisionSQL:
				return errorRow(pgx.ErrNoRows)
			default:
				return errorRow(errors.New("unexpected query row"))
			}
		},
		query: func(query string, _ []any) (pgx.Rows, error) {
			if query != latestValidationAttemptSQL {
				return nil, errors.New("unexpected query")
			}
			rows := make([][]any, len(attempt.Gates))
			for index, gate := range attempt.Gates {
				rows[index] = validationAttemptRow(attempt, &gate)
			}
			return rowsOf(rows...), nil
		},
	}
	store, _ := NewPostgreSQLStore(db)
	_, err := store.GetPolicy(context.Background(), testPolicyID)
	if !errors.Is(err, ErrInvalidRow) {
		t.Fatalf("cross-policy projection error=%v", err)
	}
}

func TestGetActionReturnsOnlySafeLatestResult(t *testing.T) {
	t.Parallel()
	db := &queryStub{queryRow: func(query string, args []any) pgx.Row {
		if query != getActionSQL || len(args) != 1 || args[0] != testActionID {
			t.Fatalf("query=%q args=%#v", query, args)
		}
		return valuesRow(
			testActionID, testPolicyID, int32(1), testValidationID, testDigest,
			"203.0.113.20", testDigest, int32(1800), "active", testNow,
			testNow, testNow, testNow.Add(30*time.Minute), nil, int32(2), testNow, testNow,
			testResultID, "inspect", "inspect_active", "active", int32(1200),
			int64(4), "none", testDigest, testNow,
		)
	}}
	store, _ := NewPostgreSQLStore(db)
	action, err := store.GetEnforcementAction(context.Background(), testActionID)
	if err != nil || action.LatestResult == nil || action.LatestResult.Operation != "inspect" ||
		action.LatestResult.RemainingTTLSeconds == nil || *action.LatestResult.RemainingTTLSeconds != 1200 {
		t.Fatalf("action=%+v err=%v", action, err)
	}
	payload, _ := json.Marshal(action)
	for _, prohibited := range []string{"result_signature", "result_jcs", "capability", "canonical_artifact\""} {
		if strings.Contains(strings.ToLower(string(payload)), prohibited) {
			t.Fatalf("action JSON exposed %q: %s", prohibited, payload)
		}
	}
}

func incidentValues(id string, lastSeen time.Time) []any {
	return []any{
		id, "request_burst", "open", "203.0.113.20", "demo",
		lastSeen.Add(-time.Minute), lastSeen, nil, "0.90000", int32(1), nil,
		lastSeen.Add(-time.Minute), lastSeen,
	}
}

func auditValues(sequence int64) []any {
	return []any{
		sequence, testEventID, "system", "analysis-worker", "analysis_succeeded",
		"analysis", testLinkID, testIncidentID, nil, nil, nil, nil,
		testDigest, nil, "succeeded", testNow, testNow,
	}
}

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
