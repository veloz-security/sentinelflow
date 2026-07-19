package validation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type activationRow func(...any) error

func (row activationRow) Scan(dest ...any) error { return row(dest...) }

type activationDBStub struct {
	mu      sync.Mutex
	rows    []pgx.Row
	queries []string
	args    [][]any
}

func (db *activationDBStub) QueryRow(_ context.Context, query string, arguments ...any) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.queries = append(db.queries, query)
	db.args = append(db.args, append([]any(nil), arguments...))
	if len(db.rows) == 0 {
		return activationRow(func(...any) error { return pgx.ErrNoRows })
	}
	row := db.rows[0]
	db.rows = db.rows[1:]
	return row
}

func TestDemoHistoryActivationPairIsOpaqueConsumerBoundAndTamperEvident(t *testing.T) {
	verifier := newFixtureDemoHistoryVerifier(t)
	input := validDemoHistoryVerificationInput(readDemoHistoryFixture(t))
	activatedAt := historyTestAt
	db := &activationDBStub{rows: []pgx.Row{activationRow(func(dest ...any) error {
		*dest[0].(*string) = "00000000-0000-4000-8000-000000000901"
		*dest[1].(*string) = "00000000-0000-4000-8000-000000000902"
		*dest[2].(*time.Time) = activatedAt
		*dest[3].(*time.Time) = activatedAt.Add(DemoHistoryRuntimeActivationLifetime)
		return nil
	})}}
	analysisSecret := []byte(strings.Repeat("a", 32))
	validationSecret := []byte(strings.Repeat("v", 32))
	pair, err := CreateDemoHistoryRuntimeActivationPair(
		context.Background(), db, analysisSecret, validationSecret, verifier, input,
	)
	if err != nil {
		t.Fatal(err)
	}
	analysis, analysisOK := pair.Analysis()
	validationBinding, validationOK := pair.Validation()
	if !analysisOK || !validationOK || analysis.Consumer() != DemoHistoryConsumerAnalysis ||
		validationBinding.Consumer() != DemoHistoryConsumerValidation {
		t.Fatal("consumer-separated activation pair unavailable")
	}
	analysisCopy, ok := analysis.ActivationSecret()
	if !ok || string(analysisCopy) != string(analysisSecret) {
		t.Fatal("analysis capability defensive copy unavailable")
	}
	analysisCopy[0] ^= 0xff
	secondCopy, ok := analysis.ActivationSecret()
	if !ok || string(secondCopy) != string(analysisSecret) {
		t.Fatal("caller mutation changed retained capability")
	}
	formatted := fmt.Sprintf("%v %#v %s %v %#v", analysis, analysis, analysis, pair, pair)
	for _, forbidden := range []string{
		string(analysisSecret), string(validationSecret), analysis.activationID,
		analysis.claimsDigest, analysis.claims.ManifestDigest,
	} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("activation formatting leaked %q", forbidden)
		}
	}
	if !strings.Contains(formatted, "REDACTED") {
		t.Fatalf("activation formatting=%q", formatted)
	}

	tampered := []ActivatedDemoHistoryBinding{analysis}
	tampered = append(tampered, analysis, analysis, analysis, analysis)
	tampered[0].consumer = DemoHistoryConsumerValidation
	tampered[1].secret[0] ^= 0xff
	tampered[2].receiptMAC[0] ^= 0xff
	tampered[3].claimsDigest = strings.Replace(analysis.claimsDigest, "a", "b", 1)
	tampered[4].expiresAt = tampered[4].expiresAt.Add(time.Second)
	for index, value := range tampered {
		if _, ok := value.ActivationSecret(); ok || value.Consumer() != "" {
			t.Fatalf("tampered activation %d retained authority", index)
		}
	}
	if _, ok := (ActivatedDemoHistoryBinding{}).Binding(); ok {
		t.Fatal("zero activation minted a binding")
	}
}

func TestDemoHistoryActivationAllowsStaleProofOnlyDuringDatabaseAuthorizedPairAttempt(t *testing.T) {
	config := fixtureDemoHistoryVerifierConfig(t)
	config.TestSecurityNow = historyTestAt.Add(10 * time.Minute)
	verifier, err := NewStrictDemoHistoryManifestVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	input := validDemoHistoryVerificationInput(readDemoHistoryFixture(t))
	if _, err := verifier.VerifyDemoHistory(context.Background(), input); manifestErrorCode(err) != DemoHistoryManifestErrorFreshness {
		t.Fatalf("stale fixture unexpectedly retained fresh authority: %v", err)
	}
	db := &activationDBStub{rows: []pgx.Row{activationRow(func(dest ...any) error {
		*dest[0].(*string) = "00000000-0000-4000-8000-000000000911"
		*dest[1].(*string) = "00000000-0000-4000-8000-000000000912"
		*dest[2].(*time.Time) = historyTestAt
		*dest[3].(*time.Time) = historyTestAt.Add(DemoHistoryRuntimeActivationLifetime)
		return nil
	})}}
	pair, err := CreateDemoHistoryRuntimeActivationPair(
		context.Background(), db, []byte(strings.Repeat("a", 32)),
		[]byte(strings.Repeat("v", 32)), verifier, input,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pair.Analysis(); !ok {
		t.Fatal("database-receipted stale exact reattach failed")
	}
	if len(db.queries) != 1 || !strings.Contains(db.queries[0], "create_demo_history_runtime_activation_pair_and_fence_000030") ||
		len(db.args[0]) != 20 {
		t.Fatalf("unexpected activation statement shape: queries=%d args=%d", len(db.queries), len(db.args[0]))
	}
}

func TestAttachDemoHistoryRuntimeActivationUsesExactConsumerCapabilityAndClaims(t *testing.T) {
	verifier := newFixtureDemoHistoryVerifier(t)
	input := validDemoHistoryVerificationInput(readDemoHistoryFixture(t))
	activatedAt := historyTestAt
	db := &activationDBStub{rows: []pgx.Row{activationRow(func(dest ...any) error {
		*dest[0].(*string) = "00000000-0000-4000-8000-000000000921"
		*dest[1].(*time.Time) = activatedAt
		*dest[2].(*time.Time) = activatedAt.Add(DemoHistoryRuntimeActivationLifetime)
		return nil
	})}}
	secret := []byte(strings.Repeat("a", 32))
	activated, err := AttachDemoHistoryRuntimeActivation(
		context.Background(), db, DemoHistoryConsumerAnalysis, secret, verifier, input,
	)
	if err != nil {
		t.Fatal(err)
	}
	if activated.Consumer() != DemoHistoryConsumerAnalysis {
		t.Fatalf("consumer=%q", activated.Consumer())
	}
	copyOfSecret, ok := activated.ActivationSecret()
	if !ok || string(copyOfSecret) != string(secret) {
		t.Fatal("attached activation did not retain the exact defensive capability copy")
	}
	if len(db.queries) != 1 || !strings.Contains(db.queries[0], "attach_demo_history_runtime_activation_000030") ||
		len(db.args) != 1 || len(db.args[0]) != 20 {
		t.Fatalf("unexpected attach statement shape: queries=%d args=%d", len(db.queries), len(db.args[0]))
	}
	if gotSecret, ok := db.args[0][0].([]byte); !ok || string(gotSecret) != string(secret) {
		t.Fatal("attach statement did not receive the exact capability")
	}
	if gotConsumer, ok := db.args[0][1].(string); !ok || gotConsumer != string(DemoHistoryConsumerAnalysis) {
		t.Fatalf("attach consumer=%v", db.args[0][1])
	}
	secret[0] ^= 0xff
	if retained, ok := activated.ActivationSecret(); !ok || string(retained) == string(secret) {
		t.Fatal("caller mutation changed the attached activation capability")
	}
}

func TestAttachDemoHistoryRuntimeActivationFailsClosedOnConsumerCapabilityOrExpiryRejection(t *testing.T) {
	verifier := newFixtureDemoHistoryVerifier(t)
	input := validDemoHistoryVerificationInput(readDemoHistoryFixture(t))
	secretDetail := "database-capability-detail-must-not-leak"
	for _, test := range []struct {
		name     string
		consumer DemoHistoryActivationConsumer
		secret   []byte
	}{
		{name: "cross consumer", consumer: DemoHistoryConsumerValidation, secret: []byte(strings.Repeat("a", 32))},
		{name: "wrong capability", consumer: DemoHistoryConsumerAnalysis, secret: []byte(strings.Repeat("x", 32))},
		{name: "expired activation", consumer: DemoHistoryConsumerAnalysis, secret: []byte(strings.Repeat("a", 32))},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := &activationDBStub{rows: []pgx.Row{activationRow(func(...any) error {
				return errors.New(secretDetail)
			})}}
			activated, err := AttachDemoHistoryRuntimeActivation(
				context.Background(), db, test.consumer, test.secret, verifier, input,
			)
			if !errors.Is(err, ErrDemoHistoryActivationRejected) ||
				strings.Contains(err.Error(), secretDetail) || activated.Consumer() != "" {
				t.Fatalf("attach rejection did not fail closed: activation=%v err=%v", activated, err)
			}
			if len(db.queries) != 1 || !strings.Contains(db.queries[0], "attach_demo_history_runtime_activation_000030") {
				t.Fatalf("attach bypassed the database verifier: %v", db.queries)
			}
		})
	}
}

func TestDemoHistoryActivationSanitizesDatabaseRejection(t *testing.T) {
	secretDetail := "database-password=must-not-leak"
	db := &activationDBStub{rows: []pgx.Row{activationRow(func(...any) error {
		return errors.New(secretDetail)
	})}}
	_, err := CreateDemoHistoryRuntimeActivationPair(
		context.Background(), db, []byte(strings.Repeat("a", 32)),
		[]byte(strings.Repeat("v", 32)), newFixtureDemoHistoryVerifier(t),
		validDemoHistoryVerificationInput(readDemoHistoryFixture(t)),
	)
	if !errors.Is(err, ErrDemoHistoryActivationRejected) || strings.Contains(err.Error(), secretDetail) {
		t.Fatalf("activation error=%v", err)
	}
}
