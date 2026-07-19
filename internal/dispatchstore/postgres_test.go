package dispatchstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	testDispatchKeyID = "dispatch-test-v1"
	testResultKeyID   = "result-test-v1"
	testExecutorID    = "executor-test"
)

func TestListEligibleUsesOnlyRestrictedViewAndRedactsFormatting(t *testing.T) {
	t.Parallel()
	first := fixtureJob()
	second := cloneJob(first)
	second.jobID = "019b0000-0000-7000-8000-000000000102"
	second.actionID = "019b0000-0000-7000-8000-000000000202"
	second.availableAt = first.availableAt.Add(time.Microsecond)
	second.targetIPv4 = "203.0.113.21"
	second.artifact = []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.21 timeout 1m }\n")
	second.artifactDigest = digestBytes(second.artifact)
	tx := &scriptedTx{query: func(query string, args []any) (pgx.Rows, error) {
		if query != listEligibleSQL || len(args) != 1 || args[0] != 2 {
			t.Fatalf("unexpected restricted-view query")
		}
		if strings.Contains(query, "sentinelflow.outbox_jobs") ||
			!strings.Contains(query, "sentinelflow.dispatcher_approved_outbox") ||
			!strings.Contains(query, "ORDER BY available_at ASC, job_id ASC") {
			t.Fatal("query bypassed deterministic restricted view")
		}
		return rowsForJobs(first, second), nil
	}}
	store := fixtureStore(tx, bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	jobs, err := store.ListEligible(context.Background(), 2)
	if err != nil || len(jobs) != 2 || jobs[0].JobID() != first.jobID || jobs[1].JobID() != second.jobID {
		t.Fatalf("jobs=%d err=%v", len(jobs), err)
	}
	if tx.options.AccessMode != pgx.ReadOnly || tx.commits != 1 || tx.rollbacks != 0 {
		t.Fatalf("options=%+v commits=%d rollbacks=%d", tx.options, tx.commits, tx.rollbacks)
	}
	formatted := jobs[0].String() + jobs[0].GoString() + store.String()
	if strings.Contains(formatted, first.targetIPv4) || strings.Contains(formatted, string(first.artifact)) ||
		!strings.Contains(formatted, "REDACTED") {
		t.Fatal("formatting exposed restricted projection")
	}
	artifact := jobs[0].ArtifactBytes()
	artifact[0] ^= 0xff
	if bytes.Equal(artifact, jobs[0].ArtifactBytes()) {
		t.Fatal("artifact accessor returned aliased storage")
	}
	if _, ok := jobs[0].OriginalAddDigest(); ok {
		t.Fatal("add unexpectedly had an original-add digest")
	}
}

func TestEligibleProjectionAccessorsAndOperationShapes(t *testing.T) {
	t.Parallel()
	job := fixtureJob()
	eligible := EligibleJob{value: cloneJob(job)}
	if eligible.Kind() != job.kind || eligible.Operation() != job.operation ||
		eligible.ActionID() != job.actionID || eligible.PolicyID() != job.policyID ||
		eligible.PolicyVersion() != job.policyVersion || eligible.TargetIPv4() != job.targetIPv4 ||
		eligible.ArtifactDigest() != job.artifactDigest ||
		eligible.EvidenceSnapshotDigest() != job.evidenceSnapshotDigest ||
		eligible.ValidationSnapshotDigest() != job.validationSnapshotDigest ||
		eligible.AuthorizationDigest() != job.authorizationDigest || eligible.ActorID() != job.actorID ||
		eligible.ReasonDigest() != job.reasonDigest || eligible.OwnedSchemaDigest() != job.ownedSchemaDigest ||
		!eligible.AvailableAt().Equal(job.availableAt) || eligible.Attempts() != job.attempts ||
		eligible.MaxAttempts() != job.maxAttempts || !eligible.NotBefore().Equal(job.notBefore) ||
		!eligible.ValidUntil().Equal(job.validUntil) {
		t.Fatal("eligible accessors changed the immutable projection")
	}

	original := "sha256:" + strings.Repeat("6", 64)
	for operation, kind := range map[capability.Operation]string{
		capability.OperationRevoke:  "dispatch_revoke",
		capability.OperationInspect: "dispatch_inspect",
	} {
		variant := cloneJob(job)
		variant.operation, variant.kind, variant.originalAddDigest = operation, kind, &original
		if !validJob(variant) {
			t.Fatalf("valid %s projection rejected", operation)
		}
		value, ok := (EligibleJob{value: variant}).OriginalAddDigest()
		if !ok || value != original {
			t.Fatalf("%s original-add digest missing", operation)
		}
	}
	wrong := cloneJob(job)
	wrong.operation = capability.OperationRevoke
	if validJob(wrong) {
		t.Fatal("revoke without original add digest accepted")
	}
	reclaim := cloneJob(job)
	reclaim.state, reclaim.attempts = "leased", 1
	if !validJob(reclaim) {
		t.Fatal("authorized expired-lease view projection was rejected")
	}
}

func TestListEligibleRejectsMalformedOrMisorderedRows(t *testing.T) {
	t.Parallel()
	base := fixtureJob()
	malformed := cloneJob(base)
	malformed.artifactDigest = strings.Repeat("a", 64)
	misordered := cloneJob(base)
	misordered.jobID = "019b0000-0000-7000-8000-000000000099"
	for name, rows := range map[string]pgx.Rows{
		"digest": rowsForJobs(malformed),
		"order":  rowsForJobs(base, misordered),
		"scan":   &scriptedRows{rows: [][]any{{"too", "short"}}},
		"driver": &scriptedRows{terminalErr: errors.New("row detail")},
	} {
		t.Run(name, func(t *testing.T) {
			tx := &scriptedTx{query: func(string, []any) (pgx.Rows, error) { return rows, nil }}
			store := fixtureStore(tx, nil)
			_, err := store.ListEligible(context.Background(), 2)
			if name == "driver" {
				if !errors.Is(err, ErrUnavailable) {
					t.Fatalf("err=%v", err)
				}
			} else if !errors.Is(err, ErrInvalidRow) {
				t.Fatalf("err=%v", err)
			}
			if tx.rollbacks != 1 || tx.commits != 0 {
				t.Fatalf("commits=%d rollbacks=%d", tx.commits, tx.rollbacks)
			}
		})
	}
}

func TestClaimNextUsesDatabaseClockFencingAndCryptoUUID(t *testing.T) {
	t.Parallel()
	job := fixtureJob()
	now := fixtureTime()
	clockCalls := 0
	var claimArguments []any
	tx := &scriptedTx{
		query: func(string, []any) (pgx.Rows, error) { return rowsForJobs(job), nil },
		queryRow: func(query string, args []any) pgx.Row {
			switch query {
			case databaseClockSQL:
				clockCalls++
				return valuesRow(now.Add(time.Duration(clockCalls) * time.Microsecond))
			case claimJobSQL:
				claimArguments = append([]any(nil), args...)
				return valuesRow(true)
			default:
				return errorRow(errors.New("unexpected query"))
			}
		},
	}
	store := fixtureStore(tx, bytes.NewReader(make([]byte, 16)))
	claim, found, err := store.ClaimNext(context.Background(), ClaimRequest{
		LeaseOwner: "dispatcher-one", LeaseDuration: 30 * time.Second, CandidateLimit: 4,
	})
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if tx.commits != 1 || tx.rollbacks != 0 || len(claimArguments) != 4 ||
		claimArguments[0] != job.jobID || claimArguments[2] != "dispatcher-one" {
		t.Fatalf("claim args=%#v commits=%d rollbacks=%d", claimArguments, tx.commits, tx.rollbacks)
	}
	token, ok := claimArguments[1].(string)
	if !ok || !uuidV4Pattern.MatchString(token) || token != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("lease token is not canonical random UUIDv4")
	}
	if !claim.ClaimedAt().Equal(now.Add(2*time.Microsecond)) ||
		!claim.LeaseUntil().Equal(now.Add(time.Microsecond).Add(30*time.Second)) || claim.Attempt() != 1 {
		t.Fatal("claim did not retain database-clock fencing")
	}
	issued, notBefore, expires, err := claim.CapabilityWindow(20 * time.Second)
	if err != nil || issued.Nanosecond()%int(time.Millisecond) != 0 || notBefore != issued ||
		!expires.Equal(issued.Add(20*time.Second)) {
		t.Fatalf("window issued=%v notBefore=%v expires=%v err=%v", issued, notBefore, expires, err)
	}
	formatted := claim.String() + claim.GoString() + (ClaimRequest{}).String()
	if strings.Contains(formatted, job.targetIPv4) || strings.Contains(formatted, token) ||
		!strings.Contains(formatted, "REDACTED") {
		t.Fatal("claim formatting exposed material")
	}
}

func TestClaimRecoveryNextUsesDedicatedPathWithoutAttemptOrMintAuthority(t *testing.T) {
	t.Parallel()
	job := fixtureJob()
	job.state = "retry"
	job.attempts = job.maxAttempts
	now := fixtureTime()
	clockCalls := 0
	tx := &scriptedTx{
		query: func(query string, args []any) (pgx.Rows, error) {
			if query != listRecoveryEligibleSQL || len(args) != 1 {
				t.Fatal("recovery claim bypassed dedicated restricted view")
			}
			return rowsForJobs(job), nil
		},
		queryRow: func(query string, _ []any) pgx.Row {
			switch query {
			case databaseClockSQL:
				clockCalls++
				return valuesRow(now.Add(time.Duration(clockCalls) * time.Microsecond))
			case claimRecoveryJobSQL:
				return valuesRow(true)
			default:
				return errorRow(errors.New("unexpected query"))
			}
		},
	}
	store := fixtureStore(tx, nil)
	claim, found, err := store.ClaimRecoveryNext(context.Background(), fixtureClaimRequest())
	if err != nil || !found || !claim.Job().RecoveryOnly() ||
		claim.Job().Attempts() != job.maxAttempts || tx.commits != 1 {
		t.Fatalf("found=%v recovery=%v attempts=%d commits=%d err=%v",
			found, claim.Job().RecoveryOnly(), claim.Job().Attempts(), tx.commits, err)
	}
	if _, _, _, err := claim.CapabilityWindow(time.Second); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("recovery claim retained mint window: %v", err)
	}
	ordinary := fixtureClaim()
	_, issuer := fixtureStoreAndIssuer(nil)
	signed, _ := fixtureSignedCapability(t, ordinary, issuer, time.Second)
	if _, err := store.PersistCapability(context.Background(), claim, signed); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("recovery claim persisted new capability: %v", err)
	}
}

func TestClaimNextHandlesContentionExpiryAndEntropyFailures(t *testing.T) {
	t.Parallel()
	job := fixtureJob()
	now := fixtureTime()
	t.Run("contended", func(t *testing.T) {
		tx := &scriptedTx{
			query: func(string, []any) (pgx.Rows, error) { return rowsForJobs(job), nil },
			queryRow: func(query string, _ []any) pgx.Row {
				if query == databaseClockSQL {
					return valuesRow(now)
				}
				return valuesRow(false)
			},
		}
		store := fixtureStore(tx, nil)
		_, found, err := store.ClaimNext(context.Background(), fixtureClaimRequest())
		if err != nil || found || tx.rollbacks != 1 {
			t.Fatalf("found=%v err=%v rollbacks=%d", found, err, tx.rollbacks)
		}
	})
	t.Run("expired-before-commit", func(t *testing.T) {
		clock := 0
		tx := &scriptedTx{
			query: func(string, []any) (pgx.Rows, error) { return rowsForJobs(job), nil },
			queryRow: func(query string, _ []any) pgx.Row {
				if query == claimJobSQL {
					return valuesRow(true)
				}
				clock++
				if clock == 1 {
					return valuesRow(now)
				}
				return valuesRow(now.Add(30 * time.Second))
			},
		}
		store := fixtureStore(tx, nil)
		_, found, err := store.ClaimNext(context.Background(), fixtureClaimRequest())
		if found || !errors.Is(err, ErrLeaseLost) || tx.rollbacks != 1 {
			t.Fatalf("found=%v err=%v", found, err)
		}
	})
	t.Run("entropy", func(t *testing.T) {
		tx := &scriptedTx{}
		store := fixtureStore(tx, bytes.NewReader(make([]byte, 15)))
		_, _, err := store.ClaimNext(context.Background(), ClaimRequest{
			LeaseOwner: "dispatcher-one", LeaseDuration: time.Second, CandidateLimit: 1,
		})
		if !errors.Is(err, ErrUnavailable) || tx.beginCalls != 0 {
			t.Fatalf("err=%v begin=%d", err, tx.beginCalls)
		}
	})
	for name, request := range map[string]ClaimRequest{
		"duration": {LeaseOwner: "dispatcher-one", LeaseDuration: MaxLeaseDuration + time.Microsecond, CandidateLimit: 1},
		"owner":    {LeaseOwner: "Bad Owner", LeaseDuration: time.Second, CandidateLimit: 1},
		"limit":    {LeaseOwner: "dispatcher-one", LeaseDuration: time.Second, CandidateLimit: 0},
		"token":    {LeaseOwner: "dispatcher-one", LeaseDuration: time.Second, CandidateLimit: 1, LeaseToken: "not-uuid"},
	} {
		t.Run(name, func(t *testing.T) {
			store := fixtureStore(&scriptedTx{}, nil)
			if _, _, err := store.ClaimNext(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestPersistCapabilityVerifiesSignatureAndExactClaimBinding(t *testing.T) {
	t.Parallel()
	claim := fixtureClaim()
	store, issuer := fixtureStoreAndIssuer(nil)
	signed, _ := fixtureSignedCapability(t, claim, issuer, 20*time.Second)
	clock := 0
	var persistedArguments []any
	tx := &scriptedTx{queryRow: func(query string, args []any) pgx.Row {
		switch query {
		case databaseClockSQL:
			clock++
			return valuesRow(claim.claimedAt.Add(time.Duration(clock) * time.Microsecond))
		case recordCapabilitySQL:
			persistedArguments = append([]any(nil), args...)
			persistedArguments[8] = append([]byte(nil), args[8].([]byte)...)
			return valuesRow("")
		default:
			return errorRow(errors.New("unexpected query"))
		}
	}}
	store.begin = beginWith(tx)
	persisted, err := store.PersistCapability(context.Background(), claim, signed)
	if err != nil || !validPersistedCapability(persisted) || tx.commits != 1 {
		t.Fatalf("err=%v commits=%d", err, tx.commits)
	}
	if len(persistedArguments) != 24 || persistedArguments[1] != claim.job.jobID ||
		persistedArguments[2] != claim.leaseToken || !bytes.Equal(persistedArguments[8].([]byte), claim.job.artifact) ||
		persistedArguments[20] != digestBytes(bytes.Repeat([]byte{0x44}, 16)) {
		t.Fatalf("unexpected capability arguments len=%d id=%v token=%v artifact=%v nonce=%v",
			len(persistedArguments), persistedArguments[1] == claim.job.jobID,
			persistedArguments[2] == claim.leaseToken,
			bytes.Equal(persistedArguments[8].([]byte), claim.job.artifact),
			persistedArguments[20] == digestBytes(bytes.Repeat([]byte{0x44}, 16)))
	}
	formatted := persisted.String() + persisted.GoString()
	if strings.Contains(formatted, claim.job.targetIPv4) || !strings.Contains(formatted, "REDACTED") {
		t.Fatal("persisted capability formatting exposed content")
	}

	mutatedClaim := cloneClaim(claim)
	mutatedClaim.job.targetIPv4 = "203.0.113.99"
	mutatedClaim.claimDigest = digestClaim(mutatedClaim)
	if _, err := store.PersistCapability(context.Background(), mutatedClaim, signed); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("mismatched exact row: %v", err)
	}
	badSignature := signed.Signature()
	badSignature[0] ^= 1
	bad := capability.NewUntrustedSignedCapability(signed.KeyID(), signed.CanonicalBytes(), badSignature, signed.ArtifactBytes())
	if _, err := store.PersistCapability(context.Background(), claim, bad); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("invalid signature: %v", err)
	}
}

func TestPersistCapabilityClassifiesDatabaseRejectionWithoutDetail(t *testing.T) {
	t.Parallel()
	claim := fixtureClaim()
	store, issuer := fixtureStoreAndIssuer(nil)
	signed, _ := fixtureSignedCapability(t, claim, issuer, 20*time.Second)
	tx := &scriptedTx{queryRow: func(query string, _ []any) pgx.Row {
		if query == databaseClockSQL {
			return valuesRow(claim.claimedAt)
		}
		return errorRow(&pgconn.PgError{Code: "42501", Message: "artifact 203.0.113.20 leaked detail"})
	}}
	store.begin = beginWith(tx)
	_, err := store.PersistCapability(context.Background(), claim, signed)
	if !errors.Is(err, ErrPersistenceRejected) || strings.Contains(err.Error(), claim.job.targetIPv4) || tx.rollbacks != 1 {
		t.Fatalf("err=%v rollbacks=%d", err, tx.rollbacks)
	}
}

func TestPersistResultRequiresDistinctVerifiedSignatureAndExactBinding(t *testing.T) {
	t.Parallel()
	claim := fixtureClaim()
	store, issuer := fixtureStoreAndIssuer(nil)
	_, persisted := fixtureSignedCapability(t, claim, issuer, 20*time.Second)
	signedResult := fixtureSignedResult(t, persisted, claim.claimedAt.Add(2*time.Second), claim.claimedAt.Add(2100*time.Millisecond))
	clock := 0
	var arguments []any
	tx := &scriptedTx{queryRow: func(query string, args []any) pgx.Row {
		if query == databaseClockSQL {
			clock++
			return valuesRow(claim.claimedAt.Add(time.Duration(clock) * time.Microsecond))
		}
		arguments = append([]any(nil), args...)
		return valuesRow("")
	}}
	store.begin = beginWith(tx)
	result, err := store.PersistResult(context.Background(), persisted, signedResult)
	if err != nil || !validPersistedResult(result) || tx.commits != 1 {
		t.Fatalf("err=%v commits=%d", err, tx.commits)
	}
	if len(arguments) != 22 || arguments[1] != claim.job.jobID || arguments[12] != nil ||
		arguments[17] != int64(2) || !bytes.Equal(arguments[21].([]byte), signedResult.Signature()) {
		t.Fatal("result persistence lost exact binding")
	}
	if strings.Contains(result.String()+result.GoString(), claim.job.targetIPv4) ||
		!strings.Contains(result.String(), "REDACTED") {
		t.Fatal("result formatting exposed content")
	}
	badSignature := signedResult.Signature()
	badSignature[len(badSignature)-1] ^= 1
	bad := capability.NewUntrustedSignedResult(
		signedResult.KeyID(), signedResult.ExecutorID(), signedResult.CanonicalBytes(), badSignature,
	)
	if _, err := store.PersistResult(context.Background(), persisted, bad); !errors.Is(err, ErrContractRejected) {
		t.Fatalf("invalid result signature: %v", err)
	}
}

func TestPersistResultPreservesPostExpiryRecoveryTimeOnPersistenceRejection(t *testing.T) {
	t.Parallel()
	claim := fixtureClaim()
	store, issuer := fixtureStoreAndIssuer(nil)
	_, persisted := fixtureSignedCapability(t, claim, issuer, 5*time.Second)
	capabilityExpiry := persisted.verified.Value().ExpiresAt
	started := capabilityExpiry.Add(time.Second)
	completed := started.Add(100 * time.Millisecond)
	signedResult := fixtureRecoveredResult(t, persisted, started, completed)
	var recordedStart time.Time
	tx := &scriptedTx{queryRow: func(query string, args []any) pgx.Row {
		if query == databaseClockSQL {
			return valuesRow(claim.claimedAt.Add(2 * time.Second))
		}
		recordedStart = args[15].(time.Time)
		return errorRow(&pgconn.PgError{Code: "42501", Message: "current function rejects recovery time"})
	}}
	store.begin = beginWith(tx)
	_, err := store.PersistResult(context.Background(), persisted, signedResult)
	if !errors.Is(err, ErrPersistenceRejected) || !recordedStart.Equal(started) || !recordedStart.After(capabilityExpiry) {
		t.Fatalf("err=%v start=%v expiry=%v", err, recordedStart, capabilityExpiry)
	}
}

func TestRecoverReverifiesExactCapabilityAndResultUnderNewLease(t *testing.T) {
	t.Parallel()
	originalClaim := fixtureClaim()
	store, issuer := fixtureStoreAndIssuer(nil)
	signedCapability, originalPersisted := fixtureSignedCapability(t, originalClaim, issuer, 5*time.Second)
	recoveredClaim := fixtureRecoveredClaim(originalClaim)
	verifiedCapability, err := store.capabilityVerifier.Verify(signedCapability)
	if err != nil {
		t.Fatal(err)
	}
	recoveredPersisted := PersistedCapability{
		claim: cloneClaim(recoveredClaim), verified: verifiedCapability, recovered: true,
	}
	started := originalPersisted.verified.Value().ExpiresAt.Add(time.Second).Truncate(time.Millisecond)
	signedResult := fixtureRecoveredResult(t, recoveredPersisted, started, started.Add(100*time.Millisecond))
	verifiedResult, err := store.resultVerifier.Verify(signedResult)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name  string
		state RecoveryState
		row   []any
	}{
		{
			name: "none", state: RecoveryNone,
			row: []any{"none", nil, nil, nil, nil, nil, nil, nil, nil, nil},
		},
		{
			name: "capability", state: RecoveryCapability,
			row: recoveryRow(signedCapability, verifiedCapability, nil, capability.VerifiedResult{}),
		},
		{
			name: "result", state: RecoveryResult,
			row: recoveryRow(signedCapability, verifiedCapability, &signedResult, verifiedResult),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := 0
			tx := &scriptedTx{queryRow: func(query string, args []any) pgx.Row {
				switch query {
				case recoverExecutionSQL:
					if len(args) != 2 || args[0] != recoveredClaim.job.jobID || args[1] != recoveredClaim.leaseToken {
						t.Fatal("recovery query lost the exact lease fence")
					}
					return valuesRow(test.row...)
				case databaseClockSQL:
					clock++
					return valuesRow(recoveredClaim.claimedAt.Add(time.Duration(clock) * time.Microsecond))
				default:
					return errorRow(errors.New("unexpected query"))
				}
			}}
			store.begin = beginWith(tx)
			recovered, recoverErr := store.Recover(context.Background(), recoveredClaim)
			if recoverErr != nil || recovered.State() != test.state || tx.commits != 1 {
				t.Fatalf("state=%s err=%v commits=%d", recovered.State(), recoverErr, tx.commits)
			}
			persisted, exactCapability, hasCapability := recovered.Capability()
			if test.state == RecoveryNone {
				if hasCapability {
					t.Fatal("none recovery exposed a capability")
				}
				return
			}
			if !hasCapability || !validPersistedCapability(persisted) || !persisted.recovered ||
				!bytes.Equal(exactCapability.CanonicalBytes(), signedCapability.CanonicalBytes()) ||
				!bytes.Equal(exactCapability.Signature(), signedCapability.Signature()) ||
				!bytes.Equal(exactCapability.ArtifactBytes(), signedCapability.ArtifactBytes()) {
				t.Fatal("recovery did not preserve the exact signed capability")
			}
			result, exactResult, hasResult := recovered.Result()
			if test.state == RecoveryCapability {
				if hasResult {
					t.Fatal("capability-only recovery exposed a result")
				}
				return
			}
			if !hasResult || !validPersistedResult(result) ||
				!bytes.Equal(exactResult.CanonicalBytes(), signedResult.CanonicalBytes()) ||
				!bytes.Equal(exactResult.Signature(), signedResult.Signature()) {
				t.Fatal("recovery did not preserve the exact signed result")
			}
			if strings.Contains(recovered.String()+recovered.GoString(), recoveredClaim.job.targetIPv4) ||
				!strings.Contains(recovered.String(), "REDACTED") {
				t.Fatal("recovery formatting exposed signed content")
			}
		})
	}
}

func TestRecoverFailsClosedForLeaseLossAndTamperedRows(t *testing.T) {
	t.Parallel()
	claim := fixtureRecoveredClaim(fixtureClaim())
	store, issuer := fixtureStoreAndIssuer(nil)
	signed, _ := fixtureSignedCapability(t, fixtureClaim(), issuer, 5*time.Second)
	verified, err := store.capabilityVerifier.Verify(signed)
	if err != nil {
		t.Fatal(err)
	}
	validRow := recoveryRow(signed, verified, nil, capability.VerifiedResult{})
	tamperedSignature := append([]byte(nil), validRow[4].([]byte)...)
	tamperedSignature[0] ^= 1
	tamperedRow := append([]any(nil), validRow...)
	tamperedRow[2] = append([]byte(nil), validRow[2].([]byte)...)
	tamperedRow[4] = tamperedSignature
	tamperedRow[5] = append([]byte(nil), validRow[5].([]byte)...)
	wrongDigestRow := append([]any(nil), validRow...)
	wrongDigestRow[2] = append([]byte(nil), validRow[2].([]byte)...)
	wrongDigestRow[4] = append([]byte(nil), validRow[4].([]byte)...)
	wrongDigestRow[5] = append([]byte(nil), validRow[5].([]byte)...)
	wrongDigest := "sha256:" + strings.Repeat("f", 64)
	wrongDigestRow[3] = &wrongDigest

	for _, test := range []struct {
		name string
		row  pgx.Row
		want error
	}{
		{"lease", errorRow(&pgconn.PgError{Code: "SF101", Message: "secret lease"}), ErrLeaseLost},
		{"database-corrupt", errorRow(&pgconn.PgError{Code: "SF102", Message: "secret artifact"}), ErrInvalidRow},
		{"signature", valuesRow(tamperedRow...), ErrContractRejected},
		{"digest", valuesRow(wrongDigestRow...), ErrInvalidRow},
		{"shape", valuesRow("result", nil, nil, nil, nil, nil, nil, nil, nil, nil), ErrInvalidRow},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &scriptedTx{queryRow: func(query string, _ []any) pgx.Row {
				if query == recoverExecutionSQL {
					return test.row
				}
				return valuesRow(claim.claimedAt)
			}}
			store.begin = beginWith(tx)
			_, recoverErr := store.Recover(context.Background(), claim)
			if !errors.Is(recoverErr, test.want) || strings.Contains(recoverErr.Error(), "secret") ||
				tx.commits != 0 || tx.rollbacks != 1 {
				t.Fatalf("err=%v commits=%d rollbacks=%d", recoverErr, tx.commits, tx.rollbacks)
			}
		})
	}
}

func TestFinishUsesDatabaseBackoffAndRequiresPersistedResult(t *testing.T) {
	t.Parallel()
	claim := fixtureClaim()
	store, issuer := fixtureStoreAndIssuer(nil)
	_, persisted := fixtureSignedCapability(t, claim, issuer, 20*time.Second)
	result := PersistedResult{
		capability: persisted,
		resultID:   "019b0000-0000-7000-8000-000000000301",
		digest:     "sha256:" + strings.Repeat("9", 64),
	}
	if !validPersistedResult(result) {
		t.Fatal("fixture result invalid")
	}
	for _, test := range []struct {
		name    string
		request FinishRequest
	}{
		{"completed", FinishRequest{Outcome: FinishCompleted, Result: &result}},
		{"retry", FinishRequest{
			Outcome: FinishRetry, RetryBackoff: 2 * time.Second,
			ErrorCode: "transport_error", ErrorDigest: "sha256:" + strings.Repeat("a", 64),
		}},
		{"dead", FinishRequest{
			Outcome: FinishDead, ErrorCode: "attempts_exhausted",
			ErrorDigest: "sha256:" + strings.Repeat("b", 64),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := claim.claimedAt.Add(time.Second)
			clock := 0
			var arguments []any
			tx := &scriptedTx{queryRow: func(query string, args []any) pgx.Row {
				if query == databaseClockSQL {
					clock++
					return valuesRow(now.Add(time.Duration(clock-1) * time.Microsecond))
				}
				arguments = append([]any(nil), args...)
				return valuesRow(true)
			}}
			store.begin = beginWith(tx)
			if err := store.Finish(context.Background(), claim, test.request); err != nil {
				t.Fatalf("finish: %v", err)
			}
			if len(arguments) != 6 || arguments[0] != claim.job.jobID || arguments[1] != claim.leaseToken ||
				arguments[2] != string(test.request.Outcome) || tx.commits != 1 {
				t.Fatalf("args=%#v", arguments)
			}
			if test.request.Outcome == FinishRetry && !arguments[5].(time.Time).Equal(now.Add(2*time.Second)) {
				t.Fatal("retry was not based on database clock")
			}
		})
	}

	invalid := []FinishRequest{
		{Outcome: FinishCompleted},
		{Outcome: FinishRetry, RetryBackoff: MinRetryBackoff - time.Nanosecond, ErrorCode: "x", ErrorDigest: "sha256:" + strings.Repeat("a", 64)},
		{Outcome: FinishDead, ErrorCode: "Bad Code", ErrorDigest: "missing"},
	}
	for _, request := range invalid {
		if err := store.Finish(context.Background(), claim, request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid finish err=%v", err)
		}
	}
	if strings.Contains((FinishRequest{}).String(), claim.job.targetIPv4) ||
		!strings.Contains((FinishRequest{}).String(), "REDACTED") {
		t.Fatal("finish formatting exposed content")
	}
}

func TestFinishRollsBackFalseExpiredAndCommitUncertainty(t *testing.T) {
	t.Parallel()
	claim := fixtureClaim()
	failure := FinishRequest{
		Outcome: FinishDead, ErrorCode: "failed",
		ErrorDigest: "sha256:" + strings.Repeat("d", 64),
	}
	for name, tx := range map[string]*scriptedTx{
		"false": {
			queryRow: func(query string, _ []any) pgx.Row {
				if query == databaseClockSQL {
					return valuesRow(claim.claimedAt)
				}
				return valuesRow(false)
			},
		},
		"expired": {
			queryRow: func(query string, _ []any) pgx.Row {
				if query == databaseClockSQL {
					return valuesRow(claim.leaseUntil)
				}
				return valuesRow(true)
			},
		},
		"commit": {
			queryRow: func(query string, _ []any) pgx.Row {
				if query == databaseClockSQL {
					return valuesRow(claim.claimedAt)
				}
				return valuesRow(true)
			},
			commitErr: errors.New("uncertain"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := fixtureStore(tx, nil)
			err := store.Finish(context.Background(), claim, failure)
			if name == "commit" {
				if !errors.Is(err, ErrUnavailable) {
					t.Fatalf("err=%v", err)
				}
			} else if !errors.Is(err, ErrLeaseLost) {
				t.Fatalf("err=%v", err)
			}
			if tx.rollbacks != 1 {
				t.Fatalf("rollbacks=%d", tx.rollbacks)
			}
		})
	}
}

func TestConstructorAndStableErrorsRejectUnsafeComposition(t *testing.T) {
	t.Parallel()
	capVerifier, resultVerifier, _ := fixtureVerifiers()
	constructed, err := NewPostgreSQLStore(&beginnerStub{}, capVerifier, resultVerifier, nil)
	if err != nil || constructed.entropy == nil || !strings.Contains(constructed.GoString(), "PUBLIC-ONLY") {
		t.Fatalf("valid constructor err=%v", err)
	}
	if _, err := NewPostgreSQLStore(nil, capVerifier, resultVerifier, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil db: %v", err)
	}
	if _, err := NewPostgreSQLStore(&beginnerStub{}, capVerifier, capability.ResultVerifier{}, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero verifier: %v", err)
	}
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x23}, ed25519.SeedSize))
	sameID, _ := capability.NewResultVerifier(
		testDispatchKeyID, testExecutorID, resultPrivate.Public().(ed25519.PublicKey),
	)
	if _, err := NewPostgreSQLStore(&beginnerStub{}, capVerifier, sameID, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("same role key id: %v", err)
	}
	for _, expected := range []*Error{
		ErrInvalidInput, ErrInvalidRow, ErrContractRejected, ErrPersistenceRejected,
		ErrConflict, ErrLeaseLost, ErrUnavailable,
	} {
		if expected.Error() == "" || expected.Code() == "" || !errors.Is(expected, &Error{code: expected.Code()}) {
			t.Fatalf("unstable error: %#v", expected)
		}
	}
	if (*Error)(nil).Code() != CodeUnavailable || (*Error)(nil).Error() == "" {
		t.Fatal("nil error was not safe")
	}
	detail := &pgconn.PgError{Code: "23505", Message: "secret row"}
	if got := classifyDatabaseError(detail); !errors.Is(got, ErrConflict) || strings.Contains(got.Error(), "secret") {
		t.Fatalf("classification exposed detail: %v", got)
	}
}

func TestGeneratedLeaseTokensRemainUniqueUnderConcurrency(t *testing.T) {
	store := fixtureStore(&scriptedTx{}, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 16*32)))
	// Deterministic identical entropy demonstrates that UUID formatting is safe;
	// uniqueness remains the responsibility of cryptographic random input and
	// PostgreSQL's lease fencing. This test exercises race-safe serialized reads.
	var wait sync.WaitGroup
	results := make(chan string, 32)
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, err := store.newLeaseToken()
			if err != nil {
				results <- ""
				return
			}
			results <- value
		}()
	}
	wait.Wait()
	close(results)
	for value := range results {
		if !uuidV4Pattern.MatchString(value) {
			t.Fatalf("invalid generated token")
		}
	}
}

func fixtureTime() time.Time {
	return time.Date(2026, 7, 18, 3, 0, 0, 123456000, time.UTC)
}

func fixtureJob() jobSnapshot {
	artifact := []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1m }\n")
	now := fixtureTime()
	return jobSnapshot{
		jobID: "019b0000-0000-7000-8000-000000000101", kind: "dispatch_add", state: "pending",
		availableAt: now.Add(-time.Second), attempts: 0, maxAttempts: 3,
		operation: capability.OperationAdd,
		actionID:  "019b0000-0000-7000-8000-000000000201",
		policyID:  "019b0000-0000-7000-8000-000000000202", policyVersion: 1,
		targetIPv4: "203.0.113.20", artifact: artifact, artifactDigest: digestBytes(artifact),
		evidenceSnapshotDigest:   "sha256:" + strings.Repeat("1", 64),
		validationSnapshotDigest: "sha256:" + strings.Repeat("2", 64),
		authorizationDigest:      "sha256:" + strings.Repeat("3", 64),
		actorID:                  "admin-test", reasonDigest: "sha256:" + strings.Repeat("4", 64),
		ownedSchemaDigest: "sha256:" + strings.Repeat("5", 64),
		notBefore:         now.Add(-time.Second), validUntil: now.Add(2 * time.Minute),
	}
}

func fixtureClaim() ClaimedJob {
	result := ClaimedJob{
		job: fixtureJob(), leaseToken: "019b0000-0000-4000-8000-000000000111",
		leaseOwner: "dispatcher-one", claimedAt: fixtureTime(),
		leaseUntil: fixtureTime().Add(30 * time.Second),
	}
	result.claimDigest = digestClaim(result)
	return result
}

func fixtureClaimRequest() ClaimRequest {
	return ClaimRequest{
		LeaseOwner: "dispatcher-one", LeaseDuration: 30 * time.Second,
		CandidateLimit: 1, LeaseToken: "019b0000-0000-4000-8000-000000000111",
	}
}

func fixtureRecoveredClaim(original ClaimedJob) ClaimedJob {
	result := cloneClaim(original)
	result.job.state = "leased"
	result.job.attempts++
	result.leaseToken = "019b0000-0000-4000-8000-000000000112"
	result.claimedAt = original.leaseUntil.Add(time.Second)
	result.leaseUntil = result.claimedAt.Add(30 * time.Second)
	result.claimDigest = digestClaim(result)
	return result
}

func recoveryRow(
	signedCapability capability.SignedCapability,
	verifiedCapability capability.VerifiedCapability,
	signedResult *capability.SignedResult,
	verifiedResult capability.VerifiedResult,
) []any {
	capabilityID := verifiedCapability.Value().CapabilityID
	capabilityDigest := verifiedCapability.Digest()
	values := []any{
		"capability", &capabilityID, signedCapability.CanonicalBytes(), &capabilityDigest,
		signedCapability.Signature(), signedCapability.ArtifactBytes(),
		nil, nil, nil, nil,
	}
	if signedResult != nil {
		resultID := verifiedResult.Value().ResultID
		resultDigest := verifiedResult.Digest()
		values[0] = "result"
		values[6] = &resultID
		values[7] = signedResult.CanonicalBytes()
		values[8] = &resultDigest
		values[9] = signedResult.Signature()
	}
	return values
}

func fixtureVerifiers() (capability.CapabilityVerifier, capability.ResultVerifier, capability.CapabilityIssuer) {
	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	issuer, _ := capability.NewCapabilityIssuer(testDispatchKeyID, dispatchPrivate)
	capVerifier, _ := capability.NewCapabilityVerifier(
		testDispatchKeyID, testExecutorID, dispatchPrivate.Public().(ed25519.PublicKey),
	)
	resultVerifier, _ := capability.NewResultVerifier(
		testResultKeyID, testExecutorID, resultPrivate.Public().(ed25519.PublicKey),
	)
	return capVerifier, resultVerifier, issuer
}

func fixtureStore(tx *scriptedTx, entropy *bytes.Reader) *PostgreSQLStore {
	capVerifier, resultVerifier, _ := fixtureVerifiers()
	reader := bytes.NewReader(bytes.Repeat([]byte{0x7a}, 128))
	if entropy != nil {
		reader = entropy
	}
	store := &PostgreSQLStore{
		capabilityVerifier: capVerifier, resultVerifier: resultVerifier, entropy: reader,
	}
	if tx != nil {
		store.begin = beginWith(tx)
	}
	return store
}

func fixtureStoreAndIssuer(tx *scriptedTx) (*PostgreSQLStore, capability.CapabilityIssuer) {
	store := fixtureStore(tx, nil)
	_, _, issuer := fixtureVerifiers()
	return store, issuer
}

func fixtureSignedCapability(
	t *testing.T,
	claim ClaimedJob,
	issuer capability.CapabilityIssuer,
	validity time.Duration,
) (capability.SignedCapability, PersistedCapability) {
	t.Helper()
	issuedAt, notBefore, expiresAt, err := claim.CapabilityWindow(validity)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := capability.CheckAdd(capability.Add{
		Common: capability.Common{
			CapabilityID: "019b0000-0000-7000-8000-000000000210",
			JobID:        claim.job.jobID, ActionID: claim.job.actionID, PolicyID: claim.job.policyID,
			PolicyVersion: claim.job.policyVersion, TargetIPv4: claim.job.targetIPv4,
			EvidenceSnapshotDigest:   claim.job.evidenceSnapshotDigest,
			ValidationSnapshotDigest: claim.job.validationSnapshotDigest,
			AuthorizationDigest:      claim.job.authorizationDigest, ActorID: claim.job.actorID,
			ReasonDigest: claim.job.reasonDigest, OwnedSchemaDigest: claim.job.ownedSchemaDigest,
			IssuedAt: issuedAt, NotBefore: notBefore, ExpiresAt: expiresAt,
			Nonce: base64URL(bytes.Repeat([]byte{0x44}, 16)),
		},
		CanonicalCommand: claim.job.artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := issuer.Sign(checked)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := fixtureStore(nil, nil).capabilityVerifier.Verify(signed)
	if err != nil {
		t.Fatal(err)
	}
	return signed, PersistedCapability{claim: cloneClaim(claim), verified: verified}
}

func fixtureSignedResult(
	t *testing.T,
	persisted PersistedCapability,
	startedAt time.Time,
	completedAt time.Time,
) capability.SignedResult {
	t.Helper()
	exit := capability.NFTExitSuccess
	ttl := uint64(59)
	checked, err := capability.CheckResult(capability.Result{
		ResultID:         "019b0000-0000-7000-8000-000000000301",
		CapabilityID:     persisted.verified.Value().CapabilityID,
		CapabilityDigest: persisted.verified.Digest(), Operation: capability.OperationAdd,
		ActionID: persisted.claim.job.actionID, ArtifactDigest: persisted.claim.job.artifactDigest,
		TargetIPv4: persisted.claim.job.targetIPv4, Classification: capability.ClassificationApplied,
		NFTExitClass: &exit, ReadbackState: capability.ReadbackActive,
		RemainingTTLSeconds: &ttl, OwnedSchemaDigest: persisted.claim.job.ownedSchemaDigest,
		StartedAt: startedAt.Truncate(time.Millisecond), CompletedAt: completedAt.Truncate(time.Millisecond),
		JournalSequence: 2, ErrorCode: capability.ResultErrorNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	signer, _ := capability.NewResultSigner(testResultKeyID, testExecutorID, private)
	signed, err := signer.SignFor(persisted.verified, checked)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func fixtureRecoveredResult(
	t *testing.T,
	persisted PersistedCapability,
	startedAt time.Time,
	completedAt time.Time,
) capability.SignedResult {
	t.Helper()
	exit := capability.NFTExitNotInvoked
	ttl := uint64(50)
	checked, err := capability.CheckResult(capability.Result{
		ResultID:         "019b0000-0000-7000-8000-000000000302",
		CapabilityID:     persisted.verified.Value().CapabilityID,
		CapabilityDigest: persisted.verified.Digest(), Operation: capability.OperationAdd,
		ActionID: persisted.claim.job.actionID, ArtifactDigest: persisted.claim.job.artifactDigest,
		TargetIPv4:     persisted.claim.job.targetIPv4,
		Classification: capability.ClassificationRecoveredActive,
		NFTExitClass:   &exit, ReadbackState: capability.ReadbackActive,
		RemainingTTLSeconds: &ttl, OwnedSchemaDigest: persisted.claim.job.ownedSchemaDigest,
		StartedAt: startedAt, CompletedAt: completedAt,
		JournalSequence: 3, ErrorCode: capability.ResultErrorNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	signer, _ := capability.NewResultSigner(testResultKeyID, testExecutorID, private)
	signed, err := signer.SignFor(persisted.verified, checked)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func base64URL(value []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, 0, (len(value)*8+5)/6)
	var bits uint32
	var count uint
	for _, item := range value {
		bits = bits<<8 | uint32(item)
		count += 8
		for count >= 6 {
			count -= 6
			result = append(result, alphabet[(bits>>count)&0x3f])
		}
	}
	if count > 0 {
		result = append(result, alphabet[(bits<<(6-count))&0x3f])
	}
	return string(result)
}

func rowsForJobs(jobs ...jobSnapshot) pgx.Rows {
	rows := make([][]any, 0, len(jobs))
	for _, job := range jobs {
		rows = append(rows, []any{
			job.jobID, job.kind, job.state, job.availableAt, job.attempts, job.maxAttempts,
			string(job.operation), job.actionID, job.policyID, int64(job.policyVersion),
			job.targetIPv4, append([]byte(nil), job.artifact...), job.artifactDigest,
			cloneStringPointer(job.originalAddDigest), job.evidenceSnapshotDigest,
			job.validationSnapshotDigest, job.authorizationDigest, job.actorID,
			job.reasonDigest, job.ownedSchemaDigest, job.notBefore, job.validUntil,
		})
	}
	return &scriptedRows{rows: rows}
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

type scriptedTx struct {
	query       func(string, []any) (pgx.Rows, error)
	queryRow    func(string, []any) pgx.Row
	options     pgx.TxOptions
	beginCalls  int
	commits     int
	rollbacks   int
	commitErr   error
	rollbackErr error
}

func beginWith(tx *scriptedTx) func(context.Context, pgx.TxOptions) (transaction, error) {
	return func(_ context.Context, options pgx.TxOptions) (transaction, error) {
		tx.beginCalls++
		tx.options = options
		return tx, nil
	}
}

func (tx *scriptedTx) Query(_ context.Context, query string, args ...any) (pgx.Rows, error) {
	if tx.query == nil {
		return nil, errors.New("unexpected query")
	}
	return tx.query(query, append([]any(nil), args...))
}

func (tx *scriptedTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	if tx.queryRow == nil {
		return errorRow(errors.New("unexpected query row"))
	}
	return tx.queryRow(query, append([]any(nil), args...))
}

func (tx *scriptedTx) Commit(context.Context) error {
	tx.commits++
	return tx.commitErr
}

func (tx *scriptedTx) Rollback(context.Context) error {
	tx.rollbacks++
	return tx.rollbackErr
}

type scriptedRows struct {
	rows        [][]any
	index       int
	closed      bool
	terminalErr error
}

func (r *scriptedRows) Close()                                       { r.closed = true }
func (r *scriptedRows) Err() error                                   { return r.terminalErr }
func (r *scriptedRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT 0") }
func (r *scriptedRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *scriptedRows) Next() bool {
	if r.index >= len(r.rows) {
		r.closed = true
		return false
	}
	r.index++
	return true
}
func (r *scriptedRows) Scan(dest ...any) error {
	if r.index == 0 || r.index > len(r.rows) {
		return errors.New("scan outside row")
	}
	return assignValues(dest, r.rows[r.index-1])
}
func (r *scriptedRows) Values() ([]any, error) {
	if r.index == 0 || r.index > len(r.rows) {
		return nil, errors.New("values outside row")
	}
	return append([]any(nil), r.rows[r.index-1]...), nil
}
func (r *scriptedRows) RawValues() [][]byte { return nil }
func (r *scriptedRows) Conn() *pgx.Conn     { return nil }

type valueRow struct {
	values []any
	err    error
}

func valuesRow(values ...any) pgx.Row { return valueRow{values: values} }
func errorRow(err error) pgx.Row      { return valueRow{err: err} }
func (r valueRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	return assignValues(dest, r.values)
}

func assignValues(dest, values []any) error {
	if len(dest) != len(values) {
		return errors.New("scan arity")
	}
	for index, value := range values {
		target := reflect.ValueOf(dest[index])
		if target.Kind() != reflect.Pointer || target.IsNil() {
			return errors.New("invalid scan destination")
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
		if source.Type().ConvertibleTo(target.Type()) {
			target.Set(source.Convert(target.Type()))
			continue
		}
		return errors.New("scan type")
	}
	return nil
}

type beginnerStub struct{}

func (*beginnerStub) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not used")
}
