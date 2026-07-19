package lifecycleruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/lifecycleartifact"
)

const (
	testActionID        = "019b0000-0000-7000-8000-000000000200"
	testPolicyID        = "019b0000-0000-7000-8000-000000000201"
	testAuthorizationID = "019b0000-0000-4000-8000-000000000202"
	testTarget          = "203.0.113.20"
	testAddDigest       = "sha256:866cc23464d760a1de172d66ccd076c6a7915c6011a75d47dc93224bbe5539e6"
	testAddAuthDigest   = "sha256:03f97cab15bf5a71ea86a486e46e9d5198aa72566bdff5bc1ff495abd544ae94"
	testEvidenceDigest  = "sha256:ea1271f46a383bd32b27e66c5d1b06fda9a5c4cf2fe7dbe81a02c1ba15af3acc"
	testValidDigest     = "sha256:eac360a5f975cd8730522b3b5846b14899dfdbfa0e7e607fab7eb3b8983c07f8"
	testOwnedDigest     = "sha256:d5582a75817d349b12f292d212483bb0c2a5db66afde7d73c6d11050a5eb5997"
)

var testRequestedAt = time.Date(2026, 7, 18, 2, 20, 0, 0, time.UTC)

func validClaimInput() ClaimInput {
	return ClaimInput{
		ScheduleIdentity: "schedule-001", LeaseIdentity: "lease-001",
		AuthorizationID: testAuthorizationID,
		ActionID:        testActionID, ActionVersion: 7,
		PolicyID: testPolicyID, PolicyVersion: 3, TargetIPv4: testTarget,
		OriginalAddDigest: testAddDigest, OriginalAuthorizationDigest: testAddAuthDigest,
		EvidenceSnapshotDigest: testEvidenceDigest, ValidationSnapshotDigest: testValidDigest,
		OwnedSchemaDigest: testOwnedDigest, Purpose: lifecycleartifact.PurposeReconciliation,
		RequestedAt: testRequestedAt, ValidUntil: testRequestedAt.Add(time.Minute),
	}
}

type fakeStore struct {
	mu sync.Mutex

	claims             []Claim
	claimErr           error
	commitErr          error
	finishErr          error
	invalidDisposition bool

	commitRequests           []PreparedInspection
	commitClaims             []Claim
	failures                 []Failure
	failureClaims            []Claim
	failureContextsCancelled []bool
	createdByIdempotency     map[string]PreparedInspection
}

func (s *fakeStore) ClaimDue(ctx context.Context) (Claim, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimErr != nil {
		return Claim{}, false, s.claimErr
	}
	if len(s.claims) == 0 {
		return Claim{}, false, nil
	}
	claim := s.claims[0]
	s.claims = s.claims[1:]
	return claim, true, nil
}

func (s *fakeStore) CommitInspection(_ context.Context, claim Claim, prepared PreparedInspection) (CommitDisposition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitClaims = append(s.commitClaims, claim)
	s.commitRequests = append(s.commitRequests, prepared)
	if s.commitErr != nil {
		return "", s.commitErr
	}
	if s.invalidDisposition {
		return "unexpected", nil
	}
	if s.createdByIdempotency == nil {
		s.createdByIdempotency = make(map[string]PreparedInspection)
	}
	key := prepared.Authorization().Value().IdempotencyKeyDigest
	if existing, exists := s.createdByIdempotency[key]; exists {
		if existing.Authorization().Digest() != prepared.Authorization().Digest() ||
			existing.Inspect().Digest() != prepared.Inspect().Digest() ||
			!bytes.Equal(existing.Authorization().CanonicalBytes(), prepared.Authorization().CanonicalBytes()) ||
			!bytes.Equal(existing.Inspect().CanonicalBytes(), prepared.Inspect().CanonicalBytes()) {
			return "", errors.New("changed replay binding")
		}
		return CommitReplayed, nil
	}
	s.createdByIdempotency[key] = prepared
	return CommitCreated, nil
}

func (s *fakeStore) FinishFailure(ctx context.Context, claim Claim, failure Failure) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failureClaims = append(s.failureClaims, claim)
	s.failures = append(s.failures, failure)
	s.failureContextsCancelled = append(s.failureContextsCancelled, ctx.Err() != nil)
	return s.finishErr
}

func (s *fakeStore) snapshot() (commits []PreparedInspection, failures []Failure, effects int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PreparedInspection(nil), s.commitRequests...),
		append([]Failure(nil), s.failures...), len(s.createdByIdempotency)
}

type blockingClock struct {
	mu      sync.Mutex
	sleeps  []time.Duration
	started chan struct{}
	once    sync.Once
}

func (c *blockingClock) Sleep(ctx context.Context, duration time.Duration) error {
	c.mu.Lock()
	c.sleeps = append(c.sleeps, duration)
	c.mu.Unlock()
	c.once.Do(func() { close(c.started) })
	<-ctx.Done()
	return ctx.Err()
}

func newTestRuntime(t testing.TB, store Store) *Runtime {
	t.Helper()
	runtime, err := New(store, DefaultConfig("reconciler"), Dependencies{})
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	return runtime
}

func TestProcessNextCommitsExactCheckedArtifacts(t *testing.T) {
	claim := NewClaim(validClaimInput())
	store := &fakeStore{claims: []Claim{claim}}
	runtime := newTestRuntime(t, store)

	result, err := runtime.ProcessNext(context.Background())
	if err != nil || result.Outcome() != OutcomeCommitted || result.FailureCode() != "" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	commits, failures, effects := store.snapshot()
	if len(commits) != 1 || len(failures) != 0 || effects != 1 {
		t.Fatalf("commits=%d failures=%d effects=%d", len(commits), len(failures), effects)
	}
	prepared := commits[0]
	inspect := prepared.Inspect()
	inspectValue := inspect.Value()
	if inspectValue.ActionID != testActionID || inspectValue.TargetIPv4 != testTarget ||
		inspectValue.OriginalAddDigest != testAddDigest || inspectValue.OwnedSchemaDigest != testOwnedDigest ||
		inspectValue.Purpose != lifecycleartifact.PurposeReconciliation || inspectValue.Operation != "inspect" {
		t.Fatalf("inspect drift: %+v", inspectValue)
	}
	authorization := prepared.Authorization()
	value := authorization.Value()
	if value.ActionID != inspectValue.ActionID || value.TargetIPv4 != inspectValue.TargetIPv4 ||
		value.OriginalAddDigest != inspectValue.OriginalAddDigest || value.OwnedSchemaDigest != inspectValue.OwnedSchemaDigest ||
		value.Purpose != inspectValue.Purpose || value.ArtifactDigest != inspect.Digest() ||
		value.PolicyID != testPolicyID || value.PolicyVersion != 3 ||
		value.OriginalAuthorizationDigest != testAddAuthDigest || value.EvidenceSnapshotDigest != testEvidenceDigest ||
		value.ValidationSnapshotDigest != testValidDigest || value.SchedulerID != "reconciler" ||
		!value.RequestedAt.Equal(testRequestedAt) || !value.ValidUntil.Equal(testRequestedAt.Add(time.Minute)) {
		t.Fatalf("authorization drift: %+v", value)
	}
	if value.IdempotencyKeyDigest != digest(idempotencyDigestDomain+"schedule-001\n") {
		t.Fatalf("idempotency digest=%s", value.IdempotencyKeyDigest)
	}
	if value.AuthorizationID != testAuthorizationID {
		t.Fatalf("authorization identity drift: %s", value.AuthorizationID)
	}
	if prepared.Authorization().InspectArtifact().Digest() != inspect.Digest() {
		t.Fatal("authorization is not bound to checked inspect")
	}
	schedule, lease := store.commitClaims[0].StoreIdentity()
	if schedule != "schedule-001" || lease != "lease-001" || store.commitClaims[0].ActionVersion() != 7 {
		t.Fatalf("claim fence drift: %s %s %d", schedule, lease, store.commitClaims[0].ActionVersion())
	}
}

func TestReplayUsesStableScheduleIdempotencyAcrossLeases(t *testing.T) {
	firstInput := validClaimInput()
	secondInput := validClaimInput()
	secondInput.LeaseIdentity = "lease-002"
	store := &fakeStore{claims: []Claim{NewClaim(firstInput), NewClaim(secondInput)}}
	runtime := newTestRuntime(t, store)

	first, firstErr := runtime.ProcessNext(context.Background())
	second, secondErr := runtime.ProcessNext(context.Background())
	if firstErr != nil || secondErr != nil || first.Outcome() != OutcomeCommitted || second.Outcome() != OutcomeReplayed {
		t.Fatalf("first=%#v/%v second=%#v/%v", first, firstErr, second, secondErr)
	}
	commits, failures, effects := store.snapshot()
	if len(commits) != 2 || len(failures) != 0 || effects != 1 {
		t.Fatalf("commits=%d failures=%d effects=%d", len(commits), len(failures), effects)
	}
	firstAuth := commits[0].Authorization().Value()
	secondAuth := commits[1].Authorization().Value()
	if firstAuth.AuthorizationID != secondAuth.AuthorizationID ||
		firstAuth.IdempotencyKeyDigest != secondAuth.IdempotencyKeyDigest ||
		!bytes.Equal(commits[0].Authorization().CanonicalBytes(), commits[1].Authorization().CanonicalBytes()) ||
		commits[0].Authorization().Digest() != commits[1].Authorization().Digest() {
		t.Fatalf("replay identity drift: first=%+v second=%+v", firstAuth, secondAuth)
	}

	other := validClaimInput()
	other.ScheduleIdentity = "schedule-002"
	if idempotencyDigest(NewClaim(other)) == idempotencyDigest(NewClaim(firstInput)) {
		t.Fatal("different schedule identities shared idempotency digest")
	}
}

func TestMalformedProjectionFinishesTypedPreMutationFailure(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ClaimInput)
	}{
		{"schedule identity", func(v *ClaimInput) { v.ScheduleIdentity = "bad schedule" }},
		{"lease identity", func(v *ClaimInput) { v.LeaseIdentity = "" }},
		{"authorization id", func(v *ClaimInput) { v.AuthorizationID = "bad" }},
		{"action id", func(v *ClaimInput) { v.ActionID = "bad" }},
		{"action version zero", func(v *ClaimInput) { v.ActionVersion = 0 }},
		{"action version large", func(v *ClaimInput) { v.ActionVersion = 1 << 31 }},
		{"policy id", func(v *ClaimInput) { v.PolicyID = "bad" }},
		{"policy version zero", func(v *ClaimInput) { v.PolicyVersion = 0 }},
		{"policy version large", func(v *ClaimInput) { v.PolicyVersion = 1 << 31 }},
		{"target", func(v *ClaimInput) { v.TargetIPv4 = "203.0.113.020" }},
		{"add digest", func(v *ClaimInput) { v.OriginalAddDigest = "bad" }},
		{"add authorization", func(v *ClaimInput) { v.OriginalAuthorizationDigest = "bad" }},
		{"evidence", func(v *ClaimInput) { v.EvidenceSnapshotDigest = "bad" }},
		{"validation", func(v *ClaimInput) { v.ValidationSnapshotDigest = "bad" }},
		{"schema", func(v *ClaimInput) { v.OwnedSchemaDigest = "bad" }},
		{"purpose", func(v *ClaimInput) { v.Purpose = "add" }},
		{"requested zero", func(v *ClaimInput) { v.RequestedAt = time.Time{} }},
		{"valid equal", func(v *ClaimInput) { v.ValidUntil = v.RequestedAt }},
		{"valid reversed", func(v *ClaimInput) { v.ValidUntil = v.RequestedAt.Add(-time.Nanosecond) }},
		{"valid too long", func(v *ClaimInput) { v.ValidUntil = v.RequestedAt.Add(5*time.Minute + time.Nanosecond) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validClaimInput()
			test.edit(&input)
			store := &fakeStore{claims: []Claim{NewClaim(input)}}
			runtime := newTestRuntime(t, store)
			result, err := runtime.ProcessNext(context.Background())
			if !errors.Is(err, ErrProjectionInvalid) || result.Outcome() != OutcomeFailed ||
				result.FailureCode() != FailureProjectionInvalid {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			commits, failures, effects := store.snapshot()
			if len(commits) != 0 || effects != 0 || len(failures) != 1 {
				t.Fatalf("commits=%d effects=%d failures=%d", len(commits), effects, len(failures))
			}
			wantFailure := checkedFailure(FailureProjectionInvalid)
			if failures[0].Code() != wantFailure.Code() || failures[0].Digest() != wantFailure.Digest() {
				t.Fatalf("failure=%#v want=%#v", failures[0], wantFailure)
			}
		})
	}
}

func TestStoreFailuresFailClosed(t *testing.T) {
	t.Run("claim", func(t *testing.T) {
		store := &fakeStore{claimErr: errors.New("unavailable")}
		runtime := newTestRuntime(t, store)
		result, err := runtime.ProcessNext(context.Background())
		_, failures, _ := store.snapshot()
		if !errors.Is(err, ErrStoreUnavailable) || result.Outcome() != OutcomeNoWork || len(failures) != 0 {
			t.Fatalf("result=%#v err=%v failures=%d", result, err, len(failures))
		}
	})
	t.Run("commit ambiguous", func(t *testing.T) {
		store := &fakeStore{claims: []Claim{NewClaim(validClaimInput())}, commitErr: errors.New("connection lost")}
		runtime := newTestRuntime(t, store)
		result, err := runtime.ProcessNext(context.Background())
		_, failures, effects := store.snapshot()
		if !errors.Is(err, ErrStoreUnavailable) || result.Outcome() != OutcomeCommitUnknown ||
			len(failures) != 0 || effects != 0 {
			t.Fatalf("result=%#v err=%v failures=%d effects=%d", result, err, len(failures), effects)
		}
	})
	t.Run("invalid commit disposition", func(t *testing.T) {
		store := &fakeStore{claims: []Claim{NewClaim(validClaimInput())}, invalidDisposition: true}
		runtime := newTestRuntime(t, store)
		result, err := runtime.ProcessNext(context.Background())
		if !errors.Is(err, ErrStoreUnavailable) || result.Outcome() != OutcomeCommitUnknown {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})
	t.Run("failure persistence", func(t *testing.T) {
		input := validClaimInput()
		input.TargetIPv4 = "bad"
		store := &fakeStore{claims: []Claim{NewClaim(input)}, finishErr: errors.New("lease lost")}
		runtime := newTestRuntime(t, store)
		result, err := runtime.ProcessNext(context.Background())
		if !errors.Is(err, ErrStoreUnavailable) || result.Outcome() != OutcomeFailed {
			t.Fatalf("result=%#v err=%v", result, err)
		}
	})
}

type cancellingStore struct {
	*fakeStore
	cancel context.CancelFunc
}

func (s *cancellingStore) ClaimDue(ctx context.Context) (Claim, bool, error) {
	claim, found, err := s.fakeStore.ClaimDue(ctx)
	if found {
		s.cancel()
	}
	return claim, found, err
}

func TestCancellationBeforeCommitFinishesWithBoundedCleanupContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	base := &fakeStore{claims: []Claim{NewClaim(validClaimInput())}}
	store := &cancellingStore{fakeStore: base, cancel: cancel}
	runtime := newTestRuntime(t, store)
	result, err := runtime.ProcessNext(ctx)
	if !errors.Is(err, ErrCancelled) || result.Outcome() != OutcomeFailed ||
		result.FailureCode() != FailureContextCancelled {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	_, failures, effects := base.snapshot()
	if len(failures) != 1 || effects != 0 || base.failureContextsCancelled[0] {
		t.Fatalf("failures=%d effects=%d cleanupCancelled=%v", len(failures), effects, base.failureContextsCancelled)
	}
}

func TestConcurrentProcessNextSerializesOneClaim(t *testing.T) {
	store := &fakeStore{claims: []Claim{NewClaim(validClaimInput())}}
	runtime := newTestRuntime(t, store)
	const workers = 64
	results := make(chan Result, workers)
	errorsCh := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := runtime.ProcessNext(context.Background())
			results <- result
			errorsCh <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsCh)
	committed, noWork := 0, 0
	for result := range results {
		switch result.Outcome() {
		case OutcomeCommitted:
			committed++
		case OutcomeNoWork:
			noWork++
		default:
			t.Fatalf("unexpected result: %#v", result)
		}
	}
	for err := range errorsCh {
		if err != nil {
			t.Fatalf("concurrent error: %v", err)
		}
	}
	_, failures, effects := store.snapshot()
	if committed != 1 || noWork != workers-1 || effects != 1 || len(failures) != 0 {
		t.Fatalf("committed=%d noWork=%d effects=%d failures=%d", committed, noWork, effects, len(failures))
	}
}

func TestRunPollsBoundedlyAndStopsOnCancellation(t *testing.T) {
	store := &fakeStore{}
	clock := &blockingClock{started: make(chan struct{})}
	runtime, err := New(store, DefaultConfig("reconciler"), Dependencies{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case <-clock.started:
	case <-time.After(time.Second):
		t.Fatal("runtime did not enter bounded poll sleep")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancelled Run returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
	clock.mu.Lock()
	defer clock.mu.Unlock()
	if len(clock.sleeps) != 1 || clock.sleeps[0] != DefaultPollInterval {
		t.Fatalf("sleeps=%v", clock.sleeps)
	}
}

func TestConfigurationAndPublicBoundaryExcludeMutationAuthority(t *testing.T) {
	valid := DefaultConfig("reconciler")
	tests := []Config{
		{},
		{SchedulerID: "Reconciler", PollInterval: valid.PollInterval, CleanupTimeout: valid.CleanupTimeout},
		{SchedulerID: valid.SchedulerID, PollInterval: 0, CleanupTimeout: valid.CleanupTimeout},
		{SchedulerID: valid.SchedulerID, PollInterval: MaxPollInterval + time.Nanosecond, CleanupTimeout: valid.CleanupTimeout},
		{SchedulerID: valid.SchedulerID, PollInterval: valid.PollInterval, CleanupTimeout: MaxCleanupTimeout + time.Nanosecond},
	}
	for _, config := range tests {
		if _, err := New(&fakeStore{}, config, Dependencies{}); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("invalid config accepted: %+v err=%v", config, err)
		}
	}
	if _, err := New(nil, valid, Dependencies{}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("nil store accepted: %v", err)
	}

	for _, typ := range []reflect.Type{reflect.TypeOf(ClaimInput{}), reflect.TypeOf(Config{}), reflect.TypeOf(Dependencies{})} {
		for index := 0; index < typ.NumField(); index++ {
			name := strings.ToLower(typ.Field(index).Name)
			for _, forbidden := range []string{"command", "mutation", "ttl", "nonce", "reason", "administrator", "admin"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s exposes forbidden field %s", typ, typ.Field(index).Name)
				}
			}
		}
	}
	storeType := reflect.TypeOf((*Store)(nil)).Elem()
	claimMethod, ok := storeType.MethodByName("ClaimDue")
	if !ok || claimMethod.Type.NumIn() != 1 || claimMethod.Type.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		t.Fatalf("ClaimDue accepts non-context/runtime clock input: %v", claimMethod)
	}
}

func TestImmutableAndRedactedTypes(t *testing.T) {
	claim := NewClaim(validClaimInput())
	store := &fakeStore{claims: []Claim{claim}}
	runtime := newTestRuntime(t, store)
	if _, err := runtime.ProcessNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	commits, _, _ := store.snapshot()
	prepared := commits[0]
	inspectBytes := prepared.Inspect().CanonicalBytes()
	authorizationBytes := prepared.Authorization().CanonicalBytes()
	inspectExpected := bytes.Clone(inspectBytes)
	authorizationExpected := bytes.Clone(authorizationBytes)
	inspectBytes[0] ^= 0xff
	authorizationBytes[0] ^= 0xff
	if !bytes.Equal(prepared.Inspect().CanonicalBytes(), inspectExpected) ||
		!bytes.Equal(prepared.Authorization().CanonicalBytes(), authorizationExpected) {
		t.Fatal("prepared artifacts expose mutable bytes")
	}
	for _, formatted := range []string{
		fmt.Sprintf("%v", claim), fmt.Sprintf("%#v", claim),
		fmt.Sprintf("%v", prepared), fmt.Sprintf("%#v", prepared),
		fmt.Sprintf("%v", checkedFailure(FailureProjectionInvalid)),
	} {
		for _, secret := range []string{
			"schedule-001", "lease-001", testAuthorizationID, testTarget, testActionID, testAddDigest,
		} {
			if strings.Contains(formatted, secret) {
				t.Fatalf("redacted type leaked %q in %q", secret, formatted)
			}
		}
	}
}

func TestCancelledContextBeforeClaimDoesNothing(t *testing.T) {
	store := &fakeStore{claims: []Claim{NewClaim(validClaimInput())}}
	runtime := newTestRuntime(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := runtime.ProcessNext(ctx)
	if !errors.Is(err, ErrCancelled) || result.Outcome() != OutcomeNoWork {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	commits, failures, effects := store.snapshot()
	if len(commits) != 0 || len(failures) != 0 || effects != 0 || len(store.claims) != 1 {
		t.Fatalf("cancelled call touched store: commits=%d failures=%d effects=%d claims=%d", len(commits), len(failures), effects, len(store.claims))
	}
}
