package correlation

import (
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

func TestIncidentHappyLifecycleOptimisticRevisionAndIdempotency(t *testing.T) {
	t.Parallel()

	incident := newTestIncident(t, testSignal(1, detection.RulePathScan, correlationNow.Add(-time.Minute), correlationNow))
	if incident.State() != IncidentOpen || incident.Revision() != 1 || incident.Version() != 1 {
		t.Fatalf("new incident = state %s revision %d version %d", incident.State(), incident.Revision(), incident.Version())
	}
	original := cloneIncident(incident)

	begin := testCommand(1, incident.Revision(), correlationNow.Add(time.Second))
	analyzing, result, err := incident.BeginAnalysis(begin)
	if err != nil {
		t.Fatalf("BeginAnalysis error = %v", err)
	}
	if result.Disposition != TransitionApplied || analyzing.State() != IncidentAnalyzing || analyzing.Revision() != 2 ||
		analyzing.Version() != 2 || analyzing.AnalysisAttempts() != 1 {
		t.Fatalf("begin result = %#v incident=%#v", result, analyzing)
	}
	if !reflect.DeepEqual(incident, original) {
		t.Fatal("BeginAnalysis mutated receiver")
	}

	duplicate, duplicateResult, err := analyzing.BeginAnalysis(begin)
	if err != nil {
		t.Fatalf("duplicate BeginAnalysis error = %v", err)
	}
	if duplicateResult.Disposition != TransitionIdempotentDuplicate || duplicateResult.AppliedRevision != 2 ||
		duplicate.Revision() != 2 || duplicate.Version() != 2 {
		t.Fatalf("duplicate result = %#v incident revision=%d", duplicateResult, duplicate.Revision())
	}

	conflictingCommand := begin
	conflictingCommand.ExpectedRevision = analyzing.Revision()
	_, _, err = analyzing.CompleteAnalysis(conflictingCommand)
	assertErrorCode(t, err, ErrorIdempotencyConflict)

	stale := testCommand(2, 1, correlationNow.Add(2*time.Second))
	_, _, err = analyzing.CompleteAnalysis(stale)
	assertErrorCode(t, err, ErrorStaleRevision)

	complete := testCommand(3, analyzing.Revision(), correlationNow.Add(2*time.Second))
	review, result, err := analyzing.CompleteAnalysis(complete)
	if err != nil {
		t.Fatalf("CompleteAnalysis error = %v", err)
	}
	if review.State() != IncidentReviewReady || result.CurrentRevision != 3 || review.Version() != 3 {
		t.Fatalf("review transition = %#v state=%s", result, review.State())
	}

	deadline := review.LastSignalAt().Add(IncidentIdleTimeout)
	tooEarly := testCommand(4, review.Revision(), deadline.Add(-time.Nanosecond))
	_, _, err = review.CloseIdle(tooEarly)
	assertErrorCode(t, err, ErrorIdleDeadlineNotReached)

	closeCommand := testCommand(5, review.Revision(), deadline)
	closed, result, err := review.CloseIdle(closeCommand)
	if err != nil {
		t.Fatalf("CloseIdle error = %v", err)
	}
	closedAt, ok := closed.ClosedAt()
	if !ok || !closedAt.Equal(deadline) || closed.State() != IncidentClosed ||
		result.CurrentRevision != 4 || closed.Version() != 4 {
		t.Fatalf("closed incident = state %s closedAt %v result %#v", closed.State(), closedAt, result)
	}
	_, duplicateResult, err = closed.CloseIdle(closeCommand)
	if err != nil || duplicateResult.Disposition != TransitionIdempotentDuplicate {
		t.Fatalf("duplicate close = %#v error=%v", duplicateResult, err)
	}
}

func TestAnalysisFailureRetryClassificationAndAttemptCap(t *testing.T) {
	t.Parallel()

	retryable := []AnalysisFailureReason{
		FailureNetworkError, FailureHTTP408, FailureHTTP409, FailureRateLimited, FailureServerError,
	}
	terminal := []AnalysisFailureReason{
		FailureBudgetExhausted, FailureInputTooLarge, FailureTimeout, FailureRefused,
		FailureIncomplete, FailureSchemaInvalid, FailureEvidenceInvalid, FailureUnsupportedAction,
		FailureCancelled, FailureConfigurationError,
	}
	for _, reason := range retryable {
		classification, err := ClassifyAnalysisFailure(reason)
		if err != nil || classification != RetryOnceWithBoundedJitter {
			t.Fatalf("classification(%s) = %s, %v", reason, classification, err)
		}
	}
	for _, reason := range terminal {
		classification, err := ClassifyAnalysisFailure(reason)
		if err != nil || classification != RetryTerminal {
			t.Fatalf("classification(%s) = %s, %v", reason, classification, err)
		}
	}
	if _, err := ClassifyAnalysisFailure("unknown"); err == nil {
		t.Fatal("unknown failure reason was accepted")
	}

	incident := newTestIncident(t, testSignal(1, detection.RuleCredentialStuffing, correlationNow.Add(-time.Minute), correlationNow))
	first, _, err := incident.BeginAnalysis(testCommand(10, 1, correlationNow.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	failed, _, err := first.FailAnalysis(testCommand(11, 2, correlationNow.Add(2*time.Second)), FailureNetworkError)
	if err != nil {
		t.Fatal(err)
	}
	if failed.State() != IncidentAnalysisFailed || !failed.IsAnalysisFailureNonEnforcing() || !failed.CanRetryAnalysis() {
		t.Fatalf("first failure state=%s reason=%s retry=%v", failed.State(), failed.FailureReason(), failed.CanRetryAnalysis())
	}
	retry, _, err := failed.BeginAnalysis(testCommand(12, 3, correlationNow.Add(3*time.Second)))
	if err != nil || retry.AnalysisAttempts() != 2 {
		t.Fatalf("retry = attempts %d error %v", retry.AnalysisAttempts(), err)
	}
	failedAgain, _, err := retry.FailAnalysis(testCommand(13, 4, correlationNow.Add(4*time.Second)), FailureServerError)
	if err != nil {
		t.Fatal(err)
	}
	if failedAgain.CanRetryAnalysis() {
		t.Fatal("second failed attempt remained retryable")
	}
	_, _, err = failedAgain.BeginAnalysis(testCommand(14, 5, correlationNow.Add(5*time.Second)))
	assertErrorCode(t, err, ErrorRetryNotAllowed)

	terminalIncident := newTestIncident(t, testSignal(2, detection.RuleLoginBruteForce, correlationNow.Add(-time.Minute), correlationNow))
	terminalIncident, _, _ = terminalIncident.BeginAnalysis(testCommand(20, 1, correlationNow.Add(time.Second)))
	terminalIncident, _, _ = terminalIncident.FailAnalysis(testCommand(21, 2, correlationNow.Add(2*time.Second)), FailureTimeout)
	if terminalIncident.CanRetryAnalysis() {
		t.Fatal("timeout failure was classified retryable")
	}
	_, _, err = terminalIncident.BeginAnalysis(testCommand(22, 3, correlationNow.Add(3*time.Second)))
	assertErrorCode(t, err, ErrorRetryNotAllowed)
}

func TestRouteSignalAppendSeparationAndEvidenceInvalidation(t *testing.T) {
	t.Parallel()

	base := testSignal(1, detection.RulePathScan, correlationNow.Add(-time.Second), correlationNow)
	incident := newTestIncident(t, base)
	originalDigest := incident.Snapshot().Digest()

	related := testSignal(2, detection.RuleCredentialStuffing, correlationNow.Add(MaximumSignalGap), correlationNow.Add(MaximumSignalGap+time.Second))
	related.ServiceLabel = "other"
	command := testCommand(30, incident.Revision(), related.WindowEnd)
	routed, err := incident.RouteSignal(command, related)
	if err != nil {
		t.Fatalf("RouteSignal related error = %v", err)
	}
	if routed.Disposition != RouteAppended || routed.NewIncident != nil || routed.Current.ID() != incident.ID() ||
		routed.Current.Version() != incident.Version()+1 || routed.Current.Revision() != incident.Revision()+1 {
		t.Fatalf("related route = %#v", routed)
	}
	if incident.Snapshot().Digest() != originalDigest || routed.Current.Snapshot().Digest() == originalDigest {
		t.Fatal("snapshot immutability/update invariant failed")
	}
	if !slices.Contains(routed.Current.Snapshot().ServiceLabels(), "other") {
		t.Fatal("different service was not retained as supporting context")
	}

	far := testSignal(3, detection.RuleRequestBurst, correlationNow.Add(MaximumSignalGap+time.Nanosecond), correlationNow.Add(MaximumSignalGap+time.Second))
	separate, err := incident.RouteSignal(testCommand(31, incident.Revision(), far.WindowEnd), far)
	if err != nil {
		t.Fatalf("RouteSignal far error = %v", err)
	}
	if separate.Disposition != RouteNewIncident || separate.NewIncident == nil || separate.NewIncident.ID() == incident.ID() || separate.Current.Revision() != incident.Revision() {
		t.Fatalf("far route = %#v", separate)
	}

	otherSource := testSignal(4, detection.RuleLoginBruteForce, correlationNow, correlationNow.Add(time.Second))
	otherSource.SourceIP = "198.51.100.10"
	separate, err = incident.RouteSignal(testCommand(32, incident.Revision(), otherSource.WindowEnd), otherSource)
	if err != nil || separate.Disposition != RouteNewIncident || separate.NewIncident == nil {
		t.Fatalf("different-source route = %#v error=%v", separate, err)
	}

	// New evidence invalidates an analysis result bound to the old snapshot.
	analyzing, _, _ := incident.BeginAnalysis(testCommand(33, incident.Revision(), correlationNow.Add(time.Second)))
	review, _, _ := analyzing.CompleteAnalysis(testCommand(34, analyzing.Revision(), correlationNow.Add(2*time.Second)))
	relatedEarly := testSignal(5, detection.RuleLoginBruteForce, correlationNow.Add(time.Second), correlationNow.Add(2*time.Second))
	updated, err := review.RouteSignal(testCommand(35, review.Revision(), correlationNow.Add(3*time.Second)), relatedEarly)
	if err != nil || updated.Current.State() != IncidentOpen {
		t.Fatalf("new evidence did not invalidate review state: state=%s error=%v", updated.Current.State(), err)
	}
}

func TestCloseAndReopenBoundariesAdvanceIncidentVersionOnce(t *testing.T) {
	t.Parallel()

	base := testSignal(1, detection.RuleRequestBurst, correlationNow.Add(-time.Second), correlationNow)
	incident := newTestIncident(t, base)
	deadline := incident.LastSignalAt().Add(IncidentIdleTimeout)
	closed, _, err := incident.CloseIdle(testCommand(40, incident.Revision(), deadline))
	if err != nil {
		t.Fatalf("CloseIdle error = %v", err)
	}
	closedAt, _ := closed.ClosedAt()

	atBoundary := closedAt.Add(IncidentReopenWindow)
	reopeningSignal := testSignal(2, detection.RulePathScan, atBoundary.Add(-time.Second), atBoundary)
	reopened, err := closed.RouteSignal(testCommand(41, closed.Revision(), atBoundary), reopeningSignal)
	if err != nil {
		t.Fatalf("RouteSignal reopen error = %v", err)
	}
	if reopened.Disposition != RouteReopened || reopened.Current.State() != IncidentOpen ||
		reopened.Current.ID() != closed.ID() || reopened.Current.Version() != closed.Version()+1 || reopened.NewIncident != nil {
		t.Fatalf("reopened = %#v", reopened)
	}
	closedValue, stillClosed := reopened.Current.ClosedAt()
	if stillClosed || !closedValue.IsZero() {
		t.Fatalf("reopened incident retained closed_at %v", closedValue)
	}
	relations := reopened.Current.Relations()
	foundReopen := false
	for _, relation := range relations {
		foundReopen = foundReopen || relation.TemporalReason == TemporalReopenedWithinThirtyMinutes
	}
	if !foundReopen {
		t.Fatalf("reopen relation missing: %#v", relations)
	}

	afterBoundary := atBoundary.Add(time.Nanosecond)
	laterSignal := testSignal(3, detection.RulePathScan, afterBoundary.Add(-time.Nanosecond), afterBoundary)
	later, err := closed.RouteSignal(testCommand(42, closed.Revision(), afterBoundary), laterSignal)
	if err != nil || later.Disposition != RouteNewIncident || later.NewIncident == nil || later.NewIncident.ID() == closed.ID() {
		t.Fatalf("later route = %#v error=%v", later, err)
	}
}

func TestSignalDuplicateIsIdempotentAndConflictFails(t *testing.T) {
	t.Parallel()

	signal := testSignal(1, detection.RulePathScan, correlationNow.Add(-time.Second), correlationNow)
	incident := newTestIncident(t, signal)
	duplicate, err := incident.RouteSignal(Command{
		ID:               digestText("new-duplicate-command"),
		ExpectedRevision: 0,
		At:               correlationNow,
	}, signal)
	if err != nil || duplicate.Disposition != RouteDuplicateSignal || duplicate.Current.Revision() != incident.Revision() ||
		duplicate.Current.Version() != incident.Version() {
		t.Fatalf("duplicate route = %#v error=%v", duplicate, err)
	}
	beginCommand := testCommand(51, incident.Revision(), correlationNow.Add(time.Second))
	analyzing, _, err := incident.BeginAnalysis(beginCommand)
	if err != nil {
		t.Fatal(err)
	}
	_, err = analyzing.RouteSignal(Command{
		ID:               beginCommand.ID,
		ExpectedRevision: analyzing.Revision(),
		At:               correlationNow.Add(time.Second),
	}, signal)
	assertErrorCode(t, err, ErrorIdempotencyConflict)

	conflict := cloneSignal(signal)
	conflict.Digest = digestText("conflicting-signal")
	_, err = incident.RouteSignal(testCommand(50, incident.Revision(), correlationNow), conflict)
	assertErrorCode(t, err, ErrorConflictingSignal)
}

func TestInvalidIncidentStateTransitions(t *testing.T) {
	t.Parallel()

	incident := newTestIncident(t, testSignal(1, detection.RulePathScan, correlationNow.Add(-time.Second), correlationNow))
	_, _, err := incident.CompleteAnalysis(testCommand(60, incident.Revision(), correlationNow.Add(time.Second)))
	assertErrorCode(t, err, ErrorInvalidTransition)
	_, _, err = incident.FailAnalysis(testCommand(61, incident.Revision(), correlationNow.Add(time.Second)), FailureNetworkError)
	assertErrorCode(t, err, ErrorInvalidTransition)

	analyzing, _, err := incident.BeginAnalysis(testCommand(62, incident.Revision(), correlationNow.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = analyzing.CloseIdle(testCommand(63, analyzing.Revision(), analyzing.LastSignalAt().Add(IncidentIdleTimeout)))
	assertErrorCode(t, err, ErrorInvalidTransition)
	review, _, err := analyzing.CompleteAnalysis(testCommand(64, analyzing.Revision(), correlationNow.Add(2*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = review.BeginAnalysis(testCommand(65, review.Revision(), correlationNow.Add(3*time.Second)))
	assertErrorCode(t, err, ErrorInvalidTransition)

	closed, _, err := review.CloseIdle(testCommand(66, review.Revision(), review.LastSignalAt().Add(IncidentIdleTimeout)))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = closed.BeginAnalysis(testCommand(67, closed.Revision(), closed.UpdatedAt().Add(time.Second)))
	assertErrorCode(t, err, ErrorInvalidTransition)
}

func TestNewIncidentIsDeterministicAndRejectsTimeRegression(t *testing.T) {
	t.Parallel()

	signal := testSignal(1, detection.RulePathScan, correlationNow.Add(-time.Second), correlationNow)
	groups, err := Correlate([]detection.Signal{signal})
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewIncident(groups[0], correlationNow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewIncident(groups[0], correlationNow.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() != second.ID() || first.Version() != second.Version() {
		t.Fatalf("deterministic identity changed: %s/%d vs %s/%d", first.ID(), first.Version(), second.ID(), second.Version())
	}
	_, err = NewIncident(groups[0], signal.WindowEnd.Add(-time.Nanosecond))
	assertErrorCode(t, err, ErrorTimeRegression)
}

func newTestIncident(t *testing.T, signals ...detection.Signal) Incident {
	t.Helper()
	groups, err := Correlate(signals)
	if err != nil {
		t.Fatalf("Correlate error = %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("group count = %d, want 1", len(groups))
	}
	at := groups[0].WindowEnd
	if at.Before(correlationNow) {
		at = correlationNow
	}
	incident, err := NewIncident(groups[0], at)
	if err != nil {
		t.Fatalf("NewIncident error = %v", err)
	}
	return incident
}

func testCommand(index int, revision uint64, at time.Time) Command {
	return Command{
		ID:               digestText("command-" + testUUID(index, index)),
		ExpectedRevision: revision,
		At:               at,
	}
}

func assertErrorCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	var correlationErr *Error
	if !errors.As(err, &correlationErr) || correlationErr.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}
