package investigationapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewHandlerRequiresEveryReadBoundary(t *testing.T) {
	t.Parallel()
	valid := Config{
		Reader: &readerStub{}, Principals: validPrincipalStub(), Events: newNumericSource(),
		Leases: &leaseStub{}, ProcessInstance: testProcessInstance,
	}
	for name, mutate := range map[string]func(*Config){
		"reader":    func(config *Config) { config.Reader = nil },
		"principal": func(config *Config) { config.Principals = nil },
		"events":    func(config *Config) { config.Events = nil },
		"leases":    func(config *Config) { config.Leases = nil },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := NewHandler(config); err == nil {
				t.Fatal("NewHandler accepted missing dependency")
			}
		})
	}
}

func TestSequenceCursorCanonicalEncodingAndOrdering(t *testing.T) {
	t.Parallel()
	zero, err := FormatSequenceCursor(0)
	if err != nil || zero != "s1.0000000000000000" {
		t.Fatalf("zero=%q err=%v", zero, err)
	}
	maximum, err := FormatSequenceCursor(int64(^uint64(0) >> 1))
	if err != nil || maximum != "s1.7fffffffffffffff" {
		t.Fatalf("maximum=%q err=%v", maximum, err)
	}
	parsed, sequence, err := ParseSequenceCursor("s1.000000000000000a")
	if err != nil || parsed != "s1.000000000000000a" || sequence != 10 {
		t.Fatalf("parsed=%q sequence=%d err=%v", parsed, sequence, err)
	}
	if comparison, err := CompareSequenceCursor(zero, parsed); err != nil || comparison != -1 {
		t.Fatalf("comparison=%d err=%v", comparison, err)
	}
	if _, err := FormatSequenceCursor(-1); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("negative format error=%v", err)
	}
	for _, raw := range []string{
		"", "s1.0", "s1.000000000000000A", "s2.0000000000000000",
		"s1.8000000000000000", "s1.00000000000000000",
	} {
		if _, _, err := ParseSequenceCursor(raw); !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("ParseSequenceCursor(%q) error=%v", raw, err)
		}
	}
}

func TestSSEReconnectEmitsStrictAuthorizedEvent(t *testing.T) {
	t.Parallel()
	source := newNumericSource()
	source.poll = func(_ context.Context, principal Principal, after StreamCursor, limit int) (EventPage, error) {
		if principal.ActorID != "admin" || principal.SessionID != testSessionID || after != "s1.0000000000000001" || limit != MaxStreamPageSize {
			t.Fatalf("principal=%+v after=%q limit=%d", principal, after, limit)
		}
		return EventPage{
			Events: []StreamEvent{streamEvent("s1.0000000000000002")}, Next: "s1.0000000000000002",
			ReplayWindow: ReplayWindow{Floor: "s1.0000000000000000", Watermark: "s1.0000000000000002"},
		}, nil
	}
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), source)
	ctx, cancel := context.WithCancel(context.Background())
	writer := newDeadlineWriter()
	writer.onWrite = func(value []byte) {
		if bytes.Contains(value, []byte("data:")) {
			cancel()
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil).WithContext(ctx)
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", "s1.0000000000000001")
	done := make(chan struct{})
	go func() { handler.ServeHTTP(writer, request); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream did not observe request cancellation")
	}
	body := writer.String()
	if writer.Status() != http.StatusOK || !strings.Contains(body, "id: s1.0000000000000002\n") ||
		!strings.Contains(body, "event: incident.updated\n") || !strings.Contains(body, `"resource_version":2`) {
		t.Fatalf("status=%d body=%q", writer.Status(), body)
	}
	for _, forbidden := range []string{"command", "signature", "approval_authority", "session"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("SSE leaked %q: %s", forbidden, body)
		}
	}
}

func TestSSEInitialReplayGapReturnsJSON409BeforeStream(t *testing.T) {
	t.Parallel()
	source := newNumericSource()
	source.poll = func(context.Context, Principal, StreamCursor, int) (EventPage, error) {
		return EventPage{Gap: true, ReplayWindow: ReplayWindow{Floor: "s1.000000000000000a", Watermark: "s1.0000000000000014"}}, nil
	}
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), source)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil)
	request.Header.Set("Last-Event-ID", "s1.0000000000000001")
	request.Header.Set("Accept", "text/event-stream")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || response.Header().Get("Content-Type") != "application/json; charset=utf-8" ||
		!strings.Contains(response.Body.String(), `"code":"stale_version"`) {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestSSEHeartbeatAndCancellation(t *testing.T) {
	t.Parallel()
	source := newNumericSource()
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), source)
	ctx, cancel := context.WithCancel(context.Background())
	writer := newDeadlineWriter()
	writer.onWrite = func(value []byte) {
		if bytes.Contains(value, []byte(": heartbeat")) {
			cancel()
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil).WithContext(ctx)
	request.Header.Set("Accept", "*/*")
	done := make(chan struct{})
	go func() { handler.ServeHTTP(writer, request); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat stream did not cancel")
	}
	if !strings.Contains(writer.String(), ": heartbeat\n\n") || writer.DeadlineCalls() < 2 || writer.Flushes() < 1 {
		t.Fatalf("body=%q deadlines=%d flushes=%d", writer.String(), writer.DeadlineCalls(), writer.Flushes())
	}
}

func TestSSEGapAfterStartSendsControlCommentAndCloses(t *testing.T) {
	t.Parallel()
	source := newNumericSource()
	var calls int
	source.poll = func(context.Context, Principal, StreamCursor, int) (EventPage, error) {
		calls++
		if calls == 1 {
			return EventPage{Events: []StreamEvent{streamEvent("s1.0000000000000002")}, Next: "s1.0000000000000002", ReplayWindow: ReplayWindow{Floor: "s1.0000000000000000", Watermark: "s1.0000000000000002"}}, nil
		}
		return EventPage{Gap: true, ReplayWindow: ReplayWindow{Floor: "s1.0000000000000003", Watermark: "s1.0000000000000004"}}, ErrReplayGap
	}
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), source)
	writer := newDeadlineWriter()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil)
	request.Header.Set("Last-Event-ID", "s1.0000000000000001")
	done := make(chan struct{})
	go func() { handler.ServeHTTP(writer, request); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream did not close on replay gap")
	}
	if calls < 2 || !strings.Contains(writer.String(), ": replay-gap\n\n") {
		t.Fatalf("calls=%d body=%q", calls, writer.String())
	}
}

func TestSSESourceTimeoutCancelsPoll(t *testing.T) {
	t.Parallel()
	source := newNumericSource()
	source.poll = func(ctx context.Context, _ Principal, _ StreamCursor, _ int) (EventPage, error) {
		<-ctx.Done()
		return EventPage{}, ctx.Err()
	}
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), source)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil)
	request.Header.Set("Last-Event-ID", "s1.0000000000000001")
	response := httptest.NewRecorder()
	started := time.Now()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || time.Since(started) > time.Second {
		t.Fatalf("status=%d duration=%s body=%s", response.Code, time.Since(started), response.Body.String())
	}
}

func TestSSEConnectionDeadlineCancelsInFlightSource(t *testing.T) {
	t.Parallel()
	for name, sessionLifetime := range map[string]time.Duration{
		"maximum connection lifetime": time.Hour,
		"session expiry":              15 * time.Millisecond,
	} {
		t.Run(name, func(t *testing.T) {
			source := newNumericSource()
			pollCancelled := make(chan struct{}, 1)
			source.poll = func(ctx context.Context, _ Principal, _ StreamCursor, _ int) (EventPage, error) {
				<-ctx.Done()
				pollCancelled <- struct{}{}
				return EventPage{}, ctx.Err()
			}
			now := time.Now().UTC()
			principal := principalStub{value: Principal{
				ActorID: "admin", SessionID: testSessionID,
				ValidatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(sessionLifetime),
			}, ok: true}
			handler, err := NewHandler(Config{
				Reader: &readerStub{}, Principals: principal, Events: source,
				Leases: &leaseStub{}, ProcessInstance: testProcessInstance,
				PollInterval: time.Millisecond, HeartbeatInterval: 50 * time.Millisecond,
				WriteTimeout: 5 * time.Millisecond, SourceTimeout: 50 * time.Millisecond,
				MaxConnectionLifetime: 20 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			writer := newDeadlineWriter()
			request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil)
			done := make(chan struct{})
			go func() { handler.ServeHTTP(writer, request); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("connection deadline did not stop handler")
			}
			select {
			case <-pollCancelled:
			default:
				t.Fatal("connection deadline did not cancel source poll")
			}
			if writer.Status() != http.StatusOK || !strings.Contains(writer.String(), ": connected") {
				t.Fatalf("status=%d body=%q", writer.Status(), writer.String())
			}
		})
	}
}

func TestSSELeaseRegistrationIsAfterPreflightAndBeforeStatus(t *testing.T) {
	t.Parallel()
	preflight := false
	source := newNumericSource()
	source.tail = func(context.Context, Principal) (ReplayWindow, error) {
		preflight = true
		return ReplayWindow{Floor: "s1.0000000000000000", Watermark: "s1.0000000000000000"}, nil
	}
	writer := newDeadlineWriter()
	leases := &leaseStub{register: func(_ context.Context, leaseID, processInstance string) error {
		if !preflight || writer.Status() != 0 || writer.DeadlineCalls() == 0 ||
			!uuidPattern.MatchString(leaseID) || processInstance != testProcessInstance {
			t.Fatalf("preflight=%v status=%d deadlines=%d lease=%q process=%q",
				preflight, writer.Status(), writer.DeadlineCalls(), leaseID, processInstance)
		}
		return errors.New("database unavailable")
	}}
	handler := newTestHandlerWithLeases(t, &readerStub{}, validPrincipalStub(), source, leases)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil)
	request.Header.Set("Accept", "text/event-stream")
	handler.ServeHTTP(writer, request)
	if writer.Status() != http.StatusServiceUnavailable ||
		!strings.Contains(writer.String(), `"code":"service_unavailable"`) || leases.unregisterCalls != 0 {
		t.Fatalf("status=%d body=%q unregister=%d", writer.Status(), writer.String(), leases.unregisterCalls)
	}
}

func TestSSELeaseTouchPrecedesHeartbeatAndUnregisters(t *testing.T) {
	t.Parallel()
	leasing := &leaseStub{}
	handler := newTestHandlerWithLeases(
		t, &readerStub{}, validPrincipalStub(), newNumericSource(), leasing,
	)
	ctx, cancel := context.WithCancel(context.Background())
	writer := newDeadlineWriter()
	writer.onWrite = func(value []byte) {
		if bytes.Contains(value, []byte(": heartbeat")) {
			leasing.mu.Lock()
			defer leasing.mu.Unlock()
			if len(leasing.calls) < 2 || leasing.calls[0] != "register" || leasing.calls[1] != "touch" {
				t.Errorf("lease calls before heartbeat=%v", leasing.calls)
			}
			cancel()
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil).WithContext(ctx)
	request.Header.Set("Accept", "text/event-stream")
	done := make(chan struct{})
	go func() { handler.ServeHTTP(writer, request); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lease-backed heartbeat did not stop")
	}
	leasing.mu.Lock()
	defer leasing.mu.Unlock()
	if len(leasing.calls) < 3 || leasing.calls[len(leasing.calls)-1] != "unregister" ||
		leasing.registerLeaseID == "" || leasing.registerLeaseID != leasing.touchLeaseID ||
		leasing.registerLeaseID != leasing.unregisterLeaseID {
		t.Fatalf("lease calls=%v ids=%q/%q/%q", leasing.calls, leasing.registerLeaseID,
			leasing.touchLeaseID, leasing.unregisterLeaseID)
	}
}

func TestSSETouchFailureClosesBeforeHeartbeatAndStillUnregisters(t *testing.T) {
	t.Parallel()
	leasing := &leaseStub{touch: func(context.Context, string, string) error {
		return errors.New("lease expired")
	}}
	handler := newTestHandlerWithLeases(
		t, &readerStub{}, validPrincipalStub(), newNumericSource(), leasing,
	)
	writer := newDeadlineWriter()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil)
	request.Header.Set("Accept", "text/event-stream")
	done := make(chan struct{})
	go func() { handler.ServeHTTP(writer, request); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("touch failure did not close stream")
	}
	if strings.Contains(writer.String(), ": heartbeat") {
		t.Fatalf("failed touch emitted heartbeat: %q", writer.String())
	}
	leasing.mu.Lock()
	defer leasing.mu.Unlock()
	if len(leasing.calls) != 3 || leasing.calls[0] != "register" ||
		leasing.calls[1] != "touch" || leasing.calls[2] != "unregister" {
		t.Fatalf("lease calls=%v", leasing.calls)
	}
}

func TestSSERejectsNonMonotonicSourcePage(t *testing.T) {
	t.Parallel()
	source := newNumericSource()
	source.poll = func(context.Context, Principal, StreamCursor, int) (EventPage, error) {
		event := streamEvent("s1.0000000000000001")
		return EventPage{Events: []StreamEvent{event}, Next: "s1.0000000000000001", ReplayWindow: ReplayWindow{Floor: "s1.0000000000000000", Watermark: "s1.0000000000000002"}}, nil
	}
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), source)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil)
	request.Header.Set("Last-Event-ID", "s1.0000000000000001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "s1.0000000000000001") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSSEEventAllowlistRejectsCrossResourceAndSummaryDrift(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), newNumericSource())
	valid := streamEvent("s1.0000000000000001")
	if !handler.validEvent(valid) {
		t.Fatal("canonical incident event rejected")
	}

	wrongSummary := valid
	wrongSummary.Summary.Outcome = "succeeded"
	if handler.validEvent(wrongSummary) {
		t.Fatal("event-specific summary drift accepted")
	}

	actionID := testActionID
	crossResource := valid
	crossResource.ActionID = &actionID
	if handler.validEvent(crossResource) {
		t.Fatal("unrelated action reference accepted")
	}

	policyID := testPolicyID
	policy := valid
	policy.Type = EventPolicyValidationUpdated
	policy.ResourceID = testPolicyID
	policy.PolicyID = &policyID
	policy.Summary = EventSummary{Code: "policy_validation_updated", Outcome: "valid"}
	if !handler.validEvent(policy) {
		t.Fatal("canonical policy event rejected")
	}
	otherPolicyID := testActionID
	policy.PolicyID = &otherPolicyID
	if handler.validEvent(policy) {
		t.Fatal("mismatched policy resource accepted")
	}
}

func TestSSEBoundsSlowConsumerWithWriteDeadline(t *testing.T) {
	t.Parallel()
	source := newNumericSource()
	source.poll = func(context.Context, Principal, StreamCursor, int) (EventPage, error) {
		return EventPage{Events: []StreamEvent{streamEvent("s1.0000000000000002")}, Next: "s1.0000000000000002", ReplayWindow: ReplayWindow{Floor: "s1.0000000000000000", Watermark: "s1.0000000000000002"}}, nil
	}
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), source)
	writer := newDeadlineWriter()
	writer.writeErr = errors.New("write deadline exceeded")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil)
	request.Header.Set("Last-Event-ID", "s1.0000000000000001")
	handler.ServeHTTP(writer, request)
	if writer.Status() != http.StatusOK || writer.DeadlineCalls() < 2 {
		t.Fatalf("status=%d deadline calls=%d", writer.Status(), writer.DeadlineCalls())
	}
}

func TestSSEFailsClosedWhenWriterCannotEnforceDeadline(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), newNumericSource())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestSSEStrictLastEventIDAndCursorConflict(t *testing.T) {
	t.Parallel()
	handler := newTestHandler(t, &readerStub{}, validPrincipalStub(), newNumericSource())
	tests := []struct {
		name    string
		target  string
		headers []string
	}{
		{name: "invalid characters", target: "/api/v1/events/stream", headers: []string{"bad cursor"}},
		{name: "query conflict", target: "/api/v1/events/stream?cursor=s1.0000000000000001", headers: []string{"s1.0000000000000001"}},
		{name: "duplicate header", target: "/api/v1/events/stream", headers: []string{"s1.0000000000000001", "s1.0000000000000002"}},
		{name: "unknown query", target: "/api/v1/events/stream?limit=1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			for _, value := range test.headers {
				request.Header.Add("Last-Event-ID", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"schema_invalid"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func streamEvent(id StreamCursor) StreamEvent {
	incidentID := testIncidentID
	traceID := "019b0000-0000-7000-8000-00000000a401"
	return StreamEvent{
		ID: id, Type: EventIncidentUpdated, ResourceID: testIncidentID,
		ResourceVersion: 2, IncidentID: &incidentID, OccurredAt: apiTestNow,
		TraceID: &traceID, Summary: EventSummary{Code: "incident_updated", Outcome: "open"},
	}
}

type numericSource struct {
	tail func(context.Context, Principal) (ReplayWindow, error)
	poll func(context.Context, Principal, StreamCursor, int) (EventPage, error)
}

type leaseStub struct {
	mu                sync.Mutex
	register          func(context.Context, string, string) error
	touch             func(context.Context, string, string) error
	unregister        func(context.Context, string, string) error
	calls             []string
	registerLeaseID   string
	touchLeaseID      string
	unregisterLeaseID string
	unregisterCalls   int
}

func (stub *leaseStub) RegisterLease(ctx context.Context, leaseID, processInstance string) error {
	stub.mu.Lock()
	stub.calls = append(stub.calls, "register")
	stub.registerLeaseID = leaseID
	callback := stub.register
	stub.mu.Unlock()
	if callback != nil {
		return callback(ctx, leaseID, processInstance)
	}
	return nil
}

func (stub *leaseStub) TouchLease(ctx context.Context, leaseID, processInstance string) error {
	stub.mu.Lock()
	stub.calls = append(stub.calls, "touch")
	stub.touchLeaseID = leaseID
	callback := stub.touch
	stub.mu.Unlock()
	if callback != nil {
		return callback(ctx, leaseID, processInstance)
	}
	return nil
}

func (stub *leaseStub) UnregisterLease(ctx context.Context, leaseID, processInstance string) error {
	stub.mu.Lock()
	stub.calls = append(stub.calls, "unregister")
	stub.unregisterLeaseID = leaseID
	stub.unregisterCalls++
	callback := stub.unregister
	stub.mu.Unlock()
	if callback != nil {
		return callback(ctx, leaseID, processInstance)
	}
	return nil
}

func newNumericSource() *numericSource { return &numericSource{} }

func (*numericSource) ParseCursor(raw string) (StreamCursor, error) {
	parsed, _, err := ParseSequenceCursor(raw)
	return parsed, err
}

func (source *numericSource) CompareCursor(left, right StreamCursor) (int, error) {
	return CompareSequenceCursor(left, right)
}

func (source *numericSource) Tail(ctx context.Context, principal Principal) (ReplayWindow, error) {
	if source.tail != nil {
		return source.tail(ctx, principal)
	}
	return ReplayWindow{Floor: "s1.0000000000000000", Watermark: "s1.0000000000000000"}, nil
}

func (source *numericSource) Poll(ctx context.Context, principal Principal, after StreamCursor, limit int) (EventPage, error) {
	if source.poll != nil {
		return source.poll(ctx, principal, after, limit)
	}
	return EventPage{Next: after, ReplayWindow: ReplayWindow{Floor: "s1.0000000000000000", Watermark: after}}, nil
}

type deadlineWriter struct {
	mu            sync.Mutex
	header        http.Header
	status        int
	body          bytes.Buffer
	deadlineCalls int
	flushes       int
	writeErr      error
	deadlineErr   error
	onWrite       func([]byte)
}

func newDeadlineWriter() *deadlineWriter           { return &deadlineWriter{header: make(http.Header)} }
func (writer *deadlineWriter) Header() http.Header { return writer.header }
func (writer *deadlineWriter) WriteHeader(status int) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.status == 0 {
		writer.status = status
	}
}
func (writer *deadlineWriter) Write(value []byte) (int, error) {
	writer.mu.Lock()
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	err := writer.writeErr
	if err == nil {
		_, _ = writer.body.Write(value)
	}
	callback := writer.onWrite
	copyValue := append([]byte(nil), value...)
	writer.mu.Unlock()
	if callback != nil {
		callback(copyValue)
	}
	if err != nil {
		return 0, err
	}
	return len(value), nil
}
func (writer *deadlineWriter) SetWriteDeadline(time.Time) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.deadlineCalls++
	return writer.deadlineErr
}
func (writer *deadlineWriter) FlushError() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.flushes++
	return nil
}
func (writer *deadlineWriter) String() string {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.body.String()
}
func (writer *deadlineWriter) Status() int {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.status
}
func (writer *deadlineWriter) DeadlineCalls() int {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.deadlineCalls
}
func (writer *deadlineWriter) Flushes() int {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.flushes
}

var _ http.ResponseWriter = (*deadlineWriter)(nil)
var _ interface{ SetWriteDeadline(time.Time) error } = (*deadlineWriter)(nil)
var _ interface{ FlushError() error } = (*deadlineWriter)(nil)

func ExampleEventSource_contract() {
	source := newNumericSource()
	cursor, _ := source.ParseCursor("s1.0000000000000001")
	window, _ := source.Tail(context.Background(), Principal{ActorID: "admin"})
	fmt.Println(cursor, window.Floor, window.Watermark)
	// Output: s1.0000000000000001 s1.0000000000000000 s1.0000000000000000
}
