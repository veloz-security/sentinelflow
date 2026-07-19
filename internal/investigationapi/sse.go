package investigationapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var opaqueCursorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$`)

func (handler *Handler) serveStream(
	writer http.ResponseWriter,
	request *http.Request,
	principal Principal,
	values map[string][]string,
	traceID string,
) {
	parentContext := request.Context()
	deadline := time.Now().UTC().Add(handler.maxConnectionLifetime)
	if principal.ExpiresAt.Before(deadline) {
		deadline = principal.ExpiresAt
	}
	streamContext, cancelStream := context.WithDeadline(parentContext, deadline)
	defer cancelStream()
	request = request.WithContext(streamContext)

	if !onlyKeys(values, "cursor") {
		writeError(writer, http.StatusBadRequest, "schema_invalid", traceID)
		return
	}
	queryCursor, err := optionalSingle(values, "cursor")
	if err != nil {
		writeError(writer, http.StatusBadRequest, "schema_invalid", traceID)
		return
	}
	headerCursor, headerPresent, err := strictLastEventID(request.Header)
	if err != nil || headerPresent && queryCursor != "" {
		writeError(writer, http.StatusBadRequest, "schema_invalid", traceID)
		return
	}
	rawCursor := queryCursor
	if headerPresent {
		rawCursor = headerCursor
	}

	var cursor StreamCursor
	var initial EventPage
	if rawCursor == "" {
		window, sourceErr := handler.tail(request.Context(), principal)
		if sourceErr != nil || !handler.validReplayWindow(window) {
			writer.Header().Set("Retry-After", "1")
			writeError(writer, http.StatusServiceUnavailable, "service_unavailable", traceID)
			return
		}
		cursor = window.Watermark
		initial = EventPage{Next: cursor, ReplayWindow: window}
	} else {
		canonicalCursor, _, canonicalErr := ParseSequenceCursor(rawCursor)
		if !validOpaqueCursor(rawCursor) || canonicalErr != nil {
			writeError(writer, http.StatusBadRequest, "schema_invalid", traceID)
			return
		}
		cursor, err = handler.events.ParseCursor(rawCursor)
		if err != nil || !sameCursor(cursor, rawCursor) || cursor != canonicalCursor {
			writeError(writer, http.StatusBadRequest, "schema_invalid", traceID)
			return
		}
		initial, err = handler.poll(request.Context(), principal, cursor)
		if errors.Is(err, ErrReplayGap) || err == nil && initial.Gap {
			writeError(writer, http.StatusConflict, "stale_version", traceID)
			return
		}
		if err != nil || !handler.validPage(cursor, initial) {
			writer.Header().Set("Retry-After", "1")
			writeError(writer, http.StatusServiceUnavailable, "service_unavailable", traceID)
			return
		}
	}

	controller := http.NewResponseController(writer)
	if err = controller.SetWriteDeadline(time.Now().Add(handler.writeTimeout)); err != nil {
		writer.Header().Set("Retry-After", "1")
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable", traceID)
		return
	}
	leaseID, err := newStrictRandomUUID()
	if err != nil || handler.registerLease(request.Context(), leaseID) != nil {
		_ = controller.SetWriteDeadline(time.Now().Add(handler.writeTimeout))
		writer.Header().Set("Retry-After", "1")
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable", traceID)
		return
	}
	defer handler.unregisterLease(leaseID)
	if err = controller.SetWriteDeadline(time.Now().Add(handler.writeTimeout)); err != nil {
		writer.Header().Set("Retry-After", "1")
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable", traceID)
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.Header().Set("Cache-Control", "no-store, no-transform")
	writer.WriteHeader(http.StatusOK)
	if err = writeSSEBytes(controller, writer, handler.writeTimeout, []byte(": connected\n\n")); err != nil {
		return
	}
	if err = handler.writeEventPage(controller, writer, initial); err != nil {
		return
	}
	if initial.Next != "" {
		cursor = initial.Next
	}

	pollTicker := time.NewTicker(handler.pollInterval)
	heartbeatTicker := time.NewTicker(handler.heartbeatInterval)
	defer pollTicker.Stop()
	defer heartbeatTicker.Stop()
	for {
		select {
		case <-streamContext.Done():
			if parentContext.Err() == nil {
				_ = writeSSEBytes(controller, writer, handler.writeTimeout, []byte(": reconnect\n\n"))
			}
			return
		case <-heartbeatTicker.C:
			if err = handler.touchLease(request.Context(), leaseID); err != nil {
				return
			}
			if err = writeSSEBytes(controller, writer, handler.writeTimeout, []byte(": heartbeat\n\n")); err != nil {
				return
			}
		case <-pollTicker.C:
			page, pollErr := handler.poll(request.Context(), principal, cursor)
			if errors.Is(pollErr, ErrReplayGap) || pollErr == nil && page.Gap {
				_ = writeSSEBytes(controller, writer, handler.writeTimeout, []byte(": replay-gap\n\n"))
				return
			}
			if pollErr != nil || !handler.validPage(cursor, page) {
				return
			}
			if err = handler.writeEventPage(controller, writer, page); err != nil {
				return
			}
			cursor = page.Next
		}
	}
}

func (handler *Handler) registerLease(parent context.Context, leaseID string) error {
	ctx, cancel := context.WithTimeout(parent, handler.sourceTimeout)
	defer cancel()
	return handler.leases.RegisterLease(ctx, leaseID, handler.processInstance)
}

func (handler *Handler) touchLease(parent context.Context, leaseID string) error {
	ctx, cancel := context.WithTimeout(parent, handler.sourceTimeout)
	defer cancel()
	return handler.leases.TouchLease(ctx, leaseID, handler.processInstance)
}

func (handler *Handler) unregisterLease(leaseID string) {
	ctx, cancel := context.WithTimeout(context.Background(), handler.sourceTimeout)
	defer cancel()
	_ = handler.leases.UnregisterLease(ctx, leaseID, handler.processInstance)
}

func (handler *Handler) tail(parent context.Context, principal Principal) (ReplayWindow, error) {
	ctx, cancel := context.WithTimeout(parent, handler.sourceTimeout)
	defer cancel()
	return handler.events.Tail(ctx, principal)
}

func (handler *Handler) poll(parent context.Context, principal Principal, cursor StreamCursor) (EventPage, error) {
	ctx, cancel := context.WithTimeout(parent, handler.sourceTimeout)
	defer cancel()
	return handler.events.Poll(ctx, principal, cursor, MaxStreamPageSize)
}

func (handler *Handler) validReplayWindow(window ReplayWindow) bool {
	if !handler.validSourceCursor(window.Floor) || !handler.validSourceCursor(window.Watermark) {
		return false
	}
	comparison, err := handler.compareCursor(window.Floor, window.Watermark)
	return err == nil && comparison <= 0
}

func (handler *Handler) validPage(after StreamCursor, page EventPage) bool {
	if page.Gap {
		return len(page.Events) == 0
	}
	if len(page.Events) > MaxStreamPageSize || !handler.validReplayWindow(page.ReplayWindow) ||
		!handler.validSourceCursor(after) || !handler.validSourceCursor(page.Next) {
		return false
	}
	if comparison, err := handler.compareCursor(after, page.ReplayWindow.Floor); err != nil || comparison < 0 {
		return false
	}
	if comparison, err := handler.compareCursor(page.Next, page.ReplayWindow.Watermark); err != nil || comparison > 0 {
		return false
	}
	current := after
	for _, event := range page.Events {
		if !handler.validEvent(event) {
			return false
		}
		if comparison, err := handler.compareCursor(current, event.ID); err != nil || comparison >= 0 {
			return false
		}
		if comparison, err := handler.compareCursor(event.ID, page.ReplayWindow.Watermark); err != nil || comparison > 0 {
			return false
		}
		current = event.ID
	}
	comparison, err := handler.compareCursor(current, page.Next)
	return err == nil && comparison == 0
}

func (handler *Handler) validSourceCursor(cursor StreamCursor) bool {
	if !validOpaqueCursor(string(cursor)) {
		return false
	}
	canonical, _, err := ParseSequenceCursor(string(cursor))
	if err != nil || canonical != cursor {
		return false
	}
	parsed, err := handler.events.ParseCursor(string(cursor))
	return err == nil && parsed == cursor
}

func (handler *Handler) compareCursor(left, right StreamCursor) (int, error) {
	canonical, err := CompareSequenceCursor(left, right)
	if err != nil {
		return 0, err
	}
	provided, err := handler.events.CompareCursor(left, right)
	if err != nil || canonical != provided {
		return 0, ErrSourceUnavailable
	}
	return canonical, nil
}

func (handler *Handler) validEvent(event StreamEvent) bool {
	if !handler.validSourceCursor(event.ID) || !allowedEventType(event.Type) ||
		!uuidPattern.MatchString(event.ResourceID) || event.ResourceVersion < 1 ||
		event.OccurredAt.IsZero() || event.OccurredAt.Year() < 2000 || event.OccurredAt.Year() > 9999 ||
		utcOffset(event.OccurredAt) != 0 ||
		!actorPattern.MatchString(event.Summary.Code) || !actorPattern.MatchString(event.Summary.Outcome) {
		return false
	}
	for _, value := range []*string{event.IncidentID, event.PolicyID, event.ActionID, event.TraceID} {
		if value != nil && !uuidPattern.MatchString(*value) {
			return false
		}
	}
	switch event.Type {
	case EventIncidentCreated:
		return event.IncidentID != nil && *event.IncidentID == event.ResourceID &&
			event.PolicyID == nil && event.ActionID == nil && event.Summary.Code == "incident_created" &&
			incidentStreamOutcome(event.Summary.Outcome)
	case EventIncidentUpdated:
		return event.IncidentID != nil && *event.IncidentID == event.ResourceID &&
			event.PolicyID == nil && event.ActionID == nil && event.Summary.Code == "incident_updated" &&
			incidentStreamOutcome(event.Summary.Outcome)
	case EventAnalysisCompleted:
		return event.IncidentID != nil && event.PolicyID == nil && event.ActionID == nil &&
			event.Summary.Code == "analysis_completed" && event.Summary.Outcome == "succeeded"
	case EventAnalysisFailed:
		return event.IncidentID != nil && event.PolicyID == nil && event.ActionID == nil &&
			event.Summary.Code == "analysis_failed" && event.Summary.Outcome == "failed"
	case EventPolicyValidationUpdated:
		return event.IncidentID != nil && event.PolicyID != nil && *event.PolicyID == event.ResourceID &&
			event.ActionID == nil && event.Summary.Code == "policy_validation_updated" &&
			oneOfStream(event.Summary.Outcome, "validating", "valid", "invalid", "stale")
	case EventApprovalRecorded:
		return event.IncidentID != nil && event.Summary.Code == "approval_recorded" &&
			oneOfStream(event.Summary.Outcome, "approved", "rejected", "revoked") &&
			(event.PolicyID != nil && *event.PolicyID == event.ResourceID && event.ActionID == nil ||
				event.ActionID != nil && *event.ActionID == event.ResourceID && event.PolicyID == nil)
	case EventEnforcementUpdated:
		return event.IncidentID != nil && event.PolicyID == nil && event.ActionID != nil &&
			*event.ActionID == event.ResourceID && event.Summary.Code == "enforcement_updated" &&
			oneOfStream(event.Summary.Outcome,
				"approved", "queued", "active", "expired", "failed", "revoked", "indeterminate")
	case EventSourceDegraded, EventSourceRecovered:
		if event.IncidentID != nil || event.PolicyID != nil || event.ActionID != nil {
			return false
		}
		if event.Type == EventSourceDegraded {
			return event.Summary.Code == "source_degraded" &&
				oneOfStream(event.Summary.Outcome, "degraded", "lost")
		}
		return event.Summary.Code == "source_recovered" && event.Summary.Outcome == "recovered"
	default:
		return false
	}
}

func incidentStreamOutcome(value string) bool {
	return oneOfStream(value, "open", "analyzing", "review_ready", "analysis_failed", "closed")
}

func oneOfStream(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func (handler *Handler) writeEventPage(controller *http.ResponseController, writer http.ResponseWriter, page EventPage) error {
	for _, event := range page.Events {
		payload, err := json.Marshal(event)
		if err != nil || len(payload) > 4096 {
			return ErrSourceUnavailable
		}
		wire := []byte(fmt.Sprintf("id: %s\nevent: %s\ndata: %s\n\n", event.ID, event.Type, payload))
		if err = writeSSEBytes(controller, writer, handler.writeTimeout, wire); err != nil {
			return err
		}
	}
	return nil
}

func writeSSEBytes(controller *http.ResponseController, writer http.ResponseWriter, timeout time.Duration, value []byte) error {
	if err := controller.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := writer.Write(value); err != nil {
		return err
	}
	return controller.Flush()
}

func strictLastEventID(header http.Header) (string, bool, error) {
	values := header.Values("Last-Event-ID")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || !validOpaqueCursor(values[0]) || strings.TrimSpace(values[0]) != values[0] {
		return "", false, ErrInvalidCursor
	}
	return values[0], true, nil
}

func validOpaqueCursor(value string) bool {
	return len(value) >= 1 && len(value) <= MaxStreamCursorBytes && opaqueCursorPattern.MatchString(value)
}

func sameCursor(cursor StreamCursor, raw string) bool { return string(cursor) == raw }
