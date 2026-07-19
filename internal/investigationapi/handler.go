// Package investigationapi implements the authenticated, read-only REST and
// SSE administrator investigation boundary.
package investigationapi

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devwooops/sentinelflow/internal/investigationstore"
)

const maxRawQueryBytes = 2048

var decimalPattern = regexp.MustCompile(`^[1-9][0-9]{0,2}$`)

type Reader interface {
	ListIncidents(context.Context, investigationstore.IncidentQuery) (investigationstore.IncidentPage, error)
	GetIncident(context.Context, string) (investigationstore.IncidentDetail, error)
	ListIncidentEvents(context.Context, investigationstore.IncidentEventQuery) (investigationstore.IncidentEventPage, error)
	GetPolicy(context.Context, string) (investigationstore.PolicyDetail, error)
	GetEnforcementAction(context.Context, string) (investigationstore.EnforcementActionDetail, error)
	ListAuditEvents(context.Context, investigationstore.AuditQuery) (investigationstore.AuditPage, error)
}

type Config struct {
	Reader                Reader
	Principals            PrincipalProvider
	Events                EventSource
	Leases                ClientLeaseStore
	ProcessInstance       string
	PollInterval          time.Duration
	HeartbeatInterval     time.Duration
	WriteTimeout          time.Duration
	SourceTimeout         time.Duration
	MaxConnectionLifetime time.Duration
}

type Handler struct {
	reader                Reader
	principals            PrincipalProvider
	events                EventSource
	leases                ClientLeaseStore
	processInstance       string
	pollInterval          time.Duration
	heartbeatInterval     time.Duration
	writeTimeout          time.Duration
	sourceTimeout         time.Duration
	maxConnectionLifetime time.Duration
}

type routeKind uint8

const (
	routeUnknown routeKind = iota
	routeIncidentList
	routeIncidentDetail
	routeIncidentEvents
	routePolicyDetail
	routeActionDetail
	routeAuditList
	routeStream
)

type matchedRoute struct {
	kind routeKind
	id   string
}

type errorResponse struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	TraceID string            `json:"trace_id"`
	Details map[string]string `json:"details"`
}

var traceIDFallbackCounter atomic.Uint64

func NewHandler(config Config) (*Handler, error) {
	if config.Reader == nil || config.Principals == nil || config.Events == nil || config.Leases == nil {
		return nil, errors.New("investigation api: reader, principal provider, event source, and client leases are required")
	}
	if config.ProcessInstance == "" {
		var err error
		config.ProcessInstance, err = newStrictRandomUUID()
		if err != nil {
			return nil, errors.New("investigation api: generate process instance")
		}
	}
	if !uuidPattern.MatchString(config.ProcessInstance) {
		return nil, errors.New("investigation api: invalid process instance")
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 15 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 2 * time.Second
	}
	if config.SourceTimeout == 0 {
		config.SourceTimeout = 2 * time.Second
	}
	if config.MaxConnectionLifetime == 0 {
		config.MaxConnectionLifetime = 2 * time.Minute
	}
	for _, value := range []time.Duration{
		config.PollInterval, config.HeartbeatInterval, config.WriteTimeout, config.SourceTimeout,
	} {
		if value < time.Millisecond || value > time.Minute {
			return nil, errors.New("investigation api: invalid bounded duration")
		}
	}
	if config.SourceTimeout > config.HeartbeatInterval {
		return nil, errors.New("investigation api: source timeout exceeds heartbeat interval")
	}
	if config.MaxConnectionLifetime < time.Millisecond || config.MaxConnectionLifetime > 15*time.Minute {
		return nil, errors.New("investigation api: invalid maximum connection lifetime")
	}
	return &Handler{
		reader: config.Reader, principals: config.Principals, events: config.Events,
		leases: config.Leases, processInstance: config.ProcessInstance,
		pollInterval: config.PollInterval, heartbeatInterval: config.HeartbeatInterval,
		writeTimeout: config.WriteTimeout, sourceTimeout: config.SourceTimeout,
		maxConnectionLifetime: config.MaxConnectionLifetime,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setCommonHeaders(writer)
	traceID := newTraceID()
	if traceID != "" {
		writer.Header().Set("X-SentinelFlow-Trace-ID", traceID)
	}
	if handler == nil || handler.reader == nil || handler.principals == nil || handler.events == nil ||
		handler.leases == nil || !uuidPattern.MatchString(handler.processInstance) ||
		request == nil || request.URL == nil || request.URL.RawPath != "" {
		writeError(writer, http.StatusNotFound, "not_found", traceID)
		return
	}
	route := matchRoute(request.URL.Path)
	if route.kind == routeUnknown {
		writeError(writer, http.StatusNotFound, "not_found", traceID)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, "schema_invalid", traceID)
		return
	}
	if hasRequestBody(request) {
		writeError(writer, http.StatusBadRequest, "schema_invalid", traceID)
		return
	}
	wantedMediaType := "application/json"
	if route.kind == routeStream {
		wantedMediaType = "text/event-stream"
	}
	if !accepts(request.Header.Values("Accept"), wantedMediaType) {
		writeError(writer, http.StatusNotAcceptable, "schema_invalid", traceID)
		return
	}
	principal, ok := handler.principals.Principal(request.Context())
	if !ok || !validPrincipal(principal) || !principal.ExpiresAt.After(time.Now().UTC()) {
		writer.Header().Set("WWW-Authenticate", `Session realm="sentinelflow-admin"`)
		writeError(writer, http.StatusUnauthorized, "authentication_required", traceID)
		return
	}
	query, err := strictQuery(request.URL.RawQuery)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "schema_invalid", traceID)
		return
	}

	switch route.kind {
	case routeIncidentList:
		handler.serveIncidentList(writer, request, query, traceID)
	case routeIncidentDetail:
		value, storeErr := handler.reader.GetIncident(request.Context(), route.id)
		handler.writeStoreResult(writer, traceID, value, storeErr)
	case routeIncidentEvents:
		handler.serveIncidentEvents(writer, request, route.id, query, traceID)
	case routePolicyDetail:
		value, storeErr := handler.reader.GetPolicy(request.Context(), route.id)
		handler.writeStoreResult(writer, traceID, value, storeErr)
	case routeActionDetail:
		value, storeErr := handler.reader.GetEnforcementAction(request.Context(), route.id)
		handler.writeStoreResult(writer, traceID, value, storeErr)
	case routeAuditList:
		handler.serveAuditList(writer, request, query, traceID)
	case routeStream:
		handler.serveStream(writer, request, principal, query, traceID)
	default:
		writeError(writer, http.StatusNotFound, "not_found", traceID)
	}
}

func (handler *Handler) serveIncidentList(writer http.ResponseWriter, request *http.Request, values url.Values, traceID string) {
	if !onlyKeys(values, "state", "kind", "source", "service", "from", "until", "cursor", "limit") {
		writeError(writer, http.StatusBadRequest, "schema_invalid", traceID)
		return
	}
	query := investigationstore.IncidentQuery{}
	var err error
	if query.State, err = optionalSingle(values, "state"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.Kind, err = optionalSingle(values, "kind"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.SourceIP, err = optionalSingle(values, "source"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.ServiceLabel, err = optionalSingle(values, "service"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.From, err = optionalTime(values, "from"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.Until, err = optionalTime(values, "until"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.Limit, err = optionalLimit(values); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	cursor, err := optionalSingle(values, "cursor")
	if err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if cursor != "" {
		if len(cursor) > 128 {
			handler.invalidQuery(writer, traceID)
			return
		}
		query.Cursor, err = investigationstore.ParseIncidentCursor(cursor)
		if err != nil {
			handler.invalidQuery(writer, traceID)
			return
		}
	}
	page, err := handler.reader.ListIncidents(request.Context(), query)
	handler.writeStoreResult(writer, traceID, page, err)
}

func (handler *Handler) serveIncidentEvents(writer http.ResponseWriter, request *http.Request, incidentID string, values url.Values, traceID string) {
	if !onlyKeys(values, "cursor", "limit") {
		handler.invalidQuery(writer, traceID)
		return
	}
	query := investigationstore.IncidentEventQuery{IncidentID: incidentID}
	var err error
	if query.Limit, err = optionalLimit(values); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	cursor, err := optionalSingle(values, "cursor")
	if err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if cursor != "" {
		if len(cursor) > 128 {
			handler.invalidQuery(writer, traceID)
			return
		}
		query.Cursor, err = investigationstore.ParseEventCursor(cursor)
		if err != nil {
			handler.invalidQuery(writer, traceID)
			return
		}
	}
	page, err := handler.reader.ListIncidentEvents(request.Context(), query)
	handler.writeStoreResult(writer, traceID, page, err)
}

func (handler *Handler) serveAuditList(writer http.ResponseWriter, request *http.Request, values url.Values, traceID string) {
	if !onlyKeys(values,
		"incident_id", "policy_id", "action_id", "actor_type", "actor_id",
		"object_type", "object_id", "trace_id", "from", "until", "cursor", "limit",
	) {
		handler.invalidQuery(writer, traceID)
		return
	}
	query := investigationstore.AuditQuery{}
	var err error
	if query.IncidentID, err = optionalSingle(values, "incident_id"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.PolicyID, err = optionalSingle(values, "policy_id"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.ActionID, err = optionalSingle(values, "action_id"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.ActorType, err = optionalSingle(values, "actor_type"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.ActorID, err = optionalSingle(values, "actor_id"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.ObjectType, err = optionalSingle(values, "object_type"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.ObjectID, err = optionalSingle(values, "object_id"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.TraceID, err = optionalSingle(values, "trace_id"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.From, err = optionalTime(values, "from"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.Until, err = optionalTime(values, "until"); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if query.Limit, err = optionalLimit(values); err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	cursor, err := optionalSingle(values, "cursor")
	if err != nil {
		handler.invalidQuery(writer, traceID)
		return
	}
	if cursor != "" {
		if len(cursor) > 128 {
			handler.invalidQuery(writer, traceID)
			return
		}
		query.Cursor, err = investigationstore.ParseAuditCursor(cursor)
		if err != nil {
			handler.invalidQuery(writer, traceID)
			return
		}
	}
	page, err := handler.reader.ListAuditEvents(request.Context(), query)
	handler.writeStoreResult(writer, traceID, page, err)
}

func (handler *Handler) writeStoreResult(writer http.ResponseWriter, traceID string, value any, err error) {
	if err == nil {
		writeJSON(writer, http.StatusOK, value)
		return
	}
	switch {
	case errors.Is(err, investigationstore.ErrInvalidArgument):
		writeError(writer, http.StatusBadRequest, "schema_invalid", traceID)
	case errors.Is(err, investigationstore.ErrNotFound):
		writeError(writer, http.StatusNotFound, "not_found", traceID)
	default:
		writer.Header().Set("Retry-After", "1")
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable", traceID)
	}
}

func (handler *Handler) invalidQuery(writer http.ResponseWriter, traceID string) {
	writeError(writer, http.StatusBadRequest, "schema_invalid", traceID)
}

func matchRoute(path string) matchedRoute {
	switch path {
	case "/api/v1/incidents":
		return matchedRoute{kind: routeIncidentList}
	case "/api/v1/audit-events":
		return matchedRoute{kind: routeAuditList}
	case "/api/v1/events/stream":
		return matchedRoute{kind: routeStream}
	}
	for prefix, kind := range map[string]routeKind{
		"/api/v1/policies/":            routePolicyDetail,
		"/api/v1/enforcement-actions/": routeActionDetail,
	} {
		if strings.HasPrefix(path, prefix) {
			id := strings.TrimPrefix(path, prefix)
			if uuidPattern.MatchString(id) {
				return matchedRoute{kind: kind, id: id}
			}
			return matchedRoute{}
		}
	}
	const incidentPrefix = "/api/v1/incidents/"
	if strings.HasPrefix(path, incidentPrefix) {
		rest := strings.TrimPrefix(path, incidentPrefix)
		if strings.HasSuffix(rest, "/events") {
			id := strings.TrimSuffix(rest, "/events")
			if uuidPattern.MatchString(id) {
				return matchedRoute{kind: routeIncidentEvents, id: id}
			}
			return matchedRoute{}
		}
		if uuidPattern.MatchString(rest) {
			return matchedRoute{kind: routeIncidentDetail, id: rest}
		}
	}
	return matchedRoute{}
}

func strictQuery(raw string) (url.Values, error) {
	if len(raw) > maxRawQueryBytes {
		return nil, errors.New("query too long")
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	for key, list := range values {
		if key == "" || len(key) > 32 || len(list) != 1 || len(list[0]) > 512 ||
			list[0] == "" || strings.TrimSpace(list[0]) != list[0] {
			return nil, errors.New("invalid query")
		}
	}
	return values, nil
}

func onlyKeys(values url.Values, keys ...string) bool {
	allowed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		allowed[key] = struct{}{}
	}
	for key := range values {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	return true
}

func optionalSingle(values url.Values, key string) (string, error) {
	list, ok := values[key]
	if !ok {
		return "", nil
	}
	if len(list) != 1 || list[0] == "" {
		return "", errors.New("invalid single value")
	}
	return list[0], nil
}

func optionalLimit(values url.Values) (int, error) {
	value, err := optionalSingle(values, "limit")
	if err != nil || value == "" {
		return 0, err
	}
	if !decimalPattern.MatchString(value) {
		return 0, errors.New("invalid limit")
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed > investigationstore.MaxPageLimit {
		return 0, errors.New("invalid limit")
	}
	return parsed, nil
}

func optionalTime(values url.Values, key string) (*time.Time, error) {
	value, err := optionalSingle(values, key)
	if err != nil || value == "" {
		return nil, err
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Year() < 2000 || parsed.Year() > 9999 {
		return nil, errors.New("invalid time")
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func hasRequestBody(request *http.Request) bool {
	return request.ContentLength > 0 || len(request.TransferEncoding) != 0 ||
		request.ContentLength < 0 && request.Body != nil && request.Body != http.NoBody ||
		request.Header.Get("Content-Type") != "" || request.Header.Get("Content-Encoding") != ""
}

func accepts(headers []string, wanted string) bool {
	if len(headers) == 0 {
		return true
	}
	if len(headers) != 1 || len(headers[0]) > 512 {
		return false
	}
	parts := strings.Split(headers[0], ",")
	if len(parts) > 8 {
		return false
	}
	accepted := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		mediaType, parameters, err := mime.ParseMediaType(part)
		if err != nil {
			return false
		}
		quality := 1.0
		for key, value := range parameters {
			if key != "q" {
				return false
			}
			quality, err = strconv.ParseFloat(value, 64)
			if err != nil || math.IsNaN(quality) || math.IsInf(quality, 0) || quality < 0 || quality > 1 {
				return false
			}
		}
		if quality > 0 && (mediaType == wanted || mediaType == "*/*" ||
			wanted == "application/json" && mediaType == "application/*") {
			accepted = true
		}
	}
	return accepted
}

func setCommonHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")
}

func writeError(writer http.ResponseWriter, status int, code, traceID string) {
	if !registeredAPIErrorCode(code) {
		code = "internal_error"
	}
	if !uuidPattern.MatchString(traceID) {
		traceID = newTraceID()
	}
	messages := map[int]string{
		http.StatusBadRequest:         "request could not be processed",
		http.StatusUnauthorized:       "authentication is required",
		http.StatusNotFound:           "resource was not found",
		http.StatusMethodNotAllowed:   "method is not allowed",
		http.StatusNotAcceptable:      "requested representation is not available",
		http.StatusConflict:           "requested replay is no longer available",
		http.StatusServiceUnavailable: "service is temporarily unavailable",
	}
	message := messages[status]
	if message == "" {
		message = "request failed"
	}
	writeJSON(writer, status, errorResponse{
		Code: code, Message: message, TraceID: traceID, Details: map[string]string{},
	})
}

func registeredAPIErrorCode(code string) bool {
	switch code {
	case "authentication_required", "permission_denied", "csrf_invalid", "step_up_required",
		"rate_limited", "stale_version", "digest_mismatch", "challenge_expired",
		"challenge_consumed", "idempotency_conflict", "validation_failed", "schema_invalid",
		"not_found", "service_unavailable", "internal_error":
		return true
	default:
		return false
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}

func newTraceID() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		binary.BigEndian.PutUint64(value[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(value[8:], traceIDFallbackCounter.Add(1))
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	raw := hex.EncodeToString(value)
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
}

func newStrictRandomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	raw := hex.EncodeToString(value)
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:], nil
}
