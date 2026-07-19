// Package demoapp implements the private synthetic origin used by the
// Gateway-first demo. It emits only privacy-minimized authentication events.
package demoapp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
)

const (
	maxLoginBodyBytes = 4096
	serviceLabel      = "demo-app"
	loginRouteLabel   = "login"
)

var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	accountPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	ErrInvalid     = errors.New("demo origin configuration is invalid")
)

type AuthEventSink interface {
	TryEnqueue(events.AuthEventV1) events.EnqueueResult
}

type Config struct {
	GatewayPeerCIDRs []netip.Prefix
	AccountHashKey   []byte
	Sink             AuthEventSink
	Clock            func() time.Time
	NewID            func() (string, error)
}

type Handler struct {
	gatewayPeers   []netip.Prefix
	accountHashKey []byte
	sink           AuthEventSink
	clock          func() time.Time
	newID          func() (string, error)
	errorSequence  atomic.Uint64
}

func New(config Config) (*Handler, error) {
	if config.Sink == nil || len(config.AccountHashKey) < 32 || len(config.AccountHashKey) > 128 ||
		len(config.GatewayPeerCIDRs) == 0 || len(config.GatewayPeerCIDRs) > 32 {
		return nil, ErrInvalid
	}
	peers := make([]netip.Prefix, len(config.GatewayPeerCIDRs))
	for index, prefix := range config.GatewayPeerCIDRs {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() < 24 {
			return nil, ErrInvalid
		}
		for _, existing := range peers[:index] {
			if existing == prefix || existing.Overlaps(prefix) {
				return nil, ErrInvalid
			}
		}
		peers[index] = prefix
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	if config.NewID == nil {
		config.NewID = newUUID
	}
	return &Handler{
		gatewayPeers:   peers,
		accountHashKey: bytes.Clone(config.AccountHashKey),
		sink:           config.Sink,
		clock:          config.Clock,
		newID:          config.NewID,
	}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if h == nil || request == nil || !h.gatewayPeerAllowed(request.RemoteAddr) {
		writeResponse(writer, http.StatusForbidden, `{"status":"forbidden"}`)
		return
	}

	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/health":
		writeResponse(writer, http.StatusOK, `{"status":"ok"}`)
	case request.Method == http.MethodGet && (request.URL.Path == "/" || request.URL.Path == "/products" ||
		request.URL.Path == "/products/featured" || request.URL.Path == "/account"):
		writeResponse(writer, http.StatusOK, `{"status":"ok","service":"demo-app"}`)
	case request.Method == http.MethodGet && request.URL.Path == "/demo/intermittent-error":
		if h.errorSequence.Add(1)%2 == 1 {
			writeResponse(writer, http.StatusServiceUnavailable, `{"status":"temporarily_unavailable"}`)
		} else {
			writeResponse(writer, http.StatusOK, `{"status":"recovered"}`)
		}
	case request.Method == http.MethodPost && request.URL.Path == "/login":
		h.handleLogin(writer, request)
	default:
		writeResponse(writer, http.StatusNotFound, `{"status":"not_found"}`)
	}
}

func (h *Handler) handleLogin(writer http.ResponseWriter, request *http.Request) {
	sourceIP, requestID, traceID, ok := gatewayMetadata(request)
	if !ok || request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
		request.ContentLength > maxLoginBodyBytes {
		writeResponse(writer, http.StatusBadRequest, `{"status":"invalid_request"}`)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxLoginBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxLoginBodyBytes {
		writeResponse(writer, http.StatusBadRequest, `{"status":"invalid_request"}`)
		return
	}
	values, err := url.ParseQuery(string(body))
	account, password, valid := exactLoginFields(values)
	if err != nil || !valid || !accountPattern.MatchString(account) || len(password) > 128 {
		writeResponse(writer, http.StatusBadRequest, `{"status":"invalid_request"}`)
		return
	}

	// Every checked-in simulator credential is deliberately invalid. The demo
	// origin has no real credential database and never stores either field.
	outcome := events.AuthOutcomeFailed
	accountHash := h.accountHash(account)
	eventID, err := h.newID()
	if err != nil || !uuidPattern.MatchString(eventID) {
		writeResponse(writer, http.StatusServiceUnavailable, `{"status":"temporarily_unavailable"}`)
		return
	}
	occurredAt, err := events.NewTimestamp(h.clock().UTC())
	if err != nil {
		writeResponse(writer, http.StatusServiceUnavailable, `{"status":"temporarily_unavailable"}`)
		return
	}
	event := events.AuthEventV1{
		SchemaVersion:    events.AuthEventV1Schema,
		EventID:          eventID,
		GatewayRequestID: requestID,
		TraceID:          traceID,
		IdempotencyKey:   authIdempotencyKey(requestID, traceID, sourceIP, accountHash, outcome),
		OccurredAt:       occurredAt,
		SourceIP:         sourceIP,
		ServiceLabel:     serviceLabel,
		RouteLabel:       loginRouteLabel,
		AccountHash:      accountHash,
		Outcome:          outcome,
	}
	if event.Validate() != nil {
		writeResponse(writer, http.StatusServiceUnavailable, `{"status":"temporarily_unavailable"}`)
		return
	}
	_ = h.sink.TryEnqueue(event)
	writeResponse(writer, http.StatusUnauthorized, `{"status":"authentication_failed"}`)
}

func (h *Handler) gatewayPeerAllowed(remoteAddress string) bool {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	address = address.Unmap()
	if !address.Is4() {
		return false
	}
	for _, prefix := range h.gatewayPeers {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func gatewayMetadata(request *http.Request) (string, string, string, bool) {
	forwarded := request.Header.Values("X-Forwarded-For")
	requestIDs := request.Header.Values("X-SentinelFlow-Request-ID")
	traceIDs := request.Header.Values("X-SentinelFlow-Trace-ID")
	if len(forwarded) != 1 || len(requestIDs) != 1 || len(traceIDs) != 1 ||
		strings.Contains(forwarded[0], ",") || !uuidPattern.MatchString(requestIDs[0]) || !uuidPattern.MatchString(traceIDs[0]) {
		return "", "", "", false
	}
	address, err := netip.ParseAddr(forwarded[0])
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.String() != forwarded[0] {
		return "", "", "", false
	}
	return address.String(), requestIDs[0], traceIDs[0], true
}

func exactLoginFields(values url.Values) (string, string, bool) {
	if len(values) != 2 || len(values["account"]) != 1 || len(values["password"]) != 1 {
		return "", "", false
	}
	account := values["account"][0]
	password := values["password"][0]
	if account == "" || password != "synthetic-demo-input" {
		return "", "", false
	}
	return account, password, true
}

func (h *Handler) accountHash(account string) string {
	hash := hmac.New(sha256.New, h.accountHashKey)
	_, _ = hash.Write([]byte("sentinelflow:demo-account:v1\x00"))
	_, _ = hash.Write([]byte(account))
	return "hmac-sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func authIdempotencyKey(requestID, traceID, sourceIP, accountHash string, outcome events.AuthOutcome) string {
	hash := sha256.New()
	for _, value := range []string{"sentinelflow:auth-event:v1", requestID, traceID, sourceIP, accountHash, string(outcome)} {
		_, _ = hash.Write([]byte{byte(len(value) >> 8), byte(len(value))})
		_, _ = hash.Write([]byte(value))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func writeResponse(writer http.ResponseWriter, status int, body string) {
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body+"\n")
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", errors.New("generate demo event identity")
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func (h *Handler) String() string { return "demoapp-handler{private-gateway-origin}" }
