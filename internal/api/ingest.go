// Package api implements SentinelFlow's typed HTTP control-plane boundaries.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
)

var (
	ErrBatchConflict    = errors.New("event batch conflicts with an existing receipt")
	ErrBatchRejected    = errors.New("event batch rejected by the atomic store")
	ErrStoreUnavailable = errors.New("event batch store unavailable")
)

type StoreOutcome string

const (
	StoreAccepted  StoreOutcome = "accepted"
	StoreDuplicate StoreOutcome = "duplicate"
)

// BatchStore owns the atomic receiver transaction. A successful call has
// inserted the authenticated nonce, batch receipt, every record, gap/source
// health state, and outbox effects together, or recognized an exact duplicate.
// No partial success is representable.
type BatchStore interface {
	StoreBatch(context.Context, string, ingestion.AuthenticatedBatch, time.Time) (StoreOutcome, error)
}

type IngestConfig struct {
	Registry *ingestion.Registry
	Store    BatchStore
	Clock    func() time.Time
}

type IngestHandler struct {
	registry *ingestion.Registry
	store    BatchStore
	clock    func() time.Time
}

type batchAcknowledgement struct {
	Status      StoreOutcome `json:"status"`
	SenderID    string       `json:"sender_id"`
	SenderEpoch string       `json:"sender_epoch"`
	BatchID     string       `json:"batch_id"`
	Sequence    uint64       `json:"sequence"`
	BodyDigest  string       `json:"body_digest"`
}

type internalError struct {
	Code string `json:"code"`
}

func NewIngestHandler(config IngestConfig) (*IngestHandler, error) {
	if config.Registry == nil || config.Store == nil {
		return nil, errors.New("api: ingest registry and atomic store are required")
	}
	if config.Clock == nil {
		config.Clock = func() time.Time { return time.Now().UTC() }
	}
	return &IngestHandler{registry: config.Registry, store: config.Store, clock: config.Clock}, nil
}

func (h *IngestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if request.URL == nil || (request.URL.Path != ingestion.GatewayEventsPath && request.URL.Path != ingestion.AuthEventsPath) {
		h.writeError(writer, http.StatusNotFound, "not_found")
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		h.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if request.Header.Get("Content-Encoding") != "" || !validJSONContentType(request.Header.Get("Content-Type")) {
		h.writeError(writer, http.StatusUnprocessableEntity, "invalid_content_type")
		return
	}
	headers, err := authenticationHeaders(request.Header)
	if err != nil {
		h.writeError(writer, http.StatusUnprocessableEntity, "invalid_authentication")
		return
	}
	if request.ContentLength > events.MaxEventBatchBodyBytes {
		h.writeError(writer, http.StatusUnprocessableEntity, "invalid_batch")
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, events.MaxEventBatchBodyBytes+1))
	if err != nil || len(body) > events.MaxEventBatchBodyBytes {
		h.writeError(writer, http.StatusUnprocessableEntity, "invalid_batch")
		return
	}
	now := h.clock().UTC()
	authenticated, err := h.registry.Authenticate(request.URL.Path, headers, body, now)
	if err != nil {
		h.writeError(writer, http.StatusUnprocessableEntity, "invalid_batch")
		return
	}
	outcome, err := h.store.StoreBatch(request.Context(), request.URL.Path, authenticated, now)
	if err != nil {
		switch {
		case errors.Is(err, ErrBatchConflict):
			h.writeError(writer, http.StatusConflict, "batch_conflict")
		case errors.Is(err, ErrBatchRejected):
			h.writeError(writer, http.StatusUnprocessableEntity, "invalid_batch")
		default:
			h.writeError(writer, http.StatusServiceUnavailable, "store_unavailable")
		}
		return
	}
	if outcome != StoreAccepted && outcome != StoreDuplicate {
		h.writeError(writer, http.StatusServiceUnavailable, "store_unavailable")
		return
	}
	batch := authenticated.Batch
	h.writeJSON(writer, http.StatusAccepted, batchAcknowledgement{
		Status:      outcome,
		SenderID:    batch.SenderID,
		SenderEpoch: batch.SenderEpoch,
		BatchID:     batch.BatchID,
		Sequence:    batch.Sequence,
		BodyDigest:  authenticated.BodyDigest,
	})
}

func authenticationHeaders(header http.Header) (ingestion.Headers, error) {
	sender, err := singleHeader(header, "X-Sentinel-Sender-ID")
	if err != nil {
		return ingestion.Headers{}, err
	}
	timestamp, err := singleHeader(header, "X-Sentinel-Timestamp")
	if err != nil {
		return ingestion.Headers{}, err
	}
	nonce, err := singleHeader(header, "X-Sentinel-Nonce")
	if err != nil {
		return ingestion.Headers{}, err
	}
	signature, err := singleHeader(header, "X-Sentinel-Signature")
	if err != nil {
		return ingestion.Headers{}, err
	}
	return ingestion.Headers{SenderID: sender, Timestamp: timestamp, Nonce: nonce, Signature: signature}, nil
}

func singleHeader(header http.Header, name string) (string, error) {
	values := header.Values(name)
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] || strings.Contains(values[0], ",") {
		return "", errors.New("api: invalid internal authentication header")
	}
	return values[0], nil
}

func validJSONContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json" && len(parameters) == 0
}

func (h *IngestHandler) writeError(writer http.ResponseWriter, status int, code string) {
	h.writeJSON(writer, status, internalError{Code: code})
}

func (h *IngestHandler) writeJSON(writer http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(payload, '\n'))
}
