package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/api"
	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
)

const (
	endpointGateway = "gateway"
	endpointAuth    = "auth"

	recordFutureSkew = 60 * time.Second
	recordPastSkew   = 5 * time.Minute
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type preparedBatch struct {
	endpointKind  string
	nonceDigest   string
	receivedAt    time.Time
	authenticated ingestion.AuthenticatedBatch
}

func prepareBatch(endpointPath string, authenticated ingestion.AuthenticatedBatch, receivedAt time.Time) (preparedBatch, error) {
	endpointKind, ok := endpointKind(endpointPath)
	if !ok {
		return preparedBatch{}, rejected(errors.New("unsupported ingest endpoint"))
	}
	if receivedAt.IsZero() || authenticated.AuthenticatedAt.IsZero() {
		return preparedBatch{}, rejected(errors.New("missing security timestamp"))
	}
	if authenticated.RawBodySize < 2 || authenticated.RawBodySize > events.MaxEventBatchBodyBytes {
		return preparedBatch{}, rejected(ErrExactRawBodySizeRequired)
	}
	if !digestPattern.MatchString(authenticated.BodyDigest) {
		return preparedBatch{}, rejected(errors.New("invalid authenticated body digest"))
	}
	if authenticated.KeyID != "" && !registryKeyPattern.MatchString(authenticated.KeyID) {
		return preparedBatch{}, rejected(errors.New("invalid authenticated key identity"))
	}
	if err := authenticated.Batch.Validate(); err != nil {
		return preparedBatch{}, rejected(errors.New("invalid authenticated batch contract"))
	}
	if !recordsMatchEndpoint(endpointPath, authenticated.Batch) {
		return preparedBatch{}, rejected(errors.New("record type does not match authenticated endpoint"))
	}

	receivedAt = receivedAt.UTC()
	authenticated.AuthenticatedAt = authenticated.AuthenticatedAt.UTC()
	if delta := receivedAt.Sub(authenticated.AuthenticatedAt); delta > recordFutureSkew || delta < -recordFutureSkew {
		return preparedBatch{}, rejected(errors.New("authenticated receipt time mismatch"))
	}

	return preparedBatch{
		endpointKind:  endpointKind,
		nonceDigest:   "sha256:" + hex.EncodeToString(authenticated.ReplayNonceDigest[:]),
		receivedAt:    receivedAt,
		authenticated: authenticated,
	}, nil
}

func recordsMatchEndpoint(endpointPath string, batch events.EventBatchV1) bool {
	for _, record := range batch.Records {
		switch endpointPath {
		case ingestion.GatewayEventsPath:
			if record.GatewayHTTP == nil && record.SourceHealth == nil && record.SourceCoverage == nil {
				return false
			}
		case ingestion.AuthEventsPath:
			if record.AuthEvent == nil && record.SourceHealth == nil && record.SourceCoverage == nil {
				return false
			}
		default:
			return false
		}
		if record.SourceHealth != nil && record.SourceHealth.SourceID != batch.SenderID {
			return false
		}
		if record.SourceCoverage != nil && record.SourceCoverage.SourceID != batch.SenderID {
			return false
		}
	}
	return true
}

func endpointKind(endpointPath string) (string, bool) {
	switch endpointPath {
	case ingestion.GatewayEventsPath:
		return endpointGateway, true
	case ingestion.AuthEventsPath:
		return endpointAuth, true
	default:
		return "", false
	}
}

func recordTrust(record events.EventRecordV1, receivedAt time.Time) (state, reason string) {
	timestamps := make([]time.Time, 0, 4)
	switch {
	case record.GatewayHTTP != nil:
		timestamps = append(timestamps,
			record.GatewayHTTP.StartedAt.Time(),
			record.GatewayHTTP.CompletedAt.Time(),
		)
	case record.AuthEvent != nil:
		timestamps = append(timestamps, record.AuthEvent.OccurredAt.Time())
	case record.SourceHealth != nil:
		timestamps = append(timestamps, record.SourceHealth.OccurredAt.Time())
	case record.SourceCoverage != nil:
		timestamps = append(timestamps,
			record.SourceCoverage.CoverageStart.Time(),
			record.SourceCoverage.CoverageEnd.Time(),
		)
	}
	for _, timestamp := range timestamps {
		if timestamp.After(receivedAt.Add(recordFutureSkew)) || timestamp.Before(receivedAt.Add(-recordPastSkew)) {
			return "untrusted", "timestamp_skew"
		}
	}
	return "trusted", "none"
}

type outboxIdentity struct {
	jobID          string
	idempotencyKey string
}

func batchOutboxIdentity(batch events.EventBatchV1) outboxIdentity {
	var canonical strings.Builder
	canonical.WriteString("sentinelflow ingest detect outbox v1\n")
	canonical.WriteString(batch.SenderID)
	canonical.WriteByte('\n')
	canonical.WriteString(batch.SenderEpoch)
	canonical.WriteByte('\n')
	canonical.WriteString(batch.BatchID)
	canonical.WriteByte('\n')
	sum := sha256.Sum256([]byte(canonical.String()))
	return outboxIdentity{
		jobID:          uuidV8FromDigest(sum),
		idempotencyKey: "sha256:" + hex.EncodeToString(sum[:]),
	}
}

func uuidV8FromDigest(sum [sha256.Size]byte) string {
	value := [16]byte{}
	copy(value[:], sum[:16])
	value[6] = (value[6] & 0x0f) | 0x80
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

func rejected(cause error) error {
	return fmt.Errorf("%w: %w", api.ErrBatchRejected, cause)
}
