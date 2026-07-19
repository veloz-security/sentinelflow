package events

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

const coverageTimestampLayout = "2006-01-02T15:04:05.000Z"

// NewSourceCoverageV1 creates the deterministic marker for one exact batch.
// The event identity is derived from the containing batch so rebuilding a
// not-yet-sent batch cannot fork the coverage chain.
func NewSourceCoverageV1(
	sourceID, senderEpoch, segmentID string,
	previousDigest *string,
	coverageStart, coverageEnd time.Time,
	batchID string,
	sequence uint64,
) (SourceCoverageV1, error) {
	identity := sha256.Sum256([]byte(
		SourceCoverageV1Schema + "\n" + sourceID + "\n" + senderEpoch + "\n" + batchID + "\n",
	))
	eventID := uuidV8FromCoverageDigest(identity)
	coverageStart = coverageStart.UTC()
	coverageEnd = coverageEnd.UTC()
	if !coverageStart.Equal(coverageStart.Truncate(time.Millisecond)) ||
		!coverageEnd.Equal(coverageEnd.Truncate(time.Millisecond)) {
		return SourceCoverageV1{}, fmt.Errorf("source coverage timestamps must have millisecond precision")
	}
	start, err := NewTimestamp(coverageStart)
	if err != nil {
		return SourceCoverageV1{}, err
	}
	end, err := NewTimestamp(coverageEnd)
	if err != nil {
		return SourceCoverageV1{}, err
	}
	event := SourceCoverageV1{
		SchemaVersion:          SourceCoverageV1Schema,
		EventID:                eventID,
		IdempotencyKey:         "sha256:" + hex.EncodeToString(identity[:]),
		SourceID:               sourceID,
		AffectedSenderEpoch:    senderEpoch,
		SegmentID:              segmentID,
		PreviousCoverageDigest: previousDigest,
		CoverageStart:          start,
		CoverageEnd:            end,
		CoveredThroughBatchID:  batchID,
		CoveredThroughSequence: sequence,
		State:                  "complete",
	}
	if err := event.Validate(); err != nil {
		return SourceCoverageV1{}, err
	}
	return event, nil
}

// CoverageSegmentID derives a UUIDv8-shaped segment identifier from a random
// epoch and an authenticated reset token such as the accepted health batch ID.
func CoverageSegmentID(sourceID, senderEpoch, resetToken string) string {
	sum := sha256.Sum256([]byte(
		"source-coverage-segment-v1\n" + sourceID + "\n" + senderEpoch + "\n" + resetToken + "\n",
	))
	return uuidV8FromCoverageDigest(sum)
}

func uuidV8FromCoverageDigest(sum [sha256.Size]byte) string {
	value := [16]byte{}
	copy(value[:], sum[:16])
	value[6] = (value[6] & 0x0f) | 0x80
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

// CanonicalBytes returns the RFC 8785/JCS representation used by the coverage
// chain. SourceCoverageV1 contains only strings, a safe integer, and null, so
// this explicit sorted-key encoder covers the complete admitted value space.
func (e SourceCoverageV1) CanonicalBytes() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	result := make([]byte, 0, 768)
	result = append(result, '{')
	result = appendJCSField(result, "affected_sender_epoch", e.AffectedSenderEpoch, true)
	result = appendJCSField(result, "coverage_end", e.CoverageEnd.Time().UTC().Format(coverageTimestampLayout), true)
	result = appendJCSField(result, "coverage_start", e.CoverageStart.Time().UTC().Format(coverageTimestampLayout), true)
	result = appendJCSField(result, "covered_through_batch_id", e.CoveredThroughBatchID, true)
	result = append(result, `"covered_through_sequence":`...)
	result = strconv.AppendUint(result, e.CoveredThroughSequence, 10)
	result = append(result, ',')
	result = appendJCSField(result, "event_id", e.EventID, true)
	result = appendJCSField(result, "idempotency_key", e.IdempotencyKey, true)
	result = append(result, `"previous_coverage_digest":`...)
	if e.PreviousCoverageDigest == nil {
		result = append(result, "null"...)
	} else {
		result = strconv.AppendQuote(result, *e.PreviousCoverageDigest)
	}
	result = append(result, ',')
	result = appendJCSField(result, "schema_version", e.SchemaVersion, true)
	result = appendJCSField(result, "segment_id", e.SegmentID, true)
	result = appendJCSField(result, "source_id", e.SourceID, true)
	result = appendJCSField(result, "state", e.State, false)
	result = append(result, '}')
	return result, nil
}

// Digest binds the exact canonical coverage record. It deliberately excludes
// containing-batch bytes; persistence separately binds this digest to the
// authenticated raw-body digest and receiver timestamp.
func (e SourceCoverageV1) Digest() (string, error) {
	canonical, err := e.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func appendJCSField(destination []byte, key, value string, comma bool) []byte {
	destination = strconv.AppendQuote(destination, key)
	destination = append(destination, ':')
	destination = strconv.AppendQuote(destination, value)
	if comma {
		destination = append(destination, ',')
	}
	return destination
}
