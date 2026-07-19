package events

import "encoding/json"

type gatewayHTTPV1JSON GatewayHTTPV1
type authEventV1JSON AuthEventV1
type sourceHealthV1JSON SourceHealthV1
type eventBatchV1JSON EventBatchV1

func (e GatewayHTTPV1) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(gatewayHTTPV1JSON(e))
}

func (e *GatewayHTTPV1) UnmarshalJSON(data []byte) error {
	decoded, err := DecodeGatewayHTTPV1(data)
	if err != nil {
		return err
	}
	*e = decoded
	return nil
}

func (e AuthEventV1) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(authEventV1JSON(e))
}

func (e *AuthEventV1) UnmarshalJSON(data []byte) error {
	decoded, err := DecodeAuthEventV1(data)
	if err != nil {
		return err
	}
	*e = decoded
	return nil
}

func (e SourceHealthV1) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(sourceHealthV1JSON(e))
}

func (e *SourceHealthV1) UnmarshalJSON(data []byte) error {
	decoded, err := DecodeSourceHealthV1(data)
	if err != nil {
		return err
	}
	*e = decoded
	return nil
}

func (e SourceCoverageV1) MarshalJSON() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		SchemaVersion          string  `json:"schema_version"`
		EventID                string  `json:"event_id"`
		IdempotencyKey         string  `json:"idempotency_key"`
		SourceID               string  `json:"source_id"`
		AffectedSenderEpoch    string  `json:"affected_sender_epoch"`
		SegmentID              string  `json:"segment_id"`
		PreviousCoverageDigest *string `json:"previous_coverage_digest"`
		CoverageStart          string  `json:"coverage_start"`
		CoverageEnd            string  `json:"coverage_end"`
		CoveredThroughBatchID  string  `json:"covered_through_batch_id"`
		CoveredThroughSequence uint64  `json:"covered_through_sequence"`
		State                  string  `json:"state"`
	}{
		SchemaVersion:          e.SchemaVersion,
		EventID:                e.EventID,
		IdempotencyKey:         e.IdempotencyKey,
		SourceID:               e.SourceID,
		AffectedSenderEpoch:    e.AffectedSenderEpoch,
		SegmentID:              e.SegmentID,
		PreviousCoverageDigest: e.PreviousCoverageDigest,
		CoverageStart:          e.CoverageStart.Time().Format(coverageTimestampLayout),
		CoverageEnd:            e.CoverageEnd.Time().Format(coverageTimestampLayout),
		CoveredThroughBatchID:  e.CoveredThroughBatchID,
		CoveredThroughSequence: e.CoveredThroughSequence,
		State:                  e.State,
	})
}

func (e *SourceCoverageV1) UnmarshalJSON(data []byte) error {
	decoded, err := DecodeSourceCoverageV1(data)
	if err != nil {
		return err
	}
	*e = decoded
	return nil
}

func (r EventRecordV1) MarshalJSON() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	switch {
	case r.GatewayHTTP != nil:
		return json.Marshal(r.GatewayHTTP)
	case r.AuthEvent != nil:
		return json.Marshal(r.AuthEvent)
	case r.SourceHealth != nil:
		return json.Marshal(r.SourceHealth)
	default:
		return json.Marshal(r.SourceCoverage)
	}
}

func (r *EventRecordV1) UnmarshalJSON(data []byte) error {
	decoded, err := DecodeEventRecordV1(data)
	if err != nil {
		return err
	}
	*r = decoded
	return nil
}

func (b EventBatchV1) MarshalJSON() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(eventBatchV1JSON(b))
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxEventBatchBodyBytes {
		return nil, fieldError("$", ErrorTooLarge, "batch body exceeds 256 KiB")
	}
	return encoded, nil
}

func (b *EventBatchV1) UnmarshalJSON(data []byte) error {
	decoded, err := DecodeEventBatchV1(data)
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}
