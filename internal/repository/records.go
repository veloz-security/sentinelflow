package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/events"
)

func lockSenderIngest(ctx context.Context, tx pgx.Tx, senderID, endpointKind string) error {
	var ignored any
	return tx.QueryRow(ctx, lockSenderIngestSQL, senderID, endpointKind).Scan(&ignored)
}

func insertRecord(ctx context.Context, tx pgx.Tx, prepared preparedBatch, record events.EventRecordV1, ordinal int) error {
	batch := prepared.authenticated.Batch
	trustState, trustReason := recordTrust(record, prepared.receivedAt)
	switch {
	case record.GatewayHTTP != nil:
		event := record.GatewayHTTP
		_, err := tx.Exec(ctx, insertGatewayEventSQL,
			event.EventID,
			batch.SenderID,
			batch.SenderEpoch,
			batch.BatchID,
			event.IdempotencyKey,
			event.RequestID,
			event.TraceID,
			event.StartedAt.Time(),
			event.CompletedAt.Time(),
			event.SourceIP,
			event.Method,
			event.RouteLabel,
			string(event.SuspiciousPathID),
			event.Host,
			event.ServiceLabel,
			event.StatusCode,
			int64(event.RequestBytes),
			int64(event.ResponseBytes),
			int32(event.LatencyMS),
			prepared.receivedAt,
			trustState,
			trustReason,
		)
		return err
	case record.AuthEvent != nil:
		event := record.AuthEvent
		_, err := tx.Exec(ctx, insertAuthEventSQL,
			event.EventID,
			batch.SenderID,
			batch.SenderEpoch,
			batch.BatchID,
			event.IdempotencyKey,
			event.GatewayRequestID,
			event.TraceID,
			event.OccurredAt.Time(),
			event.SourceIP,
			event.ServiceLabel,
			event.RouteLabel,
			event.AccountHash,
			string(event.Outcome),
			prepared.receivedAt,
			trustState,
			trustReason,
			prepared.receivedAt.Add(5*time.Minute),
		)
		return err
	case record.SourceHealth != nil:
		event := record.SourceHealth
		_, err := tx.Exec(ctx, insertSourceHealthSQL,
			event.EventID,
			batch.SenderID,
			batch.SenderEpoch,
			batch.BatchID,
			event.IdempotencyKey,
			event.OccurredAt.Time(),
			event.SourceID,
			string(event.Cause),
			string(event.State),
			event.AffectedSenderEpoch,
			uint64OrNil(event.SequenceStart),
			uint64OrNil(event.SequenceEnd),
			timeOrNil(event.IntervalStart),
			timeOrNil(event.IntervalEnd),
			int64(event.DroppedCount),
			string(event.DetailCode),
			prepared.receivedAt,
			trustState,
			trustReason,
		)
		return err
	case record.SourceCoverage != nil:
		event := record.SourceCoverage
		previousDigest := ""
		if event.PreviousCoverageDigest != nil {
			previousDigest = *event.PreviousCoverageDigest
		}
		expectedDigest, err := event.Digest()
		if err != nil {
			return err
		}
		var storedEventID, storedDigest string
		err = tx.QueryRow(ctx, insertSourceCoverageSQL,
			event.EventID,
			event.IdempotencyKey,
			batch.SenderID,
			prepared.endpointKind,
			batch.SenderEpoch,
			event.SegmentID,
			previousDigest,
			event.CoverageStart.Time(),
			event.CoverageEnd.Time(),
			batch.BatchID,
			int64(batch.Sequence),
			ordinal,
			trustState,
			trustReason,
		).Scan(&storedEventID, &storedDigest)
		if err != nil {
			return err
		}
		if storedEventID != event.EventID || storedDigest != expectedDigest {
			return errors.New("repository: source coverage persistence digest mismatch")
		}
		return nil
	default:
		return errors.New("repository: invalid event record variant")
	}
}

func resolveAuthenticatedGapLosses(ctx context.Context, tx pgx.Tx, prepared preparedBatch) error {
	batch := prepared.authenticated.Batch
	for _, record := range batch.Records {
		health := record.SourceHealth
		if health == nil || health.SequenceStart == nil || health.SequenceEnd == nil {
			continue
		}
		trustState, _ := recordTrust(record, prepared.receivedAt)
		if trustState != "trusted" ||
			health.SourceID != batch.SenderID ||
			health.Cause != events.SourceHealthPermanentLoss ||
			health.State != events.SourceHealthStateLost ||
			health.DetailCode != events.SourceHealthDetailKnownRange ||
			health.DroppedCount != *health.SequenceEnd-*health.SequenceStart+1 {
			continue
		}

		var matches bool
		if err := tx.QueryRow(ctx, matchingUnresolvedGapSQL,
			batch.SenderID,
			prepared.endpointKind,
			health.AffectedSenderEpoch,
			int64(*health.SequenceStart),
			int64(*health.SequenceEnd),
		).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			continue
		}
		if _, err := tx.Exec(ctx, resolveIngestGapAsLostSQL, health.EventID); err != nil {
			return err
		}
	}
	return nil
}

func uint64OrNil(value *uint64) any {
	if value == nil {
		return nil
	}
	return int64(*value)
}

func timeOrNil(value *events.Timestamp) any {
	if value == nil {
		return nil
	}
	return value.Time()
}
