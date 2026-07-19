package demohistory

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/events"
)

const (
	eventsMaxSafeInteger = uint64(9_007_199_254_740_991)
	coverageDuration     = 24 * time.Hour
	coverageTimeLayout   = "2006-01-02T15:04:05.000Z"
)

var (
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	senderIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	senderEpochPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
)

var datasetFields = []string{
	"schema_version", "dataset_id", "path_catalog_version", "coverage_start",
	"coverage_end", "records", "source_health",
}

var sourceCoverageFields = []string{
	"sender_id", "sender_epoch", "coverage_start", "coverage_end",
	"coverage_status", "first_sequence", "last_sequence", "unresolved_intervals",
}

// Load validates a bounded dataset and enforces all three canonical/JCS pins.
// The exact formatted input-byte hash is computed as separate observational
// provenance and is never compared with the manifest dataset_digest.
func Load(raw []byte) (Dataset, error) {
	dataset, err := parseDataset(raw)
	if err != nil {
		return Dataset{}, err
	}
	if dataset.ManifestDatasetJCSDigest() != PinnedManifestDatasetJCSDigest ||
		dataset.ImportedRowsJCSDigest() != PinnedImportedRowsJCSDigest ||
		dataset.SourceHealthJCSDigest() != PinnedSourceHealthJCSDigest ||
		dataset.RecordCount() != PinnedImportedRecordCount {
		return Dataset{}, reject(ErrorDigest)
	}
	return dataset, nil
}

func parseDataset(raw []byte) (Dataset, error) {
	if len(raw) == 0 || len(raw) > MaxDatasetBytes {
		return Dataset{}, reject(ErrorInputBounds)
	}
	if !utf8.Valid(raw) {
		return Dataset{}, reject(ErrorEncoding)
	}
	if err := validateStrictJSON(raw); err != nil {
		return Dataset{}, err
	}

	fields, err := decodeObject(raw)
	if err != nil {
		return Dataset{}, err
	}
	if err := requireFields(fields, datasetFields...); err != nil {
		return Dataset{}, err
	}

	schemaVersion, err := readString(fields, "schema_version")
	if err != nil || schemaVersion != DatasetSchemaVersion {
		return Dataset{}, reject(ErrorContract)
	}
	datasetID, err := readString(fields, "dataset_id")
	if err != nil || !uuidPattern.MatchString(datasetID) || datasetID != PinnedDatasetID {
		return Dataset{}, reject(ErrorContract)
	}
	pathCatalogVersion, err := readString(fields, "path_catalog_version")
	if err != nil || pathCatalogVersion != events.PathCatalogV1 {
		return Dataset{}, reject(ErrorContract)
	}
	coverageStart, err := readCoverageTime(fields, "coverage_start")
	if err != nil {
		return Dataset{}, err
	}
	coverageEnd, err := readCoverageTime(fields, "coverage_end")
	if err != nil || !coverageEnd.After(coverageStart) || coverageEnd.Sub(coverageStart) != coverageDuration {
		return Dataset{}, reject(ErrorCoverage)
	}

	rawRecords, err := readRawArray(fields, "records")
	if err != nil || len(rawRecords) < 1 || len(rawRecords) > MaxDatasetRecords {
		return Dataset{}, reject(ErrorShape)
	}
	records, err := parseRecords(rawRecords, pathCatalogVersion, coverageStart, coverageEnd, datasetID)
	if err != nil {
		return Dataset{}, err
	}

	rawCoverage, err := readRawArray(fields, "source_health")
	if err != nil || len(rawCoverage) < MinSourceHealthRecords || len(rawCoverage) > MaxSourceHealthRecords {
		return Dataset{}, reject(ErrorShape)
	}
	sourceCoverage, err := parseSourceCoverage(rawCoverage, coverageStart, coverageEnd)
	if err != nil {
		return Dataset{}, err
	}

	datasetJCS, err := canonicalJSON(raw)
	if err != nil {
		return Dataset{}, err
	}
	rowsJCS, err := canonicalJSON(fields["records"])
	if err != nil {
		return Dataset{}, err
	}
	healthJCS, err := canonicalJSON(fields["source_health"])
	if err != nil {
		return Dataset{}, err
	}

	return Dataset{
		schemaVersion:            schemaVersion,
		datasetID:                datasetID,
		pathCatalogVersion:       pathCatalogVersion,
		coverageStart:            coverageStart,
		coverageEnd:              coverageEnd,
		records:                  records,
		sourceCoverage:           sourceCoverage,
		rawFileByteSHA256:        sha256Digest(raw),
		manifestDatasetJCSDigest: sha256Digest(datasetJCS),
		importedRowsJCSDigest:    sha256Digest(rowsJCS),
		sourceHealthJCSDigest:    sha256Digest(healthJCS),
	}, nil
}

func parseRecords(rawRecords []json.RawMessage, pathCatalogVersion string, coverageStart, coverageEnd time.Time, datasetID string) ([]Record, error) {
	records := make([]Record, 0, len(rawRecords))
	declaredIDs := map[string]struct{}{datasetID: struct{}{}}
	idempotencyKeys := make(map[string]struct{}, len(rawRecords))
	gatewayByRequest := make(map[string]events.GatewayHTTPV1)
	authByRequest := make(map[string]struct{})

	var previousTime time.Time
	var previousEventID string
	for index, raw := range rawRecords {
		fields, err := decodeObject(raw)
		if err != nil {
			return nil, reject(ErrorContract)
		}
		schemaVersion, err := readString(fields, "schema_version")
		if err != nil {
			return nil, reject(ErrorContract)
		}

		var record Record
		var eventID, idempotencyKey string
		var eventTime time.Time
		switch schemaVersion {
		case events.GatewayHTTPV1Schema:
			event, err := events.DecodeGatewayHTTPV1(raw)
			if err != nil || event.PathCatalogVersion != pathCatalogVersion || !millisecondTime(event.StartedAt.Time()) || !millisecondTime(event.CompletedAt.Time()) {
				return nil, reject(ErrorContract)
			}
			if event.StartedAt.Time().Before(coverageStart) || event.CompletedAt.Time().After(coverageEnd) {
				return nil, reject(ErrorCoverage)
			}
			for _, id := range []string{event.EventID, event.RequestID, event.TraceID} {
				if _, duplicate := declaredIDs[id]; duplicate {
					return nil, reject(ErrorDuplicate)
				}
				declaredIDs[id] = struct{}{}
			}
			gatewayByRequest[event.RequestID] = event
			record = Record{kind: RecordGatewayHTTP, gateway: event}
			eventID, idempotencyKey, eventTime = event.EventID, event.IdempotencyKey, event.StartedAt.Time()
		case events.AuthEventV1Schema:
			event, err := events.DecodeAuthEventV1(raw)
			if err != nil || !millisecondTime(event.OccurredAt.Time()) {
				return nil, reject(ErrorContract)
			}
			if event.OccurredAt.Time().Before(coverageStart) || event.OccurredAt.Time().After(coverageEnd) {
				return nil, reject(ErrorCoverage)
			}
			if _, duplicate := declaredIDs[event.EventID]; duplicate {
				return nil, reject(ErrorDuplicate)
			}
			declaredIDs[event.EventID] = struct{}{}
			if _, duplicate := authByRequest[event.GatewayRequestID]; duplicate {
				return nil, reject(ErrorDuplicate)
			}
			authByRequest[event.GatewayRequestID] = struct{}{}
			record = Record{kind: RecordAuthEvent, auth: event}
			eventID, idempotencyKey, eventTime = event.EventID, event.IdempotencyKey, event.OccurredAt.Time()
		default:
			return nil, reject(ErrorContract)
		}

		if _, duplicate := idempotencyKeys[idempotencyKey]; duplicate {
			return nil, reject(ErrorDuplicate)
		}
		idempotencyKeys[idempotencyKey] = struct{}{}
		if index > 0 && (eventTime.Before(previousTime) ||
			(eventTime.Equal(previousTime) && bytes.Compare([]byte(eventID), []byte(previousEventID)) <= 0)) {
			return nil, reject(ErrorOrdering)
		}
		previousTime, previousEventID = eventTime, eventID
		records = append(records, record)
	}

	for _, record := range records {
		auth, ok := record.AuthEvent()
		if !ok {
			continue
		}
		gateway, exists := gatewayByRequest[auth.GatewayRequestID]
		if !exists || auth.TraceID != gateway.TraceID || auth.SourceIP != gateway.SourceIP ||
			auth.ServiceLabel != gateway.ServiceLabel || auth.RouteLabel != gateway.RouteLabel ||
			auth.OccurredAt.Time().Before(gateway.StartedAt.Time()) || auth.OccurredAt.Time().After(gateway.CompletedAt.Time()) {
			return nil, reject(ErrorBinding)
		}
	}
	return records, nil
}

func parseSourceCoverage(rawCoverage []json.RawMessage, coverageStart, coverageEnd time.Time) ([]SourceCoverage, error) {
	result := make([]SourceCoverage, 0, len(rawCoverage))
	seenSenders := make(map[string]struct{}, len(rawCoverage))
	seenEpochs := make(map[string]struct{}, len(rawCoverage))
	previousSenderID, previousSenderEpoch := "", ""
	for index, raw := range rawCoverage {
		fields, err := decodeObject(raw)
		if err != nil || requireFields(fields, sourceCoverageFields...) != nil {
			return nil, reject(ErrorShape)
		}
		senderID, err := readString(fields, "sender_id")
		if err != nil || !senderIDPattern.MatchString(senderID) {
			return nil, reject(ErrorContract)
		}
		if _, duplicate := seenSenders[senderID]; duplicate {
			return nil, reject(ErrorDuplicate)
		}
		seenSenders[senderID] = struct{}{}
		senderEpoch, err := readString(fields, "sender_epoch")
		if err != nil || !validSenderEpoch(senderEpoch) {
			return nil, reject(ErrorContract)
		}
		if _, duplicate := seenEpochs[senderEpoch]; duplicate {
			return nil, reject(ErrorDuplicate)
		}
		seenEpochs[senderEpoch] = struct{}{}
		if index > 0 && (senderID < previousSenderID || (senderID == previousSenderID && senderEpoch <= previousSenderEpoch)) {
			return nil, reject(ErrorOrdering)
		}

		start, err := readCoverageTime(fields, "coverage_start")
		if err != nil {
			return nil, err
		}
		end, err := readCoverageTime(fields, "coverage_end")
		if err != nil || !start.Equal(coverageStart) || !end.Equal(coverageEnd) {
			return nil, reject(ErrorCoverage)
		}
		status, err := readString(fields, "coverage_status")
		if err != nil || status != "complete" {
			return nil, reject(ErrorCoverage)
		}
		first, err := readUint(fields, "first_sequence", 1, eventsMaxSafeInteger)
		if err != nil {
			return nil, err
		}
		last, err := readUint(fields, "last_sequence", 1, eventsMaxSafeInteger)
		if err != nil || last < first {
			return nil, reject(ErrorCoverage)
		}
		unresolved, err := readRawArray(fields, "unresolved_intervals")
		if err != nil || len(unresolved) != 0 {
			return nil, reject(ErrorCoverage)
		}

		result = append(result, SourceCoverage{
			senderID: senderID, senderEpoch: senderEpoch, coverageStart: start,
			coverageEnd: end, firstSequence: first, lastSequence: last,
		})
		previousSenderID, previousSenderEpoch = senderID, senderEpoch
	}
	return result, nil
}

func readCoverageTime(fields map[string]json.RawMessage, name string) (time.Time, error) {
	value, err := readString(fields, name)
	if err != nil {
		return time.Time{}, err
	}
	timestamp, err := events.ParseTimestamp(value)
	if err != nil || !timestamp.Valid() || timestamp.Time().Format(coverageTimeLayout) != value {
		return time.Time{}, reject(ErrorCoverage)
	}
	return timestamp.Time().Round(0).UTC(), nil
}

func millisecondTime(value time.Time) bool {
	return !value.IsZero() && value.Nanosecond()%int(time.Millisecond) == 0
}

func validSenderEpoch(value string) bool {
	if !senderEpochPattern.MatchString(value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 16
}
