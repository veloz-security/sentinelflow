package exportbundle

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	asciiIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	eventLabelPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	scorePattern      = regexp.MustCompile(`^(?:0|0\.[0-9]{1,5}|1|1\.0{1,5})$`)
	pseudonymPattern  = regexp.MustCompile(`^(?:source|actor|trace):[0-9a-f]{64}$`)
)

var allowedIncidentKinds = stringSet(
	"credential_stuffing", "brute_force", "path_scan", "request_burst", "mixed", "unknown",
)
var allowedIncidentStates = stringSet(
	"open", "analyzing", "review_ready", "analysis_failed", "closed",
)
var allowedAnalysisFailures = stringSet(
	"budget_exhausted", "input_too_large", "network_error", "http_408", "http_409",
	"rate_limited", "server_error", "timeout", "refused", "incomplete", "schema_invalid",
	"evidence_invalid", "unsupported_action", "cancelled", "configuration_error",
)
var allowedActorTypes = stringSet("administrator", "system", "dispatcher", "executor")
var allowedOutcomes = stringSet("accepted", "rejected", "succeeded", "failed", "indeterminate")

type Exporter struct {
	store Store
	key   []byte
	keyID string
	now   func() time.Time
}

func NewExporter(store Store, pseudonymKey []byte, keyID string) (*Exporter, error) {
	if store == nil || len(pseudonymKey) < MinimumPseudonymKeyBytes ||
		len(pseudonymKey) > MaximumPseudonymKeyBytes || !labelPattern.MatchString(keyID) {
		return nil, ErrInvalidRequest
	}
	key := append([]byte(nil), pseudonymKey...)
	return &Exporter{store: store, key: key, keyID: keyID, now: time.Now}, nil
}

// Close clears the retained key bytes. Callers must not reuse an Exporter
// after Close; Build will fail closed because the key is no longer valid.
func (e *Exporter) Close() {
	if e == nil {
		return
	}
	clear(e.key)
	e.key = nil
}

func (e *Exporter) Build(ctx context.Context, query Query) (Bundle, error) {
	if e == nil || e.store == nil || e.now == nil || !query.Valid() ||
		len(e.key) < MinimumPseudonymKeyBytes || !labelPattern.MatchString(e.keyID) {
		return Bundle{}, ErrInvalidRequest
	}
	snapshot, err := e.store.Snapshot(ctx, query)
	if err != nil {
		return Bundle{}, err
	}
	if snapshot.SnapshotAt.IsZero() || len(snapshot.Incidents) > query.MaxIncidents() ||
		len(snapshot.Audit) > query.MaxAuditEvents() {
		return Bundle{}, ErrLimitExceeded
	}
	if err = validateSnapshotScope(snapshot, query); err != nil {
		return Bundle{}, err
	}

	sort.Slice(snapshot.Incidents, func(i, j int) bool {
		return snapshot.Incidents[i].IncidentID < snapshot.Incidents[j].IncidentID
	})
	sort.Slice(snapshot.Audit, func(i, j int) bool {
		return snapshot.Audit[i].Sequence < snapshot.Audit[j].Sequence
	})

	incidents := make([]IncidentRecord, 0, len(snapshot.Incidents))
	for index := range snapshot.Incidents {
		record, buildErr := e.buildIncident(snapshot.Incidents[index])
		if buildErr != nil {
			return Bundle{}, buildErr
		}
		if index > 0 && incidents[index-1].IncidentID == record.IncidentID {
			return Bundle{}, ErrInvalidData
		}
		incidents = append(incidents, record)
	}

	audit := make([]AuditRecord, 0, len(snapshot.Audit))
	previous := GenesisDigest
	for index := range snapshot.Audit {
		record, buildErr := e.buildAudit(snapshot.Audit[index], previous)
		if buildErr != nil {
			return Bundle{}, buildErr
		}
		if index > 0 && audit[index-1].Sequence >= record.Sequence {
			return Bundle{}, ErrInvalidData
		}
		audit = append(audit, record)
		previous = record.RecordDigest
	}

	incidentRoot := digestList("sentinelflow export incident set v1", incidentDigests(incidents))
	auditRoot := previous
	createdAt := e.now().UTC()
	if createdAt.IsZero() {
		return Bundle{}, ErrInvalidData
	}
	filter := Filters{}
	if query.IncidentID() != "" {
		value := query.IncidentID()
		filter.IncidentID = &value
	}
	manifest := Manifest{
		SchemaVersion:      ManifestSchemaVersion,
		CreatedAt:          canonicalTime(createdAt),
		DatabaseSnapshotAt: canonicalTime(snapshot.SnapshotAt),
		Window:             Window{Since: canonicalTime(query.Since()), Until: canonicalTime(query.Until())},
		Filters:            filter,
		Pseudonymization:   Pseudonymization{Algorithm: PseudonymAlgorithm, KeyID: e.keyID},
		IncidentCount:      len(incidents), AuditEventCount: len(audit),
		IncidentRecordsDigest: incidentRoot, AuditChainGenesis: GenesisDigest,
		AuditChainRoot: auditRoot,
	}
	manifest.ExportID = exportID(manifest)
	manifest.ManifestDigest, err = digestJSON("sentinelflow export manifest v1", manifestForDigest(manifest))
	if err != nil {
		return Bundle{}, ErrInvalidData
	}
	bundle := Bundle{SchemaVersion: BundleSchemaVersion, Manifest: manifest,
		Incidents: incidents, AuditEvents: audit}
	if err = Verify(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func (e *Exporter) buildIncident(raw RawIncident) (IncidentRecord, error) {
	if err := validateRawIncident(raw); err != nil {
		return IncidentRecord{}, err
	}
	record := IncidentRecord{
		SchemaVersion: IncidentSchemaVersion, IncidentID: raw.IncidentID,
		Kind: raw.Kind, State: raw.State,
		SourcePseudonym: e.pseudonym("source", raw.SourceIPv4),
		ServiceLabel:    raw.ServiceLabel, FirstSeen: canonicalTime(raw.FirstSeen),
		LastSeen: canonicalTime(raw.LastSeen), ClosedAt: canonicalTimePointer(raw.ClosedAt),
		ReopenUntil: canonicalTimePointer(raw.ReopenUntil), DeterministicScore: raw.DeterministicScore,
		Version: raw.Version, AnalysisFailureReason: cloneStringPointer(raw.AnalysisFailureReason),
		CreatedAt: canonicalTime(raw.CreatedAt), UpdatedAt: canonicalTime(raw.UpdatedAt),
	}
	var err error
	record.RecordDigest, err = digestJSON("sentinelflow export incident record v1", incidentForDigest(record))
	if err != nil {
		return IncidentRecord{}, ErrInvalidData
	}
	return record, nil
}

func (e *Exporter) buildAudit(raw RawAuditEvent, previous string) (AuditRecord, error) {
	if err := validateRawAudit(raw); err != nil || !digestPattern.MatchString(previous) {
		return AuditRecord{}, ErrInvalidData
	}
	record := AuditRecord{
		SchemaVersion: AuditSchemaVersion, Sequence: raw.Sequence, EventID: raw.EventID,
		ActorType: raw.ActorType, ActorPseudonym: e.pseudonym("actor", raw.ActorID),
		Action: raw.Action, ObjectType: raw.ObjectType, ObjectID: cloneStringPointer(raw.ObjectID),
		IncidentID: cloneStringPointer(raw.IncidentID), PolicyID: cloneStringPointer(raw.PolicyID),
		PolicyVersion:       cloneInt32Pointer(raw.PolicyVersion),
		EnforcementActionID: cloneStringPointer(raw.EnforcementActionID),
		PrimaryDigest:       cloneStringPointer(raw.PrimaryDigest), SecondaryDigest: cloneStringPointer(raw.SecondaryDigest),
		Outcome: raw.Outcome, OccurredAt: canonicalTime(raw.OccurredAt), RecordedAt: canonicalTime(raw.RecordedAt),
		PreviousRecordDigest: previous,
	}
	if raw.TraceID != nil {
		value := e.pseudonym("trace", *raw.TraceID)
		record.TracePseudonym = &value
	}
	var err error
	record.RecordDigest, err = digestJSON("sentinelflow export audit record v1", auditForDigest(record))
	if err != nil {
		return AuditRecord{}, ErrInvalidData
	}
	return record, nil
}

func (e *Exporter) pseudonym(domain, value string) string {
	mac := hmac.New(sha256.New, e.key)
	_, _ = mac.Write([]byte("sentinelflow export pseudonym v1\n" + domain + "\x00" + value))
	return domain + ":" + hex.EncodeToString(mac.Sum(nil))
}

func Encode(bundle Bundle) ([]byte, Result, error) {
	if err := Verify(bundle); err != nil {
		return nil, Result{}, err
	}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil || len(encoded)+1 > MaximumBundleBytes {
		return nil, Result{}, ErrLimitExceeded
	}
	encoded = append(encoded, '\n')
	result := resultFor(bundle)
	result.BundleDigest = digestBytes(encoded)
	return encoded, result, nil
}

func DecodeAndVerify(encoded []byte) (Bundle, Result, error) {
	if len(encoded) == 0 || len(encoded) > MaximumBundleBytes {
		return Bundle{}, Result{}, ErrLimitExceeded
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, Result{}, ErrIntegrity
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Bundle{}, Result{}, ErrIntegrity
	}
	if err := Verify(bundle); err != nil {
		return Bundle{}, Result{}, err
	}
	result := resultFor(bundle)
	result.BundleDigest = digestBytes(encoded)
	return bundle, result, nil
}

func Verify(bundle Bundle) error {
	manifest := bundle.Manifest
	if bundle.SchemaVersion != BundleSchemaVersion || manifest.SchemaVersion != ManifestSchemaVersion ||
		manifest.Pseudonymization.Algorithm != PseudonymAlgorithm ||
		!labelPattern.MatchString(manifest.Pseudonymization.KeyID) ||
		manifest.AuditChainGenesis != GenesisDigest ||
		manifest.IncidentCount != len(bundle.Incidents) || manifest.AuditEventCount != len(bundle.AuditEvents) ||
		manifest.IncidentCount > MaximumIncidentRecords || manifest.AuditEventCount > MaximumAuditRecords ||
		!digestPattern.MatchString(manifest.ExportID) || !digestPattern.MatchString(manifest.ManifestDigest) ||
		!digestPattern.MatchString(manifest.IncidentRecordsDigest) || !digestPattern.MatchString(manifest.AuditChainRoot) {
		return ErrIntegrity
	}
	if _, err := parseCanonicalTime(manifest.CreatedAt); err != nil {
		return ErrIntegrity
	}
	if _, err := parseCanonicalTime(manifest.DatabaseSnapshotAt); err != nil {
		return ErrIntegrity
	}
	since, err := parseCanonicalTime(manifest.Window.Since)
	if err != nil {
		return ErrIntegrity
	}
	until, err := parseCanonicalTime(manifest.Window.Until)
	if err != nil || !until.After(since) || until.Sub(since) > MaximumExportWindow {
		return ErrIntegrity
	}
	if manifest.Filters.IncidentID != nil && !uuidPattern.MatchString(*manifest.Filters.IncidentID) {
		return ErrIntegrity
	}
	incidentEvidence := make(map[string]struct{}, len(bundle.AuditEvents))
	for _, record := range bundle.AuditEvents {
		occurredAt, parseErr := parseCanonicalTime(record.OccurredAt)
		if parseErr != nil || occurredAt.Before(since) || occurredAt.After(until) {
			return ErrIntegrity
		}
		if manifest.Filters.IncidentID != nil &&
			(record.IncidentID == nil || *record.IncidentID != *manifest.Filters.IncidentID) {
			return ErrIntegrity
		}
		if record.IncidentID != nil {
			incidentEvidence[*record.IncidentID] = struct{}{}
		}
	}

	incidentDigests := make([]string, 0, len(bundle.Incidents))
	for index, record := range bundle.Incidents {
		if err = verifyIncident(record); err != nil ||
			(index > 0 && bundle.Incidents[index-1].IncidentID >= record.IncidentID) {
			return ErrIntegrity
		}
		if manifest.Filters.IncidentID != nil && record.IncidentID != *manifest.Filters.IncidentID {
			return ErrIntegrity
		}
		updatedAt, parseErr := parseCanonicalTime(record.UpdatedAt)
		_, hasAuditEvidence := incidentEvidence[record.IncidentID]
		if parseErr != nil || ((updatedAt.Before(since) || updatedAt.After(until)) && !hasAuditEvidence) {
			return ErrIntegrity
		}
		incidentDigests = append(incidentDigests, record.RecordDigest)
	}
	if digestList("sentinelflow export incident set v1", incidentDigests) != manifest.IncidentRecordsDigest {
		return ErrIntegrity
	}

	previous := GenesisDigest
	for index, record := range bundle.AuditEvents {
		if err = verifyAudit(record, previous); err != nil ||
			(index > 0 && bundle.AuditEvents[index-1].Sequence >= record.Sequence) {
			return ErrIntegrity
		}
		previous = record.RecordDigest
	}
	if previous != manifest.AuditChainRoot || exportID(manifest) != manifest.ExportID {
		return ErrIntegrity
	}
	expectedManifest, err := digestJSON("sentinelflow export manifest v1", manifestForDigest(manifest))
	if err != nil || !hmac.Equal([]byte(expectedManifest), []byte(manifest.ManifestDigest)) {
		return ErrIntegrity
	}
	return nil
}

func validateSnapshotScope(snapshot Snapshot, query Query) error {
	incidentEvidence := make(map[string]struct{}, len(snapshot.Audit))
	for _, record := range snapshot.Audit {
		if record.OccurredAt.Before(query.Since()) || record.OccurredAt.After(query.Until()) {
			return ErrInvalidData
		}
		if query.IncidentID() != "" &&
			(record.IncidentID == nil || *record.IncidentID != query.IncidentID()) {
			return ErrInvalidData
		}
		if record.IncidentID != nil {
			incidentEvidence[*record.IncidentID] = struct{}{}
		}
	}
	for _, record := range snapshot.Incidents {
		if query.IncidentID() != "" && record.IncidentID != query.IncidentID() {
			return ErrInvalidData
		}
		_, hasAuditEvidence := incidentEvidence[record.IncidentID]
		if (record.UpdatedAt.Before(query.Since()) || record.UpdatedAt.After(query.Until())) &&
			!hasAuditEvidence {
			return ErrInvalidData
		}
	}
	return nil
}

func verifyIncident(record IncidentRecord) error {
	if record.SchemaVersion != IncidentSchemaVersion || !uuidPattern.MatchString(record.IncidentID) ||
		!allowedIncidentKinds[record.Kind] || !allowedIncidentStates[record.State] ||
		!pseudonymPattern.MatchString(record.SourcePseudonym) || !strings.HasPrefix(record.SourcePseudonym, "source:") ||
		!eventLabelPattern.MatchString(record.ServiceLabel) || !scorePattern.MatchString(record.DeterministicScore) ||
		!scoreWithinBounds(record.DeterministicScore) ||
		record.Version < 1 || !digestPattern.MatchString(record.RecordDigest) {
		return ErrIntegrity
	}
	if record.AnalysisFailureReason != nil && !allowedAnalysisFailures[*record.AnalysisFailureReason] {
		return ErrIntegrity
	}
	firstSeen, err := parseCanonicalTime(record.FirstSeen)
	if err != nil {
		return ErrIntegrity
	}
	lastSeen, err := parseCanonicalTime(record.LastSeen)
	if err != nil || lastSeen.Before(firstSeen) {
		return ErrIntegrity
	}
	createdAt, err := parseCanonicalTime(record.CreatedAt)
	if err != nil {
		return ErrIntegrity
	}
	updatedAt, err := parseCanonicalTime(record.UpdatedAt)
	if err != nil || updatedAt.Before(createdAt) {
		return ErrIntegrity
	}
	if err := verifyOptionalTime(record.ClosedAt); err != nil {
		return err
	}
	if err := verifyOptionalTime(record.ReopenUntil); err != nil {
		return err
	}
	closed := record.State == "closed"
	failed := record.State == "analysis_failed"
	if closed != (record.ClosedAt != nil && record.ReopenUntil != nil) ||
		failed != (record.AnalysisFailureReason != nil) {
		return ErrIntegrity
	}
	if record.ClosedAt != nil {
		closedAt, parseErr := parseCanonicalTime(*record.ClosedAt)
		if parseErr != nil {
			return ErrIntegrity
		}
		reopenUntil, parseErr := parseCanonicalTime(*record.ReopenUntil)
		if parseErr != nil || reopenUntil.Before(closedAt) {
			return ErrIntegrity
		}
	}
	expected, err := digestJSON("sentinelflow export incident record v1", incidentForDigest(record))
	if err != nil || !hmac.Equal([]byte(expected), []byte(record.RecordDigest)) {
		return ErrIntegrity
	}
	return nil
}

func verifyAudit(record AuditRecord, previous string) error {
	if record.SchemaVersion != AuditSchemaVersion || record.Sequence < 1 ||
		record.Sequence > MaximumAuditSequence ||
		!uuidPattern.MatchString(record.EventID) || !allowedActorTypes[record.ActorType] ||
		!pseudonymPattern.MatchString(record.ActorPseudonym) || !strings.HasPrefix(record.ActorPseudonym, "actor:") ||
		!asciiIDPattern.MatchString(record.Action) || !asciiIDPattern.MatchString(record.ObjectType) ||
		!allowedOutcomes[record.Outcome] || record.PreviousRecordDigest != previous ||
		!digestPattern.MatchString(record.RecordDigest) {
		return ErrIntegrity
	}
	for _, value := range []*string{record.ObjectID, record.IncidentID, record.PolicyID, record.EnforcementActionID} {
		if value != nil && !uuidPattern.MatchString(*value) {
			return ErrIntegrity
		}
	}
	if (record.PolicyID == nil) != (record.PolicyVersion == nil) ||
		(record.PolicyVersion != nil && *record.PolicyVersion < 1) {
		return ErrIntegrity
	}
	if record.TracePseudonym != nil &&
		(!pseudonymPattern.MatchString(*record.TracePseudonym) || !strings.HasPrefix(*record.TracePseudonym, "trace:")) {
		return ErrIntegrity
	}
	for _, value := range []*string{record.PrimaryDigest, record.SecondaryDigest} {
		if value != nil && !digestPattern.MatchString(*value) {
			return ErrIntegrity
		}
	}
	if _, err := parseCanonicalTime(record.OccurredAt); err != nil {
		return ErrIntegrity
	}
	if _, err := parseCanonicalTime(record.RecordedAt); err != nil {
		return ErrIntegrity
	}
	expected, err := digestJSON("sentinelflow export audit record v1", auditForDigest(record))
	if err != nil || !hmac.Equal([]byte(expected), []byte(record.RecordDigest)) {
		return ErrIntegrity
	}
	return nil
}

func validateRawIncident(raw RawIncident) error {
	address, addressErr := netip.ParseAddr(raw.SourceIPv4)
	if !uuidPattern.MatchString(raw.IncidentID) || !allowedIncidentKinds[raw.Kind] ||
		!allowedIncidentStates[raw.State] || addressErr != nil || !address.Is4() || address.Is4In6() ||
		address.String() != raw.SourceIPv4 || !eventLabelPattern.MatchString(raw.ServiceLabel) ||
		raw.FirstSeen.IsZero() || raw.LastSeen.Before(raw.FirstSeen) || raw.CreatedAt.IsZero() ||
		raw.UpdatedAt.Before(raw.CreatedAt) || !scorePattern.MatchString(raw.DeterministicScore) ||
		!scoreWithinBounds(raw.DeterministicScore) || raw.Version < 1 {
		return ErrInvalidData
	}
	if raw.AnalysisFailureReason != nil && !allowedAnalysisFailures[*raw.AnalysisFailureReason] {
		return ErrInvalidData
	}
	closed := raw.State == "closed"
	failed := raw.State == "analysis_failed"
	if closed != (raw.ClosedAt != nil && raw.ReopenUntil != nil) ||
		(raw.ClosedAt != nil && raw.ReopenUntil.Before(*raw.ClosedAt)) ||
		failed != (raw.AnalysisFailureReason != nil) {
		return ErrInvalidData
	}
	return nil
}

func validateRawAudit(raw RawAuditEvent) error {
	if raw.Sequence < 1 || raw.Sequence > MaximumAuditSequence ||
		!uuidPattern.MatchString(raw.EventID) || !allowedActorTypes[raw.ActorType] ||
		!asciiIDPattern.MatchString(raw.ActorID) || !asciiIDPattern.MatchString(raw.Action) ||
		!asciiIDPattern.MatchString(raw.ObjectType) || !allowedOutcomes[raw.Outcome] ||
		raw.OccurredAt.IsZero() || raw.RecordedAt.IsZero() {
		return ErrInvalidData
	}
	for _, value := range []*string{raw.ObjectID, raw.IncidentID, raw.PolicyID, raw.EnforcementActionID, raw.TraceID} {
		if value != nil && !uuidPattern.MatchString(*value) {
			return ErrInvalidData
		}
	}
	if (raw.PolicyID == nil) != (raw.PolicyVersion == nil) ||
		(raw.PolicyVersion != nil && *raw.PolicyVersion < 1) {
		return ErrInvalidData
	}
	for _, value := range []*string{raw.PrimaryDigest, raw.SecondaryDigest} {
		if value != nil && !digestPattern.MatchString(*value) {
			return ErrInvalidData
		}
	}
	return nil
}

func canonicalTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func canonicalTimePointer(value *time.Time) *string {
	if value == nil {
		return nil
	}
	result := canonicalTime(*value)
	return &result
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || canonicalTime(parsed) != value {
		return time.Time{}, ErrIntegrity
	}
	return parsed, nil
}

func verifyOptionalTime(value *string) error {
	if value == nil {
		return nil
	}
	_, err := parseCanonicalTime(*value)
	return err
}

func digestJSON(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{'\n'})
	_, _ = hash.Write(encoded)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func digestList(domain string, digests []string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{'\n'})
	for _, digest := range digests {
		_, _ = hash.Write([]byte(digest))
		_, _ = hash.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func exportID(manifest Manifest) string {
	filter := ""
	if manifest.Filters.IncidentID != nil {
		filter = *manifest.Filters.IncidentID
	}
	return digestList("sentinelflow export id v1", []string{
		manifest.CreatedAt, manifest.DatabaseSnapshotAt, manifest.Window.Since,
		manifest.Window.Until, filter, manifest.Pseudonymization.KeyID,
		fmt.Sprintf("%d", manifest.IncidentCount), fmt.Sprintf("%d", manifest.AuditEventCount),
		manifest.IncidentRecordsDigest, manifest.AuditChainRoot,
	})
}

func incidentForDigest(value IncidentRecord) IncidentRecord {
	value.RecordDigest = ""
	return value
}

func auditForDigest(value AuditRecord) AuditRecord {
	value.RecordDigest = ""
	return value
}

func manifestForDigest(value Manifest) Manifest {
	value.ManifestDigest = ""
	return value
}

func incidentDigests(records []IncidentRecord) []string {
	result := make([]string, len(records))
	for index := range records {
		result[index] = records[index].RecordDigest
	}
	return result
}

func resultFor(bundle Bundle) Result {
	return Result{ExportID: bundle.Manifest.ExportID, ManifestDigest: bundle.Manifest.ManifestDigest,
		IncidentCount: len(bundle.Incidents), AuditEventCount: len(bundle.AuditEvents)}
}

func cloneStringPointer(value *string) *string {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneInt32Pointer(value *int32) *int32 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func stringSet(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func scoreWithinBounds(value string) bool {
	parsed, ok := new(big.Rat).SetString(value)
	return ok && parsed.Sign() >= 0 && parsed.Cmp(big.NewRat(1, 1)) <= 0
}
