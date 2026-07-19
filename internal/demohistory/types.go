// Package demohistory strictly loads the one pinned, synthetic v0.1
// demo-history dataset. It has no database, network, clock, signing-key, or
// enforcement authority.
package demohistory

import (
	"crypto/sha256"
	"crypto/subtle"
	"time"

	"github.com/devwooops/sentinelflow/internal/events"
)

const (
	DatasetSchemaVersion = "demo-history-dataset-v1"
	PinnedDatasetID      = "019b0000-0000-7000-8000-000000000100"

	// PinnedManifestDatasetJCSDigest is the signed manifest's dataset_digest.
	// It is a digest of RFC 8785/JCS-compatible canonical dataset bytes, not a
	// byte-exact digest of the formatted fixture file.
	PinnedManifestDatasetJCSDigest = "sha256:0686d45e11e029dd2e4712a1de981f3c0e5b92ccff45b1eaddb54c066232dd00"
	PinnedImportedRowsJCSDigest    = "sha256:33cf0e0d74065e1ac6810da95bd674f7f813059d10501249f8dbea972be1e807"
	PinnedSourceHealthJCSDigest    = "sha256:1e3d4a6754b86e4bdaf7fd4a259c1676deb6878629033962393c866e51c9d3fe"
	PinnedImportedRecordCount      = uint64(4)

	MaxDatasetBytes        = 64 << 20
	MaxDatasetRecords      = 100_000
	MinSourceHealthRecords = 2
	MaxSourceHealthRecords = 16
)

// RecordKind discriminates the only two persistence-allowlisted event types
// accepted by demo-history-dataset-v1.
type RecordKind string

const (
	RecordGatewayHTTP RecordKind = "gateway-http-v1"
	RecordAuthEvent   RecordKind = "auth-event-v1"
)

// Record is an immutable, typed, privacy-minimized import projection. The
// stored event is returned only by value and never contains arbitrary JSON or
// a raw/exact request path.
type Record struct {
	kind    RecordKind
	gateway events.GatewayHTTPV1
	auth    events.AuthEventV1
}

func (r Record) Kind() RecordKind { return r.kind }

func (r Record) GatewayHTTP() (events.GatewayHTTPV1, bool) {
	if r.kind != RecordGatewayHTTP {
		return events.GatewayHTTPV1{}, false
	}
	return r.gateway, true
}

func (r Record) AuthEvent() (events.AuthEventV1, bool) {
	if r.kind != RecordAuthEvent {
		return events.AuthEventV1{}, false
	}
	return r.auth, true
}

// SourceCoverage is the immutable complete-coverage projection imported with
// the records. unresolved_intervals is intentionally absent: v1 accepts only
// the required empty array and therefore retains no interval payload.
type SourceCoverage struct {
	senderID      string
	senderEpoch   string
	coverageStart time.Time
	coverageEnd   time.Time
	firstSequence uint64
	lastSequence  uint64
}

func (s SourceCoverage) SenderID() string             { return s.senderID }
func (s SourceCoverage) SenderEpoch() string          { return s.senderEpoch }
func (s SourceCoverage) CoverageStart() time.Time     { return s.coverageStart }
func (s SourceCoverage) CoverageEnd() time.Time       { return s.coverageEnd }
func (s SourceCoverage) CoverageStatus() string       { return "complete" }
func (s SourceCoverage) FirstSequence() uint64        { return s.firstSequence }
func (s SourceCoverage) LastSequence() uint64         { return s.lastSequence }
func (s SourceCoverage) UnresolvedIntervalCount() int { return 0 }

// Dataset contains only validated projections and explicit digest domains.
// It does not retain the input byte slice, generic maps, or arbitrary JSON.
type Dataset struct {
	schemaVersion            string
	datasetID                string
	pathCatalogVersion       string
	coverageStart            time.Time
	coverageEnd              time.Time
	records                  []Record
	sourceCoverage           []SourceCoverage
	rawFileByteSHA256        string
	manifestDatasetJCSDigest string
	importedRowsJCSDigest    string
	sourceHealthJCSDigest    string
}

func (d Dataset) SchemaVersion() string      { return d.schemaVersion }
func (d Dataset) DatasetID() string          { return d.datasetID }
func (d Dataset) PathCatalogVersion() string { return d.pathCatalogVersion }
func (d Dataset) CoverageStart() time.Time   { return d.coverageStart }
func (d Dataset) CoverageEnd() time.Time     { return d.coverageEnd }
func (d Dataset) RecordCount() uint64        { return uint64(len(d.records)) }

// RawFileByteSHA256 is observational provenance for the exact input bytes.
// It is deliberately not an authority pin and must not be substituted for the
// signed manifest's canonical/JCS dataset_digest.
func (d Dataset) RawFileByteSHA256() string { return d.rawFileByteSHA256 }

func (d Dataset) ManifestDatasetJCSDigest() string { return d.manifestDatasetJCSDigest }
func (d Dataset) ImportedRowsJCSDigest() string    { return d.importedRowsJCSDigest }
func (d Dataset) SourceHealthJCSDigest() string    { return d.sourceHealthJCSDigest }

// Records returns a defensive copy of the ordered import projections.
func (d Dataset) Records() []Record {
	return append([]Record(nil), d.records...)
}

// GatewayHTTPRecords returns defensive value copies in dataset order.
func (d Dataset) GatewayHTTPRecords() []events.GatewayHTTPV1 {
	result := make([]events.GatewayHTTPV1, 0, len(d.records))
	for _, record := range d.records {
		if event, ok := record.GatewayHTTP(); ok {
			result = append(result, event)
		}
	}
	return result
}

// AuthEventRecords returns defensive value copies in dataset order.
func (d Dataset) AuthEventRecords() []events.AuthEventV1 {
	result := make([]events.AuthEventV1, 0, len(d.records))
	for _, record := range d.records {
		if event, ok := record.AuthEvent(); ok {
			result = append(result, event)
		}
	}
	return result
}

// SourceCoverage returns a defensive copy sorted by sender_id, sender_epoch.
func (d Dataset) SourceCoverage() []SourceCoverage {
	return append([]SourceCoverage(nil), d.sourceCoverage...)
}

// MatchesRawFileBytes checks observational byte provenance without promoting
// the raw-file digest into a manifest authority pin.
func (d Dataset) MatchesRawFileBytes(raw []byte) bool {
	digest := sha256Digest(raw)
	return subtle.ConstantTimeCompare([]byte(d.rawFileByteSHA256), []byte(digest)) == 1
}

func sha256Digest(raw []byte) string {
	digest := sha256.Sum256(raw)
	const hex = "0123456789abcdef"
	encoded := make([]byte, len("sha256:")+sha256.Size*2)
	copy(encoded, "sha256:")
	for index, value := range digest {
		encoded[len("sha256:")+index*2] = hex[value>>4]
		encoded[len("sha256:")+index*2+1] = hex[value&0x0f]
	}
	return string(encoded)
}
