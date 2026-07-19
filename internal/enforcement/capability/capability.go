package capability

import (
	"bytes"
	"encoding/base64"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	actorPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	noncePattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	keyIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	addPattern    = regexp.MustCompile(`^add element inet sentinelflow blacklist_ipv4 \{ ([0-9.]{7,15}) timeout ([1-9][0-9]{0,4}[smh]) \}\n$`)
	revokePattern = regexp.MustCompile(`^delete element inet sentinelflow blacklist_ipv4 \{ ([0-9.]{7,15}) \}\n$`)
)

type capabilityWire struct {
	SchemaVersion            string  `json:"schema_version"`
	CapabilityID             string  `json:"capability_id"`
	Operation                string  `json:"operation"`
	JobID                    string  `json:"job_id"`
	ActionID                 string  `json:"action_id"`
	PolicyID                 string  `json:"policy_id"`
	PolicyVersion            uint32  `json:"policy_version"`
	TargetIPv4               string  `json:"target_ipv4"`
	ArtifactDigest           string  `json:"artifact_digest"`
	OriginalAddDigest        *string `json:"original_add_digest"`
	EvidenceSnapshotDigest   string  `json:"evidence_snapshot_digest"`
	ValidationSnapshotDigest string  `json:"validation_snapshot_digest"`
	AuthorizationDigest      string  `json:"authorization_digest"`
	ActorID                  string  `json:"actor_id"`
	ReasonDigest             string  `json:"reason_digest"`
	OwnedSchemaDigest        string  `json:"owned_schema_digest"`
	IssuedAt                 string  `json:"issued_at"`
	NotBefore                string  `json:"not_before"`
	ExpiresAt                string  `json:"expires_at"`
	Nonce                    string  `json:"nonce"`
}

// CheckAdd freezes an exact canonical nft add artifact for dispatcher signing.
func CheckAdd(input Add) (CheckedCapability, error) {
	ttl, err := checkAddArtifact(input.CanonicalCommand, input.TargetIPv4)
	if err != nil {
		return CheckedCapability{}, err
	}
	return buildChecked(input.Common, OperationAdd, "", input.CanonicalCommand, ttl, InspectArtifact{})
}

// CheckRevoke freezes a separately authorized exact canonical delete artifact.
func CheckRevoke(input Revoke) (CheckedCapability, error) {
	if !digestPattern.MatchString(input.OriginalAddDigest) {
		return CheckedCapability{}, reject(ErrorDigest)
	}
	if err := checkRevokeArtifact(input.CanonicalDelete, input.TargetIPv4); err != nil {
		return CheckedCapability{}, err
	}
	return buildChecked(input.Common, OperationRevoke, input.OriginalAddDigest, input.CanonicalDelete, 0, InspectArtifact{})
}

// CheckInspect freezes only the typed JCS read-back request. It cannot accept
// add or delete command bytes.
func CheckInspect(input Inspect) (CheckedCapability, error) {
	if !digestPattern.MatchString(input.OriginalAddDigest) {
		return CheckedCapability{}, reject(ErrorDigest)
	}
	checked, canonical, err := checkInspection(input.Artifact)
	if err != nil {
		return CheckedCapability{}, err
	}
	if checked.ActionID != input.ActionID || checked.TargetIPv4 != input.TargetIPv4 ||
		checked.OriginalAddDigest != input.OriginalAddDigest || checked.OwnedSchemaDigest != input.OwnedSchemaDigest {
		return CheckedCapability{}, reject(ErrorArtifact)
	}
	return buildChecked(input.Common, OperationInspect, input.OriginalAddDigest, canonical, 0, checked)
}

func buildChecked(common Common, operation Operation, originalAddDigest string, artifact []byte, ttl uint32, inspection InspectArtifact) (CheckedCapability, error) {
	value, err := checkCommon(common, operation, originalAddDigest, digestBytes(artifact))
	if err != nil {
		return CheckedCapability{}, err
	}
	canonical := marshalCapability(value)
	return CheckedCapability{
		value:      value,
		canonical:  canonical,
		digest:     digestBytes(canonical),
		artifact:   clone(artifact),
		addTTL:     ttl,
		inspection: inspection,
	}, nil
}

func checkCommon(common Common, operation Operation, originalAddDigest, artifactDigest string) (Value, error) {
	if operation != OperationAdd && operation != OperationRevoke && operation != OperationInspect {
		return Value{}, reject(ErrorOperation)
	}
	if !uuidPattern.MatchString(common.CapabilityID) || !uuidPattern.MatchString(common.JobID) ||
		!uuidPattern.MatchString(common.ActionID) || !uuidPattern.MatchString(common.PolicyID) {
		return Value{}, reject(ErrorIdentity)
	}
	if common.PolicyVersion == 0 || common.PolicyVersion > math.MaxInt32 {
		return Value{}, reject(ErrorSchema)
	}
	address, err := netip.ParseAddr(common.TargetIPv4)
	if err != nil || !address.Is4() || address.String() != common.TargetIPv4 {
		return Value{}, reject(ErrorSchema)
	}
	for _, digest := range []string{
		artifactDigest, common.EvidenceSnapshotDigest, common.ValidationSnapshotDigest,
		common.AuthorizationDigest, common.ReasonDigest, common.OwnedSchemaDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return Value{}, reject(ErrorDigest)
		}
	}
	if operation == OperationAdd {
		if originalAddDigest != "" {
			return Value{}, reject(ErrorOperation)
		}
	} else if !digestPattern.MatchString(originalAddDigest) {
		return Value{}, reject(ErrorDigest)
	}
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(common.Nonce)
	if !actorPattern.MatchString(common.ActorID) || !noncePattern.MatchString(common.Nonce) || nonceErr != nil ||
		len(nonce) != 16 || base64.RawURLEncoding.EncodeToString(nonce) != common.Nonce {
		return Value{}, reject(ErrorIdentity)
	}
	issuedAt := common.IssuedAt.UTC()
	notBefore := common.NotBefore.UTC()
	expiresAt := common.ExpiresAt.UTC()
	if issuedAt.IsZero() || notBefore.IsZero() || expiresAt.IsZero() ||
		issuedAt.Year() < 1 || expiresAt.Year() > 9999 ||
		!millisecondAligned(issuedAt) || !millisecondAligned(notBefore) || !millisecondAligned(expiresAt) ||
		notBefore.Before(issuedAt) || !expiresAt.After(notBefore) ||
		expiresAt.Sub(issuedAt) > MaxValidity {
		return Value{}, reject(ErrorTime)
	}
	return Value{
		SchemaVersion:            CapabilitySchemaVersion,
		CapabilityID:             common.CapabilityID,
		Operation:                operation,
		JobID:                    common.JobID,
		ActionID:                 common.ActionID,
		PolicyID:                 common.PolicyID,
		PolicyVersion:            common.PolicyVersion,
		TargetIPv4:               common.TargetIPv4,
		ArtifactDigest:           artifactDigest,
		OriginalAddDigest:        originalAddDigest,
		EvidenceSnapshotDigest:   common.EvidenceSnapshotDigest,
		ValidationSnapshotDigest: common.ValidationSnapshotDigest,
		AuthorizationDigest:      common.AuthorizationDigest,
		ActorID:                  common.ActorID,
		ReasonDigest:             common.ReasonDigest,
		OwnedSchemaDigest:        common.OwnedSchemaDigest,
		IssuedAt:                 issuedAt,
		NotBefore:                notBefore,
		ExpiresAt:                expiresAt,
		Nonce:                    common.Nonce,
	}, nil
}

// ParseCanonicalCapability checks byte-exact JCS plus the separately carried
// artifact. It returns only a dispatcher-signable value, never an executable
// one. Executor code must additionally verify its detached signature.
func ParseCanonicalCapability(data, artifact []byte) (CheckedCapability, error) {
	var wire capabilityWire
	if err := strictDecode(data, MaxCapabilityBytes, &wire); err != nil {
		return CheckedCapability{}, err
	}
	issuedAt, issuedTextOK := parseCanonicalTime(wire.IssuedAt)
	notBefore, notBeforeTextOK := parseCanonicalTime(wire.NotBefore)
	expiresAt, expiresTextOK := parseCanonicalTime(wire.ExpiresAt)
	if !issuedTextOK || !notBeforeTextOK || !expiresTextOK {
		return CheckedCapability{}, reject(ErrorTime)
	}
	original := ""
	if wire.OriginalAddDigest != nil {
		original = *wire.OriginalAddDigest
	}
	common := Common{
		CapabilityID: wire.CapabilityID, JobID: wire.JobID, ActionID: wire.ActionID,
		PolicyID: wire.PolicyID, PolicyVersion: wire.PolicyVersion, TargetIPv4: wire.TargetIPv4,
		EvidenceSnapshotDigest: wire.EvidenceSnapshotDigest, ValidationSnapshotDigest: wire.ValidationSnapshotDigest,
		AuthorizationDigest: wire.AuthorizationDigest, ActorID: wire.ActorID, ReasonDigest: wire.ReasonDigest,
		OwnedSchemaDigest: wire.OwnedSchemaDigest, IssuedAt: issuedAt, NotBefore: notBefore,
		ExpiresAt: expiresAt, Nonce: wire.Nonce,
	}
	operation := Operation(wire.Operation)
	var checked CheckedCapability
	var err error
	switch operation {
	case OperationAdd:
		if wire.OriginalAddDigest != nil {
			return CheckedCapability{}, reject(ErrorOperation)
		}
		checked, err = CheckAdd(Add{Common: common, CanonicalCommand: artifact})
	case OperationRevoke:
		if wire.OriginalAddDigest == nil {
			return CheckedCapability{}, reject(ErrorOperation)
		}
		checked, err = CheckRevoke(Revoke{Common: common, OriginalAddDigest: original, CanonicalDelete: artifact})
	case OperationInspect:
		if wire.OriginalAddDigest == nil {
			return CheckedCapability{}, reject(ErrorOperation)
		}
		inspection, parseErr := parseInspection(artifact)
		if parseErr != nil {
			return CheckedCapability{}, parseErr
		}
		checked, err = CheckInspect(Inspect{Common: common, OriginalAddDigest: original, Artifact: inspection})
	default:
		return CheckedCapability{}, reject(ErrorOperation)
	}
	if err != nil {
		return CheckedCapability{}, err
	}
	expected := marshalCapabilityTimes(checked.value, wire.IssuedAt, wire.NotBefore, wire.ExpiresAt)
	if checked.value.SchemaVersion != wire.SchemaVersion || !digestEqual(checked.value.ArtifactDigest, wire.ArtifactDigest) ||
		!bytes.Equal(expected, data) {
		return CheckedCapability{}, reject(ErrorCanonical)
	}
	checked.canonical = clone(data)
	checked.digest = digestBytes(data)
	return checked, nil
}

func marshalCapability(value Value) []byte {
	return marshalCapabilityTimes(value, formatCanonicalTime(value.IssuedAt), formatCanonicalTime(value.NotBefore), formatCanonicalTime(value.ExpiresAt))
}

func marshalCapabilityTimes(value Value, issuedAt, notBefore, expiresAt string) []byte {
	result := make([]byte, 0, 1400)
	result = append(result, `{"action_id":`...)
	result = appendString(result, value.ActionID)
	result = append(result, `,"actor_id":`...)
	result = appendString(result, value.ActorID)
	result = append(result, `,"artifact_digest":`...)
	result = appendString(result, value.ArtifactDigest)
	result = append(result, `,"authorization_digest":`...)
	result = appendString(result, value.AuthorizationDigest)
	result = append(result, `,"capability_id":`...)
	result = appendString(result, value.CapabilityID)
	result = append(result, `,"evidence_snapshot_digest":`...)
	result = appendString(result, value.EvidenceSnapshotDigest)
	result = append(result, `,"expires_at":`...)
	result = appendString(result, expiresAt)
	result = append(result, `,"issued_at":`...)
	result = appendString(result, issuedAt)
	result = append(result, `,"job_id":`...)
	result = appendString(result, value.JobID)
	result = append(result, `,"nonce":`...)
	result = appendString(result, value.Nonce)
	result = append(result, `,"not_before":`...)
	result = appendString(result, notBefore)
	result = append(result, `,"operation":`...)
	result = appendString(result, string(value.Operation))
	result = append(result, `,"original_add_digest":`...)
	result = appendNullableString(result, value.OriginalAddDigest)
	result = append(result, `,"owned_schema_digest":`...)
	result = appendString(result, value.OwnedSchemaDigest)
	result = append(result, `,"policy_id":`...)
	result = appendString(result, value.PolicyID)
	result = append(result, `,"policy_version":`...)
	result = appendUint(result, uint64(value.PolicyVersion))
	result = append(result, `,"reason_digest":`...)
	result = appendString(result, value.ReasonDigest)
	result = append(result, `,"schema_version":`...)
	result = appendString(result, value.SchemaVersion)
	result = append(result, `,"target_ipv4":`...)
	result = appendString(result, value.TargetIPv4)
	result = append(result, `,"validation_snapshot_digest":`...)
	result = appendString(result, value.ValidationSnapshotDigest)
	return append(result, '}')
}

func parseCanonicalTime(value string) (time.Time, bool) {
	if !strings.HasSuffix(value, "Z") || len(value) != len("2006-01-02T15:04:05.000Z") {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || !millisecondAligned(parsed) || formatCanonicalTime(parsed) != value {
		return time.Time{}, false
	}
	return parsed, true
}

func formatCanonicalTime(value time.Time) string { return value.UTC().Format(canonicalTimeLayout) }

func millisecondAligned(value time.Time) bool { return value.Nanosecond()%int(time.Millisecond) == 0 }

func checkAddArtifact(artifact []byte, target string) (uint32, error) {
	if len(artifact) == 0 || len(artifact) > MaxArtifactBytes {
		return 0, reject(ErrorArtifact)
	}
	matches := addPattern.FindSubmatch(artifact)
	if len(matches) != 3 || string(matches[1]) != target {
		return 0, reject(ErrorArtifact)
	}
	address, err := netip.ParseAddr(string(matches[1]))
	if err != nil || !address.Is4() || address.String() != target {
		return 0, reject(ErrorArtifact)
	}
	token := string(matches[2])
	number, err := strconv.ParseUint(token[:len(token)-1], 10, 32)
	if err != nil {
		return 0, reject(ErrorArtifact)
	}
	multiplier := uint64(1)
	switch token[len(token)-1] {
	case 'm':
		multiplier = 60
	case 'h':
		multiplier = 3600
	}
	seconds := number * multiplier
	if seconds < 60 || seconds > 86400 || canonicalTTL(uint32(seconds)) != token {
		return 0, reject(ErrorArtifact)
	}
	return uint32(seconds), nil
}

func canonicalTTL(seconds uint32) string {
	if seconds%3600 == 0 {
		return strconv.FormatUint(uint64(seconds/3600), 10) + "h"
	}
	if seconds%60 == 0 {
		return strconv.FormatUint(uint64(seconds/60), 10) + "m"
	}
	return strconv.FormatUint(uint64(seconds), 10) + "s"
}

func checkRevokeArtifact(artifact []byte, target string) error {
	if len(artifact) == 0 || len(artifact) > MaxArtifactBytes {
		return reject(ErrorArtifact)
	}
	matches := revokePattern.FindSubmatch(artifact)
	if len(matches) != 2 || string(matches[1]) != target {
		return reject(ErrorArtifact)
	}
	address, err := netip.ParseAddr(string(matches[1]))
	if err != nil || !address.Is4() || address.String() != target {
		return reject(ErrorArtifact)
	}
	return nil
}

type inspectWire struct {
	SchemaVersion     string `json:"schema_version"`
	Operation         string `json:"operation"`
	ActionID          string `json:"action_id"`
	TargetIPv4        string `json:"target_ipv4"`
	OriginalAddDigest string `json:"original_add_digest"`
	OwnedSchemaDigest string `json:"owned_schema_digest"`
	Purpose           string `json:"purpose"`
}

func checkInspection(value InspectArtifact) (InspectArtifact, []byte, error) {
	if value.SchemaVersion != InspectSchemaVersion || !uuidPattern.MatchString(value.ActionID) ||
		!digestPattern.MatchString(value.OriginalAddDigest) || !digestPattern.MatchString(value.OwnedSchemaDigest) {
		return InspectArtifact{}, nil, reject(ErrorArtifact)
	}
	address, err := netip.ParseAddr(value.TargetIPv4)
	if err != nil || !address.Is4() || address.String() != value.TargetIPv4 {
		return InspectArtifact{}, nil, reject(ErrorArtifact)
	}
	if value.Purpose != "reconciliation" && value.Purpose != "expiry_confirmation" && value.Purpose != "operator_status" {
		return InspectArtifact{}, nil, reject(ErrorArtifact)
	}
	return value, marshalInspection(value), nil
}

func marshalInspection(value InspectArtifact) []byte {
	result := make([]byte, 0, 600)
	result = append(result, `{"action_id":`...)
	result = appendString(result, value.ActionID)
	result = append(result, `,"operation":"inspect","original_add_digest":`...)
	result = appendString(result, value.OriginalAddDigest)
	result = append(result, `,"owned_schema_digest":`...)
	result = appendString(result, value.OwnedSchemaDigest)
	result = append(result, `,"purpose":`...)
	result = appendString(result, value.Purpose)
	result = append(result, `,"schema_version":"nft-inspect-v1","target_ipv4":`...)
	result = appendString(result, value.TargetIPv4)
	return append(result, '}')
}

func parseInspection(data []byte) (InspectArtifact, error) {
	var wire inspectWire
	if err := strictDecode(data, MaxArtifactBytes, &wire); err != nil {
		return InspectArtifact{}, reject(ErrorArtifact)
	}
	if wire.Operation != "inspect" {
		return InspectArtifact{}, reject(ErrorArtifact)
	}
	value, canonical, err := checkInspection(InspectArtifact{
		SchemaVersion: wire.SchemaVersion, ActionID: wire.ActionID, TargetIPv4: wire.TargetIPv4,
		OriginalAddDigest: wire.OriginalAddDigest, OwnedSchemaDigest: wire.OwnedSchemaDigest, Purpose: wire.Purpose,
	})
	if err != nil || !bytes.Equal(data, canonical) {
		return InspectArtifact{}, reject(ErrorArtifact)
	}
	return value, nil
}
