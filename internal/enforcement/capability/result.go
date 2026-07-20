package capability

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"net/netip"
	"time"
)

type resultWire struct {
	SchemaVersion       string  `json:"schema_version"`
	ResultID            string  `json:"result_id"`
	CapabilityID        string  `json:"capability_id"`
	CapabilityDigest    string  `json:"capability_digest"`
	Operation           string  `json:"operation"`
	ActionID            string  `json:"action_id"`
	ArtifactDigest      string  `json:"artifact_digest"`
	TargetIPv4          string  `json:"target_ipv4"`
	Classification      string  `json:"classification"`
	NFTExitClass        *string `json:"nft_exit_class"`
	ReadbackState       string  `json:"readback_state"`
	ElementHandle       *uint64 `json:"element_handle"`
	RemainingTTLSeconds *uint64 `json:"remaining_ttl_seconds"`
	OwnedSchemaDigest   string  `json:"owned_schema_digest"`
	StartedAt           string  `json:"started_at"`
	ReadbackStartedAt   *string `json:"readback_started_at"`
	ReadbackCompletedAt *string `json:"readback_completed_at"`
	CompletedAt         string  `json:"completed_at"`
	JournalSequence     uint64  `json:"journal_sequence"`
	ErrorCode           string  `json:"error_code"`
}

// CheckResult validates semantic outcome combinations and freezes JCS bytes.
func CheckResult(input Result) (CheckedResult, error) {
	value := cloneResultValue(input)
	if value.SchemaVersion == "" {
		value.SchemaVersion = ResultSchemaVersion
	}
	value.StartedAt = input.StartedAt.UTC()
	value.CompletedAt = input.CompletedAt.UTC()
	if value.ReadbackStartedAt != nil {
		started := value.ReadbackStartedAt.UTC()
		value.ReadbackStartedAt = &started
	}
	if value.ReadbackCompletedAt != nil {
		completed := value.ReadbackCompletedAt.UTC()
		value.ReadbackCompletedAt = &completed
	}
	if err := checkResultValue(value); err != nil {
		return CheckedResult{}, err
	}
	canonical := marshalResult(value)
	return CheckedResult{value: value, canonical: canonical, digest: digestBytes(canonical)}, nil
}

func checkResultValue(value ResultValue) error {
	if value.SchemaVersion != ResultSchemaVersion && value.SchemaVersion != ResultV2SchemaVersion {
		return reject(ErrorSchema)
	}
	if value.SchemaVersion == ResultSchemaVersion &&
		(value.ReadbackStartedAt != nil || value.ReadbackCompletedAt != nil) {
		return reject(ErrorSchema)
	}
	if !uuidPattern.MatchString(value.ResultID) || !uuidPattern.MatchString(value.CapabilityID) ||
		!uuidPattern.MatchString(value.ActionID) {
		return reject(ErrorIdentity)
	}
	if !digestPattern.MatchString(value.CapabilityDigest) || !digestPattern.MatchString(value.ArtifactDigest) ||
		!digestPattern.MatchString(value.OwnedSchemaDigest) {
		return reject(ErrorDigest)
	}
	address, err := netip.ParseAddr(value.TargetIPv4)
	if err != nil || !address.Is4() || address.String() != value.TargetIPv4 {
		return reject(ErrorResult)
	}
	if value.Operation != OperationAdd && value.Operation != OperationRevoke && value.Operation != OperationInspect {
		return reject(ErrorOperation)
	}
	if !validClassification(value.Operation, value.Classification) || !validExit(value.NFTExitClass) ||
		!validReadback(value.ReadbackState) || !validResultError(value.ErrorCode) {
		return reject(ErrorResult)
	}
	// The pinned v0.1 `list set` read-back does not expose per-element handles.
	// Keep the wire field explicitly null and reject set-handle substitution.
	if value.ElementHandle != nil {
		return reject(ErrorResult)
	}
	if value.RemainingTTLSeconds != nil && *value.RemainingTTLSeconds > 86400 {
		return reject(ErrorResult)
	}
	if value.JournalSequence == 0 || value.JournalSequence > 1<<53-1 || value.StartedAt.IsZero() ||
		value.CompletedAt.IsZero() || value.CompletedAt.Before(value.StartedAt) ||
		!millisecondAligned(value.StartedAt) || !millisecondAligned(value.CompletedAt) ||
		value.CompletedAt.Sub(value.StartedAt) > 2*time.Second {
		return reject(ErrorTime)
	}
	if value.SchemaVersion == ResultV2SchemaVersion {
		if value.ReadbackStartedAt == nil || value.ReadbackCompletedAt == nil ||
			value.ReadbackStartedAt.IsZero() || value.ReadbackCompletedAt.IsZero() ||
			!millisecondAligned(*value.ReadbackStartedAt) || !millisecondAligned(*value.ReadbackCompletedAt) ||
			value.ReadbackStartedAt.Before(value.StartedAt) ||
			value.ReadbackCompletedAt.Before(*value.ReadbackStartedAt) ||
			value.ReadbackCompletedAt.After(value.CompletedAt) {
			return reject(ErrorTime)
		}
	}
	if err := checkOutcome(value); err != nil {
		return err
	}
	return nil
}

func validClassification(operation Operation, class Classification) bool {
	switch operation {
	case OperationAdd:
		return class == ClassificationApplied || class == ClassificationRecoveredActive || class == ClassificationFailed || class == ClassificationIndeterminate
	case OperationRevoke:
		return class == ClassificationRevoked || class == ClassificationFailed || class == ClassificationIndeterminate
	case OperationInspect:
		return class == ClassificationInspectActive || class == ClassificationInspectAbsent || class == ClassificationInspectMismatch || class == ClassificationFailed || class == ClassificationIndeterminate
	default:
		return false
	}
}

func validExit(value *NFTExitClass) bool {
	if value == nil {
		return true
	}
	switch *value {
	case NFTExitSuccess, NFTExitNotInvoked, NFTExitNonzero, NFTExitTimeout, NFTExitSignaled:
		return true
	default:
		return false
	}
}

func validReadback(value ReadbackState) bool {
	return value == ReadbackActive || value == ReadbackAbsent || value == ReadbackMismatch || value == ReadbackUnavailable
}

func validResultError(value ResultErrorCode) bool {
	switch value {
	case ResultErrorNone, ResultErrorCapabilityInvalid, ResultErrorArtifactMismatch, ResultErrorSchemaMismatch,
		ResultErrorTargetExists, ResultErrorTargetAbsent, ResultErrorNFTFailed, ResultErrorReadbackFailed,
		ResultErrorReadbackMismatch, ResultErrorJournalFailed, ResultErrorDeadlineExceeded,
		ResultErrorReplayConflict, ResultErrorIndeterminate:
		return true
	default:
		return false
	}
}

func checkOutcome(value ResultValue) error {
	success := value.Classification != ClassificationFailed && value.Classification != ClassificationIndeterminate
	if success != (value.ErrorCode == ResultErrorNone) {
		return reject(ErrorResult)
	}
	switch value.Classification {
	case ClassificationApplied:
		if value.NFTExitClass == nil || *value.NFTExitClass != NFTExitSuccess || value.ReadbackState != ReadbackActive ||
			value.ElementHandle != nil || value.RemainingTTLSeconds == nil || *value.RemainingTTLSeconds == 0 {
			return reject(ErrorResult)
		}
	case ClassificationRecoveredActive:
		if value.NFTExitClass == nil || *value.NFTExitClass != NFTExitNotInvoked || value.ReadbackState != ReadbackActive ||
			value.ElementHandle != nil || value.RemainingTTLSeconds == nil || *value.RemainingTTLSeconds == 0 {
			return reject(ErrorResult)
		}
	case ClassificationRevoked, ClassificationInspectAbsent:
		if value.NFTExitClass == nil || (*value.NFTExitClass != NFTExitSuccess && *value.NFTExitClass != NFTExitNotInvoked) ||
			value.ReadbackState != ReadbackAbsent || value.ElementHandle != nil || value.RemainingTTLSeconds != nil {
			return reject(ErrorResult)
		}
	case ClassificationInspectActive:
		if value.NFTExitClass == nil || *value.NFTExitClass != NFTExitSuccess || value.ReadbackState != ReadbackActive ||
			value.ElementHandle != nil || value.RemainingTTLSeconds == nil || *value.RemainingTTLSeconds == 0 {
			return reject(ErrorResult)
		}
	case ClassificationInspectMismatch:
		if value.NFTExitClass == nil || *value.NFTExitClass != NFTExitSuccess || value.ReadbackState != ReadbackMismatch {
			return reject(ErrorResult)
		}
	}
	return nil
}

// ParseCanonicalResult accepts only byte-exact RFC 8785/JCS encoding.
func ParseCanonicalResult(data []byte) (CheckedResult, error) {
	var wire resultWire
	if err := strictDecode(data, MaxResultBytes, &wire); err != nil {
		return CheckedResult{}, err
	}
	if wire.SchemaVersion != ResultSchemaVersion && wire.SchemaVersion != ResultV2SchemaVersion {
		return CheckedResult{}, reject(ErrorSchema)
	}
	startedAt, startedOK := parseCanonicalTime(wire.StartedAt)
	completedAt, completedOK := parseCanonicalTime(wire.CompletedAt)
	if !startedOK || !completedOK {
		return CheckedResult{}, reject(ErrorTime)
	}
	var readbackStartedAt, readbackCompletedAt *time.Time
	if wire.SchemaVersion == ResultV2SchemaVersion {
		if wire.ReadbackStartedAt == nil || wire.ReadbackCompletedAt == nil {
			return CheckedResult{}, reject(ErrorTime)
		}
		started, startedOK := parseCanonicalTime(*wire.ReadbackStartedAt)
		completed, completedOK := parseCanonicalTime(*wire.ReadbackCompletedAt)
		if !startedOK || !completedOK {
			return CheckedResult{}, reject(ErrorTime)
		}
		readbackStartedAt, readbackCompletedAt = &started, &completed
	} else if wire.ReadbackStartedAt != nil || wire.ReadbackCompletedAt != nil {
		return CheckedResult{}, reject(ErrorSchema)
	}
	var exitClass *NFTExitClass
	if wire.NFTExitClass != nil {
		converted := NFTExitClass(*wire.NFTExitClass)
		exitClass = &converted
	}
	checked, err := CheckResult(Result{
		SchemaVersion: wire.SchemaVersion,
		ResultID:      wire.ResultID, CapabilityID: wire.CapabilityID, CapabilityDigest: wire.CapabilityDigest,
		Operation: Operation(wire.Operation), ActionID: wire.ActionID, ArtifactDigest: wire.ArtifactDigest,
		TargetIPv4: wire.TargetIPv4, Classification: Classification(wire.Classification), NFTExitClass: exitClass,
		ReadbackState: ReadbackState(wire.ReadbackState), ElementHandle: wire.ElementHandle,
		RemainingTTLSeconds: wire.RemainingTTLSeconds, OwnedSchemaDigest: wire.OwnedSchemaDigest,
		StartedAt: startedAt, ReadbackStartedAt: readbackStartedAt, ReadbackCompletedAt: readbackCompletedAt, CompletedAt: completedAt, JournalSequence: wire.JournalSequence,
		ErrorCode: ResultErrorCode(wire.ErrorCode),
	})
	if err != nil {
		return CheckedResult{}, err
	}
	expected := marshalResultTimes(checked.value, wire.StartedAt, wire.ReadbackStartedAt, wire.ReadbackCompletedAt, wire.CompletedAt)
	if !bytes.Equal(data, expected) {
		return CheckedResult{}, reject(ErrorCanonical)
	}
	checked.canonical = clone(data)
	checked.digest = digestBytes(data)
	return checked, nil
}

func marshalResult(value ResultValue) []byte {
	var readbackStarted, readbackCompleted *string
	if value.ReadbackStartedAt != nil {
		formatted := formatCanonicalTime(*value.ReadbackStartedAt)
		readbackStarted = &formatted
	}
	if value.ReadbackCompletedAt != nil {
		formatted := formatCanonicalTime(*value.ReadbackCompletedAt)
		readbackCompleted = &formatted
	}
	return marshalResultTimes(value, formatCanonicalTime(value.StartedAt), readbackStarted, readbackCompleted, formatCanonicalTime(value.CompletedAt))
}

func marshalResultTimes(value ResultValue, startedAt string, readbackStartedAt, readbackCompletedAt *string, completedAt string) []byte {
	result := make([]byte, 0, 1300)
	result = append(result, `{"action_id":`...)
	result = appendString(result, value.ActionID)
	result = append(result, `,"artifact_digest":`...)
	result = appendString(result, value.ArtifactDigest)
	result = append(result, `,"capability_digest":`...)
	result = appendString(result, value.CapabilityDigest)
	result = append(result, `,"capability_id":`...)
	result = appendString(result, value.CapabilityID)
	result = append(result, `,"classification":`...)
	result = appendString(result, string(value.Classification))
	result = append(result, `,"completed_at":`...)
	result = appendString(result, completedAt)
	result = append(result, `,"element_handle":`...)
	result = appendNullableUint(result, value.ElementHandle)
	result = append(result, `,"error_code":`...)
	result = appendString(result, string(value.ErrorCode))
	result = append(result, `,"journal_sequence":`...)
	result = appendUint(result, value.JournalSequence)
	result = append(result, `,"nft_exit_class":`...)
	if value.NFTExitClass == nil {
		result = append(result, "null"...)
	} else {
		result = appendString(result, string(*value.NFTExitClass))
	}
	result = append(result, `,"operation":`...)
	result = appendString(result, string(value.Operation))
	result = append(result, `,"owned_schema_digest":`...)
	result = appendString(result, value.OwnedSchemaDigest)
	if value.SchemaVersion == ResultV2SchemaVersion {
		result = append(result, `,"readback_completed_at":`...)
		if readbackCompletedAt == nil {
			result = append(result, "null"...)
		} else {
			result = appendString(result, *readbackCompletedAt)
		}
		result = append(result, `,"readback_started_at":`...)
		if readbackStartedAt == nil {
			result = append(result, "null"...)
		} else {
			result = appendString(result, *readbackStartedAt)
		}
	}
	result = append(result, `,"readback_state":`...)
	result = appendString(result, string(value.ReadbackState))
	result = append(result, `,"remaining_ttl_seconds":`...)
	result = appendNullableUint(result, value.RemainingTTLSeconds)
	result = append(result, `,"result_id":`...)
	result = appendString(result, value.ResultID)
	result = append(result, `,"schema_version":`...)
	result = appendString(result, value.SchemaVersion)
	result = append(result, `,"started_at":`...)
	result = appendString(result, startedAt)
	result = append(result, `,"target_ipv4":`...)
	result = appendString(result, value.TargetIPv4)
	return append(result, '}')
}

// ResultSigner exists only in the executor and cannot sign a capability.
type ResultSigner struct {
	keyID      string
	executorID string
	key        ed25519.PrivateKey
}

func NewResultSigner(keyID, executorID string, key ed25519.PrivateKey) (ResultSigner, error) {
	if !keyIDPattern.MatchString(keyID) || !actorPattern.MatchString(executorID) || !validPrivateKey(key) {
		return ResultSigner{}, reject(ErrorKey)
	}
	return ResultSigner{keyID: keyID, executorID: executorID, key: clone(key)}, nil
}

// SignFor requires the verified request that the result claims to describe.
func (s ResultSigner) SignFor(capability VerifiedCapability, checked CheckedResult) (SignedResult, error) {
	if len(s.key) != ed25519.PrivateKeySize || len(checked.canonical) == 0 ||
		!digestEqual(checked.digest, digestBytes(checked.canonical)) {
		return SignedResult{}, reject(ErrorUnchecked)
	}
	if err := bindResult(checked.value, capability, s.executorID); err != nil {
		return SignedResult{}, err
	}
	domain, ok := resultSigningDomain(checked.value.SchemaVersion)
	if !ok {
		return SignedResult{}, reject(ErrorSchema)
	}
	signature := ed25519.Sign(s.key, signingInput(domain, checked.canonical))
	return SignedResult{keyID: s.keyID, executorID: s.executorID, canonical: clone(checked.canonical), signature: signature}, nil
}

func NewUntrustedSignedResult(keyID, executorID string, canonical, signature []byte) SignedResult {
	return SignedResult{keyID: keyID, executorID: executorID, canonical: clone(canonical), signature: clone(signature)}
}

// ResultVerifier exists only in the dispatcher and has the executor's distinct
// result public key, never the dispatch private key.
type ResultVerifier struct {
	keyID      string
	executorID string
	key        ed25519.PublicKey
}

func (v ResultVerifier) KeyID() string      { return v.keyID }
func (v ResultVerifier) ExecutorID() string { return v.executorID }

func NewResultVerifier(keyID, executorID string, key ed25519.PublicKey) (ResultVerifier, error) {
	if !keyIDPattern.MatchString(keyID) || !actorPattern.MatchString(executorID) || len(key) != ed25519.PublicKeySize {
		return ResultVerifier{}, reject(ErrorKey)
	}
	return ResultVerifier{keyID: keyID, executorID: executorID, key: clone(key)}, nil
}

func (v ResultVerifier) Verify(signed SignedResult) (VerifiedResult, error) {
	if len(v.key) != ed25519.PublicKeySize ||
		subtle.ConstantTimeCompare([]byte(v.keyID), []byte(signed.keyID)) != 1 ||
		subtle.ConstantTimeCompare([]byte(v.executorID), []byte(signed.executorID)) != 1 {
		return VerifiedResult{}, reject(ErrorKeyRole)
	}
	if len(signed.canonical) == 0 || len(signed.canonical) > MaxResultBytes ||
		len(signed.signature) != ed25519.SignatureSize {
		return VerifiedResult{}, reject(ErrorSignature)
	}
	domain, ok := resultSigningDomainFromCanonical(signed.canonical)
	if !ok ||
		!ed25519.Verify(v.key, signingInput(domain, signed.canonical), signed.signature) {
		return VerifiedResult{}, reject(ErrorSignature)
	}
	checked, err := ParseCanonicalResult(signed.canonical)
	if err != nil {
		return VerifiedResult{}, err
	}
	return VerifiedResult{value: checked.value, canonical: clone(checked.canonical), digest: checked.digest, keyID: v.keyID, executorID: v.executorID}, nil
}

func resultSigningDomain(schemaVersion string) (string, bool) {
	switch schemaVersion {
	case ResultSchemaVersion:
		return ResultSigningDomain, true
	case ResultV2SchemaVersion:
		return ResultV2SigningDomain, true
	default:
		return "", false
	}
}

func resultSigningDomainFromCanonical(data []byte) (string, bool) {
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return "", false
	}
	return resultSigningDomain(header.SchemaVersion)
}

// BindTo checks the signed result against the exact verified request.
func (r VerifiedResult) BindTo(capability VerifiedCapability) (BoundResult, error) {
	if err := bindResult(r.value, capability, r.executorID); err != nil {
		return BoundResult{}, err
	}
	return BoundResult{result: r, capability: capability}, nil
}

func bindResult(result ResultValue, capability VerifiedCapability, executorID string) error {
	if executorID == "" || executorID != capability.executorID || len(capability.canonical) == 0 ||
		result.CapabilityID != capability.value.CapabilityID || result.Operation != capability.value.Operation ||
		result.ActionID != capability.value.ActionID || result.TargetIPv4 != capability.value.TargetIPv4 ||
		!digestEqual(result.CapabilityDigest, capability.digest) ||
		!digestEqual(result.ArtifactDigest, capability.value.ArtifactDigest) ||
		!digestEqual(result.OwnedSchemaDigest, capability.value.OwnedSchemaDigest) {
		return reject(ErrorResultBinding)
	}
	// Capability expiry limits release of mutation authority, not later signed
	// read-back or crash-recovery attestation. Journal Begin/Permit proves that
	// any mutation started while fresh; a result assessment may truthfully occur
	// after expiry but can never recreate an ExecutableAdd/ExecutableRevoke.
	if result.StartedAt.Before(capability.value.NotBefore) {
		return reject(ErrorResultBinding)
	}
	if result.Operation == OperationAdd && result.RemainingTTLSeconds != nil &&
		(*result.RemainingTTLSeconds > uint64(capability.addTTL) || capability.addTTL == 0) {
		return reject(ErrorResultBinding)
	}
	return nil
}
