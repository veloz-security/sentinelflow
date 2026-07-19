package recoverybundle

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
	"github.com/devwooops/sentinelflow/internal/enforcement/keyidentity"
)

const (
	executionArtifactRowVersionV1 = "sentinelflow-execution-artifact-row-v1"
	executionArtifactRowVersionV2 = "sentinelflow-execution-artifact-row-v2"
	executionArtifactRowVersion   = executionArtifactRowVersionV2
	lifecycleApplicationVersion   = "lifecycle-result-application-v1"
	maxExecutionArtifactRows      = 100_000
	maxExecutionArtifactRowSize   = 256 * 1024
)

type executionArtifactRow struct {
	SchemaVersion        string                                 `json:"schema_version"`
	Job                  executionArtifactJob                   `json:"job"`
	Operation            executionArtifactOperation             `json:"operation"`
	Capability           executionArtifactCapability            `json:"capability"`
	Result               *executionArtifactResult               `json:"result"`
	LifecycleApplication *executionArtifactLifecycleApplication `json:"lifecycle_application,omitempty"`
}

type executionArtifactJob struct {
	JobID                      string  `json:"job_id"`
	Kind                       string  `json:"kind"`
	Operation                  string  `json:"operation"`
	State                      string  `json:"state"`
	AggregateType              string  `json:"aggregate_type"`
	AggregateID                string  `json:"aggregate_id"`
	AggregateVersion           int32   `json:"aggregate_version"`
	AvailableAt                string  `json:"available_at"`
	Attempts                   int32   `json:"attempts"`
	MaxAttempts                int32   `json:"max_attempts"`
	LastErrorCode              *string `json:"last_error_code"`
	LastErrorDigest            *string `json:"last_error_digest"`
	DeadLetterState            *string `json:"dead_letter_state"`
	DeadLetterJobID            *string `json:"dead_letter_job_id"`
	DeadLetterKind             *string `json:"dead_letter_kind"`
	DeadLetterAggregateType    *string `json:"dead_letter_aggregate_type"`
	DeadLetterAggregateID      *string `json:"dead_letter_aggregate_id"`
	DeadLetterAggregateVersion *int32  `json:"dead_letter_aggregate_version"`
	DeadLetterAttempts         *int32  `json:"dead_letter_attempts"`
	DeadLetterFailureCode      *string `json:"dead_letter_failure_code"`
	DeadLetterFailureDigest    *string `json:"dead_letter_failure_digest"`
	DeadLetterDeadAt           *string `json:"dead_letter_dead_at"`
	DeadLetterResolvedAt       *string `json:"dead_letter_resolved_at"`
	DeadLetterResolutionActor  *string `json:"dead_letter_resolution_actor"`
	DeadLetterResolutionDigest *string `json:"dead_letter_resolution_digest"`
	UpdatedAt                  string  `json:"updated_at"`
}

type executionArtifactOperation struct {
	JobID                    string  `json:"job_id"`
	Operation                string  `json:"operation"`
	ActionID                 string  `json:"action_id"`
	PolicyID                 string  `json:"policy_id"`
	PolicyVersion            uint32  `json:"policy_version"`
	TargetIPv4               string  `json:"target_ipv4"`
	ArtifactHex              string  `json:"artifact_hex"`
	ArtifactDigest           string  `json:"artifact_digest"`
	OriginalAddDigest        *string `json:"original_add_digest"`
	EvidenceSnapshotDigest   string  `json:"evidence_snapshot_digest"`
	ValidationSnapshotDigest string  `json:"validation_snapshot_digest"`
	AuthorizationDigest      string  `json:"authorization_digest"`
	ActorID                  string  `json:"actor_id"`
	ReasonDigest             string  `json:"reason_digest"`
	OwnedSchemaDigest        string  `json:"owned_schema_digest"`
	NotBefore                string  `json:"not_before"`
	ValidUntil               string  `json:"valid_until"`
}

type executionArtifactCapability struct {
	CapabilityID             string  `json:"capability_id"`
	SchemaVersion            string  `json:"schema_version"`
	JobID                    string  `json:"job_id"`
	Operation                string  `json:"operation"`
	ActionID                 string  `json:"action_id"`
	PolicyID                 string  `json:"policy_id"`
	PolicyVersion            uint32  `json:"policy_version"`
	TargetIPv4               string  `json:"target_ipv4"`
	ArtifactHex              string  `json:"artifact_hex"`
	ArtifactDigest           string  `json:"artifact_digest"`
	OriginalAddDigest        *string `json:"original_add_digest"`
	EvidenceSnapshotDigest   string  `json:"evidence_snapshot_digest"`
	ValidationSnapshotDigest string  `json:"validation_snapshot_digest"`
	AuthorizationDigest      string  `json:"authorization_digest"`
	ActorID                  string  `json:"actor_id"`
	ReasonDigest             string  `json:"reason_digest"`
	OwnedSchemaDigest        string  `json:"owned_schema_digest"`
	JCSHex                   string  `json:"capability_jcs_hex"`
	Digest                   string  `json:"capability_digest"`
	SignatureHex             string  `json:"capability_signature_hex"`
	NonceDigest              string  `json:"nonce_digest"`
	IssuedAt                 string  `json:"issued_at"`
	NotBefore                string  `json:"not_before"`
	ExpiresAt                string  `json:"expires_at"`
	ConsumedAt               *string `json:"consumed_at"`
}

type executionArtifactResult struct {
	ResultID            string  `json:"result_id"`
	SchemaVersion       string  `json:"schema_version"`
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
	CompletedAt         string  `json:"completed_at"`
	JournalSequence     uint64  `json:"journal_sequence"`
	ErrorCode           string  `json:"error_code"`
	JCSHex              string  `json:"result_jcs_hex"`
	Digest              string  `json:"result_digest"`
	SignatureHex        string  `json:"result_signature_hex"`
	PersistedAt         string  `json:"persisted_at"`
}

type executionArtifactLifecycleApplication struct {
	SchemaVersion          string `json:"schema_version"`
	JobID                  string `json:"job_id"`
	CapabilityID           string `json:"capability_id"`
	ResultID               string `json:"result_id"`
	ResultDigest           string `json:"result_digest"`
	ActionID               string `json:"action_id"`
	Operation              string `json:"operation"`
	Classification         string `json:"classification"`
	ResultingState         string `json:"resulting_state"`
	ResultingActionVersion int32  `json:"resulting_action_version"`
	ProcessedAt            string `json:"processed_at"`
}

type executionArtifactBinding struct {
	capabilityID     string
	capabilityDigest string
	artifactDigest   string
	terminal         bool
	resultDigest     string
	journalSequence  uint64
}

// ValidateExecutionArtifactRows authenticates every NDJSON row using only the
// two role-separated public keys. The SQL producer supplies exact byte columns
// as lowercase hex; JSON is never used to reinterpret capability/result JCS.
// The existing strict parsers therefore reject missing, unknown, duplicate,
// non-canonical, whitespace-padded, or re-encoded signed payload bytes.
func ValidateExecutionArtifactRows(
	input io.Reader,
	dispatchPublic ed25519.PublicKey,
	resultPublic ed25519.PublicKey,
) error {
	return validateExecutionArtifactRows(input, dispatchPublic, resultPublic, nil)
}

// ValidateJournalExecutionArtifactRows applies the executor's exact read-only
// startup parser to the replay journal, then requires every retained database
// artifact to match one authenticated journal lifecycle. Extra authenticated
// terminal history is permitted because database retention removes old
// capability/result rows while the executor journal is append-only. Started
// history is never permitted to become orphaned: it must match a retained,
// unconsumed capability whose dispatch job is durably dead/non-runnable.
func ValidateJournalExecutionArtifactRows(
	replayJournal []byte,
	input io.Reader,
	dispatchPublic ed25519.PublicKey,
	resultPublic ed25519.PublicKey,
) error {
	if len(replayJournal) > journal.MaxJournalBytes {
		return reject(CodeContents)
	}
	identities, err := keyidentity.Derive(dispatchPublic, resultPublic)
	if err != nil {
		return reject(CodeContents)
	}
	capabilityVerifier, err := capability.NewCapabilityVerifier(
		identities.DispatchKeyID, identities.ExecutorID, dispatchPublic,
	)
	if err != nil {
		return reject(CodeContents)
	}
	resultVerifier, err := capability.NewResultVerifier(
		identities.ResultKeyID, identities.ExecutorID, resultPublic,
	)
	if err != nil {
		return reject(CodeContents)
	}
	summary, err := journal.ValidateBytes(replayJournal, capabilityVerifier, resultVerifier)
	if err != nil {
		return reject(CodeContents)
	}
	bindings := make(map[string]executionArtifactBinding, len(summary.Entries))
	if err := validateExecutionArtifactRows(
		input, dispatchPublic, resultPublic,
		func(binding executionArtifactBinding) error {
			if _, exists := bindings[binding.capabilityID]; exists {
				return reject(CodeContents)
			}
			bindings[binding.capabilityID] = binding
			return nil
		},
	); err != nil {
		return err
	}
	for _, entry := range summary.Entries {
		binding, exists := bindings[entry.CapabilityID]
		if !exists {
			if !entry.Terminal || entry.TerminalSequence <= entry.StartedSequence {
				return reject(CodeContents)
			}
			continue
		}
		if binding.capabilityDigest != entry.CapabilityDigest ||
			binding.artifactDigest != entry.ArtifactDigest ||
			(binding.terminal && !entry.Terminal) {
			return reject(CodeContents)
		}
		if binding.terminal && (entry.TerminalSequence <= entry.StartedSequence ||
			binding.resultDigest != entry.ResultDigest ||
			binding.journalSequence != entry.StartedSequence) {
			return reject(CodeContents)
		}
		delete(bindings, entry.CapabilityID)
	}
	if len(bindings) != 0 {
		return reject(CodeContents)
	}
	return nil
}

// ValidateJournalExecutionArtifactFile safely reads one private regular replay
// file and delegates to the byte-exact journal/database reconciler.
func ValidateJournalExecutionArtifactFile(
	path string,
	input io.Reader,
	dispatchPublic ed25519.PublicKey,
	resultPublic ed25519.PublicKey,
) error {
	if !canonicalAbs(path) {
		return reject(CodeArgument)
	}
	contents, _, err := readSafe(path, 0o600, journal.MaxJournalBytes, true)
	if err != nil {
		return err
	}
	defer clear(contents)
	return ValidateJournalExecutionArtifactRows(contents, input, dispatchPublic, resultPublic)
}

func validateExecutionArtifactRows(
	input io.Reader,
	dispatchPublic ed25519.PublicKey,
	resultPublic ed25519.PublicKey,
	onValidated func(executionArtifactBinding) error,
) error {
	if input == nil || len(dispatchPublic) != ed25519.PublicKeySize ||
		len(resultPublic) != ed25519.PublicKeySize ||
		subtle.ConstantTimeCompare(dispatchPublic, resultPublic) == 1 {
		return reject(CodeArgument)
	}
	identities, err := keyidentity.Derive(dispatchPublic, resultPublic)
	if err != nil {
		return reject(CodeContents)
	}
	capabilityVerifier, err := capability.NewCapabilityVerifier(
		identities.DispatchKeyID, identities.ExecutorID, dispatchPublic,
	)
	if err != nil {
		return reject(CodeContents)
	}
	resultVerifier, err := capability.NewResultVerifier(
		identities.ResultKeyID, identities.ExecutorID, resultPublic,
	)
	if err != nil {
		return reject(CodeContents)
	}

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxExecutionArtifactRowSize)
	previousCapabilityID := ""
	rows := 0
	for scanner.Scan() {
		rows++
		if rows > maxExecutionArtifactRows || len(scanner.Bytes()) == 0 {
			return reject(CodeContents)
		}
		var row executionArtifactRow
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&row); err != nil || requireJSONEOF(decoder) != nil ||
			(row.SchemaVersion != executionArtifactRowVersionV1 &&
				row.SchemaVersion != executionArtifactRowVersionV2) ||
			row.Capability.CapabilityID <= previousCapabilityID {
			return reject(CodeContents)
		}
		if err := validateExecutionArtifactRow(row, capabilityVerifier, resultVerifier); err != nil {
			return err
		}
		if onValidated != nil {
			binding := executionArtifactBinding{
				capabilityID:     row.Capability.CapabilityID,
				capabilityDigest: row.Capability.Digest,
				artifactDigest:   row.Capability.ArtifactDigest,
			}
			if row.Result != nil {
				binding.terminal = true
				binding.resultDigest = row.Result.Digest
				binding.journalSequence = row.Result.JournalSequence
			}
			if err := onValidated(binding); err != nil {
				return err
			}
		}
		previousCapabilityID = row.Capability.CapabilityID
	}
	if scanner.Err() != nil {
		return reject(CodeContents)
	}
	return nil
}

func validateExecutionArtifactRow(
	row executionArtifactRow,
	capabilityVerifier capability.CapabilityVerifier,
	resultVerifier capability.ResultVerifier,
) error {
	if row.SchemaVersion == executionArtifactRowVersionV1 && row.LifecycleApplication != nil {
		return reject(CodeContents)
	}
	capabilityJCS, ok := decodeCanonicalHex(row.Capability.JCSHex, capability.MaxCapabilityBytes)
	if !ok {
		return reject(CodeContents)
	}
	defer clear(capabilityJCS)
	artifact, ok := decodeCanonicalHex(row.Capability.ArtifactHex, capability.MaxArtifactBytes)
	if !ok {
		return reject(CodeContents)
	}
	defer clear(artifact)
	operationArtifact, ok := decodeCanonicalHex(row.Operation.ArtifactHex, capability.MaxArtifactBytes)
	if !ok {
		return reject(CodeContents)
	}
	defer clear(operationArtifact)
	capabilitySignature, ok := decodeCanonicalHex(row.Capability.SignatureHex, ed25519.SignatureSize)
	if !ok || len(capabilitySignature) != ed25519.SignatureSize {
		return reject(CodeContents)
	}
	defer clear(capabilitySignature)
	signedCapability := capability.NewUntrustedSignedCapability(
		capabilityVerifier.KeyID(), capabilityJCS, capabilitySignature, artifact,
	)
	verifiedCapability, err := capabilityVerifier.Verify(signedCapability)
	if err != nil {
		return reject(CodeContents)
	}
	value := verifiedCapability.Value()
	issuedAt, issuedOK := parseDatabaseTime(row.Capability.IssuedAt)
	capabilityNotBefore, capabilityNotBeforeOK := parseDatabaseTime(row.Capability.NotBefore)
	expiresAt, expiresOK := parseDatabaseTime(row.Capability.ExpiresAt)
	operationNotBefore, operationNotBeforeOK := parseDatabaseTime(row.Operation.NotBefore)
	operationValidUntil, operationValidUntilOK := parseDatabaseTime(row.Operation.ValidUntil)
	jobAvailableAt, jobAvailableOK := parseDatabaseTime(row.Job.AvailableAt)
	jobUpdatedAt, jobUpdatedOK := parseDatabaseTime(row.Job.UpdatedAt)
	if !issuedOK || !capabilityNotBeforeOK || !expiresOK ||
		!operationNotBeforeOK || !operationValidUntilOK || !jobAvailableOK || !jobUpdatedOK ||
		row.Job.Attempts < 0 || row.Job.MaxAttempts < 1 || row.Job.Attempts > row.Job.MaxAttempts ||
		row.Job.AggregateType != "enforcement_action" || row.Job.AggregateVersion < 1 {
		return reject(CodeContents)
	}
	nonceDigest, ok := executionNonceDigest(value.Nonce)
	if !ok {
		return reject(CodeContents)
	}
	originalAdd := nullableDigest(value.OriginalAddDigest)
	if row.Capability.CapabilityID != value.CapabilityID ||
		row.Capability.SchemaVersion != value.SchemaVersion ||
		row.Capability.JobID != value.JobID ||
		row.Capability.Operation != string(value.Operation) ||
		row.Capability.ActionID != value.ActionID ||
		row.Capability.PolicyID != value.PolicyID ||
		row.Capability.PolicyVersion != value.PolicyVersion ||
		row.Capability.TargetIPv4 != value.TargetIPv4 ||
		row.Capability.ArtifactDigest != value.ArtifactDigest ||
		!sameNullableString(row.Capability.OriginalAddDigest, originalAdd) ||
		row.Capability.EvidenceSnapshotDigest != value.EvidenceSnapshotDigest ||
		row.Capability.ValidationSnapshotDigest != value.ValidationSnapshotDigest ||
		row.Capability.AuthorizationDigest != value.AuthorizationDigest ||
		row.Capability.ActorID != value.ActorID ||
		row.Capability.ReasonDigest != value.ReasonDigest ||
		row.Capability.OwnedSchemaDigest != value.OwnedSchemaDigest ||
		row.Capability.Digest != verifiedCapability.Digest() ||
		row.Capability.NonceDigest != nonceDigest ||
		!issuedAt.Equal(value.IssuedAt) || !capabilityNotBefore.Equal(value.NotBefore) ||
		!expiresAt.Equal(value.ExpiresAt) || !bytes.Equal(artifact, operationArtifact) {
		return reject(CodeContents)
	}

	if row.Job.JobID != value.JobID ||
		row.Job.Operation != string(value.Operation) || row.Job.Kind != "dispatch_"+string(value.Operation) ||
		row.Job.AggregateID != value.ActionID ||
		row.Operation.JobID != value.JobID || row.Operation.Operation != string(value.Operation) ||
		row.Operation.ActionID != value.ActionID || row.Operation.PolicyID != value.PolicyID ||
		row.Operation.PolicyVersion != value.PolicyVersion || row.Operation.TargetIPv4 != value.TargetIPv4 ||
		row.Operation.ArtifactDigest != value.ArtifactDigest ||
		!sameNullableString(row.Operation.OriginalAddDigest, originalAdd) ||
		row.Operation.EvidenceSnapshotDigest != value.EvidenceSnapshotDigest ||
		row.Operation.ValidationSnapshotDigest != value.ValidationSnapshotDigest ||
		row.Operation.AuthorizationDigest != value.AuthorizationDigest ||
		row.Operation.ActorID != value.ActorID || row.Operation.ReasonDigest != value.ReasonDigest ||
		row.Operation.OwnedSchemaDigest != value.OwnedSchemaDigest ||
		value.NotBefore.Before(operationNotBefore) || value.ExpiresAt.After(operationValidUntil) {
		return reject(CodeContents)
	}
	if row.Result == nil {
		if row.Capability.ConsumedAt != nil || row.LifecycleApplication != nil {
			return reject(CodeContents)
		}
		switch row.Job.State {
		case "dead":
			if row.Job.LastErrorCode == nil || row.Job.LastErrorDigest == nil {
				return reject(CodeContents)
			}
			if !validDeadLetterIdentity(row.Job, value) ||
				row.Job.DeadLetterState == nil || *row.Job.DeadLetterState != "unresolved" ||
				row.Job.DeadLetterResolvedAt != nil || row.Job.DeadLetterResolutionActor != nil ||
				row.Job.DeadLetterResolutionDigest != nil ||
				row.Job.DeadLetterFailureCode == nil || row.Job.DeadLetterFailureDigest == nil ||
				*row.Job.LastErrorCode != *row.Job.DeadLetterFailureCode ||
				*row.Job.LastErrorDigest != *row.Job.DeadLetterFailureDigest {
				return reject(CodeContents)
			}
		case "retry":
			if !validDeadLetterIdentity(row.Job, value) ||
				row.Job.LastErrorCode == nil || *row.Job.LastErrorCode != "recovery_started" ||
				row.Job.LastErrorDigest == nil ||
				*row.Job.LastErrorDigest != recoveryStartedDigest(row.Job, row.Capability.Digest) ||
				jobAvailableAt.Before(value.ExpiresAt) ||
				!validRecoveryDeadLetter(row.Job, row.Capability.Digest, "requeued", jobUpdatedAt, true) {
				return reject(CodeContents)
			}
		default:
			return reject(CodeContents)
		}
		return nil
	}
	if row.Job.State != "completed" || row.Capability.ConsumedAt == nil ||
		row.Job.LastErrorCode != nil || row.Job.LastErrorDigest != nil {
		return reject(CodeContents)
	}
	consumedAt, consumedOK := parseDatabaseTime(*row.Capability.ConsumedAt)
	if !consumedOK {
		return reject(CodeContents)
	}

	resultJCS, ok := decodeCanonicalHex(row.Result.JCSHex, capability.MaxResultBytes)
	if !ok {
		return reject(CodeContents)
	}
	defer clear(resultJCS)
	resultSignature, ok := decodeCanonicalHex(row.Result.SignatureHex, ed25519.SignatureSize)
	if !ok || len(resultSignature) != ed25519.SignatureSize {
		return reject(CodeContents)
	}
	defer clear(resultSignature)
	verifiedResult, err := resultVerifier.Verify(capability.NewUntrustedSignedResult(
		resultVerifier.KeyID(), resultVerifier.ExecutorID(), resultJCS, resultSignature,
	))
	if err != nil {
		return reject(CodeContents)
	}
	if _, err := verifiedResult.BindTo(verifiedCapability); err != nil {
		return reject(CodeContents)
	}
	result := verifiedResult.Value()
	startedAt, startedOK := parseDatabaseTime(row.Result.StartedAt)
	completedAt, completedOK := parseDatabaseTime(row.Result.CompletedAt)
	persistedAt, persistedOK := parseDatabaseTime(row.Result.PersistedAt)
	if !startedOK || !completedOK || !persistedOK ||
		row.Result.ResultID != result.ResultID || row.Result.SchemaVersion != capability.ResultSchemaVersion ||
		row.Result.CapabilityID != result.CapabilityID || row.Result.CapabilityDigest != result.CapabilityDigest ||
		row.Result.Operation != string(result.Operation) || row.Result.ActionID != result.ActionID ||
		row.Result.ArtifactDigest != result.ArtifactDigest || row.Result.TargetIPv4 != result.TargetIPv4 ||
		row.Result.Classification != string(result.Classification) ||
		!sameNullableEnum(row.Result.NFTExitClass, result.NFTExitClass) ||
		row.Result.ReadbackState != string(result.ReadbackState) ||
		!sameNullableUint(row.Result.ElementHandle, result.ElementHandle) ||
		!sameNullableUint(row.Result.RemainingTTLSeconds, result.RemainingTTLSeconds) ||
		row.Result.OwnedSchemaDigest != result.OwnedSchemaDigest ||
		!startedAt.Equal(result.StartedAt) || !completedAt.Equal(result.CompletedAt) ||
		row.Result.JournalSequence != result.JournalSequence || row.Result.ErrorCode != string(result.ErrorCode) ||
		row.Result.Digest != verifiedResult.Digest() || !consumedAt.Equal(result.CompletedAt) ||
		persistedAt.Before(result.CompletedAt) || jobUpdatedAt.Before(result.CompletedAt) {
		return reject(CodeContents)
	}
	if row.SchemaVersion == executionArtifactRowVersionV2 {
		if !validLifecycleApplication(row, result, completedAt, jobUpdatedAt) {
			return reject(CodeContents)
		}
	} else if row.LifecycleApplication != nil {
		return reject(CodeContents)
	}
	if !validTerminalDeadLetter(
		row.Job, value, row.Capability.Digest, jobUpdatedAt,
		row.SchemaVersion == executionArtifactRowVersionV2 && row.LifecycleApplication != nil,
	) {
		return reject(CodeContents)
	}
	return nil
}

func validLifecycleApplication(
	row executionArtifactRow,
	result capability.Result,
	completedAt time.Time,
	jobUpdatedAt time.Time,
) bool {
	application := row.LifecycleApplication
	if application == nil || application.SchemaVersion != lifecycleApplicationVersion ||
		application.JobID != row.Job.JobID ||
		application.CapabilityID != row.Capability.CapabilityID ||
		application.ResultID != result.ResultID ||
		application.ResultDigest != row.Result.Digest ||
		application.ActionID != result.ActionID ||
		application.Operation != string(result.Operation) ||
		application.Classification != string(result.Classification) ||
		application.ResultingActionVersion < 1 ||
		application.ResultingActionVersion != row.Job.AggregateVersion ||
		row.Job.AggregateID != application.ActionID ||
		!validLifecycleOutcome(
			application.Operation, application.Classification, application.ResultingState,
		) {
		return false
	}
	processedAt, ok := parseDatabaseTime(application.ProcessedAt)
	return ok && !processedAt.Before(completedAt) && !processedAt.After(jobUpdatedAt)
}

func validLifecycleOutcome(operation, classification, state string) bool {
	switch operation {
	case "add":
		return classification == "applied" && state == "active" ||
			classification == "recovered_active" && state == "active" ||
			classification == "failed" && state == "failed" ||
			classification == "indeterminate" && state == "indeterminate"
	case "revoke":
		return classification == "revoked" && (state == "revoked" || state == "expired") ||
			classification == "failed" && state == "failed" ||
			classification == "indeterminate" && state == "indeterminate"
	case "inspect":
		return classification == "inspect_active" && (state == "active" || state == "failed") ||
			classification == "inspect_absent" && (state == "expired" || state == "failed") ||
			(classification == "inspect_mismatch" || classification == "failed" ||
				classification == "indeterminate") && state == "indeterminate"
	default:
		return false
	}
}

func validRecoveryDeadLetter(
	job executionArtifactJob,
	capabilityDigest string,
	expectedState string,
	upperBound time.Time,
	requireEqual bool,
) bool {
	if job.DeadLetterState == nil || *job.DeadLetterState != expectedState ||
		job.DeadLetterResolvedAt == nil || job.DeadLetterResolutionActor == nil ||
		job.DeadLetterResolutionDigest == nil ||
		*job.DeadLetterResolutionActor != "sentinelflow_recovery" ||
		*job.DeadLetterResolutionDigest != recoveryStartedDigest(job, capabilityDigest) {
		return false
	}
	resolvedAt, ok := parseDatabaseTime(*job.DeadLetterResolvedAt)
	deadAt, deadOK := parseDatabaseTime(*job.DeadLetterDeadAt)
	if !ok || !deadOK || deadAt.After(resolvedAt) || resolvedAt.After(upperBound) {
		return false
	}
	return !requireEqual || resolvedAt.Equal(upperBound)
}

func validTerminalDeadLetter(
	job executionArtifactJob,
	value capability.Value,
	capabilityDigest string,
	jobUpdatedAt time.Time,
	allowLifecycleVersion bool,
) bool {
	if job.DeadLetterState == nil {
		return emptyDeadLetter(job)
	}
	return validDeadLetterIdentity(job, value, allowLifecycleVersion) &&
		validRecoveryDeadLetter(job, capabilityDigest, "resolved", jobUpdatedAt, false)
}

func validDeadLetterIdentity(
	job executionArtifactJob,
	value capability.Value,
	allowPreviousVersion ...bool,
) bool {
	versionMatches := job.DeadLetterAggregateVersion != nil &&
		*job.DeadLetterAggregateVersion == job.AggregateVersion
	if len(allowPreviousVersion) == 1 && allowPreviousVersion[0] &&
		job.DeadLetterAggregateVersion != nil {
		versionMatches = versionMatches ||
			int64(*job.DeadLetterAggregateVersion)+1 == int64(job.AggregateVersion)
	}
	if job.DeadLetterJobID == nil || *job.DeadLetterJobID != job.JobID ||
		job.DeadLetterKind == nil || *job.DeadLetterKind != job.Kind ||
		job.DeadLetterAggregateType == nil || *job.DeadLetterAggregateType != job.AggregateType ||
		job.DeadLetterAggregateID == nil || *job.DeadLetterAggregateID != job.AggregateID ||
		!versionMatches ||
		job.DeadLetterAttempts == nil || *job.DeadLetterAttempts != job.Attempts ||
		job.DeadLetterFailureCode == nil || *job.DeadLetterFailureCode == "" ||
		job.DeadLetterFailureDigest == nil || !validSHA256(*job.DeadLetterFailureDigest) ||
		job.DeadLetterDeadAt == nil || job.AggregateID != value.ActionID {
		return false
	}
	_, ok := parseDatabaseTime(*job.DeadLetterDeadAt)
	return ok
}

func emptyDeadLetter(job executionArtifactJob) bool {
	return job.DeadLetterJobID == nil && job.DeadLetterKind == nil &&
		job.DeadLetterAggregateType == nil && job.DeadLetterAggregateID == nil &&
		job.DeadLetterAggregateVersion == nil && job.DeadLetterAttempts == nil &&
		job.DeadLetterFailureCode == nil && job.DeadLetterFailureDigest == nil &&
		job.DeadLetterDeadAt == nil && job.DeadLetterResolvedAt == nil &&
		job.DeadLetterResolutionActor == nil && job.DeadLetterResolutionDigest == nil
}

func decodeCanonicalHex(value string, maximum int) ([]byte, bool) {
	if value == "" || len(value) > maximum*2 || len(value)%2 != 0 {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}

func parseDatabaseTime(value string) (time.Time, bool) {
	if len(value) != len("2006-01-02T15:04:05.000000Z") || !strings.HasSuffix(value, "Z") {
		return time.Time{}, false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05.000000Z", value)
	return parsed, err == nil && parsed.UTC().Format("2006-01-02T15:04:05.000000Z") == value
}

func executionNonceDigest(encoded string) (string, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != 16 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		clear(raw)
		return "", false
	}
	sum := sha256.Sum256(raw)
	clear(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

func recoveryStartedDigest(job executionArtifactJob, capabilityDigest string) string {
	if job.DeadLetterFailureCode == nil || job.DeadLetterFailureDigest == nil {
		return ""
	}
	marker := "sentinelflow-recovery-started-v1\n" + job.JobID + "\n" +
		capabilityDigest + "\n" + *job.DeadLetterFailureCode + "\n" +
		*job.DeadLetterFailureDigest
	sum := sha256.Sum256([]byte(marker))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func nullableDigest(value string) *string {
	if value == "" {
		return nil
	}
	result := value
	return &result
}

func sameNullableString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func sameNullableEnum(left *string, right *capability.NFTExitClass) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == string(*right)
}

func sameNullableUint(left, right *uint64) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}
