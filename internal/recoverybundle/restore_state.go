package recoverybundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	RestoreStateSchemaVersion = "sentinelflow-restore-state-v1"
	RestorePhasePrepared      = "prepared"
	RestorePhaseDatabase      = "database_restored"
	RestorePhaseJournal       = "journal_installed"
	RestorePhaseFinalized     = "finalized"

	restoreBindingDomain = "SentinelFlow restore binding v1\n"
	restoreStateDomain   = "SentinelFlow restore state v1\n"
)

// RestoreStatus is the only resumable restore state exposed to shell
// orchestration. ReceiptDigest is committed inside the same PostgreSQL
// transaction as restored rows. Phase is durable through finalized; marker
// absence is never interpreted as successful completion.
type RestoreStatus struct {
	Phase          string
	ReceiptDigest  string
	JournalState   string
	ManifestDigest string
	DatabaseDigest string
	JournalDigest  string
}

type restoreState struct {
	SchemaVersion            string `json:"schema_version"`
	Phase                    string `json:"phase"`
	BundleManifestDigest     string `json:"bundle_manifest_digest"`
	BundleSigningKeyID       string `json:"bundle_signing_key_id"`
	DatabaseIdentityDigest   string `json:"database_identity_digest"`
	JournalDestinationDigest string `json:"journal_destination_digest"`
	JournalDigest            string `json:"journal_digest"`
	RestoreNonce             string `json:"restore_nonce"`
	ReceiptDigest            string `json:"receipt_digest"`
	StateChecksum            string `json:"state_checksum"`
}

type restoreStateChecksum struct {
	SchemaVersion            string `json:"schema_version"`
	Phase                    string `json:"phase"`
	BundleManifestDigest     string `json:"bundle_manifest_digest"`
	BundleSigningKeyID       string `json:"bundle_signing_key_id"`
	DatabaseIdentityDigest   string `json:"database_identity_digest"`
	JournalDestinationDigest string `json:"journal_destination_digest"`
	JournalDigest            string `json:"journal_digest"`
	RestoreNonce             string `json:"restore_nonce"`
	ReceiptDigest            string `json:"receipt_digest"`
}

// PrepareRestore verifies the signed bundle, reconciles only an exact durable
// state transition, creates the prepared marker before staging journal bytes,
// and returns the current monotonic phase. A fresh operation requires both the
// destination and stage to be absent. An existing destination is accepted only
// after a matching prior state marker has been authenticated.
func PrepareRestore(root string, publicKey ed25519.PublicKey, destination, databaseIdentity string) (RestoreStatus, error) {
	if !canonicalAbs(destination) || !validDatabaseIdentity(databaseIdentity) {
		return RestoreStatus{}, reject(CodeArgument)
	}
	verified, err := Verify(root, publicKey)
	if err != nil {
		return RestoreStatus{}, err
	}
	if err := safeDirectory(filepath.Dir(destination), false); err != nil {
		return RestoreStatus{}, err
	}
	marker := restoreStatePath(destination)
	state, exists, err := loadRestoreState(marker, verified, destination, databaseIdentity)
	if err != nil {
		return RestoreStatus{}, err
	}
	if !exists {
		if err := requireAbsent(destination); err != nil {
			return RestoreStatus{}, err
		}
		if err := requireAbsent(stagedJournalPath(destination)); err != nil {
			return RestoreStatus{}, err
		}
		nonceBytes := make([]byte, 32)
		if _, err := rand.Read(nonceBytes); err != nil {
			return RestoreStatus{}, reject(CodeFilesystem)
		}
		nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
		clear(nonceBytes)
		state = newRestoreState(verified, destination, databaseIdentity, RestorePhasePrepared, nonce)
		state, err = installInitialRestoreState(marker, state)
		if err != nil {
			return RestoreStatus{}, err
		}
	}
	journalState, err := ensureJournalForRestore(verified, destination, state)
	if err != nil {
		return RestoreStatus{}, err
	}
	return statusFromState(state, journalState), nil
}

// MarkDatabaseRestored durably advances only prepared -> database_restored.
// The caller must first verify the matching transaction-bound DB receipt.
func MarkDatabaseRestored(root string, publicKey ed25519.PublicKey, destination, databaseIdentity string) (RestoreStatus, error) {
	status, err := PrepareRestore(root, publicKey, destination, databaseIdentity)
	if err != nil {
		return RestoreStatus{}, err
	}
	if status.Phase != RestorePhasePrepared {
		return status, nil
	}
	verified, err := Verify(root, publicKey)
	if err != nil {
		return RestoreStatus{}, err
	}
	marker := restoreStatePath(destination)
	current, exists, err := loadRestoreState(marker, verified, destination, databaseIdentity)
	if err != nil || !exists {
		if err != nil {
			return RestoreStatus{}, err
		}
		return RestoreStatus{}, reject(CodeContents)
	}
	next, err := advanceRestoreState(marker, current, RestorePhaseDatabase)
	if err != nil {
		return RestoreStatus{}, err
	}
	return statusFromState(next, status.JournalState), nil
}

// CommitPreparedJournal performs the one journal rename only after the durable
// database phase, then durably advances to journal_installed. A crash after
// either rename is recovered from the exact prior marker and bytes.
func CommitPreparedJournal(root string, publicKey ed25519.PublicKey, destination, databaseIdentity string) (RestoreStatus, error) {
	status, err := PrepareRestore(root, publicKey, destination, databaseIdentity)
	if err != nil {
		return RestoreStatus{}, err
	}
	if status.Phase == RestorePhaseJournal || status.Phase == RestorePhaseFinalized {
		if status.JournalState != "installed" {
			return RestoreStatus{}, reject(CodeIntegrity)
		}
		return status, nil
	}
	if status.Phase != RestorePhaseDatabase {
		return RestoreStatus{}, reject(CodeContents)
	}
	if status.JournalState == "staged" {
		if err := CommitJournal(root, publicKey, destination); err != nil {
			return RestoreStatus{}, err
		}
	} else if status.JournalState != "installed" {
		return RestoreStatus{}, reject(CodeContents)
	}
	verified, err := Verify(root, publicKey)
	if err != nil {
		return RestoreStatus{}, err
	}
	marker := restoreStatePath(destination)
	current, exists, err := loadRestoreState(marker, verified, destination, databaseIdentity)
	if err != nil || !exists {
		if err != nil {
			return RestoreStatus{}, err
		}
		return RestoreStatus{}, reject(CodeContents)
	}
	if current.Phase == RestorePhaseJournal || current.Phase == RestorePhaseFinalized {
		return statusFromState(current, "installed"), nil
	}
	if current.Phase != RestorePhaseDatabase {
		return RestoreStatus{}, reject(CodeContents)
	}
	next, err := advanceRestoreState(marker, current, RestorePhaseJournal)
	if err != nil {
		return RestoreStatus{}, err
	}
	return statusFromState(next, "installed"), nil
}

// FinalizeRestore durably advances journal_installed -> finalized. The marker
// remains as the sole accepted completion proof and is never unlinked.
func FinalizeRestore(root string, publicKey ed25519.PublicKey, destination, databaseIdentity string) (RestoreStatus, error) {
	status, err := PrepareRestore(root, publicKey, destination, databaseIdentity)
	if err != nil {
		return RestoreStatus{}, err
	}
	if status.Phase == RestorePhaseFinalized {
		if status.JournalState != "installed" {
			return RestoreStatus{}, reject(CodeIntegrity)
		}
		return status, nil
	}
	if status.Phase != RestorePhaseJournal || status.JournalState != "installed" {
		return RestoreStatus{}, reject(CodeContents)
	}
	verified, err := Verify(root, publicKey)
	if err != nil {
		return RestoreStatus{}, err
	}
	marker := restoreStatePath(destination)
	current, exists, err := loadRestoreState(marker, verified, destination, databaseIdentity)
	if err != nil || !exists {
		if err != nil {
			return RestoreStatus{}, err
		}
		return RestoreStatus{}, reject(CodeContents)
	}
	if current.Phase == RestorePhaseFinalized {
		return statusFromState(current, "installed"), nil
	}
	next, err := advanceRestoreState(marker, current, RestorePhaseFinalized)
	if err != nil {
		return RestoreStatus{}, err
	}
	return statusFromState(next, "installed"), nil
}

// RestoreStatePath returns the permanent durable marker path.
func RestoreStatePath(destination string) (string, error) {
	if !canonicalAbs(destination) {
		return "", reject(CodeArgument)
	}
	return restoreStatePath(destination), nil
}

func restoreStatePath(destination string) string {
	return filepath.Join(filepath.Dir(destination), "."+filepath.Base(destination)+".sentinelflow-restore-v1.state")
}

func restoreNextPath(marker string) string { return marker + ".next" }

func loadRestoreState(marker string, verified Verified, destination, databaseIdentity string) (restoreState, bool, error) {
	current, currentExists, err := readOptionalRestoreState(marker)
	if err != nil {
		return restoreState{}, false, err
	}
	nextPath := restoreNextPath(marker)
	next, nextExists, err := readOptionalRestoreState(nextPath)
	if err != nil {
		return restoreState{}, false, err
	}
	if currentExists && !restoreStateMatches(current, verified, destination, databaseIdentity) {
		return restoreState{}, false, reject(CodeIntegrity)
	}
	if nextExists && !restoreStateMatches(next, verified, destination, databaseIdentity) {
		return restoreState{}, false, reject(CodeIntegrity)
	}
	switch {
	case !currentExists && !nextExists:
		return restoreState{}, false, nil
	case !currentExists && nextExists:
		if next.Phase != RestorePhasePrepared {
			return restoreState{}, false, reject(CodeIntegrity)
		}
		if err := adoptRestoreNext(marker, next); err != nil {
			return restoreState{}, false, err
		}
		return next, true, nil
	case currentExists && !nextExists:
		return current, true, nil
	default:
		if !sameRestoreBinding(current, next) ||
			(next.Phase != current.Phase && next.Phase != restorePhaseSuccessor(current.Phase)) {
			return restoreState{}, false, reject(CodeIntegrity)
		}
		if err := adoptRestoreNext(marker, next); err != nil {
			return restoreState{}, false, err
		}
		return next, true, nil
	}
}

func readOptionalRestoreState(path string) (restoreState, bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return restoreState{}, false, nil
	} else if err != nil {
		return restoreState{}, false, reject(CodeFilesystem)
	}
	state, err := readRestoreState(path)
	if err != nil {
		return restoreState{}, false, err
	}
	return state, true, nil
}

func restoreStateMatches(state restoreState, verified Verified, destination, databaseIdentity string) bool {
	if !validRestorePhase(state.Phase) {
		return false
	}
	expected := newRestoreState(verified, destination, databaseIdentity, state.Phase, state.RestoreNonce)
	return sameRestoreBinding(state, expected)
}

func installInitialRestoreState(marker string, state restoreState) (restoreState, error) {
	if state.Phase != RestorePhasePrepared {
		return restoreState{}, reject(CodeContents)
	}
	if err := requireAbsent(marker); err != nil {
		return restoreState{}, err
	}
	nextPath := restoreNextPath(marker)
	if err := requireAbsent(nextPath); err != nil {
		return restoreState{}, err
	}
	encoded, err := marshalRestoreState(state)
	if err != nil {
		return restoreState{}, err
	}
	if err := writeExclusive(nextPath, encoded, 0o600); err != nil {
		return restoreState{}, err
	}
	if err := syncDirectory(filepath.Dir(marker)); err != nil {
		return restoreState{}, err
	}
	decoded, err := readRestoreState(nextPath)
	if err != nil || !sameRestoreBinding(decoded, state) || decoded.Phase != RestorePhasePrepared {
		if err != nil {
			return restoreState{}, err
		}
		return restoreState{}, reject(CodeIntegrity)
	}
	if err := os.Rename(nextPath, marker); err != nil {
		return restoreState{}, reject(CodeFilesystem)
	}
	if err := syncDirectory(filepath.Dir(marker)); err != nil {
		return restoreState{}, err
	}
	return readRestoreState(marker)
}

func advanceRestoreState(marker string, current restoreState, nextPhase string) (restoreState, error) {
	if restorePhaseSuccessor(current.Phase) != nextPhase {
		return restoreState{}, reject(CodeContents)
	}
	next := current
	next.Phase = nextPhase
	next.StateChecksum = ""
	encoded, err := marshalRestoreState(next)
	if err != nil {
		return restoreState{}, err
	}
	nextPath := restoreNextPath(marker)
	if err := requireAbsent(nextPath); err != nil {
		return restoreState{}, err
	}
	if err := writeExclusive(nextPath, encoded, 0o600); err != nil {
		return restoreState{}, err
	}
	if err := syncDirectory(filepath.Dir(marker)); err != nil {
		return restoreState{}, err
	}
	persistedCurrent, err := readRestoreState(marker)
	if err != nil || persistedCurrent != current {
		if err != nil {
			return restoreState{}, err
		}
		return restoreState{}, reject(CodeIntegrity)
	}
	persistedNext, err := readRestoreState(nextPath)
	if err != nil || !sameRestoreBinding(current, persistedNext) || persistedNext.Phase != nextPhase {
		if err != nil {
			return restoreState{}, err
		}
		return restoreState{}, reject(CodeIntegrity)
	}
	if err := os.Rename(nextPath, marker); err != nil {
		return restoreState{}, reject(CodeFilesystem)
	}
	if err := syncDirectory(filepath.Dir(marker)); err != nil {
		return restoreState{}, err
	}
	return readRestoreState(marker)
}

func adoptRestoreNext(marker string, expected restoreState) error {
	nextPath := restoreNextPath(marker)
	rechecked, err := readRestoreState(nextPath)
	if err != nil || rechecked != expected {
		if err != nil {
			return err
		}
		return reject(CodeIntegrity)
	}
	if err := os.Rename(nextPath, marker); err != nil {
		return reject(CodeFilesystem)
	}
	return syncDirectory(filepath.Dir(marker))
}

func restorePhaseSuccessor(phase string) string {
	switch phase {
	case RestorePhasePrepared:
		return RestorePhaseDatabase
	case RestorePhaseDatabase:
		return RestorePhaseJournal
	case RestorePhaseJournal:
		return RestorePhaseFinalized
	default:
		return ""
	}
}

func validRestorePhase(phase string) bool {
	return phase == RestorePhasePrepared || phase == RestorePhaseDatabase ||
		phase == RestorePhaseJournal || phase == RestorePhaseFinalized
}

func ensureJournalForRestore(verified Verified, destination string, state restoreState) (string, error) {
	expected := verified.Manifest.Files[indexOfPath(JournalPath)]
	if _, err := os.Lstat(destination); err == nil {
		if state.Phase == RestorePhasePrepared {
			return "", reject(CodeIntegrity)
		}
		actual, inspectErr := inspectAbsolute(destination, 0o600, maxJournalBytes, true)
		if inspectErr != nil || actual.Size != expected.Size || actual.SHA256 != expected.SHA256 || actual.Mode != expected.Mode {
			return "", reject(CodeIntegrity)
		}
		if _, stageErr := os.Lstat(stagedJournalPath(destination)); stageErr == nil {
			return "", reject(CodeExists)
		} else if !errors.Is(stageErr, os.ErrNotExist) {
			return "", reject(CodeFilesystem)
		}
		return "installed", nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", reject(CodeFilesystem)
	}
	if state.Phase == RestorePhaseJournal || state.Phase == RestorePhaseFinalized {
		return "", reject(CodeIntegrity)
	}
	staged := stagedJournalPath(destination)
	if _, err := os.Lstat(staged); err == nil {
		actual, inspectErr := inspectAbsolute(staged, 0o600, maxJournalBytes, true)
		if inspectErr != nil || actual.Size != expected.Size || actual.SHA256 != expected.SHA256 || actual.Mode != expected.Mode {
			return "", reject(CodeIntegrity)
		}
		return "staged", nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", reject(CodeFilesystem)
	}
	source := filepath.Join(verified.Root, filepath.FromSlash(JournalPath))
	if err := copyExactRegular(source, staged, 0o600, maxJournalBytes, true); err != nil {
		return "", err
	}
	if err := syncDirectory(filepath.Dir(staged)); err != nil {
		return "", err
	}
	return "staged", nil
}

func requireAbsent(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return reject(CodeExists)
	} else if !errors.Is(err, os.ErrNotExist) {
		return reject(CodeFilesystem)
	}
	return nil
}

func newRestoreState(verified Verified, destination, databaseIdentity, phase, nonce string) restoreState {
	databaseDigest := digestBytes([]byte(databaseIdentity))
	destinationDigest := digestBytes([]byte(destination))
	journalDigest := verified.Manifest.Files[indexOfPath(JournalPath)].SHA256
	receipt := digestBytes([]byte(
		restoreBindingDomain + verified.ManifestDigest + "\n" + verified.Manifest.SigningKeyID + "\n" +
			databaseDigest + "\n" + destinationDigest + "\n" + journalDigest + "\n" + nonce + "\n",
	))
	return restoreState{
		SchemaVersion: RestoreStateSchemaVersion, Phase: phase,
		BundleManifestDigest: verified.ManifestDigest, BundleSigningKeyID: verified.Manifest.SigningKeyID,
		DatabaseIdentityDigest: databaseDigest, JournalDestinationDigest: destinationDigest,
		JournalDigest: journalDigest, RestoreNonce: nonce, ReceiptDigest: receipt,
	}
}

func marshalRestoreState(state restoreState) ([]byte, error) {
	if err := validateRestoreState(state, false); err != nil {
		return nil, err
	}
	checksumPayload := restoreStateChecksum{
		SchemaVersion: state.SchemaVersion, Phase: state.Phase,
		BundleManifestDigest: state.BundleManifestDigest, BundleSigningKeyID: state.BundleSigningKeyID,
		DatabaseIdentityDigest: state.DatabaseIdentityDigest, JournalDestinationDigest: state.JournalDestinationDigest,
		JournalDigest: state.JournalDigest, RestoreNonce: state.RestoreNonce, ReceiptDigest: state.ReceiptDigest,
	}
	canonical, err := json.Marshal(checksumPayload)
	if err != nil {
		return nil, reject(CodeContents)
	}
	state.StateChecksum = digestBytes(append([]byte(restoreStateDomain), canonical...))
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded) > maxManifestBytes {
		return nil, reject(CodeContents)
	}
	return append(encoded, '\n'), nil
}

func readRestoreState(path string) (restoreState, error) {
	encoded, err := readExactRegular(path, 0o600, maxManifestBytes)
	if err != nil {
		return restoreState{}, err
	}
	var state restoreState
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return restoreState{}, reject(CodeContents)
	}
	if err := requireEOF(decoder); err != nil {
		return restoreState{}, err
	}
	if err := validateRestoreState(state, true); err != nil {
		return restoreState{}, err
	}
	provided := state.StateChecksum
	state.StateChecksum = ""
	reencoded, err := marshalRestoreState(state)
	if err != nil {
		return restoreState{}, err
	}
	var computed restoreState
	if err := json.Unmarshal(reencoded, &computed); err != nil || computed.StateChecksum != provided {
		return restoreState{}, reject(CodeIntegrity)
	}
	state.StateChecksum = provided
	return state, nil
}

func validateRestoreState(state restoreState, requireChecksum bool) error {
	if state.SchemaVersion != RestoreStateSchemaVersion || !validRestorePhase(state.Phase) ||
		!validDigest(state.BundleManifestDigest) || !validDigest(state.BundleSigningKeyID) ||
		!validDigest(state.DatabaseIdentityDigest) || !validDigest(state.JournalDestinationDigest) ||
		!validDigest(state.JournalDigest) || !validRestoreNonce(state.RestoreNonce) || !validDigest(state.ReceiptDigest) ||
		requireChecksum && !validDigest(state.StateChecksum) || !requireChecksum && state.StateChecksum != "" {
		return reject(CodeContents)
	}
	return nil
}

func sameRestoreBinding(left, right restoreState) bool {
	return left.SchemaVersion == right.SchemaVersion && validRestorePhase(left.Phase) && validRestorePhase(right.Phase) &&
		left.BundleManifestDigest == right.BundleManifestDigest && left.BundleSigningKeyID == right.BundleSigningKeyID &&
		left.DatabaseIdentityDigest == right.DatabaseIdentityDigest &&
		left.JournalDestinationDigest == right.JournalDestinationDigest &&
		left.JournalDigest == right.JournalDigest && left.RestoreNonce == right.RestoreNonce &&
		left.ReceiptDigest == right.ReceiptDigest
}

func statusFromState(state restoreState, journalState string) RestoreStatus {
	return RestoreStatus{
		Phase: state.Phase, ReceiptDigest: state.ReceiptDigest, JournalState: journalState,
		ManifestDigest: state.BundleManifestDigest, DatabaseDigest: state.DatabaseIdentityDigest,
		JournalDigest: state.JournalDigest,
	}
}

func validDatabaseIdentity(identity string) bool {
	remainder, ok := strings.CutPrefix(identity, "pg17:")
	if !ok {
		return false
	}
	systemIdentifier, remainder, ok := strings.Cut(remainder, ":")
	if !ok {
		return false
	}
	databaseOID, databaseName, ok := strings.Cut(remainder, ":")
	if !ok || len(databaseName) == 0 || len(databaseName) > 63 || strings.Contains(databaseName, ":") ||
		!decimalString(systemIdentifier) || !decimalString(databaseOID) {
		return false
	}
	for _, character := range databaseName {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func decimalString(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validRestoreNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(value) == 43 && len(decoded) == 32
}

func digestBytes(contents []byte) string {
	sum := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(sum[:])
}
