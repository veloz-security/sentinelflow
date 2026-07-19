// Package recoverybundle creates and verifies SentinelFlow state backup
// bundles. The executor replay journal is deliberately opaque here: only the
// executor, with its separately restored runtime keys, may interpret recovery
// state. This package preserves and authenticates the exact journal bytes.
package recoverybundle

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	SchemaVersion = "sentinelflow-recovery-bundle-v1"

	manifestName  = "manifest.json"
	signatureName = "manifest.ed25519"

	PostgresDumpPath  = "postgres/data.dump"
	JournalPath       = "executor/replay.json"
	MigrationsPath    = "metadata/migrations.tsv"
	PostgresMajorPath = "metadata/postgres-major.txt"
	RelationsPath     = "metadata/relations.tsv"
	SchemaPath        = "metadata/schema.sql"
	SequencesPath     = "metadata/sequences.tsv"

	maxManifestBytes  = 64 * 1024
	maxSignatureBytes = 256
	maxJournalBytes   = 64 * 1024 * 1024
	maxMigrations     = 1 * 1024 * 1024
	maxRelations      = 1 * 1024 * 1024
	maxSequences      = 16 * 1024
	maxSchemaBytes    = 32 * 1024 * 1024
	maxDumpBytes      = 16 * 1024 * 1024 * 1024

	signatureDomain = "SentinelFlow recovery bundle v1\n"
)

var expectedPaths = []string{
	JournalPath,
	MigrationsPath,
	PostgresMajorPath,
	RelationsPath,
	SchemaPath,
	SequencesPath,
	PostgresDumpPath,
}

// ErrorCode is a stable, path-free failure classification.
type ErrorCode string

const (
	CodeArgument   ErrorCode = "invalid_argument"
	CodeFilesystem ErrorCode = "unsafe_filesystem"
	CodeContents   ErrorCode = "invalid_bundle_contents"
	CodeSignature  ErrorCode = "invalid_bundle_signature"
	CodeIntegrity  ErrorCode = "bundle_integrity_mismatch"
	CodeExists     ErrorCode = "destination_not_fresh"
	CodeSync       ErrorCode = "durability_barrier_failed"
)

// Error deliberately omits paths, database identifiers, key material, and
// nested operating-system details.
type Error struct{ code ErrorCode }

func (e *Error) Error() string { return "SentinelFlow recovery bundle rejected" }
func (e *Error) Code() ErrorCode {
	if e == nil {
		return CodeContents
	}
	return e.code
}
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e != nil && other != nil && e.code == other.code
}

func reject(code ErrorCode) error { return &Error{code: code} }

// File records one exact payload file. Modes are four-digit octal strings so
// JSON number handling cannot reinterpret them.
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
	Role   string `json:"role"`
}

// Manifest is signed as the exact bytes stored in manifest.json.
type Manifest struct {
	SchemaVersion        string `json:"schema_version"`
	CreatedAt            string `json:"created_at"`
	SigningKeyID         string `json:"signing_key_id"`
	PostgresMajor        int    `json:"postgres_major"`
	MigrationCount       int    `json:"migration_count"`
	LatestMigration      int64  `json:"latest_migration"`
	SchemaFingerprint    string `json:"schema_fingerprint"`
	MigrationFingerprint string `json:"migration_fingerprint"`
	RelationFingerprint  string `json:"relation_fingerprint"`
	SequenceFingerprint  string `json:"sequence_fingerprint"`
	Files                []File `json:"files"`
}

// SealOptions describes an atomic same-parent directory rename. StagingDir
// must already contain only the PostgreSQL dump and public metadata files.
type SealOptions struct {
	StagingDir string
	OutputDir  string
	Journal    string
	// JournalFD is the continuously locked existing-journal descriptor inherited
	// from recoverytool run-session. Zero keeps the standalone Seal test/API path.
	JournalFD  int
	PrivateKey ed25519.PrivateKey
	Now        time.Time
}

// Verified is immutable metadata from one successful verification. Callers
// must verify again immediately before committing restored journal bytes.
type Verified struct {
	Root           string
	Manifest       Manifest
	ManifestDigest string
}

// Seal copies the exact 0600 journal, signs the complete payload manifest,
// fsyncs every file and directory, then atomically renames staging to output.
func Seal(options SealOptions) error {
	if len(options.PrivateKey) != ed25519.PrivateKeySize || !canonicalAbs(options.StagingDir) ||
		!canonicalAbs(options.OutputDir) || !canonicalAbs(options.Journal) ||
		filepath.Dir(options.StagingDir) != filepath.Dir(options.OutputDir) ||
		filepath.Base(options.StagingDir) == filepath.Base(options.OutputDir) {
		return reject(CodeArgument)
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	options.Now = options.Now.UTC().Truncate(time.Second)
	if err := safeDirectory(options.StagingDir, true); err != nil {
		return err
	}
	if err := safeDirectory(filepath.Dir(options.OutputDir), false); err != nil {
		return err
	}
	if _, err := os.Lstat(options.OutputDir); err == nil {
		return reject(CodeExists)
	} else if !errors.Is(err, os.ErrNotExist) {
		return reject(CodeFilesystem)
	}
	if err := verifyInitialTree(options.StagingDir); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(options.StagingDir, "executor"), 0o700); err != nil {
		return reject(CodeFilesystem)
	}
	journalDestination := filepath.Join(options.StagingDir, filepath.FromSlash(JournalPath))
	var journalErr error
	if options.JournalFD >= 3 {
		journalErr = copyInheritedLockedRegular(
			options.Journal, options.JournalFD, journalDestination, 0o600, maxJournalBytes, true,
		)
	} else {
		journalErr = copyLockedRegular(options.Journal, journalDestination, 0o600, maxJournalBytes, true)
	}
	if journalErr != nil {
		return journalErr
	}

	major, migrationCount, latestMigration, err := validateMetadata(options.StagingDir)
	if err != nil {
		return err
	}
	publicKey := options.PrivateKey.Public().(ed25519.PublicKey)
	manifest := Manifest{
		SchemaVersion:   SchemaVersion,
		CreatedAt:       options.Now.Format(time.RFC3339),
		SigningKeyID:    keyID(publicKey),
		PostgresMajor:   major,
		MigrationCount:  migrationCount,
		LatestMigration: latestMigration,
	}
	for _, path := range expectedPaths {
		entry, err := inspectPayload(options.StagingDir, path)
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, entry)
		switch path {
		case SchemaPath:
			manifest.SchemaFingerprint = entry.SHA256
		case MigrationsPath:
			manifest.MigrationFingerprint = entry.SHA256
		case RelationsPath:
			manifest.RelationFingerprint = entry.SHA256
		case SequencesPath:
			manifest.SequenceFingerprint = entry.SHA256
		}
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil || len(manifestBytes) == 0 || len(manifestBytes) > maxManifestBytes {
		return reject(CodeContents)
	}
	manifestBytes = append(manifestBytes, '\n')
	signature := signManifest(options.PrivateKey, manifestBytes)
	signatureBytes := append([]byte(base64.RawURLEncoding.EncodeToString(signature)), '\n')
	if err := writeExclusive(filepath.Join(options.StagingDir, manifestName), manifestBytes, 0o600); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(options.StagingDir, signatureName), signatureBytes, 0o600); err != nil {
		return err
	}
	if err := verifyCompleteTree(options.StagingDir); err != nil {
		return err
	}
	if err := syncTree(options.StagingDir); err != nil {
		return err
	}
	if err := os.Rename(options.StagingDir, options.OutputDir); err != nil {
		return reject(CodeFilesystem)
	}
	return syncDirectory(filepath.Dir(options.OutputDir))
}

// Publish atomically moves one fully sealed hidden candidate to its public
// name. Callers must finish every database, artifact, and sequence check before
// invoking it. The OS primitive is explicitly no-clobber, so a destination
// created after the caller's preflight is never replaced.
func Publish(candidate, output string) error {
	if !canonicalAbs(candidate) || !canonicalAbs(output) || candidate == output ||
		filepath.Dir(candidate) != filepath.Dir(output) ||
		!strings.HasPrefix(filepath.Base(candidate), ".sentinelflow-recovery-v1.candidate.") {
		return reject(CodeArgument)
	}
	if err := safeDirectory(candidate, true); err != nil {
		return err
	}
	if err := safeDirectory(filepath.Dir(output), false); err != nil {
		return err
	}
	if err := verifyCompleteTree(candidate); err != nil {
		return err
	}
	if _, err := os.Lstat(output); err == nil {
		return reject(CodeExists)
	} else if !errors.Is(err, os.ErrNotExist) {
		return reject(CodeFilesystem)
	}
	if err := renameNoReplace(candidate, output); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return reject(CodeExists)
		}
		return reject(CodeFilesystem)
	}
	if err := syncDirectory(filepath.Dir(output)); err != nil {
		// A durability failure is not reported as success. Move the exact name
		// back to its private candidate path. Never recursively remove a path
		// after a failed rename: another process could have swapped that name.
		_ = renameNoReplace(output, candidate)
		_ = syncDirectory(filepath.Dir(output))
		return err
	}
	return nil
}

// Verify authenticates the exact manifest and then checks the complete tree,
// file types, modes, sizes, and hashes. It rejects every unlisted entry.
func Verify(root string, publicKey ed25519.PublicKey) (Verified, error) {
	if !canonicalAbs(root) || len(publicKey) != ed25519.PublicKeySize {
		return Verified{}, reject(CodeArgument)
	}
	if err := safeDirectory(root, true); err != nil {
		return Verified{}, err
	}
	if err := verifyCompleteTree(root); err != nil {
		return Verified{}, err
	}
	manifestBytes, err := readExactRegular(filepath.Join(root, manifestName), 0o600, maxManifestBytes)
	if err != nil {
		return Verified{}, err
	}
	signatureText, err := readExactRegular(filepath.Join(root, signatureName), 0o600, maxSignatureBytes)
	if err != nil {
		return Verified{}, err
	}
	if len(signatureText) == 0 || signatureText[len(signatureText)-1] != '\n' ||
		bytes.Count(signatureText, []byte{'\n'}) != 1 {
		return Verified{}, reject(CodeSignature)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(string(signatureText[:len(signatureText)-1]))
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, manifestMessage(manifestBytes), signature) {
		return Verified{}, reject(CodeSignature)
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Verified{}, reject(CodeContents)
	}
	if err := requireEOF(decoder); err != nil {
		return Verified{}, err
	}
	if manifest.SigningKeyID != keyID(publicKey) {
		return Verified{}, reject(CodeSignature)
	}
	if err := validateManifest(manifest); err != nil {
		return Verified{}, err
	}
	major, count, latest, err := validateMetadata(root)
	if err != nil {
		return Verified{}, err
	}
	if major != manifest.PostgresMajor || count != manifest.MigrationCount || latest != manifest.LatestMigration {
		return Verified{}, reject(CodeIntegrity)
	}
	for index, expectedPath := range expectedPaths {
		actual, err := inspectPayload(root, expectedPath)
		if err != nil {
			return Verified{}, err
		}
		expected := manifest.Files[index]
		if actual != expected {
			return Verified{}, reject(CodeIntegrity)
		}
	}
	if manifest.SchemaFingerprint != manifest.Files[indexOfPath(SchemaPath)].SHA256 ||
		manifest.MigrationFingerprint != manifest.Files[indexOfPath(MigrationsPath)].SHA256 ||
		manifest.RelationFingerprint != manifest.Files[indexOfPath(RelationsPath)].SHA256 ||
		manifest.SequenceFingerprint != manifest.Files[indexOfPath(SequencesPath)].SHA256 {
		return Verified{}, reject(CodeIntegrity)
	}
	manifestSum := sha256.Sum256(manifestBytes)
	return Verified{
		Root: root, Manifest: manifest,
		ManifestDigest: "sha256:" + hex.EncodeToString(manifestSum[:]),
	}, nil
}

// StageJournal verifies the bundle and writes an exact hidden 0600 sibling of
// destination. It never interprets or executes journal records.
func StageJournal(root string, publicKey ed25519.PublicKey, destination string) (string, error) {
	if !canonicalAbs(destination) || filepath.Base(destination) == "." || filepath.Base(destination) == string(filepath.Separator) {
		return "", reject(CodeArgument)
	}
	verified, err := Verify(root, publicKey)
	if err != nil {
		return "", err
	}
	if err := safeDirectory(filepath.Dir(destination), false); err != nil {
		return "", err
	}
	if _, err := os.Lstat(destination); err == nil {
		return "", reject(CodeExists)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", reject(CodeFilesystem)
	}
	staged := stagedJournalPath(destination)
	if _, err := os.Lstat(staged); err == nil {
		return "", reject(CodeExists)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", reject(CodeFilesystem)
	}
	source := filepath.Join(verified.Root, filepath.FromSlash(JournalPath))
	if err := copyExactRegular(source, staged, 0o600, maxJournalBytes, true); err != nil {
		return "", err
	}
	if err := syncDirectory(filepath.Dir(staged)); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	return staged, nil
}

// CommitJournal re-verifies the bundle and staged bytes immediately before an
// atomic rename. Existing destinations, links, and swapped stage files fail.
func CommitJournal(root string, publicKey ed25519.PublicKey, destination string) error {
	if !canonicalAbs(destination) {
		return reject(CodeArgument)
	}
	verified, err := Verify(root, publicKey)
	if err != nil {
		return err
	}
	if err := safeDirectory(filepath.Dir(destination), false); err != nil {
		return err
	}
	if _, err := os.Lstat(destination); err == nil {
		return reject(CodeExists)
	} else if !errors.Is(err, os.ErrNotExist) {
		return reject(CodeFilesystem)
	}
	staged := stagedJournalPath(destination)
	stageInfo, err := inspectAbsolute(staged, 0o600, maxJournalBytes, true)
	if err != nil {
		return err
	}
	sourceInfo := verified.Manifest.Files[indexOfPath(JournalPath)]
	if stageInfo.Size != sourceInfo.Size || stageInfo.SHA256 != sourceInfo.SHA256 || stageInfo.Mode != sourceInfo.Mode {
		return reject(CodeIntegrity)
	}
	if err := os.Rename(staged, destination); err != nil {
		return reject(CodeFilesystem)
	}
	return syncDirectory(filepath.Dir(destination))
}

// StagedJournalPath returns the only temporary journal path restore scripts
// may remove after a failed single-transaction database restore.
func StagedJournalPath(destination string) (string, error) {
	if !canonicalAbs(destination) {
		return "", reject(CodeArgument)
	}
	return stagedJournalPath(destination), nil
}

func stagedJournalPath(destination string) string {
	return filepath.Join(filepath.Dir(destination), "."+filepath.Base(destination)+".sentinelflow-recovery-v1.partial")
}

func verifyInitialTree(root string) error {
	allowedDirectories := map[string]bool{".": true, "metadata": true, "postgres": true}
	allowedFiles := map[string]bool{
		MigrationsPath: true, PostgresMajorPath: true, RelationsPath: true,
		SchemaPath: true, SequencesPath: true, PostgresDumpPath: true,
	}
	return verifyTree(root, allowedDirectories, allowedFiles)
}

func verifyCompleteTree(root string) error {
	allowedDirectories := map[string]bool{".": true, "metadata": true, "postgres": true, "executor": true}
	allowedFiles := map[string]bool{manifestName: true, signatureName: true}
	for _, path := range expectedPaths {
		allowedFiles[path] = true
	}
	return verifyTree(root, allowedDirectories, allowedFiles)
}

func verifyTree(root string, allowedDirectories, allowedFiles map[string]bool) error {
	seenDirectories := make(map[string]bool)
	seenFiles := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return reject(CodeFilesystem)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return reject(CodeFilesystem)
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return reject(CodeFilesystem)
		}
		info, err := entry.Info()
		if err != nil {
			return reject(CodeFilesystem)
		}
		if info.IsDir() {
			if !allowedDirectories[relative] || info.Mode().Perm() != 0o700 {
				return reject(CodeContents)
			}
			if err := safeDirectory(path, true); err != nil {
				return err
			}
			seenDirectories[relative] = true
			return nil
		}
		if !info.Mode().IsRegular() || !allowedFiles[relative] || info.Mode().Perm() != 0o600 {
			return reject(CodeContents)
		}
		seenFiles[relative] = true
		return nil
	})
	if err != nil {
		return err
	}
	if len(seenDirectories) != len(allowedDirectories) || len(seenFiles) != len(allowedFiles) {
		return reject(CodeContents)
	}
	return nil
}

func validateMetadata(root string) (int, int, int64, error) {
	majorBytes, err := readExactRegular(filepath.Join(root, filepath.FromSlash(PostgresMajorPath)), 0o600, 16)
	if err != nil {
		return 0, 0, 0, err
	}
	if len(majorBytes) < 2 || majorBytes[len(majorBytes)-1] != '\n' || bytes.Count(majorBytes, []byte{'\n'}) != 1 {
		return 0, 0, 0, reject(CodeContents)
	}
	major, err := strconv.Atoi(string(majorBytes[:len(majorBytes)-1]))
	if err != nil || major != 17 {
		return 0, 0, 0, reject(CodeContents)
	}
	migrations, err := readExactRegular(filepath.Join(root, filepath.FromSlash(MigrationsPath)), 0o600, maxMigrations)
	if err != nil {
		return 0, 0, 0, err
	}
	if len(migrations) == 0 || migrations[len(migrations)-1] != '\n' {
		return 0, 0, 0, reject(CodeContents)
	}
	scanner := bufio.NewScanner(bytes.NewReader(migrations))
	var count int
	var previous int64
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) != 2 || parts[1] == "" || len(parts[1]) > 128 || !validMigrationName(parts[1]) {
			return 0, 0, 0, reject(CodeContents)
		}
		version, parseErr := strconv.ParseInt(parts[0], 10, 64)
		if parseErr != nil || version <= previous || version > 1<<53-1 {
			return 0, 0, 0, reject(CodeContents)
		}
		previous = version
		count++
	}
	if scanner.Err() != nil || count == 0 {
		return 0, 0, 0, reject(CodeContents)
	}
	relations, err := readExactRegular(filepath.Join(root, filepath.FromSlash(RelationsPath)), 0o600, maxRelations)
	if err != nil || !bytes.Equal(relations, []byte(PostgreSQLRelationContractRows())) {
		return 0, 0, 0, reject(CodeContents)
	}
	sequences, err := readExactRegular(filepath.Join(root, filepath.FromSlash(SequencesPath)), 0o600, maxSequences)
	if err != nil || validateSequenceState(sequences) != nil {
		return 0, 0, 0, reject(CodeContents)
	}
	schema, err := readExactRegular(filepath.Join(root, filepath.FromSlash(SchemaPath)), 0o600, maxSchemaBytes)
	if err != nil {
		return 0, 0, 0, err
	}
	if !bytes.Contains(schema, []byte("sentinelflow")) || !bytes.Contains(schema, []byte("schema_migrations")) {
		return 0, 0, 0, reject(CodeContents)
	}
	dumpInfo, err := inspectAbsolute(filepath.Join(root, filepath.FromSlash(PostgresDumpPath)), 0o600, maxDumpBytes, false)
	if err != nil || dumpInfo.Size == 0 {
		return 0, 0, 0, reject(CodeContents)
	}
	return major, count, previous, nil
}

func validMigrationName(value string) bool {
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func validateSequenceState(contents []byte) error {
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		return reject(CodeContents)
	}
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	names := PostgreSQLSequenceNames()
	if len(lines) != len(names) {
		return reject(CodeContents)
	}
	for index, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 || fields[0] != names[index] ||
			(fields[2] != "true" && fields[2] != "false") {
			return reject(CodeContents)
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || value < 1 {
			return reject(CodeContents)
		}
	}
	return nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion || manifest.PostgresMajor != 17 ||
		manifest.MigrationCount <= 0 || manifest.LatestMigration <= 0 ||
		!validDigest(manifest.SigningKeyID) || !validDigest(manifest.SchemaFingerprint) ||
		!validDigest(manifest.MigrationFingerprint) || !validDigest(manifest.RelationFingerprint) ||
		!validDigest(manifest.SequenceFingerprint) || len(manifest.Files) != len(expectedPaths) {
		return reject(CodeContents)
	}
	createdAt, err := time.Parse(time.RFC3339, manifest.CreatedAt)
	if err != nil || createdAt.Location() != time.UTC || createdAt.Format(time.RFC3339) != manifest.CreatedAt {
		return reject(CodeContents)
	}
	for index, path := range expectedPaths {
		file := manifest.Files[index]
		if file.Path != path || file.Size < 0 || file.Size == 0 && path != JournalPath || !validDigest(file.SHA256) || file.Mode != "0600" || file.Role != roleFor(path) {
			return reject(CodeContents)
		}
	}
	return nil
}

func inspectPayload(root, relative string) (File, error) {
	if !validRelative(relative) {
		return File{}, reject(CodeContents)
	}
	absolute := filepath.Join(root, filepath.FromSlash(relative))
	entry, err := inspectAbsolute(absolute, 0o600, maximumFor(relative), relative == JournalPath)
	if err != nil {
		return File{}, err
	}
	entry.Path = relative
	entry.Role = roleFor(relative)
	return entry, nil
}

func inspectAbsolute(path string, mode os.FileMode, maximum int64, allowEmpty bool) (File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return File{}, reject(CodeFilesystem)
	}
	file := os.NewFile(uintptr(fd), "recovery-payload")
	if file == nil {
		_ = unix.Close(fd)
		return File{}, reject(CodeFilesystem)
	}
	defer file.Close()
	info, err := validateOpenRegular(fd, file, mode, maximum, allowEmpty)
	if err != nil {
		return File{}, err
	}
	hash := sha256.New()
	copied, err := io.Copy(hash, io.LimitReader(file, maximum+1))
	if err != nil || copied != info.Size() || copied > maximum {
		return File{}, reject(CodeFilesystem)
	}
	return File{
		Size: info.Size(), SHA256: "sha256:" + hex.EncodeToString(hash.Sum(nil)),
		Mode: fmt.Sprintf("%04o", info.Mode().Perm()),
	}, nil
}

func readExactRegular(path string, mode os.FileMode, maximum int64) ([]byte, error) {
	contents, _, err := readSafe(path, mode, maximum, false)
	return contents, err
}

func readSafe(path string, mode os.FileMode, maximum int64, allowEmpty bool) ([]byte, os.FileInfo, error) {
	return readSafeWithLock(path, mode, maximum, allowEmpty, false)
}

func readSafeWithLock(path string, mode os.FileMode, maximum int64, allowEmpty, exclusiveLock bool) ([]byte, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, reject(CodeFilesystem)
	}
	file := os.NewFile(uintptr(fd), "recovery-payload")
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, reject(CodeFilesystem)
	}
	defer file.Close()
	if exclusiveLock {
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return nil, nil, reject(CodeFilesystem)
		}
	}
	info, err := validateOpenRegular(fd, file, mode, maximum, allowEmpty)
	if err != nil {
		return nil, nil, err
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) != info.Size() {
		return nil, nil, reject(CodeFilesystem)
	}
	return contents, info, nil
}

func validateOpenRegular(fd int, file *os.File, mode os.FileMode, maximum int64, allowEmpty bool) (os.FileInfo, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Size() < 0 ||
		info.Size() == 0 && !allowEmpty || info.Size() > maximum {
		return nil, reject(CodeContents)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return nil, reject(CodeFilesystem)
	}
	return info, nil
}

func copyExactRegular(source, destination string, mode os.FileMode, maximum int64, allowEmpty bool) error {
	contents, _, err := readSafe(source, mode, maximum, allowEmpty)
	if err != nil {
		return err
	}
	return writeExclusive(destination, contents, mode)
}

func copyLockedRegular(source, destination string, mode os.FileMode, maximum int64, allowEmpty bool) error {
	contents, _, err := readSafeWithLock(source, mode, maximum, allowEmpty, true)
	if err != nil {
		return err
	}
	return writeExclusive(destination, contents, mode)
}

func copyInheritedLockedRegular(source string, sourceFD int, destination string, mode os.FileMode, maximum int64, allowEmpty bool) error {
	if sourceFD < 3 || !canonicalAbs(source) {
		return reject(CodeArgument)
	}
	pathFD, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return reject(CodeFilesystem)
	}
	defer unix.Close(pathFD)
	var inheritedStat, pathStat unix.Stat_t
	if unix.Fstat(sourceFD, &inheritedStat) != nil || unix.Fstat(pathFD, &pathStat) != nil ||
		inheritedStat.Dev != pathStat.Dev || inheritedStat.Ino != pathStat.Ino ||
		uint32(inheritedStat.Mode&unix.S_IFMT) != unix.S_IFREG || uint32(inheritedStat.Mode&0o777) != uint32(mode.Perm()) ||
		inheritedStat.Nlink != 1 || inheritedStat.Uid != uint32(os.Geteuid()) ||
		inheritedStat.Size < 0 || inheritedStat.Size > maximum || inheritedStat.Size == 0 && !allowEmpty {
		return reject(CodeFilesystem)
	}
	if err := unix.Flock(sourceFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return reject(CodeFilesystem)
	}
	contents := make([]byte, inheritedStat.Size)
	for offset := 0; offset < len(contents); {
		read, readErr := unix.Pread(sourceFD, contents[offset:], int64(offset))
		if readErr != nil || read <= 0 {
			return reject(CodeFilesystem)
		}
		offset += read
	}
	return writeExclusive(destination, contents, mode)
}

func writeExclusive(path string, contents []byte, mode os.FileMode) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode))
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return reject(CodeExists)
		}
		return reject(CodeFilesystem)
	}
	file := os.NewFile(uintptr(fd), "recovery-output")
	if file == nil {
		_ = unix.Close(fd)
		return reject(CodeFilesystem)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return reject(CodeFilesystem)
	}
	if _, err := file.Write(contents); err != nil {
		return reject(CodeFilesystem)
	}
	if err := file.Sync(); err != nil {
		return reject(CodeSync)
	}
	remove = false
	return nil
}

func safeDirectory(path string, exactMode bool) error {
	if !canonicalAbs(path) {
		return reject(CodeArgument)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return reject(CodeFilesystem)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 || exactMode && stat.Mode&0o777 != 0o700 {
		return reject(CodeFilesystem)
	}
	return nil
}

func canonicalAbs(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		filepath.Base(path) != "." && filepath.Base(path) != string(filepath.Separator)
}

func validRelative(path string) bool {
	if path == "" || strings.Contains(path, "\\") || filepath.IsAbs(path) || filepath.ToSlash(filepath.Clean(path)) != path {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func maximumFor(path string) int64 {
	switch path {
	case JournalPath:
		return maxJournalBytes
	case MigrationsPath:
		return maxMigrations
	case RelationsPath:
		return maxRelations
	case PostgresMajorPath:
		return 16
	case SchemaPath:
		return maxSchemaBytes
	case SequencesPath:
		return maxSequences
	case PostgresDumpPath:
		return maxDumpBytes
	default:
		return 0
	}
}

func roleFor(path string) string {
	switch path {
	case JournalPath:
		return "executor_replay_journal"
	case MigrationsPath:
		return "migration_ledger"
	case RelationsPath:
		return "postgres_relation_contract"
	case PostgresMajorPath:
		return "postgres_major"
	case SchemaPath:
		return "schema_fingerprint_source"
	case SequencesPath:
		return "sequence_state"
	case PostgresDumpPath:
		return "postgres_data_archive"
	default:
		return ""
	}
}

func indexOfPath(path string) int {
	return sort.SearchStrings(expectedPaths, path)
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func keyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func manifestMessage(manifest []byte) []byte {
	sum := sha256.Sum256(manifest)
	message := make([]byte, 0, len(signatureDomain)+len(sum))
	message = append(message, signatureDomain...)
	message = append(message, sum[:]...)
	return message
}

func signManifest(privateKey ed25519.PrivateKey, manifest []byte) []byte {
	return ed25519.Sign(privateKey, manifestMessage(manifest))
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return reject(CodeContents)
	}
	return nil
}

func syncTree(root string) error {
	for _, path := range append(append([]string{}, expectedPaths...), manifestName, signatureName) {
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return reject(CodeFilesystem)
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil || closeErr != nil {
			return reject(CodeSync)
		}
	}
	for _, directory := range []string{"metadata", "postgres", "executor", "."} {
		if err := syncDirectory(filepath.Join(root, directory)); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return reject(CodeFilesystem)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return reject(CodeSync)
	}
	return nil
}
