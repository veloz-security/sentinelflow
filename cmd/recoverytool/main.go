package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/devwooops/sentinelflow/internal/keymaterial"
	"github.com/devwooops/sentinelflow/internal/recoverybundle"
	"github.com/devwooops/sentinelflow/internal/recoverybundle/offlinefence"
	"golang.org/x/sys/unix"
)

const (
	sessionFenceFDEnv       = "SENTINELFLOW_RECOVERY_FENCE_FD"
	sessionJournalFDEnv     = "SENTINELFLOW_RECOVERY_JOURNAL_FD"
	sessionJournalPathEnv   = "SENTINELFLOW_RECOVERY_JOURNAL_PATH"
	sessionCompatibilityEnv = "SENTINELFLOW_RECOVERY_COMPATIBILITY"
	compatibilityExisting   = "existing-journal-continuously-fenced"
	compatibilityFreshV01   = "fresh-v0.1-stable-fence-required"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(arguments []string) int {
	_ = unix.Umask(0o077)
	if len(arguments) == 0 {
		return fail("command_required")
	}
	var err error
	switch arguments[0] {
	case "keygen":
		err = runKeygen(arguments[1:])
	case "run-session":
		err = runSession(arguments[1:])
	case "validate-session":
		err = runValidateSession(arguments[1:])
	case "exec-session-child":
		err = runExecSessionChild(arguments[1:])
	case "postgres-lock-sql":
		err = runPostgreSQLLockSQL(arguments[1:])
	case "postgres-relation-contract":
		err = runPostgreSQLRelationContract(arguments[1:])
	case "postgres-sequence-names":
		err = runPostgreSQLSequenceNames(arguments[1:])
	case "postgres-artifact-copy-sql":
		err = runPostgreSQLArtifactCopySQL(arguments[1:])
	case "postgres-relation-copy-sql":
		err = runPostgreSQLRelationCopySQL(arguments[1:])
	case "postgres-sequence-copy-sql":
		err = runPostgreSQLSequenceCopySQL(arguments[1:])
	case "validate-execution-artifacts":
		err = runValidateExecutionArtifacts(arguments[1:])
	case "validate-recovery-state":
		err = runValidateRecoveryState(arguments[1:])
	case "seal":
		err = runSeal(arguments[1:])
	case "publish":
		err = runPublish(arguments[1:])
	case "verify":
		err = runVerify(arguments[1:])
	case "stage-journal":
		err = runStageJournal(arguments[1:])
	case "commit-journal":
		err = runCommitJournal(arguments[1:])
	case "staged-journal-path":
		err = runStagedJournalPath(arguments[1:])
	case "restore-state-path":
		err = runRestoreStatePath(arguments[1:])
	case "prepare-restore":
		err = runPrepareRestore(arguments[1:])
	case "mark-database-restored":
		err = runMarkDatabaseRestored(arguments[1:])
	case "commit-prepared-journal":
		err = runCommitPreparedJournal(arguments[1:])
	case "finalize-restore":
		err = runFinalizeRestore(arguments[1:])
	default:
		return fail("unknown_command")
	}
	if err != nil {
		var bundleError *recoverybundle.Error
		if errors.As(err, &bundleError) {
			return fail(string(bundleError.Code()))
		}
		return fail("operation_rejected")
	}
	return 0
}

func runKeygen(arguments []string) error {
	set := flag.NewFlagSet("keygen", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	privatePath := set.String("private", "", "absolute private-key path")
	publicPath := set.String("public", "", "absolute public-key path")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 || !canonicalAbs(*privatePath) || !canonicalAbs(*publicPath) || *privatePath == *publicPath {
		return errors.New("invalid keygen arguments")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	defer clear(privatePEM)
	if err := writeKeyExclusive(*privatePath, privatePEM, 0o600); err != nil {
		return err
	}
	if err := writeKeyExclusive(*publicPath, publicPEM, 0o644); err != nil {
		_ = os.Remove(*privatePath)
		return err
	}
	if err := syncDirectory(filepath.Dir(*privatePath)); err != nil {
		return err
	}
	if filepath.Dir(*publicPath) != filepath.Dir(*privatePath) {
		return syncDirectory(filepath.Dir(*publicPath))
	}
	return nil
}

func runSession(arguments []string) error {
	set := flag.NewFlagSet("run-session", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	journal := set.String("journal", "", "absolute replay-journal path")
	if err := set.Parse(arguments); err != nil || set.NArg() < 1 ||
		!canonicalAbs(*journal) || !canonicalAbs(set.Arg(0)) ||
		os.Getenv(sessionFenceFDEnv) != "" || os.Getenv(sessionJournalFDEnv) != "" ||
		os.Getenv(sessionJournalPathEnv) != "" || os.Getenv(sessionCompatibilityEnv) != "" {
		return errors.New("invalid recovery session arguments")
	}
	lock, err := offlinefence.AcquireOffline(*journal)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	fenceFD, journalFD, fresh, err := lock.PrepareInheritance()
	if err != nil {
		return err
	}
	compatibility := compatibilityExisting
	if fresh {
		compatibility = compatibilityFreshV01
	}
	environment := make([]string, 0, len(os.Environ())+4)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case sessionFenceFDEnv, sessionJournalFDEnv, sessionJournalPathEnv, sessionCompatibilityEnv:
			continue
		}
		environment = append(environment, entry)
	}
	environment = append(environment,
		sessionFenceFDEnv+"="+strconv.Itoa(fenceFD),
		sessionJournalFDEnv+"="+strconv.Itoa(journalFD),
		sessionJournalPathEnv+"="+*journal,
		sessionCompatibilityEnv+"="+compatibility,
	)
	return syscall.Exec(set.Arg(0), set.Args(), environment)
}

func runValidateSession(arguments []string) error {
	set := flag.NewFlagSet("validate-session", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	journal := set.String("journal", "", "absolute replay-journal path")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid recovery session validation arguments")
	}
	return requireInheritedSession(*journal)
}

func runExecSessionChild(arguments []string) error {
	set := flag.NewFlagSet("exec-session-child", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	journal := set.String("journal", "", "absolute replay-journal path")
	if err := set.Parse(arguments); err != nil || set.NArg() < 1 || !canonicalAbs(set.Arg(0)) {
		return errors.New("invalid recovery child arguments")
	}
	fenceFD, journalFD, _, err := inheritedSession(*journal)
	if err != nil {
		return err
	}
	for _, fd := range []int{fenceFD, journalFD} {
		if fd < 0 {
			continue
		}
		flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if flagErr != nil {
			return offlinefence.ErrUnsafe
		}
		if _, flagErr = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags&^unix.FD_CLOEXEC); flagErr != nil {
			return offlinefence.ErrUnsafe
		}
	}
	return syscall.Exec(set.Arg(0), set.Args(), os.Environ())
}

func runPostgreSQLLockSQL(arguments []string) error {
	set := flag.NewFlagSet("postgres-lock-sql", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	mode := set.String("mode", "", "backup or restore")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid PostgreSQL lock arguments")
	}
	sql, err := recoverybundle.PostgreSQLRecoveryLockSQL(
		recoverybundle.PostgreSQLRelationLockMode(*mode),
	)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(os.Stdout, sql)
	return err
}

func runPostgreSQLRelationContract(arguments []string) error {
	set := flag.NewFlagSet("postgres-relation-contract", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid PostgreSQL relation contract arguments")
	}
	_, err := fmt.Fprint(os.Stdout, recoverybundle.PostgreSQLRelationContractRows())
	return err
}

func runPostgreSQLSequenceNames(arguments []string) error {
	set := flag.NewFlagSet("postgres-sequence-names", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid PostgreSQL sequence arguments")
	}
	for _, name := range recoverybundle.PostgreSQLSequenceNames() {
		if _, err := fmt.Fprintln(os.Stdout, name); err != nil {
			return err
		}
	}
	return nil
}

func runPostgreSQLArtifactCopySQL(arguments []string) error {
	set := flag.NewFlagSet("postgres-artifact-copy-sql", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid PostgreSQL artifact query arguments")
	}
	_, err := fmt.Fprint(os.Stdout, recoverybundle.PostgreSQLExecutionArtifactCopySQL())
	return err
}

func runPostgreSQLRelationCopySQL(arguments []string) error {
	set := flag.NewFlagSet("postgres-relation-copy-sql", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid PostgreSQL relation query arguments")
	}
	_, err := fmt.Fprint(os.Stdout, recoverybundle.PostgreSQLRelationContractCopySQL())
	return err
}

func runPostgreSQLSequenceCopySQL(arguments []string) error {
	set := flag.NewFlagSet("postgres-sequence-copy-sql", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid PostgreSQL sequence query arguments")
	}
	_, err := fmt.Fprint(os.Stdout, recoverybundle.PostgreSQLSequenceStateCopySQL())
	return err
}

func runValidateExecutionArtifacts(arguments []string) error {
	set := flag.NewFlagSet("validate-execution-artifacts", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	journal := set.String("journal", "", "absolute replay-journal path")
	dispatchPath := set.String("dispatch-public-key", "", "dispatcher Ed25519 public key")
	resultPath := set.String("result-public-key", "", "executor result Ed25519 public key")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 ||
		!canonicalAbs(*dispatchPath) || !canonicalAbs(*resultPath) || *dispatchPath == *resultPath {
		return errors.New("invalid execution artifact arguments")
	}
	if err := requireInheritedSession(*journal); err != nil {
		return err
	}
	dispatchPublic, err := keymaterial.LoadPublicFile(*dispatchPath)
	if err != nil {
		return err
	}
	defer clear(dispatchPublic)
	resultPublic, err := keymaterial.LoadPublicFile(*resultPath)
	if err != nil {
		return err
	}
	defer clear(resultPublic)
	return recoverybundle.ValidateExecutionArtifactRows(os.Stdin, dispatchPublic, resultPublic)
}

func runValidateRecoveryState(arguments []string) error {
	set := flag.NewFlagSet("validate-recovery-state", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	journal := set.String("journal", "", "absolute offline-fenced journal path")
	replayPath := set.String("replay-journal", "", "absolute copied executor replay journal")
	dispatchPath := set.String("dispatch-public-key", "", "dispatcher Ed25519 public key")
	resultPath := set.String("result-public-key", "", "executor result Ed25519 public key")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 ||
		!canonicalAbs(*replayPath) || !canonicalAbs(*dispatchPath) ||
		!canonicalAbs(*resultPath) || *dispatchPath == *resultPath {
		return errors.New("invalid recovery state arguments")
	}
	if err := requireInheritedSession(*journal); err != nil {
		return err
	}
	dispatchPublic, err := keymaterial.LoadPublicFile(*dispatchPath)
	if err != nil {
		return err
	}
	defer clear(dispatchPublic)
	resultPublic, err := keymaterial.LoadPublicFile(*resultPath)
	if err != nil {
		return err
	}
	defer clear(resultPublic)
	return recoverybundle.ValidateJournalExecutionArtifactFile(
		*replayPath, os.Stdin, dispatchPublic, resultPublic,
	)
}

func runSeal(arguments []string) error {
	set := flag.NewFlagSet("seal", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	staging := set.String("staging", "", "absolute staging directory")
	output := set.String("output", "", "absolute output directory")
	journal := set.String("journal", "", "absolute replay journal path")
	keyPath := set.String("signing-key", "", "absolute Ed25519 private-key path")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid seal arguments")
	}
	_, journalFD, _, err := inheritedSession(*journal)
	if err != nil {
		return err
	}
	privateKey, err := keymaterial.LoadPrivateFile(*keyPath)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	return recoverybundle.Seal(recoverybundle.SealOptions{
		StagingDir: *staging,
		OutputDir:  *output,
		Journal:    *journal,
		JournalFD:  journalFD,
		PrivateKey: privateKey,
		Now:        time.Now(),
	})
}

func runPublish(arguments []string) error {
	set := flag.NewFlagSet("publish", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	candidate := set.String("candidate", "", "absolute sealed candidate directory")
	output := set.String("output", "", "absolute public bundle directory")
	journal := set.String("journal", "", "absolute replay journal path")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid publish arguments")
	}
	if err := requireInheritedSession(*journal); err != nil {
		return err
	}
	return recoverybundle.Publish(*candidate, *output)
}

func runVerify(arguments []string) error {
	root, publicKey, err := parseVerifiedArguments("verify", arguments, false)
	if err != nil {
		return err
	}
	_, err = recoverybundle.Verify(root, publicKey)
	return err
}

func runStageJournal(arguments []string) error {
	root, publicKey, destination, err := parseJournalArguments("stage-journal", arguments)
	if err != nil {
		return err
	}
	_, err = recoverybundle.StageJournal(root, publicKey, destination)
	return err
}

func runCommitJournal(arguments []string) error {
	root, publicKey, destination, err := parseJournalArguments("commit-journal", arguments)
	if err != nil {
		return err
	}
	return recoverybundle.CommitJournal(root, publicKey, destination)
}

func runStagedJournalPath(arguments []string) error {
	set := flag.NewFlagSet("staged-journal-path", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	destination := set.String("destination", "", "absolute journal destination")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid staged path arguments")
	}
	path, err := recoverybundle.StagedJournalPath(*destination)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, path)
	return err
}

func runRestoreStatePath(arguments []string) error {
	set := flag.NewFlagSet("restore-state-path", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	destination := set.String("destination", "", "absolute journal destination")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("invalid restore state path arguments")
	}
	path, err := recoverybundle.RestoreStatePath(*destination)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, path)
	return err
}

func runPrepareRestore(arguments []string) error {
	root, publicKey, destination, identity, err := parseRestoreArguments("prepare-restore", arguments)
	if err != nil {
		return err
	}
	status, err := recoverybundle.PrepareRestore(root, publicKey, destination, identity)
	if err != nil {
		return err
	}
	return printRestoreStatus(status)
}

func runMarkDatabaseRestored(arguments []string) error {
	root, publicKey, destination, identity, err := parseRestoreArguments("mark-database-restored", arguments)
	if err != nil {
		return err
	}
	status, err := recoverybundle.MarkDatabaseRestored(root, publicKey, destination, identity)
	if err != nil {
		return err
	}
	return printRestoreStatus(status)
}

func runCommitPreparedJournal(arguments []string) error {
	root, publicKey, destination, identity, err := parseRestoreArguments("commit-prepared-journal", arguments)
	if err != nil {
		return err
	}
	status, err := recoverybundle.CommitPreparedJournal(root, publicKey, destination, identity)
	if err != nil {
		return err
	}
	return printRestoreStatus(status)
}

func runFinalizeRestore(arguments []string) error {
	root, publicKey, destination, identity, err := parseRestoreArguments("finalize-restore", arguments)
	if err != nil {
		return err
	}
	status, err := recoverybundle.FinalizeRestore(root, publicKey, destination, identity)
	if err != nil {
		return err
	}
	return printRestoreStatus(status)
}

func parseJournalArguments(name string, arguments []string) (string, ed25519.PublicKey, string, error) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	root := set.String("bundle", "", "absolute bundle directory")
	keyPath := set.String("verification-key", "", "absolute Ed25519 public-key path")
	destination := set.String("destination", "", "absolute replay journal destination")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return "", nil, "", errors.New("invalid journal arguments")
	}
	publicKey, err := keymaterial.LoadPublicFile(*keyPath)
	if err != nil {
		return "", nil, "", err
	}
	if err := requireInheritedSession(*destination); err != nil {
		return "", nil, "", err
	}
	return *root, publicKey, *destination, nil
}

func parseRestoreArguments(name string, arguments []string) (string, ed25519.PublicKey, string, string, error) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	root := set.String("bundle", "", "absolute bundle directory")
	keyPath := set.String("verification-key", "", "absolute Ed25519 public-key path")
	destination := set.String("destination", "", "absolute replay journal destination")
	databaseIdentity := set.String("database-identity", "", "bounded PostgreSQL destination identity")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return "", nil, "", "", errors.New("invalid restore arguments")
	}
	publicKey, err := keymaterial.LoadPublicFile(*keyPath)
	if err != nil {
		return "", nil, "", "", err
	}
	if err := requireInheritedSession(*destination); err != nil {
		return "", nil, "", "", err
	}
	return *root, publicKey, *destination, *databaseIdentity, nil
}

func requireInheritedSession(journal string) error {
	_, _, _, err := inheritedSession(journal)
	return err
}

func inheritedSession(journal string) (int, int, bool, error) {
	if !canonicalAbs(journal) || os.Getenv(sessionJournalPathEnv) != journal {
		return -1, -1, false, offlinefence.ErrInvalid
	}
	fenceFD, err := strconv.Atoi(os.Getenv(sessionFenceFDEnv))
	if err != nil {
		return -1, -1, false, offlinefence.ErrInvalid
	}
	journalFD, err := strconv.Atoi(os.Getenv(sessionJournalFDEnv))
	if err != nil {
		return -1, -1, false, offlinefence.ErrInvalid
	}
	compatibility := os.Getenv(sessionCompatibilityEnv)
	fresh := compatibility == compatibilityFreshV01
	if !fresh && compatibility != compatibilityExisting {
		return -1, -1, false, offlinefence.ErrInvalid
	}
	if err := offlinefence.ValidateInherited(journal, fenceFD, journalFD, fresh); err != nil {
		return -1, -1, false, err
	}
	return fenceFD, journalFD, fresh, nil
}

func printRestoreStatus(status recoverybundle.RestoreStatus) error {
	_, err := fmt.Fprintf(
		os.Stdout, "%s\t%s\t%s\t%s\t%s\t%s\n",
		status.Phase, status.ReceiptDigest, status.JournalState,
		status.ManifestDigest, status.DatabaseDigest, status.JournalDigest,
	)
	return err
}

func parseVerifiedArguments(name string, arguments []string, allowExtra bool) (string, ed25519.PublicKey, error) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	root := set.String("bundle", "", "absolute bundle directory")
	keyPath := set.String("verification-key", "", "absolute Ed25519 public-key path")
	if err := set.Parse(arguments); err != nil || (!allowExtra && set.NArg() != 0) {
		return "", nil, errors.New("invalid verify arguments")
	}
	publicKey, err := keymaterial.LoadPublicFile(*keyPath)
	if err != nil {
		return "", nil, err
	}
	return *root, publicKey, nil
}

func writeKeyExclusive(path string, contents []byte, mode os.FileMode) error {
	if !canonicalAbs(path) {
		return errors.New("invalid key path")
	}
	if err := safeParent(filepath.Dir(path)); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode))
	if err != nil {
		return errors.New("key destination rejected")
	}
	file := os.NewFile(uintptr(fd), "recovery-key")
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("key destination rejected")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	remove = false
	return nil
}

func safeParent(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 {
		return errors.New("unsafe key directory")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func canonicalAbs(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		filepath.Base(path) != "." && filepath.Base(path) != string(filepath.Separator)
}

func fail(code string) int {
	fmt.Fprintf(os.Stderr, "SentinelFlow recovery tool failed: %s\n", code)
	return 1
}

type ioDiscard struct{}

func (ioDiscard) Write(contents []byte) (int, error) { return len(contents), nil }
