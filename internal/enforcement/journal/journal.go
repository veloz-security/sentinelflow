package journal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/recoverybundle/offlinefence"
	"golang.org/x/sys/unix"
)

type osSyncer struct{}

func (osSyncer) SyncFile(file FileSyncTarget) error           { return file.Sync() }
func (osSyncer) SyncDirectory(directory FileSyncTarget) error { return directory.Sync() }

// Journal owns an exclusively locked file descriptor and an immutable index
// reconstructed only from verified frames. It must be closed by its owner.
type Journal struct {
	mu                 sync.RWMutex
	file               *os.File
	directory          *os.File
	offlineFence       *offlinefence.Lock
	syncer             Syncer
	capabilityVerifier CapabilityVerifier
	resultVerifier     ResultVerifier
	entries            map[string]*startedRecord
	nextSequence       uint64
	lastRecordDigest   string
	size               int64
	closed             bool
	poisoned           bool
}

func (j *Journal) String() string   { return "executor replay journal [redacted]" }
func (j *Journal) GoString() string { return j.String() }

// Open securely opens and exclusively locks an existing or new journal,
// verifies every frame, and refuses any torn, corrupt, duplicated, or
// conflicting history. It never truncates or repairs the file.
func Open(options Options) (*Journal, error) {
	if options.CapabilityVerifier == nil || options.ResultVerifier == nil ||
		options.CapabilityVerifier.KeyID() == "" || options.ResultVerifier.KeyID() == "" ||
		options.ResultVerifier.ExecutorID() == "" {
		return nil, reject(ErrorVerification)
	}
	clean := filepath.Clean(options.Path)
	if options.Path == "" || !filepath.IsAbs(clean) || clean != options.Path || filepath.Base(clean) == "." || filepath.Base(clean) == string(filepath.Separator) {
		return nil, reject(ErrorPath)
	}
	offlineLock, err := offlinefence.AcquireRuntime(clean)
	if err != nil {
		if errors.Is(err, offlinefence.ErrLocked) {
			return nil, reject(ErrorLocked)
		}
		if errors.Is(err, offlinefence.ErrInvalid) {
			return nil, reject(ErrorPath)
		}
		return nil, reject(ErrorUnsafeDirectory)
	}
	closeOfflineLock := true
	defer func() {
		if closeOfflineLock {
			_ = offlineLock.Close()
		}
	}()
	directoryPath, base := filepath.Split(clean)
	directoryPath = filepath.Clean(directoryPath)
	if base == "" || base == "." || base == ".." {
		return nil, reject(ErrorPath)
	}
	directoryFD, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, reject(ErrorUnsafeDirectory)
	}
	directory := os.NewFile(uintptr(directoryFD), "journal-directory")
	if directory == nil {
		_ = unix.Close(directoryFD)
		return nil, reject(ErrorUnsafeDirectory)
	}
	closeDirectory := true
	defer func() {
		if closeDirectory {
			_ = directory.Close()
		}
	}()
	if err := checkDirectory(directoryFD); err != nil {
		return nil, err
	}

	fileFD, created, err := openJournalAt(directoryFD, base)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fileFD), "executor-journal")
	if file == nil {
		_ = unix.Close(fileFD)
		return nil, reject(ErrorUnsafeFile)
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	if err := unix.Flock(fileFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, reject(ErrorLocked)
	}
	stat, err := checkFile(fileFD)
	if err != nil {
		return nil, err
	}
	if stat.Size > MaxJournalBytes {
		return nil, reject(ErrorTooLarge)
	}
	syncer := options.Syncer
	if syncer == nil {
		syncer = osSyncer{}
	}
	if created {
		if err := syncer.SyncFile(file); err != nil {
			return nil, reject(ErrorSync)
		}
		if err := syncer.SyncDirectory(directory); err != nil {
			return nil, reject(ErrorSync)
		}
	}
	j := &Journal{
		file: file, directory: directory, offlineFence: offlineLock, syncer: syncer,
		capabilityVerifier: options.CapabilityVerifier, resultVerifier: options.ResultVerifier,
		entries: make(map[string]*startedRecord), nextSequence: 1, size: stat.Size,
	}
	if err := j.scan(); err != nil {
		return nil, err
	}
	closeFile = false
	closeDirectory = false
	closeOfflineLock = false
	return j, nil
}

func openJournalAt(directoryFD int, base string) (int, bool, error) {
	flags := unix.O_RDWR | unix.O_APPEND | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fileFD, err := unix.Openat(directoryFD, base, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err == nil {
		if chmodErr := unix.Fchmod(fileFD, 0o600); chmodErr != nil {
			_ = unix.Close(fileFD)
			return -1, false, reject(ErrorUnsafeFile)
		}
		return fileFD, true, nil
	}
	if !errors.Is(err, unix.EEXIST) {
		return -1, false, reject(ErrorUnsafeFile)
	}
	fileFD, err = unix.Openat(directoryFD, base, flags, 0)
	if err != nil {
		return -1, false, reject(ErrorUnsafeFile)
	}
	return fileFD, false, nil
}

func checkDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 {
		return reject(ErrorUnsafeDirectory)
	}
	return nil
}

func checkFile(fd int) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return unix.Stat_t{}, reject(ErrorUnsafeFile)
	}
	return stat, nil
}

func (j *Journal) scan() error {
	var offset int64
	expectedSequence := uint64(1)
	previousRecordDigest := ""
	for offset < j.size {
		remaining := j.size - offset
		if remaining < frameHeaderBytes+checksumBytes {
			return reject(ErrorCorrupt)
		}
		header := make([]byte, frameHeaderBytes)
		if _, err := j.file.ReadAt(header, offset); err != nil {
			return reject(ErrorIO)
		}
		payloadLength := binary.BigEndian.Uint32(header[20:24])
		if payloadLength == 0 || payloadLength > MaxPayloadBytes {
			return reject(ErrorCorrupt)
		}
		length := int64(frameHeaderBytes) + int64(payloadLength) + checksumBytes
		if length > remaining || length > MaxFrameBytes {
			return reject(ErrorCorrupt)
		}
		frame := make([]byte, int(length))
		if _, err := j.file.ReadAt(frame, offset); err != nil {
			return reject(ErrorIO)
		}
		decoded, err := decodeFrame(frame)
		if err != nil {
			return err
		}
		if decoded.sequence != expectedSequence {
			return reject(ErrorSequence)
		}
		payload, recordDigest, err := parseRecordPayload(decoded.payload, decoded.recordType, decoded.sequence, previousRecordDigest)
		if err != nil {
			return err
		}
		if err := j.indexFrame(decoded, payload); err != nil {
			return err
		}
		previousRecordDigest = recordDigest
		offset += length
		expectedSequence++
	}
	if offset != j.size {
		return reject(ErrorCorrupt)
	}
	j.nextSequence = expectedSequence
	j.lastRecordDigest = previousRecordDigest
	return nil
}

func (j *Journal) indexFrame(frame decodedFrame, payload recordPayload) error {
	switch frame.recordType {
	case recordStarted:
		started, err := parseStartedPayload(payload, j.capabilityVerifier, frame.sequence)
		if err != nil {
			return err
		}
		identifier := started.verified.Value().CapabilityID
		if _, exists := j.entries[identifier]; exists {
			return reject(ErrorConflict)
		}
		j.entries[identifier] = started
		return nil
	case recordTerminal:
		start := j.entries[payload.CapabilityID]
		if start == nil {
			return reject(ErrorMissingStart)
		}
		if start.terminal != nil {
			return reject(ErrorDuplicateTerminal)
		}
		terminal, err := parseTerminalPayload(payload, j.resultVerifier, frame.sequence, start)
		if err != nil {
			return err
		}
		start.terminal = terminal
		return nil
	default:
		return reject(ErrorVersion)
	}
}

// Lookup verifies the incoming exact request and checks durable replay state.
// It never performs freshness checks and never returns execution authority.
func (j *Journal) Lookup(signed capability.SignedCapability) (Outcome, error) {
	verified, err := j.capabilityVerifier.Verify(signed)
	if err != nil {
		return Outcome{}, reject(ErrorVerification)
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	if err := j.readyLocked(); err != nil {
		return Outcome{}, err
	}
	start := j.entries[verified.Value().CapabilityID]
	if start == nil {
		return Outcome{state: StateUnseen}, nil
	}
	if !sameCapability(start, signed, verified) {
		return Outcome{}, reject(ErrorConflict)
	}
	return existingOutcome(start), nil
}

// Begin performs replay lookup before freshness, then commits a started frame
// across file and directory fsync before returning a one-use Permit. Exact
// retries return only terminal or recovery state and cannot execute again.
func (j *Journal) Begin(signed capability.SignedCapability, receivedAt, deadlineAt time.Time) (Outcome, error) {
	verified, err := j.capabilityVerifier.Verify(signed)
	if err != nil {
		return Outcome{}, reject(ErrorVerification)
	}
	receivedAt = receivedAt.UTC()
	deadlineAt = deadlineAt.UTC()
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.readyLocked(); err != nil {
		return Outcome{}, err
	}
	identifier := verified.Value().CapabilityID
	if start := j.entries[identifier]; start != nil {
		if !sameCapability(start, signed, verified) {
			return Outcome{}, reject(ErrorConflict)
		}
		return existingOutcome(start), nil
	}
	if !canonicalTime(receivedAt) || !canonicalTime(deadlineAt) || !deadlineAt.After(receivedAt) ||
		deadlineAt.Sub(receivedAt) > MaxDeadline || deadlineAt.After(verified.Value().ExpiresAt) {
		return Outcome{}, reject(ErrorTime)
	}
	if err := checkFresh(verified, receivedAt); err != nil {
		return Outcome{}, err
	}
	sequence := j.nextSequence
	payload, recordDigest, err := marshalRecordPayload(newStartedPayload(
		signed, verified, receivedAt, deadlineAt, sequence, j.lastRecordDigest,
	))
	if err != nil {
		return Outcome{}, err
	}
	frame, err := encodeFrame(recordStarted, sequence, payload)
	if err != nil {
		return Outcome{}, err
	}
	if err := j.appendLocked(frame); err != nil {
		return Outcome{}, err
	}
	start := &startedRecord{sequence: sequence, signed: copyCapability(signed), verified: verified, received: receivedAt, deadline: deadlineAt}
	j.entries[identifier] = start
	j.nextSequence++
	j.lastRecordDigest = recordDigest
	return Outcome{
		state: StateNewStarted, started: snapshotStarted(start),
		permit: &Permit{verified: verified, deadline: deadlineAt},
	}, nil
}

func checkFresh(verified capability.VerifiedCapability, at time.Time) error {
	var err error
	switch verified.Value().Operation {
	case capability.OperationAdd:
		_, err = verified.AddAt(at)
	case capability.OperationRevoke:
		_, err = verified.RevokeAt(at)
	case capability.OperationInspect:
		_, err = verified.InspectAt(at)
	default:
		return reject(ErrorOperation)
	}
	if err != nil {
		return reject(ErrorFreshness)
	}
	return nil
}

// Complete verifies, binds, and durably appends an exact terminal result.
// The bool result is true only when this call appended the terminal frame.
func (j *Journal) Complete(signed capability.SignedResult) (TerminalSnapshot, bool, error) {
	verified, err := j.resultVerifier.Verify(signed)
	if err != nil {
		return TerminalSnapshot{}, false, reject(ErrorVerification)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.readyLocked(); err != nil {
		return TerminalSnapshot{}, false, err
	}
	value := verified.Value()
	start := j.entries[value.CapabilityID]
	if start == nil {
		return TerminalSnapshot{}, false, reject(ErrorMissingStart)
	}
	if _, err := verified.BindTo(start.verified); err != nil || value.JournalSequence != start.sequence {
		return TerminalSnapshot{}, false, reject(ErrorVerification)
	}
	if start.terminal != nil {
		if !sameResult(start.terminal, signed, verified) {
			return TerminalSnapshot{}, false, reject(ErrorDuplicateTerminal)
		}
		return snapshotTerminal(start.sequence, start.terminal), false, nil
	}
	sequence := j.nextSequence
	payload, recordDigest, err := marshalRecordPayload(newTerminalPayload(
		start, signed, verified, sequence, j.lastRecordDigest,
	))
	if err != nil {
		return TerminalSnapshot{}, false, err
	}
	frame, err := encodeFrame(recordTerminal, sequence, payload)
	if err != nil {
		return TerminalSnapshot{}, false, err
	}
	if err := j.appendLocked(frame); err != nil {
		return TerminalSnapshot{}, false, err
	}
	terminal := &terminalRecord{sequence: sequence, signed: copyResult(signed), verified: verified}
	start.terminal = terminal
	j.nextSequence++
	j.lastRecordDigest = recordDigest
	return snapshotTerminal(start.sequence, terminal), true, nil
}

func (j *Journal) appendLocked(frame []byte) error {
	stat, err := checkFile(int(j.file.Fd()))
	if err != nil || stat.Size != j.size {
		j.poisoned = true
		return reject(ErrorUnsafeFile)
	}
	if err := checkDirectory(int(j.directory.Fd())); err != nil {
		j.poisoned = true
		return err
	}
	if int64(len(frame)) > MaxJournalBytes-j.size {
		return reject(ErrorTooLarge)
	}
	written, writeErr := j.file.Write(frame)
	if writeErr != nil || written != len(frame) {
		j.poisoned = true
		return reject(ErrorIO)
	}
	if err := j.syncer.SyncFile(j.file); err != nil {
		j.poisoned = true
		return reject(ErrorSync)
	}
	if err := j.syncer.SyncDirectory(j.directory); err != nil {
		j.poisoned = true
		return reject(ErrorSync)
	}
	j.size += int64(len(frame))
	return nil
}

func (j *Journal) readyLocked() error {
	if j == nil || j.closed || j.poisoned || j.file == nil || j.directory == nil || j.offlineFence == nil {
		return reject(ErrorUnhealthy)
	}
	return nil
}

// Close releases the process lock. It does not alter journal contents.
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	fileErr := j.file.Close()
	directoryErr := j.directory.Close()
	fenceErr := j.offlineFence.Close()
	if fileErr != nil || directoryErr != nil || fenceErr != nil {
		return reject(ErrorIO)
	}
	return nil
}

func sameCapability(start *startedRecord, signed capability.SignedCapability, verified capability.VerifiedCapability) bool {
	return start.verified.Digest() == verified.Digest() && start.verified.KeyID() == verified.KeyID() &&
		start.verified.ExecutorID() == verified.ExecutorID() && start.signed.KeyID() == signed.KeyID() &&
		bytes.Equal(start.signed.CanonicalBytes(), signed.CanonicalBytes()) &&
		bytes.Equal(start.signed.Signature(), signed.Signature()) &&
		bytes.Equal(start.signed.ArtifactBytes(), signed.ArtifactBytes())
}

func sameResult(existing *terminalRecord, signed capability.SignedResult, verified capability.VerifiedResult) bool {
	return existing.verified.Digest() == verified.Digest() && existing.signed.KeyID() == signed.KeyID() &&
		existing.signed.ExecutorID() == signed.ExecutorID() &&
		bytes.Equal(existing.signed.CanonicalBytes(), signed.CanonicalBytes()) &&
		bytes.Equal(existing.signed.Signature(), signed.Signature())
}

func existingOutcome(start *startedRecord) Outcome {
	if start.terminal != nil {
		terminal := snapshotTerminal(start.sequence, start.terminal)
		return Outcome{state: StateTerminal, started: snapshotStarted(start), terminal: &terminal}
	}
	return Outcome{state: StateStartedOnly, started: snapshotStarted(start), recovery: &Recovery{verified: start.verified}}
}

func snapshotStarted(start *startedRecord) StartedSnapshot {
	value := start.verified.Value()
	return StartedSnapshot{
		Sequence: start.sequence, CapabilityID: value.CapabilityID, CapabilityDigest: start.verified.Digest(),
		ArtifactDigest: value.ArtifactDigest, Operation: value.Operation, ActionID: value.ActionID,
		TargetIPv4: value.TargetIPv4, ReceivedAt: start.received, DeadlineAt: start.deadline,
	}
}

func snapshotTerminal(startSequence uint64, terminal *terminalRecord) TerminalSnapshot {
	return TerminalSnapshot{
		sequence: terminal.sequence, startedSequence: startSequence, resultDigest: terminal.verified.Digest(),
		signed: copyResult(terminal.signed),
	}
}

func copyCapability(input capability.SignedCapability) capability.SignedCapability {
	return capability.NewUntrustedSignedCapability(input.KeyID(), input.CanonicalBytes(), input.Signature(), input.ArtifactBytes())
}

func copyResult(input capability.SignedResult) capability.SignedResult {
	return capability.NewUntrustedSignedResult(input.KeyID(), input.ExecutorID(), input.CanonicalBytes(), input.Signature())
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Year() >= 1 && value.Year() <= 9999 &&
		value.Nanosecond()%int(time.Millisecond) == 0
}
