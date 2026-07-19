// Package offlinefence provides the live process fence shared by the executor
// replay journal and recovery tooling. Runtime journal owners hold a shared
// lock for their entire lifetime. Backup and restore sessions hold the
// exclusive lock, so neither side can race the other across file replacement.
package offlinefence

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

const suffix = ".sentinelflow-offline-v1.fence"

var (
	ErrInvalid = errors.New("offline fence argument rejected")
	ErrUnsafe  = errors.New("offline fence filesystem rejected")
	ErrLocked  = errors.New("offline fence is held")
	ErrNotHeld = errors.New("offline recovery fence is not held")
)

// Lock owns one advisory lock until Close. It contains no journal data.
type Lock struct {
	mu            sync.Mutex
	file          *os.File
	legacyJournal *os.File
	freshJournal  bool
	closed        bool
}

// Path returns the stable sibling fence path for a replay journal.
func Path(journal string) (string, error) {
	if !canonicalAbs(journal) {
		return "", ErrInvalid
	}
	return filepath.Join(filepath.Dir(journal), "."+filepath.Base(journal)+suffix), nil
}

// AcquireRuntime obtains the shared lock an executor must hold from before it
// opens the replay journal until after the journal descriptor is closed.
func AcquireRuntime(journal string) (*Lock, error) {
	return acquire(journal, unix.LOCK_SH, false)
}

// AcquireOffline obtains the exclusive recovery lock. When the journal already
// exists, it also owns that journal inode's exclusive flock for the complete
// session. A fresh destination has no inode that can fence an older executor;
// it is therefore supported only with the v0.1 stable-fence-aware executor.
func AcquireOffline(journal string) (*Lock, error) {
	return acquire(journal, unix.LOCK_EX, true)
}

// RequireOffline fails unless another process currently owns the exclusive
// fence for this exact journal path. Recovery subcommands use it to prevent
// accidental invocation outside the long-lived recovery session.
func RequireOffline(journal string) error {
	path, err := Path(journal)
	if err != nil {
		return err
	}
	file, err := openExistingFence(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB); err == nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		return ErrNotHeld
	} else if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return nil
	}
	return ErrUnsafe
}

func acquire(journal string, mode int, checkJournal bool) (*Lock, error) {
	path, err := Path(journal)
	if err != nil {
		return nil, err
	}
	directoryPath := filepath.Dir(path)
	directoryFD, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	directory := os.NewFile(uintptr(directoryFD), "offline-fence-directory")
	if directory == nil {
		_ = unix.Close(directoryFD)
		return nil, ErrUnsafe
	}
	defer directory.Close()
	if err := checkDirectory(directoryFD); err != nil {
		return nil, err
	}
	file, created, err := openFenceAt(directoryFD, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	if err := unix.Flock(int(file.Fd()), mode|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, ErrUnsafe
	}
	if created {
		if err := file.Sync(); err != nil {
			return nil, ErrUnsafe
		}
		if err := directory.Sync(); err != nil {
			return nil, ErrUnsafe
		}
	}
	var legacyJournal *os.File
	freshJournal := false
	if checkJournal {
		legacyJournal, freshJournal, err = lockExistingJournal(directoryFD, filepath.Base(journal))
		if err != nil {
			return nil, err
		}
	}
	closeFile = false
	return &Lock{file: file, legacyJournal: legacyJournal, freshJournal: freshJournal}, nil
}

func openFenceAt(directoryFD int, base string) (*os.File, bool, error) {
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Openat(directoryFD, base, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	created := err == nil
	if err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return nil, false, ErrUnsafe
		}
		fd, err = unix.Openat(directoryFD, base, flags, 0)
		if err != nil {
			return nil, false, ErrUnsafe
		}
	}
	file := os.NewFile(uintptr(fd), "offline-fence")
	if file == nil {
		_ = unix.Close(fd)
		return nil, false, ErrUnsafe
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return nil, false, ErrUnsafe
		}
	}
	if err := checkRegular(int(file.Fd()), true); err != nil {
		_ = file.Close()
		return nil, false, err
	}
	return file, created, nil
}

func openExistingFence(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrNotHeld
	}
	file := os.NewFile(uintptr(fd), "offline-fence-check")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrUnsafe
	}
	if err := checkRegular(fd, true); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func lockExistingJournal(directoryFD int, base string) (*os.File, bool, error) {
	fd, err := unix.Openat(directoryFD, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, ErrUnsafe
	}
	file := os.NewFile(uintptr(fd), "offline-legacy-journal")
	if file == nil {
		_ = unix.Close(fd)
		return nil, false, ErrUnsafe
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	if err := checkRegular(fd, false); err != nil {
		return nil, false, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, false, ErrLocked
		}
		return nil, false, ErrUnsafe
	}
	closeFile = false
	return file, false, nil
}

// PrepareInheritance clears close-on-exec only for the two recovery fence
// descriptors. The returned descriptors must be inherited by the session
// shell and every database helper so an orphaned child continues to fence the
// executor after wrapper or shell death.
func (lock *Lock) PrepareInheritance() (fenceFD, legacyJournalFD int, fresh bool, err error) {
	if lock == nil {
		return -1, -1, false, ErrInvalid
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.closed || lock.file == nil {
		return -1, -1, false, ErrUnsafe
	}
	fenceFD = int(lock.file.Fd())
	if err := clearCloseOnExec(fenceFD); err != nil {
		return -1, -1, false, err
	}
	legacyJournalFD = -1
	if lock.legacyJournal != nil {
		legacyJournalFD = int(lock.legacyJournal.Fd())
		if err := clearCloseOnExec(legacyJournalFD); err != nil {
			return -1, -1, false, err
		}
	}
	return fenceFD, legacyJournalFD, lock.freshJournal, nil
}

func clearCloseOnExec(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return ErrUnsafe
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
		return ErrUnsafe
	}
	return nil
}

// ValidateInherited verifies that the exact stable fence descriptor belongs to
// this journal and still owns the exclusive lock. Existing-journal sessions
// must also carry the continuously locked legacy inode. Fresh sessions are
// explicitly stable-fence-only and cannot claim compatibility with an executor
// that predates the v0.1 fence contract.
func ValidateInherited(journal string, fenceFD, legacyJournalFD int, fresh bool) error {
	path, err := Path(journal)
	if err != nil || fenceFD < 3 || legacyJournalFD == fenceFD {
		return ErrInvalid
	}
	if err := validateInheritedFile(path, fenceFD, true); err != nil {
		return err
	}
	if err := unix.Flock(fenceFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return ErrNotHeld
	}
	if fresh {
		if legacyJournalFD >= 0 {
			return ErrInvalid
		}
		return nil
	}
	if legacyJournalFD < 3 {
		return ErrNotHeld
	}
	if err := validateInheritedFile(journal, legacyJournalFD, false); err != nil {
		return err
	}
	if err := unix.Flock(legacyJournalFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return ErrNotHeld
	}
	return nil
}

func validateInheritedFile(path string, fd int, requireEmpty bool) error {
	if err := checkRegular(fd, requireEmpty); err != nil {
		return err
	}
	opened, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafe
	}
	defer unix.Close(opened)
	if err := checkRegular(opened, requireEmpty); err != nil {
		return err
	}
	var inheritedStat, pathStat unix.Stat_t
	if unix.Fstat(fd, &inheritedStat) != nil || unix.Fstat(opened, &pathStat) != nil ||
		inheritedStat.Dev != pathStat.Dev || inheritedStat.Ino != pathStat.Ino {
		return ErrUnsafe
	}
	return nil
}

func checkDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 {
		return ErrUnsafe
	}
	return nil
}

func checkRegular(fd int, requireEmpty bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) ||
		requireEmpty && stat.Size != 0 {
		return ErrUnsafe
	}
	return nil
}

func canonicalAbs(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		filepath.Base(path) != "." && filepath.Base(path) != string(filepath.Separator)
}

// Close releases the live fence without deleting its stable inode.
func (lock *Lock) Close() error {
	if lock == nil {
		return nil
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if lock.closed {
		return nil
	}
	lock.closed = true
	if lock.file == nil {
		return ErrUnsafe
	}
	unlockErr := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	var legacyUnlockErr, legacyCloseErr error
	if lock.legacyJournal != nil {
		legacyUnlockErr = unix.Flock(int(lock.legacyJournal.Fd()), unix.LOCK_UN)
		legacyCloseErr = lock.legacyJournal.Close()
	}
	closeErr := lock.file.Close()
	if unlockErr != nil || closeErr != nil || legacyUnlockErr != nil || legacyCloseErr != nil {
		return ErrUnsafe
	}
	return nil
}
