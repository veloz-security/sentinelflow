package offlinefence

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRuntimeAndOfflineLocksAreMutuallyExclusive(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(directory, "replay.json")
	runtime, err := AcquireRuntime(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireOffline(journal); !errors.Is(err, ErrLocked) {
		t.Fatalf("offline fence ignored runtime owner: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	offline, err := AcquireOffline(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireRuntime(journal); !errors.Is(err, ErrLocked) {
		t.Fatalf("runtime fence ignored recovery owner: %v", err)
	}
	if err := RequireOffline(journal); err != nil {
		t.Fatalf("exclusive recovery fence not detected: %v", err)
	}
	if err := offline.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RequireOffline(journal); !errors.Is(err, ErrNotHeld) {
		t.Fatalf("released recovery fence was accepted: %v", err)
	}
}

func TestOfflineFenceRejectsActiveLegacyJournalAndUnsafeFence(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(directory, "replay.json")
	file, err := os.OpenFile(journal, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireOffline(journal); !errors.Is(err, ErrLocked) {
		t.Fatalf("active legacy journal was not fenced: %v", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	path, err := Path(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireOffline(journal); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("nonempty fence was accepted: %v", err)
	}
}

func TestInheritedFreshSessionValidatesExactStableDescriptor(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(directory, "replay.json")
	lock, err := AcquireOffline(journal)
	if err != nil {
		t.Fatal(err)
	}
	fenceFD, journalFD, fresh, err := lock.PrepareInheritance()
	if err != nil || !fresh || journalFD != -1 {
		t.Fatalf("inheritance = %d/%d/%v err=%v", fenceFD, journalFD, fresh, err)
	}
	if err := ValidateInherited(journal, fenceFD, journalFD, fresh); err != nil {
		t.Fatalf("exact inherited fence rejected: %v", err)
	}
	other, err := os.OpenFile(filepath.Join(directory, "other"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := ValidateInherited(journal, int(other.Fd()), -1, true); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("wrong inherited inode accepted: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInherited(journal, fenceFD, journalFD, fresh); err == nil {
		t.Fatal("closed inherited fence descriptor accepted")
	}
}

func TestExistingJournalFlockIsHeldForWholeOfflineSession(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(directory, "replay.json")
	if err := os.WriteFile(journal, []byte("opaque"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireOffline(journal)
	if err != nil {
		t.Fatal(err)
	}
	fenceFD, journalFD, fresh, err := lock.PrepareInheritance()
	if err != nil || fresh || journalFD < 3 {
		t.Fatalf("inheritance = %d/%d/%v err=%v", fenceFD, journalFD, fresh, err)
	}
	if err := ValidateInherited(journal, fenceFD, journalFD, fresh); err != nil {
		t.Fatalf("existing journal inheritance rejected: %v", err)
	}
	competitor, err := os.Open(journal)
	if err != nil {
		t.Fatal(err)
	}
	defer competitor.Close()
	if err := unix.Flock(int(competitor.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("legacy journal lock was not retained: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(competitor.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("legacy journal lock not released: %v", err)
	}
	_ = unix.Flock(int(competitor.Fd()), unix.LOCK_UN)
}
