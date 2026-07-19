package journal

import (
	"errors"
	"testing"
)

var errInjectedSync = errors.New("injected sync failure")

type failingSyncer struct {
	failFile       bool
	failDirectory  bool
	fileCalls      int
	directoryCalls int
}

func (s *failingSyncer) SyncFile(target FileSyncTarget) error {
	s.fileCalls++
	if err := target.Sync(); err != nil {
		return err
	}
	if s.failFile {
		return errInjectedSync
	}
	return nil
}

func (s *failingSyncer) SyncDirectory(target FileSyncTarget) error {
	s.directoryCalls++
	if err := target.Sync(); err != nil {
		return err
	}
	if s.failDirectory {
		return errInjectedSync
	}
	return nil
}

func TestFsyncFailuresPoisonUntilVerifiedRestart(t *testing.T) {
	f := newFixture(t)
	for _, test := range []struct {
		name          string
		failFile      bool
		failDirectory bool
	}{
		{"file", true, false},
		{"directory", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := journalPath(t)
			initial, err := Open(f.options(path))
			if err != nil {
				t.Fatal(err)
			}
			initial.Close()
			syncer := &failingSyncer{failFile: test.failFile, failDirectory: test.failDirectory}
			options := f.options(path)
			options.Syncer = syncer
			j, err := Open(options)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := j.Begin(f.signed, f.received, f.deadline); err == nil {
				t.Fatal("injected sync failure accepted")
			} else {
				assertCode(t, err, ErrorSync)
			}
			if _, err := j.Lookup(f.signed); err == nil {
				t.Fatal("poisoned journal remained usable")
			} else {
				assertCode(t, err, ErrorUnhealthy)
			}
			j.Close()
			if syncer.fileCalls != 1 || (!test.failFile && syncer.directoryCalls != 1) || (test.failFile && syncer.directoryCalls != 0) {
				t.Fatalf("unexpected barriers file=%d directory=%d", syncer.fileCalls, syncer.directoryCalls)
			}

			reopened, err := Open(f.options(path))
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			outcome, err := reopened.Lookup(f.signed)
			if err != nil || outcome.State() != StateStartedOnly {
				t.Fatalf("restart did not recover durable started record: state=%s err=%v", outcome.State(), err)
			}
		})
	}
}

func TestCreationFsyncFailureFailsOpen(t *testing.T) {
	f := newFixture(t)
	for _, syncer := range []*failingSyncer{{failFile: true}, {failDirectory: true}} {
		path := journalPath(t)
		options := f.options(path)
		options.Syncer = syncer
		if opened, err := Open(options); err == nil {
			opened.Close()
			t.Fatal("creation sync failure accepted")
		} else {
			assertCode(t, err, ErrorSync)
		}
	}
}
