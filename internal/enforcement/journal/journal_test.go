package journal

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/recoverybundle/offlinefence"
)

func TestLifecycleExactRetryAndRestart(t *testing.T) {
	f := newFixture(t)
	path := journalPath(t)
	j, err := Open(f.options(path))
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := j.Begin(f.signed, f.received, f.deadline)
	if err != nil || outcome.State() != StateNewStarted {
		t.Fatalf("begin failed: state=%s err=%v", outcome.State(), err)
	}
	permit, ok := outcome.Permit()
	if !ok {
		t.Fatal("new start did not return permit")
	}
	executable, err := permit.TakeAddAt(f.received.Add(100 * time.Millisecond))
	if err != nil || executable.TTLSeconds() != 1800 {
		t.Fatalf("permit failed: ttl=%d err=%v", executable.TTLSeconds(), err)
	}
	if _, err := permit.TakeAddAt(f.received.Add(200 * time.Millisecond)); err == nil {
		t.Fatal("permit reused")
	} else {
		assertCode(t, err, ErrorPermitUsed)
	}
	if _, err := permit.TakeRevokeAt(f.received); err == nil {
		t.Fatal("add permit released revoke")
	}

	signedResult := f.signedResult(t, outcome.Started().Sequence, capability.ClassificationApplied, f.received.Add(100*time.Millisecond), func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return permit.SignResult(f.resultSigner, checked)
	})
	terminal, appended, err := j.Complete(signedResult)
	if err != nil || !appended || terminal.StartedSequence() != outcome.Started().Sequence || terminal.Sequence() != 2 {
		t.Fatalf("terminal failed: appended=%v terminal=%+v err=%v", appended, terminal, err)
	}
	if _, appended, err := j.Complete(signedResult); err != nil || appended {
		t.Fatalf("exact terminal retry was not idempotent: appended=%v err=%v", appended, err)
	}
	lookup, err := j.Lookup(f.signed)
	if err != nil || lookup.State() != StateTerminal {
		t.Fatalf("terminal lookup failed: state=%s err=%v", lookup.State(), err)
	}
	if _, ok := lookup.Permit(); ok {
		t.Fatal("terminal replay exposed permit")
	}
	returned, _ := lookup.Terminal()
	bytesCopy := returned.SignedResult().CanonicalBytes()
	bytesCopy[0] = 'X'
	again, _, _ := j.Complete(signedResult)
	if again.SignedResult().CanonicalBytes()[0] != '{' {
		t.Fatal("terminal getter aliases journal memory")
	}
	before := readJournal(t, path)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(f.options(path))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	late, err := reopened.Begin(f.signed, f.verified.Value().ExpiresAt.Add(time.Hour), f.verified.Value().ExpiresAt.Add(time.Hour+time.Second))
	if err != nil || late.State() != StateTerminal {
		t.Fatalf("lookup did not precede freshness on retry: state=%s err=%v", late.State(), err)
	}
	if _, err := reopened.Begin(f.alternate(t), f.received, f.deadline); err == nil {
		t.Fatal("conflicting replay accepted")
	} else {
		assertCode(t, err, ErrorConflict)
	}
	if !bytes.Equal(before, readJournal(t, path)) {
		t.Fatal("restart or exact retry rewrote journal")
	}
}

func TestStartedOnlyRecoveryCannotReexecute(t *testing.T) {
	f := newFixture(t)
	path := journalPath(t)
	j, err := Open(f.options(path))
	if err != nil {
		t.Fatal(err)
	}
	first, err := j.Begin(f.signed, f.received, f.deadline)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(f.options(path))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retry, err := reopened.Begin(f.signed, f.received.Add(time.Hour), f.deadline.Add(time.Hour))
	if err != nil || retry.State() != StateStartedOnly {
		t.Fatalf("started recovery failed: state=%s err=%v", retry.State(), err)
	}
	if _, ok := retry.Permit(); ok {
		t.Fatal("started-only retry exposed executable permit")
	}
	recovery, ok := retry.Recovery()
	if !ok || recovery.Value().CapabilityID != f.verified.Value().CapabilityID {
		t.Fatal("started-only retry omitted recovery binding")
	}
	if ttl, ok := recovery.ExpectedAddTTLSeconds(); !ok || ttl != 1800 {
		t.Fatalf("started-only recovery lost verified TTL bound: ttl=%d ok=%v", ttl, ok)
	}
	applied := f.signedResult(t, first.Started().Sequence, capability.ClassificationApplied, f.received, func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return f.resultSigner.SignFor(f.verified, checked)
	})
	appliedChecked, err := capability.ParseCanonicalResult(applied.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recovery.SignResult(f.resultSigner, appliedChecked); err == nil {
		t.Fatal("recovery binding signed a fresh mutation outcome")
	} else {
		assertCode(t, err, ErrorOperation)
	}
	recoveredAt := f.verified.Value().ExpiresAt.Add(time.Minute)
	result := f.signedResult(t, first.Started().Sequence, capability.ClassificationRecoveredActive, recoveredAt, func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return recovery.SignResult(f.resultSigner, checked)
	})
	if _, appended, err := reopened.Complete(result); err != nil || !appended {
		t.Fatalf("recovery result failed: appended=%v err=%v", appended, err)
	}
}

func TestConcurrentBeginPermitCompleteAndLookup(t *testing.T) {
	f := newFixture(t)
	j, err := Open(f.options(journalPath(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()

	const workers = 48
	var newCount atomic.Int32
	var startedCount atomic.Int32
	var permit *Permit
	var permitMu sync.Mutex
	errorsChannel := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			outcome, err := j.Begin(f.signed, f.received, f.deadline)
			if err != nil {
				errorsChannel <- err
				return
			}
			switch outcome.State() {
			case StateNewStarted:
				newCount.Add(1)
				candidate, _ := outcome.Permit()
				permitMu.Lock()
				permit = candidate
				permitMu.Unlock()
			case StateStartedOnly:
				startedCount.Add(1)
			default:
				errorsChannel <- fmt.Errorf("unexpected state %s", outcome.State())
			}
		}()
	}
	group.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
	if newCount.Load() != 1 || startedCount.Load() != workers-1 || permit == nil {
		t.Fatalf("unexpected claims new=%d retries=%d", newCount.Load(), startedCount.Load())
	}

	var takeSuccess atomic.Int32
	group = sync.WaitGroup{}
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := permit.TakeAddAt(f.received.Add(time.Millisecond)); err == nil {
				takeSuccess.Add(1)
			}
		}()
	}
	group.Wait()
	if takeSuccess.Load() != 1 {
		t.Fatalf("permit succeeded %d times", takeSuccess.Load())
	}

	result := f.signedResult(t, 1, capability.ClassificationApplied, f.received.Add(time.Millisecond), func(checked capability.CheckedResult) (capability.SignedResult, error) {
		return permit.SignResult(f.resultSigner, checked)
	})
	var appendCount atomic.Int32
	errorsChannel = make(chan error, workers)
	group = sync.WaitGroup{}
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			_, appended, err := j.Complete(result)
			if err != nil {
				errorsChannel <- err
				return
			}
			if appended {
				appendCount.Add(1)
			}
			lookup, err := j.Lookup(f.signed)
			if err != nil || lookup.State() != StateTerminal {
				errorsChannel <- fmt.Errorf("lookup state=%s err=%v", lookup.State(), err)
			}
		}()
	}
	group.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
	if appendCount.Load() != 1 {
		t.Fatalf("terminal appended %d times", appendCount.Load())
	}
}

func TestFreshnessDeadlineAndOperationFailures(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name     string
		received time.Time
		deadline time.Time
		code     ErrorCode
	}{
		{"unaligned", f.received.Add(time.Nanosecond), f.deadline, ErrorTime},
		{"zero window", f.received, f.received, ErrorTime},
		{"long window", f.received, f.received.Add(MaxDeadline + time.Millisecond), ErrorTime},
		{"deadline after expiry", f.verified.Value().ExpiresAt.Add(-time.Second), f.verified.Value().ExpiresAt.Add(time.Millisecond), ErrorTime},
		{"expired", f.verified.Value().ExpiresAt, f.verified.Value().ExpiresAt.Add(time.Millisecond), ErrorTime},
		{"too early", f.verified.Value().NotBefore.Add(-time.Millisecond), f.verified.Value().NotBefore.Add(time.Second), ErrorFreshness},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			j, err := Open(f.options(journalPath(t)))
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			_, err = j.Begin(f.signed, test.received, test.deadline)
			if err == nil {
				t.Fatal("invalid timing accepted")
			}
			assertCode(t, err, test.code)
		})
	}
}

func TestFileSafetyLockSizeAndExternalMutation(t *testing.T) {
	f := newFixture(t)
	t.Run("mode", func(t *testing.T) {
		path := journalPath(t)
		writeJournal(t, path, nil)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Open(f.options(path))
		assertCode(t, err, ErrorUnsafeFile)
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		writeJournal(t, target, nil)
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		_, err := Open(f.options(link))
		assertCode(t, err, ErrorUnsafeFile)
	})
	t.Run("hardlink", func(t *testing.T) {
		path := journalPath(t)
		writeJournal(t, path, nil)
		if err := os.Link(path, path+".other"); err != nil {
			t.Fatal(err)
		}
		_, err := Open(f.options(path))
		assertCode(t, err, ErrorUnsafeFile)
	})
	t.Run("unsafe directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dir, 0o700)
		_, err := Open(f.options(filepath.Join(dir, "journal")))
		assertCode(t, err, ErrorUnsafeDirectory)
	})
	t.Run("exclusive lock", func(t *testing.T) {
		path := journalPath(t)
		first, err := Open(f.options(path))
		if err != nil {
			t.Fatal(err)
		}
		defer first.Close()
		_, err = Open(f.options(path))
		assertCode(t, err, ErrorLocked)
	})
	t.Run("recovery fence blocks startup and releases", func(t *testing.T) {
		path := journalPath(t)
		offline, err := offlinefence.AcquireOffline(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Open(f.options(path))
		assertCode(t, err, ErrorLocked)
		if err := offline.Close(); err != nil {
			t.Fatal(err)
		}
		opened, err := Open(f.options(path))
		if err != nil {
			t.Fatalf("executor did not recover after fence owner exit: %v", err)
		}
		if err := opened.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("maximum", func(t *testing.T) {
		path := journalPath(t)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(MaxJournalBytes + 1); err != nil {
			t.Fatal(err)
		}
		file.Close()
		_, err = Open(f.options(path))
		assertCode(t, err, ErrorTooLarge)
	})
	t.Run("external append poisons", func(t *testing.T) {
		path := journalPath(t)
		j, err := Open(f.options(path))
		if err != nil {
			t.Fatal(err)
		}
		defer j.Close()
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = file.Write([]byte{0})
		file.Close()
		_, err = j.Begin(f.signed, f.received, f.deadline)
		assertCode(t, err, ErrorUnsafeFile)
		_, err = j.Lookup(f.signed)
		assertCode(t, err, ErrorUnhealthy)
	})
}

func TestRedactedFormattingAndInvalidSetup(t *testing.T) {
	f := newFixture(t)
	if _, err := Open(Options{Path: "relative", CapabilityVerifier: f.capVerifier, ResultVerifier: f.resultVerifier}); err == nil {
		t.Fatal("relative path accepted")
	}
	if _, err := Open(Options{Path: journalPath(t)}); err == nil {
		t.Fatal("missing verifiers accepted")
	}
	j, err := Open(f.options(journalPath(t)))
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := j.Begin(f.signed, f.received, f.deadline)
	if err != nil {
		t.Fatal(err)
	}
	permit, _ := outcome.Permit()
	for _, value := range []any{j, outcome, permit} {
		formatted := fmt.Sprintf("%#v", value)
		if strings.Contains(formatted, "add element") || strings.Contains(formatted, encodeBytes(f.signed.Signature())) {
			t.Fatalf("format leaked sensitive bytes: %s", formatted)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Lookup(f.signed); err == nil {
		t.Fatal("closed journal accepted lookup")
	} else {
		assertCode(t, err, ErrorUnhealthy)
	}
}
