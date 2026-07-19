package nftbinary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

func TestInspectFileAcceptsOnlyPinnedRegularImmutableBytes(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "nft")
	content := []byte("synthetic nft executable bytes")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	expected := testDigest(content)
	got, err := inspectFile(path, expected)
	if err != nil || got != expected {
		t.Fatalf("digest=%q err=%v", got, err)
	}
	if _, err := inspectFile(path, testDigest([]byte("different"))); !hasCode(err, ErrorDigestMismatch) {
		t.Fatalf("digest mismatch error=%v", err)
	}
	if err := os.Chmod(path, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectFile(path, expected); !hasCode(err, ErrorFileUnsafe) {
		t.Fatalf("writable file error=%v", err)
	}
}

func TestInspectFileRejectsSymlinkAndEmptyFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("target"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectFile(link, testDigest([]byte("target"))); !hasCode(err, ErrorFileUnsafe) {
		t.Fatalf("symlink error=%v", err)
	}
	empty := filepath.Join(directory, "empty")
	if err := os.WriteFile(empty, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectFile(empty, testDigest(nil)); !hasCode(err, ErrorFileUnsafe) {
		t.Fatalf("empty error=%v", err)
	}
}

func TestVerifyVersionPinsInvocationAndNormalizedValue(t *testing.T) {
	t.Parallel()
	runner := versionRunner{result: nftcheck.ProcessResult{
		Path: nftcheck.FixedNFTBinaryPath, Arguments: []string{"--version"},
		ExitStatus: 0, Stdout: []byte("nftables v1.1.1 (Synthetic)\n"),
	}}
	got, err := verifyVersion(context.Background(), runner, "nftables v1.1.1")
	if err != nil || got != "nftables v1.1.1" {
		t.Fatalf("version=%q err=%v", got, err)
	}

	variants := []versionRunner{
		{result: nftcheck.ProcessResult{Path: "/tmp/nft", Arguments: []string{"--version"}, ExitStatus: 0, Stdout: []byte("nftables v1.1.1\n")}},
		{result: nftcheck.ProcessResult{Path: nftcheck.FixedNFTBinaryPath, Arguments: []string{"list", "ruleset"}, ExitStatus: 0, Stdout: []byte("nftables v1.1.1\n")}},
		{result: nftcheck.ProcessResult{Path: nftcheck.FixedNFTBinaryPath, Arguments: []string{"--version"}, ExitStatus: 0, Stdout: []byte("nftables v1.1.1\nsecret")}},
		{result: nftcheck.ProcessResult{Path: nftcheck.FixedNFTBinaryPath, Arguments: []string{"--version"}, ExitStatus: 0, Stdout: []byte("nftables v1.1.2\n")}},
	}
	for index, variant := range variants {
		_, err := verifyVersion(context.Background(), variant, "nftables v1.1.1")
		if err == nil {
			t.Fatalf("variant %d accepted", index)
		}
	}
}

func TestAttestationErrorsAreTypedAndRedacted(t *testing.T) {
	t.Parallel()
	secret := "secret-output-must-not-leak"
	runner := versionRunner{err: errors.New(secret), result: nftcheck.ProcessResult{
		Path: nftcheck.FixedNFTBinaryPath, Arguments: []string{"--version"}, ExitStatus: -1,
		Stderr: []byte(secret),
	}}
	_, err := verifyVersion(context.Background(), runner, "nftables v1.1.1")
	if !hasCode(err, ErrorVersionUnavailable) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = verifyVersion(cancelled, runner, "nftables v1.1.1")
	if !hasCode(err, ErrorCancelled) {
		t.Fatalf("cancelled error=%v", err)
	}
}

func TestVerifyVersionFailsClosedOnDeadlineAndMismatch(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	blocking := versionRunner{run: func(ctx context.Context) (nftcheck.ProcessResult, error) {
		<-ctx.Done()
		return nftcheck.ProcessResult{}, ctx.Err()
	}}
	if _, err := verifyVersion(ctx, blocking, "nftables v1.1.1"); !hasCode(err, ErrorTimeout) {
		t.Fatalf("deadline error=%v", err)
	}
	mismatch := versionRunner{result: nftcheck.ProcessResult{
		Path: nftcheck.FixedNFTBinaryPath, Arguments: []string{"--version"},
		ExitStatus: 0, Stdout: []byte("nftables v1.1.2\n"),
	}}
	if _, err := verifyVersion(context.Background(), mismatch, "nftables v1.1.1"); !hasCode(err, ErrorVersionMismatch) {
		t.Fatalf("version mismatch error=%v", err)
	}
}

type versionRunner struct {
	result nftcheck.ProcessResult
	err    error
	run    func(context.Context) (nftcheck.ProcessResult, error)
}

func (r versionRunner) Version(ctx context.Context) (nftcheck.ProcessResult, error) {
	if r.run != nil {
		return r.run(ctx)
	}
	return r.result, r.err
}

func (versionRunner) Check(context.Context, []byte) (nftcheck.ProcessResult, error) {
	panic("unexpected check invocation")
}

func testDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hasCode(err error, code ErrorCode) bool {
	var typed *Error
	return errors.As(err, &typed) && typed.Code == code
}
