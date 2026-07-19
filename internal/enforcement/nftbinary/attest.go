// Package nftbinary attests the fixed nft executable before validation work
// starts. It has no mutation or executor authority.
package nftbinary

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

const (
	MaxBinaryBytes = 64 << 20
	verifyTimeout  = 2 * time.Second
)

var (
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	expectedVersionPattern = regexp.MustCompile(`^nftables v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
	observedVersionPattern = regexp.MustCompile(`^nftables v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?)(?: \([ -~]{1,128}\))?\n?$`)
)

type ErrorCode string

const (
	ErrorInvalidInput       ErrorCode = "invalid_input"
	ErrorPathUnsafe         ErrorCode = "nft_binary_path_unsafe"
	ErrorFileUnsafe         ErrorCode = "nft_binary_file_unsafe"
	ErrorDigestMismatch     ErrorCode = "nft_binary_digest_mismatch"
	ErrorVersionUnavailable ErrorCode = "nft_version_unavailable"
	ErrorVersionMismatch    ErrorCode = "nft_version_mismatch"
	ErrorCancelled          ErrorCode = "attestation_cancelled"
	ErrorTimeout            ErrorCode = "attestation_timeout"
)

// Error exposes only a stable classification. Filesystem paths, process
// output, and underlying errors are deliberately omitted.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "nft binary attestation failed"
	}
	return "nft binary attestation failed: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }

// Evidence is safe to bind into a validation snapshot. It contains no file
// metadata or process output.
type Evidence struct {
	BinaryDigest string
	Version      string
}

// Verify attests the fixed binary twice around a bounded, fixed --version
// invocation. The second pass detects replacement during startup.
func Verify(
	ctx context.Context,
	runner nftcheck.ProcessRunner,
	expectedDigest string,
	expectedVersion string,
) (Evidence, error) {
	if ctx == nil || runner == nil || !digestPattern.MatchString(expectedDigest) ||
		!expectedVersionPattern.MatchString(expectedVersion) {
		return Evidence{}, reject(ErrorInvalidInput)
	}
	before, err := inspectFile(nftcheck.FixedNFTBinaryPath, expectedDigest)
	if err != nil {
		return Evidence{}, err
	}
	version, err := verifyVersion(ctx, runner, expectedVersion)
	if err != nil {
		return Evidence{}, err
	}
	after, err := inspectFile(nftcheck.FixedNFTBinaryPath, expectedDigest)
	if err != nil || after != before {
		return Evidence{}, reject(ErrorDigestMismatch)
	}
	return Evidence{BinaryDigest: before, Version: version}, nil
}

func inspectFile(path, expectedDigest string) (string, error) {
	if path == "" || !digestPattern.MatchString(expectedDigest) {
		return "", reject(ErrorInvalidInput)
	}
	before, err := os.Lstat(path)
	if err != nil || !safeFileInfo(before) {
		return "", reject(ErrorFileUnsafe)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", reject(ErrorPathUnsafe)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return "", reject(ErrorFileUnsafe)
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil || !safeFileInfo(opened) || !os.SameFile(before, opened) {
		return "", reject(ErrorFileUnsafe)
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, MaxBinaryBytes+1))
	if err != nil || count < 1 || count > MaxBinaryBytes {
		return "", reject(ErrorFileUnsafe)
	}
	after, err := os.Lstat(path)
	if err != nil || !safeFileInfo(after) || !os.SameFile(opened, after) {
		return "", reject(ErrorPathUnsafe)
	}
	digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if digest != expectedDigest {
		return "", reject(ErrorDigestMismatch)
	}
	return digest, nil
}

func safeFileInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0
}

func verifyVersion(ctx context.Context, runner nftcheck.ProcessRunner, expected string) (string, error) {
	if ctx == nil || runner == nil || !expectedVersionPattern.MatchString(expected) {
		return "", reject(ErrorInvalidInput)
	}
	checkCtx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	result, runErr := runner.Version(checkCtx)
	if err := contextError(checkCtx); err != nil {
		return "", err
	}
	if runErr != nil || result.Path != nftcheck.FixedNFTBinaryPath ||
		len(result.Arguments) != 1 || result.Arguments[0] != "--version" ||
		result.ExitStatus != 0 || result.OutputOverflow || len(result.Stderr) != 0 ||
		len(result.Stdout) == 0 || len(result.Stdout) > nftcheck.MaxProcessOutput || !utf8.Valid(result.Stdout) {
		return "", reject(ErrorVersionUnavailable)
	}
	matches := observedVersionPattern.FindSubmatch(result.Stdout)
	if len(matches) != 2 {
		return "", reject(ErrorVersionUnavailable)
	}
	version := "nftables v" + string(matches[1])
	if version != expected {
		return "", reject(ErrorVersionMismatch)
	}
	return version, nil
}

func contextError(ctx context.Context) error {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return reject(ErrorTimeout)
	case errors.Is(ctx.Err(), context.Canceled):
		return reject(ErrorCancelled)
	default:
		return nil
	}
}
