package nftcheck

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"time"
)

const (
	GateVersion = "nft-syntax-check-v1"

	// FixedNFTBinaryPath is deliberately absolute. Production code never uses
	// PATH, an environment-provided binary, or caller-provided arguments.
	FixedNFTBinaryPath = "/usr/sbin/nft"

	PinnedBaseContractDigest = "sha256:2d6476f6297f9b135032934bc557110541bae7eb2fe16fe29be70d20d0f4c488"

	MaxCandidateBytes    = 256
	MaxBaseContractBytes = 16 * 1024
	MaxProcessOutput     = 8 * 1024

	GateTimeout = 2 * time.Second
)

var (
	versionArguments = []string{"--version"}
	checkArguments   = []string{"--check", "-f", "-"}

	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	expectedVersionPattern = regexp.MustCompile(`^nftables v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
	observedVersionPattern = regexp.MustCompile(`^nftables v([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?)(?: \([ -~]{1,128}\))?\n?$`)
)

type ErrorCode string

const (
	ErrorInvalidInput        ErrorCode = "invalid_input"
	ErrorCandidateInvalid    ErrorCode = "canonical_candidate_invalid"
	ErrorCandidateDigest     ErrorCode = "canonical_digest_invalid"
	ErrorCandidateMismatch   ErrorCode = "canonical_digest_mismatch"
	ErrorBaseDigest          ErrorCode = "base_contract_digest_invalid"
	ErrorBaseContract        ErrorCode = "base_contract_mismatch"
	ErrorRunnerUnavailable   ErrorCode = "nft_runner_unavailable"
	ErrorInvocationMismatch  ErrorCode = "nft_invocation_mismatch"
	ErrorVersionCommand      ErrorCode = "nft_version_command_failed"
	ErrorVersionInvalid      ErrorCode = "nft_version_invalid"
	ErrorVersionMismatch     ErrorCode = "nft_version_mismatch"
	ErrorOutputLimit         ErrorCode = "nft_output_limit_exceeded"
	ErrorSyntaxRejected      ErrorCode = "nft_syntax_rejected"
	ErrorCancelled           ErrorCode = "nft_check_cancelled"
	ErrorTimeout             ErrorCode = "nft_check_timeout"
	ErrorUnsupportedPlatform ErrorCode = "unsupported_platform"
)

// Error deliberately contains only a stable classification. Process errors
// and raw nft output are never included in logs through Error().
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "nftables syntax check rejected"
	}
	return "nftables syntax check rejected: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }

// Input binds the two byte sequences to independently supplied digests. The
// base digest itself must equal PinnedBaseContractDigest; callers cannot choose
// a different owned schema by supplying a matching digest of their own.
type Input struct {
	CanonicalBytes     []byte
	CanonicalDigest    string
	BaseContract       []byte
	BaseContractDigest string
}

// ProcessResult is the bounded runner attestation. Stdout and Stderr exist only
// in memory long enough to calculate sanitized evidence digests and are never
// copied into Evidence or Error.
type ProcessResult struct {
	Path           string
	Arguments      []string
	ExitStatus     int
	Stdout         []byte
	Stderr         []byte
	OutputOverflow bool
}

// ProcessRunner deliberately exposes operations rather than arbitrary argv.
// The production implementation maps these methods to two fixed invocations.
type ProcessRunner interface {
	Version(context.Context) (ProcessResult, error)
	Check(context.Context, []byte) (ProcessResult, error)
}

// Evidence is safe to persist. It contains no raw process output, candidate
// bytes, or base-contract bytes. Exit statuses default to -1 when a subprocess
// was not reached.
type Evidence struct {
	GateVersion            string
	CanonicalDigest        string
	BaseContractDigest     string
	NFTBinaryPath          string
	VersionArguments       [1]string
	SyntaxArguments        [3]string
	NFTVersion             string
	VersionExitStatus      int
	VersionOutputDigest    string
	VersionOutputByteCount uint32
	SyntaxExitStatus       int
	SyntaxOutputDigest     string
	SyntaxOutputByteCount  uint32
}

func initialEvidence() Evidence {
	return Evidence{
		GateVersion:       GateVersion,
		NFTBinaryPath:     FixedNFTBinaryPath,
		VersionArguments:  [1]string{versionArguments[0]},
		SyntaxArguments:   [3]string{checkArguments[0], checkArguments[1], checkArguments[2]},
		VersionExitStatus: -1,
		SyntaxExitStatus:  -1,
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// outputDigest commits stdout and stderr separately using length prefixes so
// stream-boundary ambiguity cannot produce the same evidence digest.
func outputDigest(stdout, stderr []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("sentinelflow-nft-process-output-v1\x00"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(stdout)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(stdout)
	binary.BigEndian.PutUint64(size[:], uint64(len(stderr)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(stderr)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func sameArguments(got, expected []string) bool {
	if len(got) != len(expected) {
		return false
	}
	for index := range expected {
		if got[index] != expected[index] {
			return false
		}
	}
	return true
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}
