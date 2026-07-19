package nftvalidator

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

const maxSocketPathBytes = 100

type Client struct {
	socketPath           string
	timeout              time.Duration
	expectedBinaryDigest string
	expectedNFTVersion   string
	random               io.Reader
	afterBoundaryInspect func()
}

func NewClient(socketPath string, timeout time.Duration, expectedBinaryDigest, expectedNFTVersion string) (*Client, error) {
	clean := filepath.Clean(socketPath)
	if socketPath == "" || clean != socketPath || !filepath.IsAbs(clean) || len(clean) > maxSocketPathBytes ||
		timeout != ipc.MaxExchangeTimeout || !digestPattern.MatchString(expectedBinaryDigest) ||
		!validNFTVersion(expectedNFTVersion) {
		return nil, reject(ErrorInvalidConfiguration)
	}
	return &Client{
		socketPath: clean, timeout: timeout, expectedBinaryDigest: expectedBinaryDigest,
		expectedNFTVersion: expectedNFTVersion, random: rand.Reader,
	}, nil
}

// Check implements validationworker.SyntaxChecker without invoking nftables in
// the caller. Base bytes are verified against the frozen digest and are never
// transmitted; the validator uses its own startup-loaded immutable copy.
func (c *Client) Check(ctx context.Context, input nftcheck.Input) (nftcheck.Evidence, error) {
	evidence := initialEvidence(input.CanonicalDigest)
	if c == nil || ctx == nil || c.random == nil || c.timeout != ipc.MaxExchangeTimeout {
		return evidence, reject(ErrorInvalidConfiguration)
	}
	if err := ctx.Err(); err != nil {
		return evidence, &nftcheck.Error{Code: nftcheck.ErrorCancelled}
	}
	if code := validateClientInput(input); code != "" {
		return evidence, &nftcheck.Error{Code: code}
	}
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return evidence, reject(ErrorNonceUnavailable)
	}
	requestPayload, err := encodeRequest(input.CanonicalBytes, input.CanonicalDigest, nonce)
	if err != nil {
		return evidence, reject(ErrorRequestInvalid)
	}
	expectedRequestDigest := requestDigest(requestPayload)

	before, err := inspectSocketBoundary(c.socketPath)
	if err != nil {
		return evidence, err
	}
	if c.afterBoundaryInspect != nil {
		c.afterBoundaryInspect()
	}
	dialer := net.Dialer{Timeout: c.timeout}
	raw, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return evidence, transportError(ctx, err)
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return evidence, reject(ErrorTransport)
	}
	after, err := inspectSocketBoundary(c.socketPath)
	if err != nil || before != after {
		_ = connection.Close()
		return evidence, reject(ErrorSocketBoundary)
	}
	responsePayload, err := ipc.ClientExchange(ctx, connection, requestPayload, c.timeout)
	if err != nil {
		return evidence, transportError(ctx, err)
	}
	responseValue, err := decodeResponse(responsePayload)
	if err != nil || responseValue.requestDigest != expectedRequestDigest ||
		responseValue.baseContractDigest != nftcheck.PinnedBaseContractDigest ||
		responseValue.nftBinaryDigest != c.expectedBinaryDigest ||
		responseValue.nftBinaryPath != nftcheck.FixedNFTBinaryPath ||
		responseValue.nftVersion != c.expectedNFTVersion ||
		responseValue.evidence.CanonicalDigest != input.CanonicalDigest ||
		responseValue.evidence.BaseContractDigest != nftcheck.PinnedBaseContractDigest {
		return evidence, reject(ErrorResponseInvalid)
	}
	evidence = responseValue.evidence
	if responseValue.passed {
		return evidence, nil
	}
	if responseValue.errorCode == string(ErrorRequestReplayed) {
		return evidence, reject(ErrorRequestReplayed)
	}
	if responseValue.errorCode == string(ErrorReplayCacheFull) {
		return evidence, reject(ErrorReplayCacheFull)
	}
	return evidence, &nftcheck.Error{Code: nftcheck.ErrorCode(responseValue.errorCode)}
}

func validateClientInput(input nftcheck.Input) nftcheck.ErrorCode {
	if !validCandidateEnvelope(input.CanonicalBytes) {
		return nftcheck.ErrorCandidateInvalid
	}
	if !digestPattern.MatchString(input.CanonicalDigest) {
		return nftcheck.ErrorCandidateDigest
	}
	if digestBytes(input.CanonicalBytes) != input.CanonicalDigest {
		return nftcheck.ErrorCandidateMismatch
	}
	if input.BaseContractDigest != nftcheck.PinnedBaseContractDigest {
		return nftcheck.ErrorBaseDigest
	}
	if len(input.BaseContract) == 0 || len(input.BaseContract) > nftcheck.MaxBaseContractBytes ||
		digestBytes(input.BaseContract) != nftcheck.PinnedBaseContractDigest {
		return nftcheck.ErrorBaseContract
	}
	return ""
}

func transportError(ctx context.Context, err error) error {
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &nftcheck.Error{Code: nftcheck.ErrorTimeout}
	}
	if ctx == nil || errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return &nftcheck.Error{Code: nftcheck.ErrorCancelled}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &nftcheck.Error{Code: nftcheck.ErrorTimeout}
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return &nftcheck.Error{Code: nftcheck.ErrorTimeout}
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return &nftcheck.Error{Code: nftcheck.ErrorTimeout}
	}
	return reject(ErrorTransport)
}

type socketIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
}

func inspectSocketBoundary(path string) (socketIdentity, error) {
	clean := filepath.Clean(path)
	if path == "" || clean != path || !filepath.IsAbs(clean) || len(clean) > maxSocketPathBytes {
		return socketIdentity{}, reject(ErrorSocketBoundary)
	}
	parentInfo, err := os.Lstat(filepath.Dir(clean))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentInfo.Mode().Perm()&0o027 != 0 || parentInfo.Mode().Perm()&0o300 != 0o300 {
		return socketIdentity{}, reject(ErrorSocketBoundary)
	}
	socketInfo, err := os.Lstat(clean)
	if err != nil || socketInfo.Mode()&os.ModeSymlink != 0 ||
		socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != SocketMode {
		return socketIdentity{}, reject(ErrorSocketBoundary)
	}
	parentStat, parentOK := parentInfo.Sys().(*syscall.Stat_t)
	socketStat, socketOK := socketInfo.Sys().(*syscall.Stat_t)
	if !parentOK || !socketOK || socketStat.Uid != parentStat.Uid ||
		(socketStat.Gid != parentStat.Gid && socketStat.Gid != uint32(os.Getegid())) {
		return socketIdentity{}, reject(ErrorSocketBoundary)
	}
	return socketIdentity{
		device: uint64(socketStat.Dev), inode: uint64(socketStat.Ino),
		uid: socketStat.Uid, gid: socketStat.Gid,
	}, nil
}

func (*Client) String() string     { return "nftvalidator.Client{socket:[REDACTED]}" }
func (c *Client) GoString() string { return c.String() }
