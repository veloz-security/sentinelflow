package dispatchruntime

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
)

type ExchangeClient interface {
	Exchange(context.Context, capability.SignedCapability) (capability.SignedResult, error)
}

// RecoveryExchangeClient is deliberately separate from ordinary dispatch.
// Runtime may use it only for an already-persisted exact capability while its
// database lease remains live. The executor remains journal-first: terminal is
// replayed, started-only is inspected, and unseen expired authority is rejected
// before Journal.Begin can create a permit.
type RecoveryExchangeClient interface {
	ExchangeRecovery(context.Context, capability.SignedCapability) (capability.SignedResult, error)
}

type UDSClient struct {
	socketPath  string
	timeout     time.Duration
	resultKeyID string
	executorID  string
}

func (*UDSClient) String() string     { return "dispatchruntime.UDSClient{socket:[REDACTED]}" }
func (c *UDSClient) GoString() string { return c.String() }

func NewUDSClient(socketPath string, timeout time.Duration, resultKeyID, executorID string) (*UDSClient, error) {
	clean := filepath.Clean(socketPath)
	if socketPath == "" || clean != socketPath || !filepath.IsAbs(clean) ||
		timeout != ipc.MaxExchangeTimeout || resultKeyID == "" || executorID == "" {
		return nil, ErrInvalidConfiguration
	}
	return &UDSClient{
		socketPath: clean, timeout: timeout, resultKeyID: resultKeyID, executorID: executorID,
	}, nil
}

func (c *UDSClient) Exchange(
	ctx context.Context,
	signed capability.SignedCapability,
) (capability.SignedResult, error) {
	return c.exchange(ctx, signed, false)
}

// ExchangeRecovery uses the same bounded UDS framing but is a distinct caller
// contract. It never mints or rewrites authority and must receive the exact
// signed bytes recovered from durable dispatcher storage.
func (c *UDSClient) ExchangeRecovery(
	ctx context.Context,
	signed capability.SignedCapability,
) (capability.SignedResult, error) {
	return c.exchange(ctx, signed, true)
}

func (c *UDSClient) exchange(
	ctx context.Context,
	signed capability.SignedCapability,
	recoveryOnly bool,
) (capability.SignedResult, error) {
	if ctx == nil || c == nil || c.socketPath == "" || c.timeout != ipc.MaxExchangeTimeout {
		return capability.SignedResult{}, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return capability.SignedResult{}, ErrCancelled
	}
	before, err := inspectSocketBoundary(c.socketPath)
	if err != nil {
		return capability.SignedResult{}, err
	}
	envelope, err := ipc.NewRequestEnvelope(
		signed.CanonicalBytes(), signed.Signature(), signed.ArtifactBytes(),
	)
	if recoveryOnly {
		envelope, err = ipc.NewRecoveryRequestEnvelope(
			signed.CanonicalBytes(), signed.Signature(), signed.ArtifactBytes(),
		)
	}
	if err != nil {
		return capability.SignedResult{}, ErrContractRejected
	}
	request, err := ipc.EncodeRequestEnvelope(envelope)
	if err != nil {
		return capability.SignedResult{}, ErrContractRejected
	}
	dialer := net.Dialer{Timeout: c.timeout}
	raw, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		if contextEnded(ctx) || contextError(err) != nil {
			return capability.SignedResult{}, ErrCancelled
		}
		return capability.SignedResult{}, ErrTransport
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return capability.SignedResult{}, ErrTransport
	}
	after, err := inspectSocketBoundary(c.socketPath)
	if err != nil || before != after {
		_ = conn.Close()
		return capability.SignedResult{}, ErrSocketBoundary
	}
	responsePayload, err := ipc.ClientExchange(ctx, conn, request, c.timeout)
	if err != nil {
		if contextEnded(ctx) || contextError(err) != nil {
			return capability.SignedResult{}, ErrCancelled
		}
		return capability.SignedResult{}, ErrTransport
	}
	response, err := ipc.DecodeResponseEnvelope(responsePayload)
	if err != nil {
		return capability.SignedResult{}, ErrResponseRejected
	}
	return capability.NewUntrustedSignedResult(
		c.resultKeyID, c.executorID, response.ResultJCS(), response.ResultSignature(),
	), nil
}

type socketIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
}

func inspectSocketBoundary(path string) (socketIdentity, error) {
	clean := filepath.Clean(path)
	if path == "" || clean != path || !filepath.IsAbs(clean) {
		return socketIdentity{}, ErrSocketBoundary
	}
	parentInfo, err := os.Lstat(filepath.Dir(clean))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentInfo.Mode().Perm()&0o022 != 0 {
		return socketIdentity{}, ErrSocketBoundary
	}
	socketInfo, err := os.Lstat(clean)
	if err != nil || socketInfo.Mode()&os.ModeSymlink != 0 ||
		socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0o660 {
		return socketIdentity{}, ErrSocketBoundary
	}
	parentStat, parentOK := parentInfo.Sys().(*syscall.Stat_t)
	socketStat, socketOK := socketInfo.Sys().(*syscall.Stat_t)
	if !parentOK || !socketOK || socketStat.Uid != parentStat.Uid {
		return socketIdentity{}, ErrSocketBoundary
	}
	return socketIdentity{
		device: uint64(socketStat.Dev), inode: uint64(socketStat.Ino),
		uid: socketStat.Uid, gid: socketStat.Gid,
	}, nil
}

func contextEnded(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}
