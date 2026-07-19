package nftvalidator

import (
	"context"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/executorserver"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
)

const (
	SocketMode      = executorserver.SocketMode
	ExchangeTimeout = ipc.MaxExchangeTimeout
)

type Server struct{ inner *executorserver.Server }

// Listen creates a fresh 0660 UDS in an owner-controlled parent directory.
// The shared framing layer enforces one request, clean EOF, one response, the
// 16 KiB bound, and the frozen two-second deadline.
func Listen(path string, timeout time.Duration, service *Service) (*Server, error) {
	if service == nil || timeout != ipc.MaxExchangeTimeout {
		return nil, reject(ErrorInvalidConfiguration)
	}
	inner, err := executorserver.Listen(executorserver.Config{
		Path: path, Timeout: timeout, Handler: service.Handle,
	})
	if err != nil {
		return nil, reject(ErrorServerBoundary)
	}
	return &Server{inner: inner}, nil
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.inner == nil || ctx == nil {
		return reject(ErrorInvalidConfiguration)
	}
	if err := s.inner.Serve(ctx); err != nil {
		return reject(ErrorServerBoundary)
	}
	return nil
}

func (s *Server) Close() error {
	if s == nil || s.inner == nil {
		return nil
	}
	if err := s.inner.Close(); err != nil {
		return reject(ErrorServerBoundary)
	}
	return nil
}

func (s *Server) Counts() (uint64, uint64) {
	if s == nil || s.inner == nil {
		return 0, 0
	}
	return s.inner.Counts()
}

func (*Server) String() string     { return "private nft validator UDS [redacted]" }
func (s *Server) GoString() string { return s.String() }
