package executorserver

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
	"golang.org/x/sys/unix"
)

const SocketMode os.FileMode = 0o660

const (
	MaxConcurrentConnections = 8
	maxSocketPathBytes       = 100
)

// Config freezes the only configurable listener values. Handler receives
// bytes only after ipc has validated one complete frame and clean EOF.
type Config struct {
	Path    string
	Timeout time.Duration
	Handler ipc.Handler
}

// Server owns one fresh Unix listener. It is ready for the dispatcher as soon
// as Listen returns; callers must complete every other startup gate first.
type Server struct {
	listener *net.UnixListener
	timeout  time.Duration
	handler  ipc.Handler
	gate     chan struct{}
	closing  chan struct{}
	closeOne sync.Once
	workers  sync.WaitGroup
	started  atomic.Bool
	served   atomic.Uint64
	rejected atomic.Uint64
}

// Listen binds a fresh filesystem Unix socket inside an already provisioned,
// owner-controlled directory. It never removes a pre-existing path.
func Listen(config Config) (*Server, error) {
	if config.Handler == nil || config.Timeout != ipc.MaxExchangeTimeout {
		return nil, reject(ErrorConfiguration)
	}
	clean, directory, parentStat, err := validateSocketBoundary(config.Path)
	if err != nil {
		return nil, err
	}

	address := &net.UnixAddr{Name: clean, Net: "unix"}
	listener, listenErr := net.ListenUnix("unix", address)
	if listenErr != nil {
		return nil, reject(ErrorSocketCreate)
	}
	listener.SetUnlinkOnClose(true)
	cleanup := true
	defer func() {
		if cleanup {
			_ = listener.Close()
		}
	}()

	if chmodErr := os.Chmod(clean, SocketMode); chmodErr != nil {
		return nil, reject(ErrorSocketMode)
	}
	if err = verifySocketBoundary(clean, directory, parentStat); err != nil {
		return nil, err
	}

	server := &Server{
		listener: listener,
		timeout:  config.Timeout,
		handler:  config.Handler,
		gate:     make(chan struct{}, MaxConcurrentConnections),
		closing:  make(chan struct{}),
	}
	cleanup = false
	return server, nil
}

// Serve accepts only Unix stream connections. Per-connection protocol errors
// close that exchange without stopping the listener or manufacturing a result.
func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil || ctx == nil || s.handler == nil || s.timeout != ipc.MaxExchangeTimeout {
		return reject(ErrorConfiguration)
	}
	if !s.started.CompareAndSwap(false, true) {
		return reject(ErrorConfiguration)
	}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()

	for {
		connection, err := s.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || s.isClosing() || errors.Is(err, net.ErrClosed) {
				s.workers.Wait()
				return nil
			}
			_ = s.Close()
			s.workers.Wait()
			return reject(ErrorServe)
		}
		select {
		case s.gate <- struct{}{}:
			s.workers.Add(1)
			go s.exchange(ctx, connection)
		default:
			s.rejected.Add(1)
			_ = connection.Close()
		}
	}
}

func (s *Server) exchange(ctx context.Context, connection *net.UnixConn) {
	defer s.workers.Done()
	defer func() { <-s.gate }()
	if ipc.ServerExchange(ctx, connection, s.timeout, s.handler) == nil {
		s.served.Add(1)
	} else {
		s.rejected.Add(1)
	}
}

// Close is idempotent. UnixListener removes only the socket it created.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.closeOne.Do(func() {
		close(s.closing)
		if s.listener != nil {
			closeErr = s.listener.Close()
		}
	})
	if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return reject(ErrorServe)
	}
	return nil
}

// Counts returns only bounded protocol outcomes, never request or result data.
func (s *Server) Counts() (served, rejected uint64) {
	if s == nil {
		return 0, 0
	}
	return s.served.Load(), s.rejected.Load()
}

func (s *Server) String() string   { return "private executor UDS [redacted]" }
func (s *Server) GoString() string { return s.String() }

func (s *Server) isClosing() bool {
	select {
	case <-s.closing:
		return true
	default:
		return false
	}
}

func validateSocketBoundary(path string) (string, string, unix.Stat_t, error) {
	clean := filepath.Clean(path)
	if path == "" || strings.IndexByte(path, 0) >= 0 || clean != path || !filepath.IsAbs(clean) || len(clean) > maxSocketPathBytes ||
		filepath.Base(clean) == "." || filepath.Base(clean) == string(filepath.Separator) {
		return "", "", unix.Stat_t{}, reject(ErrorSocketPath)
	}
	directory := filepath.Dir(clean)
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", "", unix.Stat_t{}, reject(ErrorSocketParent)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || !safeParent(stat) {
		return "", "", unix.Stat_t{}, reject(ErrorSocketParent)
	}
	if _, err = os.Lstat(clean); err == nil {
		return "", "", unix.Stat_t{}, reject(ErrorSocketExists)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", unix.Stat_t{}, reject(ErrorSocketPath)
	}
	return clean, directory, stat, nil
}

func verifySocketBoundary(path, directory string, before unix.Stat_t) error {
	fd, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return reject(ErrorSocketParent)
	}
	defer unix.Close(fd)
	var after unix.Stat_t
	if err = unix.Fstat(fd, &after); err != nil || !safeParent(after) ||
		before.Dev != after.Dev || before.Ino != after.Ino {
		return reject(ErrorSocketParent)
	}
	var socket unix.Stat_t
	if err = unix.Lstat(path, &socket); err != nil || socket.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		socket.Uid != uint32(os.Geteuid()) ||
		(socket.Gid != before.Gid && socket.Gid != uint32(os.Getegid())) ||
		os.FileMode(socket.Mode).Perm() != SocketMode {
		return reject(ErrorSocketMode)
	}
	return nil
}

func safeParent(stat unix.Stat_t) bool {
	permissions := os.FileMode(stat.Mode).Perm()
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Uid == uint32(os.Geteuid()) &&
		permissions&0o300 == 0o300 &&
		permissions&0o027 == 0
}
