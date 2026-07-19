package executorserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
)

func TestServerExchangesOneFrameAndShutsDownCleanly(t *testing.T) {
	var calls atomic.Uint64
	server, path := listenForTest(t, func(ctx context.Context, request []byte) ([]byte, error) {
		calls.Add(1)
		if ctx.Err() != nil || string(request) != "request" {
			return nil, errors.New("unexpected request")
		}
		return []byte("response"), nil
	})
	ctx, cancel, done := serveForTest(t, server)

	connection := dialForTest(t, path)
	response, err := ipc.ClientExchange(ctx, connection, []byte("request"), ipc.MaxExchangeTimeout)
	if err != nil || string(response) != "response" || calls.Load() != 1 {
		t.Fatalf("exchange response=%q calls=%d err=%v", response, calls.Load(), err)
	}
	served, rejected := waitForCounts(server, 1)
	if served != 1 || rejected != 0 {
		t.Fatalf("counts=(%d,%d), want (1,0)", served, rejected)
	}
	if err = server.Serve(context.Background()); err == nil {
		t.Fatal("second concurrent Serve() unexpectedly accepted")
	}

	cancel()
	if err = <-done; err != nil {
		t.Fatalf("Serve() shutdown error = %v", err)
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remained after shutdown: %v", err)
	}
}

func TestMalformedFramesNeverReachHandler(t *testing.T) {
	var calls atomic.Uint64
	server, path := listenForTest(t, func(context.Context, []byte) ([]byte, error) {
		calls.Add(1)
		return []byte("must-not-run"), nil
	})
	_, cancel, done := serveForTest(t, server)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve() shutdown error = %v", err)
		}
	}()

	tests := []struct {
		name  string
		frame []byte
	}{
		{name: "short header", frame: []byte{0, 0, 0}},
		{name: "zero length", frame: []byte{0, 0, 0, 0}},
		{name: "truncated payload", frame: []byte{0, 0, 0, 2, 'x'}},
		{name: "trailing second byte", frame: []byte{0, 0, 0, 1, 'x', 'y'}},
		{name: "oversized", frame: sizeHeader(ipc.MaxFramePayloadBytes + 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection := dialForTest(t, path)
			if _, err := connection.Write(test.frame); err != nil {
				t.Fatalf("Write() error = %v", err)
			}
			if err := connection.CloseWrite(); err != nil {
				t.Fatalf("CloseWrite() error = %v", err)
			}
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			response, err := io.ReadAll(connection)
			_ = connection.Close()
			if err != nil || len(response) != 0 {
				t.Fatalf("malformed response=%q err=%v", response, err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("malformed frames reached handler %d times", calls.Load())
	}
}

func TestIncompleteFrameTimesOutAndConnectionCloses(t *testing.T) {
	var calls atomic.Uint64
	server, path := listenForTest(t, func(context.Context, []byte) ([]byte, error) {
		calls.Add(1)
		return []byte("must-not-run"), nil
	})
	_, cancel, done := serveForTest(t, server)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve() shutdown error = %v", err)
		}
	}()

	connection := dialForTest(t, path)
	if _, err := connection.Write([]byte{0, 0, 0, 1}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	started := time.Now()
	_ = connection.SetReadDeadline(started.Add(3 * time.Second))
	response, err := io.ReadAll(connection)
	_ = connection.Close()
	if err != nil || len(response) != 0 || calls.Load() != 0 {
		t.Fatalf("timeout response=%q calls=%d err=%v", response, calls.Load(), err)
	}
	elapsed := time.Since(started)
	if elapsed < 1500*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("exchange timeout elapsed=%v, want bounded near 2s", elapsed)
	}
}

func TestCancellationInterruptsActiveExchange(t *testing.T) {
	server, path := listenForTest(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	_, cancel, done := serveForTest(t, server)
	connection := dialForTest(t, path)
	frame, err := ipc.EncodeFrame([]byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Write(frame); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err = connection.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatalf("Serve() shutdown error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not interrupt active exchange")
	}
	_ = connection.Close()
}

func TestSocketBoundaryPermissionsAndUnsafePaths(t *testing.T) {
	handler := func(context.Context, []byte) ([]byte, error) { return []byte("ok"), nil }
	server, path := listenForTest(t, handler)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != SocketMode {
		t.Fatalf("socket mode=%v, want socket %04o", info.Mode(), SocketMode)
	}
	if err = server.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	unsafeDirectory := filepath.Join(secureDirectory(t), "unsafe")
	if err = os.Mkdir(unsafeDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(unsafeDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	existingDirectory := secureDirectory(t)
	existingPath := filepath.Join(existingDirectory, "existing.sock")
	if err = os.WriteFile(existingPath, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkParent := filepath.Join(secureDirectory(t), "socket-parent-link")
	if err = os.Symlink(existingDirectory, symlinkParent); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		config Config
		code   ErrorCode
	}{
		{"relative", Config{Path: "executor.sock", Timeout: ipc.MaxExchangeTimeout, Handler: handler}, ErrorSocketPath},
		{"nul", Config{Path: filepath.Join(secureDirectory(t), "executor\x00.sock"), Timeout: ipc.MaxExchangeTimeout, Handler: handler}, ErrorSocketPath},
		{"unsafe parent", Config{Path: filepath.Join(unsafeDirectory, "executor.sock"), Timeout: ipc.MaxExchangeTimeout, Handler: handler}, ErrorSocketParent},
		{"symlink parent", Config{Path: filepath.Join(symlinkParent, "executor.sock"), Timeout: ipc.MaxExchangeTimeout, Handler: handler}, ErrorSocketParent},
		{"existing path", Config{Path: existingPath, Timeout: ipc.MaxExchangeTimeout, Handler: handler}, ErrorSocketExists},
		{"short timeout", Config{Path: filepath.Join(secureDirectory(t), "executor.sock"), Timeout: time.Second, Handler: handler}, ErrorConfiguration},
		{"nil handler", Config{Path: filepath.Join(secureDirectory(t), "executor.sock"), Timeout: ipc.MaxExchangeTimeout}, ErrorConfiguration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, listenErr := Listen(test.config)
			var typed *Error
			if !errors.As(listenErr, &typed) || typed.Code != test.code {
				t.Fatalf("error=%v, want code=%q", listenErr, test.code)
			}
			if strings.Contains(listenErr.Error(), test.config.Path) || strings.Contains(fmt.Sprintf("%#v", listenErr), test.config.Path) {
				t.Fatalf("error leaked socket path: %#v", listenErr)
			}
		})
	}
}

func listenForTest(t *testing.T, handler ipc.Handler) (*Server, string) {
	t.Helper()
	directory := secureDirectory(t)
	path := filepath.Join(directory, "executor.sock")
	server, err := Listen(Config{Path: path, Timeout: ipc.MaxExchangeTimeout, Handler: handler})
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, path
}

func secureDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sentinelflow-executor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func serveForTest(t *testing.T, server *Server) (context.Context, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	return ctx, cancel, done
}

func dialForTest(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("DialUnix() error = %v", err)
	}
	return connection
}

func sizeHeader(size int) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(size))
	return result
}

func waitForCounts(server *Server, minimum uint64) (uint64, uint64) {
	deadline := time.Now().Add(time.Second)
	for {
		served, rejected := server.Counts()
		if served+rejected >= minimum || time.Now().After(deadline) {
			return served, rejected
		}
		time.Sleep(time.Millisecond)
	}
}
