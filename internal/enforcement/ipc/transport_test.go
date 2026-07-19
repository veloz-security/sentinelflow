package ipc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnixExchangeUsesOneRequestAndResponse(t *testing.T) {
	t.Parallel()
	vectors := loadIPCVectors(t)
	request := decodeRawVector(t, vectors.Vectors.Request.PayloadJCSB64)
	response := decodeRawVector(t, vectors.Vectors.Response.PayloadJCSB64)
	listener := listenUnix(t)
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverResult <- err
			return
		}
		serverResult <- ServerExchange(context.Background(), connection, time.Second,
			func(_ context.Context, received []byte) ([]byte, error) {
				if !bytes.Equal(received, request) {
					return nil, errors.New("request differs")
				}
				return response, nil
			})
	}()
	client := dialUnix(t, listener.Addr().String())
	got, err := ClientExchange(context.Background(), client, request, time.Second)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("ClientExchange() = (%d bytes, %v)", len(got), err)
	}
	if err = <-serverResult; err != nil {
		t.Fatalf("ServerExchange() error = %v", err)
	}
}

func TestServerRejectsSecondFrameBeforeHandler(t *testing.T) {
	t.Parallel()
	listener := listenUnix(t)
	var handlerCalls atomic.Int32
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverResult <- err
			return
		}
		serverResult <- ServerExchange(context.Background(), connection, time.Second,
			func(context.Context, []byte) ([]byte, error) {
				handlerCalls.Add(1)
				return []byte("response"), nil
			})
	}()
	client := dialUnix(t, listener.Addr().String())
	first, _ := EncodeFrame([]byte("first"))
	second, _ := EncodeFrame([]byte("second"))
	if _, err := client.Write(append(first, second...)); err != nil {
		t.Fatalf("write two frames: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	if err := <-serverResult; !errors.Is(err, ErrFrameTrailingData) {
		t.Fatalf("ServerExchange() error = %v, want trailing data", err)
	}
	if handlerCalls.Load() != 0 {
		t.Fatal("handler ran before exact request termination was established")
	}
	_ = client.Close()
}

func TestExchangeDeadlineAndCancellationFailClosed(t *testing.T) {
	t.Parallel()
	listener := listenUnix(t)
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverResult <- err
			return
		}
		serverResult <- ServerExchange(context.Background(), connection, 25*time.Millisecond,
			func(ctx context.Context, _ []byte) ([]byte, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			})
	}()
	client := dialUnix(t, listener.Addr().String())
	if _, err := ClientExchange(context.Background(), client, []byte("request"), 25*time.Millisecond); err == nil {
		t.Fatal("exchange exceeded its total deadline without failing")
	}
	if err := <-serverResult; err == nil {
		t.Fatal("server reported success after its exchange deadline")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ClientExchange(cancelled, nil, []byte("request"), time.Second); !errors.Is(err, ErrExchangeConfiguration) {
		t.Fatalf("nil connection error = %v", err)
	}
}

func TestServerContainsHandlerPanic(t *testing.T) {
	t.Parallel()
	listener := listenUnix(t)
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverResult <- err
			return
		}
		serverResult <- ServerExchange(context.Background(), connection, time.Second,
			func(context.Context, []byte) ([]byte, error) { panic("do not leak") })
	}()
	client := dialUnix(t, listener.Addr().String())
	if _, err := ClientExchange(context.Background(), client, []byte("request"), time.Second); err == nil {
		t.Fatal("handler panic produced a response")
	}
	if err := <-serverResult; !errors.Is(err, ErrExchangeHandler) {
		t.Fatalf("server panic error = %v", err)
	}
}

func listenUnix(t *testing.T) *net.UnixListener {
	t.Helper()
	placeholder, err := os.CreateTemp("", "sentinelflow-ipc-*.sock")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	path := placeholder.Name()
	if closeErr := placeholder.Close(); closeErr != nil {
		t.Fatalf("close socket placeholder: %v", closeErr)
	}
	if removeErr := os.Remove(path); removeErr != nil {
		t.Fatalf("remove socket placeholder: %v", removeErr)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix() error = %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})
	return listener
}

func dialUnix(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("DialUnix() error = %v", err)
	}
	return connection
}
