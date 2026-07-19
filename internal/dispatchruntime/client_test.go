package dispatchruntime

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
)

func TestUDSClientUsesOneExactFramedExchange(t *testing.T) {
	request := testTransportCapability()
	resultJCS := []byte(`{"result":"synthetic"}`)
	resultSignature := bytes.Repeat([]byte{0x42}, 64)
	server := startUDSServer(t, func(_ context.Context, payload []byte) ([]byte, error) {
		envelope, err := ipc.DecodeRequestEnvelope(payload)
		if err != nil || !bytes.Equal(envelope.CapabilityJCS(), request.CanonicalBytes()) ||
			!bytes.Equal(envelope.CapabilitySignature(), request.Signature()) ||
			!bytes.Equal(envelope.Artifact(), request.ArtifactBytes()) {
			t.Errorf("request envelope mismatch: %v", err)
			return nil, errors.New("request mismatch")
		}
		response, err := ipc.NewResponseEnvelope(resultJCS, resultSignature)
		if err != nil {
			return nil, err
		}
		return ipc.EncodeResponseEnvelope(response)
	})
	client, err := NewUDSClient(server.path, ipc.MaxExchangeTimeout, "result-test", "executor-test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Exchange(context.Background(), request)
	if err != nil || result.KeyID() != "result-test" || result.ExecutorID() != "executor-test" ||
		!bytes.Equal(result.CanonicalBytes(), resultJCS) ||
		!bytes.Equal(result.Signature(), resultSignature) {
		t.Fatalf("result key=%s executor=%s err=%v", result.KeyID(), result.ExecutorID(), err)
	}
	server.wait(t)
}

func TestUDSClientRejectsMalformedResponseAndUnsafeSocket(t *testing.T) {
	t.Run("malformed response", func(t *testing.T) {
		server := startUDSServer(t, func(context.Context, []byte) ([]byte, error) {
			return []byte(`{"not":"a response envelope"}`), nil
		})
		client, _ := NewUDSClient(server.path, ipc.MaxExchangeTimeout, "result-test", "executor-test")
		_, err := client.Exchange(context.Background(), testTransportCapability())
		if !errors.Is(err, ErrResponseRejected) {
			t.Fatalf("malformed response err=%v", err)
		}
		server.wait(t)
	})

	t.Run("unsafe socket mode", func(t *testing.T) {
		server := startUDSServer(t, func(context.Context, []byte) ([]byte, error) {
			return nil, errors.New("must not be reached")
		})
		if err := os.Chmod(server.path, 0o666); err != nil {
			t.Fatal(err)
		}
		client, _ := NewUDSClient(server.path, ipc.MaxExchangeTimeout, "result-test", "executor-test")
		_, err := client.Exchange(context.Background(), testTransportCapability())
		if !errors.Is(err, ErrSocketBoundary) {
			t.Fatalf("unsafe socket err=%v", err)
		}
		server.close()
	})
}

func TestUDSClientHonorsCancellationAndFrozenTimeout(t *testing.T) {
	if _, err := NewUDSClient("/tmp/executor.sock", time.Second, "result-test", "executor-test"); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("short timeout err=%v", err)
	}
	server := startUDSServer(t, func(ctx context.Context, _ []byte) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	client, _ := NewUDSClient(server.path, ipc.MaxExchangeTimeout, "result-test", "executor-test")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.Exchange(ctx, testTransportCapability())
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancelled exchange err=%v", err)
	}
	server.wait(t)
}

type udsTestServer struct {
	path     string
	listener *net.UnixListener
	done     chan error
}

func startUDSServer(t *testing.T, handler ipc.Handler) *udsTestServer {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sfuds-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "executor.sock")
	address, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o660); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	server := &udsTestServer{path: path, listener: listener, done: make(chan error, 1)}
	t.Cleanup(server.close)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			server.done <- acceptErr
			return
		}
		server.done <- ipc.ServerExchange(context.Background(), conn, ipc.MaxExchangeTimeout, handler)
	}()
	return server
}

func (s *udsTestServer) wait(t *testing.T) {
	t.Helper()
	select {
	case err := <-s.done:
		if err != nil && !errors.Is(err, ipc.ErrExchangeHandler) {
			t.Fatalf("UDS server error=%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("UDS server did not finish")
	}
}

func (s *udsTestServer) close() {
	if s != nil && s.listener != nil {
		_ = s.listener.Close()
	}
}

func testTransportCapability() capability.SignedCapability {
	return capability.NewUntrustedSignedCapability(
		"dispatch-test", []byte(`{"capability":"synthetic"}`),
		bytes.Repeat([]byte{0x41}, 64), []byte("exact synthetic artifact\n"),
	)
}
