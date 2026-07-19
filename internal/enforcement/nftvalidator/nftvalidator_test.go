package nftvalidator

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

const (
	testNFTVersion = "nftables v1.1.1"
	testCandidate  = "add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n"
)

var testBinaryDigest = "sha256:" + strings.Repeat("a", 64)

type fakeRunner struct {
	mu         sync.Mutex
	checkInput []byte
	checkCalls int
	checkBlock bool
	checkExit  int
}

func (r *fakeRunner) Version(context.Context) (nftcheck.ProcessResult, error) {
	return nftcheck.ProcessResult{
		Path: nftcheck.FixedNFTBinaryPath, Arguments: []string{"--version"}, ExitStatus: 0,
		Stdout: []byte(testNFTVersion + " (synthetic)\n"),
	}, nil
}

func (r *fakeRunner) Check(ctx context.Context, input []byte) (nftcheck.ProcessResult, error) {
	r.mu.Lock()
	r.checkCalls++
	r.checkInput = append([]byte(nil), input...)
	block, exit := r.checkBlock, r.checkExit
	r.mu.Unlock()
	result := nftcheck.ProcessResult{
		Path: nftcheck.FixedNFTBinaryPath, Arguments: []string{"--check", "-f", "-"}, ExitStatus: exit,
	}
	if block {
		<-ctx.Done()
		return result, ctx.Err()
	}
	if exit != 0 {
		result.Stderr = []byte("synthetic rejection")
		return result, errors.New("synthetic process rejection")
	}
	return result, nil
}

func TestClientServerChecksOneCanonicalCandidate(t *testing.T) {
	runner := &fakeRunner{}
	server, client := startIntegratedServer(t, runner)
	evidence, err := client.Check(t.Context(), validInput(t))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if evidence.CanonicalDigest != digestBytes([]byte(testCandidate)) ||
		evidence.BaseContractDigest != nftcheck.PinnedBaseContractDigest ||
		evidence.NFTVersion != testNFTVersion || evidence.SyntaxExitStatus != 0 {
		t.Fatalf("unexpected evidence: %#v", evidence)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.checkCalls != 1 || string(runner.checkInput) != testCandidate {
		t.Fatalf("check calls=%d input=%q", runner.checkCalls, runner.checkInput)
	}
	cancelAndWait(t, server)
}

func TestClientPreservesSyntaxRejectionWithoutOutput(t *testing.T) {
	runner := &fakeRunner{checkExit: 1}
	server, client := startIntegratedServer(t, runner)
	evidence, err := client.Check(t.Context(), validInput(t))
	var typed *nftcheck.Error
	if !errors.As(err, &typed) || typed.Code != nftcheck.ErrorSyntaxRejected ||
		evidence.SyntaxExitStatus != 1 || evidence.SyntaxOutputDigest == "" ||
		evidence.SyntaxOutputByteCount == 0 {
		t.Fatalf("evidence=%#v error=%v", evidence, err)
	}
	if strings.Contains(err.Error(), "synthetic rejection") {
		t.Fatalf("process output leaked through error: %v", err)
	}
	cancelAndWait(t, server)
}

func TestClientRejectsReplayBeforeSecondProcessInvocation(t *testing.T) {
	runner := &fakeRunner{}
	server, client := startIntegratedServer(t, runner)
	client.random = bytes.NewReader(bytes.Repeat([]byte{0x42}, nonceBytes*2))
	if _, err := client.Check(t.Context(), validInput(t)); err != nil {
		t.Fatal(err)
	}
	_, err := client.Check(t.Context(), validInput(t))
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != ErrorRequestReplayed {
		t.Fatalf("replay error=%v", err)
	}
	runner.mu.Lock()
	calls := runner.checkCalls
	runner.mu.Unlock()
	if calls != 1 {
		t.Fatalf("replay reached process: calls=%d", calls)
	}
	cancelAndWait(t, server)
}

func TestClientRejectsResponseBindingMismatches(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*response)
	}{
		{name: "request digest", mutate: func(value *response) { value.requestDigest = "sha256:" + strings.Repeat("b", 64) }},
		{name: "binary digest", mutate: func(value *response) { value.nftBinaryDigest = "sha256:" + strings.Repeat("b", 64) }},
		{name: "version", mutate: func(value *response) {
			value.nftVersion = "nftables v1.1.2"
			value.evidence.NFTVersion = value.nftVersion
		}},
		{name: "candidate", mutate: func(value *response) { value.evidence.CanonicalDigest = "sha256:" + strings.Repeat("b", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, stop := startRawServer(t, func(_ context.Context, payload []byte) ([]byte, error) {
				requestValue, err := decodeRequest(payload)
				if err != nil {
					return nil, err
				}
				value := passedResponse(requestValue.candidateDigest, requestDigest(payload))
				test.mutate(&value)
				return encodeResponse(value)
			})
			client, err := NewClient(path, ExchangeTimeout, testBinaryDigest, testNFTVersion)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Check(t.Context(), validInput(t))
			var typed *Error
			if !errors.As(err, &typed) || typed.Code != ErrorResponseInvalid {
				t.Fatalf("mismatch error=%v", err)
			}
			stop()
		})
	}
}

func TestClientTimeoutAndSocketSafetyFailures(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		path, stop := startRawServer(t, func(ctx context.Context, _ []byte) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		client, _ := NewClient(path, ExchangeTimeout, testBinaryDigest, testNFTVersion)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := client.Check(ctx, validInput(t))
		var typed *nftcheck.Error
		if !errors.As(err, &typed) || typed.Code != nftcheck.ErrorTimeout {
			t.Fatalf("timeout error=%v", err)
		}
		stop()
	})

	t.Run("symlink", func(t *testing.T) {
		path, stop := startRawServer(t, func(context.Context, []byte) ([]byte, error) {
			return nil, errors.New("must not be reached")
		})
		link := filepath.Join(filepath.Dir(path), "validator-link.sock")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		client, _ := NewClient(link, ExchangeTimeout, testBinaryDigest, testNFTVersion)
		_, err := client.Check(t.Context(), validInput(t))
		var typed *Error
		if !errors.As(err, &typed) || typed.Code != ErrorSocketBoundary {
			t.Fatalf("symlink error=%v", err)
		}
		stop()
	})
}

func TestClientRejectsSocketReplacementBetweenInspectionAndDial(t *testing.T) {
	path, stopFirst := startRawServer(t, func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("must not be reached")
	})
	client, _ := NewClient(path, ExchangeTimeout, testBinaryDigest, testNFTVersion)
	var stopSecond func()
	var replacementCalls uint64
	client.afterBoundaryInspect = func() {
		stopFirst()
		_, stopSecond = startRawServerAt(t, path, func(context.Context, []byte) ([]byte, error) {
			atomic.AddUint64(&replacementCalls, 1)
			return nil, errors.New("replacement must not be trusted")
		})
	}
	_, err := client.Check(t.Context(), validInput(t))
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != ErrorSocketBoundary {
		t.Fatalf("replacement error=%v", err)
	}
	if calls := atomic.LoadUint64(&replacementCalls); calls != 0 {
		t.Fatalf("replacement received %d request(s)", calls)
	}
	if stopSecond != nil {
		stopSecond()
	}
}

func TestClientClassifiesMissingSocketAfterInspectionAsBoundary(t *testing.T) {
	path, stop := startRawServer(t, func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("must not be reached")
	})
	client, _ := NewClient(path, ExchangeTimeout, testBinaryDigest, testNFTVersion)
	client.afterBoundaryInspect = stop

	_, err := client.Check(t.Context(), validInput(t))
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != ErrorSocketBoundary {
		t.Fatalf("missing socket error=%v", err)
	}
}

func TestServerRejectsOversizedAndTrailingFramesBeforeChecker(t *testing.T) {
	for _, test := range []struct {
		name  string
		write func(*net.UnixConn)
	}{
		{name: "oversized", write: func(conn *net.UnixConn) {
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], ipc.MaxFramePayloadBytes+1)
			_, _ = conn.Write(header[:])
		}},
		{name: "trailing", write: func(conn *net.UnixConn) {
			payload, _ := encodeRequest([]byte(testCandidate), digestBytes([]byte(testCandidate)), bytes.Repeat([]byte{1}, nonceBytes))
			frame, _ := ipc.EncodeFrame(payload)
			_, _ = conn.Write(append(frame, 0))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeRunner{}
			server, _ := startIntegratedServer(t, runner)
			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: server.path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			test.write(conn)
			_ = conn.CloseWrite()
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			var one [1]byte
			if count, _ := conn.Read(one[:]); count != 0 {
				t.Fatal("malformed frame received a response")
			}
			_ = conn.Close()
			runner.mu.Lock()
			calls := runner.checkCalls
			runner.mu.Unlock()
			if calls != 0 {
				t.Fatalf("malformed frame reached checker: %d", calls)
			}
			cancelAndWait(t, server)
		})
	}
}

func TestLoadPinnedBaseContractRequiresImmutableRegularExactFile(t *testing.T) {
	base := testBaseContract(t)
	directory := shortTempDir(t)
	path := filepath.Join(directory, "base.nft")
	if err := os.WriteFile(path, base, 0o444); err != nil {
		t.Fatal(err)
	}
	if value, err := LoadPinnedBaseContract(path); err != nil || !bytes.Equal(value, base) {
		t.Fatalf("valid base rejected: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinnedBaseContract(path); err == nil {
		t.Fatal("owner-writable base accepted")
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "base-link.nft")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinnedBaseContract(link); err == nil {
		t.Fatal("symlink base accepted")
	}
	mutated := append([]byte(nil), base...)
	mutated[0] ^= 1
	other := filepath.Join(directory, "mutated.nft")
	if err := os.WriteFile(other, mutated, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinnedBaseContract(other); err == nil {
		t.Fatal("digest-mismatched base accepted")
	}
}

func TestClientRejectsInvalidInputBeforeSocket(t *testing.T) {
	client, _ := NewClient("/tmp/missing-validator.sock", ExchangeTimeout, testBinaryDigest, testNFTVersion)
	input := validInput(t)
	input.BaseContract[0] ^= 1
	_, err := client.Check(t.Context(), input)
	var typed *nftcheck.Error
	if !errors.As(err, &typed) || typed.Code != nftcheck.ErrorBaseContract {
		t.Fatalf("invalid input error=%v", err)
	}
}

func TestProtocolRejectsUnknownDuplicateNonCanonicalAndInvalidUTF8(t *testing.T) {
	validRequest, err := encodeRequest(
		[]byte(testCandidate), digestBytes([]byte(testCandidate)), bytes.Repeat([]byte{1}, nonceBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	validResponse, err := encodeResponse(passedResponse(
		digestBytes([]byte(testCandidate)), "sha256:"+strings.Repeat("e", 64),
	))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		payload []byte
		decode  func([]byte) error
	}{
		{name: "request unknown", payload: append(validRequest[:len(validRequest)-1], []byte(`,"unknown":true}`)...), decode: func(value []byte) error { _, err := decodeRequest(value); return err }},
		{name: "request duplicate", payload: append(validRequest[:len(validRequest)-1], []byte(`,"schema_version":"nft-validator-request-v1"}`)...), decode: func(value []byte) error { _, err := decodeRequest(value); return err }},
		{name: "request whitespace", payload: append([]byte{' '}, validRequest...), decode: func(value []byte) error { _, err := decodeRequest(value); return err }},
		{name: "request invalid utf8", payload: append(validRequest, 0xff), decode: func(value []byte) error { _, err := decodeRequest(value); return err }},
		{name: "response unknown", payload: append(validResponse[:len(validResponse)-1], []byte(`,"unknown":true}`)...), decode: func(value []byte) error { _, err := decodeResponse(value); return err }},
		{name: "response duplicate", payload: append(validResponse[:len(validResponse)-1], []byte(`,"passed":true}`)...), decode: func(value []byte) error { _, err := decodeResponse(value); return err }},
		{name: "response whitespace", payload: append([]byte{'\n'}, validResponse...), decode: func(value []byte) error { _, err := decodeResponse(value); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.decode(test.payload); err == nil {
				t.Fatal("non-exact protocol payload accepted")
			}
		})
	}
}

type integratedServer struct {
	path   string
	server *Server
	cancel context.CancelFunc
	done   chan error
}

func startIntegratedServer(t *testing.T, runner nftcheck.ProcessRunner) (*integratedServer, *Client) {
	t.Helper()
	base := testBaseContract(t)
	checker, err := nftcheck.New(runner, testNFTVersion)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(ServiceConfig{
		Checker: checker, BaseContract: base, NFTBinaryDigest: testBinaryDigest, NFTVersion: testNFTVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := shortTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "validator.sock")
	server, err := Listen(path, ExchangeTimeout, service)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client, err := NewClient(path, ExchangeTimeout, testBinaryDigest, testNFTVersion)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
	})
	return &integratedServer{path: path, server: server, cancel: cancel, done: done}, client
}

func cancelAndWait(t *testing.T, value *integratedServer) {
	t.Helper()
	value.cancel()
	_ = value.server.Close()
	select {
	case err := <-value.done:
		if err != nil {
			t.Fatalf("server error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}

func startRawServer(t *testing.T, handler ipc.Handler) (string, func()) {
	t.Helper()
	directory := shortTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return startRawServerAt(t, filepath.Join(directory, "validator.sock"), handler)
}

func startRawServerAt(t *testing.T, path string, handler ipc.Handler) (string, func()) {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(path, SocketMode); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr == nil {
			_ = ipc.ServerExchange(ctx, conn, ExchangeTimeout, handler)
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			_ = listener.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
			}
		})
	}
	t.Cleanup(stop)
	return path, stop
}

func passedResponse(candidateDigest, reqDigest string) response {
	evidence := initialEvidence(candidateDigest)
	evidence.NFTVersion = testNFTVersion
	evidence.VersionExitStatus = 0
	evidence.SyntaxExitStatus = 0
	evidence.VersionOutputDigest = "sha256:" + strings.Repeat("c", 64)
	evidence.SyntaxOutputDigest = "sha256:" + strings.Repeat("d", 64)
	return response{
		baseContractDigest: nftcheck.PinnedBaseContractDigest,
		evidence:           evidence, nftBinaryDigest: testBinaryDigest,
		nftBinaryPath: nftcheck.FixedNFTBinaryPath, nftVersion: testNFTVersion,
		passed: true, requestDigest: reqDigest,
	}
}

func validInput(t *testing.T) nftcheck.Input {
	t.Helper()
	base := testBaseContract(t)
	candidate := []byte(testCandidate)
	return nftcheck.Input{
		CanonicalBytes: candidate, CanonicalDigest: digestBytes(candidate),
		BaseContract: base, BaseContractDigest: nftcheck.PinnedBaseContractDigest,
	}
}

func testBaseContract(t *testing.T) []byte {
	t.Helper()
	value, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "enforcement", "nft_base_chain_v1.nft"))
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(value) != nftcheck.PinnedBaseContractDigest {
		t.Fatal("test base contract digest mismatch")
	}
	return value
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sfv-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func FuzzDecodeRequest(f *testing.F) {
	payload, _ := encodeRequest([]byte(testCandidate), digestBytes([]byte(testCandidate)), bytes.Repeat([]byte{1}, nonceBytes))
	f.Add(payload)
	f.Add([]byte(`{"candidate_b64url":"x","candidate_b64url":"x"}`))
	f.Fuzz(func(t *testing.T, value []byte) {
		requestValue, err := decodeRequest(value)
		if err == nil {
			if !validCandidateEnvelope(requestValue.candidate) || digestBytes(requestValue.candidate) != requestValue.candidateDigest {
				t.Fatal("decoder accepted an invalid request")
			}
		}
	})
}

func FuzzDecodeResponse(f *testing.F) {
	payload, _ := encodeResponse(passedResponse(digestBytes([]byte(testCandidate)), "sha256:"+strings.Repeat("e", 64)))
	f.Add(payload)
	f.Add([]byte(`{"passed":true,"passed":false}`))
	f.Fuzz(func(t *testing.T, value []byte) {
		responseValue, err := decodeResponse(value)
		if err == nil && !validResponse(responseValue) {
			t.Fatal("decoder accepted an invalid response")
		}
	})
}
