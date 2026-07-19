package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/executor"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
	"github.com/devwooops/sentinelflow/internal/enforcement/keyidentity"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

const runtimeTarget = "203.0.113.20"

var runtimeAddArtifact = []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n")

type fakeLiveSchemaGate struct {
	mu                sync.Mutex
	calls             int
	failCall          int
	bootstrapCalls    int
	failBootstrap     bool
	bootstrappedBytes []byte
}

func (g *fakeLiveSchemaGate) Bootstrap(ctx context.Context, baseContract []byte) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("cancelled bootstrap detail")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.bootstrapCalls++
	g.bootstrappedBytes = append([]byte(nil), baseContract...)
	if g.failBootstrap {
		return errors.New("bootstrap detail that must be redacted")
	}
	return nil
}

func (g *fakeLiveSchemaGate) Verify(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.New("cancelled gate detail")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	if g.calls == g.failCall {
		return errors.New("live-schema detail that must be redacted")
	}
	return nil
}

func (g *fakeLiveSchemaGate) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

func (g *fakeLiveSchemaGate) bootstrapState() (int, []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.bootstrapCalls, append([]byte(nil), g.bootstrappedBytes...)
}

type fakeNFTRunner struct {
	mu          sync.Mutex
	active      bool
	mutations   int
	inspections int
}

func (r *fakeNFTRunner) Mutate(ctx context.Context, mutation executor.Mutation) (executor.MutationOutcome, error) {
	if ctx == nil || ctx.Err() != nil || mutation.Operation() != capability.OperationAdd ||
		mutation.Path() != executor.FixedNFTBinaryPath || !bytes.Equal(mutation.Stdin(), runtimeAddArtifact) {
		return executor.MutationOutcome{ExitClass: capability.NFTExitNotInvoked}, errors.New("unexpected mutation")
	}
	r.mu.Lock()
	r.mutations++
	r.active = true
	r.mu.Unlock()
	return executor.MutationOutcome{ExitClass: capability.NFTExitSuccess}, nil
}

func (r *fakeNFTRunner) Inspect(ctx context.Context, inspection executor.Inspection) (executor.Observation, error) {
	if ctx == nil || ctx.Err() != nil || inspection.TargetIPv4() != runtimeTarget ||
		inspection.OwnedSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest {
		return executor.Observation{}, errors.New("unexpected inspection")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inspections++
	observation := executor.Observation{
		State:             capability.ReadbackAbsent,
		TargetIPv4:        runtimeTarget,
		OwnedSchemaDigest: nftvalidate.PinnedLiveSchemaDigest,
	}
	if r.active {
		observation.State = capability.ReadbackActive
		observation.RemainingTTLSeconds = 1800
	}
	return observation, nil
}

func (r *fakeNFTRunner) counts() (mutations, inspections int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutations, r.inspections
}

func TestApplicationUDSExecutesOnceAndReplaysSignedResult(t *testing.T) {
	configured, socketPath := testRuntimeConfig(t)
	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize))
	gate := &fakeLiveSchemaGate{}
	runner := &fakeNFTRunner{}
	application, err := assembleApplication(
		context.Background(), configured,
		dispatchPrivate.Public().(ed25519.PublicKey), resultPrivate, gate, runner,
	)
	if err != nil {
		t.Fatalf("assembleApplication() error = %v", err)
	}
	defer application.close()
	if gate.count() != 1 {
		t.Fatalf("readiness gate calls=%d, want 1", gate.count())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.serve(ctx) }()

	signed, verifier := signedAdd(t, dispatchPrivate, resultPrivate)
	request := requestPayload(t, signed)
	first := exchangePayload(t, ctx, socketPath, request)
	second := exchangePayload(t, ctx, socketPath, request)
	if !bytes.Equal(first, second) {
		t.Fatal("exact replay did not return byte-identical signed response")
	}
	response, err := ipc.DecodeResponseEnvelope(first)
	if err != nil {
		t.Fatalf("DecodeResponseEnvelope() error = %v", err)
	}
	verified, err := verifier.Verify(capability.NewUntrustedSignedResult(
		application.identities.ResultKeyID,
		application.identities.ExecutorID,
		response.ResultJCS(),
		response.ResultSignature(),
	))
	if err != nil || verified.Value().Classification != capability.ClassificationApplied {
		t.Fatalf("verified result=%+v err=%v", verified.Value(), err)
	}
	mutations, inspections := runner.counts()
	if mutations != 1 || inspections != 2 || gate.count() != 2 {
		t.Fatalf("mutations=%d inspections=%d gate=%d, want 1/2/2", mutations, inspections, gate.count())
	}

	cancel()
	if err = <-done; err != nil {
		t.Fatalf("serve shutdown error = %v", err)
	}
}

func TestPreMutationLiveSchemaFailureNeverInvokesDelegate(t *testing.T) {
	configured, socketPath := testRuntimeConfig(t)
	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x13}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x27}, ed25519.SeedSize))
	gate := &fakeLiveSchemaGate{failCall: 2}
	runner := &fakeNFTRunner{}
	application, err := assembleApplication(
		context.Background(), configured,
		dispatchPrivate.Public().(ed25519.PublicKey), resultPrivate, gate, runner,
	)
	if err != nil {
		t.Fatalf("assembleApplication() error = %v", err)
	}
	defer application.close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- application.serve(ctx) }()

	signed, verifier := signedAdd(t, dispatchPrivate, resultPrivate)
	responsePayload := exchangePayload(t, ctx, socketPath, requestPayload(t, signed))
	response, err := ipc.DecodeResponseEnvelope(responsePayload)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(capability.NewUntrustedSignedResult(
		application.identities.ResultKeyID,
		application.identities.ExecutorID,
		response.ResultJCS(), response.ResultSignature(),
	))
	if err != nil {
		t.Fatalf("failed result signature invalid: %v", err)
	}
	if verified.Value().Classification == capability.ClassificationApplied {
		t.Fatalf("schema drift produced success: %+v", verified.Value())
	}
	mutations, _ := runner.counts()
	if mutations != 0 || gate.count() != 2 {
		t.Fatalf("mutations=%d gate=%d, want 0/2", mutations, gate.count())
	}

	cancel()
	if err = <-done; err != nil {
		t.Fatalf("serve shutdown error = %v", err)
	}
}

func TestExplicitBootstrapReadsExactBoundedContractBeforeReadiness(t *testing.T) {
	baseContract, err := os.ReadFile(filepath.Join("..", "..", "contracts", "enforcement", "nft_base_chain_v1.nft"))
	if err != nil {
		t.Fatal(err)
	}
	contractPath := writeContractFile(t, baseContract, 0o644)
	configured, socketPath := testRuntimeConfigWith(t, bootstrapEnvironment(contractPath))
	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x18}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x29}, ed25519.SeedSize))
	gate := &fakeLiveSchemaGate{failCall: 1}
	application, err := assembleApplication(
		context.Background(), configured,
		dispatchPrivate.Public().(ed25519.PublicKey), resultPrivate, gate, &fakeNFTRunner{},
	)
	if err != nil {
		t.Fatalf("assembleApplication() bootstrap error = %v", err)
	}
	defer application.close()
	bootstrapCalls, observed := gate.bootstrapState()
	if bootstrapCalls != 1 || gate.count() != 1 || !bytes.Equal(observed, baseContract) {
		t.Fatalf("bootstrap calls=%d verify=%d exact=%t", bootstrapCalls, gate.count(), bytes.Equal(observed, baseContract))
	}
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("bootstrap readiness socket = %v, %v", info, err)
	}
}

func TestVerifyModeNeverReadsOrBootstrapsBaseContract(t *testing.T) {
	missing := filepath.Join(secureTestDirectory(t), "does-not-exist.nft")
	configured, _ := testRuntimeConfigWith(t, map[string]string{"NFT_BASE_CHAIN_CONTRACT": missing})
	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x38}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x49}, ed25519.SeedSize))
	gate := &fakeLiveSchemaGate{}
	application, err := assembleApplication(
		context.Background(), configured,
		dispatchPrivate.Public().(ed25519.PublicKey), resultPrivate, gate, &fakeNFTRunner{},
	)
	if err != nil {
		t.Fatalf("verify mode opened bootstrap file: %v", err)
	}
	application.close()
	bootstrapCalls, _ := gate.bootstrapState()
	if gate.count() != 1 || bootstrapCalls != 0 {
		t.Fatalf("verify=%d bootstrap=%d, want 1/0", gate.count(), bootstrapCalls)
	}
}

func TestBootstrapModeRestartVerifiesWithoutReadingOrReapplying(t *testing.T) {
	missing := filepath.Join(secureTestDirectory(t), "restart-must-not-read-base.nft")
	configured, _ := testRuntimeConfigWith(t, bootstrapEnvironment(missing))
	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x39}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4a}, ed25519.SeedSize))
	gate := &fakeLiveSchemaGate{}
	application, err := assembleApplication(
		context.Background(), configured,
		dispatchPrivate.Public().(ed25519.PublicKey), resultPrivate, gate, &fakeNFTRunner{},
	)
	if err != nil {
		t.Fatalf("restart attempted bootstrap instead of verify-only resume: %v", err)
	}
	application.close()
	bootstrapCalls, observed := gate.bootstrapState()
	if gate.count() != 1 || bootstrapCalls != 0 || observed != nil {
		t.Fatalf("restart verify=%d bootstrap=%d bytes=%d", gate.count(), bootstrapCalls, len(observed))
	}
}

func TestBootstrapContractAndProofFailuresExposeNoReadiness(t *testing.T) {
	validContract, err := os.ReadFile(filepath.Join("..", "..", "contracts", "enforcement", "nft_base_chain_v1.nft"))
	if err != nil {
		t.Fatal(err)
	}
	validPath := writeContractFile(t, validContract, 0o644)
	symlinkPath := filepath.Join(secureTestDirectory(t), "base-link.nft")
	if err = os.Symlink(validPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		gate *fakeLiveSchemaGate
	}{
		{name: "missing", path: filepath.Join(secureTestDirectory(t), "missing.nft"), gate: &fakeLiveSchemaGate{failCall: 1}},
		{name: "symlink", path: symlinkPath, gate: &fakeLiveSchemaGate{failCall: 1}},
		{name: "writable", path: writeContractFile(t, validContract, 0o666), gate: &fakeLiveSchemaGate{failCall: 1}},
		{name: "oversized", path: writeContractFile(t, bytes.Repeat([]byte{'x'}, 16*1024+1), 0o644), gate: &fakeLiveSchemaGate{failCall: 1}},
		{name: "bootstrap proof", path: validPath, gate: &fakeLiveSchemaGate{failCall: 1, failBootstrap: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configured, socketPath := testRuntimeConfigWith(t, bootstrapEnvironment(test.path))
			dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x58}, ed25519.SeedSize))
			resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x69}, ed25519.SeedSize))
			application, assembleErr := assembleApplication(
				context.Background(), configured,
				dispatchPrivate.Public().(ed25519.PublicKey), resultPrivate, test.gate, &fakeNFTRunner{},
			)
			if application != nil || runtimeCode(assembleErr) != runtimeSchema {
				t.Fatalf("application=%v error=%v code=%q", application, assembleErr, runtimeCode(assembleErr))
			}
			if strings.Contains(assembleErr.Error(), test.path) || strings.Contains(fmt.Sprintf("%#v", assembleErr), test.path) {
				t.Fatalf("bootstrap error leaked path: %#v", assembleErr)
			}
			if _, statErr := os.Lstat(socketPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed bootstrap exposed readiness: %v", statErr)
			}
		})
	}
}

func TestStartupFailsClosedForConfigKeysAndReadiness(t *testing.T) {
	valid, socketPath := testRuntimeConfig(t)
	dispatchPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	resultPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	validDispatch := dispatchPrivate.Public().(ed25519.PublicKey)
	runner := &fakeNFTRunner{}

	tests := []struct {
		name       string
		configured config.Config
		dispatch   ed25519.PublicKey
		result     ed25519.PrivateKey
		gate       *fakeLiveSchemaGate
		want       runtimeErrorCode
	}{
		{name: "readiness schema", configured: valid, dispatch: validDispatch, result: resultPrivate, gate: &fakeLiveSchemaGate{failCall: 1}, want: runtimeSchema},
		{name: "zero dispatch key", configured: valid, dispatch: make(ed25519.PublicKey, ed25519.PublicKeySize), result: resultPrivate, gate: &fakeLiveSchemaGate{}, want: runtimeKey},
		{name: "short result key", configured: valid, dispatch: validDispatch, result: make(ed25519.PrivateKey, ed25519.PrivateKeySize-1), gate: &fakeLiveSchemaGate{}, want: runtimeKey},
		{name: "corrupt result key", configured: valid, dispatch: validDispatch, result: corruptPrivate(resultPrivate), gate: &fakeLiveSchemaGate{}, want: runtimeKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			application, err := assembleApplication(context.Background(), test.configured, test.dispatch, test.result, test.gate, runner)
			if application != nil || runtimeCode(err) != test.want {
				t.Fatalf("application=%v error=%v code=%q want=%q", application, err, runtimeCode(err), test.want)
			}
			if err != nil && (strings.Contains(err.Error(), socketPath) || strings.Contains(fmt.Sprintf("%#v", err), socketPath)) {
				t.Fatalf("runtime error leaked path: %#v", err)
			}
		})
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed startup exposed readiness socket: %v", err)
	}
}

func TestRuntimeConfigRequiresFrozenExecutorBounds(t *testing.T) {
	configured, _ := testRuntimeConfig(t)
	tests := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"role", func(value *config.Config) { value.Role = config.RoleWorker }},
		{"binary", func(value *config.Config) { value.Enforcement.NFTBinary = "/bin/true" }},
		{"binary digest", func(value *config.Config) { value.Enforcement.NFTBinaryExpectedSHA256 = "" }},
		{"version", func(value *config.Config) { value.Enforcement.NFTExpectedVersion = "" }},
		{"raw schema", func(value *config.Config) { value.Enforcement.BaseChainExpectedSHA256 = strings.Repeat("0", 64) }},
		{"live schema", func(value *config.Config) { value.Enforcement.BaseChainLiveExpectedSHA256 = strings.Repeat("0", 64) }},
		{"frame", func(value *config.Config) { value.Enforcement.ExecutorMaxFrameBytes-- }},
		{"timeout", func(value *config.Config) { value.Enforcement.ExecutorIOTimeout = time.Second }},
		{"host authority", func(value *config.Config) { value.Enforcement.HostEnforcementEnabled = true }},
		{"startup mode", func(value *config.Config) { value.Enforcement.ExecutorStartupMode = "unknown" }},
		{"bootstrap missing proof", func(value *config.Config) {
			value.Enforcement.ExecutorStartupMode = config.ExecutorStartupBootstrap
			value.Environment = config.EnvironmentTest
			value.Demo.AllowRFC5737 = true
			value.Demo.EnforcementIsolationVerified = true
			value.Demo.HostRulesetUnchanged = false
		}},
		{"dispatcher private key", func(value *config.Config) { value.Enforcement.DispatcherSigningKeyFile = "/run/secrets/forbidden.pem" }},
		{"dispatcher result key", func(value *config.Config) {
			value.Enforcement.DispatcherResultPublicKeyFile = "/run/secrets/forbidden.pem"
		}},
		{"gateway tls key", func(value *config.Config) { value.Gateway.TLSKeyFile = "/run/secrets/forbidden.pem" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := configured
			test.mutate(&candidate)
			if validRuntimeConfig(candidate) {
				t.Fatal("unsafe executor configuration accepted")
			}
		})
	}
	if !validRuntimeConfig(configured) {
		t.Fatal("valid frozen executor configuration rejected")
	}
	withOpenAISecret, _ := testRuntimeConfigWith(t, map[string]string{"OPENAI_API_KEY": "executor-must-not-receive-this"})
	if validRuntimeConfig(withOpenAISecret) {
		t.Fatal("executor accepted an OpenAI credential")
	}
}

func TestProductionRuntimeIsLinuxOnly(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux production path requires deployment-provided secrets and nft authority")
	}
	application, err := newProductionApplication(context.Background())
	if application != nil || runtimeCode(err) != runtimePlatform {
		t.Fatalf("application=%v err=%v code=%q", application, err, runtimeCode(err))
	}
}

func signedAdd(
	t *testing.T,
	dispatchPrivate ed25519.PrivateKey,
	resultPrivate ed25519.PrivateKey,
) (capability.SignedCapability, capability.ResultVerifier) {
	t.Helper()
	identities, err := keyidentity.Derive(
		dispatchPrivate.Public().(ed25519.PublicKey),
		resultPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := capability.NewCapabilityIssuer(identities.DispatchKeyID, dispatchPrivate)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewResultVerifier(
		identities.ResultKeyID, identities.ExecutorID,
		resultPrivate.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	checked, err := capability.CheckAdd(capability.Add{
		Common: capability.Common{
			CapabilityID:             "019b0000-0000-4000-8000-000000000001",
			JobID:                    "019b0000-0000-4000-8000-000000000002",
			ActionID:                 "019b0000-0000-4000-8000-000000000003",
			PolicyID:                 "019b0000-0000-4000-8000-000000000004",
			PolicyVersion:            1,
			TargetIPv4:               runtimeTarget,
			EvidenceSnapshotDigest:   testDigest('e'),
			ValidationSnapshotDigest: testDigest('v'),
			AuthorizationDigest:      testDigest('a'),
			ActorID:                  "admin",
			ReasonDigest:             testDigest('r'),
			OwnedSchemaDigest:        nftvalidate.PinnedLiveSchemaDigest,
			IssuedAt:                 now.Add(-time.Second),
			NotBefore:                now.Add(-time.Second),
			ExpiresAt:                now.Add(30 * time.Second),
			Nonce:                    base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 16)),
		},
		CanonicalCommand: runtimeAddArtifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := issuer.Sign(checked)
	if err != nil {
		t.Fatal(err)
	}
	return signed, verifier
}

func requestPayload(t *testing.T, signed capability.SignedCapability) []byte {
	t.Helper()
	envelope, err := ipc.NewRequestEnvelope(signed.CanonicalBytes(), signed.Signature(), signed.ArtifactBytes())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ipc.EncodeRequestEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func exchangePayload(t *testing.T, ctx context.Context, path string, payload []byte) []byte {
	t.Helper()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := ipc.ClientExchange(ctx, connection, payload, ipc.MaxExchangeTimeout)
	if err != nil {
		t.Fatalf("ClientExchange() error = %v", err)
	}
	return response
}

func testRuntimeConfig(t *testing.T) (config.Config, string) {
	return testRuntimeConfigWith(t, nil)
}

func testRuntimeConfigWith(t *testing.T, extra map[string]string) (config.Config, string) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sentinelflow-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err = os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "executor.sock")
	values := map[string]string{
		"EXECUTOR_DISPATCH_PUBLIC_KEY_FILE": "/run/secrets/dispatcher-public.pem",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE":  "/run/secrets/executor-result-private.pem",
		"EXECUTOR_SOCKET":                   socketPath,
		"EXECUTOR_REPLAY_JOURNAL":           filepath.Join(directory, "replay.journal"),
		"NFT_BINARY_EXPECTED_SHA256":        strings.Repeat("1", 64),
		"NFT_EXPECTED_VERSION":              "nftables v1.1.1",
	}
	for name, value := range extra {
		values[name] = value
	}
	configured, err := config.LoadFrom(config.RoleExecutor, func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	return configured, socketPath
}

func bootstrapEnvironment(contractPath string) map[string]string {
	return map[string]string{
		"SENTINELFLOW_ENV":                    "test",
		"EXECUTOR_STARTUP_MODE":               "bootstrap",
		"NFT_BASE_CHAIN_CONTRACT":             contractPath,
		"DEMO_ALLOW_RFC5737":                  "true",
		"DEMO_ENFORCEMENT_ISOLATION_VERIFIED": "true",
		"DEMO_HOST_RULESET_UNCHANGED":         "true",
	}
}

func writeContractFile(t *testing.T, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(secureTestDirectory(t), "base.nft")
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func secureTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sentinelflow-contract-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err = os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func testDigest(fill byte) string {
	sum := sha256.Sum256([]byte{fill})
	return "sha256:" + hex.EncodeToString(sum[:])
}

func corruptPrivate(value ed25519.PrivateKey) ed25519.PrivateKey {
	result := append(ed25519.PrivateKey(nil), value...)
	result[len(result)-1] ^= 1
	return result
}
