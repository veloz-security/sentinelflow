package main

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/executor"
	"github.com/devwooops/sentinelflow/internal/enforcement/executorserver"
	"github.com/devwooops/sentinelflow/internal/enforcement/ipc"
	"github.com/devwooops/sentinelflow/internal/enforcement/journal"
	"github.com/devwooops/sentinelflow/internal/enforcement/keyidentity"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftbinary"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftbootstrap"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftrunner"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/keymaterial"
	"golang.org/x/sys/unix"
)

type runtimeErrorCode string

const (
	runtimePlatform    runtimeErrorCode = "unsupported_platform"
	runtimeConfig      runtimeErrorCode = "configuration_rejected"
	runtimeKey         runtimeErrorCode = "key_material_rejected"
	runtimeAttestation runtimeErrorCode = "nft_binary_attestation_rejected"
	runtimeSchema      runtimeErrorCode = "nft_live_schema_rejected"
	runtimeRunner      runtimeErrorCode = "nft_runner_rejected"
	runtimeJournal     runtimeErrorCode = "journal_rejected"
	runtimeService     runtimeErrorCode = "executor_service_rejected"
	runtimeSocket      runtimeErrorCode = "executor_socket_rejected"
)

// runtimeError intentionally omits paths, key identities, underlying errors,
// process output, and nftables observations.
type runtimeError struct{ code runtimeErrorCode }

func (e *runtimeError) Error() string {
	if e == nil {
		return "executor runtime rejected"
	}
	return "executor runtime rejected: " + string(e.code)
}

func failRuntime(code runtimeErrorCode) error { return &runtimeError{code: code} }

type liveSchemaGate interface {
	Verify(context.Context) error
	Bootstrap(context.Context, []byte) error
}

type productionLiveGate struct {
	manager         *nftbootstrap.Manager
	expectedVersion string
}

func (g productionLiveGate) Verify(ctx context.Context) error {
	if g.manager == nil || ctx == nil || !strings.HasPrefix(g.expectedVersion, "nftables v") {
		return failRuntime(runtimeSchema)
	}
	proof, err := g.manager.VerifyLive(ctx)
	if err != nil || proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest ||
		proof.NFTVersion() != strings.TrimPrefix(g.expectedVersion, "nftables v") ||
		!proof.IsReadOnlyVerification() || proof.BootstrapWasPerformed() {
		return failRuntime(runtimeSchema)
	}
	return nil
}

func (g productionLiveGate) Bootstrap(ctx context.Context, baseContract []byte) error {
	if g.manager == nil || ctx == nil || !strings.HasPrefix(g.expectedVersion, "nftables v") {
		return failRuntime(runtimeSchema)
	}
	proof, err := g.manager.Bootstrap(ctx, baseContract)
	if err != nil || proof.BaseContractDigest() != nftvalidate.PinnedBaseChainRawDigest ||
		proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest ||
		proof.NFTVersion() != strings.TrimPrefix(g.expectedVersion, "nftables v") ||
		proof.IsReadOnlyVerification() || !proof.BootstrapWasPerformed() {
		return failRuntime(runtimeSchema)
	}
	return nil
}

// gatedRunner performs the namespace-wide live-schema read-back immediately
// before each add/revoke subprocess. Inspection is already a fixed read-only
// operation and cannot repair or mutate a drifted schema.
type gatedRunner struct {
	gate     liveSchemaGate
	delegate executor.Runner
}

func (r gatedRunner) Mutate(ctx context.Context, mutation executor.Mutation) (executor.MutationOutcome, error) {
	if r.gate == nil || r.delegate == nil || ctx == nil ||
		(mutation.Operation() != capability.OperationAdd && mutation.Operation() != capability.OperationRevoke) {
		return executor.MutationOutcome{ExitClass: capability.NFTExitNotInvoked}, failRuntime(runtimeRunner)
	}
	if err := r.gate.Verify(ctx); err != nil {
		return executor.MutationOutcome{ExitClass: capability.NFTExitNotInvoked}, failRuntime(runtimeSchema)
	}
	return r.delegate.Mutate(ctx, mutation)
}

func (r gatedRunner) Inspect(ctx context.Context, inspection executor.Inspection) (executor.Observation, error) {
	if r.delegate == nil || ctx == nil {
		return executor.Observation{}, failRuntime(runtimeRunner)
	}
	return r.delegate.Inspect(ctx, inspection)
}

func (r gatedRunner) String() string   { return "live-schema-gated nft runner [redacted]" }
func (r gatedRunner) GoString() string { return r.String() }

type application struct {
	server     *executorserver.Server
	journal    *journal.Journal
	identities keyidentity.Set
	closeOne   sync.Once
}

func newProductionApplication(ctx context.Context) (*application, error) {
	if runtime.GOOS != "linux" {
		return nil, failRuntime(runtimePlatform)
	}
	configured, err := config.Load(config.RoleExecutor)
	if err != nil || !validRuntimeConfig(configured) {
		return nil, failRuntime(runtimeConfig)
	}

	dispatchPublic, err := keymaterial.LoadPublicFile(configured.Enforcement.ExecutorDispatchPublicKeyFile)
	if err != nil {
		return nil, failRuntime(runtimeKey)
	}
	resultPrivate, err := keymaterial.LoadPrivateFile(configured.Enforcement.ExecutorResultPrivateKeyFile)
	if err != nil {
		return nil, failRuntime(runtimeKey)
	}
	defer clear(resultPrivate)

	checkRunner, err := nftcheck.NewProductionRunner()
	if err != nil {
		return nil, failRuntime(runtimeRunner)
	}
	evidence, err := nftbinary.Verify(
		ctx,
		checkRunner,
		"sha256:"+configured.Enforcement.NFTBinaryExpectedSHA256,
		configured.Enforcement.NFTExpectedVersion,
	)
	if err != nil || evidence.BinaryDigest != "sha256:"+configured.Enforcement.NFTBinaryExpectedSHA256 ||
		evidence.Version != configured.Enforcement.NFTExpectedVersion {
		return nil, failRuntime(runtimeAttestation)
	}

	manager, err := nftbootstrap.NewProductionManager()
	if err != nil {
		return nil, failRuntime(runtimeSchema)
	}
	liveGate := productionLiveGate{manager: manager, expectedVersion: configured.Enforcement.NFTExpectedVersion}
	runner, err := nftrunner.NewProductionRunner()
	if err != nil {
		return nil, failRuntime(runtimeRunner)
	}
	return assembleApplication(ctx, configured, dispatchPublic, resultPrivate, liveGate, runner)
}

func assembleApplication(
	ctx context.Context,
	configured config.Config,
	dispatchPublic ed25519.PublicKey,
	resultPrivate ed25519.PrivateKey,
	liveGate liveSchemaGate,
	runner executor.Runner,
) (*application, error) {
	if ctx == nil || ctx.Err() != nil || !validRuntimeConfig(configured) || liveGate == nil || runner == nil {
		return nil, failRuntime(runtimeConfig)
	}
	if !validResultPrivateKey(resultPrivate) {
		return nil, failRuntime(runtimeKey)
	}
	resultPublic := append(ed25519.PublicKey(nil), resultPrivate[ed25519.SeedSize:]...)
	identities, err := keyidentity.Derive(dispatchPublic, resultPublic)
	if err != nil {
		return nil, failRuntime(runtimeKey)
	}
	verifier, err := capability.NewCapabilityVerifier(identities.DispatchKeyID, identities.ExecutorID, dispatchPublic)
	if err != nil {
		return nil, failRuntime(runtimeKey)
	}
	resultSigner, err := capability.NewResultSigner(identities.ResultKeyID, identities.ExecutorID, resultPrivate)
	if err != nil {
		return nil, failRuntime(runtimeKey)
	}
	resultVerifier, err := capability.NewResultVerifier(identities.ResultKeyID, identities.ExecutorID, resultPublic)
	if err != nil {
		return nil, failRuntime(runtimeKey)
	}

	if err = prepareOwnedSchema(ctx, configured, liveGate); err != nil {
		return nil, failRuntime(runtimeSchema)
	}

	replayJournal, err := journal.Open(journal.Options{
		Path:               configured.Enforcement.ExecutorReplayJournal,
		CapabilityVerifier: verifier,
		ResultVerifier:     resultVerifier,
	})
	if err != nil {
		return nil, failRuntime(runtimeJournal)
	}
	cleanupJournal := true
	defer func() {
		if cleanupJournal {
			_ = replayJournal.Close()
		}
	}()

	service, err := executor.New(executor.Config{
		CapabilityVerifier: verifier,
		ResultSigner:       resultSigner,
		Journal:            replayJournal,
		Runner:             gatedRunner{gate: liveGate, delegate: runner},
		DispatchKeyID:      identities.DispatchKeyID,
	})
	if err != nil {
		return nil, failRuntime(runtimeService)
	}
	server, err := executorserver.Listen(executorserver.Config{
		Path:    configured.Enforcement.ExecutorSocket,
		Timeout: configured.Enforcement.ExecutorIOTimeout,
		Handler: service.HandlePayload,
	})
	if err != nil {
		return nil, failRuntime(runtimeSocket)
	}
	cleanupJournal = false
	return &application{server: server, journal: replayJournal, identities: identities}, nil
}

func validRuntimeConfig(value config.Config) bool {
	return value.Role == config.RoleExecutor && value.Enforcement.NFTBinary == nftcheck.FixedNFTBinaryPath &&
		value.Enforcement.NFTBinaryExpectedSHA256 != "" && value.Enforcement.NFTExpectedVersion != "" &&
		value.Enforcement.BaseChainExpectedSHA256 == strings.TrimPrefix(nftvalidate.PinnedBaseChainRawDigest, "sha256:") &&
		value.Enforcement.BaseChainLiveExpectedSHA256 == strings.TrimPrefix(nftvalidate.PinnedLiveSchemaDigest, "sha256:") &&
		value.Enforcement.ExecutorMaxFrameBytes == ipc.MaxFramePayloadBytes &&
		value.Enforcement.ExecutorIOTimeout == ipc.MaxExchangeTimeout &&
		!value.Enforcement.HostEnforcementEnabled && validStartupMode(value) &&
		forbiddenExecutorSecretsAbsent(value)
}

func validStartupMode(value config.Config) bool {
	switch value.Enforcement.ExecutorStartupMode {
	case config.ExecutorStartupVerify:
		return true
	case config.ExecutorStartupBootstrap:
		return (value.Environment == config.EnvironmentDemo || value.Environment == config.EnvironmentTest) &&
			value.Demo.AllowRFC5737 && value.Demo.EnforcementIsolationVerified && value.Demo.HostRulesetUnchanged
	default:
		return false
	}
}

func prepareOwnedSchema(ctx context.Context, configured config.Config, gate liveSchemaGate) error {
	if ctx == nil || ctx.Err() != nil || gate == nil || !validStartupMode(configured) {
		return failRuntime(runtimeSchema)
	}
	switch configured.Enforcement.ExecutorStartupMode {
	case config.ExecutorStartupVerify:
		// Verify mode is read-only and never opens the raw bootstrap contract.
		return gate.Verify(ctx)
	case config.ExecutorStartupBootstrap:
		// A restarted executor shares the still-live Gateway namespace. Resume
		// only when the exact owned structure already verifies; never reapply
		// bootstrap bytes or refresh dynamic set-element TTLs. If verification
		// fails, Bootstrap still refuses any partial or drifted owned object and
		// can provision only a genuinely absent owned table.
		if err := gate.Verify(ctx); err == nil {
			return nil
		}
		baseContract, err := readBoundedBaseContract(configured.Enforcement.BaseChainContract)
		if err != nil {
			return failRuntime(runtimeSchema)
		}
		return gate.Bootstrap(ctx, baseContract)
	default:
		return failRuntime(runtimeSchema)
	}
}

func readBoundedBaseContract(path string) ([]byte, error) {
	clean := filepath.Clean(path)
	if path == "" || strings.IndexByte(path, 0) >= 0 || clean != path || filepath.Base(clean) == "." ||
		filepath.Base(clean) == string(filepath.Separator) {
		return nil, failRuntime(runtimeSchema)
	}
	fd, err := unix.Open(clean, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, failRuntime(runtimeSchema)
	}
	file := os.NewFile(uintptr(fd), "nft-base-chain-contract")
	if file == nil {
		_ = unix.Close(fd)
		return nil, failRuntime(runtimeSchema)
	}
	defer file.Close()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Nlink != 1 || os.FileMode(stat.Mode).Perm()&0o022 != 0 {
		return nil, failRuntime(runtimeSchema)
	}
	value, err := io.ReadAll(io.LimitReader(file, nftbootstrap.MaxBaseContractBytes+1))
	if err != nil || len(value) == 0 || len(value) > nftbootstrap.MaxBaseContractBytes {
		return nil, failRuntime(runtimeSchema)
	}
	return value, nil
}

func forbiddenExecutorSecretsAbsent(value config.Config) bool {
	return !value.Database.MigrationURL.IsSet() && !value.Database.APIURL.IsSet() &&
		!value.Database.WorkerURL.IsSet() && !value.Database.ReadURL.IsSet() &&
		!value.Database.DispatcherURL.IsSet() && !value.OpenAI.APIKey.IsSet() &&
		!value.Admin.PasswordArgon2idHash.IsSet() && !value.Admin.SessionHMACKey.IsSet() &&
		!value.Events.GatewayHMACKey.IsSet() && !value.Events.AuthHMACKey.IsSet() &&
		!value.Events.AuthAccountHashKey.IsSet() && value.Enforcement.DispatcherSigningKeyFile == "" &&
		value.Enforcement.DispatcherResultPublicKeyFile == "" &&
		value.Demo.HistoryPublicKeyFile == "" && value.Demo.HistorySimulatorPrivateKeyFile == "" &&
		value.Gateway.TLSKeyFile == "" && value.Gateway.TLSCertFile == ""
}

func validResultPrivateKey(value ed25519.PrivateKey) bool {
	if len(value) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(value[:ed25519.SeedSize])
	valid := subtle.ConstantTimeCompare(derived, value) == 1
	clear(derived)
	return valid
}

func (a *application) serve(ctx context.Context) error {
	if a == nil || a.server == nil || a.journal == nil || ctx == nil {
		return failRuntime(runtimeConfig)
	}
	if err := a.server.Serve(ctx); err != nil {
		return failRuntime(runtimeSocket)
	}
	return nil
}

func (a *application) close() {
	if a == nil {
		return
	}
	a.closeOne.Do(func() {
		if a.server != nil {
			_ = a.server.Close()
		}
		if a.journal != nil {
			_ = a.journal.Close()
		}
	})
}

func runtimeCode(err error) runtimeErrorCode {
	var typed *runtimeError
	if errors.As(err, &typed) {
		return typed.code
	}
	return ""
}
