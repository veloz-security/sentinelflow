// Command validationworker runs the provider-independent policy validation
// consumer. It has no model, ingestion, administrator, dispatcher, executor,
// signing, shell, or direct nftables mutation authority.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/buildinfo"
	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/demohistoryactivation"
	"github.com/devwooops/sentinelflow/internal/demohistoryproof"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidator"
	"github.com/devwooops/sentinelflow/internal/validation"
	"github.com/devwooops/sentinelflow/internal/validationstore"
	validationloop "github.com/devwooops/sentinelflow/internal/validationworker"
)

const (
	validationLeaseOwner  = "validation-worker-01"
	validationPoolConns   = 4
	validationLockTimeout = 2 * time.Second
	analysisInputSchema   = "contracts/ai/sentinelflow_analysis_input_v1.schema.json"
	analysisSystemPrompt  = "contracts/ai/sentinelflow_system_prompt_v1.txt"
	analysisOutputSchema  = "contracts/ai/sentinelflow_analysis_v1.schema.json"
)

var errUnexpectedRuntimeExit = errors.New("validation worker runtime exited unexpectedly")

type policyValidationRuntime interface {
	Run(context.Context) error
}

type runtimeFailure struct{ cause error }

func (*runtimeFailure) Error() string { return "validation worker runtime failed" }

func (e *runtimeFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type runtimeSet struct {
	runtime policyValidationRuntime
	pool    *pgxpool.Pool
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger); err != nil {
		logger.Error("validation worker stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	if ctx == nil || logger == nil {
		return errors.New("validation worker: runtime dependencies are required")
	}
	runtimeConfig, err := config.Load(config.RoleValidationWorker)
	if err != nil {
		return fmt.Errorf("load validation worker configuration: %w", err)
	}
	runtimes, err := buildValidationRuntime(ctx, runtimeConfig)
	if err != nil {
		return err
	}
	defer runtimes.pool.Close()

	logger.Info("provider-independent policy validation worker configured",
		"service", buildinfo.Name, "version", buildinfo.Version)
	return superviseRuntime(ctx, runtimes.runtime)
}

func superviseRuntime(ctx context.Context, runtime policyValidationRuntime) error {
	if ctx == nil || runtime == nil {
		return errors.New("validation worker: runtime is required")
	}
	err := invokeRuntime(ctx, runtime)
	if ctx.Err() != nil {
		return nil
	}
	if err == nil {
		err = errUnexpectedRuntimeExit
	}
	return &runtimeFailure{cause: err}
}

func invokeRuntime(ctx context.Context, runtime policyValidationRuntime) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("validation worker: runtime panic contained")
		}
	}()
	return runtime.Run(ctx)
}

func buildValidationRuntime(ctx context.Context, runtimeConfig config.Config) (runtimeSet, error) {
	if ctx == nil || runtimeConfig.Role != config.RoleValidationWorker {
		return runtimeSet{}, errors.New("validation worker: invalid runtime configuration")
	}

	// These checked-in artifacts provide immutable validation digests, not model
	// authority. RoleValidationWorker rejects every OPENAI_* environment value.
	artifacts, err := ai.LoadArtifacts(ai.ArtifactPaths{
		InputSchema:  analysisInputSchema,
		SystemPrompt: analysisSystemPrompt,
		OutputSchema: analysisOutputSchema,
	})
	if err != nil {
		return runtimeSet{}, errors.New("validation worker: analysis contract artifacts are invalid")
	}
	baseContract, err := readContract(runtimeConfig.Enforcement.BaseChainContract, nftvalidate.MaxBaseContractBytes)
	if err != nil {
		return runtimeSet{}, errors.New("validation worker: raw base-chain contract is invalid")
	}
	liveSchema, err := readContract(runtimeConfig.Enforcement.BaseChainLiveContract, nftvalidate.MaxLiveSchemaBytes)
	if err != nil {
		return runtimeSet{}, errors.New("validation worker: live base-chain contract is invalid")
	}
	if _, err := nftvalidate.ValidateOwnedSchema(baseContract, liveSchema); err != nil {
		return runtimeSet{}, errors.New("validation worker: owned nftables contracts are invalid")
	}
	protectedContract, err := validation.LoadProtectedContractFile(runtimeConfig.Enforcement.ProtectedIPv4Contract)
	if err != nil {
		return runtimeSet{}, errors.New("validation worker: protected IPv4 contract is invalid")
	}
	protectedConfig, err := validationProtectedConfig(runtimeConfig)
	if err != nil {
		return runtimeSet{}, err
	}
	protectedGate, err := validation.NewProtectedGate(protectedContract, protectedConfig)
	if err != nil {
		return runtimeSet{}, errors.New("validation worker: protected IPv4 configuration is invalid")
	}

	expectedBinaryDigest := "sha256:" + runtimeConfig.Enforcement.NFTBinaryExpectedSHA256
	syntaxChecker, err := nftvalidator.NewClient(
		runtimeConfig.Enforcement.ValidatorSocket,
		nftvalidator.ExchangeTimeout,
		expectedBinaryDigest,
		runtimeConfig.Enforcement.NFTExpectedVersion,
	)
	if err != nil {
		return runtimeSet{}, errors.New("validation worker: configure isolated nftables validator client")
	}

	pool, err := openValidationPool(ctx, runtimeConfig)
	if err != nil {
		return runtimeSet{}, err
	}
	failed := true
	defer func() {
		if failed {
			pool.Close()
		}
	}()

	store, err := buildValidationStore(ctx, pool, runtimeConfig)
	if err != nil {
		return runtimeSet{}, errors.New("validation worker: configure atomic validation store")
	}
	workerConfig := validationloop.DefaultConfig(
		validationLeaseOwner,
		expectedBinaryDigest,
		runtimeConfig.Enforcement.NFTExpectedVersion,
		artifacts.OutputSchemaDigest(),
		artifacts.PromptDigest(),
	)
	workerConfig.Environment = protectedConfig.Environment
	runtime, err := validationloop.New(store, workerConfig, validationloop.Dependencies{
		ProtectedGate: protectedGate,
		SyntaxChecker: syntaxChecker,
		BaseContract:  baseContract,
		LiveSchema:    liveSchema,
	})
	if err != nil {
		return runtimeSet{}, errors.New("validation worker: configure validation runtime")
	}

	failed = false
	return runtimeSet{runtime: runtime, pool: pool}, nil
}

func buildValidationStore(
	ctx context.Context,
	pool *pgxpool.Pool,
	runtimeConfig config.Config,
) (*validationstore.PostgreSQLStore, error) {
	if runtimeConfig.Environment != config.EnvironmentDemo {
		store, err := validationstore.NewPostgreSQLStore(pool)
		if err != nil {
			return nil, errors.New("validation worker: configure retained validation history store")
		}
		return store, nil
	}

	secret, err := demohistoryactivation.Load(
		runtimeConfig.Demo.HistoryValidationActivationSecretFile,
	)
	if err != nil {
		return nil, errors.New("validation worker: demo activation capability rejected")
	}
	activated, err := demohistoryproof.Attach(ctx, demohistoryproof.Config{
		SignedEnvelopeFile:       runtimeConfig.Demo.HistorySignedEnvelopeFile,
		PublicKeyB64URL:          runtimeConfig.Demo.HistoryPublicKeyB64URL,
		RunScope:                 runtimeConfig.Demo.HistoryRunScope,
		ImportID:                 runtimeConfig.Demo.HistoryImportID,
		ClockAt:                  runtimeConfig.Demo.HistoryClockAt,
		ImpactSourceHealthDigest: runtimeConfig.Demo.HistoryImpactSourceHealthDigest,
	}, pool, validation.DemoHistoryConsumerValidation, secret)
	if err != nil {
		return nil, errors.New("validation worker: attach demo history activation")
	}
	store, err := validationstore.NewPostgreSQLActivatedDemoStore(pool, activated)
	if err != nil {
		return nil, errors.New("validation worker: bind verified demo history ledger")
	}
	return store, nil
}

func openValidationPool(ctx context.Context, runtimeConfig config.Config) (*pgxpool.Pool, error) {
	poolConfig, err := validationPoolConfig(runtimeConfig.Database.WorkerURL.Reveal())
	if err != nil {
		return nil, errors.New("validation worker: invalid database pool configuration")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("validation worker: open database pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("validation worker: database readiness check failed")
	}
	return pool, nil
}

func validationPoolConfig(databaseURL string) (*pgxpool.Config, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil || poolConfig.ConnConfig.User != "sentinelflow_worker" ||
		poolConfig.ConnConfig.Database != "sentinelflow" || len(poolConfig.ConnConfig.RuntimeParams) != 0 {
		return nil, errors.New("invalid validation database configuration")
	}
	poolConfig.MaxConns = validationPoolConns
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	poolConfig.ConnConfig.RuntimeParams = map[string]string{
		"application_name": "sentinelflow-validation-worker",
		"lock_timeout":     validationLockTimeout.String(),
	}
	return poolConfig, nil
}

func validationProtectedConfig(runtimeConfig config.Config) (validation.ProtectedConfig, error) {
	environment, err := validationEnvironment(runtimeConfig.Environment)
	if err != nil {
		return validation.ProtectedConfig{}, err
	}
	profile := validation.DemoExceptionDisabled
	if runtimeConfig.Demo.AllowRFC5737 {
		profile = validation.DemoExceptionIsolatedRFC5737
	}
	return validation.ProtectedConfig{
		Environment:      environment,
		ProtectedCIDRs:   prefixStrings(runtimeConfig.Enforcement.ProtectedCIDRs),
		OriginIPv4:       addressStrings(runtimeConfig.Enforcement.ProtectedOriginIPv4),
		GatewayIPv4:      addressStrings(runtimeConfig.Enforcement.ProtectedGatewayIPv4),
		ExecutorIPv4:     addressStrings(runtimeConfig.Enforcement.ProtectedExecutorIPv4),
		ManagementIPv4:   addressStrings(runtimeConfig.Enforcement.ProtectedManagementIPv4),
		CurrentAdminIPv4: addressStrings(runtimeConfig.Enforcement.ProtectedCurrentAdminIPv4),
		Demo: validation.DemoExceptionConfig{
			Profile: profile, AllowRFC5737: runtimeConfig.Demo.AllowRFC5737,
			IsolationVerified:    runtimeConfig.Demo.EnforcementIsolationVerified,
			HostRulesetUnchanged: runtimeConfig.Demo.HostRulesetUnchanged,
			ClientCIDR:           runtimeConfig.Demo.ClientCIDR.String(),
			AttackSourceIPv4:     runtimeConfig.Demo.AttackSourceIP.String(),
		},
	}, nil
}

func validationEnvironment(value config.Environment) (validation.Environment, error) {
	switch value {
	case config.EnvironmentDevelopment:
		return validation.EnvironmentDevelopment, nil
	case config.EnvironmentTest:
		return validation.EnvironmentTest, nil
	case config.EnvironmentDemo:
		return validation.EnvironmentDemo, nil
	case config.EnvironmentProduction:
		return validation.EnvironmentProduction, nil
	default:
		return "", errors.New("validation worker: invalid validation environment")
	}
}

func prefixStrings(values []netip.Prefix) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func addressStrings(values []netip.Addr) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func readContract(path string, maximum int) ([]byte, error) {
	if path == "" || maximum < 1 {
		return nil, errors.New("invalid contract path")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open contract")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("invalid contract file")
	}
	value, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(value) == 0 || len(value) > maximum {
		return nil, errors.New("read contract")
	}
	return value, nil
}
