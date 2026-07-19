// Command worker runs the OpenAI-backed analysis consumer only. Policy
// validation is deliberately isolated in cmd/validationworker so switching
// analysis providers cannot disable or duplicate the validation hard gates.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/analysisstore"
	"github.com/devwooops/sentinelflow/internal/analysisworker"
	"github.com/devwooops/sentinelflow/internal/buildinfo"
	"github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/demohistoryactivation"
	"github.com/devwooops/sentinelflow/internal/demohistoryproof"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const (
	analysisLeaseOwner = "analysis-worker-01"
	poolSpareConns     = 2
)

var errUnexpectedRuntimeExit = errors.New("worker runtime exited unexpectedly")

type workerRuntime interface {
	Run(context.Context) error
}

type runtimeFailure struct{ cause error }

func (*runtimeFailure) Error() string { return "worker analysis runtime failed" }

func (e *runtimeFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type runtimeSet struct {
	analysis workerRuntime
	pool     *pgxpool.Pool
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger); err != nil {
		logger.Error("worker stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	if ctx == nil || logger == nil {
		return errors.New("worker: runtime dependencies are required")
	}
	runtimeConfig, err := config.Load(config.RoleWorker)
	if err != nil {
		return fmt.Errorf("load worker configuration: %w", err)
	}
	runtimes, err := buildWorkerRuntime(ctx, runtimeConfig)
	if err != nil {
		return err
	}
	defer runtimes.pool.Close()

	logger.Info("OpenAI analysis worker configured",
		"service", buildinfo.Name, "version", buildinfo.Version, "model", ai.Model)
	return superviseRuntime(ctx, runtimes.analysis)
}

func superviseRuntime(ctx context.Context, runtime workerRuntime) error {
	if ctx == nil || runtime == nil {
		return errors.New("worker: analysis runtime is required")
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

func invokeRuntime(ctx context.Context, runtime workerRuntime) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("worker: analysis runtime panic contained")
		}
	}()
	return runtime.Run(ctx)
}

func buildWorkerRuntime(ctx context.Context, runtimeConfig config.Config) (runtimeSet, error) {
	if ctx == nil || runtimeConfig.Role != config.RoleWorker {
		return runtimeSet{}, errors.New("worker: invalid runtime configuration")
	}

	artifacts, err := ai.LoadArtifacts(ai.ArtifactPaths{
		InputSchema:  runtimeConfig.OpenAI.InputSchemaFile,
		SystemPrompt: runtimeConfig.OpenAI.SystemPromptFile,
		OutputSchema: runtimeConfig.OpenAI.OutputSchemaFile,
	})
	if err != nil {
		return runtimeSet{}, errors.New("worker: OpenAI artifacts are invalid")
	}
	pool, err := openWorkerPool(ctx, runtimeConfig)
	if err != nil {
		return runtimeSet{}, err
	}
	failed := true
	defer func() {
		if failed {
			pool.Close()
		}
	}()
	analysisStore, err := buildAnalysisStore(ctx, pool, runtimeConfig)
	if err != nil {
		return runtimeSet{}, errors.New("worker: configure atomic analysis store")
	}

	budgetConfig, err := postgresBudgetConfig(runtimeConfig.OpenAI)
	if err != nil {
		return runtimeSet{}, err
	}
	budget, err := ai.NewPostgreSQLBudgetGate(pool, budgetConfig)
	if err != nil {
		return runtimeSet{}, errors.New("worker: configure AI budget gate")
	}
	analyzer, err := ai.NewClient(ai.ClientConfig{
		APIKey:          runtimeConfig.OpenAI.APIKey.Reveal(),
		RateCardVersion: runtimeConfig.OpenAI.RateCardVersion,
		RequestTimeout:  runtimeConfig.OpenAI.Timeout,
		MaxAttempts:     runtimeConfig.OpenAI.MaxTransientRetries + 1,
		Artifacts:       artifacts,
		Budget:          budget,
	})
	if err != nil {
		return runtimeSet{}, errors.New("worker: configure OpenAI client")
	}
	analysisConfig := analysisworker.DefaultConfig(analysisLeaseOwner, runtimeConfig.OpenAI.RateCardVersion)
	analysisConfig.MaxConcurrency = runtimeConfig.OpenAI.MaxConcurrency
	analysisRuntime, err := analysisworker.New(analysisStore, analyzer, analysisConfig, analysisworker.Dependencies{})
	if err != nil {
		return runtimeSet{}, errors.New("worker: configure analysis runtime")
	}

	failed = false
	return runtimeSet{analysis: analysisRuntime, pool: pool}, nil
}

func buildAnalysisStore(
	ctx context.Context,
	pool *pgxpool.Pool,
	runtimeConfig config.Config,
) (*analysisstore.PostgreSQLStore, error) {
	if runtimeConfig.Environment != config.EnvironmentDemo {
		return analysisstore.NewPostgreSQLStore(pool)
	}
	secret, err := demohistoryactivation.Load(
		runtimeConfig.Demo.HistoryAnalysisActivationSecretFile,
	)
	if err != nil {
		return nil, errors.New("worker: demo activation capability rejected")
	}
	activated, err := demohistoryproof.Attach(ctx, demohistoryproof.Config{
		SignedEnvelopeFile:       runtimeConfig.Demo.HistorySignedEnvelopeFile,
		PublicKeyB64URL:          runtimeConfig.Demo.HistoryPublicKeyB64URL,
		RunScope:                 runtimeConfig.Demo.HistoryRunScope,
		ImportID:                 runtimeConfig.Demo.HistoryImportID,
		ClockAt:                  runtimeConfig.Demo.HistoryClockAt,
		ImpactSourceHealthDigest: runtimeConfig.Demo.HistoryImpactSourceHealthDigest,
	}, pool, validation.DemoHistoryConsumerAnalysis, secret)
	if err != nil {
		return nil, errors.New("worker: demo history activation rejected")
	}
	return analysisstore.NewPostgreSQLActivatedDemoStore(pool, activated)
}

func openWorkerPool(ctx context.Context, runtimeConfig config.Config) (*pgxpool.Pool, error) {
	poolConfig, err := pgxpool.ParseConfig(runtimeConfig.Database.WorkerURL.Reveal())
	if err != nil || poolConfig.ConnConfig.User != "sentinelflow_worker" ||
		poolConfig.ConnConfig.Database != "sentinelflow" || len(poolConfig.ConnConfig.RuntimeParams) != 0 {
		return nil, errors.New("worker: invalid database pool configuration")
	}
	poolConfig.MaxConns = int32(runtimeConfig.OpenAI.MaxConcurrency + poolSpareConns)
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	poolConfig.ConnConfig.RuntimeParams = map[string]string{
		"application_name": "sentinelflow-openai-analysis-worker",
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("worker: open database pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("worker: database readiness check failed")
	}
	return pool, nil
}

func postgresBudgetConfig(openAI config.OpenAIConfig) (ai.PostgreSQLBudgetConfig, error) {
	daily, err := ai.DailyLimitMicroUSD(openAI.DailyBudgetUSD)
	if err != nil {
		return ai.PostgreSQLBudgetConfig{}, errors.New("worker: invalid AI daily budget")
	}
	input, err := ai.MicroUSDPerMillion(openAI.InputUSDPerMillion)
	if err != nil {
		return ai.PostgreSQLBudgetConfig{}, errors.New("worker: invalid AI input rate")
	}
	cached, err := ai.MicroUSDPerMillion(openAI.CachedInputUSDPerMillion)
	if err != nil {
		return ai.PostgreSQLBudgetConfig{}, errors.New("worker: invalid AI cached-input rate")
	}
	output, err := ai.MicroUSDPerMillion(openAI.OutputUSDPerMillion)
	if err != nil {
		return ai.PostgreSQLBudgetConfig{}, errors.New("worker: invalid AI output rate")
	}
	return ai.PostgreSQLBudgetConfig{
		Model:                         ai.Model,
		RateCardVersion:               openAI.RateCardVersion,
		DailyLimitMicroUSD:            daily,
		InputMicroUSDPerMillion:       input,
		CachedInputMicroUSDPerMillion: cached,
		OutputMicroUSDPerMillion:      output,
	}, nil
}
