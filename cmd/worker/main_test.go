package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/ai"
	"github.com/devwooops/sentinelflow/internal/config"
)

func TestSuperviseRuntimeRedactsFailure(t *testing.T) {
	t.Parallel()
	secret := "database-row-must-not-leak"
	err := superviseRuntime(context.Background(), runtimeFunc(func(context.Context) error {
		return errors.New(secret)
	}))
	var failure *runtimeFailure
	if !errors.As(err, &failure) || !errors.Is(err, failure.cause) || strings.Contains(err.Error(), secret) {
		t.Fatalf("failure=%+v err=%v", failure, err)
	}
}

func TestSuperviseRuntimeTreatsParentCancellationAsCleanShutdown(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- superviseRuntime(ctx, runtimeFunc(func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}))
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("clean shutdown error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop")
	}
}

func TestSuperviseRuntimeTreatsSuccessfulExitAsFailure(t *testing.T) {
	t.Parallel()
	err := superviseRuntime(context.Background(), runtimeFunc(func(context.Context) error { return nil }))
	if !errors.Is(err, errUnexpectedRuntimeExit) {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestSuperviseRuntimeContainsPanic(t *testing.T) {
	t.Parallel()
	err := superviseRuntime(context.Background(), runtimeFunc(func(context.Context) error {
		panic("must not escape")
	}))
	var failure *runtimeFailure
	if !errors.As(err, &failure) || failure.cause == nil {
		t.Fatalf("panic was not contained: %v", err)
	}
}

func TestPostgresBudgetConfigUsesConservativeIntegerPrecision(t *testing.T) {
	t.Parallel()
	input := config.OpenAIConfig{
		RateCardVersion:          "operator-2026-07-18",
		DailyBudgetUSD:           10.0000009,
		InputUSDPerMillion:       1.0000001,
		CachedInputUSDPerMillion: 0.2500001,
		OutputUSDPerMillion:      5.0000001,
	}
	value, err := postgresBudgetConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if value.Model != ai.Model || value.RateCardVersion != input.RateCardVersion ||
		value.DailyLimitMicroUSD != 10_000_000 || value.InputMicroUSDPerMillion != 1_000_001 ||
		value.CachedInputMicroUSDPerMillion != 250_001 || value.OutputMicroUSDPerMillion != 5_000_001 {
		t.Fatalf("budget config = %+v", value)
	}
}

func TestPostgresBudgetConfigRejectsMissingRates(t *testing.T) {
	t.Parallel()
	valid := config.OpenAIConfig{
		RateCardVersion: "operator-v1", DailyBudgetUSD: 10,
		InputUSDPerMillion: 1, CachedInputUSDPerMillion: 0.25, OutputUSDPerMillion: 5,
	}
	for _, mutate := range []func(*config.OpenAIConfig){
		func(value *config.OpenAIConfig) { value.DailyBudgetUSD = 0 },
		func(value *config.OpenAIConfig) { value.InputUSDPerMillion = 0 },
		func(value *config.OpenAIConfig) { value.CachedInputUSDPerMillion = 0 },
		func(value *config.OpenAIConfig) { value.OutputUSDPerMillion = 0 },
	} {
		input := valid
		mutate(&input)
		if _, err := postgresBudgetConfig(input); err == nil {
			t.Fatal("invalid budget configuration accepted")
		}
	}
}

func TestRunRequiresLoggerBeforeReadingConfiguration(t *testing.T) {
	t.Parallel()
	if err := run(t.Context(), nil); err == nil {
		t.Fatal("nil logger accepted")
	}
}

func TestRunDoesNotExposeDatabaseSecretOnConfigurationFailure(t *testing.T) {
	secret := "database-password-must-not-leak"
	t.Setenv("DATABASE_WORKER_URL", "postgresql://sentinelflow_worker:"+secret+"@%invalid:5432/sentinelflow?sslmode=disable")
	t.Setenv("OPENAI_API_KEY", "sk-local-test-value")
	t.Setenv("OPENAI_RATE_CARD_VERSION", "operator-v1")
	t.Setenv("OPENAI_INPUT_USD_PER_1M_TOKENS", "1")
	t.Setenv("OPENAI_CACHED_INPUT_USD_PER_1M_TOKENS", "0.25")
	t.Setenv("OPENAI_OUTPUT_USD_PER_1M_TOKENS", "5")
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	err := run(t.Context(), logger)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("run error was not safely redacted: %v", err)
	}
	if errors.Is(err, ai.ErrBudgetExhausted) {
		t.Fatalf("unexpected budget result: %v", err)
	}
}

type runtimeFunc func(context.Context) error

func (function runtimeFunc) Run(ctx context.Context) error { return function(ctx) }
