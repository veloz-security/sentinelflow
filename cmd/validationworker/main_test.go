package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devwooops/sentinelflow/internal/config"
)

func TestSuperviseRuntimeRedactsFailure(t *testing.T) {
	t.Parallel()
	secret := "validation-row-must-not-leak"
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

func TestValidationProtectedConfigBindsRuntimeAndDemoInputs(t *testing.T) {
	t.Parallel()
	base := config.Config{Environment: config.EnvironmentProduction}
	base.Enforcement.ProtectedCIDRs = []netip.Prefix{netip.MustParsePrefix("8.8.4.0/24")}
	base.Enforcement.ProtectedOriginIPv4 = []netip.Addr{netip.MustParseAddr("10.0.0.10")}
	base.Enforcement.ProtectedGatewayIPv4 = []netip.Addr{netip.MustParseAddr("10.0.0.20")}
	base.Enforcement.ProtectedCurrentAdminIPv4 = []netip.Addr{netip.MustParseAddr("8.8.8.8")}
	base.Demo.ClientCIDR = netip.MustParsePrefix("203.0.113.0/24")
	base.Demo.AttackSourceIP = netip.MustParseAddr("203.0.113.20")
	got, err := validationProtectedConfig(base)
	if err != nil || got.Environment != "production" ||
		len(got.ProtectedCIDRs) != 1 || len(got.OriginIPv4) != 1 ||
		len(got.GatewayIPv4) != 1 || len(got.ExecutorIPv4) != 0 ||
		len(got.CurrentAdminIPv4) != 1 || got.Demo.Profile != "disabled" {
		t.Fatalf("config=%+v err=%v", got, err)
	}

	base.Environment = config.EnvironmentDemo
	base.Demo.AllowRFC5737 = true
	base.Demo.EnforcementIsolationVerified = true
	base.Demo.HostRulesetUnchanged = true
	got, err = validationProtectedConfig(base)
	if err != nil || got.Demo.Profile != "isolated-rfc5737" ||
		!got.Demo.AllowRFC5737 || !got.Demo.IsolationVerified || !got.Demo.HostRulesetUnchanged {
		t.Fatalf("demo config=%+v err=%v", got, err)
	}
}

func TestReadContractIsBounded(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "contract")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := readContract(path, 3); err != nil || string(value) != "abc" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	if _, err := readContract(path, 2); err == nil {
		t.Fatal("oversized contract accepted")
	}
	if _, err := readContract(t.TempDir(), 16); err == nil {
		t.Fatal("non-regular contract accepted")
	}
}

func TestBuildValidationRuntimeRejectsAnalysisRole(t *testing.T) {
	t.Parallel()
	_, err := buildValidationRuntime(t.Context(), config.Config{Role: config.RoleWorker})
	if err == nil {
		t.Fatal("analysis role accepted by validation runtime")
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
	t.Setenv("NFT_BINARY_EXPECTED_SHA256", strings.Repeat("a", 64))
	t.Setenv("NFT_EXPECTED_VERSION", "nftables v1.1.1")
	t.Setenv("PROTECTED_CURRENT_ADMIN_IPV4", "8.8.8.8")
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	err := run(t.Context(), logger)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("run error was not safely redacted: %v", err)
	}
}

func TestValidationPoolConfigPinsRuntimeParameters(t *testing.T) {
	t.Parallel()
	poolConfig, err := validationPoolConfig(
		"postgresql://sentinelflow_worker:test@127.0.0.1:5432/sentinelflow?sslmode=disable",
	)
	if err != nil {
		t.Fatal(err)
	}
	parameters := poolConfig.ConnConfig.RuntimeParams
	if len(parameters) != 2 ||
		parameters["application_name"] != "sentinelflow-validation-worker" ||
		parameters["lock_timeout"] != "2s" {
		t.Fatalf("runtime parameters=%v", parameters)
	}
}

func TestValidationPoolConfigRejectsDSNRuntimeParameters(t *testing.T) {
	t.Parallel()
	for _, query := range []string{
		"application_name=untrusted",
		"lock_timeout=0",
		"statement_timeout=0",
		"options=-c%20lock_timeout%3D0",
	} {
		query := query
		t.Run(query, func(t *testing.T) {
			databaseURL := "postgresql://sentinelflow_worker:test@127.0.0.1:5432/sentinelflow?sslmode=disable&" + query
			if poolConfig, err := validationPoolConfig(databaseURL); err == nil || poolConfig != nil {
				t.Fatalf("unsafe DSN parameter accepted: config=%v err=%v", poolConfig, err)
			}
		})
	}
}

type runtimeFunc func(context.Context) error

func (function runtimeFunc) Run(ctx context.Context) error { return function(ctx) }
