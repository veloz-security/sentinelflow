package main

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	configpkg "github.com/devwooops/sentinelflow/internal/config"
	"github.com/devwooops/sentinelflow/internal/demohistoryactivation"
	"github.com/devwooops/sentinelflow/internal/demohistoryproof"
	"github.com/devwooops/sentinelflow/internal/validation"
)

type activatorTestRow func(...any) error

func (row activatorTestRow) Scan(destination ...any) error { return row(destination...) }

type activatorTestPool struct {
	events        *[]string
	role          string
	pingErr       error
	fencePhaseOne bool
	fencePhaseTwo bool
	closeCalls    int
}

func (pool *activatorTestPool) Ping(context.Context) error {
	*pool.events = append(*pool.events, "ping")
	return pool.pingErr
}

func (pool *activatorTestPool) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	switch {
	case strings.Contains(query, "SELECT current_user"):
		*pool.events = append(*pool.events, "current-role")
		return activatorTestRow(func(destination ...any) error {
			*destination[0].(*string) = pool.role
			return nil
		})
	case strings.Contains(query, "fence_demo_history_bootstrap_roles_000030"):
		*pool.events = append(*pool.events, "fence-phase-one")
		return activatorTestRow(func(destination ...any) error {
			*destination[0].(*bool) = pool.fencePhaseOne
			return nil
		})
	case strings.Contains(query, "finalize_demo_history_bootstrap_role_fence_000030"):
		*pool.events = append(*pool.events, "fence-phase-two")
		return activatorTestRow(func(destination ...any) error {
			*destination[0].(*bool) = pool.fencePhaseTwo
			return nil
		})
	default:
		return activatorTestRow(func(...any) error { return pgx.ErrNoRows })
	}
}

func (pool *activatorTestPool) Close() {
	pool.closeCalls++
	*pool.events = append(*pool.events, "close")
}

func TestLoadConfigAcceptsOnlyExactDemoActivationHandoff(t *testing.T) {
	env := validActivatorEnvironment()
	config, err := loadConfig(mapActivatorLookup(env), mapActivatorEnviron(env))
	if err != nil {
		t.Fatal(err)
	}
	if config.databaseURL != env[activatorURLName] ||
		config.analysisSecret != configpkg.DemoHistoryAnalysisActivationPath ||
		config.validationSecret != configpkg.DemoHistoryValidationActivationPath ||
		config.proof.SignedEnvelopeFile != signedEnvelopePath ||
		config.proof.ImportID != env["DEMO_HISTORY_IMPORT_ID"] ||
		config.proof.ImpactSourceHealthDigest != validation.PinnedDemoHistoryImpactSourceHealthDigest {
		t.Fatalf("unexpected activator config: %+v", config)
	}
	if config.proof.ClockAt.Format("2006-01-02T15:04:05.000Z") != env["DEMO_HISTORY_CLOCK_AT"] {
		t.Fatalf("clock_at=%s", config.proof.ClockAt)
	}
}

func TestLoadConfigRejectsMissingNonDemoAndWrongPaths(t *testing.T) {
	for _, field := range []string{
		"SENTINELFLOW_ENV", activatorURLName, analysisSecretName, validationSecretName,
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE", "DEMO_HISTORY_PUBLIC_KEY_B64URL",
		"DEMO_HISTORY_RUN_SCOPE", "DEMO_HISTORY_IMPORT_ID", "DEMO_HISTORY_CLOCK_AT",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST",
	} {
		t.Run("missing_"+field, func(t *testing.T) {
			env := validActivatorEnvironment()
			delete(env, field)
			if _, err := loadConfig(mapActivatorLookup(env), mapActivatorEnviron(env)); err == nil {
				t.Fatalf("missing %s accepted", field)
			}
		})
	}
	for _, environment := range []string{"development", "test", "production", " demo "} {
		t.Run("environment_"+strings.TrimSpace(environment), func(t *testing.T) {
			env := validActivatorEnvironment()
			env["SENTINELFLOW_ENV"] = environment
			if _, err := loadConfig(mapActivatorLookup(env), mapActivatorEnviron(env)); err == nil {
				t.Fatalf("environment %q accepted", environment)
			}
		})
	}
	for _, mutation := range []func(map[string]string){
		func(env map[string]string) { env[analysisSecretName] = configpkg.DemoHistoryValidationActivationPath },
		func(env map[string]string) { env[validationSecretName] = configpkg.DemoHistoryAnalysisActivationPath },
		func(env map[string]string) { env[analysisSecretName] = "/run/secrets/analysis/../capability" },
		func(env map[string]string) { env["DEMO_HISTORY_SIGNED_ENVELOPE_FILE"] = "/tmp/signed-manifest.json" },
	} {
		env := validActivatorEnvironment()
		mutation(env)
		if _, err := loadConfig(mapActivatorLookup(env), mapActivatorEnviron(env)); err == nil {
			t.Fatal("wrong or swapped authority path accepted")
		}
	}
}

func TestLoadConfigRejectsInheritedAuthorityWithoutLeakingValues(t *testing.T) {
	for _, field := range []string{
		"DATABASE_WORKER_URL", "DATABASE_DEMO_IMPORTER_URL", "DATABASE_API_URL",
		"OPENAI_API_KEY", "ADMIN_PASSWORD_ARGON2ID_HASH", "SESSION_HMAC_KEY",
		"HIL_REAUTH_AFTER", "DISPATCHER_SIGNING_PRIVATE_KEY_FILE",
		"EXECUTOR_RESULT_PRIVATE_KEY_FILE", "NFT_BINARY", "AUTH_EVENT_HMAC_KEY",
		"GATEWAY_EVENT_HMAC_KEY", "PGPASSWORD", "POSTGRES_PASSWORD",
		"DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE", "DEMO_HISTORY_PUBLIC_KEY_FILE",
	} {
		t.Run(field, func(t *testing.T) {
			env := validActivatorEnvironment()
			secret := "forbidden-secret-" + strings.ToLower(field)
			env[field] = secret
			_, err := loadConfig(mapActivatorLookup(env), mapActivatorEnviron(env))
			if err == nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("field=%s err=%v", field, err)
			}
		})
	}
}

func TestLoadConfigRejectsNonCanonicalDatabaseAndPublicKey(t *testing.T) {
	for _, raw := range []string{
		"postgresql://sentinelflow_worker:secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_demo_activator@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_demo_activator:secret@localhost:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_demo_activator:secret@postgres:5432/sentinelflow?sslmode=require",
		"postgresql://sentinelflow_demo_activator:secret@postgres:5432/sentinelflow?sslmode=disable&options=-crole%3Dpostgres",
	} {
		env := validActivatorEnvironment()
		env[activatorURLName] = raw
		if _, err := loadConfig(mapActivatorLookup(env), mapActivatorEnviron(env)); err == nil || strings.Contains(err.Error(), raw) {
			t.Fatalf("database URL accepted or leaked: %v", err)
		}
	}
	for _, key := range []string{"bad", validation.PinnedDemoHistoryFixturePublicKey,
		base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 31)))} {
		env := validActivatorEnvironment()
		env["DEMO_HISTORY_PUBLIC_KEY_B64URL"] = key
		if _, err := loadConfig(mapActivatorLookup(env), mapActivatorEnviron(env)); err == nil || strings.Contains(err.Error(), key) {
			t.Fatalf("public key accepted or leaked: %v", err)
		}
	}
}

func TestRunConnectsBeforeUntrustedInputsAndFencesEveryConnectedFailure(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(map[string]string, *activatorDependencies)
		wantLoads  int
		wantActive int
	}{
		{
			name: "environment rejected",
			mutate: func(environment map[string]string, _ *activatorDependencies) {
				environment["DEMO_HISTORY_RUN_SCOPE"] = "sentinelflow-demo-run:wrong"
			},
		},
		{
			name: "analysis capability rejected",
			mutate: func(_ map[string]string, deps *activatorDependencies) {
				deps.loadSecret = func(string) (demohistoryactivation.Secret, error) {
					return demohistoryactivation.Secret{}, errors.New("secret detail must not leak")
				}
			},
			wantLoads: 1,
		},
		{
			name: "validation capability rejected",
			mutate: func(_ map[string]string, deps *activatorDependencies) {
				calls := 0
				deps.loadSecret = func(string) (demohistoryactivation.Secret, error) {
					calls++
					if calls == 2 {
						return demohistoryactivation.Secret{}, errors.New("secret detail must not leak")
					}
					return demohistoryactivation.Secret{}, nil
				}
			},
			wantLoads: 2,
		},
		{
			name: "activation rejected",
			mutate: func(_ map[string]string, deps *activatorDependencies) {
				deps.activate = func(context.Context, demohistoryproof.Config,
					validation.DemoHistoryActivationDB, demohistoryactivation.Secret,
					demohistoryactivation.Secret) error {
					return errors.New("database detail must not leak")
				}
			},
			wantLoads: 2, wantActive: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := validActivatorEnvironment()
			events := make([]string, 0, 12)
			pool := &activatorTestPool{
				events: &events, role: activatorDatabaseRole, fencePhaseOne: true, fencePhaseTwo: true,
			}
			loadCalls, activateCalls := 0, 0
			deps := activatorDependencies{
				lookup: mapActivatorLookup(environment),
				environ: func() []string {
					events = append(events, "environment")
					return mapActivatorEnviron(environment)()
				},
				openPool: func(context.Context, *pgxpool.Config) (activatorPool, error) {
					events = append(events, "open")
					return pool, nil
				},
				loadSecret: func(string) (demohistoryactivation.Secret, error) {
					return demohistoryactivation.Secret{}, nil
				},
				activate: func(context.Context, demohistoryproof.Config,
					validation.DemoHistoryActivationDB, demohistoryactivation.Secret,
					demohistoryactivation.Secret) error {
					return nil
				},
			}
			test.mutate(environment, &deps)
			originalLoad := deps.loadSecret
			deps.loadSecret = func(path string) (demohistoryactivation.Secret, error) {
				loadCalls++
				return originalLoad(path)
			}
			originalActivate := deps.activate
			deps.activate = func(ctx context.Context, config demohistoryproof.Config,
				db validation.DemoHistoryActivationDB, analysis demohistoryactivation.Secret,
				validationSecret demohistoryactivation.Secret) error {
				activateCalls++
				return originalActivate(ctx, config, db, analysis, validationSecret)
			}

			err := run(context.Background(), deps)
			if err == nil || strings.Contains(err.Error(), "detail must not leak") {
				t.Fatalf("unsafe run result: %v", err)
			}
			if len(events) < 7 || events[0] != "open" || events[1] != "ping" ||
				events[2] != "current-role" || events[len(events)-3] != "fence-phase-one" ||
				events[len(events)-2] != "fence-phase-two" || events[len(events)-1] != "close" {
				t.Fatalf("unexpected staging events: %v", events)
			}
			if loadCalls != test.wantLoads || activateCalls != test.wantActive || pool.closeCalls != 1 {
				t.Fatalf("loads=%d activate=%d close=%d", loadCalls, activateCalls, pool.closeCalls)
			}
		})
	}
}

func TestRunSuccessFencesExactlyOnceBeforeClosing(t *testing.T) {
	environment := validActivatorEnvironment()
	events := make([]string, 0, 12)
	pool := &activatorTestPool{
		events: &events, role: activatorDatabaseRole, fencePhaseOne: true, fencePhaseTwo: true,
	}
	deps := activatorDependencies{
		lookup: mapActivatorLookup(environment), environ: mapActivatorEnviron(environment),
		openPool: func(context.Context, *pgxpool.Config) (activatorPool, error) {
			events = append(events, "open")
			return pool, nil
		},
		loadSecret: func(path string) (demohistoryactivation.Secret, error) {
			events = append(events, "load:"+path)
			return demohistoryactivation.Secret{}, nil
		},
		activate: func(context.Context, demohistoryproof.Config, validation.DemoHistoryActivationDB,
			demohistoryactivation.Secret, demohistoryactivation.Secret) error {
			events = append(events, "activate")
			return nil
		},
	}
	if err := run(context.Background(), deps); err != nil {
		t.Fatal(err)
	}
	wantTail := []string{"activate", "fence-phase-one", "fence-phase-two", "close"}
	if len(events) < len(wantTail) || strings.Join(events[len(events)-len(wantTail):], ",") != strings.Join(wantTail, ",") {
		t.Fatalf("success did not fence before close: %v", events)
	}
	if pool.closeCalls != 1 {
		t.Fatalf("close calls=%d", pool.closeCalls)
	}
}

func validActivatorEnvironment() map[string]string {
	return map[string]string{
		"SENTINELFLOW_ENV":                         "demo",
		activatorURLName:                           "postgresql://sentinelflow_demo_activator:test-password@postgres:5432/sentinelflow?sslmode=disable",
		analysisSecretName:                         configpkg.DemoHistoryAnalysisActivationPath,
		validationSecretName:                       configpkg.DemoHistoryValidationActivationPath,
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE":        signedEnvelopePath,
		"DEMO_HISTORY_PUBLIC_KEY_B64URL":           base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", 32))),
		"DEMO_HISTORY_RUN_SCOPE":                   "sentinelflow-demo-run:019b0000-0000-7000-8000-000000000901",
		"DEMO_HISTORY_IMPORT_ID":                   "019b0000-0000-7000-8000-000000000902",
		"DEMO_HISTORY_CLOCK_AT":                    "2026-07-18T02:00:00.000Z",
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST": validation.PinnedDemoHistoryImpactSourceHealthDigest,
	}
}

func mapActivatorLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func mapActivatorEnviron(values map[string]string) func() []string {
	return func() []string {
		result := make([]string, 0, len(values))
		for name, value := range values {
			result = append(result, name+"="+value)
		}
		return result
	}
}
