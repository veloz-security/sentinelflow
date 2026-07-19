package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/devwooops/sentinelflow/internal/demohistoryimport"
	"github.com/devwooops/sentinelflow/internal/demohistoryseal"
	"github.com/devwooops/sentinelflow/internal/validation"
)

const testWorkerDatabaseURL = "postgresql://sentinelflow_demo_importer:worker-secret@postgres:5432/sentinelflow?sslmode=disable"

type staticDatasetReader struct{ raw []byte }

func (s staticDatasetReader) ReadPinnedDataset(context.Context) ([]byte, error) {
	return bytes.Clone(s.raw), nil
}

func TestLoadRuntimeConfigAcceptsExactPublicWorkerHandoff(t *testing.T) {
	values, _, _, assertions := validHandoff(t)
	config, err := loadRuntimeConfig(mapGetenv(values), mapEnviron(values))
	if err != nil {
		t.Fatal(err)
	}
	if config.databaseURL != testWorkerDatabaseURL || !publicHandoffMatches(config, assertions) ||
		config.impactSourceHealthDigest != validation.PinnedDemoHistoryImpactSourceHealthDigest {
		t.Fatal("exact public worker handoff did not round-trip")
	}
}

func TestLoadRuntimeConfigRejectsDatabaseURLDriftWithoutLeakingSecret(t *testing.T) {
	base, _, _, _ := validHandoff(t)
	badURLs := []string{
		"postgres://sentinelflow_worker:worker-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://other:worker-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_worker@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_worker:worker-secret@other:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_worker:worker-secret@postgres/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_worker:worker-secret@postgres:05432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_worker:worker-secret@postgres:5432/other?sslmode=disable",
		"postgresql://sentinelflow_worker:worker-secret@postgres:5432/sentinelflow",
		"postgresql://sentinelflow_worker:worker-secret@postgres:5432/sentinelflow?sslmode=verify-full",
		"postgresql://sentinelflow_worker:worker-secret@postgres:5432/sentinelflow?sslmode=disable&options=-crole%3Dadmin",
		"postgresql://sentinelflow_worker:worker-secret@postgres:5432/sentinelflow?sslmode=disable#fragment",
	}
	for _, candidate := range badURLs {
		values := cloneValues(base)
		values["DATABASE_DEMO_IMPORTER_URL"] = candidate
		_, err := loadRuntimeConfig(mapGetenv(values), mapEnviron(values))
		if err == nil || strings.Contains(err.Error(), "worker-secret") {
			t.Fatalf("unsafe database URL accepted or leaked: %q err=%v", candidate, err)
		}
	}
}

func TestLoadRuntimeConfigRejectsInheritedAndExtraAuthority(t *testing.T) {
	base, _, _, _ := validHandoff(t)
	for _, name := range []string{
		"PGHOST", "PGSERVICE", "PGOPTIONS", "PGPASSWORD", "PGSSLROOTCERT",
		"DATABASE_API_URL", "DATABASE_ADMIN_URL", "DATABASE_ARBITRARY_URL",
		"POSTGRES_PASSWORD", "OPENAI_API_KEY", "OPENAI_ARBITRARY_AUTHORITY",
		"ADMIN_PASSWORD_ARGON2ID_HASH", "ADMIN_ARBITRARY_AUTHORITY", "AUTH_ARBITRARY_SECRET",
		"DISPATCHER_SIGNING_PRIVATE_KEY_FILE", "EXECUTOR_RESULT_PRIVATE_KEY_FILE",
		"NFT_ARBITRARY_AUTHORITY", "VALIDATOR_ARBITRARY_AUTHORITY", "PROTECTED_ARBITRARY_AUTHORITY",
		"DEMO_HISTORY_PUBLIC_KEY_FILE", "DEMO_HISTORY_SIMULATOR_PRIVATE_KEY_FILE",
	} {
		values := cloneValues(base)
		values[name] = "inherited-secret-or-authority"
		_, err := loadRuntimeConfig(mapGetenv(values), mapEnviron(values))
		if err == nil || strings.Contains(err.Error(), values[name]) {
			t.Fatalf("forbidden authority %s accepted or leaked: %v", name, err)
		}
	}
}

func TestLoadRuntimeConfigRejectsPublicAssertionDrift(t *testing.T) {
	base, _, _, assertions := validHandoff(t)
	tests := map[string]func(map[string]string){
		"missing proof": func(values map[string]string) { values["DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST"] = "" },
		"wrong proof": func(values map[string]string) {
			values["DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST"] = "sha256:" + strings.Repeat("9", 64)
		},
		"fixture public key": func(values map[string]string) {
			values["DEMO_HISTORY_PUBLIC_KEY_B64URL"] = validation.PinnedDemoHistoryFixturePublicKey
		},
		"wrong run": func(values map[string]string) {
			values["DEMO_HISTORY_RUN_SCOPE"] = "sentinelflow-demo-run:wrong"
		},
		"wrong import": func(values map[string]string) {
			values["DEMO_HISTORY_IMPORT_ID"] = "wrong"
		},
		"imprecise clock": func(values map[string]string) {
			values["DEMO_HISTORY_CLOCK_AT"] = assertions.ClockAt().Format("2006-01-02T15:04:05Z")
		},
		"dataset path":  func(values map[string]string) { values["DEMO_HISTORY_FIXTURE_DATASET"] = "/tmp/dataset.json" },
		"envelope path": func(values map[string]string) { values["DEMO_HISTORY_SIGNED_ENVELOPE_FILE"] = "/tmp/envelope.json" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			values := cloneValues(base)
			mutate(values)
			if _, err := loadRuntimeConfig(mapGetenv(values), mapEnviron(values)); err == nil {
				t.Fatal("drifted public assertion accepted")
			}
		})
	}
}

func TestRunStagesDatabaseFenceBeforeUntrustedInputsAndProducesNoOutput(t *testing.T) {
	values, dataset, bundle, _ := validHandoff(t)
	tests := []struct {
		name   string
		mutate func(*dependencies, map[string]string)
	}{
		{name: "wrong run", mutate: func(_ *dependencies, values map[string]string) {
			values["DEMO_HISTORY_RUN_SCOPE"] = "sentinelflow-demo-run:019b0000-0000-4000-8000-000000000999"
		}},
		{name: "wrong import", mutate: func(_ *dependencies, values map[string]string) {
			values["DEMO_HISTORY_IMPORT_ID"] = "019b0000-0000-4000-8000-000000000999"
		}},
		{name: "tampered envelope", mutate: func(deps *dependencies, _ map[string]string) {
			tampered := bundle.SignedEnvelope()
			tampered[len(tampered)-2] ^= 1
			deps.readBundle = func(string) ([]byte, []byte, error) {
				return tampered, bundle.PublicAssertions(), nil
			}
		}},
		{name: "failed import database", mutate: func(deps *dependencies, _ map[string]string) {
			deps.openPool = func(context.Context, string) (databasePool, error) {
				return nil, errors.New("database unavailable with secret worker-secret")
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := cloneValues(values)
			var output bytes.Buffer
			openCalls := 0
			pool := &stagedFencePool{}
			deps := dependencies{
				getenv: mapGetenv(current), environ: mapEnviron(current), output: &output,
				datasetRoot: "/app", bundleRoot: "/run/sentinelflow-demo-history",
				readBundle: func(string) ([]byte, []byte, error) {
					return bundle.SignedEnvelope(), bundle.PublicAssertions(), nil
				},
				newReader: func(string) (demohistoryimport.DatasetReader, error) {
					return staticDatasetReader{raw: dataset}, nil
				},
				openPool: func(context.Context, string) (databasePool, error) {
					openCalls++
					return pool, nil
				},
			}
			test.mutate(&deps, current)
			deps.getenv, deps.environ = mapGetenv(current), mapEnviron(current)
			if err := run(context.Background(), deps); err == nil || strings.Contains(err.Error(), "worker-secret") {
				t.Fatalf("unsafe run result: %v", err)
			}
			if output.Len() != 0 {
				t.Fatal("failed import emitted output")
			}
			if test.name != "failed import database" {
				if openCalls != 1 || pool.pingCalls != 1 || pool.closeCalls != 1 ||
					pool.importerFenceCalls != 1 || pool.importerFinalizeCalls != 1 {
					t.Fatalf("staged fence open=%d ping=%d close=%d phases=%d/%d",
						openCalls, pool.pingCalls, pool.closeCalls,
						pool.importerFenceCalls, pool.importerFinalizeCalls)
				}
			}
		})
	}
}

type stagedFenceRow func(...any) error

func (row stagedFenceRow) Scan(destination ...any) error { return row(destination...) }

type stagedFencePool struct {
	pingCalls             int
	closeCalls            int
	importerFenceCalls    int
	importerFinalizeCalls int
}

func (*stagedFencePool) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("unexpected import transaction")
}

func (pool *stagedFencePool) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	switch {
	case strings.Contains(query, "SELECT current_user"):
		return stagedFenceRow(func(destination ...any) error {
			*destination[0].(*string) = importerDatabaseRole
			return nil
		})
	case strings.Contains(query, "fence_demo_history_importer_role_000030"):
		pool.importerFenceCalls++
	case strings.Contains(query, "finalize_demo_history_importer_role_fence_000030"):
		pool.importerFinalizeCalls++
	default:
		return stagedFenceRow(func(...any) error { return pgx.ErrNoRows })
	}
	return stagedFenceRow(func(destination ...any) error {
		*destination[0].(*bool) = true
		return nil
	})
}

func (pool *stagedFencePool) Ping(context.Context) error {
	pool.pingCalls++
	return nil
}

func (pool *stagedFencePool) Close() { pool.closeCalls++ }

func TestSafeResultHasNoAuthorityOrDigestFields(t *testing.T) {
	typeOf := reflect.TypeOf(safeResult{})
	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
		for _, forbidden := range []string{"key", "secret", "password", "database", "digest", "envelope", "signature"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("safe result exposes %q through %s", forbidden, field.Name)
			}
		}
	}
	encoded, err := json.Marshal(safeResult{Status: "completed"})
	if err != nil || bytes.Contains(encoded, []byte("worker-secret")) {
		t.Fatal("safe result encoding is not content-free")
	}
}

func validHandoff(t testing.TB) (map[string]string, []byte, demohistoryseal.Bundle, demohistoryseal.Assertions) {
	t.Helper()
	dataset := readFixtureDataset(t)
	random := make([]byte, 128)
	for index := range random {
		random[index] = byte(index + 17)
	}
	bundle, err := demohistoryseal.Seal(context.Background(), dataset, bytes.NewReader(random))
	if err != nil {
		t.Fatal(err)
	}
	assertions, err := demohistoryseal.ParseAssertions(bundle.PublicAssertions())
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"SENTINELFLOW_ENV":                         "demo",
		"DATABASE_DEMO_IMPORTER_URL":               testWorkerDatabaseURL,
		"DEMO_HISTORY_FIXTURE_DATASET":             datasetFile,
		"DEMO_HISTORY_SIGNED_ENVELOPE_FILE":        envelopeFile,
		"DEMO_HISTORY_PUBLIC_KEY_B64URL":           assertions.PublicKeyB64URL(),
		"DEMO_HISTORY_RUN_SCOPE":                   assertions.RunScope(),
		"DEMO_HISTORY_IMPORT_ID":                   assertions.ImportID(),
		"DEMO_HISTORY_CLOCK_AT":                    assertions.ClockAt().Format("2006-01-02T15:04:05.000Z"),
		"DEMO_HISTORY_IMPACT_SOURCE_HEALTH_DIGEST": assertions.ImpactSourceHealthDigest(),
	}
	return values, dataset, bundle, assertions
}

func readFixtureDataset(t testing.TB) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, validation.DemoHistoryDatasetLocator))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mapGetenv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func mapEnviron(values map[string]string) func() []string {
	return func() []string {
		result := make([]string, 0, len(values))
		for name, value := range values {
			result = append(result, name+"="+value)
		}
		return result
	}
}

func cloneValues(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for name, value := range values {
		result[name] = value
	}
	return result
}
