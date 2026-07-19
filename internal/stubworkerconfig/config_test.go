package stubworkerconfig

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testURL = "postgresql://sentinelflow_worker:stub-secret@postgres:5432/sentinelflow?sslmode=disable"

func TestLoadFromAcceptsOnlyBoundedStubSettings(t *testing.T) {
	t.Parallel()
	config, err := LoadFrom(mapLookup(map[string]string{DatabaseWorkerURLName: testURL}))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Valid() || config.LeaseDuration() != 30*time.Second ||
		config.PollInterval() != 250*time.Millisecond || config.MaxConcurrency() != 2 {
		t.Fatalf("unexpected defaults: %+v", config)
	}
	configured, err := LoadFrom(mapLookup(map[string]string{
		DatabaseWorkerURLName: testURL,
		LeaseDurationName:     "5s", PollIntervalName: "25ms", MaxConcurrencyName: "1",
	}))
	if err != nil || configured.LeaseDuration() != 5*time.Second ||
		configured.PollInterval() != 25*time.Millisecond || configured.MaxConcurrency() != 1 {
		t.Fatalf("configured values = %+v err=%v", configured, err)
	}
}

func TestLoadFromAcceptsPublicDemoProofAndRejectsPartialOrNonDemoProof(t *testing.T) {
	t.Parallel()
	proof := map[string]string{
		DatabaseWorkerURLName: testURL,
		EnvironmentName:       "demo",
		HistoryEnvelopeName:   "/run/sentinelflow-demo-history/signed-manifest.json",
		HistoryPublicKeyName:  base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", 32))),
		HistoryRunScopeName:   "sentinelflow-demo-run:019b0000-0000-4000-8000-000000000901",
		HistoryImportIDName:   "019b0000-0000-4000-8000-000000000902",
		HistoryClockAtName:    "2026-07-18T02:00:00.000Z",
		HistoryImpactName:     "sha256:e2493dd1befd0d0a8ed321b6ff6ee3c0078a91692197c6b90c65d728e17cb1e3",
		HistoryActivationName: "/run/secrets/sentinelflow-demo-history-analysis/activation-capability",
	}
	config, err := LoadFrom(mapLookup(proof))
	loaded, ok := config.DemoHistoryProof()
	if err != nil || !config.Valid() || !config.DemoMode() || !ok ||
		loaded.ImportID != proof[HistoryImportIDName] || loaded.SignedEnvelopeFile != proof[HistoryEnvelopeName] {
		t.Fatalf("config=%+v proof=%+v ok=%v err=%v", config, loaded, ok, err)
	}

	for _, name := range []string{
		HistoryEnvelopeName, HistoryPublicKeyName, HistoryRunScopeName,
		HistoryImportIDName, HistoryClockAtName, HistoryImpactName,
		HistoryActivationName,
	} {
		values := cloneValues(proof)
		delete(values, name)
		if _, err := LoadFrom(mapLookup(values)); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("missing %s error=%v", name, err)
		}
	}
	nondemo := cloneValues(proof)
	nondemo[EnvironmentName] = "production"
	if _, err := LoadFrom(mapLookup(nondemo)); !errors.Is(err, ErrForbiddenAuthority) {
		t.Fatalf("non-demo proof error=%v", err)
	}
}

func TestLoadFromRejectsForbiddenAuthority(t *testing.T) {
	t.Parallel()
	for _, name := range forbiddenNames {
		name := name
		t.Run(name, func(t *testing.T) {
			values := map[string]string{DatabaseWorkerURLName: testURL, name: "inherited-secret-or-authority"}
			_, err := LoadFrom(mapLookup(values))
			if !errors.Is(err, ErrForbiddenAuthority) || strings.Contains(err.Error(), values[name]) {
				t.Fatalf("unsafe rejection for %s: %v", name, err)
			}
		})
	}
}

func TestLoadFromRejectsDatabaseAndBoundDriftWithoutLeakingSecrets(t *testing.T) {
	t.Parallel()
	badURLs := []string{
		"postgres://sentinelflow_worker:stub-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://other:stub-secret@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_worker@postgres:5432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_worker:stub-secret@postgres/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_worker:stub-secret@postgres:05432/sentinelflow?sslmode=disable",
		"postgresql://sentinelflow_worker:stub-secret@postgres:5432/a/b?sslmode=disable",
		"postgresql://sentinelflow_worker:stub-secret@postgres:5432/sentinelflow",
		"postgresql://sentinelflow_worker:stub-secret@postgres:5432/sentinelflow?sslmode=prefer",
		"postgresql://sentinelflow_worker:stub-secret@postgres:5432/sentinelflow?sslmode=disable&options=-crole%3Dadmin",
		"postgresql://sentinelflow_worker:stub-secret@postgres:5432/sentinelflow?sslmode=disable#fragment",
	}
	for _, value := range badURLs {
		_, err := LoadFrom(mapLookup(map[string]string{DatabaseWorkerURLName: value}))
		if !errors.Is(err, ErrInvalidConfiguration) || strings.Contains(err.Error(), "stub-secret") {
			t.Fatalf("unsafe URL rejection for %q: %v", value, err)
		}
	}
	for name, values := range map[string][]string{
		LeaseDurationName:  {"4s", "61s", " 30s", "30.0s"},
		PollIntervalName:   {"24ms", "6s", " 250ms", "0.25s"},
		MaxConcurrencyName: {"0", "3", "01", " 2"},
	} {
		for _, value := range values {
			_, err := LoadFrom(mapLookup(map[string]string{DatabaseWorkerURLName: testURL, name: value}))
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("%s=%q accepted: %v", name, value, err)
			}
		}
	}
}

func TestConfigFormattingAlwaysRedactsDatabaseURL(t *testing.T) {
	t.Parallel()
	config, err := LoadFrom(mapLookup(map[string]string{DatabaseWorkerURLName: testURL}))
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{fmt.Sprint(config), fmt.Sprintf("%+v", config), fmt.Sprintf("%#v", config)} {
		if strings.Contains(formatted, "stub-secret") || strings.Contains(formatted, testURL) {
			t.Fatalf("configuration formatting leaked URL: %s", formatted)
		}
	}
}

func mapLookup(values map[string]string) LookupFunc {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func cloneValues(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for name, value := range values {
		result[name] = value
	}
	return result
}
