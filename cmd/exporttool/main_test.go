package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/devwooops/sentinelflow/internal/exportbundle"
)

func TestVerifyModeIsOfflineAndEmitsOnlySafeResult(t *testing.T) {
	var output bytes.Buffer
	databaseOpened := false
	deps := testDependencies(&output)
	deps.openPool = func(context.Context, string) (databasePool, error) {
		databaseOpened = true
		return nil, errors.New("must not run")
	}
	deps.verifyFile = func(path string) (exportbundle.Bundle, exportbundle.Result, error) {
		if path != "/tmp/private-export.json" {
			t.Fatalf("path=%q", path)
		}
		return exportbundle.Bundle{}, exportbundle.Result{
			ExportID:       "sha256:" + strings.Repeat("a", 64),
			ManifestDigest: "sha256:" + strings.Repeat("b", 64),
			BundleDigest:   "sha256:" + strings.Repeat("c", 64),
			IncidentCount:  2, AuditEventCount: 3,
		}, nil
	}
	if err := run(t.Context(), []string{"verify", "--input", "/tmp/private-export.json"}, deps); err != nil {
		t.Fatal(err)
	}
	if databaseOpened || strings.Contains(output.String(), "secret") ||
		!strings.Contains(output.String(), `"incident_count":2`) ||
		!strings.Contains(output.String(), `"output_path":"/tmp/private-export.json"`) {
		t.Fatalf("databaseOpened=%v output=%q", databaseOpened, output.String())
	}
}

func TestCreateRejectsInheritedAuthorityBeforeReadingSecretsOrDatabase(t *testing.T) {
	var output bytes.Buffer
	deps := testDependencies(&output)
	deps.environ = func() []string {
		return []string{
			"SENTINELFLOW_ENV=test",
			"DATABASE_READ_URL=postgresql://sentinelflow_read:read@127.0.0.1:5432/sentinelflow?sslmode=disable",
			"OPENAI_API_KEY=must-not-be-inherited",
		}
	}
	keyRead := false
	deps.readKey = func(string) ([]byte, error) {
		keyRead = true
		return nil, errors.New("must not run")
	}
	err := run(t.Context(), []string{
		"create", "--output", "/tmp/export.json", "--pseudonym-key-file", "/tmp/key",
		"--pseudonym-key-id", "key-v1", "--since", "2026-07-18T00:00:00Z",
		"--until", "2026-07-18T01:00:00Z",
	}, deps)
	if err == nil || keyRead {
		t.Fatalf("err=%v keyRead=%v", err, keyRead)
	}
}

func TestCommandAndCanonicalTimeInputsFailClosed(t *testing.T) {
	var output bytes.Buffer
	deps := testDependencies(&output)
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"verify"},
		{"verify", "--input", "/tmp/a", "extra"},
		{"create", "--output", "/tmp/a"},
	} {
		if err := run(t.Context(), args, deps); err == nil {
			t.Fatalf("args=%q accepted", args)
		}
	}
	for _, value := range []string{
		"2026-07-18T09:00:00+09:00", "2026-07-18 00:00:00Z", "2026-07-18T00:00:00.000Z",
	} {
		if _, err := parseCanonicalTime(value); err == nil {
			t.Fatalf("time=%q accepted", value)
		}
	}
}

func testDependencies(output *bytes.Buffer) dependencies {
	return dependencies{
		getenv: func(name string) string {
			switch name {
			case exportbundle.EnvironmentName:
				return "test"
			case exportbundle.DatabaseURLName:
				return "postgresql://sentinelflow_read:read@127.0.0.1:5432/sentinelflow?sslmode=disable"
			default:
				return ""
			}
		},
		environ: func() []string { return nil },
		openPool: func(context.Context, string) (databasePool, error) {
			return nil, errors.New("not implemented")
		},
		readKey: func(string) ([]byte, error) { return nil, errors.New("not implemented") },
		writeBundle: func(string, exportbundle.Bundle) (exportbundle.Result, error) {
			return exportbundle.Result{}, errors.New("not implemented")
		},
		verifyFile: func(string) (exportbundle.Bundle, exportbundle.Result, error) {
			return exportbundle.Bundle{}, exportbundle.Result{}, errors.New("not implemented")
		},
		output: output,
	}
}
