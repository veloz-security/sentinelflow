// Command exporttool creates and verifies bounded, privacy-preserving incident
// and audit exports. Create mode transitions an exact one-capability deployment
// login to sentinelflow_read; verify mode is entirely offline.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/devwooops/sentinelflow/internal/exportbundle"
)

const (
	defaultMaxIncidents = 1000
	defaultMaxAudit     = 10_000
)

type databasePool interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	Ping(context.Context) error
	Close()
}

type dependencies struct {
	getenv      func(string) string
	environ     func() []string
	openPool    func(context.Context, string) (databasePool, error)
	readKey     func(string) ([]byte, error)
	writeBundle func(string, exportbundle.Bundle) (exportbundle.Result, error)
	verifyFile  func(string) (exportbundle.Bundle, exportbundle.Result, error)
	output      io.Writer
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], productionDependencies()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sentinelflow export failed")
		os.Exit(1)
	}
}

func productionDependencies() dependencies {
	return dependencies{
		getenv: os.Getenv, environ: os.Environ,
		openPool: func(ctx context.Context, databaseURL string) (databasePool, error) {
			config, err := pgxpool.ParseConfig(databaseURL)
			if err != nil || !exportbundle.ValidReadLoginRole(config.ConnConfig.User) ||
				config.ConnConfig.Database != "sentinelflow" || config.ConnConfig.Password == "" ||
				len(config.ConnConfig.RuntimeParams) != 0 {
				return nil, errors.New("export database configuration rejected")
			}
			config.MinConns = 1
			config.MaxConns = 1
			config.MaxConnLifetime = 5 * time.Minute
			config.MaxConnIdleTime = time.Minute
			config.ConnConfig.RuntimeParams["application_name"] = "sentinelflow-export-tool"
			pool, err := pgxpool.NewWithConfig(ctx, config)
			if err != nil {
				return nil, errors.New("export database unavailable")
			}
			return pool, nil
		},
		readKey: exportbundle.ReadPseudonymKey, writeBundle: exportbundle.WriteBundle,
		verifyFile: exportbundle.VerifyFile, output: os.Stdout,
	}
}

func run(ctx context.Context, args []string, deps dependencies) error {
	if ctx == nil || len(args) == 0 || deps.getenv == nil || deps.environ == nil ||
		deps.openPool == nil || deps.readKey == nil || deps.writeBundle == nil ||
		deps.verifyFile == nil || deps.output == nil {
		return errors.New("export dependencies rejected")
	}
	switch args[0] {
	case "create":
		return runCreate(ctx, args[1:], deps)
	case "verify":
		return runVerify(args[1:], deps)
	default:
		return errors.New("export command rejected")
	}
}

func runCreate(ctx context.Context, args []string, deps dependencies) error {
	flags := flag.NewFlagSet("create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	outputPath := flags.String("output", "", "new private export file")
	keyPath := flags.String("pseudonym-key-file", "", "private base64url key file")
	keyID := flags.String("pseudonym-key-id", "", "non-secret key version identifier")
	sinceText := flags.String("since", "", "inclusive UTC RFC3339Nano bound")
	untilText := flags.String("until", "", "inclusive UTC RFC3339Nano bound")
	incidentID := flags.String("incident-id", "", "optional exact incident UUID")
	maxIncidents := flags.Int("max-incidents", defaultMaxIncidents, "maximum incident records")
	maxAudit := flags.Int("max-audit-events", defaultMaxAudit, "maximum audit records")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *outputPath == "" ||
		*keyPath == "" || *keyID == "" || *sinceText == "" || *untilText == "" {
		return errors.New("export create arguments rejected")
	}
	if err := exportbundle.RejectInheritedAuthority(deps.environ()); err != nil {
		return errors.New("export inherited authority rejected")
	}
	environment := deps.getenv(exportbundle.EnvironmentName)
	databaseURL := deps.getenv(exportbundle.DatabaseURLName)
	if err := exportbundle.ValidateReadDatabaseURL(databaseURL, environment); err != nil {
		return errors.New("export database configuration rejected")
	}
	since, err := parseCanonicalTime(*sinceText)
	if err != nil {
		return errors.New("export time bound rejected")
	}
	until, err := parseCanonicalTime(*untilText)
	if err != nil {
		return errors.New("export time bound rejected")
	}
	query, err := exportbundle.NewQuery(since, until, *incidentID, *maxIncidents, *maxAudit)
	if err != nil {
		return errors.New("export query rejected")
	}
	key, err := deps.readKey(*keyPath)
	if err != nil {
		return errors.New("export pseudonym key rejected")
	}
	defer clear(key)
	pool, err := deps.openPool(ctx, databaseURL)
	if err != nil || pool == nil {
		return errors.New("export database unavailable")
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		return errors.New("export database readiness failed")
	}
	store, err := exportbundle.NewPostgresStore(pool)
	if err != nil {
		return errors.New("export store rejected")
	}
	exporter, err := exportbundle.NewExporter(store, key, *keyID)
	if err != nil {
		return errors.New("export configuration rejected")
	}
	defer exporter.Close()
	bundle, err := exporter.Build(ctx, query)
	if err != nil {
		return errors.New("export snapshot failed")
	}
	result, err := deps.writeBundle(*outputPath, bundle)
	if err != nil {
		return errors.New("export publication failed")
	}
	return encodeResult(deps.output, result)
}

func runVerify(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "", "private export file")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *inputPath == "" {
		return errors.New("export verify arguments rejected")
	}
	_, result, err := deps.verifyFile(*inputPath)
	if err != nil {
		return errors.New("export verification failed")
	}
	result.OutputPath = *inputPath
	return encodeResult(deps.output, result)
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("non-canonical time")
	}
	return parsed, nil
}

func encodeResult(output io.Writer, result exportbundle.Result) error {
	if result.ExportID == "" || result.ManifestDigest == "" || result.BundleDigest == "" {
		return errors.New("export safe result rejected")
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return errors.New("export safe result output failed")
	}
	return nil
}
