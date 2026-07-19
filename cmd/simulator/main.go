package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/devwooops/sentinelflow/internal/simulator"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sentinelflow simulator failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	return runTo(ctx, args, os.Stdout)
}

func runTo(ctx context.Context, args []string, output io.Writer) error {
	if ctx == nil || output == nil {
		return errors.New("invalid simulator invocation")
	}
	flags := flag.NewFlagSet("sentinelflow-simulator", flag.ContinueOnError)
	flags.SetOutput(ioDiscard{})
	baseURL := flags.String("gateway-url", "http://gateway:8080", "Gateway base URL")
	hostHeader := flags.String("gateway-host", "localhost:8080", "allowlisted Gateway Host header")
	seed := flags.Int64("seed", simulator.DefaultSeed, "deterministic scenario seed")
	concurrency := flags.Int("concurrency", 4, "bounded request concurrency")
	timeout := flags.Duration("request-timeout", 10*time.Second, "per-request timeout")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return errors.New("invalid simulator arguments")
	}
	scenario, err := simulator.ParseScenario(flags.Arg(0))
	if err != nil {
		return err
	}
	plan, err := simulator.BuildPlan(scenario, *seed)
	if err != nil {
		return err
	}
	runner, err := simulator.NewRunner(simulator.RunnerConfig{
		BaseURL:        *baseURL,
		HostHeader:     *hostHeader,
		Concurrency:    *concurrency,
		RequestTimeout: *timeout,
	})
	if err != nil {
		return err
	}
	report, err := runner.Run(ctx, plan)
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(true)
	if encodeErr := encoder.Encode(report); encodeErr != nil {
		return errors.New("simulator report encoding failed")
	}
	return err
}

type ioDiscard struct{}

func (ioDiscard) Write(value []byte) (int, error) { return len(value), nil }
