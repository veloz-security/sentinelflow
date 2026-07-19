// Command thresholdreport compares checked normal/attack aggregate fixtures
// against frozen offline profiles. It has no database, network, AI, HIL, or
// configuration-write capability and cannot activate a profile.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/devwooops/sentinelflow/internal/tuning"
)

type dependencies struct {
	loadCorpus  func(string) (tuning.Corpus, error)
	writeReport func(string, tuning.Report, tuning.Corpus) (tuning.Result, error)
	verifyFile  func(string, tuning.Corpus) (tuning.Report, tuning.Result, error)
	output      io.Writer
}

func main() {
	if err := run(os.Args[1:], productionDependencies()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sentinelflow threshold report failed")
		os.Exit(1)
	}
}

func productionDependencies() dependencies {
	return dependencies{
		loadCorpus: tuning.LoadCorpusFile, writeReport: tuning.WriteNewReport,
		verifyFile: tuning.VerifyReportFile, output: os.Stdout,
	}
}

func run(args []string, deps dependencies) error {
	if len(args) == 0 || deps.loadCorpus == nil || deps.writeReport == nil ||
		deps.verifyFile == nil || deps.output == nil {
		return errors.New("threshold report dependencies rejected")
	}
	switch args[0] {
	case "compare":
		return runCompare(args[1:], deps)
	case "verify":
		return runVerify(args[1:], deps)
	default:
		return errors.New("threshold report command rejected")
	}
}

func runCompare(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "checked aggregate corpus")
	output := flags.String("output", "", "new comparison report")
	author := flags.String("author", "", "bounded operator identifier")
	evaluatedAtText := flags.String("evaluated-at", "", "canonical UTC RFC3339Nano")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *input == "" ||
		*output == "" || *author == "" || *evaluatedAtText == "" {
		return errors.New("threshold report arguments rejected")
	}
	evaluatedAt, err := parseCanonicalTime(*evaluatedAtText)
	if err != nil {
		return errors.New("threshold report evaluation time rejected")
	}
	corpus, err := deps.loadCorpus(*input)
	if err != nil {
		return errors.New("threshold report corpus rejected")
	}
	report, err := tuning.Compare(corpus, *author, evaluatedAt)
	if err != nil {
		return errors.New("threshold comparison failed")
	}
	result, err := deps.writeReport(*output, report, corpus)
	if err != nil {
		return errors.New("threshold report publication failed")
	}
	return encodeResult(deps.output, result)
}

func runVerify(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "checked aggregate corpus")
	reportPath := flags.String("report", "", "comparison report")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *input == "" || *reportPath == "" {
		return errors.New("threshold report verify arguments rejected")
	}
	corpus, err := deps.loadCorpus(*input)
	if err != nil {
		return errors.New("threshold report corpus rejected")
	}
	_, result, err := deps.verifyFile(*reportPath, corpus)
	if err != nil {
		return errors.New("threshold report verification failed")
	}
	result.OutputPath = *reportPath
	return encodeResult(deps.output, result)
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("non-canonical time")
	}
	return parsed, nil
}

func encodeResult(output io.Writer, result tuning.Result) error {
	if result.ReportID == "" || result.ReportDigest == "" {
		return errors.New("threshold safe result rejected")
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		return errors.New("threshold safe result output failed")
	}
	return nil
}
