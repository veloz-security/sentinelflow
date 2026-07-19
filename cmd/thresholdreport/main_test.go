package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devwooops/sentinelflow/internal/tuning"
)

func TestCompareProducesNoActivationReportAndSafeResult(t *testing.T) {
	corpus := checkedCorpus(t)
	var output bytes.Buffer
	written := false
	deps := dependencies{
		loadCorpus: func(path string) (tuning.Corpus, error) {
			if path != "corpus.json" {
				t.Fatalf("path=%q", path)
			}
			return corpus, nil
		},
		writeReport: func(path string, report tuning.Report, supplied tuning.Corpus) (tuning.Result, error) {
			written = true
			if path != "/tmp/report.json" || report.ActivationPerformed ||
				report.SelectedProfileID != "baseline-v1" || supplied.CanonicalDigest() != corpus.CanonicalDigest() {
				t.Fatalf("path=%q report=%+v", path, report)
			}
			return tuning.Result{ReportID: report.ReportID, ReportDigest: report.ReportDigest, OutputPath: path}, nil
		},
		verifyFile: func(string, tuning.Corpus) (tuning.Report, tuning.Result, error) {
			return tuning.Report{}, tuning.Result{}, errors.New("not used")
		},
		output: &output,
	}
	if err := run([]string{
		"compare", "--input", "corpus.json", "--output", "/tmp/report.json",
		"--author", "ops.qa", "--evaluated-at", "2026-07-18T05:00:00Z",
	}, deps); err != nil {
		t.Fatal(err)
	}
	if !written || !strings.Contains(output.String(), `"output_path":"/tmp/report.json"`) {
		t.Fatalf("written=%v output=%q", written, output.String())
	}
}

func TestVerifyIsOfflineAndUnknownActivationFlagFailsClosed(t *testing.T) {
	corpus := checkedCorpus(t)
	var output bytes.Buffer
	verified := false
	deps := dependencies{
		loadCorpus: func(string) (tuning.Corpus, error) { return corpus, nil },
		writeReport: func(string, tuning.Report, tuning.Corpus) (tuning.Result, error) {
			return tuning.Result{}, errors.New("must not run")
		},
		verifyFile: func(path string, supplied tuning.Corpus) (tuning.Report, tuning.Result, error) {
			verified = true
			if path != "report.json" || supplied.RawDigest() != corpus.RawDigest() {
				t.Fatal("verify binding mismatch")
			}
			return tuning.Report{}, tuning.Result{
				ReportID:     "sha256:" + strings.Repeat("a", 64),
				ReportDigest: "sha256:" + strings.Repeat("b", 64),
			}, nil
		},
		output: &output,
	}
	if err := run([]string{"verify", "--input", "corpus.json", "--report", "report.json"}, deps); err != nil {
		t.Fatal(err)
	}
	if !verified || !strings.Contains(output.String(), `"output_path":"report.json"`) {
		t.Fatalf("verified=%v output=%q", verified, output.String())
	}
	if err := run([]string{
		"compare", "--input", "corpus.json", "--output", "/tmp/report.json",
		"--author", "ops.qa", "--evaluated-at", "2026-07-18T05:00:00Z", "--activate",
	}, deps); err == nil {
		t.Fatal("unknown activation flag accepted")
	}
}

func TestCommandAndTimeInputsFailClosed(t *testing.T) {
	deps := dependencies{
		loadCorpus: func(string) (tuning.Corpus, error) { return tuning.Corpus{}, errors.New("not used") },
		writeReport: func(string, tuning.Report, tuning.Corpus) (tuning.Result, error) {
			return tuning.Result{}, errors.New("not used")
		},
		verifyFile: func(string, tuning.Corpus) (tuning.Report, tuning.Result, error) {
			return tuning.Report{}, tuning.Result{}, errors.New("not used")
		},
		output: &bytes.Buffer{},
	}
	for _, args := range [][]string{nil, {"unknown"}, {"compare"}, {"verify"}} {
		if err := run(args, deps); err == nil {
			t.Fatalf("args=%q accepted", args)
		}
	}
	for _, value := range []string{"2026-07-18T14:00:00+09:00", "2026-07-18T05:00:00.000Z"} {
		if _, err := parseCanonicalTime(value); err == nil {
			t.Fatalf("time=%q accepted", value)
		}
	}
}

func checkedCorpus(t *testing.T) tuning.Corpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "samples", "tuning", "threshold_cases_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := tuning.LoadCorpus(raw)
	if err != nil {
		t.Fatal(err)
	}
	return corpus
}
