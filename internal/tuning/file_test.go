package tuning

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReportFileIsAtomicNoClobberAndCorpusBound(t *testing.T) {
	corpus := loadCheckedCorpus(t)
	report, err := Compare(corpus, "ops.qa", time.Date(2026, 7, 18, 5, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "comparison.json")
	result, err := WriteNewReport(path, report, corpus)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
	_, verified, err := VerifyReportFile(path, corpus)
	if err != nil || verified.ReportDigest != result.ReportDigest {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	if _, err = WriteNewReport(path, report, corpus); !errors.Is(err, ErrUnsafeOutput) {
		t.Fatalf("overwrite err=%v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"false_positive": 5`), []byte(`"false_positive": 4`), 1)
	tampered := filepath.Join(directory, "tampered.json")
	if err = os.WriteFile(tampered, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifyReportFile(tampered, corpus); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("tamper err=%v", err)
	}
}

func TestCorpusFileRejectsSymlinkAndOversize(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join("..", "..", "samples", "tuning", "threshold_cases_v1.json")
	link := filepath.Join(directory, "corpus.json")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCorpusFile(link); !errors.Is(err, ErrInvalidCorpus) {
		t.Fatalf("symlink err=%v", err)
	}
	large := filepath.Join(directory, "large.json")
	if err := os.WriteFile(large, bytes.Repeat([]byte{'x'}, MaximumCorpusBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCorpusFile(large); !errors.Is(err, ErrInvalidCorpus) {
		t.Fatalf("oversize err=%v", err)
	}
}
