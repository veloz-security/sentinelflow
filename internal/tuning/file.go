package tuning

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func LoadCorpusFile(path string) (Corpus, error) {
	raw, err := readRegularFile(path, MaximumCorpusBytes)
	if err != nil {
		return Corpus{}, ErrInvalidCorpus
	}
	return LoadCorpus(raw)
}

func WriteNewReport(path string, report Report, corpus Corpus) (Result, error) {
	encoded, result, err := EncodeReport(report, corpus)
	if err != nil {
		return Result{}, err
	}
	if err = writeNewFile(path, encoded); err != nil {
		return Result{}, err
	}
	result.OutputPath = path
	return result, nil
}

func VerifyReportFile(path string, corpus Corpus) (Report, Result, error) {
	raw, err := readRegularFile(path, MaximumCorpusBytes)
	if err != nil {
		return Report{}, Result{}, ErrInvalidReport
	}
	return DecodeAndVerifyReport(raw, corpus)
}

func readRegularFile(path string, limit int) ([]byte, error) {
	if path == "" || strings.ContainsAny(path, "\x00\r\n") || limit < 1 {
		return nil, ErrInvalidCorpus
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > int64(limit) {
		return nil, ErrInvalidCorpus
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidCorpus
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
		return nil, ErrInvalidCorpus
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(raw) < 1 || len(raw) > limit {
		return nil, ErrInvalidCorpus
	}
	return raw, nil
}

func writeNewFile(path string, data []byte) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.ContainsAny(path, "\x00\r\n") || len(data) == 0 || len(data) > MaximumCorpusBytes {
		return ErrUnsafeOutput
	}
	parent, base := filepath.Dir(path), filepath.Base(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeOutput
	}
	if _, err = os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return ErrUnsafeOutput
	}
	random := make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return ErrUnsafeOutput
	}
	temporary := filepath.Join(parent, "."+base+".tmp-"+hex.EncodeToString(random))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return ErrUnsafeOutput
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(data); err != nil || file.Sync() != nil || file.Close() != nil {
		return ErrUnsafeOutput
	}
	if err = os.Link(temporary, path); err != nil {
		return ErrUnsafeOutput
	}
	if err = os.Remove(temporary); err != nil {
		_ = os.Remove(path)
		return ErrUnsafeOutput
	}
	removeTemporary = false
	directory, err := os.Open(parent)
	if err != nil {
		_ = os.Remove(path)
		return ErrUnsafeOutput
	}
	err = directory.Sync()
	_ = directory.Close()
	if err != nil {
		_ = os.Remove(path)
		return ErrUnsafeOutput
	}
	return nil
}
