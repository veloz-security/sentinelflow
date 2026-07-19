package demohistoryimport

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/devwooops/sentinelflow/internal/demohistory"
	"github.com/devwooops/sentinelflow/internal/validation"
)

// DatasetReader supplies only the fixed pinned dataset bytes. Arbitrary paths
// never cross the importer API.
type DatasetReader interface {
	ReadPinnedDataset(context.Context) ([]byte, error)
}

// FixedDatasetFile reads validation.DemoHistoryDatasetLocator beneath one
// absolute root using os.Root traversal containment and a hard byte bound.
type FixedDatasetFile struct {
	repositoryRoot string
}

func NewFixedDatasetFile(repositoryRoot string) (*FixedDatasetFile, error) {
	if repositoryRoot == "" || !filepath.IsAbs(repositoryRoot) {
		return nil, reject(ErrorConfiguration)
	}
	return &FixedDatasetFile{repositoryRoot: filepath.Clean(repositoryRoot)}, nil
}

func (s *FixedDatasetFile) ReadPinnedDataset(ctx context.Context) ([]byte, error) {
	if s == nil || ctx == nil {
		return nil, reject(ErrorSource)
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(s.repositoryRoot)
	if err != nil {
		return nil, reject(ErrorSource)
	}
	defer root.Close()
	file, err := root.Open(validation.DemoHistoryDatasetLocator)
	if err != nil {
		return nil, reject(ErrorSource)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > demohistory.MaxDatasetBytes {
		return nil, reject(ErrorSource)
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(demohistory.MaxDatasetBytes)+1))
	if err != nil || len(raw) < 1 || len(raw) > demohistory.MaxDatasetBytes {
		return nil, reject(ErrorSource)
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return raw, nil
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return reject(ErrorCanceled)
		}
	}
	return nil
}
