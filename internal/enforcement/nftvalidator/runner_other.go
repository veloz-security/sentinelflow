//go:build !linux

package nftvalidator

import (
	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
)

func NewProductionRunner([]byte) (nftcheck.ProcessRunner, error) {
	return nil, runnerError(nftcheck.ErrorUnsupportedPlatform)
}
