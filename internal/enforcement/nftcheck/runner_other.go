//go:build !linux

package nftcheck

// NewProductionRunner fails closed outside Linux. Unit tests use a fake
// ProcessRunner and never invoke host nftables.
func NewProductionRunner() (ProcessRunner, error) {
	return nil, reject(ErrorUnsupportedPlatform)
}
