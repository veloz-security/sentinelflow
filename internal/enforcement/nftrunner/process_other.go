//go:build !linux

package nftrunner

// NewProductionRunner fails closed outside Linux. Tests exercise the common
// adapter with an unexported fake process function and never invoke host tools.
func NewProductionRunner() (*Runner, error) {
	return nil, reject(ErrorUnsupportedPlatform)
}
