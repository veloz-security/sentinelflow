//go:build !linux

package nftbootstrap

// NewProductionManager fails closed outside Linux. Unit tests use the common
// manager with an unexported fake process function and never invoke host tools.
func NewProductionManager() (*Manager, error) {
	return nil, reject(ErrorUnsupportedPlatform)
}
