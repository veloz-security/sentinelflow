//go:build !linux

package nftbootstrap

import "testing"

func TestProductionManagerFailsClosedOutsideLinux(t *testing.T) {
	manager, err := NewProductionManager()
	if manager != nil {
		t.Fatalf("manager = %#v, want nil", manager)
	}
	requireErrorCode(t, err, ErrorUnsupportedPlatform)
}
