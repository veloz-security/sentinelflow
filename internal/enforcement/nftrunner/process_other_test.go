//go:build !linux

package nftrunner

import "testing"

func TestProductionRunnerFailsClosedOutsideLinux(t *testing.T) {
	runner, err := NewProductionRunner()
	if runner != nil {
		t.Fatalf("runner = %#v, want nil", runner)
	}
	requireErrorCode(t, err, ErrorUnsupportedPlatform)
}
