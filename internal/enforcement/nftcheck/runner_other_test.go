//go:build !linux

package nftcheck

import (
	"errors"
	"testing"
)

func TestProductionRunnerFailsClosedOutsideLinux(t *testing.T) {
	runner, err := NewProductionRunner()
	if runner != nil {
		t.Fatalf("runner = %#v, want nil", runner)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != ErrorUnsupportedPlatform {
		t.Fatalf("error = %v, want %q", err, ErrorUnsupportedPlatform)
	}
}
