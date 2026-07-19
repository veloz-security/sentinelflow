package worker

import (
	"bytes"
	"errors"
	"testing"
)

func TestUUIDV4FromSetsVersionAndVariant(t *testing.T) {
	t.Parallel()

	token, err := uuidV4From(bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatalf("uuidV4From: %v", err)
	}
	if token != "00000000-0000-4000-8000-000000000000" || !validUUIDV4(token) {
		t.Fatalf("token = %q", token)
	}
}

func TestUUIDV4FromFailsOnShortEntropy(t *testing.T) {
	t.Parallel()

	if _, err := uuidV4From(bytes.NewReader(make([]byte, 15))); err == nil {
		t.Fatal("short entropy was accepted")
	}
	if _, err := uuidV4From(errorReader{}); err == nil {
		t.Fatal("entropy error was accepted")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy failed") }
