package buildinfo

import "testing"

func TestIdentityIsNonEmpty(t *testing.T) {
	t.Parallel()

	if Name == "" {
		t.Fatal("Name must not be empty")
	}
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
}
