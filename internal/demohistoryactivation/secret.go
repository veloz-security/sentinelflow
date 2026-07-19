// Package demohistoryactivation loads the process-local capability used to
// attach a demo worker to its consumer-separated database activation.
package demohistoryactivation

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const SecretBytes = 32

var ErrSecretSource = errors.New("demo history activation capability rejected")

// Secret is immutable outside this package and never formats its bytes.
type Secret struct {
	value [SecretBytes]byte
	valid bool
}

func Load(path string) (Secret, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Secret{}, ErrSecretSource
	}
	directory, name := filepath.Split(path)
	if name == "" {
		return Secret{}, ErrSecretSource
	}
	root, err := os.OpenRoot(filepath.Clean(directory))
	if err != nil {
		return Secret{}, ErrSecretSource
	}
	defer root.Close()
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 ||
		before.Size() != SecretBytes {
		return Secret{}, ErrSecretSource
	}
	file, err := root.Open(name)
	if err != nil {
		return Secret{}, ErrSecretSource
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Mode().Perm() != 0o400 ||
		!os.SameFile(before, after) {
		return Secret{}, ErrSecretSource
	}
	raw, err := io.ReadAll(io.LimitReader(file, SecretBytes+1))
	if err != nil || len(raw) != SecretBytes || allZero(raw) {
		return Secret{}, ErrSecretSource
	}
	result := Secret{valid: true}
	copy(result.value[:], raw)
	clear(raw)
	return result, nil
}

func (s Secret) Bytes() ([]byte, bool) {
	if !s.valid || allZero(s.value[:]) {
		return nil, false
	}
	return append([]byte(nil), s.value[:]...), true
}

func (s Secret) String() string {
	if !s.valid {
		return "demo-history-activation-capability[INVALID]"
	}
	return "demo-history-activation-capability[REDACTED]"
}

func (s Secret) GoString() string { return s.String() }
func (s Secret) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(s.String()))
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}
