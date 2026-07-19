package keymaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEd25519PrivateAndPublicRoundTrip(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := writePrivatePEM(t, private, 0o600)
	publicPath := writePublicPEM(t, public, 0o644)
	loadedPrivate, err := LoadPrivateFile(privatePath)
	if err != nil || !bytes.Equal(loadedPrivate, private) {
		t.Fatalf("private round trip failed: %v", err)
	}
	loadedPublic, err := LoadPublicFile(publicPath)
	if err != nil || !bytes.Equal(loadedPublic, public) {
		t.Fatalf("public round trip failed: %v", err)
	}
	loadedPrivate[0] ^= 1
	loadedPublic[0] ^= 1
	if bytes.Equal(loadedPrivate, private) || bytes.Equal(loadedPublic, public) {
		t.Fatal("returned key aliases parser or caller storage")
	}
	clear(loadedPrivate)
	clear(private)
}

func TestKeyRoleEncodingAndFileSafetyFailClosed(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	validPrivate := writePrivatePEM(t, private, 0o600)
	validPublic := writePublicPEM(t, public, 0o644)

	tests := []struct {
		name string
		load func() error
		want error
	}{
		{"relative path", func() error { _, err := LoadPrivateFile("relative.pem"); return err }, ErrPath},
		{"missing", func() error { _, err := LoadPrivateFile(filepath.Join(t.TempDir(), "missing.pem")); return err }, ErrFilesystem},
		{"private as public", func() error { _, err := LoadPublicFile(validPrivate); return err }, ErrEncoding},
		{"public as private", func() error { _, err := LoadPrivateFile(copyWithMode(t, validPublic, 0o600)); return err }, ErrEncoding},
		{"trailing data", func() error {
			path := writeBytes(t, append(mustPrivatePEM(t, private), '\n'), 0o600)
			_, err := LoadPrivateFile(path)
			return err
		}, ErrEncoding},
		{"multiple blocks", func() error {
			data := append(mustPublicPEM(t, public), mustPublicPEM(t, public)...)
			_, err := LoadPublicFile(writeBytes(t, data, 0o644))
			return err
		}, ErrEncoding},
		{"private world readable", func() error { _, err := LoadPrivateFile(copyWithMode(t, validPrivate, 0o604)); return err }, ErrFilesystem},
		{"public world writable", func() error { _, err := LoadPublicFile(copyWithMode(t, validPublic, 0o646)); return err }, ErrFilesystem},
		{"empty", func() error { _, err := LoadPrivateFile(writeBytes(t, nil, 0o600)); return err }, ErrFilesystem},
		{"oversized", func() error {
			_, err := LoadPrivateFile(writeBytes(t, bytes.Repeat([]byte{'x'}, maximumKeyFileBytes+1), 0o600))
			return err
		}, ErrFilesystem},
	}
	if runtime.GOOS != "windows" {
		tests = append(tests,
			struct {
				name string
				load func() error
				want error
			}{"symlink", func() error {
				link := filepath.Join(t.TempDir(), "key-link.pem")
				if err := os.Symlink(validPrivate, link); err != nil {
					t.Fatal(err)
				}
				_, err := LoadPrivateFile(link)
				return err
			}, ErrFilesystem},
			struct {
				name string
				load func() error
				want error
			}{"hardlink", func() error {
				link := filepath.Join(t.TempDir(), "key-hardlink.pem")
				if err := os.Link(validPrivate, link); err != nil {
					t.Fatal(err)
				}
				_, err := LoadPrivateFile(validPrivate)
				return err
			}, ErrFilesystem},
		)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.load(); !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestWrongAlgorithmAndErrorsAreRedacted(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	path := writeBytes(t, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	if _, err := LoadPrivateFile(path); !errors.Is(err, ErrKeyRole) || strings.Contains(err.Error(), path) || strings.Contains(fmt.Sprintf("%#v", err), path) {
		t.Fatalf("wrong role was not safely rejected: %v", err)
	}
	for _, value := range []*Error{ErrPath, ErrFilesystem, ErrEncoding, ErrKeyRole, nil} {
		if strings.Contains(value.Error(), "/") || value.Code() == "" {
			t.Fatalf("unsafe typed error: %#v", value)
		}
	}
}

func writePrivatePEM(t *testing.T, key ed25519.PrivateKey, mode os.FileMode) string {
	t.Helper()
	return writeBytes(t, mustPrivatePEM(t, key), mode)
}

func mustPrivatePEM(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func writePublicPEM(t *testing.T, key ed25519.PublicKey, mode os.FileMode) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writeBytes(t, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), mode)
}

func mustPublicPEM(t *testing.T, key ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func writeBytes(t *testing.T, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func copyWithMode(t *testing.T, source string, mode os.FileMode) string {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	return writeBytes(t, data, mode)
}
