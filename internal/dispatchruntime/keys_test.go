package dispatchruntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadKeySetUsesDistinctSecureRoleKeysAndDerivedIDs(t *testing.T) {
	dispatch := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	result := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	privatePath, publicPath := writeKeyPair(t, dispatch, result.Public().(ed25519.PublicKey))
	keys, err := LoadKeySet(privatePath, publicPath)
	if err != nil {
		t.Fatalf("load key set: %v", err)
	}
	identities := keys.Identities()
	if identities.DispatchKeyID == "" || identities.ResultKeyID == "" || identities.ExecutorID == "" ||
		identities.DispatchKeyID == identities.ResultKeyID ||
		keys.Issuer().KeyID() != identities.DispatchKeyID ||
		keys.CapabilityVerifier().KeyID() != identities.DispatchKeyID ||
		keys.ResultVerifier().KeyID() != identities.ResultKeyID ||
		keys.ResultVerifier().ExecutorID() != identities.ExecutorID {
		t.Fatalf("role identities are inconsistent: %#v", identities)
	}
	if !strings.Contains(keys.String(), "REDACTED") || strings.Contains(keys.String(), "PRIVATE KEY") {
		t.Fatal("key formatting was not redacted")
	}
}

func TestLoadKeySetRejectsRoleReuseAndUnsafeFiles(t *testing.T) {
	dispatch := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	privatePath, samePublic := writeKeyPair(t, dispatch, dispatch.Public().(ed25519.PublicKey))
	if _, err := LoadKeySet(privatePath, samePublic); !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("same role key error = %v", err)
	}

	result := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	privatePath, publicPath := writeKeyPair(t, dispatch, result.Public().(ed25519.PublicKey))
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeySet(privatePath, publicPath); !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("unsafe private mode error = %v", err)
	}
}

func writeKeyPair(
	t *testing.T,
	private ed25519.PrivateKey,
	public ed25519.PublicKey,
) (string, string) {
	t.Helper()
	directory := t.TempDir()
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "dispatch.pem")
	publicPath := filepath.Join(directory, "result.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return privatePath, publicPath
}
