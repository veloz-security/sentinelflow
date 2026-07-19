package exportbundle

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBundleIsPrivateNoClobberAndRoundTrips(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "incident-audit-export.json")
	bundle := buildTestBundle(t)
	result, err := WriteBundle(path, bundle)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
	_, verified, err := VerifyFile(path)
	if err != nil || verified.BundleDigest != result.BundleDigest || verified.ExportID != result.ExportID {
		t.Fatalf("verified=%+v result=%+v err=%v", verified, result, err)
	}
	if _, err = WriteBundle(path, bundle); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("overwrite err=%v", err)
	}
}

func TestVerifyFileRejectsTamperPermissionsSymlinkAndTrailingDocument(t *testing.T) {
	directory := t.TempDir()
	bundle := buildTestBundle(t)
	encoded, _, err := Encode(bundle)
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Replace(encoded, []byte(`"kind": "path_scan"`), []byte(`"kind": "brute_force"`), 1)
	if bytes.Equal(mutated, encoded) {
		t.Fatal("tamper fixture did not change")
	}
	tamperedPath := filepath.Join(directory, "tampered.json")
	if err = os.WriteFile(tamperedPath, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifyFile(tamperedPath); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tamper err=%v", err)
	}
	publicPath := filepath.Join(directory, "public.json")
	if err = os.WriteFile(publicPath, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifyFile(publicPath); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("public mode err=%v", err)
	}
	symlinkPath := filepath.Join(directory, "link.json")
	if err = os.Symlink(tamperedPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifyFile(symlinkPath); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("symlink err=%v", err)
	}
	trailingPath := filepath.Join(directory, "trailing.json")
	if err = os.WriteFile(trailingPath, append(encoded, []byte("{}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = VerifyFile(trailingPath); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("trailing err=%v", err)
	}
}

func TestReadPseudonymKeyRequiresPrivateCanonicalBase64URL(t *testing.T) {
	directory := t.TempDir()
	raw := []byte("0123456789abcdef0123456789abcdef")
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	keyPath := filepath.Join(directory, "key")
	if err := os.WriteFile(keyPath, []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadPseudonymKey(keyPath)
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatalf("decoded=%x err=%v", decoded, err)
	}
	clear(decoded)
	if err = os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPseudonymKey(keyPath); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("public key mode err=%v", err)
	}
	badPath := filepath.Join(directory, "bad-key")
	if err = os.WriteFile(badPath, []byte(encoded+"=="), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPseudonymKey(badPath); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("non-canonical key err=%v", err)
	}
}

func TestValidateDatabaseURLAndAuthorityIsolation(t *testing.T) {
	valid := "postgresql://sentinelflow_read:secret@127.0.0.1:5432/sentinelflow?sslmode=disable"
	if err := ValidateReadDatabaseURL(valid, "test"); err != nil {
		t.Fatal(err)
	}
	delegated := "postgresql://sentinelflow_export_login:secret@127.0.0.1:5432/sentinelflow?sslmode=disable"
	if err := ValidateReadDatabaseURL(delegated, "test"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []struct {
		url string
		env string
	}{
		{"postgres://sentinelflow_read:secret@127.0.0.1:5432/sentinelflow?sslmode=disable", "test"},
		{"postgresql://sentinelflow_api:secret@127.0.0.1:5432/sentinelflow?sslmode=disable", "test"},
		{"postgresql://SentinelFlow_export:secret@127.0.0.1:5432/sentinelflow?sslmode=disable", "test"},
		{valid, "production"},
		{"postgresql://sentinelflow_read:secret@127.0.0.1:05432/sentinelflow?sslmode=disable", "test"},
	} {
		if err := ValidateReadDatabaseURL(value.url, value.env); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("url=%q env=%q err=%v", value.url, value.env, err)
		}
	}
	if err := RejectInheritedAuthority([]string{
		DatabaseURLName + "=" + valid, EnvironmentName + "=test", "PATH=/usr/bin",
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"OPENAI_API_KEY", "DATABASE_API_URL", "EXECUTOR_RESULT_PRIVATE_KEY_FILE", "ADMIN_PASSWORD"} {
		if err := RejectInheritedAuthority([]string{name + "=secret"}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("name=%s err=%v", name, err)
		}
	}
}
