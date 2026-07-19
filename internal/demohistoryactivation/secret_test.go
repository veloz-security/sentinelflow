package demohistoryactivation

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAcceptsExactPrivateRegularFileAndRedactsFormatting(t *testing.T) {
	raw := bytes.Repeat([]byte{0x5a}, SecretBytes)
	path := filepath.Join(t.TempDir(), "activation.cap")
	if err := os.WriteFile(path, raw, 0o400); err != nil {
		t.Fatal(err)
	}
	secret, err := Load(path)
	loaded, ok := secret.Bytes()
	if err != nil || !ok || !bytes.Equal(loaded, raw) {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	loaded[0] ^= 0xff
	second, ok := secret.Bytes()
	if !ok || !bytes.Equal(second, raw) {
		t.Fatal("secret bytes were aliased")
	}
	for _, formatted := range []string{fmt.Sprint(secret), fmt.Sprintf("%+v", secret), fmt.Sprintf("%#v", secret)} {
		if strings.Contains(formatted, string(raw)) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("unsafe formatting %q", formatted)
		}
	}
}

func TestLoadRejectsSymlinkModeSizeAndZeroContent(t *testing.T) {
	for name, setup := range map[string]func(*testing.T) string{
		"mode": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "activation.cap")
			if err := os.WriteFile(path, bytes.Repeat([]byte{1}, SecretBytes), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"short": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "activation.cap")
			if err := os.WriteFile(path, bytes.Repeat([]byte{1}, SecretBytes-1), 0o400); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"large": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "activation.cap")
			if err := os.WriteFile(path, bytes.Repeat([]byte{1}, SecretBytes+1), 0o400); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"zero": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "activation.cap")
			if err := os.WriteFile(path, make([]byte, SecretBytes), 0o400); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"symlink": func(t *testing.T) string {
			root := t.TempDir()
			target := filepath.Join(root, "target.cap")
			if err := os.WriteFile(target, bytes.Repeat([]byte{1}, SecretBytes), 0o400); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "activation.cap")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(setup(t)); !errors.Is(err, ErrSecretSource) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
