package keymaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const maximumKeyFileBytes = 4096

// LoadPrivateFile accepts exactly one header-free PKCS#8 PRIVATE KEY PEM block
// containing an Ed25519 private key. The file must be owned by the effective
// user, single-linked, regular, owner-readable, and inaccessible to group and
// other users.
func LoadPrivateFile(path string) (ed25519.PrivateKey, error) {
	contents, err := readSecureFile(path, true)
	if err != nil {
		return nil, err
	}
	defer clear(contents)
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, ErrEncoding
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		clear(block.Bytes)
		return nil, ErrEncoding
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		clear(block.Bytes)
		return nil, ErrKeyRole
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(derived, key) != 1 {
		clear(derived)
		clear(key)
		clear(block.Bytes)
		return nil, ErrEncoding
	}
	clear(derived)
	result := bytes.Clone(key)
	clear(key)
	clear(block.Bytes)
	return result, nil
}

// LoadPublicFile accepts exactly one header-free PKIX PUBLIC KEY PEM block
// containing an Ed25519 public key. It rejects private-key material and files
// writable by group or other users.
func LoadPublicFile(path string) (ed25519.PublicKey, error) {
	contents, err := readSecureFile(path, false)
	if err != nil {
		return nil, err
	}
	defer clear(contents)
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, ErrEncoding
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrEncoding
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, ErrKeyRole
	}
	return bytes.Clone(key), nil
}

func readSecureFile(path string, private bool) ([]byte, error) {
	clean := filepath.Clean(path)
	if path == "" || clean != path || !filepath.IsAbs(clean) || filepath.Base(clean) == "." ||
		filepath.Base(clean) == string(filepath.Separator) {
		return nil, ErrPath
	}
	fd, err := unix.Open(clean, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrFilesystem
	}
	file := os.NewFile(uintptr(fd), "key-material")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrFilesystem
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return nil, ErrFilesystem
	}
	permissions := stat.Mode & 0o777
	if permissions&0o400 == 0 || private && permissions&0o077 != 0 || !private && permissions&0o022 != 0 {
		return nil, ErrFilesystem
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumKeyFileBytes+1))
	if err != nil || len(contents) == 0 || len(contents) > maximumKeyFileBytes {
		clear(contents)
		return nil, ErrFilesystem
	}
	return contents, nil
}
