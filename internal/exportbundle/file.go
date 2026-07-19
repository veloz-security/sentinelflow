package exportbundle

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func WriteBundle(path string, bundle Bundle) (Result, error) {
	encoded, result, err := Encode(bundle)
	if err != nil {
		return Result{}, err
	}
	if err = WriteNewFile(path, encoded); err != nil {
		return Result{}, err
	}
	result.OutputPath = path
	return result, nil
}

func VerifyFile(path string) (Bundle, Result, error) {
	encoded, err := ReadPrivateFile(path, MaximumBundleBytes)
	if err != nil {
		return Bundle{}, Result{}, err
	}
	return DecodeAndVerify(encoded)
}

// WriteNewFile publishes private bytes without ever replacing an existing
// path. A same-directory hard link is the no-clobber publication primitive;
// both file and containing directory are synced before success is returned.
func WriteNewFile(path string, data []byte) error {
	parent, base, err := validateNewPath(path)
	if err != nil || len(data) == 0 || len(data) > MaximumBundleBytes {
		return ErrUnsafeFile
	}
	random := make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, random); err != nil {
		return ErrUnsafeFile
	}
	temporary := filepath.Join(parent, "."+base+".tmp-"+hex.EncodeToString(random))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrUnsafeFile
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(data); err != nil || file.Sync() != nil || file.Close() != nil {
		return ErrUnsafeFile
	}
	if err = os.Link(temporary, path); err != nil {
		return ErrUnsafeFile
	}
	if err = os.Remove(temporary); err != nil {
		_ = os.Remove(path)
		return ErrUnsafeFile
	}
	removeTemporary = false
	if err = syncDirectory(parent); err != nil {
		_ = os.Remove(path)
		_ = syncDirectory(parent)
		return ErrUnsafeFile
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = os.Remove(path)
		_ = syncDirectory(parent)
		return ErrUnsafeFile
	}
	return nil
}

func ReadPrivateFile(path string, limit int) ([]byte, error) {
	if limit < 1 || limit > MaximumBundleBytes || !validAbsolutePath(path) {
		return nil, ErrUnsafeFile
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 ||
		before.Size() < 1 || before.Size() > int64(limit) {
		return nil, ErrUnsafeFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnsafeFile
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() {
		return nil, ErrUnsafeFile
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) < 1 || len(data) > limit {
		return nil, ErrUnsafeFile
	}
	return data, nil
}

func validateNewPath(path string) (string, string, error) {
	if !validAbsolutePath(path) {
		return "", "", ErrUnsafeFile
	}
	parent, base := filepath.Dir(path), filepath.Base(path)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return "", "", ErrUnsafeFile
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", ErrUnsafeFile
	}
	if _, err = os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "", "", ErrUnsafeFile
	}
	return parent, base, nil
}

func validAbsolutePath(path string) bool {
	return path != "" && len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		!strings.ContainsAny(path, "\x00\r\n")
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
