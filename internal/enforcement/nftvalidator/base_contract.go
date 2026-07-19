package nftvalidator

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftcheck"
	"golang.org/x/sys/unix"
)

// LoadPinnedBaseContract reads the validator-owned base contract through a
// no-follow descriptor and verifies that the process cannot modify it. The
// caller supplies only startup configuration; UDS requests never carry a path
// or base bytes.
func LoadPinnedBaseContract(path string) ([]byte, error) {
	clean := filepath.Clean(path)
	if path == "" || clean != path || strings.IndexByte(path, 0) >= 0 || clean == "." {
		return nil, reject(ErrorInvalidConfiguration)
	}
	before, err := os.Lstat(clean)
	if err != nil || !safeContractInfo(before) {
		return nil, reject(ErrorInvalidConfiguration)
	}
	fd, err := unix.Open(clean, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, reject(ErrorInvalidConfiguration)
	}
	file := os.NewFile(uintptr(fd), "validator base contract [redacted]")
	if file == nil {
		_ = unix.Close(fd)
		return nil, reject(ErrorInvalidConfiguration)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !safeContractInfo(opened) || !os.SameFile(before, opened) {
		return nil, reject(ErrorInvalidConfiguration)
	}
	value, err := io.ReadAll(io.LimitReader(file, nftcheck.MaxBaseContractBytes+1))
	if err != nil || len(value) == 0 || len(value) > nftcheck.MaxBaseContractBytes ||
		digestBytes(value) != nftcheck.PinnedBaseContractDigest {
		return nil, reject(ErrorInvalidConfiguration)
	}
	after, err := os.Lstat(clean)
	if err != nil || !safeContractInfo(after) || !os.SameFile(opened, after) {
		return nil, reject(ErrorInvalidConfiguration)
	}
	return value, nil
}

func safeContractInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	// Owner-write is safe only when a different uid owns the file. The
	// production image copies the contract as root and runs this process as the
	// unprivileged SentinelFlow uid.
	if stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0o200 != 0 {
		return false
	}
	return true
}
