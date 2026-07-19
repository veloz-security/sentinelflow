package postgres_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMigrationRunnerShellSyntax(t *testing.T) {
	t.Parallel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate migration runner test")
	}
	script := filepath.Join(filepath.Dir(source), "init.sh")
	info, err := os.Stat(script)
	if err != nil {
		t.Fatalf("stat migration runner: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("migration runner is not executable")
	}
	if output, err := exec.Command("sh", "-n", script).CombinedOutput(); err != nil {
		t.Fatalf("migration runner shell syntax: %v\n%s", err, output)
	}
}
