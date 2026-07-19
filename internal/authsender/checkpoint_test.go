package authsender

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckpointStrictValidationAndAtomicReplacement(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "nested", "checkpoint.json")
	valid := checkpoint{
		SenderID: "auth-app", EndpointPath: "/internal/v1/auth-events", SenderEpoch: "AQEBAQEBAQEBAQEBAQEBAQ",
		LastAcknowledgedSequence: 1, LastAcknowledgedBodyDigest: "sha256:" + strings.Repeat("a", 64), CleanShutdown: true,
	}
	data, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteCheckpoint(path, append(data, '\n')); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := loadCheckpoint(path)
	if err != nil || !exists || loaded != valid {
		t.Fatalf("loaded=%#v exists=%v err=%v", loaded, exists, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}

	valid.CleanShutdown = false
	replacement, _ := json.Marshal(valid)
	if err := atomicWriteCheckpoint(path, append(replacement, '\n')); err != nil {
		t.Fatal(err)
	}
	loaded, _, err = loadCheckpoint(path)
	if err != nil || loaded.CleanShutdown {
		t.Fatalf("replacement=%#v err=%v", loaded, err)
	}
}

func TestCheckpointRejectsAmbiguousOrUnsafeState(t *testing.T) {
	t.Parallel()
	valid := `{"sender_id":"auth-app","endpoint_path":"/internal/v1/auth-events","sender_epoch":"AQEBAQEBAQEBAQEBAQEBAQ","last_acknowledged_sequence":0,"last_acknowledged_body_digest":"","clean_shutdown":false}`
	tests := []struct {
		name string
		data string
		mode os.FileMode
	}{
		{"unknown field", strings.Replace(valid, `"clean_shutdown":false`, `"unknown":1,"clean_shutdown":false`, 1), 0o600},
		{"duplicate", strings.Replace(valid, `"sender_id":"auth-app"`, `"sender_id":"auth-app","sender_id":"auth-app"`, 1), 0o600},
		{"trailing", valid + `{}`, 0o600},
		{"wrong endpoint", strings.Replace(valid, "/internal/v1/auth-events", "/internal/v1/gateway-events", 1), 0o600},
		{"invalid epoch", strings.Replace(valid, "AQEBAQEBAQEBAQEBAQEBAQ", "AAAAAAAAAAAAAAAAAAAAA", 1), 0o600},
		{"digest without sequence", strings.Replace(valid, `"last_acknowledged_body_digest":""`, `"last_acknowledged_body_digest":"sha256:`+strings.Repeat("a", 64)+`"`, 1), 0o600},
		{"public mode", valid, 0o644},
		{"oversized", strings.Repeat("x", maximumCheckpointBytes+1), 0o600},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "checkpoint.json")
			if err := os.WriteFile(path, []byte(test.data), test.mode); err != nil {
				t.Fatal(err)
			}
			if _, _, err := loadCheckpoint(path); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
		})
	}

	missing := filepath.Join(t.TempDir(), "missing.json")
	if _, exists, err := loadCheckpoint(missing); err != nil || exists {
		t.Fatalf("missing exists=%v err=%v", exists, err)
	}
}

func TestCheckpointTargetMustBeRegular(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := atomicWriteCheckpoint(directory, []byte("{}\n")); err == nil {
		t.Fatal("directory target accepted")
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteCheckpoint(link, []byte("{}\n")); err == nil {
		t.Fatal("symlink target accepted")
	}
}
