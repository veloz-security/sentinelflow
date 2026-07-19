package authsender

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/devwooops/sentinelflow/internal/events"
	"github.com/devwooops/sentinelflow/internal/ingestion"
)

const maximumCheckpointBytes = 4096

type checkpoint struct {
	SenderID                   string `json:"sender_id"`
	EndpointPath               string `json:"endpoint_path"`
	SenderEpoch                string `json:"sender_epoch"`
	LastAcknowledgedSequence   uint64 `json:"last_acknowledged_sequence"`
	LastAcknowledgedBodyDigest string `json:"last_acknowledged_body_digest"`
	CleanShutdown              bool   `json:"clean_shutdown"`
}

func (s *Sender) storeCheckpoint(clean bool) error {
	state := checkpoint{
		SenderID:                   s.config.SenderID,
		EndpointPath:               ingestion.AuthEventsPath,
		SenderEpoch:                s.epoch,
		LastAcknowledgedSequence:   s.lastAckSequence,
		LastAcknowledgedBodyDigest: s.lastAckDigest,
		CleanShutdown:              clean,
	}
	data, err := json.Marshal(state)
	if err != nil {
		return errors.New("authsender: encode checkpoint")
	}
	data = append(data, '\n')
	return atomicWriteCheckpoint(s.config.CheckpointFile, data)
}

func loadCheckpoint(path string) (checkpoint, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return checkpoint{}, false, nil
	}
	if err != nil {
		return checkpoint{}, false, errors.New("authsender: inspect checkpoint")
	}
	if err := validateCheckpointInfo(info); err != nil {
		return checkpoint{}, false, err
	}
	file, err := os.Open(path)
	if err != nil {
		return checkpoint{}, false, errors.New("authsender: open checkpoint")
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) || validateCheckpointInfo(openedInfo) != nil {
		_ = file.Close()
		return checkpoint{}, false, errors.New("authsender: checkpoint changed during open")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumCheckpointBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > maximumCheckpointBytes || validateStrictJSONObject(data) != nil {
		return checkpoint{}, false, errors.New("authsender: invalid checkpoint bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state checkpoint
	if err := decoder.Decode(&state); err != nil {
		return checkpoint{}, false, errors.New("authsender: invalid checkpoint")
	}
	if !senderPattern.MatchString(state.SenderID) || state.EndpointPath != ingestion.AuthEventsPath || !validEpoch(state.SenderEpoch) ||
		state.LastAcknowledgedSequence > events.MaxSafeInteger ||
		(state.LastAcknowledgedSequence == 0 && state.LastAcknowledgedBodyDigest != "") ||
		(state.LastAcknowledgedSequence > 0 && !digestPattern.MatchString(state.LastAcknowledgedBodyDigest)) {
		return checkpoint{}, false, errors.New("authsender: invalid checkpoint")
	}
	return state, true, nil
}

func validateCheckpointInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return errors.New("authsender: unsafe checkpoint file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() {
			return errors.New("authsender: unsafe checkpoint ownership")
		}
	}
	return nil
}

func atomicWriteCheckpoint(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("authsender: create checkpoint directory")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("authsender: unsafe checkpoint target")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("authsender: inspect checkpoint target")
	}

	temporary, err := os.CreateTemp(directory, ".authsender-checkpoint-*")
	if err != nil {
		return errors.New("authsender: create checkpoint temporary file")
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return errors.New("authsender: set checkpoint permissions")
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return errors.New("authsender: write checkpoint")
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return errors.New("authsender: sync checkpoint")
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return errors.New("authsender: close checkpoint")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return errors.New("authsender: replace checkpoint")
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return errors.New("authsender: open checkpoint directory")
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("authsender: sync checkpoint directory")
	}
	return nil
}
