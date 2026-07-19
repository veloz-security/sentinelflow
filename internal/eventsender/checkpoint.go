package eventsender

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/devwooops/sentinelflow/internal/observability"
)

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
		EndpointPath:               ingestionGatewayPath,
		SenderEpoch:                s.epoch,
		LastAcknowledgedSequence:   s.lastAckSequence,
		LastAcknowledgedBodyDigest: s.lastAckDigest,
		CleanShutdown:              clean,
	}
	data, err := json.Marshal(state)
	if err != nil {
		return errors.New("eventsender: encode checkpoint")
	}
	data = append(data, '\n')
	err = atomicWriteCheckpoint(s.config.CheckpointFile, data)
	if err != nil {
		s.config.Metrics.ObserveCheckpoint(observability.CheckpointStore, observability.CheckpointError)
		return err
	}
	s.config.Metrics.ObserveCheckpoint(observability.CheckpointStore, observability.CheckpointSuccess)
	return nil
}

const ingestionGatewayPath = "/internal/v1/gateway-events"

func loadCheckpoint(path string) (checkpoint, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return checkpoint{}, false, nil
	}
	if err != nil {
		return checkpoint{}, false, errors.New("eventsender: inspect checkpoint")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return checkpoint{}, false, errors.New("eventsender: unsafe checkpoint file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return checkpoint{}, false, errors.New("eventsender: checkpoint must not be hard-linked")
	}
	file, err := os.Open(path)
	if err != nil {
		return checkpoint{}, false, errors.New("eventsender: open checkpoint")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 4096 || validateStrictJSON(data) != nil {
		return checkpoint{}, false, errors.New("eventsender: invalid checkpoint bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state checkpoint
	if err := decoder.Decode(&state); err != nil {
		return checkpoint{}, false, errors.New("eventsender: invalid checkpoint")
	}
	decodedEpoch, epochErr := base64.RawURLEncoding.Strict().DecodeString(state.SenderEpoch)
	if !senderPattern.MatchString(state.SenderID) ||
		state.EndpointPath != ingestionGatewayPath || epochErr != nil || len(decodedEpoch) != 16 ||
		state.LastAcknowledgedSequence > eventsMaxSafeInteger ||
		(state.LastAcknowledgedSequence == 0 && state.LastAcknowledgedBodyDigest != "") ||
		(state.LastAcknowledgedSequence > 0 && !digestPattern.MatchString(state.LastAcknowledgedBodyDigest)) {
		return checkpoint{}, false, errors.New("eventsender: invalid checkpoint")
	}
	return state, true, nil
}

const eventsMaxSafeInteger = uint64(9007199254740991)

func atomicWriteCheckpoint(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("eventsender: create checkpoint directory")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("eventsender: unsafe checkpoint target")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("eventsender: inspect checkpoint target")
	}
	temporary, err := os.CreateTemp(directory, ".sender-checkpoint-*")
	if err != nil {
		return errors.New("eventsender: create checkpoint temporary file")
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return errors.New("eventsender: set checkpoint permissions")
	}
	if _, err := temporary.Write(data); err != nil {
		cleanup()
		return errors.New("eventsender: write checkpoint")
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return errors.New("eventsender: sync checkpoint")
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return errors.New("eventsender: close checkpoint")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return errors.New("eventsender: replace checkpoint")
	}
	dir, err := os.Open(directory)
	if err != nil {
		return errors.New("eventsender: open checkpoint directory")
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("eventsender: sync checkpoint directory")
	}
	return nil
}
