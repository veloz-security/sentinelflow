// Package ipc implements SentinelFlow's private dispatcher/executor wire
// contract. It has no network listener, signing key, database, or nftables
// authority; callers must provide those boundaries separately.
package ipc

import (
	"encoding/binary"
	"errors"
	"io"
)

const MaxFramePayloadBytes = 16 * 1024

var (
	ErrFrameZeroLength   = errors.New("executor IPC frame has zero length")
	ErrFrameOversized    = errors.New("executor IPC frame exceeds the payload bound")
	ErrFrameTruncated    = errors.New("executor IPC frame is truncated")
	ErrFrameTrailingData = errors.New("executor IPC connection contains trailing data")
	ErrFrameTermination  = errors.New("executor IPC connection did not terminate cleanly")
	ErrFrameWrite        = errors.New("executor IPC frame write failed")
)

// EncodeFrame returns the exact uint32-big-endian prefix and payload bytes.
func EncodeFrame(payload []byte) ([]byte, error) {
	if err := validateFramePayload(payload); err != nil {
		return nil, err
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame, nil
}

// WriteFrame writes one complete frame. A short write is retried; a writer
// that makes no progress fails closed.
func WriteFrame(writer io.Writer, payload []byte) error {
	if writer == nil {
		return ErrFrameWrite
	}
	frame, err := EncodeFrame(payload)
	if err != nil {
		return err
	}
	for len(frame) > 0 {
		written, writeErr := writer.Write(frame)
		if written < 0 || written > len(frame) {
			return ErrFrameWrite
		}
		if written > 0 {
			frame = frame[written:]
		}
		if writeErr != nil || written == 0 {
			return ErrFrameWrite
		}
	}
	return nil
}

// ReadSingleFrame reads one frame and then requires EOF. Dispatcher clients
// must half-close their request write side, and executor servers close after
// their one response, so a second frame or any trailing byte is observable
// before an artifact reaches a privileged handler.
func ReadSingleFrame(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, ErrFrameTruncated
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, ErrFrameTruncated
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 {
		return nil, ErrFrameZeroLength
	}
	if size > MaxFramePayloadBytes {
		return nil, ErrFrameOversized
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, ErrFrameTruncated
	}

	var trailing [1]byte
	count, err := io.ReadFull(reader, trailing[:])
	if count != 0 {
		return nil, ErrFrameTrailingData
	}
	if !errors.Is(err, io.EOF) {
		return nil, ErrFrameTermination
	}
	return payload, nil
}

func validateFramePayload(payload []byte) error {
	if len(payload) == 0 {
		return ErrFrameZeroLength
	}
	if len(payload) > MaxFramePayloadBytes {
		return ErrFrameOversized
	}
	return nil
}
