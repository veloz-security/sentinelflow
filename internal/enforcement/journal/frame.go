package journal

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
)

const (
	frameHeaderBytes = 24
	checksumBytes    = sha256.Size
	frameVersion     = byte(1)
	recordStarted    = byte(1)
	recordTerminal   = byte(2)
)

var frameMagic = [8]byte{'S', 'F', 'J', 'N', 'L', 'v', '1', '\n'}

type decodedFrame struct {
	recordType byte
	sequence   uint64
	payload    []byte
}

func encodeFrame(recordType byte, sequence uint64, payload []byte) ([]byte, error) {
	if (recordType != recordStarted && recordType != recordTerminal) || sequence == 0 ||
		sequence > 1<<53-1 || len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return nil, reject(ErrorCorrupt)
	}
	frame := make([]byte, frameHeaderBytes+len(payload)+checksumBytes)
	copy(frame[:8], frameMagic[:])
	frame[8] = frameVersion
	frame[9] = recordType
	// Bytes 10..11 are reserved and must remain zero.
	binary.BigEndian.PutUint64(frame[12:20], sequence)
	binary.BigEndian.PutUint32(frame[20:24], uint32(len(payload)))
	copy(frame[frameHeaderBytes:], payload)
	sum := sha256.Sum256(frame[:frameHeaderBytes+len(payload)])
	copy(frame[frameHeaderBytes+len(payload):], sum[:])
	return frame, nil
}

func decodeFrame(frame []byte) (decodedFrame, error) {
	if len(frame) < frameHeaderBytes+checksumBytes || len(frame) > MaxFrameBytes ||
		!bytes.Equal(frame[:8], frameMagic[:]) {
		return decodedFrame{}, reject(ErrorCorrupt)
	}
	if frame[8] != frameVersion {
		return decodedFrame{}, reject(ErrorVersion)
	}
	if frame[9] != recordStarted && frame[9] != recordTerminal {
		return decodedFrame{}, reject(ErrorVersion)
	}
	if frame[10] != 0 || frame[11] != 0 {
		return decodedFrame{}, reject(ErrorCorrupt)
	}
	sequence := binary.BigEndian.Uint64(frame[12:20])
	length := binary.BigEndian.Uint32(frame[20:24])
	if sequence == 0 || sequence > 1<<53-1 || length == 0 || length > MaxPayloadBytes ||
		int(length)+frameHeaderBytes+checksumBytes != len(frame) {
		return decodedFrame{}, reject(ErrorCorrupt)
	}
	payloadEnd := frameHeaderBytes + int(length)
	expected := sha256.Sum256(frame[:payloadEnd])
	if subtle.ConstantTimeCompare(expected[:], frame[payloadEnd:]) != 1 {
		return decodedFrame{}, reject(ErrorCorrupt)
	}
	return decodedFrame{recordType: frame[9], sequence: sequence, payload: append([]byte(nil), frame[frameHeaderBytes:payloadEnd]...)}, nil
}
