package worker

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

type TokenSource interface {
	NewLeaseToken() (string, error)
}

type JitterSource interface {
	Uint64() (uint64, error)
}

type CryptoTokenSource struct{}

func (CryptoTokenSource) NewLeaseToken() (string, error) {
	return uuidV4From(rand.Reader)
}

type CryptoJitterSource struct{}

func (CryptoJitterSource) Uint64() (uint64, error) {
	var value [8]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return 0, fmt.Errorf("worker: jitter entropy unavailable: %w", err)
	}
	return binary.BigEndian.Uint64(value[:]), nil
}

func uuidV4From(reader io.Reader) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return "", fmt.Errorf("worker: lease token entropy unavailable: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
