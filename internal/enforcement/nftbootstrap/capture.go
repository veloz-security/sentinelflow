package nftbootstrap

import (
	"bytes"
	"context"
	"sync"
)

type boundedCapture struct {
	mu       sync.Mutex
	limit    int
	total    int
	overflow bool
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	cancel   context.CancelFunc
}

func newBoundedCapture(limit int, cancel context.CancelFunc) *boundedCapture {
	return &boundedCapture{limit: limit, cancel: cancel}
}

func (capture *boundedCapture) writer(stderr bool) captureWriter {
	return captureWriter{capture: capture, stderr: stderr}
}

func (capture *boundedCapture) write(value []byte, stderr bool) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()

	remaining := capture.limit - capture.total
	if remaining < 0 {
		remaining = 0
	}
	accepted := len(value)
	if accepted > remaining {
		accepted = remaining
		if !capture.overflow {
			capture.overflow = true
			capture.cancel()
		}
	}
	if accepted > 0 {
		if stderr {
			_, _ = capture.stderr.Write(value[:accepted])
		} else {
			_, _ = capture.stdout.Write(value[:accepted])
		}
		capture.total += accepted
	}
	return len(value), nil
}

func (capture *boundedCapture) result() ([]byte, []byte, bool) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]byte(nil), capture.stdout.Bytes()...),
		append([]byte(nil), capture.stderr.Bytes()...), capture.overflow
}

type captureWriter struct {
	capture *boundedCapture
	stderr  bool
}

func (writer captureWriter) Write(value []byte) (int, error) {
	return writer.capture.write(value, writer.stderr)
}
