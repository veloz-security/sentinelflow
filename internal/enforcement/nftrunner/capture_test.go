package nftrunner

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBoundedCaptureLimitsStreamsTogetherAndCancelsOnce(t *testing.T) {
	t.Parallel()
	var cancellations atomic.Int32
	capture := newBoundedCapture(8, func() { cancellations.Add(1) })
	if count, err := capture.writer(false).Write([]byte("12345")); err != nil || count != 5 {
		t.Fatalf("stdout write = %d, %v", count, err)
	}
	if count, err := capture.writer(true).Write([]byte("abcdef")); err != nil || count != 6 {
		t.Fatalf("stderr write = %d, %v", count, err)
	}
	if count, err := capture.writer(false).Write([]byte("ignored")); err != nil || count != 7 {
		t.Fatalf("overflow write = %d, %v", count, err)
	}
	stdout, stderr, overflow := capture.result()
	if !overflow || !bytes.Equal(stdout, []byte("12345")) || !bytes.Equal(stderr, []byte("abc")) ||
		cancellations.Load() != 1 {
		t.Fatalf("capture = %q/%q overflow=%t cancels=%d", stdout, stderr, overflow, cancellations.Load())
	}
	stdout[0] = 'x'
	again, _, _ := capture.result()
	if bytes.Equal(stdout, again) {
		t.Fatal("capture result was not defensive")
	}
}

func TestBoundedCaptureIsRaceSafe(t *testing.T) {
	t.Parallel()
	cancel := func() {}
	capture := newBoundedCapture(4096, cancel)
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func(stderr bool) {
			defer wait.Done()
			for write := 0; write < 32; write++ {
				_, _ = capture.writer(stderr).Write(bytes.Repeat([]byte{'x'}, 16))
			}
		}(index%2 == 0)
	}
	wait.Wait()
	stdout, stderr, overflow := capture.result()
	if !overflow || len(stdout)+len(stderr) != 4096 {
		t.Fatalf("capture bytes=%d overflow=%t", len(stdout)+len(stderr), overflow)
	}
}
