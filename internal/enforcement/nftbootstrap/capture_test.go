package nftbootstrap

import (
	"context"
	"testing"
)

func TestBoundedCaptureStopsAtCombinedLimitAndCancels(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	capture := newBoundedCapture(5, cancel)
	if count, err := capture.writer(false).Write([]byte("abc")); err != nil || count != 3 {
		t.Fatalf("stdout write = %d, %v", count, err)
	}
	if count, err := capture.writer(true).Write([]byte("defg")); err != nil || count != 4 {
		t.Fatalf("stderr write = %d, %v", count, err)
	}
	stdout, stderr, overflow := capture.result()
	if string(stdout) != "abc" || string(stderr) != "de" || !overflow || ctx.Err() != context.Canceled {
		t.Fatalf("capture = stdout %q stderr %q overflow=%t err=%v", stdout, stderr, overflow, ctx.Err())
	}
	stdout[0] = 'X'
	if next, _, _ := capture.result(); string(next) != "abc" {
		t.Fatal("capture exposed mutable output")
	}
}
