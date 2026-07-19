package main

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDecodeKey(t *testing.T) {
	t.Parallel()
	key := []byte(strings.Repeat("k", 32))
	for _, encoded := range []string{
		base64.StdEncoding.EncodeToString(key),
		base64.RawStdEncoding.EncodeToString(key),
	} {
		decoded, err := decodeKey(encoded)
		if err != nil || string(decoded) != string(key) {
			t.Fatalf("decodeKey() = %d bytes, %v", len(decoded), err)
		}
	}
	for _, invalid := range []string{"", "not-base64", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := decodeKey(invalid); err == nil {
			t.Fatalf("invalid key %q accepted", invalid)
		}
	}
}

func TestNewMetricsServerUsesDedicatedBoundedListener(t *testing.T) {
	t.Parallel()
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := newMetricsServer("127.0.0.1:19090", handler)
	if server.Addr != "127.0.0.1:19090" || server.Handler == nil ||
		server.ReadHeaderTimeout != 2*time.Second || server.ReadTimeout != 5*time.Second ||
		server.WriteTimeout != 5*time.Second || server.IdleTimeout != 30*time.Second ||
		server.MaxHeaderBytes != 4096 {
		t.Fatalf("unsafe metrics server: %+v", server)
	}
}
