package main

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDecodeDemoKey(t *testing.T) {
	t.Parallel()
	key := []byte(strings.Repeat("k", minimumKeyBytes))
	for _, encoded := range []string{
		base64.StdEncoding.EncodeToString(key),
		base64.RawStdEncoding.EncodeToString(key),
	} {
		decoded, err := decodeDemoKey(encoded, 128)
		if err != nil || string(decoded) != string(key) {
			t.Fatalf("decodeDemoKey() = %d bytes, %v", len(decoded), err)
		}
	}
	for _, test := range []struct {
		name    string
		encoded string
		maximum int
	}{
		{name: "empty", maximum: 128},
		{name: "malformed", encoded: "not-base64", maximum: 128},
		{name: "short", encoded: base64.StdEncoding.EncodeToString([]byte("short")), maximum: 128},
		{name: "too long", encoded: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 129))), maximum: 128},
		{name: "impossible maximum", encoded: base64.StdEncoding.EncodeToString(key), maximum: minimumKeyBytes - 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if decoded, err := decodeDemoKey(test.encoded, test.maximum); err == nil || decoded != nil {
				t.Fatalf("invalid key accepted: %d bytes, %v", len(decoded), err)
			}
		})
	}
}

func TestNewDemoServerUsesBoundedHTTPSettings(t *testing.T) {
	t.Parallel()
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := newDemoServer("172.30.0.10:8081", handler, slog.Default())
	if server.Addr != "172.30.0.10:8081" || server.Handler == nil || server.ErrorLog == nil {
		t.Fatalf("incomplete server = %+v", server)
	}
	if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 10*time.Second ||
		server.WriteTimeout != 10*time.Second || server.IdleTimeout != 30*time.Second ||
		server.MaxHeaderBytes != demoMaxHeaderBytes {
		t.Fatalf("unsafe server limits = %+v", server)
	}
}

func TestRunRejectsMissingRuntimeDependencies(t *testing.T) {
	t.Parallel()
	if err := run(t.Context(), nil); err == nil {
		t.Fatal("nil logger accepted")
	}
}
