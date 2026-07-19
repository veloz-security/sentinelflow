package config

import (
	"testing"

	"github.com/devwooops/sentinelflow/internal/adminauth"
)

func TestAdminBoundarySyntaxMatchesRuntimePolicies(t *testing.T) {
	t.Parallel()
	originSets := [][]string{
		{"https://admin.example.test"},
		{"https://admin.example.test:8443", "http://localhost:4173"},
		{"http://console.localhost:5173"},
		{"http://127.0.0.1:4173"},
		{"http://admin.example.test"},
		{"https://Admin.example.test"},
		{"https://admin.example.test/"},
		{"https://admin.example.test", "https://admin.example.test"},
	}
	for _, origins := range originSets {
		_, runtimeErr := adminauth.NewOriginPolicy(origins)
		if got, want := validAdminOrigins(origins), runtimeErr == nil; got != want {
			t.Fatalf("origin policy drift for %q: config=%v runtime=%v", origins, got, want)
		}
	}

	for _, name := range []string{"sentinelflow_admin", "__Host-sentinelflow", "bad cookie", "", "bad;cookie"} {
		_, runtimeErr := adminauth.NewCookiePolicy(name, adminauth.CookieTransportTLS)
		if got, want := validCookieName(name), runtimeErr == nil; got != want {
			t.Fatalf("cookie policy drift for %q: config=%v runtime=%v", name, got, want)
		}
	}
}
