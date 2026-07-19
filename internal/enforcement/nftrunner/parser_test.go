package nftrunner

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

// Captured from an isolated Alpine 3.21 container running nftables v1.1.1.
// The RFC 5737 values are synthetic; this fixture contains no host state.
const realNFT111ActiveJSON = `{"nftables": [{"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "blacklist_ipv4", "table": "sentinelflow", "type": "ipv4_addr", "handle": 1, "flags": ["timeout"], "elem": [{"elem": {"val": "203.0.113.20", "timeout": 1800, "expires": 1799}}]}}]}`

const realNFT111EmptyJSON = `{"nftables": [{"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}}, {"set": {"family": "inet", "name": "blacklist_ipv4", "table": "sentinelflow", "type": "ipv4_addr", "handle": 1, "flags": ["timeout"]}}]}`

const testTarget = "203.0.113.20"

func TestParseRealNFT111ActiveAndEmptyReadback(t *testing.T) {
	t.Parallel()
	active, err := parseReadback([]byte(realNFT111ActiveJSON), testTarget, nftvalidate.PinnedLiveSchemaDigest)
	if err != nil {
		t.Fatal(err)
	}
	if active.State != capability.ReadbackActive || active.TargetIPv4 != testTarget ||
		active.OwnedSchemaDigest != nftvalidate.PinnedLiveSchemaDigest || active.RemainingTTLSeconds != 1799 {
		t.Fatalf("active projection = %+v", active)
	}

	absent, err := parseReadback([]byte(realNFT111EmptyJSON), testTarget, nftvalidate.PinnedLiveSchemaDigest)
	if err != nil {
		t.Fatal(err)
	}
	if absent.State != capability.ReadbackAbsent || absent.RemainingTTLSeconds != 0 {
		t.Fatalf("empty projection = %+v", absent)
	}
}

func TestParseReadbackFindsOnlyExactCanonicalTarget(t *testing.T) {
	t.Parallel()
	data := strings.Replace(realNFT111ActiveJSON,
		`{"elem": {"val": "203.0.113.20", "timeout": 1800, "expires": 1799}}`,
		`{"elem":{"val":"203.0.113.19","timeout":60,"expires":59}},`+
			`{"elem":{"val":"203.0.113.20","timeout":1800,"expires":1777}},`+
			`{"elem":{"val":"203.0.113.21","timeout":3600,"expires":3599}}`, 1)
	observation, err := parseReadback([]byte(data), testTarget, nftvalidate.PinnedLiveSchemaDigest)
	if err != nil {
		t.Fatal(err)
	}
	if observation.State != capability.ReadbackActive || observation.RemainingTTLSeconds != 1777 {
		t.Fatalf("projection = %+v", observation)
	}

	observation, err = parseReadback([]byte(data), "203.0.113.22", nftvalidate.PinnedLiveSchemaDigest)
	if err != nil || observation.State != capability.ReadbackAbsent || observation.RemainingTTLSeconds != 0 {
		t.Fatalf("absent projection = %+v, %v", observation, err)
	}
}

func TestParseReadbackReturnsMismatchForOwnedSetDrift(t *testing.T) {
	t.Parallel()
	mutations := []string{
		strings.Replace(realNFT111EmptyJSON, `"family": "inet"`, `"family": "ip"`, 1),
		strings.Replace(realNFT111EmptyJSON, `"name": "blacklist_ipv4"`, `"name": "other"`, 1),
		strings.Replace(realNFT111EmptyJSON, `"table": "sentinelflow"`, `"table": "other"`, 1),
		strings.Replace(realNFT111EmptyJSON, `"type": "ipv4_addr"`, `"type": "ipv6_addr"`, 1),
		strings.Replace(realNFT111EmptyJSON, `"handle": 1`, `"handle": 0`, 1),
		strings.Replace(realNFT111EmptyJSON, `"flags": ["timeout"]`, `"flags": ["interval"]`, 1),
	}
	for index, data := range mutations {
		observation, err := parseReadback([]byte(data), testTarget, nftvalidate.PinnedLiveSchemaDigest)
		if err != nil || observation.State != capability.ReadbackMismatch || observation.RemainingTTLSeconds != 0 {
			t.Fatalf("case %d = %+v, %v", index, observation, err)
		}
	}
}

func TestParseReadbackRejectsMalformedNoncanonicalAndAmbiguousJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated", []byte(realNFT111ActiveJSON[:len(realNFT111ActiveJSON)-1])},
		{"trailing document", []byte(realNFT111ActiveJSON + `{}`)},
		{"unknown root field", []byte(strings.Replace(realNFT111ActiveJSON, `{"nftables":`, `{"unknown":true,"nftables":`, 1))},
		{"duplicate root key", []byte(strings.Replace(realNFT111ActiveJSON, `{"nftables":`, `{"nftables":[],"nftables":`, 1))},
		{"duplicate nested key", []byte(strings.Replace(realNFT111ActiveJSON, `"family": "inet",`, `"family":"inet","family":"inet",`, 1))},
		{"unknown set field", []byte(strings.Replace(realNFT111ActiveJSON, `"family": "inet",`, `"unknown":true,"family":"inet",`, 1))},
		{"unknown element field", []byte(strings.Replace(realNFT111ActiveJSON, `"expires": 1799`, `"expires":1799,"handle":42`, 1))},
		{"swapped entries", []byte(`{"nftables":[{"set":{"family":"inet","name":"blacklist_ipv4","table":"sentinelflow","type":"ipv4_addr","handle":1,"flags":["timeout"]}},{"metainfo":{"version":"1.1.1","release_name":"test","json_schema_version":1}}]}`)},
		{"missing metadata field", []byte(strings.Replace(realNFT111ActiveJSON, `"release_name": "Commodore Bullmoose #2", `, "", 1))},
		{"bad schema version", []byte(strings.Replace(realNFT111ActiveJSON, `"json_schema_version": 1`, `"json_schema_version": 2`, 1))},
		{"bad nft version", []byte(strings.Replace(realNFT111ActiveJSON, `"version": "1.1.1"`, `"version": "latest"`, 1))},
		{"null elements", []byte(strings.Replace(realNFT111EmptyJSON, `"flags": ["timeout"]`, `"flags":["timeout"],"elem":null`, 1))},
		{"empty explicit elements", []byte(strings.Replace(realNFT111EmptyJSON, `"flags": ["timeout"]`, `"flags":["timeout"],"elem":[]`, 1))},
		{"duplicate target", []byte(strings.Replace(realNFT111ActiveJSON,
			`[{"elem": {"val": "203.0.113.20", "timeout": 1800, "expires": 1799}}]`,
			`[{"elem":{"val":"203.0.113.20","timeout":1800,"expires":1799}},{"elem":{"val":"203.0.113.20","timeout":1800,"expires":1798}}]`, 1))},
		{"noncanonical IPv4", []byte(strings.Replace(realNFT111ActiveJSON, testTarget, "203.000.113.20", 1))},
		{"timeout below contract", []byte(strings.Replace(realNFT111ActiveJSON, `"timeout": 1800`, `"timeout": 59`, 1))},
		{"timeout above contract", []byte(strings.Replace(realNFT111ActiveJSON, `"timeout": 1800`, `"timeout": 86401`, 1))},
		{"zero expiry", []byte(strings.Replace(realNFT111ActiveJSON, `"expires": 1799`, `"expires": 0`, 1))},
		{"expiry beyond timeout", []byte(strings.Replace(realNFT111ActiveJSON, `"expires": 1799`, `"expires": 1801`, 1))},
		{"fractional expiry", []byte(strings.Replace(realNFT111ActiveJSON, `"expires": 1799`, `"expires": 1799.5`, 1))},
		{"negative expiry", []byte(strings.Replace(realNFT111ActiveJSON, `"expires": 1799`, `"expires": -1`, 1))},
		{"element null", []byte(strings.Replace(realNFT111ActiveJSON,
			`{"elem": {"val": "203.0.113.20", "timeout": 1800, "expires": 1799}}`, `{"elem":null}`, 1))},
		{"invalid UTF-8", append([]byte(realNFT111ActiveJSON), 0xff)},
		{"oversized", bytes.Repeat([]byte{' '}, MaxProcessOutput+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation, err := parseReadback(test.data, testTarget, nftvalidate.PinnedLiveSchemaDigest)
			if err == nil || observation.State != "" {
				t.Fatalf("accepted invalid readback: %+v, %v", observation, err)
			}
			requireErrorCode(t, err, ErrorReadbackInvalid)
		})
	}
}

func TestParseReadbackRejectsInvalidExpectationWithoutLeakingIt(t *testing.T) {
	t.Parallel()
	secretShaped := "203.0.113.20-do-not-log"
	for _, input := range []struct {
		target string
		digest string
	}{
		{secretShaped, nftvalidate.PinnedLiveSchemaDigest},
		{testTarget, "sha256:do-not-log"},
	} {
		_, err := parseReadback([]byte(realNFT111ActiveJSON), input.target, input.digest)
		requireErrorCode(t, err, ErrorReadbackInvalid)
		if strings.Contains(err.Error(), secretShaped) || strings.Contains(err.Error(), "do-not-log") {
			t.Fatalf("error leaked expectation: %q", err)
		}
	}
}

func FuzzParseReadbackNeverAcceptsAnUnboundedProjection(f *testing.F) {
	f.Add([]byte(realNFT111ActiveJSON))
	f.Add([]byte(realNFT111EmptyJSON))
	f.Add([]byte(`{"nftables":[]}`))
	f.Add([]byte{0xff, 0x00, '{'})
	f.Fuzz(func(t *testing.T, data []byte) {
		observation, err := parseReadback(data, testTarget, nftvalidate.PinnedLiveSchemaDigest)
		if err != nil {
			if observation.State != "" {
				t.Fatalf("failed parse returned state %q", observation.State)
			}
			return
		}
		if observation.TargetIPv4 != testTarget || observation.OwnedSchemaDigest != nftvalidate.PinnedLiveSchemaDigest {
			t.Fatalf("accepted projection changed its binding: %+v", observation)
		}
		switch observation.State {
		case capability.ReadbackActive:
			if observation.RemainingTTLSeconds == 0 || observation.RemainingTTLSeconds > uint64(nftvalidate.MaxTTLSeconds) {
				t.Fatalf("accepted unbounded active projection: %+v", observation)
			}
		case capability.ReadbackAbsent, capability.ReadbackMismatch:
			if observation.RemainingTTLSeconds != 0 {
				t.Fatalf("accepted TTL on non-active projection: %+v", observation)
			}
		default:
			t.Fatalf("accepted unsupported projection state: %+v", observation)
		}
	})
}

func requireErrorCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("error = %v, want %q", err, code)
	}
}
