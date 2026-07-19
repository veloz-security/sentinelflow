package config

import (
	"encoding/json"
	"strings"
)

const redacted = "[REDACTED]"

// Secret is an intentionally opaque configuration value. Call Reveal only at
// the adapter boundary that consumes the credential. Formatting and JSON
// marshaling never expose the underlying value.
type Secret struct {
	value string
}

func makeSecret(value string) Secret {
	return Secret{value: value}
}

// Reveal returns the credential for an explicit handoff to its consumer.
func (s Secret) Reveal() string {
	return s.value
}

func (s Secret) IsSet() bool {
	return s.value != ""
}

func (s Secret) String() string {
	if !s.IsSet() {
		return "[UNSET]"
	}
	return redacted
}

func (s Secret) GoString() string {
	return s.String()
}

func (s Secret) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// IsSecretName identifies environment variables whose values must never be
// included in diagnostics. It intentionally over-redacts ambiguous names.
func IsSecretName(name string) bool {
	name = strings.ToUpper(name)
	if strings.HasPrefix(name, "DATABASE_") && strings.HasSuffix(name, "_URL") {
		return true
	}
	for _, marker := range []string{"API_KEY", "PASSWORD", "PRIVATE_KEY", "HMAC_KEY", "HASH_KEY", "TOKEN", "SECRET"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// RedactValue is safe for configuration diagnostics and structured logs.
func RedactValue(name, value string) string {
	if IsSecretName(name) && value != "" {
		return redacted
	}
	return value
}
