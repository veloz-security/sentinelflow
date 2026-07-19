package exportbundle

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	DatabaseURLName    = "DATABASE_READ_URL"
	EnvironmentName    = "SENTINELFLOW_ENV"
	ReadCapabilityRole = "sentinelflow_read"
)

var databaseLoginRolePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

var nonReadCapabilityRoles = map[string]bool{
	"postgres":                true,
	"sentinelflow_migration":  true,
	"sentinelflow_api":        true,
	"sentinelflow_worker":     true,
	"sentinelflow_dispatcher": true,
	"sentinelflow_retention":  true,
	"sentinelflow_metrics":    true,
}

// ValidReadLoginRole permits the demo's direct reader login and production
// deployment logins whose exact one-role membership is verified after
// connecting. Other canonical SentinelFlow capability roles fail early.
func ValidReadLoginRole(value string) bool {
	return databaseLoginRolePattern.MatchString(value) && !nonReadCapabilityRoles[value]
}

func ValidateReadDatabaseURL(raw, environment string) error {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\x00\r\n") ||
		(environment != "development" && environment != "test" && environment != "production") {
		return ErrInvalidRequest
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "postgresql" || parsed.Opaque != "" || parsed.User == nil ||
		!ValidReadLoginRole(parsed.User.Username()) || parsed.Hostname() == "" || parsed.Port() == "" ||
		parsed.Path != "/sentinelflow" || parsed.Fragment != "" || parsed.RawFragment != "" ||
		parsed.RawPath != "" || parsed.ForceQuery {
		return ErrInvalidRequest
	}
	password, hasPassword := parsed.User.Password()
	port, portErr := strconv.Atoi(parsed.Port())
	if !hasPassword || password == "" || portErr != nil || port < 1 || port > 65535 ||
		strconv.Itoa(port) != parsed.Port() {
		return ErrInvalidRequest
	}
	if parsed.RawQuery != "sslmode=verify-full" &&
		(environment == "production" || parsed.RawQuery != "sslmode=disable") {
		return ErrInvalidRequest
	}
	if parsed.String() != raw {
		return ErrInvalidRequest
	}
	return nil
}

func RejectInheritedAuthority(environ []string) error {
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || name == "" || value == "" || name == DatabaseURLName || name == EnvironmentName {
			continue
		}
		for _, prefix := range forbiddenEnvironmentPrefixes {
			if strings.HasPrefix(name, prefix) {
				return ErrInvalidRequest
			}
		}
	}
	return nil
}

func ReadPseudonymKey(path string) ([]byte, error) {
	data, err := ReadPrivateFile(path, 128)
	if err != nil {
		return nil, ErrUnsafeFile
	}
	defer clear(data)
	data = bytes.TrimSuffix(data, []byte{'\n'})
	if len(data) == 0 || bytes.ContainsAny(data, "\r\n \t") {
		return nil, ErrInvalidRequest
	}
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	decodedLength, err := base64.RawURLEncoding.Strict().Decode(decoded, data)
	if err != nil {
		clear(decoded)
		return nil, ErrInvalidRequest
	}
	decoded = decoded[:decodedLength]
	reencoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(decoded)))
	base64.RawURLEncoding.Encode(reencoded, decoded)
	canonical := bytes.Equal(reencoded, data)
	clear(reencoded)
	if len(decoded) < MinimumPseudonymKeyBytes || len(decoded) > MaximumPseudonymKeyBytes || !canonical {
		clear(decoded)
		return nil, ErrInvalidRequest
	}
	return decoded, nil
}

var forbiddenEnvironmentPrefixes = []string{
	"PG", "POSTGRES_", "DATABASE_", "OPENAI_", "ADMIN_", "SESSION_",
	"GATEWAY_", "AUTH_", "DISPATCHER_", "EXECUTOR_", "NFT_", "VALIDATOR_",
	"PROTECTED_", "HIL_", "DEMO_HISTORY_", "RETENTION_", "CONTROL_", "SENTINELFLOW_",
}
