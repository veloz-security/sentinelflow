package gateway

import (
	"errors"
	"strings"

	"github.com/devwooops/sentinelflow/internal/events"
)

var errInvalidPath = errors.New("request path is outside the gateway contract")

func validateTarget(requestURI string, maxTarget, maxPath int) (string, error) {
	if len(requestURI) == 0 || len(requestURI) > maxTarget || requestURI[0] != '/' || strings.HasPrefix(requestURI, "//") {
		return "", errInvalidPath
	}
	if err := validateTargetSyntax(requestURI); err != nil {
		return "", err
	}
	path := requestURI
	if index := strings.IndexByte(path, '?'); index >= 0 {
		path = path[:index]
	}
	if len(path) > maxPath {
		return "", errInvalidPath
	}
	return canonicalPath(path, maxPath)
}

func validateTargetSyntax(target string) error {
	for i := 0; i < len(target); i++ {
		value := target[i]
		if value == '\\' || value == 0 || value < 0x20 || value == 0x7f {
			return errInvalidPath
		}
		if value != '%' {
			continue
		}
		if i+2 >= len(target) {
			return errInvalidPath
		}
		hi, okHi := hexValue(target[i+1])
		lo, okLo := hexValue(target[i+2])
		if !okHi || !okLo {
			return errInvalidPath
		}
		decoded := hi<<4 | lo
		if decoded == '/' || decoded == '\\' || decoded == 0 || decoded < 0x20 || decoded == 0x7f {
			return errInvalidPath
		}
		i += 2
	}
	return nil
}

func canonicalPath(path string, maxPath int) (string, error) {
	if path == "" || path[0] != '/' || len(path) > maxPath {
		return "", errInvalidPath
	}
	var out strings.Builder
	out.Grow(len(path))
	previousSlash := false
	for i := 0; i < len(path); {
		char := path[i]
		if char == '\\' || char == 0 || char < 0x20 || char == 0x7f {
			return "", errInvalidPath
		}
		if char == '%' {
			if i+2 >= len(path) {
				return "", errInvalidPath
			}
			hi, okHi := hexValue(path[i+1])
			lo, okLo := hexValue(path[i+2])
			if !okHi || !okLo {
				return "", errInvalidPath
			}
			decoded := hi<<4 | lo
			if decoded == '/' || decoded == '\\' || decoded == 0 || decoded < 0x20 || decoded == 0x7f {
				return "", errInvalidPath
			}
			if isUnreserved(decoded) {
				char = decoded
				i += 3
			} else {
				out.WriteByte('%')
				out.WriteByte(upperHex(decoded >> 4))
				out.WriteByte(upperHex(decoded & 0xf))
				previousSlash = false
				i += 3
				continue
			}
		} else {
			i++
		}
		if char == '/' {
			if previousSlash {
				continue
			}
			previousSlash = true
		} else {
			previousSlash = false
		}
		out.WriteByte(char)
	}
	canonical := out.String()
	for _, segment := range strings.Split(canonical, "/") {
		if segment == "." || segment == ".." {
			return "", errInvalidPath
		}
	}
	if len(canonical) > maxPath {
		return "", errInvalidPath
	}
	return canonical, nil
}

func classifyPath(path, loginPath, loginLabel string) (string, events.SuspiciousPathID) {
	route := "other"
	if path == loginPath {
		route = loginLabel
	}
	lower := strings.ToLower(path)
	switch {
	case strings.HasPrefix(lower, "/admin"), strings.HasPrefix(lower, "/administrator"):
		return route, events.SuspiciousPathAdminConsole
	case lower == "/.env":
		return route, events.SuspiciousPathEnvFile
	case lower == "/.git/config":
		return route, events.SuspiciousPathGitConfig
	case strings.HasPrefix(lower, "/wp-admin"), lower == "/wp-login.php":
		return route, events.SuspiciousPathWPAdmin
	case strings.HasPrefix(lower, "/phpmyadmin"):
		return route, events.SuspiciousPathPHPMyAdmin
	case lower == "/server-status":
		return route, events.SuspiciousPathServerStatus
	case lower == "/actuator/env":
		return route, events.SuspiciousPathActuatorEnv
	case strings.HasSuffix(lower, ".bak"), strings.HasSuffix(lower, ".backup"), strings.HasSuffix(lower, ".old"), strings.HasSuffix(lower, ".zip"):
		return route, events.SuspiciousPathBackupArchive
	default:
		return route, events.SuspiciousPathNone
	}
}

func hexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func upperHex(value byte) byte {
	const digits = "0123456789ABCDEF"
	return digits[value]
}

func isUnreserved(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
		(value >= '0' && value <= '9') || value == '-' || value == '.' || value == '_' || value == '~'
}
