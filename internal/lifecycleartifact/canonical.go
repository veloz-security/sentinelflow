package lifecycleartifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	uuidPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	schedulerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// appendJCSString is RFC 8785 compatible for this package because every
// dynamic string is first restricted to the schemas' ASCII-only alphabets.
func appendJCSString(destination []byte, value string) []byte {
	encoded, _ := json.Marshal(value)
	return append(destination, encoded...)
}

func appendUint(destination []byte, value uint64) []byte {
	return strconv.AppendUint(destination, value, 10)
}

func validCanonicalIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

func validPurpose(value Purpose) bool {
	return value == PurposeReconciliation || value == PurposeExpiryConfirmation || value == PurposeOperatorStatus
}

func normalizeTime(value time.Time) (time.Time, bool) {
	if value.IsZero() || value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, false
	}
	value = value.Round(0).UTC()
	if value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, false
	}
	return value, true
}

// formatCanonicalTime uses RFC3339Nano in UTC. Whole-second values retain the
// frozen contract's explicit millisecond form (.000Z); non-zero fractional
// seconds use RFC3339Nano's shortest exact representation.
func formatCanonicalTime(value time.Time) string {
	formatted := value.UTC().Format(time.RFC3339Nano)
	if !strings.Contains(formatted, ".") {
		return strings.TrimSuffix(formatted, "Z") + ".000Z"
	}
	return formatted
}

func parseCanonicalTime(value string) (time.Time, bool) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	parsed, ok := normalizeTime(parsed)
	return parsed, ok && formatCanonicalTime(parsed) == value
}

func strictDecode(data []byte, maximum int, destination any) error {
	if len(data) == 0 || len(data) > maximum || !utf8.Valid(data) {
		return reject(ErrorEncoding)
	}
	if err := rejectDuplicateNames(data); err != nil {
		return reject(ErrorEncoding)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return reject(ErrorEncoding)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return reject(ErrorEncoding)
	}
	return nil
}

func rejectDuplicateNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func scanJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
	default:
		return errors.New("unexpected delimiter")
	}
	return nil
}
