package validation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
)

const maxProtectedContractBytes = 1 << 20

var entryIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var referencePattern = regexp.MustCompile(`^RFC[0-9]+(?: section [0-9A-Za-z.]+)?$`)

type protectedContractDocument struct {
	SchemaVersion            string                   `json:"schema_version"`
	RegistrySource           string                   `json:"registry_source"`
	AuthoritativeRegistryURL string                   `json:"authoritative_registry_url"`
	RegistryLastUpdated      string                   `json:"registry_last_updated"`
	PolicyVersion            string                   `json:"policy_version"`
	ConfiguredAdditionsOnly  bool                     `json:"configured_additions_only"`
	Entries                  []protectedEntryDocument `json:"entries"`
}

type protectedEntryDocument struct {
	EntryID              string   `json:"entry_id"`
	CIDRs                []string `json:"cidrs"`
	Name                 string   `json:"name"`
	Reference            string   `json:"reference"`
	Source               string   `json:"source"`
	ProductionProtected  bool     `json:"production_protected"`
	DemoExceptionAllowed bool     `json:"demo_exception_allowed"`
}

func LoadProtectedContractFile(path string) (ProtectedContract, error) {
	file, err := os.Open(path)
	if err != nil {
		return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxProtectedContractBytes+1))
	if err != nil || len(raw) > maxProtectedContractBytes {
		return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
	}
	return ParseProtectedContract(raw, PinnedProtectedIPv4Digest)
}

func ParseProtectedContract(raw []byte, expectedDigest string) (ProtectedContract, error) {
	if len(raw) == 0 || len(raw) > maxProtectedContractBytes || strictJSON(raw) != nil {
		return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
	}
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
	}
	digest := sha256Digest(canonical)
	if expectedDigest != PinnedProtectedIPv4Digest || digest != expectedDigest {
		return ProtectedContract{}, &ProtectedError{Code: ErrDigestMismatch}
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document protectedContractDocument
	if err := decoder.Decode(&document); err != nil {
		return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
	}
	if document.SchemaVersion != "protected-ipv4-v1" ||
		document.RegistrySource != "IANA IPv4 Special-Purpose Address Space plus RFC 1112 multicast" ||
		document.AuthoritativeRegistryURL != "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml" ||
		document.RegistryLastUpdated != "2025-10-09" ||
		document.PolicyVersion != "sentinelflow-protected-ipv4-policy-v1" ||
		!document.ConfiguredAdditionsOnly || len(document.Entries) != 26 {
		return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
	}

	expectedExceptions := map[string]string{
		"test_net_1": "192.0.2.0/24",
		"test_net_2": "198.51.100.0/24",
		"test_net_3": "203.0.113.0/24",
	}
	seenEntries := make(map[string]struct{}, len(document.Entries))
	seenCIDRs := make(map[netip.Prefix]struct{}, 27)
	entries := make([]protectedEntry, 0, len(document.Entries))
	exceptionCount := 0
	for _, entry := range document.Entries {
		if !entryIDPattern.MatchString(entry.EntryID) || len(entry.CIDRs) < 1 || len(entry.CIDRs) > 2 ||
			entry.Name == "" || len(entry.Name) > 128 || !referencePattern.MatchString(entry.Reference) ||
			(entry.Source != "iana-special-purpose" && entry.Source != "rfc1112-multicast") || !entry.ProductionProtected {
			return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
		}
		if _, duplicate := seenEntries[entry.EntryID]; duplicate {
			return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
		}
		seenEntries[entry.EntryID] = struct{}{}
		parsed := make([]netip.Prefix, 0, len(entry.CIDRs))
		for _, text := range entry.CIDRs {
			prefix, err := parseCanonicalIPv4Prefix(text)
			if err != nil {
				return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
			}
			if _, duplicate := seenCIDRs[prefix]; duplicate {
				return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
			}
			seenCIDRs[prefix] = struct{}{}
			parsed = append(parsed, prefix)
		}
		if entry.DemoExceptionAllowed {
			expectedCIDR, allowed := expectedExceptions[entry.EntryID]
			if !allowed || len(entry.CIDRs) != 1 || entry.CIDRs[0] != expectedCIDR {
				return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
			}
			exceptionCount++
		} else if _, shouldAllow := expectedExceptions[entry.EntryID]; shouldAllow {
			return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
		}
		entries = append(entries, protectedEntry{id: entry.EntryID, cidrs: parsed, demoExceptionAllowed: entry.DemoExceptionAllowed})
	}
	if exceptionCount != len(expectedExceptions) {
		return ProtectedContract{}, &ProtectedError{Code: ErrContractInvalid}
	}
	return ProtectedContract{entries: entries, digest: digest, rawDigest: sha256Digest(raw)}, nil
}

func strictJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid JSON")
	}
	if err := consumeJSON(decoder, token, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func consumeJSON(decoder *json.Decoder, token json.Token, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds contract bound")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeJSON(decoder, value, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid object")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := consumeJSON(decoder, value, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid array")
		}
	default:
		return errors.New("invalid delimiter")
	}
	return nil
}

func canonicalJSON(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	buffer := &bytes.Buffer{}
	if err := appendCanonicalJSON(buffer, value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func appendCanonicalJSON(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case string:
		encoded, _ := json.Marshal(typed)
		buffer.Write(encoded)
	case json.Number:
		integer, err := strconv.ParseInt(typed.String(), 10, 64)
		if err != nil || integer < -9007199254740991 || integer > 9007199254740991 || strconv.FormatInt(integer, 10) != typed.String() {
			return errors.New("unsupported canonical JSON number")
		}
		buffer.WriteString(typed.String())
	case int:
		if int64(typed) < -9007199254740991 || int64(typed) > 9007199254740991 {
			return errors.New("unsupported canonical JSON number")
		}
		buffer.WriteString(strconv.Itoa(typed))
	case int64:
		if typed < -9007199254740991 || typed > 9007199254740991 {
			return errors.New("unsupported canonical JSON number")
		}
		buffer.WriteString(strconv.FormatInt(typed, 10))
	case uint32:
		buffer.WriteString(strconv.FormatUint(uint64(typed), 10))
	case uint64:
		if typed > 9007199254740991 {
			return errors.New("unsupported canonical JSON number")
		}
		buffer.WriteString(strconv.FormatUint(typed, 10))
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := appendCanonicalJSON(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys) // Contract/effective keys are ASCII; UTF-8 and UTF-16 order coincide.
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			encoded, _ := json.Marshal(key)
			buffer.Write(encoded)
			buffer.WriteByte(':')
			if err := appendCanonicalJSON(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		// Signed contracts intentionally use strings, booleans, null, and safe
		// integers only. Floating-point JCS stays outside this contract domain.
		return errors.New("unsupported canonical JSON value")
	}
	return nil
}

func sha256Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
