package nftrunner

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/executor"
	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

const (
	maxJSONDepth  = 16
	maxJSONTokens = MaxProcessOutput
	maxSafeHandle = 1<<53 - 1
)

var (
	nftVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
	releasePattern    = regexp.MustCompile(`^[ -~]{1,128}$`)
)

type readbackRoot struct {
	NFTables []readbackEntry `json:"nftables"`
}

type readbackEntry struct {
	Metainfo *metainfoWire `json:"metainfo,omitempty"`
	Set      *setWire      `json:"set,omitempty"`
}

type metainfoWire struct {
	Version           string `json:"version"`
	ReleaseName       string `json:"release_name"`
	JSONSchemaVersion uint64 `json:"json_schema_version"`
}

type setWire struct {
	Family   string          `json:"family"`
	Name     string          `json:"name"`
	Table    string          `json:"table"`
	Type     string          `json:"type"`
	Handle   uint64          `json:"handle"`
	Flags    []string        `json:"flags"`
	Elements json.RawMessage `json:"elem"`
}

type elementWire struct {
	Element elementValueWire `json:"elem"`
}

type elementValueWire struct {
	Value   string `json:"val"`
	Timeout uint64 `json:"timeout"`
	Expires uint64 `json:"expires"`
}

func parseReadback(data []byte, targetIPv4, ownedSchemaDigest string) (executor.Observation, error) {
	base := executor.Observation{
		State:             capability.ReadbackMismatch,
		TargetIPv4:        targetIPv4,
		OwnedSchemaDigest: ownedSchemaDigest,
	}
	if len(data) == 0 || len(data) > MaxProcessOutput || !utf8.Valid(data) ||
		!canonicalIPv4(targetIPv4) || ownedSchemaDigest != nftvalidate.PinnedLiveSchemaDigest ||
		validateUniqueJSONKeys(data) != nil {
		return executor.Observation{}, reject(ErrorReadbackInvalid)
	}

	var document readbackRoot
	if strictDecode(data, &document) != nil || len(document.NFTables) != 2 ||
		document.NFTables[0].Metainfo == nil || document.NFTables[0].Set != nil ||
		document.NFTables[1].Metainfo != nil || document.NFTables[1].Set == nil {
		return executor.Observation{}, reject(ErrorReadbackInvalid)
	}
	metadata := document.NFTables[0].Metainfo
	if metadata.JSONSchemaVersion != 1 || !nftVersionPattern.MatchString(metadata.Version) ||
		!releasePattern.MatchString(metadata.ReleaseName) {
		return executor.Observation{}, reject(ErrorReadbackInvalid)
	}

	set := document.NFTables[1].Set
	if set.Family != nftvalidate.Family || set.Table != nftvalidate.Table ||
		set.Name != nftvalidate.BlacklistSet || set.Type != "ipv4_addr" ||
		set.Handle == 0 || set.Handle > maxSafeHandle ||
		len(set.Flags) != 1 || set.Flags[0] != "timeout" {
		return base, nil
	}

	if len(set.Elements) == 0 {
		base.State = capability.ReadbackAbsent
		return base, nil
	}
	if bytes.Equal(bytes.TrimSpace(set.Elements), []byte("null")) {
		return executor.Observation{}, reject(ErrorReadbackInvalid)
	}
	var elements []elementWire
	if strictDecode(set.Elements, &elements) != nil || len(elements) == 0 {
		return executor.Observation{}, reject(ErrorReadbackInvalid)
	}

	seen := make(map[string]struct{}, len(elements))
	var remaining uint64
	for _, wrapper := range elements {
		element := wrapper.Element
		if !canonicalIPv4(element.Value) || element.Timeout < uint64(nftvalidate.MinTTLSeconds) ||
			element.Timeout > uint64(nftvalidate.MaxTTLSeconds) || element.Expires == 0 ||
			element.Expires > element.Timeout || element.Expires > uint64(nftvalidate.MaxTTLSeconds) {
			return executor.Observation{}, reject(ErrorReadbackInvalid)
		}
		if _, duplicate := seen[element.Value]; duplicate {
			return executor.Observation{}, reject(ErrorReadbackInvalid)
		}
		seen[element.Value] = struct{}{}
		if element.Value == targetIPv4 {
			remaining = element.Expires
		}
	}
	if remaining == 0 {
		base.State = capability.ReadbackAbsent
		return base, nil
	}
	base.State = capability.ReadbackActive
	base.RemainingTTLSeconds = remaining
	return base, nil
}

func strictDecode(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return reject(ErrorReadbackInvalid)
		}
		return err
	}
	return nil
}

func validateUniqueJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	tokens := 0
	if err := consumeJSONValue(decoder, 0, &tokens); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return reject(ErrorReadbackInvalid)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int, tokens *int) error {
	if depth > maxJSONDepth || *tokens >= maxJSONTokens {
		return reject(ErrorReadbackInvalid)
	}
	token, err := decoder.Token()
	if err != nil {
		return reject(ErrorReadbackInvalid)
	}
	(*tokens)++
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			if *tokens >= maxJSONTokens {
				return reject(ErrorReadbackInvalid)
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return reject(ErrorReadbackInvalid)
			}
			(*tokens)++
			key, ok := keyToken.(string)
			if !ok {
				return reject(ErrorReadbackInvalid)
			}
			if _, duplicate := keys[key]; duplicate {
				return reject(ErrorReadbackInvalid)
			}
			keys[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		return consumeClosingDelimiter(decoder, '}', tokens)
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		return consumeClosingDelimiter(decoder, ']', tokens)
	default:
		return reject(ErrorReadbackInvalid)
	}
}

func consumeClosingDelimiter(decoder *json.Decoder, expected json.Delim, tokens *int) error {
	if *tokens >= maxJSONTokens {
		return reject(ErrorReadbackInvalid)
	}
	token, err := decoder.Token()
	if err != nil || token != expected {
		return reject(ErrorReadbackInvalid)
	}
	(*tokens)++
	return nil
}
