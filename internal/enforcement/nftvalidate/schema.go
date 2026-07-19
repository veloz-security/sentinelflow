package nftvalidate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

type liveSchemaWire struct {
	SchemaVersion string        `json:"schema_version"`
	Family        string        `json:"family"`
	Table         string        `json:"table"`
	Set           liveSetWire   `json:"set"`
	Chain         liveChainWire `json:"chain"`
	Rule          liveRuleWire  `json:"rule"`
}

type liveSetWire struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Flags []string `json:"flags"`
}

type liveChainWire struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Hook     string `json:"hook"`
	Priority *int   `json:"priority"`
	Policy   string `json:"policy"`
}

type liveRuleWire struct {
	Protocol        string `json:"protocol"`
	DestinationPort int    `json:"destination_port"`
	SourceSet       string `json:"source_set"`
	Verdict         string `json:"verdict"`
	OwnedRuleCount  int    `json:"owned_rule_count"`
}

// ValidateOwnedSchema verifies both the byte-exact bootstrap contract and the
// separately canonicalized live structure. It never treats the raw-file SHA as
// proof of the live kernel state.
func ValidateOwnedSchema(baseContract, liveSchema []byte) (SchemaProof, error) {
	if len(baseContract) == 0 || len(baseContract) > MaxBaseContractBytes ||
		digest(baseContract) != PinnedBaseChainRawDigest {
		return SchemaProof{}, reject(ErrorBaseContract)
	}
	if len(liveSchema) == 0 || len(liveSchema) > MaxLiveSchemaBytes ||
		!utf8.Valid(liveSchema) || bytes.HasPrefix(liveSchema, []byte{0xef, 0xbb, 0xbf}) {
		return SchemaProof{}, reject(ErrorLiveSchema)
	}
	if err := strictJSONObject(liveSchema); err != nil {
		return SchemaProof{}, reject(ErrorLiveSchema)
	}
	decoder := json.NewDecoder(bytes.NewReader(liveSchema))
	decoder.DisallowUnknownFields()
	var value liveSchemaWire
	if err := decoder.Decode(&value); err != nil {
		return SchemaProof{}, reject(ErrorLiveSchema)
	}
	if value.SchemaVersion != LiveSchemaVersion || value.Family != Family || value.Table != Table ||
		value.Set.Name != BlacklistSet || value.Set.Type != SetType ||
		len(value.Set.Flags) != 1 || value.Set.Flags[0] != "timeout" ||
		value.Chain.Name != GatewayChain || value.Chain.Type != "filter" || value.Chain.Hook != "input" ||
		value.Chain.Priority == nil || *value.Chain.Priority != 0 || value.Chain.Policy != "accept" ||
		value.Rule.Protocol != "tcp" || value.Rule.DestinationPort != GatewayPort ||
		value.Rule.SourceSet != BlacklistSet || value.Rule.Verdict != "drop" || value.Rule.OwnedRuleCount != 1 {
		return SchemaProof{}, reject(ErrorLiveSchema)
	}
	canonical := canonicalLiveSchema()
	liveDigest := digest(canonical)
	if liveDigest != PinnedLiveSchemaDigest || liveDigest == PinnedBaseChainRawDigest {
		return SchemaProof{}, reject(ErrorSchemaDigest)
	}
	return SchemaProof{
		baseContractDigest: PinnedBaseChainRawDigest,
		liveSchemaDigest:   liveDigest,
		liveCanonical:      canonical,
	}, nil
}

// canonicalLiveSchema is the RFC 8785/JCS form for the fixed ASCII-key,
// safe-integer live-schema domain. All values have already been checked against
// exact constants, so emitting this byte string cannot normalize a different
// semantic schema into the accepted one.
func canonicalLiveSchema() []byte {
	return []byte(`{"chain":{"hook":"input","name":"gateway_input","policy":"accept","priority":0,"type":"filter"},"family":"inet","rule":{"destination_port":8080,"owned_rule_count":1,"protocol":"tcp","source_set":"blacklist_ipv4","verdict":"drop"},"schema_version":"nft-base-chain-live-v1","set":{"flags":["timeout"],"name":"blacklist_ipv4","type":"ipv4_addr"},"table":"sentinelflow"}`)
}

func strictJSONObject(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid JSON object")
	}
	if err := consumeJSON(decoder, token, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON input")
	}
	return nil
}

func consumeJSON(decoder *json.Decoder, token json.Token, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting exceeds bound")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
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
			return errors.New("invalid JSON object")
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
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}
