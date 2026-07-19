package nftbootstrap

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"regexp"
	"unicode"
	"unicode/utf8"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

var (
	nftVersionPattern  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,63})?$`)
	releaseNamePattern = regexp.MustCompile(`^[ -~]{1,128}$`)
	knownFamilies      = map[string]struct{}{
		"arp": {}, "bridge": {}, "inet": {}, "ip": {}, "ip6": {}, "netdev": {},
	}
)

type nftEntry struct {
	Metainfo *metainfoWire `json:"metainfo,omitempty"`
	Table    *tableWire    `json:"table,omitempty"`
	Chain    *chainWire    `json:"chain,omitempty"`
	Set      *setWire      `json:"set,omitempty"`
	Rule     *ruleWire     `json:"rule,omitempty"`
}

type metainfoWire struct {
	Version           string `json:"version"`
	ReleaseName       string `json:"release_name"`
	JSONSchemaVersion uint64 `json:"json_schema_version"`
}

type tableWire struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle uint64 `json:"handle"`
}

type chainWire struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Name     string `json:"name"`
	Handle   uint64 `json:"handle"`
	Type     string `json:"type"`
	Hook     string `json:"hook"`
	Priority *int64 `json:"prio"`
	Policy   string `json:"policy"`
}

type setWire struct {
	Family   string          `json:"family"`
	Name     string          `json:"name"`
	Table    string          `json:"table"`
	Type     string          `json:"type"`
	Handle   uint64          `json:"handle"`
	Flags    []string        `json:"flags"`
	Elements json.RawMessage `json:"elem,omitempty"`
}

type ruleWire struct {
	Family string     `json:"family"`
	Table  string     `json:"table"`
	Chain  string     `json:"chain"`
	Handle uint64     `json:"handle"`
	Expr   []exprWire `json:"expr"`
}

type exprWire struct {
	Match *matchWire      `json:"match,omitempty"`
	Drop  json.RawMessage `json:"drop,omitempty"`
}

type matchWire struct {
	Operator string          `json:"op"`
	Left     matchLeftWire   `json:"left"`
	Right    json.RawMessage `json:"right"`
}

type matchLeftWire struct {
	Payload payloadWire `json:"payload"`
}

type payloadWire struct {
	Protocol string `json:"protocol"`
	Field    string `json:"field"`
}

type elementWire struct {
	Element elementValueWire `json:"elem"`
}

type elementValueWire struct {
	Value   string `json:"val"`
	Timeout uint64 `json:"timeout"`
	Expires uint64 `json:"expires"`
}

type tableInventory struct {
	tableCount       int
	ownedTableExists bool
	ownedObjectCount int
	foreignCanonical []byte
	nftVersion       string
}

type liveProjection struct {
	canonical        []byte
	foreignCanonical []byte
	nftVersion       string
}

func parseTableInventory(data []byte) (tableInventory, error) {
	snapshot, err := parseRulesetSnapshot(data, ErrorInventoryInvalid)
	if err != nil {
		return tableInventory{}, reject(ErrorInventoryInvalid)
	}
	return tableInventory{
		tableCount:       snapshot.tableCount,
		ownedTableExists: snapshot.ownedTableExists,
		ownedObjectCount: snapshot.ownedObjectCount,
		foreignCanonical: append([]byte(nil), snapshot.foreignCanonical...),
		nftVersion:       snapshot.metainfo.Version,
	}, nil
}

func projectLiveSchema(data []byte) ([]byte, error) {
	projection, err := projectLiveObservation(data)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), projection.canonical...), nil
}

func projectLiveObservation(data []byte) (liveProjection, error) {
	snapshot, err := parseRulesetSnapshot(data, ErrorLiveReadbackInvalid)
	if err != nil || len(snapshot.ownedEntries) != 4 || !snapshot.ownedTableExists {
		return liveProjection{}, reject(ErrorLiveReadbackInvalid)
	}

	var table *tableWire
	var chain *chainWire
	var set *setWire
	var rule *ruleWire
	for _, entry := range snapshot.ownedEntries {
		switch {
		case onlyTable(entry) && table == nil:
			table = entry.Table
		case onlyChain(entry) && chain == nil:
			chain = entry.Chain
		case onlySet(entry) && set == nil:
			set = entry.Set
		case onlyRule(entry) && rule == nil:
			rule = entry.Rule
		default:
			return liveProjection{}, reject(ErrorLiveReadbackInvalid)
		}
	}
	if !validOwnedTable(table) || !validOwnedChain(chain) || !validOwnedSet(set) || !validOwnedRule(rule) {
		return liveProjection{}, reject(ErrorLiveReadbackInvalid)
	}

	projection := map[string]any{
		"schema_version": nftvalidate.LiveSchemaVersion,
		"family":         table.Family,
		"table":          table.Name,
		"set": map[string]any{
			"name":  set.Name,
			"type":  set.Type,
			"flags": append([]string(nil), set.Flags...),
		},
		"chain": map[string]any{
			"name":     chain.Name,
			"type":     chain.Type,
			"hook":     chain.Hook,
			"priority": *chain.Priority,
			"policy":   chain.Policy,
		},
		"rule": map[string]any{
			"protocol":         "tcp",
			"destination_port": nftvalidate.GatewayPort,
			"source_set":       set.Name,
			"verdict":          "drop",
			"owned_rule_count": 1,
		},
	}
	canonical, marshalErr := json.Marshal(projection)
	if marshalErr != nil {
		return liveProjection{}, reject(ErrorLiveReadbackInvalid)
	}
	return liveProjection{
		canonical:        canonical,
		foreignCanonical: append([]byte(nil), snapshot.foreignCanonical...),
		nftVersion:       snapshot.metainfo.Version,
	}, nil
}

func validMetainfo(value *metainfoWire) bool {
	return value != nil && value.JSONSchemaVersion == 1 &&
		nftVersionPattern.MatchString(value.Version) && releaseNamePattern.MatchString(value.ReleaseName)
}

func validInventoryTable(value *tableWire) bool {
	if value == nil || value.Handle == 0 || value.Handle > maxSafeInteger ||
		!validPrintable(value.Name, 256) {
		return false
	}
	_, familyKnown := knownFamilies[value.Family]
	return familyKnown
}

func validOwnedTable(value *tableWire) bool {
	return validInventoryTable(value) && value.Family == nftvalidate.Family && value.Name == nftvalidate.Table
}

func validOwnedChain(value *chainWire) bool {
	return value != nil && value.Family == nftvalidate.Family && value.Table == nftvalidate.Table &&
		value.Name == nftvalidate.GatewayChain && value.Handle > 0 && value.Handle <= maxSafeInteger &&
		value.Type == "filter" && value.Hook == "input" &&
		value.Priority != nil && *value.Priority == 0 && value.Policy == "accept"
}

func validOwnedSet(value *setWire) bool {
	if value == nil || value.Family != nftvalidate.Family || value.Table != nftvalidate.Table ||
		value.Name != nftvalidate.BlacklistSet || value.Type != nftvalidate.SetType ||
		value.Handle == 0 || value.Handle > maxSafeInteger ||
		len(value.Flags) != 1 || value.Flags[0] != "timeout" {
		return false
	}
	return validElements(value.Elements)
}

func validElements(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	var elements []elementWire
	if strictDecode(raw, &elements) != nil || len(elements) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(elements))
	for _, wrapper := range elements {
		value := wrapper.Element
		address, err := netip.ParseAddr(value.Value)
		if err != nil || !address.Is4() || address.String() != value.Value ||
			value.Timeout < uint64(nftvalidate.MinTTLSeconds) ||
			value.Timeout > uint64(nftvalidate.MaxTTLSeconds) || value.Expires == 0 ||
			value.Expires > value.Timeout || value.Expires > uint64(nftvalidate.MaxTTLSeconds) {
			return false
		}
		if _, duplicate := seen[value.Value]; duplicate {
			return false
		}
		seen[value.Value] = struct{}{}
	}
	return true
}

func validOwnedRule(value *ruleWire) bool {
	if value == nil || value.Family != nftvalidate.Family || value.Table != nftvalidate.Table ||
		value.Chain != nftvalidate.GatewayChain || value.Handle == 0 || value.Handle > maxSafeInteger ||
		len(value.Expr) != 3 {
		return false
	}
	if !validPortMatch(value.Expr[0]) || !validSourceSetMatch(value.Expr[1]) {
		return false
	}
	return onlyDropExpr(value.Expr[2])
}

func validPortMatch(value exprWire) bool {
	if !onlyMatchExpr(value) || value.Match.Operator != "==" ||
		value.Match.Left.Payload.Protocol != "tcp" || value.Match.Left.Payload.Field != "dport" {
		return false
	}
	var port uint64
	return strictDecode(value.Match.Right, &port) == nil && port == uint64(nftvalidate.GatewayPort)
}

func validSourceSetMatch(value exprWire) bool {
	if !onlyMatchExpr(value) || value.Match.Operator != "==" ||
		value.Match.Left.Payload.Protocol != "ip" || value.Match.Left.Payload.Field != "saddr" {
		return false
	}
	var reference string
	return strictDecode(value.Match.Right, &reference) == nil && reference == "@"+nftvalidate.BlacklistSet
}

func validPrintable(value string, maxBytes int) bool {
	if !utf8.ValidString(value) || value == "" || len(value) > maxBytes {
		return false
	}
	for _, current := range value {
		if unicode.IsControl(current) {
			return false
		}
	}
	return true
}

func onlyMetainfo(value nftEntry) bool {
	return value.Metainfo != nil && value.Table == nil && value.Chain == nil && value.Set == nil && value.Rule == nil
}

func onlyTable(value nftEntry) bool {
	return value.Metainfo == nil && value.Table != nil && value.Chain == nil && value.Set == nil && value.Rule == nil
}

func onlyChain(value nftEntry) bool {
	return value.Metainfo == nil && value.Table == nil && value.Chain != nil && value.Set == nil && value.Rule == nil
}

func onlySet(value nftEntry) bool {
	return value.Metainfo == nil && value.Table == nil && value.Chain == nil && value.Set != nil && value.Rule == nil
}

func onlyRule(value nftEntry) bool {
	return value.Metainfo == nil && value.Table == nil && value.Chain == nil && value.Set == nil && value.Rule != nil
}

func onlyMatchExpr(value exprWire) bool {
	return value.Match != nil && len(value.Drop) == 0
}

func onlyDropExpr(value exprWire) bool {
	return value.Match == nil && bytes.Equal(bytes.TrimSpace(value.Drop), []byte("null"))
}

func strictDecode(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return reject(ErrorLiveReadbackInvalid)
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
		return reject(ErrorLiveReadbackInvalid)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int, tokens *int) error {
	if depth > MaxJSONDepth || *tokens >= MaxJSONTokens {
		return reject(ErrorLiveReadbackInvalid)
	}
	token, err := decoder.Token()
	if err != nil {
		return reject(ErrorLiveReadbackInvalid)
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
			if *tokens >= MaxJSONTokens {
				return reject(ErrorLiveReadbackInvalid)
			}
			keyToken, tokenErr := decoder.Token()
			if tokenErr != nil {
				return reject(ErrorLiveReadbackInvalid)
			}
			(*tokens)++
			key, ok := keyToken.(string)
			if !ok {
				return reject(ErrorLiveReadbackInvalid)
			}
			if _, duplicate := keys[key]; duplicate {
				return reject(ErrorLiveReadbackInvalid)
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
		return reject(ErrorLiveReadbackInvalid)
	}
}

func consumeClosingDelimiter(decoder *json.Decoder, expected json.Delim, tokens *int) error {
	if *tokens >= MaxJSONTokens {
		return reject(ErrorLiveReadbackInvalid)
	}
	token, err := decoder.Token()
	if err != nil || token != expected {
		return reject(ErrorLiveReadbackInvalid)
	}
	(*tokens)++
	return nil
}
