package nftbootstrap

import (
	"bytes"
	"strings"
	"testing"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

func TestProjectRealNFT111FixturesToPinnedLiveSchema(t *testing.T) {
	t.Parallel()
	fixtures := []string{
		realNFT111EmptyLiveJSON,
		realNFT111ActiveLiveJSON,
	}
	var first []byte
	for index, fixture := range fixtures {
		canonical, err := projectLiveSchema([]byte(fixture))
		if err != nil {
			t.Fatalf("fixture %d: %v", index, err)
		}
		if got := digest(canonical); got != nftvalidate.PinnedLiveSchemaDigest {
			t.Fatalf("fixture %d digest = %s", index, got)
		}
		if index == 0 {
			first = canonical
		} else if !bytes.Equal(first, canonical) {
			t.Fatalf("fixture %d changed projection\nfirst=%s\ngot=%s", index, first, canonical)
		}
		for _, excluded := range []string{"203.0.113.20", "table note", "packets", "handle", "expires"} {
			if bytes.Contains(canonical, []byte(excluded)) {
				t.Fatalf("fixture %d leaked excluded state %q into %s", index, excluded, canonical)
			}
		}
	}

	proof, err := nftvalidate.ValidateOwnedSchema([]byte(testBaseContract), first)
	if err != nil || proof.BaseContractDigest() != nftvalidate.PinnedBaseChainRawDigest ||
		proof.LiveSchemaDigest() != nftvalidate.PinnedLiveSchemaDigest {
		t.Fatalf("independent contract validation = %+v, %v", proof, err)
	}
}

func TestProjectLiveSchemaAcceptsStrictDynamicElementsWithoutDigestingThem(t *testing.T) {
	t.Parallel()
	multiple := strings.Replace(realNFT111ActiveLiveJSON,
		`[{"elem": {"val": "203.0.113.20", "timeout": 1800, "expires": 1799}}]`,
		`[{"elem":{"val":"192.0.2.10","timeout":60,"expires":1}},`+
			`{"elem":{"val":"198.51.100.11","timeout":86400,"expires":86399}},`+
			`{"elem":{"val":"203.0.113.20","timeout":1800,"expires":1700}}]`, 1)
	canonical, err := projectLiveSchema([]byte(multiple))
	if err != nil || digest(canonical) != nftvalidate.PinnedLiveSchemaDigest {
		t.Fatalf("dynamic projection = %s, %v", canonical, err)
	}
}

func TestProjectLiveSchemaRejectsStructuralDriftAndExtraObjects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data string
	}{
		{"family", strings.Replace(realNFT111EmptyLiveJSON, `"family": "inet"`, `"family":"ip"`, 1)},
		{"table", strings.Replace(realNFT111EmptyLiveJSON, `"name": "sentinelflow"`, `"name":"other"`, 1)},
		{"set name", strings.Replace(realNFT111EmptyLiveJSON, `"name": "blacklist_ipv4"`, `"name":"other"`, 1)},
		{"set type", strings.Replace(realNFT111EmptyLiveJSON, `"type": "ipv4_addr"`, `"type":"ipv6_addr"`, 1)},
		{"set flags", strings.Replace(realNFT111EmptyLiveJSON, `"flags": ["timeout"]`, `"flags":["timeout","interval"]`, 1)},
		{"chain", strings.Replace(realNFT111EmptyLiveJSON, `"name": "gateway_input"`, `"name":"other"`, 1)},
		{"hook", strings.Replace(realNFT111EmptyLiveJSON, `"hook": "input"`, `"hook":"forward"`, 1)},
		{"priority", strings.Replace(realNFT111EmptyLiveJSON, `"prio": 0`, `"prio":1`, 1)},
		{"policy", strings.Replace(realNFT111EmptyLiveJSON, `"policy": "accept"`, `"policy":"drop"`, 1)},
		{"port", strings.Replace(realNFT111EmptyLiveJSON, `"right": 8080`, `"right":8081`, 1)},
		{"source set", strings.Replace(realNFT111EmptyLiveJSON, `"right": "@blacklist_ipv4"`, `"right":"@other"`, 1)},
		{"source protocol", strings.Replace(realNFT111EmptyLiveJSON, `"protocol": "ip", "field": "saddr"`, `"protocol":"ip6","field":"saddr"`, 1)},
		{"verdict", strings.Replace(realNFT111EmptyLiveJSON, `{"drop": null}`, `{"accept":null}`, 1)},
		{"extra expression", strings.Replace(realNFT111EmptyLiveJSON, `{"drop": null}`, `{"counter":{"packets":0,"bytes":0}},{"counter":{"packets":0,"bytes":0}},{"drop":null}`, 1)},
		{"unowned counter", strings.Replace(realNFT111EmptyLiveJSON, `{"drop": null}`, `{"counter":{"packets":0,"bytes":0}},{"drop":null}`, 1)},
		{"unowned comments", realNFT111CommentCounterLiveJSON},
		{"extra object", strings.Replace(realNFT111EmptyLiveJSON, `, {"rule":`, `, {"chain":{"family":"inet","table":"sentinelflow","name":"extra","handle":4,"type":"filter","hook":"input","prio":1,"policy":"accept"}}, {"rule":`, 1)},
		{"duplicate rule replaces set", strings.Replace(realNFT111EmptyLiveJSON, `{"set": {`, `{"rule": {`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			canonical, err := projectLiveSchema([]byte(test.data))
			if err == nil || canonical != nil {
				t.Fatalf("accepted structural drift: %s", canonical)
			}
			requireErrorCode(t, err, ErrorLiveReadbackInvalid)
		})
	}
}

func TestProjectLiveSchemaRejectsMalformedUnknownDuplicateAndAmbiguousJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"truncated", []byte(realNFT111EmptyLiveJSON[:len(realNFT111EmptyLiveJSON)-1])},
		{"trailing object", []byte(realNFT111EmptyLiveJSON + `{}`)},
		{"BOM", append([]byte{0xef, 0xbb, 0xbf}, []byte(realNFT111EmptyLiveJSON)...)},
		{"invalid UTF-8", append([]byte(realNFT111EmptyLiveJSON), 0xff)},
		{"oversized", bytes.Repeat([]byte{' '}, MaxProcessOutput+1)},
		{"unknown root", []byte(strings.Replace(realNFT111EmptyLiveJSON, `{"nftables":`, `{"unknown":true,"nftables":`, 1))},
		{"duplicate root", []byte(strings.Replace(realNFT111EmptyLiveJSON, `{"nftables":`, `{"nftables":[],"nftables":`, 1))},
		{"second metainfo", []byte(strings.Replace(realNFT111EmptyLiveJSON, `, {"table":`, `, {"metainfo":{"version":"1.1.1","release_name":"duplicate","json_schema_version":1}}, {"table":`, 1))},
		{"duplicate nested", []byte(strings.Replace(realNFT111EmptyLiveJSON, `"family": "inet",`, `"family":"inet","family":"inet",`, 1))},
		{"unknown table", []byte(strings.Replace(realNFT111EmptyLiveJSON, `"handle": 1}}, {"chain"`, `"handle":1,"secret":"value"}}, {"chain"`, 1))},
		{"unknown chain", []byte(strings.Replace(realNFT111EmptyLiveJSON, `"policy": "accept"`, `"policy":"accept","device":"eth0"`, 1))},
		{"unknown set", []byte(strings.Replace(realNFT111EmptyLiveJSON, `"flags": ["timeout"]`, `"flags":["timeout"],"size":1024`, 1))},
		{"unknown rule", []byte(strings.Replace(realNFT111EmptyLiveJSON, `"handle": 3, "expr"`, `"handle":3,"position":1,"expr"`, 1))},
		{"unknown match", []byte(strings.Replace(realNFT111EmptyLiveJSON, `"op": "==",`, `"op":"==","secret":true,`, 1))},
		{"entry with two kinds", []byte(strings.Replace(realNFT111EmptyLiveJSON, `{"table": {`, `{"metainfo":{"version":"1.1.1","release_name":"x","json_schema_version":1},"table":{`, 1))},
		{"null comment", []byte(strings.Replace(realNFT111EmptyLiveJSON, `"handle": 1}`, `"handle":1,"comment":null}`, 1))},
		{"control comment", []byte(strings.Replace(realNFT111EmptyLiveJSON, `"handle": 1}`, `"handle":1,"comment":"bad\ncomment"}`, 1))},
		{"fractional handle", []byte(strings.Replace(realNFT111EmptyLiveJSON, `"handle": 1`, `"handle":1.5`, 1))},
		{"unsafe handle", []byte(strings.Replace(realNFT111EmptyLiveJSON, `"handle": 1`, `"handle":9007199254740992`, 1))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			canonical, err := projectLiveSchema(test.data)
			if err == nil || canonical != nil {
				t.Fatalf("accepted invalid readback: %s", canonical)
			}
			requireErrorCode(t, err, ErrorLiveReadbackInvalid)
		})
	}
}

func TestProjectLiveSchemaRejectsInvalidCountersAndElements(t *testing.T) {
	t.Parallel()
	elementCases := []string{
		strings.Replace(realNFT111ActiveLiveJSON, `"val": "203.0.113.20"`, `"val":"203.000.113.20"`, 1),
		strings.Replace(realNFT111ActiveLiveJSON, `"timeout": 1800`, `"timeout":59`, 1),
		strings.Replace(realNFT111ActiveLiveJSON, `"timeout": 1800`, `"timeout":86401`, 1),
		strings.Replace(realNFT111ActiveLiveJSON, `"expires": 1799`, `"expires":0`, 1),
		strings.Replace(realNFT111ActiveLiveJSON, `"expires": 1799`, `"expires":1801`, 1),
		strings.Replace(realNFT111ActiveLiveJSON, `"expires": 1799`, `"expires":1799.5`, 1),
		strings.Replace(realNFT111ActiveLiveJSON, `"expires": 1799`, `"expires":1799,"secret":true`, 1),
		strings.Replace(realNFT111ActiveLiveJSON,
			`[{"elem": {"val": "203.0.113.20", "timeout": 1800, "expires": 1799}}]`,
			`[{"elem":{"val":"203.0.113.20","timeout":1800,"expires":1799}},{"elem":{"val":"203.0.113.20","timeout":1800,"expires":1798}}]`, 1),
		strings.Replace(realNFT111ActiveLiveJSON,
			`[{"elem": {"val": "203.0.113.20", "timeout": 1800, "expires": 1799}}]`, `[]`, 1),
		strings.Replace(realNFT111ActiveLiveJSON,
			`[{"elem": {"val": "203.0.113.20", "timeout": 1800, "expires": 1799}}]`, `null`, 1),
	}
	for index, data := range elementCases {
		canonical, err := projectLiveSchema([]byte(data))
		if err == nil || canonical != nil {
			t.Fatalf("case %d accepted invalid dynamic state: %s", index, canonical)
		}
		requireErrorCode(t, err, ErrorLiveReadbackInvalid)
	}
}

func TestParseTableInventoryRequiresStrictRealShape(t *testing.T) {
	t.Parallel()
	empty, err := parseTableInventory([]byte(realNFT111EmptyInventoryJSON))
	if err != nil || empty.tableCount != 0 || empty.ownedTableExists {
		t.Fatalf("empty inventory = %+v, %v", empty, err)
	}
	owned, err := parseTableInventory([]byte(realNFT111OwnedInventoryJSON))
	if err != nil || owned.tableCount != 1 || !owned.ownedTableExists {
		t.Fatalf("owned inventory = %+v, %v", owned, err)
	}
	otherJSON := strings.Replace(realNFT111OwnedInventoryJSON, `"name": "sentinelflow"`, `"name":"other"`, 1)
	other, err := parseTableInventory([]byte(otherJSON))
	if err != nil || other.tableCount != 1 || other.ownedTableExists {
		t.Fatalf("other inventory = %+v, %v", other, err)
	}

	invalid := []string{
		realNFT111EmptyInventoryJSON + `{}`,
		strings.Replace(realNFT111OwnedInventoryJSON, `{"nftables":`, `{"unknown":true,"nftables":`, 1),
		strings.Replace(realNFT111OwnedInventoryJSON, `"family": "inet",`, `"family":"inet","family":"inet",`, 1),
		strings.Replace(realNFT111OwnedInventoryJSON, `"handle": 1`, `"handle":0`, 1),
		strings.Replace(realNFT111OwnedInventoryJSON, `]}`, `, {"table":{"family":"inet","name":"sentinelflow","handle":2}}]}`, 1),
	}
	for index, data := range invalid {
		inventory, parseErr := parseTableInventory([]byte(data))
		if parseErr == nil || !zeroInventory(inventory) {
			t.Fatalf("case %d accepted invalid inventory: %+v", index, inventory)
		}
		requireErrorCode(t, parseErr, ErrorInventoryInvalid)
	}
}

func zeroInventory(inventory tableInventory) bool {
	return inventory.tableCount == 0 && !inventory.ownedTableExists && inventory.ownedObjectCount == 0 &&
		inventory.foreignCanonical == nil && inventory.nftVersion == ""
}

func FuzzProjectLiveSchemaNeverChangesPinnedProjection(f *testing.F) {
	f.Add([]byte(realNFT111EmptyLiveJSON))
	f.Add([]byte(realNFT111ActiveLiveJSON))
	f.Add([]byte(realNFT111CommentCounterLiveJSON))
	f.Add([]byte(`{"nftables":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		canonical, err := projectLiveSchema(data)
		if err != nil {
			if canonical != nil {
				t.Fatal("failed projection returned bytes")
			}
			return
		}
		if digest(canonical) != nftvalidate.PinnedLiveSchemaDigest {
			t.Fatalf("accepted divergent projection: %s", canonical)
		}
	})
}
