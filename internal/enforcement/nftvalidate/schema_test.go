package nftvalidate

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateOwnedSchemaCheckedContracts(t *testing.T) {
	t.Parallel()
	base, live := loadOwnedSchemaContracts(t)
	proof, err := ValidateOwnedSchema(base, live)
	if err != nil {
		t.Fatalf("ValidateOwnedSchema() error = %v", err)
	}
	if proof.BaseContractDigest() != PinnedBaseChainRawDigest || proof.LiveSchemaDigest() != PinnedLiveSchemaDigest {
		t.Fatalf("schema digests = raw %s, live %s", proof.BaseContractDigest(), proof.LiveSchemaDigest())
	}
	if proof.BaseContractDigest() == proof.LiveSchemaDigest() {
		t.Fatal("raw and live schema digests were conflated")
	}
	if got := digest(proof.LiveCanonicalBytes()); got != PinnedLiveSchemaDigest {
		t.Fatalf("canonical live schema digest = %s", got)
	}
}

func TestValidateOwnedSchemaAcceptsFormattingButPinsSemantics(t *testing.T) {
	t.Parallel()
	base, _ := loadOwnedSchemaContracts(t)
	compact := canonicalLiveSchema()
	proof, err := ValidateOwnedSchema(base, compact)
	if err != nil {
		t.Fatalf("ValidateOwnedSchema(compact) error = %v", err)
	}
	if proof.LiveSchemaDigest() != PinnedLiveSchemaDigest || !bytes.Equal(proof.LiveCanonicalBytes(), compact) {
		t.Fatalf("unexpected proof: digest=%s canonical=%q", proof.LiveSchemaDigest(), proof.LiveCanonicalBytes())
	}
}

func TestValidateOwnedSchemaRejectsRawContractMutationAndBounds(t *testing.T) {
	t.Parallel()
	base, live := loadOwnedSchemaContracts(t)
	mutated := append([]byte(nil), base...)
	mutated[len(mutated)-1] ^= 1
	for _, input := range [][]byte{nil, mutated, bytes.Repeat([]byte{'x'}, MaxBaseContractBytes+1)} {
		_, err := ValidateOwnedSchema(input, live)
		assertCode(t, err, ErrorBaseContract)
	}
}

func TestValidateOwnedSchemaRejectsSemanticOrStructuralMutation(t *testing.T) {
	t.Parallel()
	base, live := loadOwnedSchemaContracts(t)
	valid := string(live)
	tests := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"array root", []byte("[]")},
		{"wrong version", []byte(strings.Replace(valid, "nft-base-chain-live-v1", "nft-base-chain-live-v2", 1))},
		{"wrong family", []byte(strings.Replace(valid, `"family": "inet"`, `"family": "ip"`, 1))},
		{"wrong table", []byte(strings.Replace(valid, `"table": "sentinelflow"`, `"table": "filter"`, 1))},
		{"wrong set", []byte(strings.Replace(valid, `"name": "blacklist_ipv4"`, `"name": "other"`, 1))},
		{"wrong set type", []byte(strings.Replace(valid, `"type": "ipv4_addr"`, `"type": "ipv4_addr . inet_service"`, 1))},
		{"missing timeout flag", []byte(strings.Replace(valid, "\"flags\": [\n      \"timeout\"\n    ]", `"flags": []`, 1))},
		{"extra set flag", []byte(strings.Replace(valid, `"timeout"`, `"timeout", "interval"`, 1))},
		{"wrong chain", []byte(strings.Replace(valid, `"name": "gateway_input"`, `"name": "input"`, 1))},
		{"wrong hook", []byte(strings.Replace(valid, `"hook": "input"`, `"hook": "forward"`, 1))},
		{"wrong priority", []byte(strings.Replace(valid, `"priority": 0`, `"priority": 1`, 1))},
		{"missing priority", []byte(strings.Replace(valid, "    \"priority\": 0,\n", "", 1))},
		{"wrong policy", []byte(strings.Replace(valid, `"policy": "accept"`, `"policy": "drop"`, 1))},
		{"wrong protocol", []byte(strings.Replace(valid, `"protocol": "tcp"`, `"protocol": "udp"`, 1))},
		{"wrong port", []byte(strings.Replace(valid, `"destination_port": 8080`, `"destination_port": 80`, 1))},
		{"fractional port", []byte(strings.Replace(valid, `"destination_port": 8080`, `"destination_port": 8080.0`, 1))},
		{"wrong source set", []byte(strings.Replace(valid, `"source_set": "blacklist_ipv4"`, `"source_set": "other"`, 1))},
		{"wrong verdict", []byte(strings.Replace(valid, `"verdict": "drop"`, `"verdict": "accept"`, 1))},
		{"extra owned rule", []byte(strings.Replace(valid, `"owned_rule_count": 1`, `"owned_rule_count": 2`, 1))},
		{"unknown root field", []byte(strings.Replace(valid, "{\n", "{\n  \"unknown\": true,\n", 1))},
		{"unknown nested field", []byte(strings.Replace(valid, `"name": "blacklist_ipv4",`, `"unknown": true, "name": "blacklist_ipv4",`, 1))},
		{"duplicate root key", []byte(strings.Replace(valid, "{\n", "{\n  \"family\": \"inet\",\n", 1))},
		{"duplicate nested key", []byte(strings.Replace(valid, `"name": "blacklist_ipv4",`, `"name": "blacklist_ipv4", "name": "blacklist_ipv4",`, 1))},
		{"missing family", []byte(strings.Replace(valid, "  \"family\": \"inet\",\n", "", 1))},
		{"trailing object", append(append([]byte(nil), live...), []byte("{}")...)},
		{"bom", append([]byte{0xef, 0xbb, 0xbf}, live...)},
		{"invalid utf8", append(append([]byte(nil), live...), 0xff)},
		{"oversized", bytes.Repeat([]byte{' '}, MaxLiveSchemaBytes+1)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if bytes.Equal(test.raw, live) {
				t.Fatal("test mutation did not change the live schema")
			}
			_, err := ValidateOwnedSchema(base, test.raw)
			assertCode(t, err, ErrorLiveSchema)
		})
	}
}

func TestValidateCompletePureGateAndDefensiveResult(t *testing.T) {
	t.Parallel()
	base, live := loadOwnedSchemaContracts(t)
	candidate := []byte(validCandidate)
	result, err := Validate(Input{
		GeneratedCandidate: candidate,
		PolicyTTLSeconds:   1800,
		AuthorizeTarget: func(target netip.Addr) bool {
			// Represents the preceding isolated-demo protected-IP decision.
			return target.String() == "203.0.113.20"
		},
		BaseContract: base,
		LiveSchema:   live,
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	candidate[0] = 'x'
	artifact := result.Artifact()
	proof := result.Schema()
	artifactGenerated := artifact.GeneratedBytes()
	artifactCanonical := artifact.CanonicalBytes()
	proofCanonical := proof.LiveCanonicalBytes()
	artifactGenerated[0] = 'x'
	artifactCanonical[0] = 'x'
	proofCanonical[0] = 'x'
	if result.Artifact().GeneratedBytes()[0] != 'a' || result.Artifact().CanonicalBytes()[0] != 'a' ||
		result.Schema().LiveCanonicalBytes()[0] != '{' {
		t.Fatal("validated result is caller-mutable")
	}
}

func loadOwnedSchemaContracts(t *testing.T) ([]byte, []byte) {
	t.Helper()
	root := filepath.Join("..", "..", "..", "contracts", "enforcement")
	base, err := os.ReadFile(filepath.Join(root, "nft_base_chain_v1.nft"))
	if err != nil {
		t.Fatalf("read base contract: %v", err)
	}
	live, err := os.ReadFile(filepath.Join(root, "nft_base_chain_v1.live.json"))
	if err != nil {
		t.Fatalf("read live schema: %v", err)
	}
	return base, live
}
