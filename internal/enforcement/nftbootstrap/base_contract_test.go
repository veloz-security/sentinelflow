package nftbootstrap

import (
	"strings"
	"testing"
)

func TestOwnedBaseContractScopePinsEveryPrivilegedToken(t *testing.T) {
	t.Parallel()
	if !validOwnedBaseContractScope([]byte(testBaseContract)) {
		t.Fatal("checked base contract did not satisfy its owned-only grammar")
	}
	mutations := []string{
		"flush ruleset\n" + testBaseContract,
		strings.Replace(testBaseContract, "table inet sentinelflow", "table ip foreign", 1),
		strings.Replace(testBaseContract, "set blacklist_ipv4", "set foreign", 1),
		strings.Replace(testBaseContract, "chain gateway_input", "chain foreign", 1),
		strings.Replace(testBaseContract, "tcp dport 8080", "tcp dport 8081", 1),
		strings.Replace(testBaseContract, "drop", "accept", 1),
		strings.Replace(testBaseContract, "policy accept", "policy accept; delete table ip foreign", 1),
		strings.Replace(testBaseContract, "table inet", "include \"foreign.nft\"\ntable inet", 1),
		testBaseContract + "# foreign comment\n",
		strings.TrimSuffix(testBaseContract, "}\n"),
	}
	for index, mutation := range mutations {
		if validOwnedBaseContractScope([]byte(mutation)) {
			t.Fatalf("mutation %d escaped the owned-only grammar", index)
		}
	}
}
