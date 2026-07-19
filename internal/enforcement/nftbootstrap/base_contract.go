package nftbootstrap

import "slices"

var ownedBaseContractTokens = []string{
	"table", "inet", "sentinelflow", "{",
	"set", "blacklist_ipv4", "{",
	"type", "ipv4_addr",
	"flags", "timeout",
	"}",
	"chain", "gateway_input", "{",
	"type", "filter", "hook", "input", "priority", "0",
	"policy", "accept",
	"tcp", "dport", "8080", "ip", "saddr", "@", "blacklist_ipv4", "drop",
	"}",
	"}",
}

// validOwnedBaseContractScope is intentionally narrower than nft syntax. The
// pinned bootstrap artifact may create only the SentinelFlow table, timeout
// set, input chain, and protected-port drop rule. In particular, flush,
// delete, include, foreign table references, and additional statements cannot
// reach the privileged apply boundary even if a future digest constant were
// changed incorrectly.
func validOwnedBaseContractScope(value []byte) bool {
	tokens, ok := lexOwnedBaseContract(value)
	return ok && slices.Equal(tokens, ownedBaseContractTokens)
}

func lexOwnedBaseContract(value []byte) ([]string, bool) {
	tokens := make([]string, 0, len(ownedBaseContractTokens))
	for index := 0; index < len(value); {
		current := value[index]
		switch {
		case current == ' ' || current == '\t' || current == '\r' || current == '\n':
			index++
		case current == '{' || current == '}' || current == '@':
			tokens = append(tokens, string(current))
			index++
		case isBaseContractWordByte(current):
			start := index
			for index < len(value) && isBaseContractWordByte(value[index]) {
				index++
			}
			tokens = append(tokens, string(value[start:index]))
		default:
			return nil, false
		}
	}
	return tokens, true
}

func isBaseContractWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '_'
}
