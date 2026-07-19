package nftbootstrap

import (
	"errors"
	"testing"
)

// Captured from a disposable Alpine 3.21 container running nftables v1.1.1.
// The RFC 5737 element is synthetic and the fixture contains no host state.
const realNFT111EmptyInventoryJSON = `{"nftables": [{"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}}]}`

const realNFT111OwnedInventoryJSON = `{"nftables": [{"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "sentinelflow", "handle": 1}}]}`

const realNFT111EmptyLiveJSON = `{"nftables": [{"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "sentinelflow", "handle": 1}}, {"chain": {"family": "inet", "table": "sentinelflow", "name": "gateway_input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"set": {"family": "inet", "name": "blacklist_ipv4", "table": "sentinelflow", "type": "ipv4_addr", "handle": 2, "flags": ["timeout"]}}, {"rule": {"family": "inet", "table": "sentinelflow", "chain": "gateway_input", "handle": 3, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8080}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@blacklist_ipv4"}}, {"drop": null}]}}]}`

const realNFT111ActiveLiveJSON = `{"nftables": [{"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "sentinelflow", "handle": 1}}, {"chain": {"family": "inet", "table": "sentinelflow", "name": "gateway_input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"set": {"family": "inet", "name": "blacklist_ipv4", "table": "sentinelflow", "type": "ipv4_addr", "handle": 2, "flags": ["timeout"], "elem": [{"elem": {"val": "203.0.113.20", "timeout": 1800, "expires": 1799}}]}}, {"rule": {"family": "inet", "table": "sentinelflow", "chain": "gateway_input", "handle": 3, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8080}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@blacklist_ipv4"}}, {"drop": null}]}}]}`

// Captured separately from v1.1.1 after injecting object comments and one
// inline counter expression. It is a negative drift fixture: the pinned raw
// contract owns neither comments nor a counter, so VerifyLive must reject it.
const realNFT111CommentCounterLiveJSON = `{"nftables": [{"metainfo": {"version": "1.1.1", "release_name": "Commodore Bullmoose #2", "json_schema_version": 1}}, {"table": {"family": "inet", "name": "sentinelflow", "handle": 1, "comment": "table note"}}, {"chain": {"family": "inet", "table": "sentinelflow", "name": "gateway_input", "handle": 1, "comment": "chain note", "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"set": {"family": "inet", "name": "blacklist_ipv4", "table": "sentinelflow", "type": "ipv4_addr", "handle": 2, "comment": "set note", "flags": ["timeout"]}}, {"rule": {"family": "inet", "table": "sentinelflow", "chain": "gateway_input", "handle": 3, "comment": "rule note", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8080}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@blacklist_ipv4"}}, {"counter": {"packets": 0, "bytes": 0}}, {"drop": null}]}}]}`

const testBaseContract = `table inet sentinelflow {
  set blacklist_ipv4 {
    type ipv4_addr
    flags timeout
  }

  chain gateway_input {
    type filter hook input priority 0
    policy accept
    tcp dport 8080 ip saddr @blacklist_ipv4 drop
  }
}
`

func requireErrorCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("error = %v, want %q", err, code)
	}
}
