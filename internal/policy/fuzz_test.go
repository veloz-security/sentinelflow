package policy

import (
	"bytes"
	"testing"
)

func FuzzParseNeverBroadensGrammar(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }"),
		[]byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 1800s }\n"),
		[]byte("delete element inet sentinelflow blacklist_ipv4 { 203.0.113.20 }"),
		{0xef, 0xbb, 0xbf, 'a'},
		{0},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		ast, err := Parse(input)
		if err != nil {
			return
		}
		if ast.Operation() != "add element" || ast.Family() != Family || ast.Table() != Table || ast.Set() != BlacklistSet {
			t.Fatalf("parser broadened operation: %+v", ast)
		}
		if ast.TTLSeconds() < MinTTLSeconds || ast.TTLSeconds() > MaxTTLSeconds {
			t.Fatalf("accepted TTL out of bounds: %d", ast.TTLSeconds())
		}
		canonical, err := CanonicalBytes(ast)
		if err != nil {
			t.Fatalf("accepted AST failed canonicalization: %v", err)
		}
		if len(canonical) == 0 || canonical[len(canonical)-1] != '\n' || bytes.Count(canonical, []byte("\n")) != 1 {
			t.Fatalf("invalid canonical terminator: %q", canonical)
		}
		reparsed, err := Parse(canonical)
		if err != nil || reparsed.TargetIPv4() != ast.TargetIPv4() || reparsed.TTLSeconds() != ast.TTLSeconds() {
			t.Fatalf("canonical parse mismatch: ast=%+v reparsed=%+v err=%v", ast, reparsed, err)
		}
	})
}

func FuzzTTLCanonicalRoundTrip(f *testing.F) {
	for _, seed := range []string{"60s", "61s", "1800s", "30m", "1h", "24h", "0s", "25h", "99999h"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		seconds, err := ParseTTL(token)
		if err != nil {
			return
		}
		canonical, err := CanonicalTTL(seconds)
		if err != nil {
			t.Fatalf("accepted TTL failed canonicalization: %v", err)
		}
		roundTrip, err := ParseTTL(canonical)
		if err != nil || roundTrip != seconds {
			t.Fatalf("TTL round trip: %q -> %d -> %q -> %d, %v", token, seconds, canonical, roundTrip, err)
		}
	})
}
