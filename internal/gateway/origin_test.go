package gateway

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestOriginPolicyRejectsMixedAAAAAndRebinding(t *testing.T) {
	t.Parallel()
	prefixes := []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")}
	tests := []struct {
		name      string
		addresses []netip.Addr
		wantError bool
	}{
		{"allowed", []netip.Addr{netip.MustParseAddr("172.30.0.11"), netip.MustParseAddr("172.30.0.10")}, false},
		{"public", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, true},
		{"mixed", []netip.Addr{netip.MustParseAddr("172.30.0.10"), netip.MustParseAddr("8.8.8.8")}, true},
		{"aaaa", []netip.Addr{netip.MustParseAddr("2001:db8::10")}, true},
		{"mapped AAAA", []netip.Addr{netip.MustParseAddr("::ffff:172.30.0.10")}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := NewOriginPolicy("demo.internal:8081", prefixes, resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				return test.addresses, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			addresses, err := policy.Resolve(context.Background())
			if (err != nil) != test.wantError {
				t.Fatalf("Resolve() addresses=%v err=%v", addresses, err)
			}
			if !test.wantError && len(addresses) > 1 && !addresses[0].Less(addresses[1]) {
				t.Fatalf("addresses not stable-sorted: %v", addresses)
			}
		})
	}

	calls := 0
	policy, err := NewOriginPolicy("demo.internal:8081", prefixes, resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{netip.MustParseAddr("172.30.0.10")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := policy.Check(context.Background()); err == nil {
		t.Fatal("rebinding to a disallowed address was accepted")
	}
}

func TestOriginPolicyAndConfigFailClosed(t *testing.T) {
	t.Parallel()
	if _, err := NewOriginPolicy("demo.internal", []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")}, nil); err == nil {
		t.Fatal("missing port accepted")
	}
	if _, err := NewOriginPolicy("demo.internal:8081", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil); err == nil {
		t.Fatal("broad RFC1918 prefix accepted")
	}
	policy, err := NewOriginPolicy("demo.internal:8081", []netip.Prefix{netip.MustParsePrefix("172.30.0.0/24")}, resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("dns unavailable")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Check(context.Background()); err == nil {
		t.Fatal("resolver error accepted")
	}
}
