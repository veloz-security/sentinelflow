package nftvalidate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/devwooops/sentinelflow/internal/policy"
)

func TestIndependentCanonicalizerMatchesPolicyBoundary(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		token   string
		seconds uint32
	}{
		{"60s", 60},
		{"61s", 61},
		{"1800s", 1800},
		{"30m", 1800},
		{"3600s", 3600},
		{"24h", 86400},
	} {
		test := test
		t.Run(test.token, func(t *testing.T) {
			t.Parallel()
			generated := []byte(strings.Replace(validCandidate, "30m", test.token, 1))
			executorArtifact, err := Canonicalize(generated, test.seconds)
			if err != nil {
				t.Fatalf("nftvalidate Canonicalize() error = %v", err)
			}
			policyAST, err := policy.Parse(generated)
			if err != nil {
				t.Fatalf("policy Parse() error = %v", err)
			}
			policyCanonical, err := policy.CanonicalBytes(policyAST)
			if err != nil {
				t.Fatalf("policy CanonicalBytes() error = %v", err)
			}
			if !bytes.Equal(executorArtifact.CanonicalBytes(), policyCanonical) ||
				executorArtifact.CanonicalDigest() != policy.Digest(policyCanonical) {
				t.Fatalf("independent canonicalizers diverged: nftvalidate=%q policy=%q", executorArtifact.CanonicalBytes(), policyCanonical)
			}
		})
	}
}
