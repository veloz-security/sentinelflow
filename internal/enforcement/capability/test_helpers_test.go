package capability

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

const (
	dispatchSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	resultSeedHex   = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)

type goldenVector struct {
	JCSB64URL       string `json:"jcs_b64url"`
	Digest          string `json:"digest"`
	SignatureB64URL string `json:"signature_b64url"`
}

type goldenBundle struct {
	Vectors struct {
		CapabilityAdd     goldenVector `json:"capability_add_v1"`
		CapabilityRevoke  goldenVector `json:"capability_revoke_v1"`
		CapabilityInspect goldenVector `json:"capability_inspect_v1"`
		ResultApplied     goldenVector `json:"execution_result_applied_v1"`
		ResultRecovered   goldenVector `json:"execution_result_recovered_active_v1"`
		ResultRevoked     goldenVector `json:"execution_result_revoked_v1"`
		ResultInspect     goldenVector `json:"execution_result_inspect_absent_v1"`
	} `json:"vectors"`
}

func loadGolden(t *testing.T) goldenBundle {
	t.Helper()
	data, err := os.ReadFile("../../../contracts/vectors/contract_vectors_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var bundle goldenBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func decodeURL(t *testing.T, value string) []byte {
	t.Helper()
	result, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func keyFromSeed(t *testing.T, value string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func ptr[T any](value T) *T { return &value }

func testDigest(label string) string { return digestBytes([]byte(label)) }

func testCommon(operation Operation) Common {
	suffix := map[Operation]string{OperationAdd: "210", OperationRevoke: "220", OperationInspect: "230"}[operation]
	job := map[Operation]string{OperationAdd: "211", OperationRevoke: "221", OperationInspect: "231"}[operation]
	base := time.Date(2026, 7, 18, 2, 0, 5, 0, time.UTC)
	return Common{
		CapabilityID:             "019b0000-0000-7000-8000-000000000" + suffix,
		JobID:                    "019b0000-0000-7000-8000-000000000" + job,
		ActionID:                 "019b0000-0000-7000-8000-000000000200",
		PolicyID:                 "019b0000-0000-7000-8000-000000000201",
		PolicyVersion:            1,
		TargetIPv4:               "203.0.113.20",
		EvidenceSnapshotDigest:   testDigest("evidence"),
		ValidationSnapshotDigest: testDigest("validation"),
		AuthorizationDigest:      testDigest("authorization " + string(operation)),
		ActorID:                  "admin-demo",
		ReasonDigest:             testDigest("reason " + string(operation)),
		OwnedSchemaDigest:        testDigest("owned schema"),
		IssuedAt:                 base,
		NotBefore:                base,
		ExpiresAt:                base.Add(time.Minute),
		Nonce:                    "AAECAwQFBgcICQoLDA0ODw",
	}
}

func testCheckedAdd(t *testing.T) CheckedCapability {
	t.Helper()
	checked, err := CheckAdd(Add{
		Common:           testCommon(OperationAdd),
		CanonicalCommand: []byte("add element inet sentinelflow blacklist_ipv4 { 203.0.113.20 timeout 30m }\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return checked
}

func testVerifiedAdd(t *testing.T) VerifiedCapability {
	t.Helper()
	private := keyFromSeed(t, dispatchSeedHex)
	issuer, err := NewCapabilityIssuer("dispatch-test-v1", private)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := issuer.Sign(testCheckedAdd(t))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCapabilityVerifier("dispatch-test-v1", "executor-demo", private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(signed)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func assertCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	contractError, ok := err.(*Error)
	if !ok || contractError.Code != code {
		t.Fatalf("got error %v, want code %s", err, code)
	}
}
