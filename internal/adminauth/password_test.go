package adminauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestParsePasswordHashStrict(t *testing.T) {
	valid := fastPHC()
	tests := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"algorithm", strings.Replace(valid, "argon2id", "argon2i", 1)},
		{"version", strings.Replace(valid, "v=19", "v=16", 1)},
		{"missing-version", strings.Replace(valid, "$v=19", "", 1)},
		{"weak-memory", strings.Replace(valid, "m=65536", "m=65535", 1)},
		{"weak-time", strings.Replace(valid, "t=3", "t=2", 1)},
		{"weak-parallelism", strings.Replace(valid, "p=2", "p=1", 1)},
		{"excessive-memory", strings.Replace(valid, "m=65536", "m=262145", 1)},
		{"excessive-time", strings.Replace(valid, "t=3", "t=11", 1)},
		{"excessive-parallelism", strings.Replace(valid, "p=2", "p=17", 1)},
		{"leading-zero", strings.Replace(valid, "m=65536", "m=065536", 1)},
		{"plus", strings.Replace(valid, "t=3", "t=+3", 1)},
		{"wrong-order", strings.Replace(valid, "m=65536,t=3,p=2", "t=3,m=65536,p=2", 1)},
		{"duplicate", strings.Replace(valid, "m=65536,t=3,p=2", "m=65536,m=65536,p=2", 1)},
		{"unknown", strings.Replace(valid, "p=2", "q=2", 1)},
		{"p-overflow", strings.Replace(valid, "p=2", "p=256", 1)},
		{"m-overflow", strings.Replace(valid, "m=65536", "m=4294967296", 1)},
		{"salt-padding", strings.Replace(valid, base64.RawStdEncoding.EncodeToString(testSalt()), base64.StdEncoding.EncodeToString(testSalt()), 1)},
		{"hash-padding", valid + "="},
		{"salt-short", strings.Replace(valid, base64.RawStdEncoding.EncodeToString(testSalt()), base64.RawStdEncoding.EncodeToString(testSalt()[:15]), 1)},
		{"hash-short", strings.Replace(valid, base64.RawStdEncoding.EncodeToString(sha256Bytes(testPassword())), base64.RawStdEncoding.EncodeToString(make([]byte, 31)), 1)},
		{"trailing-field", valid + "$extra"},
		{"oversized", strings.Repeat("x", maxPHCLength+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parsePasswordHash(test.value); !errors.Is(err, ErrInvalidPasswordHash) {
				t.Fatalf("expected strict rejection, got %v", err)
			}
		})
	}

	parsed, err := parsePasswordHash(valid)
	if err != nil {
		t.Fatalf("valid PHC rejected: %v", err)
	}
	if encoded := encodePHC(parsed); encoded != valid {
		t.Fatalf("round trip mismatch: %q", encoded)
	}
	if parsed.memory != MinArgon2MemoryKiB || parsed.iterations != MinArgon2Iterations || parsed.parallelism != MinArgon2Parallelism {
		t.Fatalf("wrong parameters: %+v", parsed)
	}
}

func sha256Bytes(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func TestCredentialVerifierRealArgon2idAndGenericFailures(t *testing.T) {
	password := testPassword()
	salt := testSalt()
	sum := argon2.IDKey(password, salt, MinArgon2Iterations, MinArgon2MemoryKiB, MinArgon2Parallelism, MinArgon2KeyBytes)
	phc := encodePHC(passwordHash{
		memory:      MinArgon2MemoryKiB,
		iterations:  MinArgon2Iterations,
		parallelism: MinArgon2Parallelism,
		salt:        salt,
		sum:         sum,
	})
	verifier, err := NewCredentialVerifier("admin", "administrator", phc)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := verifier.Verify("admin", password)
	if err != nil || actor != "administrator" {
		t.Fatalf("valid verification failed: actor=%q err=%v", actor, err)
	}
	for _, candidate := range []struct {
		username string
		password []byte
	}{{"missing", password}, {"admin", otherPassword()}, {"missing", otherPassword()}, {"admin", nil}} {
		if _, err := verifier.Verify(candidate.username, candidate.password); !errors.Is(err, ErrInvalidCredentials) || err.Error() != ErrInvalidCredentials.Error() {
			t.Fatalf("failure was not generic: %v", err)
		}
	}
	clear(sum)
}

func TestCredentialVerifierOneWorkUnitForAllCredentialOutcomes(t *testing.T) {
	verifier := fastVerifier()
	var calls atomic.Int32
	verifier.workObserved = func() { calls.Add(1) }

	tests := []struct {
		username string
		password []byte
		wantOK   bool
	}{
		{"admin", testPassword(), true},
		{"unknown", testPassword(), false},
		{"admin", otherPassword(), false},
		{"unknown", otherPassword(), false},
		{"admin", nil, false},
		{"admin", make([]byte, MaxPasswordBytes+1), false},
	}
	for index, test := range tests {
		_, err := verifier.Verify(test.username, test.password)
		if (err == nil) != test.wantOK {
			t.Fatalf("case %d unexpected result: %v", index, err)
		}
		if got := calls.Load(); got != int32(index+1) {
			t.Fatalf("case %d used %d cumulative work units", index, got)
		}
	}
}

func TestCredentialVerifierConfigurationAndFormatting(t *testing.T) {
	for _, test := range []struct {
		username string
		actor    string
		phc      string
	}{
		{"", "administrator", fastPHC()},
		{"admin name", "administrator", fastPHC()},
		{"admin", "", fastPHC()},
		{"admin", "administrator", "invalid"},
	} {
		if _, err := NewCredentialVerifier(test.username, test.actor, test.phc); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	verifier := fastVerifier()
	formatted := fmt.Sprintf("%v %#v", verifier, verifier)
	if strings.Contains(formatted, fastPHC()) || !strings.Contains(formatted, "redacted") {
		t.Fatalf("unsafe verifier formatting: %s", formatted)
	}
	parameters := verifier.Parameters()
	if parameters.MemoryKiB != 65536 || parameters.Iterations != 3 || parameters.Parallelism != 2 || parameters.SaltBytes != 16 || parameters.KeyBytes != 32 {
		t.Fatalf("wrong public parameters: %+v", parameters)
	}
}

func FuzzParsePasswordHash(f *testing.F) {
	f.Add(fastPHC())
	f.Add("")
	f.Add("$argon2id$v=19$m=65536,t=3,p=2$bad$bad")
	f.Fuzz(func(t *testing.T, value string) {
		parsed, err := parsePasswordHash(value)
		if err != nil {
			return
		}
		if parsed.memory < MinArgon2MemoryKiB || parsed.memory > MaxArgon2MemoryKiB ||
			parsed.iterations < MinArgon2Iterations || parsed.iterations > MaxArgon2Iterations ||
			parsed.parallelism < MinArgon2Parallelism || parsed.parallelism > MaxArgon2Parallelism ||
			len(parsed.salt) < MinArgon2SaltBytes || len(parsed.salt) > MaxArgon2SaltBytes ||
			len(parsed.sum) < MinArgon2KeyBytes || len(parsed.sum) > MaxArgon2KeyBytes {
			t.Fatal("parser accepted an unsafe Argon2id resource bound")
		}
		if encodePHC(parsed) != value {
			t.Fatalf("accepted input was not canonical: %q", value)
		}
	})
}
