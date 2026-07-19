package adminauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	MinArgon2MemoryKiB   uint32 = 65536
	MinArgon2Iterations  uint32 = 3
	MinArgon2Parallelism uint8  = 2
	MinArgon2SaltBytes          = 16
	MinArgon2KeyBytes           = 32
	MaxArgon2MemoryKiB   uint32 = 262144
	MaxArgon2Iterations  uint32 = 10
	MaxArgon2Parallelism uint8  = 16
	MaxArgon2SaltBytes          = 64
	MaxArgon2KeyBytes           = 64
	MaxPasswordBytes            = 1024
	maxPHCLength                = 8192
	maxPHCPartBytes             = 1024
)

type passwordHash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	sum         []byte
}

type passwordWork func(password, salt []byte, iterations, memory uint32, parallelism uint8, keyLen uint32) []byte

// Argon2Parameters reports non-secret PHC cost and length metadata.
type Argon2Parameters struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltBytes   int
	KeyBytes    int
}

// CredentialVerifier owns one administrator identity and a validated Argon2id
// verifier. It never stores a plaintext password.
type CredentialVerifier struct {
	usernameDigest [sha256.Size]byte
	actorID        string
	hash           passwordHash
	work           passwordWork
	workObserved   func()
}

// NewCredentialVerifier parses a strict Argon2id v=19 PHC string. The actor ID
// is returned after successful authentication; the configured username is
// retained only as a fixed-size digest.
func NewCredentialVerifier(username, actorID, phc string) (*CredentialVerifier, error) {
	if !validPublicIdentity(username) || !validPublicIdentity(actorID) {
		return nil, ErrInvalidConfiguration
	}
	parsed, err := parsePasswordHash(phc)
	if err != nil {
		return nil, err
	}
	return &CredentialVerifier{
		usernameDigest: sha256.Sum256([]byte(username)),
		actorID:        actorID,
		hash:           parsed,
		work:           argon2.IDKey,
	}, nil
}

func validPublicIdentity(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '@') {
			return false
		}
	}
	return true
}

// Parameters returns the validated PHC metadata without exposing salt or hash
// bytes.
func (v *CredentialVerifier) Parameters() Argon2Parameters {
	if v == nil {
		return Argon2Parameters{}
	}
	return Argon2Parameters{
		MemoryKiB:   v.hash.memory,
		Iterations:  v.hash.iterations,
		Parallelism: v.hash.parallelism,
		SaltBytes:   len(v.hash.salt),
		KeyBytes:    len(v.hash.sum),
	}
}

// Verify performs exactly one Argon2id work unit for every syntactically valid
// call, including an unknown username. Username and hash comparisons are both
// fixed-size constant-time comparisons and every failure is generic.
func (v *CredentialVerifier) Verify(username string, password []byte) (string, error) {
	if v == nil || v.work == nil {
		return "", ErrInvalidCredentials
	}
	candidateUsername := sha256.Sum256([]byte(username))
	usernameOK := subtle.ConstantTimeCompare(v.usernameDigest[:], candidateUsername[:])
	passwordOK := v.verifyPassword(password)
	if usernameOK&passwordOK != 1 {
		return "", ErrInvalidCredentials
	}
	return v.actorID, nil
}

// VerifyPassword is the password-only work path used after an already
// authenticated session requests step-up. Failure remains generic.
func (v *CredentialVerifier) VerifyPassword(password []byte) error {
	if v == nil || v.work == nil || v.verifyPassword(password) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

func (v *CredentialVerifier) verifyPassword(password []byte) int {
	if v.workObserved != nil {
		v.workObserved()
	}
	lengthOK := 1
	candidate := password
	if len(candidate) == 0 || len(candidate) > MaxPasswordBytes {
		lengthOK = 0
		candidate = []byte("invalid-password-length")
	}
	derived := v.work(candidate, v.hash.salt, v.hash.iterations, v.hash.memory, v.hash.parallelism, uint32(len(v.hash.sum)))
	ok := 0
	if len(derived) == len(v.hash.sum) {
		ok = subtle.ConstantTimeCompare(derived, v.hash.sum)
	}
	clear(derived)
	return ok & lengthOK
}

func (v *CredentialVerifier) String() string   { return "adminauth.CredentialVerifier{redacted}" }
func (v *CredentialVerifier) GoString() string { return v.String() }

func parsePasswordHash(phc string) (passwordHash, error) {
	if len(phc) == 0 || len(phc) > maxPHCLength {
		return passwordHash{}, ErrInvalidPasswordHash
	}
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return passwordHash{}, ErrInvalidPasswordHash
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 || !strings.HasPrefix(params[0], "m=") || !strings.HasPrefix(params[1], "t=") || !strings.HasPrefix(params[2], "p=") {
		return passwordHash{}, ErrInvalidPasswordHash
	}
	memory, err := parseStrictUint(params[0][2:], 32)
	if err != nil || memory < uint64(MinArgon2MemoryKiB) || memory > uint64(MaxArgon2MemoryKiB) {
		return passwordHash{}, ErrInvalidPasswordHash
	}
	iterations, err := parseStrictUint(params[1][2:], 32)
	if err != nil || iterations < uint64(MinArgon2Iterations) || iterations > uint64(MaxArgon2Iterations) {
		return passwordHash{}, ErrInvalidPasswordHash
	}
	parallelism, err := parseStrictUint(params[2][2:], 8)
	if err != nil || parallelism < uint64(MinArgon2Parallelism) || parallelism > uint64(MaxArgon2Parallelism) {
		return passwordHash{}, ErrInvalidPasswordHash
	}
	salt, err := decodePHCPart(parts[4])
	if err != nil || len(salt) < MinArgon2SaltBytes || len(salt) > MaxArgon2SaltBytes {
		return passwordHash{}, ErrInvalidPasswordHash
	}
	sum, err := decodePHCPart(parts[5])
	if err != nil || len(sum) < MinArgon2KeyBytes || len(sum) > MaxArgon2KeyBytes {
		return passwordHash{}, ErrInvalidPasswordHash
	}
	return passwordHash{
		memory:      uint32(memory),
		iterations:  uint32(iterations),
		parallelism: uint8(parallelism),
		salt:        salt,
		sum:         sum,
	}, nil
}

func parseStrictUint(value string, bits int) (uint64, error) {
	if value == "" || len(value) > 10 || value[0] == '+' || value[0] == '-' || len(value) > 1 && value[0] == '0' {
		return 0, errors.New("invalid decimal")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("invalid decimal")
		}
	}
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil || parsed > math.MaxUint32 {
		return 0, errors.New("invalid decimal")
	}
	return parsed, nil
}

func decodePHCPart(value string) ([]byte, error) {
	if value == "" || len(value) > base64.RawStdEncoding.EncodedLen(maxPHCPartBytes) {
		return nil, ErrInvalidPasswordHash
	}
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) > maxPHCPartBytes || base64.RawStdEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidPasswordHash
	}
	return decoded, nil
}

func encodePHC(hash passwordHash) string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", hash.memory, hash.iterations, hash.parallelism,
		base64.RawStdEncoding.EncodeToString(hash.salt), base64.RawStdEncoding.EncodeToString(hash.sum))
}
