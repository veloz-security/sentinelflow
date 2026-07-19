package keyidentity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"errors"
)

const derivationDomain = "sentinelflow key-identity-v1\n"

var ErrInvalidKey = errors.New("key identity input is invalid")

// Set contains the identities that both dispatcher and executor independently
// derive from the same two public keys. Keeping these values derived prevents
// an operator-configured key ID from selecting a different verification key.
type Set struct {
	DispatchKeyID string
	ResultKeyID   string
	ExecutorID    string
}

// Derive returns stable, role-separated identifiers. Callers must derive the
// public half of private keys before calling this function; private bytes are
// never accepted or hashed.
func Derive(dispatchPublic, resultPublic ed25519.PublicKey) (Set, error) {
	if !validPublicKey(dispatchPublic) || !validPublicKey(resultPublic) {
		return Set{}, ErrInvalidKey
	}
	return Set{
		DispatchKeyID: derive("dispatch-key", dispatchPublic, "dispatch-"),
		ResultKeyID:   derive("result-key", resultPublic, "result-"),
		ExecutorID:    derive("executor", resultPublic, "executor-"),
	}, nil
}

func derive(role string, public ed25519.PublicKey, prefix string) string {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(derivationDomain))
	_, _ = hasher.Write([]byte(role))
	_, _ = hasher.Write([]byte{'\n'})
	_, _ = hasher.Write(public)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hasher.Sum(nil))
	result := make([]byte, len(prefix)+len(encoded))
	copy(result, prefix)
	for index := range encoded {
		value := encoded[index]
		if value >= 'A' && value <= 'Z' {
			value += 'a' - 'A'
		}
		result[len(prefix)+index] = value
	}
	return string(result)
}

func validPublicKey(key ed25519.PublicKey) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	var nonzero byte
	for _, value := range key {
		nonzero |= value
	}
	return nonzero != 0
}
