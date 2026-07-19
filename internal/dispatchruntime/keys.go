package dispatchruntime

import (
	"crypto/ed25519"
	"crypto/subtle"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
	"github.com/devwooops/sentinelflow/internal/enforcement/keyidentity"
	"github.com/devwooops/sentinelflow/internal/keymaterial"
)

// KeySet contains only role-specific typed consumers and public identifiers.
// It cannot construct an executor result signer.
type KeySet struct {
	issuer             capability.CapabilityIssuer
	capabilityVerifier capability.CapabilityVerifier
	resultVerifier     capability.ResultVerifier
	identities         keyidentity.Set
}

func (KeySet) String() string     { return "dispatchruntime.KeySet{private:[REDACTED]}" }
func (k KeySet) GoString() string { return k.String() }

func (k KeySet) Issuer() capability.CapabilityIssuer { return k.issuer }
func (k KeySet) CapabilityVerifier() capability.CapabilityVerifier {
	return k.capabilityVerifier
}
func (k KeySet) ResultVerifier() capability.ResultVerifier { return k.resultVerifier }
func (k KeySet) Identities() keyidentity.Set               { return k.identities }

// LoadKeySet loads exactly the dispatch private key and executor-result public
// key. The two Ed25519 roles must use distinct public keys and all identifiers
// are derived locally from those public bytes.
func LoadKeySet(dispatchPrivatePath, resultPublicPath string) (KeySet, error) {
	dispatchPrivate, err := keymaterial.LoadPrivateFile(dispatchPrivatePath)
	if err != nil {
		return KeySet{}, ErrKeyRejected
	}
	defer clear(dispatchPrivate)
	dispatchPublic, ok := dispatchPrivate.Public().(ed25519.PublicKey)
	if !ok || len(dispatchPublic) != ed25519.PublicKeySize {
		return KeySet{}, ErrKeyRejected
	}
	resultPublic, err := keymaterial.LoadPublicFile(resultPublicPath)
	if err != nil {
		return KeySet{}, ErrKeyRejected
	}
	defer clear(resultPublic)
	if subtle.ConstantTimeCompare(dispatchPublic, resultPublic) == 1 {
		return KeySet{}, ErrKeyRejected
	}
	identities, err := keyidentity.Derive(dispatchPublic, resultPublic)
	if err != nil {
		return KeySet{}, ErrKeyRejected
	}
	issuer, err := capability.NewCapabilityIssuer(identities.DispatchKeyID, dispatchPrivate)
	if err != nil {
		return KeySet{}, ErrKeyRejected
	}
	capabilityVerifier, err := capability.NewCapabilityVerifier(
		identities.DispatchKeyID, identities.ExecutorID, dispatchPublic,
	)
	if err != nil {
		return KeySet{}, ErrKeyRejected
	}
	resultVerifier, err := capability.NewResultVerifier(
		identities.ResultKeyID, identities.ExecutorID, resultPublic,
	)
	if err != nil {
		return KeySet{}, ErrKeyRejected
	}
	return KeySet{
		issuer: issuer, capabilityVerifier: capabilityVerifier,
		resultVerifier: resultVerifier, identities: identities,
	}, nil
}
