package capability

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"time"
)

// CapabilityIssuer is held only by the dispatcher. Its role-specific type is
// not accepted by result APIs.
type CapabilityIssuer struct {
	keyID string
	key   ed25519.PrivateKey
}

func NewCapabilityIssuer(keyID string, key ed25519.PrivateKey) (CapabilityIssuer, error) {
	if !keyIDPattern.MatchString(keyID) || !validPrivateKey(key) {
		return CapabilityIssuer{}, reject(ErrorKey)
	}
	return CapabilityIssuer{keyID: keyID, key: clone(key)}, nil
}

func validPrivateKey(key ed25519.PrivateKey) bool {
	if len(key) != ed25519.PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	return subtle.ConstantTimeCompare(derived[ed25519.SeedSize:], key[ed25519.SeedSize:]) == 1
}

func (i CapabilityIssuer) KeyID() string { return i.keyID }

func (i CapabilityIssuer) Sign(checked CheckedCapability) (SignedCapability, error) {
	if !keyIDPattern.MatchString(i.keyID) || len(i.key) != ed25519.PrivateKeySize ||
		len(checked.canonical) == 0 || len(checked.artifact) == 0 ||
		!digestEqual(checked.digest, digestBytes(checked.canonical)) {
		return SignedCapability{}, reject(ErrorUnchecked)
	}
	signature := ed25519.Sign(i.key, signingInput(CapabilitySigningDomain, checked.canonical))
	return SignedCapability{
		keyID: i.keyID, canonical: clone(checked.canonical), signature: signature, artifact: clone(checked.artifact),
	}, nil
}

// NewUntrustedSignedCapability wraps transport bytes without validating them.
// Only CapabilityVerifier.Verify can turn this into a verified value.
func NewUntrustedSignedCapability(keyID string, canonical, signature, artifact []byte) SignedCapability {
	return SignedCapability{keyID: keyID, canonical: clone(canonical), signature: clone(signature), artifact: clone(artifact)}
}

// CapabilityVerifier is configured only in the isolated executor. ExecutorID
// identifies the sole executor instance/profile for which this key is trusted.
type CapabilityVerifier struct {
	keyID      string
	executorID string
	key        ed25519.PublicKey
}

func NewCapabilityVerifier(keyID, executorID string, key ed25519.PublicKey) (CapabilityVerifier, error) {
	if !keyIDPattern.MatchString(keyID) || !actorPattern.MatchString(executorID) || len(key) != ed25519.PublicKeySize {
		return CapabilityVerifier{}, reject(ErrorKey)
	}
	return CapabilityVerifier{keyID: keyID, executorID: executorID, key: clone(key)}, nil
}

func (v CapabilityVerifier) KeyID() string      { return v.keyID }
func (v CapabilityVerifier) ExecutorID() string { return v.executorID }

// Verify authenticates canonical bytes before parsing them and checks the exact
// operation-specific artifact. It intentionally does not apply freshness: the
// journal/replay lookup must happen first so duplicates cannot refresh TTL.
func (v CapabilityVerifier) Verify(signed SignedCapability) (VerifiedCapability, error) {
	if len(v.key) != ed25519.PublicKeySize || subtle.ConstantTimeCompare([]byte(v.keyID), []byte(signed.keyID)) != 1 {
		return VerifiedCapability{}, reject(ErrorKeyRole)
	}
	if len(signed.canonical) == 0 || len(signed.canonical) > MaxCapabilityBytes ||
		len(signed.artifact) == 0 || len(signed.artifact) > MaxArtifactBytes ||
		len(signed.signature) != ed25519.SignatureSize ||
		!ed25519.Verify(v.key, signingInput(CapabilitySigningDomain, signed.canonical), signed.signature) {
		return VerifiedCapability{}, reject(ErrorSignature)
	}
	checked, err := ParseCanonicalCapability(signed.canonical, signed.artifact)
	if err != nil {
		return VerifiedCapability{}, err
	}
	return VerifiedCapability{
		value: checked.value, canonical: clone(checked.canonical), digest: checked.digest,
		artifact: clone(checked.artifact), keyID: v.keyID, executorID: v.executorID,
		addTTL: checked.addTTL, inspection: checked.inspection,
	}, nil
}

// AddAt authorizes an unseen add after replay lookup and returns the sole type
// capable of releasing add bytes.
func (v VerifiedCapability) AddAt(now time.Time) (ExecutableAdd, error) {
	if v.value.Operation != OperationAdd {
		return ExecutableAdd{}, reject(ErrorOperation)
	}
	if err := v.checkFresh(now); err != nil {
		return ExecutableAdd{}, err
	}
	return ExecutableAdd{verified: v}, nil
}

func (v VerifiedCapability) RevokeAt(now time.Time) (ExecutableRevoke, error) {
	if v.value.Operation != OperationRevoke {
		return ExecutableRevoke{}, reject(ErrorOperation)
	}
	if err := v.checkFresh(now); err != nil {
		return ExecutableRevoke{}, err
	}
	return ExecutableRevoke{verified: v}, nil
}

func (v VerifiedCapability) InspectAt(now time.Time) (ExecutableInspect, error) {
	if v.value.Operation != OperationInspect {
		return ExecutableInspect{}, reject(ErrorOperation)
	}
	if err := v.checkFresh(now); err != nil {
		return ExecutableInspect{}, err
	}
	return ExecutableInspect{verified: v}, nil
}

func (v VerifiedCapability) checkFresh(now time.Time) error {
	if len(v.canonical) == 0 || v.digest == "" || v.executorID == "" {
		return reject(ErrorUnchecked)
	}
	now = now.UTC()
	if now.Before(v.value.IssuedAt) || now.Before(v.value.NotBefore) {
		return reject(ErrorNotYetValid)
	}
	if !now.Before(v.value.ExpiresAt) {
		return reject(ErrorExpired)
	}
	return nil
}

func signingInput(domain string, canonical []byte) []byte {
	digest := sha256.Sum256(canonical)
	result := make([]byte, 0, len(domain)+1+sha256.Size)
	result = append(result, domain...)
	result = append(result, '\n')
	return append(result, digest[:]...)
}
