package hil

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"sync"
	"time"
)

// Challenge is the exact hil-challenge-v1 wire value. It can represent the
// policy approve/reject branches or the enforcement-action revoke branch. The
// actor ID, server session ID, idempotency binding, and command bytes are
// deliberately stored outside the wire artifact.
type Challenge struct {
	SchemaVersion              string
	ChallengeID                string
	SessionDigest              string
	Operation                  Operation
	ResourceType               string
	ResourceID                 string
	ResourceVersion            uint32
	TargetIPv4                 string
	PolicyDigest               string
	GeneratedArtifactDigest    string
	CanonicalArtifactDigest    string
	OriginalAddDigest          *string
	EvidenceSnapshotDigest     string
	ValidationSnapshotDigest   string
	ValidationValidUntil       time.Time
	NonceDigest                string
	AuthenticatedAt            time.Time
	ReauthRequiredAfterSeconds uint32
	IssuedAt                   time.Time
	ExpiresAt                  time.Time
}

type CheckedChallenge struct {
	value     Challenge
	canonical []byte
	digest    string
}

func (CheckedChallenge) String() string     { return "hil.CheckedChallenge{artifact:[REDACTED]}" }
func (c CheckedChallenge) GoString() string { return c.String() }

func (c CheckedChallenge) Value() Challenge {
	value := c.value
	if c.value.OriginalAddDigest != nil {
		copyValue := *c.value.OriginalAddDigest
		value.OriginalAddDigest = &copyValue
	}
	return value
}
func (c CheckedChallenge) CanonicalBytes() []byte { return bytes.Clone(c.canonical) }
func (c CheckedChallenge) DigestInput() []byte    { return bytes.Clone(c.canonical) }
func (c CheckedChallenge) Digest() string         { return c.digest }

func CheckChallenge(value Challenge) (CheckedChallenge, error) {
	if value.SchemaVersion != ChallengeSchemaVersion || !validOperation(value.Operation) ||
		!validChallengeBranch(value.Operation, value.ResourceType, value.OriginalAddDigest) {
		return CheckedChallenge{}, reject(ErrorSchema)
	}
	if !validUUID(value.ChallengeID) || !validUUID(value.ResourceID) ||
		value.ResourceVersion == 0 || value.ResourceVersion > 2_147_483_647 ||
		!validCanonicalIPv4(value.TargetIPv4) || value.ResourceID == "" {
		return CheckedChallenge{}, reject(ErrorField)
	}
	for _, digest := range [...]string{
		value.SessionDigest, value.PolicyDigest, value.GeneratedArtifactDigest,
		value.CanonicalArtifactDigest, value.EvidenceSnapshotDigest,
		value.ValidationSnapshotDigest, value.NonceDigest,
	} {
		if !validDigest(digest) {
			return CheckedChallenge{}, reject(ErrorDigest)
		}
	}
	if value.OriginalAddDigest != nil && !validDigest(*value.OriginalAddDigest) {
		return CheckedChallenge{}, reject(ErrorDigest)
	}
	if value.Operation == OperationRevoke &&
		!digestEqual(value.GeneratedArtifactDigest, value.CanonicalArtifactDigest) {
		return CheckedChallenge{}, reject(ErrorArtifactMismatch)
	}
	if value.ReauthRequiredAfterSeconds != uint32(ReauthAfter/time.Second) {
		return CheckedChallenge{}, reject(ErrorField)
	}
	authenticatedAt, ok := normalizedTime(value.AuthenticatedAt)
	if !ok {
		return CheckedChallenge{}, reject(ErrorTime)
	}
	issuedAt, ok := normalizedTime(value.IssuedAt)
	if !ok {
		return CheckedChallenge{}, reject(ErrorTime)
	}
	expiresAt, ok := normalizedTime(value.ExpiresAt)
	if !ok {
		return CheckedChallenge{}, reject(ErrorTime)
	}
	validationValidUntil, ok := normalizedTime(value.ValidationValidUntil)
	if !ok || issuedAt.Before(authenticatedAt) || issuedAt.After(authenticatedAt.Add(ReauthAfter)) ||
		!expiresAt.After(issuedAt) || expiresAt.After(issuedAt.Add(ChallengeLifetime)) ||
		expiresAt.After(validationValidUntil) {
		return CheckedChallenge{}, reject(ErrorTime)
	}
	value.AuthenticatedAt = authenticatedAt
	value.IssuedAt = issuedAt
	value.ExpiresAt = expiresAt
	value.ValidationValidUntil = validationValidUntil
	value.OriginalAddDigest = cloneOptionalString(value.OriginalAddDigest)
	canonical := marshalChallengeJCS(value)
	if len(canonical) > MaxChallengeBytes {
		return CheckedChallenge{}, reject(ErrorEncoding)
	}
	return CheckedChallenge{value: value, canonical: canonical, digest: digestBytes(canonical)}, nil
}

type challengeWire struct {
	AuthenticatedAt            string    `json:"authenticated_at"`
	CanonicalArtifactDigest    string    `json:"canonical_artifact_digest"`
	ChallengeID                string    `json:"challenge_id"`
	EvidenceSnapshotDigest     string    `json:"evidence_snapshot_digest"`
	ExpiresAt                  string    `json:"expires_at"`
	GeneratedArtifactDigest    string    `json:"generated_artifact_digest"`
	IssuedAt                   string    `json:"issued_at"`
	NonceDigest                string    `json:"nonce_digest"`
	Operation                  Operation `json:"operation"`
	OriginalAddDigest          *string   `json:"original_add_digest"`
	PolicyDigest               string    `json:"policy_digest"`
	ReauthRequiredAfterSeconds uint32    `json:"reauth_required_after_seconds"`
	ResourceID                 string    `json:"resource_id"`
	ResourceType               string    `json:"resource_type"`
	ResourceVersion            uint32    `json:"resource_version"`
	SchemaVersion              string    `json:"schema_version"`
	SessionDigest              string    `json:"session_digest"`
	TargetIPv4                 string    `json:"target_ipv4"`
	ValidationSnapshotDigest   string    `json:"validation_snapshot_digest"`
	ValidationValidUntil       string    `json:"validation_valid_until"`
}

func ParseCanonicalChallenge(data []byte) (CheckedChallenge, error) {
	var wire challengeWire
	if err := decodeStrict(data, MaxChallengeBytes, &wire); err != nil {
		return CheckedChallenge{}, err
	}
	authenticatedAt, err := time.Parse(time.RFC3339Nano, wire.AuthenticatedAt)
	if err != nil {
		return CheckedChallenge{}, reject(ErrorTime)
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, wire.IssuedAt)
	if err != nil {
		return CheckedChallenge{}, reject(ErrorTime)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, wire.ExpiresAt)
	if err != nil {
		return CheckedChallenge{}, reject(ErrorTime)
	}
	validationValidUntil, err := time.Parse(time.RFC3339Nano, wire.ValidationValidUntil)
	if err != nil {
		return CheckedChallenge{}, reject(ErrorTime)
	}
	checked, err := CheckChallenge(Challenge{
		SchemaVersion:              wire.SchemaVersion,
		ChallengeID:                wire.ChallengeID,
		SessionDigest:              wire.SessionDigest,
		Operation:                  wire.Operation,
		ResourceType:               wire.ResourceType,
		ResourceID:                 wire.ResourceID,
		ResourceVersion:            wire.ResourceVersion,
		TargetIPv4:                 wire.TargetIPv4,
		PolicyDigest:               wire.PolicyDigest,
		GeneratedArtifactDigest:    wire.GeneratedArtifactDigest,
		CanonicalArtifactDigest:    wire.CanonicalArtifactDigest,
		OriginalAddDigest:          wire.OriginalAddDigest,
		EvidenceSnapshotDigest:     wire.EvidenceSnapshotDigest,
		ValidationSnapshotDigest:   wire.ValidationSnapshotDigest,
		ValidationValidUntil:       validationValidUntil,
		NonceDigest:                wire.NonceDigest,
		AuthenticatedAt:            authenticatedAt,
		ReauthRequiredAfterSeconds: wire.ReauthRequiredAfterSeconds,
		IssuedAt:                   issuedAt,
		ExpiresAt:                  expiresAt,
	})
	if err != nil {
		return CheckedChallenge{}, err
	}
	if !bytes.Equal(data, checked.canonical) {
		return CheckedChallenge{}, reject(ErrorCanonical)
	}
	return checked, nil
}

func marshalChallengeJCS(value Challenge) []byte {
	result := make([]byte, 0, 1536)
	result = append(result, `{"authenticated_at":`...)
	result = appendJCSString(result, value.AuthenticatedAt.Format(time.RFC3339Nano))
	result = append(result, `,"canonical_artifact_digest":`...)
	result = appendJCSString(result, value.CanonicalArtifactDigest)
	result = append(result, `,"challenge_id":`...)
	result = appendJCSString(result, value.ChallengeID)
	result = append(result, `,"evidence_snapshot_digest":`...)
	result = appendJCSString(result, value.EvidenceSnapshotDigest)
	result = append(result, `,"expires_at":`...)
	result = appendJCSString(result, value.ExpiresAt.Format(time.RFC3339Nano))
	result = append(result, `,"generated_artifact_digest":`...)
	result = appendJCSString(result, value.GeneratedArtifactDigest)
	result = append(result, `,"issued_at":`...)
	result = appendJCSString(result, value.IssuedAt.Format(time.RFC3339Nano))
	result = append(result, `,"nonce_digest":`...)
	result = appendJCSString(result, value.NonceDigest)
	result = append(result, `,"operation":`...)
	result = appendJCSString(result, string(value.Operation))
	result = append(result, `,"original_add_digest":`...)
	result = appendOptionalJCSString(result, value.OriginalAddDigest)
	result = append(result, `,"policy_digest":`...)
	result = appendJCSString(result, value.PolicyDigest)
	result = append(result, `,"reauth_required_after_seconds":`...)
	result = appendUint32(result, value.ReauthRequiredAfterSeconds)
	result = append(result, `,"resource_id":`...)
	result = appendJCSString(result, value.ResourceID)
	result = append(result, `,"resource_type":`...)
	result = appendJCSString(result, value.ResourceType)
	result = append(result, `,"resource_version":`...)
	result = appendUint32(result, value.ResourceVersion)
	result = append(result, `,"schema_version":`...)
	result = appendJCSString(result, value.SchemaVersion)
	result = append(result, `,"session_digest":`...)
	result = appendJCSString(result, value.SessionDigest)
	result = append(result, `,"target_ipv4":`...)
	result = appendJCSString(result, value.TargetIPv4)
	result = append(result, `,"validation_snapshot_digest":`...)
	result = appendJCSString(result, value.ValidationSnapshotDigest)
	result = append(result, `,"validation_valid_until":`...)
	result = appendJCSString(result, value.ValidationValidUntil.Format(time.RFC3339Nano))
	return append(result, '}')
}

type boundChallenge struct {
	artifact             CheckedChallenge
	session              SessionBinding
	exact                ExactArtifact
	idempotencyKeyDigest string
}

// ChallengeRecord is the secret-free immutable persistence projection. A DB
// adapter stores these fields with the checked wire artifact and performs an
// atomic unconsumed-to-consumed transition; CanonicalCommandBytes is retained
// solely to recheck byte identity and must not be emitted to ordinary logs.
type ChallengeRecord struct {
	Artifact              CheckedChallenge
	SessionID             string
	ActorID               string
	IdempotencyKeyDigest  string
	CanonicalCommandBytes []byte
}

func (ChallengeRecord) String() string     { return "hil.ChallengeRecord{command:[REDACTED]}" }
func (r ChallengeRecord) GoString() string { return r.String() }

func cloneBoundChallenge(value boundChallenge) boundChallenge {
	value.artifact.canonical = bytes.Clone(value.artifact.canonical)
	value.artifact.value.OriginalAddDigest = cloneOptionalString(value.artifact.value.OriginalAddDigest)
	value.exact = cloneExactArtifact(value.exact)
	return value
}

// IssueRequest requires an idempotency key at challenge issuance because the
// durable schema binds it to the one challenge/decision transaction.
type IssueRequest struct {
	Operation      Operation
	Session        SessionBinding
	Artifact       ExactArtifact
	IdempotencyKey []byte
}

func (IssueRequest) String() string     { return "hil.IssueRequest{idempotency_key:[REDACTED]}" }
func (r IssueRequest) GoString() string { return r.String() }

// Service owns only injected time and entropy. It has no persistence or
// authorization key and is safe for concurrent Issue/Consume calls when its
// Clock is safe for concurrent use.
type Service struct {
	clock     Clock
	entropy   io.Reader
	entropyMu sync.Mutex
}

func (*Service) String() string     { return "hil.Service{entropy:[REDACTED]}" }
func (s *Service) GoString() string { return s.String() }

func NewService(clock Clock, entropy io.Reader) (*Service, error) {
	if clock == nil || entropy == nil {
		return nil, reject(ErrorConfiguration)
	}
	return &Service{clock: clock, entropy: entropy}, nil
}

func NewDefaultService() *Service {
	service, _ := NewService(realClock{}, cryptoReader{})
	return service
}

// cryptoReader is a tiny indirection that keeps crypto/rand out of test
// replacement paths while retaining the standard CSPRNG default.
type cryptoReader struct{}

func (cryptoReader) Read(destination []byte) (int, error) { return rand.Read(destination) }

func (s *Service) now() (time.Time, error) {
	if s == nil || s.clock == nil {
		return time.Time{}, reject(ErrorConfiguration)
	}
	now, ok := normalizedTime(s.clock.Now())
	if !ok {
		return time.Time{}, reject(ErrorTime)
	}
	return now, nil
}

func (s *Service) randomUUID() (string, error) {
	if s == nil || s.entropy == nil {
		return "", reject(ErrorConfiguration)
	}
	s.entropyMu.Lock()
	defer s.entropyMu.Unlock()
	return makeUUID(s.entropy)
}

func (s *Service) randomBytes(destination []byte) error {
	if s == nil || s.entropy == nil {
		return reject(ErrorConfiguration)
	}
	s.entropyMu.Lock()
	defer s.entropyMu.Unlock()
	return readEntropy(s.entropy, destination)
}

func (s *Service) Issue(request IssueRequest) (*IssuedChallenge, error) {
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	if !validPolicyOperation(request.Operation) {
		return nil, reject(ErrorField)
	}
	session, err := checkSession(request.Session, now)
	if err != nil {
		return nil, err
	}
	if !validIdempotencyKey(request.IdempotencyKey) {
		return nil, reject(ErrorIdempotency)
	}
	exact := cloneExactArtifact(request.Artifact)
	if !validExactArtifact(exact) {
		return nil, reject(ErrorArtifact)
	}
	if !exact.FreshAt(now) {
		return nil, reject(ErrorValidationStale)
	}
	expiresAt := minTime(now.Add(ChallengeLifetime), exact.ValidationValidUntil(), session.ExpiresAt)
	if !expiresAt.After(now) {
		return nil, reject(ErrorChallengeExpired)
	}
	challengeID, err := s.randomUUID()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceBytes)
	if err := s.randomBytes(nonce); err != nil {
		return nil, err
	}
	nonceDigest := digestBytes(nonce)
	checked, err := CheckChallenge(Challenge{
		SchemaVersion:              ChallengeSchemaVersion,
		ChallengeID:                challengeID,
		SessionDigest:              session.SessionDigest,
		Operation:                  request.Operation,
		ResourceType:               ResourcePolicy,
		ResourceID:                 exact.PolicyID(),
		ResourceVersion:            exact.PolicyVersion(),
		TargetIPv4:                 exact.TargetIPv4(),
		PolicyDigest:               exact.PolicyDigest(),
		GeneratedArtifactDigest:    exact.GeneratedArtifactDigest(),
		CanonicalArtifactDigest:    exact.CanonicalArtifactDigest(),
		OriginalAddDigest:          nil,
		EvidenceSnapshotDigest:     exact.EvidenceSnapshotDigest(),
		ValidationSnapshotDigest:   exact.ValidationSnapshotDigest(),
		ValidationValidUntil:       exact.ValidationValidUntil(),
		NonceDigest:                nonceDigest,
		AuthenticatedAt:            session.AuthenticatedAt,
		ReauthRequiredAfterSeconds: uint32(ReauthAfter / time.Second),
		IssuedAt:                   now,
		ExpiresAt:                  expiresAt,
	})
	if err != nil {
		clear(nonce)
		return nil, err
	}
	bound := boundChallenge{
		artifact:             checked,
		session:              session,
		exact:                exact,
		idempotencyKeyDigest: digestBytes(request.IdempotencyKey),
	}
	return &IssuedChallenge{
		guard: &OneUseChallenge{bound: bound},
		nonce: nonce,
	}, nil
}

func validExactArtifact(value ExactArtifact) bool {
	return validUUID(value.PolicyID()) && value.PolicyVersion() > 0 && value.PolicyVersion() <= 2_147_483_647 &&
		validCanonicalIPv4(value.TargetIPv4()) && validDigest(value.PolicyDigest()) &&
		validDigest(value.GeneratedArtifactDigest()) && validDigest(value.CanonicalArtifactDigest()) &&
		validDigest(value.EvidenceSnapshotDigest()) && validDigest(value.ValidationSnapshotDigest()) &&
		len(value.GeneratedBytes()) > 0 && len(value.CanonicalBytes()) > 0 &&
		digestBytes(value.GeneratedBytes()) == value.GeneratedArtifactDigest() &&
		digestBytes(value.CanonicalBytes()) == value.CanonicalArtifactDigest()
}

func validIdempotencyKey(value []byte) bool {
	return len(value) >= MinIdempotencyKeyBytes && len(value) <= MaxIdempotencyKeyBytes
}

// IssuedChallenge returns its raw nonce exactly once. String and GoString
// never expose the nonce or any other binding material.
type IssuedChallenge struct {
	guard   *OneUseChallenge
	nonceMu sync.Mutex
	nonce   []byte
}

func (i *IssuedChallenge) Challenge() CheckedChallenge {
	if i == nil || i.guard == nil {
		return CheckedChallenge{}
	}
	return i.guard.Artifact()
}

func (i *IssuedChallenge) Guard() *OneUseChallenge {
	if i == nil {
		return nil
	}
	return i.guard
}

func (i *IssuedChallenge) TakeNonce() (string, error) {
	if i == nil {
		return "", reject(ErrorNonceUnavailable)
	}
	i.nonceMu.Lock()
	defer i.nonceMu.Unlock()
	if len(i.nonce) != NonceBytes {
		return "", reject(ErrorNonceUnavailable)
	}
	result := base64.RawURLEncoding.EncodeToString(i.nonce)
	clear(i.nonce)
	i.nonce = nil
	return result, nil
}

func (i *IssuedChallenge) String() string   { return "hil.IssuedChallenge{nonce:[REDACTED]}" }
func (i *IssuedChallenge) GoString() string { return i.String() }

// OneUseChallenge serializes local consumption. A durable adapter must mirror
// this with one transaction/CAS over the challenge's unconsumed state and
// unique challenge/decision/idempotency constraints.
type OneUseChallenge struct {
	mu          sync.Mutex
	bound       boundChallenge
	consumed    *CheckedDecision
	fingerprint string
}

func (*OneUseChallenge) String() string     { return "hil.OneUseChallenge{binding:[REDACTED]}" }
func (g *OneUseChallenge) GoString() string { return g.String() }

func (g *OneUseChallenge) Artifact() CheckedChallenge {
	if g == nil {
		return CheckedChallenge{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return cloneBoundChallenge(g.bound).artifact
}

func (g *OneUseChallenge) Consumed() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.consumed != nil
}

func (g *OneUseChallenge) Record() ChallengeRecord {
	if g == nil {
		return ChallengeRecord{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	bound := cloneBoundChallenge(g.bound)
	return ChallengeRecord{
		Artifact:              bound.artifact,
		SessionID:             bound.session.SessionID,
		ActorID:               bound.session.ActorID,
		IdempotencyKeyDigest:  bound.idempotencyKeyDigest,
		CanonicalCommandBytes: bound.exact.CanonicalBytes(),
	}
}

func (g *OneUseChallenge) ConsumedDecision() (CheckedDecision, bool) {
	if g == nil {
		return CheckedDecision{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.consumed == nil {
		return CheckedDecision{}, false
	}
	return cloneDecision(*g.consumed), true
}

func canonicalNonce(presented string) ([]byte, bool) {
	if len(presented) != base64.RawURLEncoding.EncodedLen(NonceBytes) {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil || len(decoded) != NonceBytes || base64.RawURLEncoding.EncodeToString(decoded) != presented {
		clear(decoded)
		return nil, false
	}
	return decoded, true
}

func digestEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
