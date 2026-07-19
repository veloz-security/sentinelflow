// Package policy implements the closed nft-blacklist-v1 candidate grammar.
// It does not execute nftables or decide protected-network eligibility.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
)

const (
	PolicySchemaVersion           = "response-policy-v1"
	CandidateSchemaVersion        = "nft-blacklist-v1"
	ActionBlockIP                 = "block_ip"
	Family                        = "inet"
	Table                         = "sentinelflow"
	BlacklistSet                  = "blacklist_ipv4"
	MinTTLSeconds          uint32 = 60
	DefaultTTLSeconds      uint32 = 1800
	MaxTTLSeconds          uint32 = 86400
	MaxEvidenceIDs                = 50
	MaxGeneratedBytes             = 256
)

type ErrorCode string

const (
	ErrorSyntax            ErrorCode = "syntax_invalid"
	ErrorTarget            ErrorCode = "target_invalid"
	ErrorTTL               ErrorCode = "ttl_invalid"
	ErrorSchema            ErrorCode = "schema_invalid"
	ErrorAction            ErrorCode = "action_invalid"
	ErrorEvidence          ErrorCode = "evidence_invalid"
	ErrorTargetMismatch    ErrorCode = "target_mismatch"
	ErrorTTLMismatch       ErrorCode = "ttl_mismatch"
	ErrorCandidateMismatch ErrorCode = "candidate_mismatch"
)

// Error never embeds generated command bytes or evidence content and is safe
// for logs. Detailed validation records should use only Code.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "nft-blacklist-v1 rejected"
	}
	return "nft-blacklist-v1 rejected: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }

// Policy is the security-relevant subset of response-policy-v1 required at the
// candidate boundary. ResponsePolicy is the complete immutable JCS contract.
type Policy struct {
	SchemaVersion string
	Action        string
	TargetIPv4    string
	TTLSeconds    uint32
	EvidenceIDs   []string
}

// Candidate represents the strict structured-output fields owned by the AI
// command candidate. GeneratedBytes are retained and digested exactly as
// received; they are never executed.
type Candidate struct {
	SchemaVersion  string
	TargetIPv4     string
	TimeoutToken   string
	EvidenceIDs    []string
	GeneratedBytes []byte
}

// AST is created only by Parse. Its fields are intentionally private so a
// caller cannot turn a validated add into another nftables operation.
type AST struct {
	target        netip.Addr
	ttlSeconds    uint32
	inputTTLToken string
}

func (a AST) Operation() string     { return "add element" }
func (a AST) Family() string        { return Family }
func (a AST) Table() string         { return Table }
func (a AST) Set() string           { return BlacklistSet }
func (a AST) TargetIPv4() string    { return a.target.String() }
func (a AST) TTLSeconds() uint32    { return a.ttlSeconds }
func (a AST) InputTTLToken() string { return a.inputTTLToken }

// Artifact keeps generated and canonical bytes distinct. Accessors return
// copies so downstream code cannot mutate bytes after digest binding.
type Artifact struct {
	ast             AST
	generatedBytes  []byte
	generatedDigest string
	canonicalBytes  []byte
	canonicalDigest string
	canonicalToken  string
	evidenceIDs     []string
}

func (a Artifact) AST() AST                  { return a.ast }
func (a Artifact) GeneratedBytes() []byte    { return append([]byte(nil), a.generatedBytes...) }
func (a Artifact) GeneratedDigest() string   { return a.generatedDigest }
func (a Artifact) CanonicalBytes() []byte    { return append([]byte(nil), a.canonicalBytes...) }
func (a Artifact) CanonicalDigest() string   { return a.canonicalDigest }
func (a Artifact) CanonicalTTLToken() string { return a.canonicalToken }
func (a Artifact) EvidenceIDs() []string     { return append([]string(nil), a.evidenceIDs...) }

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
