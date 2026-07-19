package nftbootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const (
	BoundaryVersion = "nft-bootstrap-boundary-v1"

	// FixedNFTBinaryPath is the only executable used by production code. It is
	// intentionally absolute and is never resolved through PATH.
	FixedNFTBinaryPath = "/usr/sbin/nft"

	MaxBaseContractBytes = 16 * 1024
	MaxProcessOutput     = 64 * 1024
	MaxJSONDepth         = 20
	MaxJSONTokens        = MaxProcessOutput

	OperationTimeout = 2 * time.Second
	processWaitDelay = 100 * time.Millisecond
	maxSafeInteger   = uint64(1<<53 - 1)
)

type Operation string

const (
	OperationBootstrap  Operation = "bootstrap"
	OperationVerifyLive Operation = "verify_live"
)

type ErrorCode string

const (
	ErrorInvalidInput        ErrorCode = "invalid_input"
	ErrorBaseContract        ErrorCode = "base_contract_mismatch"
	ErrorInventoryInvalid    ErrorCode = "nft_table_inventory_invalid"
	ErrorOwnedTableExists    ErrorCode = "owned_table_already_exists"
	ErrorNamespaceNotEmpty   ErrorCode = "bootstrap_namespace_not_empty"
	ErrorForeignStateChanged ErrorCode = "bootstrap_foreign_state_changed"
	ErrorApplyRollback       ErrorCode = "bootstrap_apply_rollback_unverified"
	ErrorProcessUnavailable  ErrorCode = "nft_process_unavailable"
	ErrorProcessNonzero      ErrorCode = "nft_process_nonzero"
	ErrorProcessSignaled     ErrorCode = "nft_process_signaled"
	ErrorUnexpectedOutput    ErrorCode = "nft_process_output_invalid"
	ErrorOutputLimit         ErrorCode = "nft_output_limit_exceeded"
	ErrorLiveReadbackInvalid ErrorCode = "nft_live_readback_invalid"
	ErrorLiveSchemaMismatch  ErrorCode = "nft_live_schema_mismatch"
	ErrorCancelled           ErrorCode = "nft_bootstrap_cancelled"
	ErrorTimeout             ErrorCode = "nft_bootstrap_timeout"
	ErrorUnsupportedPlatform ErrorCode = "unsupported_platform"
)

// Error deliberately exposes only a stable classification. It never embeds
// raw nft output, contract bytes, object comments, or process errors.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string {
	if e == nil {
		return "nftables bootstrap boundary rejected"
	}
	return "nftables bootstrap boundary rejected: " + string(e.Code)
}

func reject(code ErrorCode) error { return &Error{Code: code} }

// Proof is safe to persist. The canonical live-schema bytes contain only the
// fixed projected structure, never dynamic set elements, handles, or raw
// process output. Because the pinned rule owns no comments or counter
// expression, either one is rejected rather than normalized away. NFTVersion
// is observed non-authority evidence and is not part of the schema digest.
type Proof struct {
	operation          Operation
	baseContractDigest string
	liveSchemaDigest   string
	liveCanonical      []byte
	nftVersion         string
}

func (p Proof) BoundaryVersion() string      { return BoundaryVersion }
func (p Proof) Operation() Operation         { return p.operation }
func (p Proof) NFTBinaryPath() string        { return FixedNFTBinaryPath }
func (p Proof) BaseContractDigest() string   { return p.baseContractDigest }
func (p Proof) LiveSchemaDigest() string     { return p.liveSchemaDigest }
func (p Proof) LiveCanonicalBytes() []byte   { return append([]byte(nil), p.liveCanonical...) }
func (p Proof) NFTVersion() string           { return p.nftVersion }
func (p Proof) BootstrapWasPerformed() bool  { return p.operation == OperationBootstrap }
func (p Proof) IsReadOnlyVerification() bool { return p.operation == OperationVerifyLive }

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
