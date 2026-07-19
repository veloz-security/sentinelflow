package nftbootstrap

import (
	"bytes"
	"context"
	"errors"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

// Manager is immutable after construction and safe for concurrent read-only
// verification. Bootstrap has authority only over the exact SentinelFlow
// table; bounded stateless snapshots prove foreign namespace state unchanged.
type Manager struct {
	run processFunc
}

func (manager *Manager) String() string   { return "fixed nft bootstrap boundary [redacted]" }
func (manager *Manager) GoString() string { return manager.String() }

// Bootstrap provisions an absent owned table in a private network namespace.
// It verifies the exact raw contract and its strictly owned grammar before the
// first process call, refuses any existing owned object, snapshots all foreign
// state, applies the pinned bytes once, and proves the foreign snapshot is
// unchanged while verifying the actual owned live projection. It never flushes
// or replaces either owned or foreign state.
func (manager *Manager) Bootstrap(ctx context.Context, baseContract []byte) (Proof, error) {
	if manager == nil || manager.run == nil || ctx == nil || ctx.Err() != nil {
		return Proof{}, inputOrContextError(ctx)
	}
	if len(baseContract) == 0 || len(baseContract) > MaxBaseContractBytes {
		return Proof{}, reject(ErrorBaseContract)
	}
	baseDigest := digest(baseContract)
	if baseDigest != nftvalidate.PinnedBaseChainRawDigest || !validOwnedBaseContractScope(baseContract) {
		return Proof{}, reject(ErrorBaseContract)
	}

	inventoryResult, err := manager.invoke(ctx, processInventory, nil)
	if err != nil {
		return Proof{}, err
	}
	inventory, err := parseTableInventory(inventoryResult.stdout)
	if err != nil {
		return Proof{}, err
	}
	if inventory.ownedTableExists || inventory.ownedObjectCount != 0 {
		return Proof{}, reject(ErrorOwnedTableExists)
	}

	if _, applyErr := manager.invoke(ctx, processApply, append([]byte(nil), baseContract...)); applyErr != nil {
		if !manager.rollbackWasAtomic(ctx, inventory) {
			return Proof{}, reject(ErrorApplyRollback)
		}
		return Proof{}, applyErr
	}
	postResult, err := manager.invoke(ctx, processInventory, nil)
	if err != nil {
		return Proof{}, err
	}
	postProjection, err := projectLiveObservation(postResult.stdout)
	if err != nil {
		return Proof{}, err
	}
	postDigest := digest(postProjection.canonical)
	if postDigest != nftvalidate.PinnedLiveSchemaDigest || postDigest == nftvalidate.PinnedBaseChainRawDigest ||
		postProjection.nftVersion != inventory.nftVersion {
		return Proof{}, reject(ErrorLiveSchemaMismatch)
	}
	if !bytes.Equal(inventory.foreignCanonical, postProjection.foreignCanonical) {
		return Proof{}, reject(ErrorForeignStateChanged)
	}

	// A second, owned-table-only read proves that the steady-state query sees
	// the same pinned projection as the namespace-wide bootstrap snapshot.
	proof, err := manager.verifyLive(ctx, OperationBootstrap)
	if err != nil {
		return Proof{}, err
	}
	if proof.nftVersion != postProjection.nftVersion ||
		!bytes.Equal(proof.liveCanonical, postProjection.canonical) {
		return Proof{}, reject(ErrorLiveSchemaMismatch)
	}
	proof.baseContractDigest = baseDigest
	return proof, nil
}

// VerifyLive performs only the fixed read-only owned-table query. It proves
// that the namespace contains exactly the owned table, set, chain, and
// protected-port drop rule without reading or depending on foreign state. It
// never creates, flushes, replaces, adds, or deletes nftables state.
func (manager *Manager) VerifyLive(ctx context.Context) (Proof, error) {
	if manager == nil || manager.run == nil || ctx == nil || ctx.Err() != nil {
		return Proof{}, inputOrContextError(ctx)
	}
	return manager.verifyLive(ctx, OperationVerifyLive)
}

func (manager *Manager) verifyLive(ctx context.Context, operation Operation) (Proof, error) {
	result, err := manager.invoke(ctx, processVerifyLive, nil)
	if err != nil {
		return Proof{}, err
	}
	projection, err := projectLiveObservation(result.stdout)
	if err != nil {
		return Proof{}, err
	}
	liveDigest := digest(projection.canonical)
	if liveDigest != nftvalidate.PinnedLiveSchemaDigest ||
		liveDigest == nftvalidate.PinnedBaseChainRawDigest {
		return Proof{}, reject(ErrorLiveSchemaMismatch)
	}
	return Proof{
		operation:        operation,
		liveSchemaDigest: liveDigest,
		liveCanonical:    append([]byte(nil), projection.canonical...),
		nftVersion:       projection.nftVersion,
	}, nil
}

func (manager *Manager) rollbackWasAtomic(ctx context.Context, before tableInventory) bool {
	result, err := manager.invoke(ctx, processInventory, nil)
	if err != nil {
		return false
	}
	after, err := parseTableInventory(result.stdout)
	return err == nil && after.ownedObjectCount == 0 && !after.ownedTableExists &&
		after.nftVersion == before.nftVersion && bytes.Equal(after.foreignCanonical, before.foreignCanonical)
}

func (manager *Manager) invoke(ctx context.Context, kind processKind, stdin []byte) (processResult, error) {
	if manager == nil || manager.run == nil || ctx == nil || ctx.Err() != nil ||
		(kind != processInventory && kind != processApply && kind != processVerifyLive) ||
		(kind != processApply && len(stdin) != 0) {
		return processResult{}, inputOrContextError(ctx)
	}

	operationCtx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	result, runError := manager.run(operationCtx, processRequest{
		kind:  kind,
		stdin: append([]byte(nil), stdin...),
	})
	if err := contextError(operationCtx); err != nil {
		return processResult{}, err
	}
	if result.overflow || len(result.stdout) > MaxProcessOutput ||
		len(result.stderr) > MaxProcessOutput-len(result.stdout) {
		return processResult{}, reject(ErrorOutputLimit)
	}
	if result.signaled {
		return processResult{}, reject(ErrorProcessSignaled)
	}
	if result.exitStatus != 0 {
		return processResult{}, reject(ErrorProcessNonzero)
	}
	if runError {
		return processResult{}, reject(ErrorProcessUnavailable)
	}
	if len(result.stderr) != 0 || (kind == processApply && len(result.stdout) != 0) ||
		(kind != processApply && len(result.stdout) == 0) {
		return processResult{}, reject(ErrorUnexpectedOutput)
	}
	return processResult{
		exitStatus: result.exitStatus,
		stdout:     append([]byte(nil), result.stdout...),
		stderr:     append([]byte(nil), result.stderr...),
	}, nil
}

func inputOrContextError(ctx context.Context) error {
	if ctx == nil {
		return reject(ErrorInvalidInput)
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	return reject(ErrorInvalidInput)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return reject(ErrorInvalidInput)
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return reject(ErrorTimeout)
	case errors.Is(ctx.Err(), context.Canceled):
		return reject(ErrorCancelled)
	default:
		return nil
	}
}
