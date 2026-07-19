package demohistoryactivation

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

var ErrAuthorityFence = errors.New("demo history bootstrap authority fence rejected")

const (
	importerFenceSQL     = `SELECT sentinelflow.fence_demo_history_importer_role_000030()`
	importerFinalizeSQL  = `SELECT sentinelflow.finalize_demo_history_importer_role_fence_000030()`
	bootstrapFenceSQL    = `SELECT sentinelflow.fence_demo_history_bootstrap_roles_000030()`
	bootstrapFinalizeSQL = `SELECT sentinelflow.finalize_demo_history_bootstrap_role_fence_000030()`
)

type FenceDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// FenceImporter commits NOLOGIN, password removal, and an expired credential
// boundary in phase one. Only after that commit can phase two safely terminate
// and prove the absence of every other importer session. The already
// authenticated caller is the sole excluded backend and must close immediately.
func FenceImporter(ctx context.Context, db FenceDB) error {
	return fence(ctx, db, importerFenceSQL, importerFinalizeSQL)
}

// FenceBootstrap applies the same two-phase boundary to both the importer and
// activator roles. It is used after activation and on every connected
// pre-activation failure path.
func FenceBootstrap(ctx context.Context, db FenceDB) error {
	return fence(ctx, db, bootstrapFenceSQL, bootstrapFinalizeSQL)
}

func fence(ctx context.Context, db FenceDB, phaseOne, phaseTwo string) error {
	if ctx == nil || db == nil || strings.TrimSpace(phaseOne) == "" ||
		strings.TrimSpace(phaseTwo) == "" || phaseOne == phaseTwo {
		return ErrAuthorityFence
	}
	var phaseOneReady bool
	if err := db.QueryRow(ctx, phaseOne).Scan(&phaseOneReady); err != nil || !phaseOneReady {
		return ErrAuthorityFence
	}
	// QueryRow statements are individually committed by the one-connection
	// bootstrap pools. Do not combine these phases in an explicit transaction.
	var finalized bool
	if err := db.QueryRow(ctx, phaseTwo).Scan(&finalized); err != nil || !finalized {
		return ErrAuthorityFence
	}
	return nil
}
