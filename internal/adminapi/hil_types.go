package adminapi

import (
	"context"
	"errors"
	"time"

	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/hilartifactstore"
	"github.com/devwooops/sentinelflow/internal/hilstore"
)

const MaxHILRequestBodyBytes int64 = 16 * 1024

// ExactArtifactReader returns the one server-checked artifact for the path
// policy and submitted version. It must not synthesize an artifact from HTTP
// fields; every returned value is re-bound at this boundary before HIL use.
type ExactArtifactReader interface {
	LoadExactArtifact(context.Context, string, uint32) (hil.ExactArtifact, error)
	LoadHistoricalExactArtifact(context.Context, string, uint32) (hil.ExactArtifact, error)
}

// ExactArtifactStore and ArtifactClock adapt hilartifactstore without making
// that lower-level package depend on the HTTP layer or on wall-clock globals.
type ExactArtifactStore interface {
	Load(context.Context, string, uint32, time.Time) (hil.ExactArtifact, error)
	LoadHistorical(context.Context, string, uint32) (hil.ExactArtifact, error)
}

type ArtifactClock interface{ Now() time.Time }

type exactArtifactStoreAdapter struct {
	store ExactArtifactStore
	clock ArtifactClock
}

func NewExactArtifactStoreAdapter(store ExactArtifactStore, clock ArtifactClock) (ExactArtifactReader, error) {
	if store == nil || clock == nil {
		return nil, errors.New("exact artifact adapter configuration is invalid")
	}
	return &exactArtifactStoreAdapter{store: store, clock: clock}, nil
}

func (adapter *exactArtifactStoreAdapter) LoadExactArtifact(ctx context.Context, policyID string, version uint32) (hil.ExactArtifact, error) {
	if adapter == nil || adapter.store == nil || adapter.clock == nil {
		return hil.ExactArtifact{}, ErrExactArtifactUnavailable
	}
	artifact, err := adapter.store.Load(ctx, policyID, version, adapter.clock.Now())
	switch {
	case err == nil:
		return artifact, nil
	case errors.Is(err, hilartifactstore.ErrNotFound):
		return hil.ExactArtifact{}, ErrExactArtifactNotFound
	case errors.Is(err, hilartifactstore.ErrStale):
		return hil.ExactArtifact{}, ErrExactArtifactStale
	default:
		return hil.ExactArtifact{}, ErrExactArtifactUnavailable
	}
}

func (adapter *exactArtifactStoreAdapter) LoadHistoricalExactArtifact(ctx context.Context, policyID string, version uint32) (hil.ExactArtifact, error) {
	if adapter == nil || adapter.store == nil {
		return hil.ExactArtifact{}, ErrExactArtifactUnavailable
	}
	artifact, err := adapter.store.LoadHistorical(ctx, policyID, version)
	switch {
	case err == nil:
		return artifact, nil
	case errors.Is(err, hilartifactstore.ErrNotFound):
		return hil.ExactArtifact{}, ErrExactArtifactNotFound
	default:
		return hil.ExactArtifact{}, ErrExactArtifactUnavailable
	}
}

func (*exactArtifactStoreAdapter) String() string {
	return "adminapi.exactArtifactStoreAdapter{store:configured}"
}

func (adapter *exactArtifactStoreAdapter) GoString() string { return adapter.String() }

// Exact artifact adapters may wrap these stable classifications without
// exposing database, validation, or command details at the HTTP boundary.
var (
	ErrExactArtifactNotFound    = errors.New("exact artifact not found")
	ErrExactArtifactStale       = errors.New("exact artifact version is stale")
	ErrExactArtifactUnavailable = errors.New("exact artifact store unavailable")
)

// HILIssuedChallenge exposes only the checked public artifact and the single
// destructive nonce read. Its implementations must redact String/GoString.
type HILIssuedChallenge interface {
	Challenge() hil.CheckedChallenge
	TakeNonce() (string, error)
}

// HILStoredDecision is the minimum read-only result needed by HTTP. It omits
// reason, command, capability, and session-secret material.
type HILStoredDecision interface {
	Decision() hil.CheckedDecision
	ActionID() string
	AuthorizationDigest() string
	OutboxJobID() string
	SessionRotated() bool
}

// HILPersistence is deliberately narrower than a database pool. The checked
// hilstore inputs prevent browser secrets and arbitrary policy data from
// crossing this boundary.
type HILPersistence interface {
	Issue(context.Context, hilstore.IssueRequest) (HILIssuedChallenge, error)
	LookupHistoricalDecision(context.Context, hilstore.DecisionLookup) (HILStoredDecision, error)
	Commit(context.Context, hilstore.PrivilegedDecisionCommit) (HILStoredDecision, error)
}

// HILStore is the concrete-store-shaped seam used only by NewHILStoreAdapter.
// hilstore.PostgreSQLStore satisfies it without importing adminapi.
type HILStore interface {
	Issue(context.Context, hilstore.IssueRequest) (*hilstore.IssuedChallenge, error)
	LookupHistoricalDecision(context.Context, hilstore.DecisionLookup) (hilstore.StoredDecision, error)
	Commit(context.Context, hilstore.PrivilegedDecisionCommit) (hilstore.StoredDecision, error)
}

type hilStoreAdapter struct{ store HILStore }

// NewHILStoreAdapter converts the persistence implementation's concrete
// immutable results to the narrow HTTP-facing result interfaces.
func NewHILStoreAdapter(store HILStore) (HILPersistence, error) {
	if store == nil {
		return nil, errors.New("HIL store adapter configuration is invalid")
	}
	return &hilStoreAdapter{store: store}, nil
}

func (adapter *hilStoreAdapter) Issue(ctx context.Context, request hilstore.IssueRequest) (HILIssuedChallenge, error) {
	if adapter == nil || adapter.store == nil {
		return nil, hilstore.ErrUnavailable
	}
	return adapter.store.Issue(ctx, request)
}

func (adapter *hilStoreAdapter) LookupHistoricalDecision(ctx context.Context, lookup hilstore.DecisionLookup) (HILStoredDecision, error) {
	if adapter == nil || adapter.store == nil {
		return nil, hilstore.ErrUnavailable
	}
	value, err := adapter.store.LookupHistoricalDecision(ctx, lookup)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (adapter *hilStoreAdapter) Commit(ctx context.Context, commit hilstore.PrivilegedDecisionCommit) (HILStoredDecision, error) {
	if adapter == nil || adapter.store == nil {
		return nil, hilstore.ErrUnavailable
	}
	value, err := adapter.store.Commit(ctx, commit)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (*hilStoreAdapter) String() string           { return "adminapi.hilStoreAdapter{store:configured}" }
func (adapter *hilStoreAdapter) GoString() string { return adapter.String() }

var _ HILStore = (*hilstore.PostgreSQLStore)(nil)
var _ ExactArtifactStore = (*hilartifactstore.PostgreSQLStore)(nil)
