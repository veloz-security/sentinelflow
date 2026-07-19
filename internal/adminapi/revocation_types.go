package adminapi

import (
	"context"
	"errors"

	"github.com/devwooops/sentinelflow/internal/hil"
	"github.com/devwooops/sentinelflow/internal/hilstore"
)

// RevocationIssuedChallenge exposes only the checked revoke-only challenge,
// its database-derived policy identity, and the one destructive nonce read.
// It deliberately cannot be converted to the generic policy HIL interface.
type RevocationIssuedChallenge interface {
	Challenge() hil.CheckedRevocationChallenge
	PolicyID() string
	PolicyVersion() uint32
	TakeNonce() (string, error)
}

// RevocationStoredResult is the minimum checked, read-only projection needed
// by the HTTP boundary. It omits reason text, session secrets, SQL state, and
// dispatcher/executor details.
type RevocationStoredResult interface {
	Decision() hil.CheckedRevocationDecision
	RevocationID() string
	AuthorizationID() string
	AuthorizationDigest() string
	OutboxJobID() string
	AuditEventID() string
	SessionRotated() bool
}

// RevocationPersistence is a revoke-only seam. In particular, historical
// lookup accepts hilstore's historical-only BrowserRequest and cannot issue a
// challenge, rotate a session, or recreate add authority.
type RevocationPersistence interface {
	IssueRevocation(context.Context, hilstore.RevocationIssueRequest) (RevocationIssuedChallenge, error)
	LookupHistoricalRevocation(context.Context, hilstore.RevocationLookup) (RevocationStoredResult, error)
	CommitRevocation(context.Context, hilstore.PrivilegedRevocationCommit) (RevocationStoredResult, error)
}

// RevocationStore is concrete-store-shaped only at the construction seam.
// Keeping it separate preserves the narrower policy-HIL test and production
// interfaces.
type RevocationStore interface {
	IssueRevocation(context.Context, hilstore.RevocationIssueRequest) (*hilstore.IssuedRevocationChallenge, error)
	LookupHistoricalRevocation(context.Context, hilstore.RevocationLookup) (hilstore.StoredRevocation, error)
	CommitRevocation(context.Context, hilstore.PrivilegedRevocationCommit) (hilstore.StoredRevocation, error)
}

type revocationStoreAdapter struct{ store RevocationStore }

func NewRevocationStoreAdapter(store RevocationStore) (RevocationPersistence, error) {
	if store == nil {
		return nil, errors.New("revocation store adapter configuration is invalid")
	}
	return &revocationStoreAdapter{store: store}, nil
}

func (adapter *revocationStoreAdapter) IssueRevocation(
	ctx context.Context,
	request hilstore.RevocationIssueRequest,
) (RevocationIssuedChallenge, error) {
	if adapter == nil || adapter.store == nil {
		return nil, hilstore.ErrUnavailable
	}
	return adapter.store.IssueRevocation(ctx, request)
}

func (adapter *revocationStoreAdapter) LookupHistoricalRevocation(
	ctx context.Context,
	lookup hilstore.RevocationLookup,
) (RevocationStoredResult, error) {
	if adapter == nil || adapter.store == nil {
		return nil, hilstore.ErrUnavailable
	}
	value, err := adapter.store.LookupHistoricalRevocation(ctx, lookup)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (adapter *revocationStoreAdapter) CommitRevocation(
	ctx context.Context,
	commit hilstore.PrivilegedRevocationCommit,
) (RevocationStoredResult, error) {
	if adapter == nil || adapter.store == nil {
		return nil, hilstore.ErrUnavailable
	}
	value, err := adapter.store.CommitRevocation(ctx, commit)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (*revocationStoreAdapter) String() string {
	return "adminapi.revocationStoreAdapter{store:configured}"
}

func (adapter *revocationStoreAdapter) GoString() string { return adapter.String() }

var _ RevocationStore = (*hilstore.PostgreSQLStore)(nil)
