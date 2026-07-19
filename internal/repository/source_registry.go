package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	SourceEndpointGateway = "gateway"
	SourceEndpointAuth    = "auth"
)

var (
	ErrInvalidSourceBinding      = errors.New("repository: invalid source binding")
	ErrSourceBindingConflict     = errors.New("repository: source binding conflict")
	ErrSourceRegistryUnavailable = errors.New("repository: source registry unavailable")

	registryUUIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	registryKeyPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	registryLabelPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

const registerExpectedSourceBindingSQL = `
SELECT binding_id::text, sender_id, endpoint_kind, endpoint_path,
    service_label, key_id, config_digest::text, binding_digest::text, effective_at
FROM sentinelflow.register_expected_source_binding(
    $1::uuid, $2::text, $3::text, $4::text, $5::text, $6::text
)`

const retireExpectedSourceBindingSQL = `
SELECT retirement_id::text, binding_id::text, reason_digest::text, retired_at
FROM sentinelflow.retire_expected_source_binding($1::uuid, $2::uuid, $3::text)`

// SourceRegistryQueryRower is intentionally narrower than a pool. Registration
// is the sole coordinator operation and never receives a transport HMAC key.
type SourceRegistryQueryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type PostgreSQLSourceRegistry struct {
	db SourceRegistryQueryRower
}

type ExpectedSourceBinding struct {
	BindingID    string
	SenderID     string
	EndpointKind string
	ServiceLabel string
	KeyID        string
	ConfigDigest string
}

type RegisteredSourceBinding struct {
	ExpectedSourceBinding
	EndpointPath  string
	BindingDigest string
	EffectiveAt   time.Time
}

type SourceBindingRetirement struct {
	RetirementID string
	BindingID    string
	ReasonDigest string
}

type RegisteredSourceRetirement struct {
	SourceBindingRetirement
	RetiredAt time.Time
}

func NewPostgreSQLSourceRegistry(db SourceRegistryQueryRower) (*PostgreSQLSourceRegistry, error) {
	if db == nil {
		return nil, ErrSourceRegistryUnavailable
	}
	return &PostgreSQLSourceRegistry{db: db}, nil
}

func (r *PostgreSQLSourceRegistry) Register(
	ctx context.Context,
	input ExpectedSourceBinding,
) (RegisteredSourceBinding, error) {
	if err := validateExpectedSourceBinding(input); err != nil {
		return RegisteredSourceBinding{}, err
	}
	var stored RegisteredSourceBinding
	err := r.db.QueryRow(ctx, registerExpectedSourceBindingSQL,
		input.BindingID, input.SenderID, input.EndpointKind,
		input.ServiceLabel, input.KeyID, input.ConfigDigest,
	).Scan(
		&stored.BindingID, &stored.SenderID, &stored.EndpointKind, &stored.EndpointPath,
		&stored.ServiceLabel, &stored.KeyID, &stored.ConfigDigest, &stored.BindingDigest,
		&stored.EffectiveAt,
	)
	if err != nil {
		return RegisteredSourceBinding{}, classifySourceRegistryError(ctx, err)
	}
	expectedPath, _ := sourceEndpointPath(input.EndpointKind)
	if stored.ExpectedSourceBinding != input || stored.EndpointPath != expectedPath ||
		stored.BindingDigest != expectedSourceBindingDigest(input, expectedPath) ||
		stored.EffectiveAt.IsZero() {
		return RegisteredSourceBinding{}, ErrSourceRegistryUnavailable
	}
	stored.EffectiveAt = stored.EffectiveAt.UTC()
	return stored, nil
}

func (r *PostgreSQLSourceRegistry) Retire(
	ctx context.Context,
	input SourceBindingRetirement,
) (RegisteredSourceRetirement, error) {
	if !registryUUIDPattern.MatchString(input.RetirementID) ||
		!registryUUIDPattern.MatchString(input.BindingID) || !digestPattern.MatchString(input.ReasonDigest) {
		return RegisteredSourceRetirement{}, ErrInvalidSourceBinding
	}
	var stored RegisteredSourceRetirement
	err := r.db.QueryRow(ctx, retireExpectedSourceBindingSQL,
		input.RetirementID, input.BindingID, input.ReasonDigest,
	).Scan(&stored.RetirementID, &stored.BindingID, &stored.ReasonDigest, &stored.RetiredAt)
	if err != nil {
		return RegisteredSourceRetirement{}, classifySourceRegistryError(ctx, err)
	}
	if stored.SourceBindingRetirement != input || stored.RetiredAt.IsZero() {
		return RegisteredSourceRetirement{}, ErrSourceRegistryUnavailable
	}
	stored.RetiredAt = stored.RetiredAt.UTC()
	return stored, nil
}

func validateExpectedSourceBinding(input ExpectedSourceBinding) error {
	if !registryUUIDPattern.MatchString(input.BindingID) ||
		!registryKeyPattern.MatchString(input.SenderID) ||
		!registryLabelPattern.MatchString(input.ServiceLabel) ||
		!registryKeyPattern.MatchString(input.KeyID) ||
		!digestPattern.MatchString(input.ConfigDigest) {
		return ErrInvalidSourceBinding
	}
	if _, ok := sourceEndpointPath(input.EndpointKind); !ok {
		return ErrInvalidSourceBinding
	}
	return nil
}

func sourceEndpointPath(endpointKind string) (string, bool) {
	switch endpointKind {
	case SourceEndpointGateway:
		return "/internal/v1/gateway-events", true
	case SourceEndpointAuth:
		return "/internal/v1/auth-events", true
	default:
		return "", false
	}
}

func expectedSourceBindingDigest(input ExpectedSourceBinding, endpointPath string) string {
	canonical := "expected-source-binding-v1\n" + input.BindingID + "\n" + input.SenderID + "\n" +
		input.EndpointKind + "\n" + endpointPath + "\n" + input.ServiceLabel + "\n" +
		input.KeyID + "\n" + input.ConfigDigest + "\n"
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func classifySourceRegistryError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return ErrSourceRegistryUnavailable
	}
	switch pgErr.Code {
	case "22023", "22P02", "23502", "23503", "23514":
		return ErrInvalidSourceBinding
	case "23505":
		return ErrSourceBindingConflict
	default:
		return ErrSourceRegistryUnavailable
	}
}
