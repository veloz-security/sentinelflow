package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgreSQLSourceRegistryRegistersAndRetiresWithoutSecrets(t *testing.T) {
	now := time.Date(2026, 7, 18, 3, 4, 5, 0, time.UTC)
	input := ExpectedSourceBinding{
		BindingID:    "00000000-0000-4000-8000-000000000101",
		SenderID:     "gateway-01",
		EndpointKind: SourceEndpointGateway,
		ServiceLabel: "demo-app",
		KeyID:        "gateway-key-01",
		ConfigDigest: "sha256:" + strings.Repeat("a", 64),
	}
	path, _ := sourceEndpointPath(input.EndpointKind)
	digest := expectedSourceBindingDigest(input, path)
	stub := &sourceRegistryStub{rows: []pgx.Row{
		&sourceRegistryRow{values: []any{
			input.BindingID, input.SenderID, input.EndpointKind, path,
			input.ServiceLabel, input.KeyID, input.ConfigDigest, digest, now,
		}},
		&sourceRegistryRow{values: []any{
			"00000000-0000-4000-8000-000000000102", input.BindingID,
			"sha256:" + strings.Repeat("b", 64), now.Add(time.Second),
		}},
	}}
	registry, err := NewPostgreSQLSourceRegistry(stub)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := registry.Register(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ExpectedSourceBinding != input || stored.EndpointPath != path ||
		stored.BindingDigest != digest || !stored.EffectiveAt.Equal(now) {
		t.Fatalf("stored binding = %#v", stored)
	}
	retirement := SourceBindingRetirement{
		RetirementID: "00000000-0000-4000-8000-000000000102",
		BindingID:    input.BindingID,
		ReasonDigest: "sha256:" + strings.Repeat("b", 64),
	}
	retired, err := registry.Retire(context.Background(), retirement)
	if err != nil {
		t.Fatal(err)
	}
	if retired.SourceBindingRetirement != retirement || !retired.RetiredAt.Equal(now.Add(time.Second)) {
		t.Fatalf("stored retirement = %#v", retired)
	}
	for _, arguments := range stub.arguments {
		for _, argument := range arguments {
			if value, ok := argument.(string); ok && strings.Contains(value, "secret") {
				t.Fatalf("secret-shaped argument reached registry query: %q", value)
			}
		}
	}
}

func TestPostgreSQLSourceRegistryFailsClosedAndRedactsDatabaseErrors(t *testing.T) {
	registry, err := NewPostgreSQLSourceRegistry(&sourceRegistryStub{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(context.Background(), ExpectedSourceBinding{}); !errors.Is(err, ErrInvalidSourceBinding) {
		t.Fatalf("invalid registration error = %v", err)
	}
	if _, err := registry.Retire(context.Background(), SourceBindingRetirement{}); !errors.Is(err, ErrInvalidSourceBinding) {
		t.Fatalf("invalid retirement error = %v", err)
	}
	if _, err := NewPostgreSQLSourceRegistry(nil); !errors.Is(err, ErrSourceRegistryUnavailable) {
		t.Fatalf("nil registry error = %v", err)
	}

	input := ExpectedSourceBinding{
		BindingID: "00000000-0000-4000-8000-000000000201", SenderID: "auth-app",
		EndpointKind: SourceEndpointAuth, ServiceLabel: "demo-app", KeyID: "auth-key-01",
		ConfigDigest: "sha256:" + strings.Repeat("c", 64),
	}
	secret := "database secret should not escape"
	conflict, _ := NewPostgreSQLSourceRegistry(&sourceRegistryStub{rows: []pgx.Row{
		&sourceRegistryRow{err: &pgconn.PgError{Code: "23505", Message: secret}},
	}})
	_, err = conflict.Register(context.Background(), input)
	if !errors.Is(err, ErrSourceBindingConflict) || strings.Contains(err.Error(), secret) {
		t.Fatalf("conflict error = %v", err)
	}

	path, _ := sourceEndpointPath(input.EndpointKind)
	mismatch, _ := NewPostgreSQLSourceRegistry(&sourceRegistryStub{rows: []pgx.Row{
		&sourceRegistryRow{values: []any{
			input.BindingID, input.SenderID, input.EndpointKind, path,
			input.ServiceLabel, input.KeyID, input.ConfigDigest,
			"sha256:" + strings.Repeat("d", 64), time.Now().UTC(),
		}},
	}})
	if _, err := mismatch.Register(context.Background(), input); !errors.Is(err, ErrSourceRegistryUnavailable) {
		t.Fatalf("digest mismatch error = %v", err)
	}
}

type sourceRegistryStub struct {
	rows      []pgx.Row
	arguments [][]any
}

func (s *sourceRegistryStub) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	s.arguments = append(s.arguments, append([]any(nil), args...))
	if len(s.rows) == 0 {
		return &sourceRegistryRow{err: errors.New("unexpected query")}
	}
	row := s.rows[0]
	s.rows = s.rows[1:]
	return row
}

type sourceRegistryRow struct {
	values []any
	err    error
}

func (r *sourceRegistryRow) Scan(destinations ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(destinations) != len(r.values) {
		return errors.New("scan arity mismatch")
	}
	for index, value := range r.values {
		switch destination := destinations[index].(type) {
		case *string:
			*destination = value.(string)
		case *time.Time:
			*destination = value.(time.Time)
		default:
			return errors.New("unsupported scan destination")
		}
	}
	return nil
}
