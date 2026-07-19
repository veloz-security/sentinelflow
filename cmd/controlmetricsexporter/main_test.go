package main

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

type rowFunc func(...any) error

func (f rowFunc) Scan(destinations ...any) error { return f(destinations...) }

type identityPool struct {
	role, database                                               string
	bounded, membershipFree, schemaBounded, executable           bool
	aggregateContract, aggregateOnly, relationFree, sequenceFree bool
	err                                                          error
}

func (p *identityPool) QueryRow(context.Context, string, ...any) pgx.Row {
	return rowFunc(func(destinations ...any) error {
		if p.err != nil {
			return p.err
		}
		*destinations[0].(*string) = p.role
		*destinations[1].(*string) = p.database
		*destinations[2].(*bool) = p.bounded
		*destinations[3].(*bool) = p.membershipFree
		*destinations[4].(*bool) = p.schemaBounded
		*destinations[5].(*bool) = p.executable
		*destinations[6].(*bool) = p.aggregateContract
		*destinations[7].(*bool) = p.aggregateOnly
		*destinations[8].(*bool) = p.relationFree
		*destinations[9].(*bool) = p.sequenceFree
		return nil
	})
}
func (*identityPool) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unused")
}
func (*identityPool) Ping(context.Context) error { return nil }
func (*identityPool) Close()                     {}

func TestValidateDatabaseIdentityAcceptsOnlyBoundedReadRole(t *testing.T) {
	t.Parallel()
	valid := identityPool{
		role: databaseRole, database: "sentinelflow", bounded: true,
		membershipFree: true, schemaBounded: true, executable: true,
		aggregateContract: true, aggregateOnly: true, relationFree: true, sequenceFree: true,
	}
	if err := validateDatabaseIdentity(context.Background(), &valid); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*identityPool){
		func(pool *identityPool) { pool.role = "sentinelflow_worker" },
		func(pool *identityPool) { pool.database = "postgres" },
		func(pool *identityPool) { pool.bounded = false },
		func(pool *identityPool) { pool.membershipFree = false },
		func(pool *identityPool) { pool.schemaBounded = false },
		func(pool *identityPool) { pool.executable = false },
		func(pool *identityPool) { pool.aggregateContract = false },
		func(pool *identityPool) { pool.aggregateOnly = false },
		func(pool *identityPool) { pool.relationFree = false },
		func(pool *identityPool) { pool.sequenceFree = false },
		func(pool *identityPool) { pool.err = errors.New("database-secret") },
	}
	for _, mutate := range mutations {
		candidate := valid
		mutate(&candidate)
		if err := validateDatabaseIdentity(context.Background(), &candidate); err == nil || err.Error() != "read database identity rejected" {
			t.Fatalf("unsafe identity accepted or leaked detail: %v", err)
		}
	}
}
