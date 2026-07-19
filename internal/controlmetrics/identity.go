package controlmetrics

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

var ErrDatabaseIdentity = errors.New("control metrics database identity rejected")

type identityQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// ValidateDatabaseIdentity attests the exact aggregate function and proves
// that the runtime role has no direct schema-mutation, relation, sequence, or
// alternate function authority before the metrics listener starts.
func ValidateDatabaseIdentity(ctx context.Context, database identityQueryer) error {
	if ctx == nil || database == nil {
		return ErrDatabaseIdentity
	}
	var role, currentDatabase string
	var bounded, membershipFree, schemaBounded, aggregateExecutable bool
	var aggregateContract, aggregateOnly, relationFree, sequenceFree bool
	err := database.QueryRow(ctx, `
SELECT current_user::text, current_database()::text,
       COALESCE((
           SELECT role.rolcanlogin AND NOT role.rolinherit AND
                  NOT role.rolsuper AND NOT role.rolcreatedb AND
                  NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls
           FROM pg_roles role WHERE role.rolname = current_user
       ), false),
       NOT EXISTS (
           SELECT 1 FROM pg_auth_members membership
           JOIN pg_roles member ON member.oid = membership.member
           JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
           WHERE member.rolname = current_user OR granted_role.rolname = current_user
       ),
       has_schema_privilege(current_user, 'sentinelflow', 'USAGE') AND
           NOT has_schema_privilege(current_user, 'sentinelflow', 'CREATE'),
       has_function_privilege(
           current_user,
           'sentinelflow.control_observability_samples_000028()',
           'EXECUTE'
       ),
       EXISTS (
           SELECT 1
           FROM pg_proc function
           JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
           JOIN pg_roles owner ON owner.oid = function.proowner
           JOIN pg_language language ON language.oid = function.prolang
           WHERE function.oid =
                 'sentinelflow.control_observability_samples_000028()'::regprocedure
             AND namespace.nspname = 'sentinelflow'
             AND owner.rolname = 'sentinelflow_migration'
             AND language.lanname = 'sql'
             AND function.prokind = 'f'
             AND function.prosecdef
             AND function.provolatile = 's'
             AND function.proretset
             AND function.proallargtypes = ARRAY[
                 'text'::regtype, 'text'::regtype, 'text'::regtype,
                 'text'::regtype, 'text'::regtype, 'double precision'::regtype
             ]::oid[]
             AND function.proargmodes = ARRAY['t','t','t','t','t','t']::"char"[]
             AND function.proargnames = ARRAY[
                 'metric_name', 'label_1_name', 'label_1_value',
                 'label_2_name', 'label_2_value', 'sample_value'
             ]::text[]
             AND function.proconfig = ARRAY['search_path=pg_catalog, sentinelflow']::text[]
       ),
       NOT EXISTS (
           SELECT 1 FROM pg_proc function
           JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
           WHERE namespace.nspname = 'sentinelflow'
             AND function.oid <>
                 'sentinelflow.control_observability_samples_000028()'::regprocedure
             AND has_function_privilege(current_user, function.oid, 'EXECUTE')
       ),
       NOT EXISTS (
           SELECT 1
           FROM pg_class relation
           JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
           WHERE namespace.nspname = 'sentinelflow'
             AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
             AND (
                 has_table_privilege(current_user, relation.oid, 'SELECT') OR
                 has_table_privilege(current_user, relation.oid, 'INSERT') OR
                 has_table_privilege(current_user, relation.oid, 'UPDATE') OR
                 has_table_privilege(current_user, relation.oid, 'DELETE') OR
                 has_table_privilege(current_user, relation.oid, 'TRUNCATE') OR
                 has_table_privilege(current_user, relation.oid, 'REFERENCES') OR
                 has_table_privilege(current_user, relation.oid, 'TRIGGER') OR
                 has_any_column_privilege(current_user, relation.oid, 'SELECT') OR
                 has_any_column_privilege(current_user, relation.oid, 'INSERT') OR
                 has_any_column_privilege(current_user, relation.oid, 'UPDATE') OR
                 has_any_column_privilege(current_user, relation.oid, 'REFERENCES')
             )
       ),
       NOT EXISTS (
           SELECT 1
           FROM pg_class sequence
           JOIN pg_namespace namespace ON namespace.oid = sequence.relnamespace
           WHERE namespace.nspname = 'sentinelflow'
             AND sequence.relkind = 'S'
             AND (
                 has_sequence_privilege(current_user, sequence.oid, 'USAGE') OR
                 has_sequence_privilege(current_user, sequence.oid, 'SELECT') OR
                 has_sequence_privilege(current_user, sequence.oid, 'UPDATE')
             )
       )`).Scan(&role, &currentDatabase, &bounded, &membershipFree, &schemaBounded,
		&aggregateExecutable, &aggregateContract, &aggregateOnly, &relationFree, &sequenceFree)
	if err != nil || role != "sentinelflow_metrics" || currentDatabase != "sentinelflow" ||
		!bounded || !membershipFree || !schemaBounded || !aggregateExecutable ||
		!aggregateContract || !aggregateOnly || !relationFree || !sequenceFree {
		return ErrDatabaseIdentity
	}
	return nil
}
