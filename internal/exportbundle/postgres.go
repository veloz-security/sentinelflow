package exportbundle

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

const readDatabaseRole = ReadCapabilityRole

type transactionStarter interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type PostgresStore struct {
	database transactionStarter
}

func NewPostgresStore(database transactionStarter) (*PostgresStore, error) {
	if database == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgresStore{database: database}, nil
}

func (s *PostgresStore) Snapshot(ctx context.Context, query Query) (Snapshot, error) {
	if s == nil || s.database == nil || !query.Valid() {
		return Snapshot{}, ErrInvalidRequest
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return Snapshot{}, errors.New("export database snapshot unavailable")
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE sentinelflow_read`); err != nil {
		return Snapshot{}, errors.New("export database role transition rejected")
	}

	var role, sessionRole, database string
	var capabilitySafe, capabilityLogin, sessionSafe, sessionNoInherit bool
	var capabilityOutboundFree, sessionAuthorityFree, selectOnly, functionFree, namespaceSafe bool
	var sessionMemberships, safeReadMemberships int
	if err = tx.QueryRow(ctx, exportRoleIdentitySQL).Scan(
		&role, &sessionRole, &database, &capabilitySafe, &capabilityLogin,
		&sessionSafe, &sessionNoInherit, &capabilityOutboundFree,
		&sessionMemberships, &safeReadMemberships, &sessionAuthorityFree,
		&selectOnly, &functionFree, &namespaceSafe,
	); err != nil || role != readDatabaseRole || database != "sentinelflow" ||
		!capabilitySafe || !capabilityOutboundFree || !selectOnly || !functionFree || !namespaceSafe {
		return Snapshot{}, errors.New("export database identity rejected")
	}
	directDemo := sessionRole == role && capabilityLogin && sessionMemberships == 0
	delegated := sessionRole != role && !capabilityLogin && sessionSafe && sessionNoInherit &&
		sessionMemberships == 1 && safeReadMemberships == 1 && sessionAuthorityFree
	if !directDemo && !delegated {
		return Snapshot{}, errors.New("export database identity rejected")
	}

	var snapshot Snapshot
	if err = tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&snapshot.SnapshotAt); err != nil {
		return Snapshot{}, errors.New("export database clock unavailable")
	}
	snapshot.Incidents, err = queryIncidents(ctx, tx, query)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Audit, err = queryAudit(ctx, tx, query)
	if err != nil {
		return Snapshot{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Snapshot{}, errors.New("export database snapshot commit failed")
	}
	return snapshot, nil
}

func queryIncidents(ctx context.Context, tx pgx.Tx, query Query) ([]RawIncident, error) {
	rows, err := tx.Query(ctx, exportIncidentsSQL, query.Since(), query.Until(),
		query.IncidentID(), query.MaxIncidents()+1)
	if err != nil {
		return nil, errors.New("export incident snapshot failed")
	}
	defer rows.Close()
	result := make([]RawIncident, 0)
	for rows.Next() {
		var value RawIncident
		if err = rows.Scan(
			&value.IncidentID, &value.Kind, &value.State, &value.SourceIPv4,
			&value.ServiceLabel, &value.FirstSeen, &value.LastSeen, &value.ClosedAt,
			&value.ReopenUntil, &value.DeterministicScore, &value.Version,
			&value.AnalysisFailureReason, &value.CreatedAt, &value.UpdatedAt,
		); err != nil {
			return nil, errors.New("export incident row rejected")
		}
		result = append(result, value)
		if len(result) > query.MaxIncidents() {
			return nil, ErrLimitExceeded
		}
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("export incident snapshot interrupted")
	}
	return result, nil
}

func queryAudit(ctx context.Context, tx pgx.Tx, query Query) ([]RawAuditEvent, error) {
	rows, err := tx.Query(ctx, exportAuditSQL, query.Since(), query.Until(),
		query.IncidentID(), query.MaxAuditEvents()+1)
	if err != nil {
		return nil, errors.New("export audit snapshot failed")
	}
	defer rows.Close()
	result := make([]RawAuditEvent, 0)
	for rows.Next() {
		var value RawAuditEvent
		if err = rows.Scan(
			&value.Sequence, &value.EventID, &value.ActorType, &value.ActorID,
			&value.Action, &value.ObjectType, &value.ObjectID, &value.IncidentID,
			&value.PolicyID, &value.PolicyVersion, &value.EnforcementActionID,
			&value.TraceID, &value.PrimaryDigest, &value.SecondaryDigest,
			&value.Outcome, &value.OccurredAt, &value.RecordedAt,
		); err != nil {
			return nil, errors.New("export audit row rejected")
		}
		result = append(result, value)
		if len(result) > query.MaxAuditEvents() {
			return nil, ErrLimitExceeded
		}
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New("export audit snapshot interrupted")
	}
	return result, nil
}

const exportRoleIdentitySQL = `
SELECT current_user::text, session_user::text, current_database()::text,
       COALESCE((
           SELECT NOT role.rolsuper AND NOT role.rolcreatedb AND
                  NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls
           FROM pg_catalog.pg_roles role
           WHERE role.rolname = current_user
       ), false),
       COALESCE((
           SELECT role.rolcanlogin
           FROM pg_catalog.pg_roles role
           WHERE role.rolname = current_user
       ), false),
       COALESCE((
           SELECT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolcreatedb AND
                  NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls
           FROM pg_catalog.pg_roles role
           WHERE role.rolname = session_user
       ), false),
       COALESCE((
           SELECT NOT role.rolinherit
           FROM pg_catalog.pg_roles role
           WHERE role.rolname = session_user
       ), false),
       NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_auth_members membership
           JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
           WHERE member_role.rolname = current_user
       ),
       (
           SELECT count(*)::integer
           FROM pg_catalog.pg_auth_members membership
           JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
           WHERE member_role.rolname = session_user
       ),
       (
           SELECT count(*)::integer
           FROM pg_catalog.pg_auth_members membership
           JOIN pg_catalog.pg_roles member_role ON member_role.oid = membership.member
           JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = membership.roleid
           WHERE member_role.rolname = session_user
             AND granted_role.rolname = 'sentinelflow_read'
             AND NOT membership.admin_option
             AND NOT membership.inherit_option
             AND membership.set_option
       ),
       NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_class relation
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
           WHERE namespace.nspname = 'sentinelflow'
             AND (
                 relation.relowner = (
                     SELECT role.oid FROM pg_catalog.pg_roles role
                     WHERE role.rolname = session_user
                 ) OR EXISTS (
                     SELECT 1 FROM pg_catalog.aclexplode(relation.relacl) privilege
                     JOIN pg_catalog.pg_roles grantee ON grantee.oid = privilege.grantee
                     WHERE grantee.rolname = session_user
                 )
             )
       ) AND
       NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_type object_type
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid = object_type.typnamespace
           WHERE namespace.nspname = 'sentinelflow'
             AND (
                 object_type.typowner = (
                     SELECT role.oid FROM pg_catalog.pg_roles role
                     WHERE role.rolname = session_user
                 ) OR EXISTS (
                     SELECT 1 FROM pg_catalog.aclexplode(object_type.typacl) privilege
                     JOIN pg_catalog.pg_roles grantee ON grantee.oid = privilege.grantee
                     WHERE grantee.rolname = session_user
                 )
             )
       ) AND
       NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_proc procedure
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
           WHERE namespace.nspname = 'sentinelflow'
             AND (
                 procedure.proowner = (
                     SELECT role.oid FROM pg_catalog.pg_roles role
                     WHERE role.rolname = session_user
                 ) OR EXISTS (
                     SELECT 1 FROM pg_catalog.aclexplode(procedure.proacl) privilege
                     JOIN pg_catalog.pg_roles grantee ON grantee.oid = privilege.grantee
                     WHERE grantee.rolname = session_user
                 )
             )
       ) AND
       NOT has_schema_privilege(session_user, 'sentinelflow', 'USAGE') AND
       NOT has_schema_privilege(session_user, 'sentinelflow', 'CREATE') AND
       NOT has_database_privilege(session_user, current_database(), 'CREATE'),
       NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_class relation
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
           WHERE namespace.nspname = 'sentinelflow'
             AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
             AND (
                 has_table_privilege(current_user, relation.oid, 'INSERT') OR
                 has_table_privilege(current_user, relation.oid, 'UPDATE') OR
                 has_table_privilege(current_user, relation.oid, 'DELETE') OR
                 has_table_privilege(current_user, relation.oid, 'TRUNCATE') OR
                 has_table_privilege(current_user, relation.oid, 'REFERENCES') OR
                 has_table_privilege(current_user, relation.oid, 'TRIGGER')
             )
       ),
       NOT EXISTS (
           SELECT 1
           FROM pg_catalog.pg_proc procedure
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
           WHERE namespace.nspname = 'sentinelflow'
             AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
       ),
       NOT has_schema_privilege(current_user, 'sentinelflow', 'CREATE') AND
       NOT has_database_privilege(current_user, current_database(), 'CREATE')`

const exportIncidentsSQL = `
SELECT incident.incident_id::text, incident.kind, incident.state,
       host(incident.source_ip), incident.service_label::text,
       incident.first_seen, incident.last_seen, incident.closed_at,
       incident.reopen_until, incident.deterministic_score::text,
       incident.version, incident.analysis_failure_reason,
       incident.created_at, incident.updated_at
FROM sentinelflow.incidents incident
WHERE (NULLIF($3::text, '') IS NULL OR incident.incident_id = NULLIF($3::text, '')::uuid)
  AND (
      incident.updated_at BETWEEN $1::timestamptz AND $2::timestamptz OR
      EXISTS (
          SELECT 1 FROM sentinelflow.audit_events audit
          WHERE audit.incident_id = incident.incident_id
            AND audit.occurred_at BETWEEN $1::timestamptz AND $2::timestamptz
      )
  )
ORDER BY incident.incident_id
LIMIT $4`

const exportAuditSQL = `
SELECT audit.sequence, audit.event_id::text, audit.actor_type,
       audit.actor_id::text, audit.action::text, audit.object_type::text,
       audit.object_id::text, audit.incident_id::text, audit.policy_id::text,
       audit.policy_version, audit.enforcement_action_id::text,
       audit.trace_id::text, audit.primary_digest::text,
       audit.secondary_digest::text, audit.outcome,
       audit.occurred_at, audit.recorded_at
FROM sentinelflow.audit_events audit
WHERE audit.occurred_at BETWEEN $1::timestamptz AND $2::timestamptz
  AND (NULLIF($3::text, '') IS NULL OR audit.incident_id = NULLIF($3::text, '')::uuid)
ORDER BY audit.sequence
LIMIT $4`
