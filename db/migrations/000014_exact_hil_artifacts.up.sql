BEGIN;

SET LOCAL ROLE sentinelflow_migration;
SET LOCAL search_path = sentinelflow, pg_catalog;

-- Canonical validation evidence is a distinct contract from
-- correlation-evidence-v1.  It is created in the same transaction as the
-- normalized evidence rows and is never attached to a legacy row later.
CREATE TABLE IF NOT EXISTS evidence_snapshot_artifacts (
    evidence_snapshot_id uuid PRIMARY KEY
        REFERENCES evidence_snapshots (evidence_snapshot_id) ON DELETE RESTRICT,
    schema_version text NOT NULL CHECK (schema_version = 'evidence-snapshot-v1'),
    source_health_digest sha256_digest NOT NULL,
    canonical_bytes bytea NOT NULL,
    canonical_digest sha256_digest NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    CONSTRAINT evidence_snapshot_artifact_size CHECK (
        octet_length(canonical_bytes) BETWEEN 2 AND 67108864
    ),
    CONSTRAINT evidence_snapshot_artifact_digest CHECK (
        canonical_digest = sentinelflow.validation_sha256(canonical_bytes)
    )
);

-- This row is the only database projection from which an exact HIL artifact
-- may be loaded.  Keeping every byte identity in one immutable row prevents a
-- later join from assembling a policy from different artifact generations.
CREATE TABLE IF NOT EXISTS hil_exact_artifacts (
    policy_id uuid NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version >= 1),
    command_candidate_id uuid NOT NULL UNIQUE
        REFERENCES command_candidates (command_candidate_id) ON DELETE RESTRICT,
    validation_snapshot_id uuid NOT NULL UNIQUE
        REFERENCES validation_snapshots (validation_snapshot_id) ON DELETE RESTRICT,
    evidence_snapshot_id uuid NOT NULL
        REFERENCES evidence_snapshot_artifacts (evidence_snapshot_id) ON DELETE RESTRICT,
    target_ipv4 canonical_ipv4 NOT NULL,
    ttl_seconds integer NOT NULL CHECK (ttl_seconds BETWEEN 60 AND 86400),
    policy_bytes bytea NOT NULL,
    policy_digest sha256_digest NOT NULL,
    evidence_bytes bytea NOT NULL,
    evidence_digest sha256_digest NOT NULL,
    validation_bytes bytea NOT NULL,
    validation_digest sha256_digest NOT NULL UNIQUE,
    generated_bytes bytea NOT NULL,
    generated_digest sha256_digest NOT NULL,
    canonical_bytes bytea NOT NULL,
    canonical_digest sha256_digest NOT NULL,
    validation_created_at timestamptz NOT NULL,
    validation_valid_until timestamptz NOT NULL,
    persisted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (policy_id, policy_version),
    CONSTRAINT hil_exact_artifact_policy_fk
        FOREIGN KEY (policy_id, policy_version)
        REFERENCES policy_proposals (policy_id, version) ON DELETE RESTRICT,
    CONSTRAINT hil_exact_artifact_sizes CHECK (
        octet_length(policy_bytes) BETWEEN 2 AND 8192 AND
        octet_length(evidence_bytes) BETWEEN 2 AND 67108864 AND
        octet_length(validation_bytes) BETWEEN 2 AND 32768 AND
        octet_length(generated_bytes) BETWEEN 1 AND 256 AND
        octet_length(canonical_bytes) BETWEEN 1 AND 256
    ),
    CONSTRAINT hil_exact_artifact_digests CHECK (
        policy_digest = sentinelflow.validation_sha256(policy_bytes) AND
        evidence_digest = sentinelflow.validation_sha256(evidence_bytes) AND
        validation_digest = sentinelflow.validation_sha256(validation_bytes) AND
        generated_digest = sentinelflow.validation_sha256(generated_bytes) AND
        canonical_digest = sentinelflow.validation_sha256(canonical_bytes)
    ),
    CONSTRAINT hil_exact_artifact_validity CHECK (
        validation_valid_until = validation_created_at + interval '5 minutes'
    )
);

CREATE OR REPLACE FUNCTION sentinelflow.reject_exact_artifact_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'canonical artifact rows are immutable';
END
$function$;

DROP TRIGGER IF EXISTS evidence_snapshot_artifacts_immutable
    ON sentinelflow.evidence_snapshot_artifacts;
CREATE TRIGGER evidence_snapshot_artifacts_immutable
BEFORE UPDATE OR DELETE ON sentinelflow.evidence_snapshot_artifacts
FOR EACH ROW EXECUTE FUNCTION sentinelflow.reject_exact_artifact_mutation();

DROP TRIGGER IF EXISTS hil_exact_artifacts_immutable
    ON sentinelflow.hil_exact_artifacts;
CREATE TRIGGER hil_exact_artifacts_immutable
BEFORE UPDATE OR DELETE ON sentinelflow.hil_exact_artifacts
FOR EACH ROW EXECUTE FUNCTION sentinelflow.reject_exact_artifact_mutation();

-- The correlation runtime calls this single seam only after Go has parsed and
-- re-canonicalized validation.EvidenceSnapshot.  PostgreSQL independently
-- checks the byte digest and every normalized membership relation before any
-- row becomes visible.
CREATE OR REPLACE FUNCTION sentinelflow.insert_exact_evidence_snapshot(
    p_snapshot json,
    p_canonical_bytes bytea
)
RETURNS TABLE(evidence_snapshot_id uuid, snapshot_digest sha256_digest, inserted boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    document jsonb;
    canonical_document jsonb;
    snapshot_id_value uuid;
    incident_id_value uuid;
    incident_version_value integer;
    source_ip_value inet;
    service_label_value text;
    window_start_value timestamptz;
    window_end_value timestamptz;
    created_at_value timestamptz;
    expires_at_value timestamptz;
    digest_value sentinelflow.sha256_digest;
    source_health_digest_value sentinelflow.sha256_digest;
    signal_count_value integer;
    event_count_value integer;
    existing_snapshot sentinelflow.evidence_snapshots%ROWTYPE;
    existing_artifact sentinelflow.evidence_snapshot_artifacts%ROWTYPE;
BEGIN
    IF p_snapshot IS NULL OR p_canonical_bytes IS NULL OR
       NOT sentinelflow.validation_json_no_duplicate_keys(p_snapshot) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid exact evidence request';
    END IF;
    document := p_snapshot::jsonb;
    IF NOT sentinelflow.validation_jsonb_exact_keys(document, ARRAY[
        'created_at', 'events', 'expanded_event_count', 'expires_at', 'incident_id',
        'incident_version', 'schema_version', 'service_label', 'signal_count',
        'signals', 'snapshot_digest', 'snapshot_id', 'source_health_status',
        'source_ipv4', 'window_end', 'window_start'
    ]) OR document->>'schema_version' <> 'evidence-snapshot-v1' OR
       document->>'source_health_status' NOT IN ('complete', 'incomplete') OR
       jsonb_typeof(document->'signals') <> 'array' OR
       jsonb_typeof(document->'events') <> 'array' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid exact evidence request';
    END IF;

    BEGIN
        canonical_document := convert_from(p_canonical_bytes, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid canonical evidence bytes';
    END;
    IF NOT sentinelflow.validation_json_no_duplicate_keys(
            convert_from(p_canonical_bytes, 'UTF8')::json) OR
       NOT sentinelflow.validation_jsonb_exact_keys(canonical_document, ARRAY[
            'created_at', 'event_ids', 'incident_id', 'incident_version',
            'schema_version', 'service_label', 'signal_ids', 'snapshot_id',
            'source_health_digest', 'source_ipv4', 'window_end', 'window_start'
       ]) OR canonical_document->>'schema_version' <> 'evidence-snapshot-v1' OR
       canonical_document->>'source_health_digest' !~ '^sha256:[0-9a-f]{64}$' OR
       octet_length(p_canonical_bytes) NOT BETWEEN 2 AND 67108864 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid canonical evidence bytes';
    END IF;

    BEGIN
        snapshot_id_value := (document->>'snapshot_id')::uuid;
        incident_id_value := (document->>'incident_id')::uuid;
        incident_version_value := (document->>'incident_version')::integer;
        source_ip_value := (document->>'source_ipv4')::inet;
        service_label_value := document->>'service_label';
        window_start_value := (document->>'window_start')::timestamptz;
        window_end_value := (document->>'window_end')::timestamptz;
        created_at_value := (document->>'created_at')::timestamptz;
        expires_at_value := (document->>'expires_at')::timestamptz;
        digest_value := (document->>'snapshot_digest')::sentinelflow.sha256_digest;
        source_health_digest_value :=
            (canonical_document->>'source_health_digest')::sentinelflow.sha256_digest;
        signal_count_value := (document->>'signal_count')::integer;
        event_count_value := (document->>'expanded_event_count')::integer;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid exact evidence fields';
    END;

    IF digest_value <> sentinelflow.validation_sha256(p_canonical_bytes) OR
       signal_count_value NOT BETWEEN 1 AND 50 OR event_count_value < 1 OR
       jsonb_array_length(document->'signals') <> signal_count_value OR
       jsonb_array_length(document->'events') <> event_count_value OR
       jsonb_array_length(canonical_document->'signal_ids') <> signal_count_value OR
       created_at_value < window_end_value OR window_end_value < window_start_value OR
       expires_at_value <= created_at_value OR
       canonical_document->>'snapshot_id' <> snapshot_id_value::text OR
       canonical_document->>'incident_id' <> incident_id_value::text OR
       (canonical_document->>'incident_version')::integer <> incident_version_value OR
       canonical_document->>'source_ipv4' <> host(source_ip_value) OR
       canonical_document->>'service_label' <> service_label_value OR
       (canonical_document->>'window_start')::timestamptz <> window_start_value OR
       (canonical_document->>'window_end')::timestamptz <> window_end_value OR
       (canonical_document->>'created_at')::timestamptz <> created_at_value THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'exact evidence binding mismatch';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(document->'signals') item
        WHERE NOT sentinelflow.validation_jsonb_exact_keys(item, ARRAY[
            'evidence_digest', 'expanded_event_count', 'ordinal', 'signal_id'
        ]) OR item->>'evidence_digest' !~ '^sha256:[0-9a-f]{64}$' OR
        (item->>'ordinal')::integer NOT BETWEEN 1 AND 50 OR
        (item->>'expanded_event_count')::integer < 1
    ) OR EXISTS (
        SELECT 1
        FROM jsonb_array_elements(document->'events') item
        WHERE NOT sentinelflow.validation_jsonb_exact_keys(item, ARRAY[
            'event_id', 'event_kind', 'event_row_id', 'event_time', 'signal_id'
        ]) OR item->>'event_kind' NOT IN ('gateway', 'auth', 'source_health')
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid normalized evidence rows';
    END IF;

    IF canonical_document->'signal_ids' <> (
        SELECT COALESCE(jsonb_agg(to_jsonb(item->>'signal_id') ORDER BY (item->>'ordinal')::integer), '[]'::jsonb)
        FROM jsonb_array_elements(document->'signals') item
    ) OR canonical_document->'event_ids' <> (
        SELECT COALESCE(jsonb_agg(to_jsonb(event_id) ORDER BY event_id), '[]'::jsonb)
        FROM (SELECT DISTINCT item->>'event_id' AS event_id
              FROM jsonb_array_elements(document->'events') item) ids
    ) OR EXISTS (
        SELECT 1
        FROM generate_series(1, signal_count_value) ordinal
        WHERE NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(document->'signals') item
            WHERE (item->>'ordinal')::integer = ordinal
        )
    ) OR (SELECT count(DISTINCT item->>'signal_id')
          FROM jsonb_array_elements(document->'signals') item) <> signal_count_value OR
       (SELECT count(DISTINCT (item->>'ordinal')::integer)
          FROM jsonb_array_elements(document->'signals') item) <> signal_count_value OR
       (SELECT count(DISTINCT item->>'event_row_id')
          FROM jsonb_array_elements(document->'events') item) <> event_count_value OR
       (SELECT count(DISTINCT concat_ws(chr(10), item->>'signal_id',
            item->>'event_kind', item->>'event_id'))
          FROM jsonb_array_elements(document->'events') item) <> event_count_value OR EXISTS (
        SELECT 1
        FROM jsonb_array_elements(document->'signals') item
        WHERE (item->>'ordinal')::integer <> (
            SELECT ordinal
            FROM jsonb_array_elements(canonical_document->'signal_ids')
                WITH ORDINALITY AS expected(signal_id, ordinal)
            WHERE expected.signal_id = to_jsonb(item->>'signal_id')
        )
    ) OR EXISTS (
        SELECT 1
        FROM jsonb_array_elements(document->'signals') signal
        WHERE (signal->>'expanded_event_count')::integer <> (
            SELECT count(*) FROM jsonb_array_elements(document->'events') event
            WHERE event->>'signal_id' = signal->>'signal_id'
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'normalized evidence membership mismatch';
    END IF;

    -- A replay is accepted only when the complete immutable row and every
    -- normalized relation already match.  A legacy row without its artifact is
    -- deliberately not eligible for attachment.
    SELECT * INTO existing_snapshot
    FROM sentinelflow.evidence_snapshots row_value
    WHERE row_value.evidence_snapshot_id = snapshot_id_value;
    IF FOUND THEN
        SELECT * INTO existing_artifact
        FROM sentinelflow.evidence_snapshot_artifacts row_value
        WHERE row_value.evidence_snapshot_id = snapshot_id_value;
        IF NOT FOUND OR existing_artifact.canonical_bytes <> p_canonical_bytes OR
           existing_artifact.canonical_digest <> digest_value OR
           existing_snapshot.snapshot_digest <> digest_value OR
           existing_snapshot.incident_id <> incident_id_value OR
           existing_snapshot.incident_version <> incident_version_value OR
           existing_snapshot.source_ip <> source_ip_value OR
           existing_snapshot.service_label <> service_label_value OR
           existing_snapshot.window_start <> window_start_value OR
           existing_snapshot.window_end <> window_end_value OR
           existing_snapshot.created_at <> created_at_value OR
           existing_snapshot.expires_at <> expires_at_value OR
           existing_snapshot.source_health_status <> document->>'source_health_status' OR
           existing_snapshot.signal_count <> signal_count_value OR
           existing_snapshot.expanded_event_count <> event_count_value OR
           (SELECT count(*) FROM sentinelflow.evidence_snapshot_signals link
             WHERE link.evidence_snapshot_id = snapshot_id_value) <> signal_count_value OR
           (SELECT count(*) FROM sentinelflow.evidence_snapshot_events link
             WHERE link.evidence_snapshot_id = snapshot_id_value) <> event_count_value OR
           EXISTS (
               SELECT 1
               FROM jsonb_array_elements(document->'signals') item
               LEFT JOIN sentinelflow.evidence_snapshot_signals link
                 ON link.evidence_snapshot_id = snapshot_id_value
                AND link.ordinal = (item->>'ordinal')::integer
                AND link.signal_id = (item->>'signal_id')::uuid
                AND link.evidence_id = item->>'signal_id'
                AND link.evidence_digest =
                    (item->>'evidence_digest')::sentinelflow.sha256_digest
                AND link.expanded_event_count = (item->>'expanded_event_count')::integer
               WHERE link.signal_id IS NULL
           ) OR EXISTS (
               SELECT 1
               FROM jsonb_array_elements(document->'events') item
               LEFT JOIN sentinelflow.evidence_snapshot_events link
                 ON link.evidence_snapshot_id = snapshot_id_value
                AND link.evidence_snapshot_event_id = (item->>'event_row_id')::uuid
                AND link.signal_id = (item->>'signal_id')::uuid
                AND link.event_kind = item->>'event_kind'
                AND link.gateway_event_id IS NOT DISTINCT FROM
                    CASE WHEN item->>'event_kind' = 'gateway'
                        THEN (item->>'event_id')::uuid END
                AND link.auth_event_id IS NOT DISTINCT FROM
                    CASE WHEN item->>'event_kind' = 'auth'
                        THEN (item->>'event_id')::uuid END
                AND link.source_health_event_id IS NOT DISTINCT FROM
                    CASE WHEN item->>'event_kind' = 'source_health'
                        THEN (item->>'event_id')::uuid END
                AND link.event_time = (item->>'event_time')::timestamptz
               WHERE link.evidence_snapshot_event_id IS NULL
           ) THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'exact evidence replay conflict';
        END IF;
        evidence_snapshot_id := snapshot_id_value;
        snapshot_digest := digest_value;
        inserted := false;
        RETURN NEXT;
        RETURN;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM sentinelflow.incidents incident
        WHERE incident.incident_id = incident_id_value
          AND incident.version = incident_version_value
          AND incident.source_ip = source_ip_value
          AND incident.service_label = service_label_value
    ) OR EXISTS (
        SELECT 1
        FROM jsonb_array_elements(document->'signals') item
        LEFT JOIN sentinelflow.signals signal
          ON signal.signal_id = (item->>'signal_id')::uuid
         AND signal.evidence_digest = (item->>'evidence_digest')::sentinelflow.sha256_digest
         AND signal.source_ip = source_ip_value
         AND signal.service_label = service_label_value
         AND signal.window_start >= window_start_value
         AND signal.window_end <= window_end_value
        WHERE signal.signal_id IS NULL
    ) OR EXISTS (
        SELECT 1
        FROM jsonb_array_elements(document->'events') item
        LEFT JOIN sentinelflow.signal_evidence link
          ON link.signal_id = (item->>'signal_id')::uuid
         AND link.event_kind = item->>'event_kind'
         AND link.gateway_event_id IS NOT DISTINCT FROM
             CASE WHEN item->>'event_kind' = 'gateway' THEN (item->>'event_id')::uuid END
         AND link.auth_event_id IS NOT DISTINCT FROM
             CASE WHEN item->>'event_kind' = 'auth' THEN (item->>'event_id')::uuid END
         AND link.source_health_event_id IS NOT DISTINCT FROM
             CASE WHEN item->>'event_kind' = 'source_health' THEN (item->>'event_id')::uuid END
         AND link.event_time = (item->>'event_time')::timestamptz
        WHERE link.evidence_link_id IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'normalized evidence source mismatch';
    END IF;

    INSERT INTO sentinelflow.evidence_snapshots (
        evidence_snapshot_id, schema_version, incident_id, incident_version,
        source_ip, service_label, window_start, window_end, source_health_status,
        signal_count, expanded_event_count, snapshot_digest, created_at, expires_at
    ) VALUES (
        snapshot_id_value, 'evidence-snapshot-v1', incident_id_value,
        incident_version_value, source_ip_value, service_label_value,
        window_start_value, window_end_value, document->>'source_health_status',
        signal_count_value, event_count_value, digest_value, created_at_value,
        expires_at_value
    );
    INSERT INTO sentinelflow.evidence_snapshot_artifacts (
        evidence_snapshot_id, schema_version, source_health_digest,
        canonical_bytes, canonical_digest, created_at
    ) VALUES (
        snapshot_id_value, 'evidence-snapshot-v1', source_health_digest_value,
        p_canonical_bytes, digest_value, created_at_value
    );
    INSERT INTO sentinelflow.evidence_snapshot_signals (
        evidence_snapshot_id, ordinal, signal_id, evidence_id,
        evidence_digest, expanded_event_count
    )
    SELECT snapshot_id_value, (item->>'ordinal')::smallint,
        (item->>'signal_id')::uuid, item->>'signal_id',
        (item->>'evidence_digest')::sentinelflow.sha256_digest,
        (item->>'expanded_event_count')::integer
    FROM jsonb_array_elements(document->'signals') item;
    INSERT INTO sentinelflow.evidence_snapshot_events (
        evidence_snapshot_event_id, evidence_snapshot_id, signal_id, event_kind,
        gateway_event_id, auth_event_id, source_health_event_id, event_time
    )
    SELECT (item->>'event_row_id')::uuid, snapshot_id_value,
        (item->>'signal_id')::uuid, item->>'event_kind',
        CASE WHEN item->>'event_kind' = 'gateway' THEN (item->>'event_id')::uuid END,
        CASE WHEN item->>'event_kind' = 'auth' THEN (item->>'event_id')::uuid END,
        CASE WHEN item->>'event_kind' = 'source_health' THEN (item->>'event_id')::uuid END,
        (item->>'event_time')::timestamptz
    FROM jsonb_array_elements(document->'events') item;

    evidence_snapshot_id := snapshot_id_value;
    snapshot_digest := digest_value;
    inserted := true;
    RETURN NEXT;
END
$function$;

-- Preserve the pre-000014 implementations behind owner-only names.  The new
-- public names are fail-closed wrappers, so existing callers cannot bypass the
-- canonical-evidence prerequisite.
DO $rename_analysis_prepare$
BEGIN
    IF to_regprocedure('sentinelflow.prepare_analysis_attempt_legacy(uuid,uuid)') IS NULL THEN
        ALTER FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid)
            RENAME TO prepare_analysis_attempt_legacy;
    END IF;
END
$rename_analysis_prepare$;

CREATE OR REPLACE FUNCTION sentinelflow.prepare_analysis_attempt(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS TABLE(status text, snapshot jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    base_status text;
    base_snapshot jsonb;
    artifact_bytes bytea;
    artifact_digest sentinelflow.sha256_digest;
BEGIN
    SELECT result.status, result.snapshot INTO base_status, base_snapshot
    FROM sentinelflow.prepare_analysis_attempt_legacy(p_job_id, p_lease_token) result;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF base_status = 'prepared' THEN
        SELECT artifact.canonical_bytes, artifact.canonical_digest
        INTO artifact_bytes, artifact_digest
        FROM sentinelflow.evidence_snapshot_artifacts artifact
        JOIN sentinelflow.evidence_snapshots evidence USING (evidence_snapshot_id)
        WHERE artifact.evidence_snapshot_id = (base_snapshot->>'evidence_snapshot_id')::uuid
          AND artifact.canonical_digest = base_snapshot->>'evidence_snapshot_digest'
          AND evidence.snapshot_digest = artifact.canonical_digest;
        IF NOT FOUND OR artifact_digest <> sentinelflow.validation_sha256(artifact_bytes) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'canonical analysis evidence unavailable';
        END IF;
    END IF;
    status := base_status;
    snapshot := base_snapshot;
    RETURN NEXT;
END
$function$;

CREATE OR REPLACE FUNCTION sentinelflow.prepare_validation_attempt_exact(
    p_job_id uuid,
    p_lease_token uuid
)
RETURNS TABLE(status text, snapshot jsonb, evidence_canonical bytea)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    base_status text;
    base_snapshot jsonb;
    canonical_document jsonb;
    artifact_digest sentinelflow.sha256_digest;
BEGIN
    SELECT result.status, result.snapshot INTO base_status, base_snapshot
    FROM sentinelflow.prepare_validation_attempt(p_job_id, p_lease_token) result;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    evidence_canonical := NULL;
    IF base_status = 'prepared' THEN
        SELECT artifact.canonical_bytes, artifact.canonical_digest
        INTO evidence_canonical, artifact_digest
        FROM sentinelflow.evidence_snapshot_artifacts artifact
        JOIN sentinelflow.evidence_snapshots evidence USING (evidence_snapshot_id)
        WHERE artifact.evidence_snapshot_id = (base_snapshot->>'evidence_snapshot_id')::uuid
          AND artifact.canonical_digest = base_snapshot->>'evidence_snapshot_digest'
          AND evidence.snapshot_digest = artifact.canonical_digest;
        IF NOT FOUND OR artifact_digest <> sentinelflow.validation_sha256(evidence_canonical) OR
           octet_length(evidence_canonical) NOT BETWEEN 2 AND 67108864 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'canonical validation evidence unavailable';
        END IF;
        canonical_document := convert_from(evidence_canonical, 'UTF8')::jsonb;
        IF canonical_document->>'snapshot_id' <> base_snapshot->>'evidence_snapshot_id' OR
           canonical_document->>'incident_id' <> base_snapshot->>'incident_id' OR
           (canonical_document->>'incident_version')::integer <>
                (base_snapshot->>'incident_version')::integer OR
           canonical_document->>'source_ipv4' <> base_snapshot->'evidence'->>'source_ipv4' OR
           canonical_document->>'service_label' <> base_snapshot->'evidence'->>'service_label' OR
           canonical_document->'signal_ids' <> base_snapshot->'evidence'->'signal_ids' OR
           canonical_document->'event_ids' <> base_snapshot->'evidence'->'event_ids' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'canonical validation evidence mismatch';
        END IF;
        base_snapshot := jsonb_set(
            base_snapshot, '{evidence,source_health_digest}',
            canonical_document->'source_health_digest', false
        );
    END IF;
    status := base_status;
    snapshot := base_snapshot;
    RETURN NEXT;
END
$function$;

-- The original finalizer still performs the detailed normalized publication.
-- Its valid path predates the RETURNS TABLE state output and therefore has one
-- ambiguous unqualified state predicate.  Preserve the old function for
-- rollback, but create an owner-only copy with that predicate fully qualified.
-- The replacement is guarded so a source drift fails the migration instead of
-- silently applying an unreviewed rewrite.
DO $clone_normalized_finalizer$
DECLARE
    definition text;
    patched text;
    old_predicate constant text :=
        'WHERE policy_id = claim.policy_id AND version = 1 AND state = ''draft'';';
    new_predicate constant text :=
        'WHERE policy_id = claim.policy_id AND version = 1 AND sentinelflow.policy_proposals.state = ''draft'';';
    old_validation_predicate constant text :=
        'WHERE validation_snapshot_id = claim.validation_snapshot_id AND state = ''draft'';';
    new_validation_predicate constant text :=
        'WHERE validation_snapshot_id = claim.validation_snapshot_id AND sentinelflow.validation_snapshots.state = ''draft'';';
    old_validating_predicate constant text :=
        'WHERE policy_id = claim.policy_id AND version = 1 AND state = ''validating'';';
    new_validating_predicate constant text :=
        'WHERE policy_id = claim.policy_id AND version = 1 AND sentinelflow.policy_proposals.state = ''validating'';';
BEGIN
    SELECT pg_get_functiondef(
        'sentinelflow.finalize_validation_attempt(uuid,uuid,text,timestamptz,timestamptz,text,text,json)'::regprocedure
    ) INTO definition;
    IF position('sentinelflow.finalize_validation_attempt(' IN definition) = 0 OR
       position(old_predicate IN definition) = 0 OR
       position(old_validation_predicate IN definition) = 0 OR
       position(old_validating_predicate IN definition) = 0 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'validation finalizer source drift';
    END IF;
    patched := replace(
        definition,
        'sentinelflow.finalize_validation_attempt(',
        'sentinelflow.finalize_validation_attempt_normalized('
    );
    patched := replace(patched, old_predicate, new_predicate);
    patched := replace(patched, old_validation_predicate, new_validation_predicate);
    patched := replace(patched, old_validating_predicate, new_validating_predicate);
    EXECUTE patched;
END
$clone_normalized_finalizer$;

CREATE OR REPLACE FUNCTION sentinelflow.finalize_validation_attempt_exact(
    p_job_id uuid,
    p_lease_token uuid,
    p_finish_state text,
    p_retry_at timestamptz,
    p_client_now timestamptz,
    p_error_code text,
    p_error_digest text,
    p_mutation json,
    p_evidence_canonical bytea
)
RETURNS TABLE(job_id uuid, state text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
DECLARE
    result_job_id uuid;
    result_state text;
    mutation jsonb;
    claim sentinelflow.validation_attempt_claims%ROWTYPE;
    policy_row sentinelflow.policy_proposals%ROWTYPE;
    candidate_row sentinelflow.command_candidates%ROWTYPE;
    validation_row sentinelflow.validation_snapshots%ROWTYPE;
    evidence_row sentinelflow.evidence_snapshot_artifacts%ROWTYPE;
    policy_bytes_value bytea;
    validation_bytes_value bytea;
    generated_bytes_value bytea;
BEGIN
    SELECT result.job_id, result.state INTO result_job_id, result_state
    FROM sentinelflow.finalize_validation_attempt_normalized(
        p_job_id, p_lease_token, p_finish_state, p_retry_at, p_client_now,
        p_error_code, p_error_digest, p_mutation
    ) result;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF p_finish_state = 'completed' AND p_mutation IS NOT NULL AND
       p_mutation::text <> 'null' THEN
        mutation := p_mutation::jsonb;
    END IF;
    IF mutation->>'state' = 'valid' THEN
        IF p_evidence_canonical IS NULL OR
           octet_length(p_evidence_canonical) NOT BETWEEN 2 AND 67108864 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'exact evidence bytes unavailable';
        END IF;
        SELECT * INTO claim
        FROM sentinelflow.validation_attempt_claims row_value
        WHERE row_value.job_id = p_job_id
          AND row_value.validation_attempt_id = (mutation->>'validation_attempt_id')::uuid
          AND row_value.state = 'valid';
        SELECT * INTO policy_row
        FROM sentinelflow.policy_proposals row_value
        WHERE row_value.policy_id = claim.policy_id AND row_value.version = 1;
        SELECT * INTO candidate_row
        FROM sentinelflow.command_candidates row_value
        WHERE row_value.command_candidate_id = claim.command_candidate_id;
        SELECT * INTO validation_row
        FROM sentinelflow.validation_snapshots row_value
        WHERE row_value.validation_snapshot_id = claim.validation_snapshot_id;
        SELECT * INTO evidence_row
        FROM sentinelflow.evidence_snapshot_artifacts row_value
        WHERE row_value.evidence_snapshot_id = claim.evidence_snapshot_id;
        IF claim.validation_attempt_id IS NULL OR policy_row.policy_id IS NULL OR
           candidate_row.command_candidate_id IS NULL OR
           validation_row.validation_snapshot_id IS NULL OR
           evidence_row.evidence_snapshot_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'exact validation publication incomplete';
        END IF;

        BEGIN
            policy_bytes_value := decode(mutation->'policy'->>'canonical_hex', 'hex');
            validation_bytes_value := decode(mutation->'validation'->>'canonical_hex', 'hex');
            generated_bytes_value := convert_to(candidate_row.generated_command, 'UTF8');
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid exact validation bytes';
        END;
        IF p_evidence_canonical <> evidence_row.canonical_bytes OR
           sentinelflow.validation_sha256(p_evidence_canonical) <> claim.evidence_snapshot_digest OR
           sentinelflow.validation_sha256(policy_bytes_value) <> policy_row.policy_digest OR
           sentinelflow.validation_sha256(validation_bytes_value) <> validation_row.snapshot_digest OR
           sentinelflow.validation_sha256(generated_bytes_value) <> candidate_row.generated_artifact_digest OR
           sentinelflow.validation_sha256(candidate_row.canonical_artifact) <>
                candidate_row.canonical_artifact_digest OR
           policy_row.evidence_snapshot_digest <> evidence_row.canonical_digest OR
           validation_row.evidence_snapshot_digest <> evidence_row.canonical_digest OR
           validation_row.policy_digest <> policy_row.policy_digest OR
           validation_row.generated_candidate_digest <> candidate_row.generated_artifact_digest OR
           validation_row.canonical_artifact_digest <> candidate_row.canonical_artifact_digest OR
           validation_row.target_ipv4 <> policy_row.target_ipv4 OR
           validation_row.ttl_seconds <> policy_row.ttl_seconds THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'exact validation binding mismatch';
        END IF;

        INSERT INTO sentinelflow.hil_exact_artifacts (
            policy_id, policy_version, command_candidate_id, validation_snapshot_id,
            evidence_snapshot_id, target_ipv4, ttl_seconds,
            policy_bytes, policy_digest, evidence_bytes, evidence_digest,
            validation_bytes, validation_digest, generated_bytes, generated_digest,
            canonical_bytes, canonical_digest, validation_created_at,
            validation_valid_until
        ) VALUES (
            policy_row.policy_id, policy_row.version, candidate_row.command_candidate_id,
            validation_row.validation_snapshot_id, evidence_row.evidence_snapshot_id,
            policy_row.target_ipv4, policy_row.ttl_seconds,
            policy_bytes_value, policy_row.policy_digest,
            p_evidence_canonical, evidence_row.canonical_digest,
            validation_bytes_value, validation_row.snapshot_digest,
            generated_bytes_value, candidate_row.generated_artifact_digest,
            candidate_row.canonical_artifact, candidate_row.canonical_artifact_digest,
            validation_row.created_at, validation_row.valid_until
        );
    END IF;

    job_id := result_job_id;
    state := result_state;
    RETURN NEXT;
END
$function$;

-- API callers receive one bounded row and never obtain SELECT authority on the
-- canonical tables.
CREATE OR REPLACE FUNCTION sentinelflow.read_hil_exact_artifact(
    p_policy_id uuid,
    p_policy_version integer
)
RETURNS TABLE(
    policy_id uuid,
    policy_version integer,
    command_candidate_id uuid,
    validation_snapshot_id uuid,
    evidence_snapshot_id uuid,
    target_ipv4 text,
    ttl_seconds integer,
    policy_bytes bytea,
    policy_digest text,
    evidence_bytes bytea,
    evidence_digest text,
    validation_bytes bytea,
    validation_digest text,
    generated_bytes bytea,
    generated_digest text,
    canonical_bytes bytea,
    canonical_digest text,
    validation_created_at timestamptz,
    validation_valid_until timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, sentinelflow
AS $function$
    SELECT artifact.policy_id, artifact.policy_version,
        artifact.command_candidate_id, artifact.validation_snapshot_id,
        artifact.evidence_snapshot_id, host(artifact.target_ipv4),
        artifact.ttl_seconds, artifact.policy_bytes, artifact.policy_digest::text,
        artifact.evidence_bytes, artifact.evidence_digest::text,
        artifact.validation_bytes, artifact.validation_digest::text,
        artifact.generated_bytes, artifact.generated_digest::text,
        artifact.canonical_bytes, artifact.canonical_digest::text,
        artifact.validation_created_at, artifact.validation_valid_until
    FROM sentinelflow.hil_exact_artifacts artifact
    WHERE artifact.policy_id = p_policy_id
      AND artifact.policy_version = p_policy_version
      AND p_policy_version >= 1
    LIMIT 1;
$function$;

REVOKE ALL ON sentinelflow.evidence_snapshot_artifacts,
    sentinelflow.hil_exact_artifacts FROM PUBLIC;
REVOKE ALL ON sentinelflow.evidence_snapshot_artifacts,
    sentinelflow.hil_exact_artifacts FROM sentinelflow_api,
    sentinelflow_worker, sentinelflow_read, sentinelflow_dispatcher;
REVOKE INSERT ON sentinelflow.evidence_snapshots,
    sentinelflow.evidence_snapshot_signals,
    sentinelflow.evidence_snapshot_events FROM sentinelflow_worker;

REVOKE ALL ON FUNCTION sentinelflow.reject_exact_artifact_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.insert_exact_evidence_snapshot(json, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.insert_exact_evidence_snapshot(json, bytea)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt_legacy(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt_legacy(uuid, uuid)
    FROM sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_analysis_attempt(uuid, uuid)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_validation_attempt(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.prepare_validation_attempt(uuid, uuid)
    FROM sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.prepare_validation_attempt_exact(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.prepare_validation_attempt_exact(uuid, uuid)
    TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_validation_attempt(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json
) FROM sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_validation_attempt_normalized(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json
) FROM PUBLIC;
REVOKE ALL ON FUNCTION sentinelflow.finalize_validation_attempt_normalized(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json
) FROM sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.finalize_validation_attempt_exact(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.finalize_validation_attempt_exact(
    uuid, uuid, text, timestamptz, timestamptz, text, text, json, bytea
) TO sentinelflow_worker;
REVOKE ALL ON FUNCTION sentinelflow.read_hil_exact_artifact(uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sentinelflow.read_hil_exact_artifact(uuid, integer)
    TO sentinelflow_api;

INSERT INTO sentinelflow.schema_migrations (version, name)
VALUES (14, 'exact_hil_artifacts')
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name;

COMMIT;
