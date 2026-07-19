package adminstore

const databaseClockSQL = `SELECT clock_timestamp()`

const sessionColumns = `session_id::text, actor_id::text, token_digest::text,
    csrf_digest::text, authenticated_at, created_at, last_seen_at, expires_at,
    revoked_at, rotation_parent_id::text`

const loadSessionSQL = `
SELECT ` + sessionColumns + `
FROM sentinelflow.admin_sessions
WHERE session_id = $1::uuid
LIMIT 1
FOR SHARE`

// loadRevokedDecisionReplayParentSQL locks one revoked parent and its unique
// rotation child. The caller samples PostgreSQL's clock only after both locks
// succeed and then rechecks every time and rotation relation in Go.
const loadRevokedDecisionReplayParentSQL = `
SELECT parent.session_id::text, parent.actor_id::text, parent.token_digest::text,
    parent.csrf_digest::text, parent.authenticated_at, parent.created_at,
    parent.last_seen_at, parent.expires_at, parent.revoked_at,
    parent.rotation_parent_id::text,
    child.session_id::text, child.actor_id::text, child.token_digest::text,
    child.csrf_digest::text, child.authenticated_at, child.created_at,
    child.last_seen_at, child.expires_at, child.revoked_at,
    child.rotation_parent_id::text
FROM sentinelflow.admin_sessions AS parent
JOIN sentinelflow.admin_sessions AS child
  ON child.rotation_parent_id = parent.session_id
WHERE parent.session_id = $1::uuid
  AND parent.revoked_at IS NOT NULL
  AND child.actor_id = parent.actor_id
  AND child.authenticated_at = parent.authenticated_at
  AND child.revoked_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM sentinelflow.admin_sessions AS sibling
      WHERE sibling.rotation_parent_id = parent.session_id
        AND sibling.session_id <> child.session_id
  )
LIMIT 1
FOR SHARE OF parent, child`

const lockSessionSQL = `
SELECT ` + sessionColumns + `
FROM sentinelflow.admin_sessions
WHERE session_id = $1::uuid
LIMIT 1
FOR UPDATE`

const insertSessionSQL = `
INSERT INTO sentinelflow.admin_sessions (
    session_id, actor_id, token_digest, csrf_digest, authenticated_at,
    created_at, last_seen_at, expires_at, revoked_at, rotation_parent_id
) VALUES (
    $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10::uuid
)
RETURNING ` + sessionColumns

const touchSessionSQL = `
UPDATE sentinelflow.admin_sessions
SET last_seen_at = $11
WHERE session_id = $1::uuid
  AND actor_id = $2
  AND token_digest = $3
  AND csrf_digest = $4
  AND authenticated_at = $5
  AND created_at = $6
  AND last_seen_at = $7
  AND expires_at = $8
  AND revoked_at IS NOT DISTINCT FROM $9::timestamptz
  AND rotation_parent_id IS NOT DISTINCT FROM $10::uuid
  AND revoked_at IS NULL
  AND expires_at > $11
  AND last_seen_at + interval '30 minutes' > $11
RETURNING ` + sessionColumns

const revokeSessionSQL = `
UPDATE sentinelflow.admin_sessions
SET revoked_at = $11
WHERE session_id = $1::uuid
  AND actor_id = $2
  AND token_digest = $3
  AND csrf_digest = $4
  AND authenticated_at = $5
  AND created_at = $6
  AND last_seen_at = $7
  AND expires_at = $8
  AND revoked_at IS NOT DISTINCT FROM $9::timestamptz
  AND rotation_parent_id IS NOT DISTINCT FROM $10::uuid
  AND revoked_at IS NULL
  AND expires_at > $11
  AND last_seen_at + interval '30 minutes' > $11
RETURNING ` + sessionColumns

const deleteExpiredSQL = `
WITH victims AS (
    SELECT candidate.session_id
    FROM sentinelflow.admin_sessions AS candidate
    WHERE candidate.expires_at <= clock_timestamp()
      AND NOT EXISTS (
          SELECT 1 FROM sentinelflow.admin_sessions AS child
          WHERE child.rotation_parent_id = candidate.session_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM sentinelflow.decision_challenges AS challenge
          WHERE challenge.session_id = candidate.session_id
      )
    ORDER BY candidate.expires_at, candidate.session_id
    LIMIT $1
    FOR UPDATE OF candidate SKIP LOCKED
), deleted AS (
    DELETE FROM sentinelflow.admin_sessions AS session
    USING victims
    WHERE session.session_id = victims.session_id
    RETURNING session.session_id
)
SELECT count(*)::integer FROM deleted`
