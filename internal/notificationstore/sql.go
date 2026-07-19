package notificationstore

const readWindowSQL = `SELECT replay_floor, watermark
FROM sentinelflow.read_sse_notification_window()`

const readPageSQL = `SELECT replay_floor, watermark, replay_gap, future_cursor,
       cursor, event_type, resource_type, resource_id, resource_version,
       state, summary_code, incident_id, trace_id, occurred_at
FROM sentinelflow.read_sse_notification_page($1, $2)`

const registerLeaseSQL = `SELECT sentinelflow.register_sse_client_lease_000024($1, $2)`
const touchLeaseSQL = `SELECT sentinelflow.touch_sse_client_lease_000024($1, $2)`
const unregisterLeaseSQL = `SELECT sentinelflow.unregister_sse_client_lease_000024($1, $2)`
