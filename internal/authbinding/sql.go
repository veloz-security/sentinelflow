package authbinding

const databaseClockSQL = `
SELECT clock_timestamp()`

const lockPendingSQL = `
SELECT
    auth_event.event_id,
    auth_event.gateway_request_id,
    auth_event.trace_id,
    auth_event.occurred_at,
    auth_event.source_ip::text,
    auth_event.service_label,
    auth_event.route_label,
    auth_event.received_at,
    auth_event.trust_state,
    auth_event.trust_reason,
    auth_event.binding_deadline
FROM sentinelflow.auth_events AS auth_event
WHERE auth_event.binding_state = 'pending'
ORDER BY auth_event.binding_deadline, auth_event.event_id
LIMIT $1
FOR UPDATE OF auth_event SKIP LOCKED`

const gatewayByRequestSQL = `
SELECT
    gateway_event.event_id,
    gateway_event.request_id,
    gateway_event.trace_id,
    gateway_event.source_ip::text,
    gateway_event.service_label,
    gateway_event.route_label,
    gateway_event.trust_state,
    gateway_event.trust_reason
FROM sentinelflow.gateway_events AS gateway_event
WHERE gateway_event.request_id = $1`

// trace_id is not a database uniqueness constraint. Returning a candidate only
// when exactly one trusted row matches prevents an arbitrary LIMIT 1 choice
// from manufacturing request_mismatch.
const gatewayByTraceSQL = `
SELECT
    gateway_event.event_id,
    gateway_event.request_id,
    gateway_event.trace_id,
    gateway_event.source_ip::text,
    gateway_event.service_label,
    gateway_event.route_label,
    gateway_event.trust_state,
    gateway_event.trust_reason
FROM sentinelflow.gateway_events AS gateway_event
WHERE gateway_event.trace_id = $1
  AND gateway_event.trust_state = 'trusted'
  AND gateway_event.trust_reason = 'none'
  AND NOT EXISTS (
      SELECT 1
      FROM sentinelflow.gateway_events AS duplicate
      WHERE duplicate.trace_id = gateway_event.trace_id
        AND duplicate.event_id <> gateway_event.event_id
        AND duplicate.trust_state = 'trusted'
        AND duplicate.trust_reason = 'none'
  )`

const verifyBindingSQL = `
UPDATE sentinelflow.auth_events AS auth_event
SET binding_state = 'verified',
    binding_reason = 'verified',
    bound_gateway_event_id = $2
WHERE auth_event.event_id = $1
  AND auth_event.binding_state = 'pending'
  AND auth_event.binding_deadline >= clock_timestamp()
  AND auth_event.trust_state = 'trusted'
  AND auth_event.trust_reason = 'none'
  AND auth_event.service_label = 'demo-app'
  AND EXISTS (
      SELECT 1
      FROM sentinelflow.gateway_events AS gateway_event
      WHERE gateway_event.event_id = $2
        AND gateway_event.request_id = auth_event.gateway_request_id
        AND gateway_event.trace_id = auth_event.trace_id
        AND gateway_event.source_ip = auth_event.source_ip
        AND gateway_event.service_label = 'demo-app'
        AND gateway_event.service_label = auth_event.service_label
        AND gateway_event.route_label = auth_event.route_label
        AND gateway_event.trust_state = 'trusted'
        AND gateway_event.trust_reason = 'none'
  )`

const markUntrustedSQL = `
UPDATE sentinelflow.auth_events AS auth_event
SET binding_state = 'untrusted',
    binding_reason = $2,
    bound_gateway_event_id = NULL
WHERE auth_event.event_id = $1
  AND auth_event.binding_state = 'pending'
  AND auth_event.binding_deadline >= clock_timestamp()
  AND $2 IN (
      'request_mismatch', 'trace_mismatch', 'source_mismatch',
      'service_mismatch', 'route_mismatch'
  )`

const expireBindingSQL = `
UPDATE sentinelflow.auth_events AS auth_event
SET binding_state = 'untrusted',
    binding_reason = 'expired',
    bound_gateway_event_id = NULL
WHERE auth_event.event_id = $1
  AND auth_event.binding_state = 'pending'
  AND auth_event.binding_deadline < clock_timestamp()`
