// Package worker implements the unprivileged, durable outbox runner used by
// SentinelFlow control-plane jobs.
//
// The runner deliberately has no dispatcher or executor authority. PostgreSQL
// owns lease recovery and dead-letter atomicity; domain handlers own business
// idempotency because a handler can run more than once after a crash or lease
// loss.
package worker
