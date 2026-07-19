# Incident and audit export contract

`export_bundle_v1.schema.json` is the checked structural contract for the
bounded v0.1 operational export. The Go verifier additionally enforces strict
UTC time encoding, incident ordering, strictly increasing original audit
sequence values, record digests, the incident-set digest, the audit chain, the
export ID, and the manifest digest.

The export deliberately omits raw events, paths, query strings, bodies,
cookies, authorization values, account hashes, free-text HIL reasons, model
prose, generated commands, and key material. Source IPv4 values, actor IDs, and
trace IDs are replaced with domain-separated `HMAC-SHA-256` pseudonyms using a
private operator key that is never written into the bundle. Incident, policy,
object, and enforcement IDs plus existing evidence digests remain available
for audit traceability.

The chained digests make accidental or unreviewed record mutation, deletion,
insertion, and reordering detectable. They are not a signature or an external
timestamp. Production-grade signed archival and external audit anchoring remain
post-v0.1 work.

Create mode begins a read-only repeatable-read transaction and explicitly
transitions a bounded `NOINHERIT` deployment login to the `sentinelflow_read`
`NOLOGIN` capability role. The login must have exactly that one direct role
membership with `ADMIN FALSE`, `INHERIT FALSE`, and `SET TRUE`; it may own or
hold no direct SentinelFlow table, sequence/type, function, or schema authority.
The capability must have no outbound membership, mutation or function
authority, or schema/database create authority. The isolated demo may use the
direct `sentinelflow_read` login, but the checked production role model does not
require weakening the capability role to `LOGIN`.
