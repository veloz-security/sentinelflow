-- sqlc's static analyzer cannot infer schema/domain creation from the guarded
-- PostgreSQL DO blocks used by the repeatable runtime migrations. This file is
-- analyzer-only; runtime deployments apply migrations/*.up.sql instead.
CREATE ROLE sentinelflow_migration;
CREATE SCHEMA sentinelflow;

CREATE DOMAIN sentinelflow.sha256_digest AS text;
CREATE DOMAIN sentinelflow.hmac_sha256_digest AS text;
CREATE DOMAIN sentinelflow.ascii_id AS text;
CREATE DOMAIN sentinelflow.event_label AS text;
CREATE DOMAIN sentinelflow.sender_epoch AS text;
CREATE DOMAIN sentinelflow.canonical_ipv4 AS inet;
CREATE DOMAIN sentinelflow.safe_integer AS bigint;

SET search_path = sentinelflow, pg_catalog;
