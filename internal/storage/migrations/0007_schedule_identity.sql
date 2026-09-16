-- 0007_schedule_identity.sql — durable schedule identity fields and the
-- downstream stable-child launch key.
--
-- Schedules gain the canonical identity columns (repo_id, repo_url, forge,
-- trusted) so automatic firing can use the stored immutable identity
-- instead of the request context, and trusted schedules can be gated by the
-- repo-scoped trusted_run grant at creation/update/manual-trigger time.
-- Repository keeps the full name, repo_id carries host+full name and
-- repo_url is the clone URL.
--
-- downstream_links gains stable_child_id: the derived launch idempotency
-- key (sha256(parent_job, target_repo, target_ref) hex). Every launch of a
-- link reuses the SAME child run ID, so a crash between the reservation and
-- the child launch can never produce a duplicate child.

ALTER TABLE schedules ADD COLUMN repo_id TEXT NOT NULL DEFAULT ''

ALTER TABLE schedules ADD COLUMN repo_url TEXT NOT NULL DEFAULT ''

ALTER TABLE schedules ADD COLUMN forge TEXT NOT NULL DEFAULT ''

ALTER TABLE schedules ADD COLUMN trusted BOOLEAN NOT NULL DEFAULT FALSE

ALTER TABLE downstream_links ADD COLUMN stable_child_id TEXT NOT NULL DEFAULT ''

CREATE INDEX schedules_repo_id_idx ON schedules (repo_id)

CREATE INDEX downstream_links_stable_child_idx ON downstream_links (stable_child_id)
