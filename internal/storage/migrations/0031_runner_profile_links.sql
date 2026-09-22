-- 0031_runner_profile_links.sql — durable runner-ID -> profile binding.
--
-- Runner profile selection must never be driven by a client-asserted
-- certificate serial in an authenticated bearer mode: the payload serial is
-- attacker-chosen, so honoring it as a binding key let a per-runner bearer
-- token inherit the profile (labels, capabilities, capacity, repository ACL)
-- of any pre-bound runner whose serial no runner row currently held. The
-- old ownership check scanned runner payloads, which is client-asserted
-- state and racy: two concurrent registrations both saw the serial
-- "unclaimed" and both inherited the privileged profile.
--
-- runner_profile_links makes the binding an explicit, admin-managed,
-- PRIMARY KEY bound fact: at most one profile per runner ID, enforced by the
-- database rather than by a payload scan. Per-runner bearer identities
-- resolve their profile through this table alone, while the mTLS path keeps
-- cert_profile_links, whose serial is derived from the VERIFIED TLS peer
-- certificate rather than the payload.
--
-- DEPLOY-SAFETY (same discipline as 0021-0030): the table is new and
-- referenced by no other relation, so CREATE TABLE + CREATE INDEX touch only
-- this relation and are safe to run while registrations continue.
-- runner_id is the PRIMARY KEY index, the profile_id index backs the
-- RunnerIDsForProfile lookup and binding re-pointing, and IF NOT EXISTS
-- keeps a replay harmless.

CREATE TABLE IF NOT EXISTS runner_profile_links (
    runner_id TEXT NOT NULL PRIMARY KEY,
    profile_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS runner_profile_links_profile_idx
    ON runner_profile_links (profile_id);
