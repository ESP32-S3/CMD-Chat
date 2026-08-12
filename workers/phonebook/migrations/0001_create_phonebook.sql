-- CMD-Chat phonebook schema, v1.
--
-- This database is a RENDEZVOUS DIRECTORY ONLY. It stores just enough for two
-- CMD-Chat clients that are not on the same LAN to find each other and attempt
-- a direct connection. It never stores chat messages, private keys, passwords,
-- or long-lived personal information.
--
-- Identity model (derived from the real CMD-Chat client, see identity.json):
--   * every client holds an Ed25519 keypair
--   * cmd_chat_id = 'cc-' || base32(sha256(ed25519_public_key)[0..9])
-- The ID is therefore a self-authenticating commitment to the public key, so
-- the Worker can prove ownership without inventing a new auth mechanism.

-- Migration number: 0001 	 2026-08-11

-- ---------------------------------------------------------------------------
-- registrations: the stable identity half of the phonebook.
-- Deliberately contains NO network addresses. Anything that could locate a
-- person lives in `candidates`, which is wiped on every re-register and on
-- expiry.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS registrations (
	-- 'cc-' + 16 RFC4648 base32 chars.
	cmd_chat_id         TEXT    PRIMARY KEY NOT NULL,

	-- Base64 (std, padded) Ed25519 public key, 32 bytes -> 44 chars.
	-- Public by definition; the ID is a hash of exactly these bytes.
	public_key          TEXT    NOT NULL,

	-- Per-session transport fingerprint the client advertises (hex sha256).
	-- Rotates every run, so it is presence data, not identity.
	session_fingerprint TEXT,

	-- Phonebook wire-protocol version the client speaks.
	protocol_version    INTEGER NOT NULL DEFAULT 1,

	-- Short, charset-restricted build string (e.g. "0.4.1"). Never free text.
	client_version      TEXT,

	-- Unix seconds.
	created_at          INTEGER NOT NULL,
	last_seen           INTEGER NOT NULL,

	-- last_seen + TTL. Rows past this are offline and eligible for GC.
	expires_at          INTEGER NOT NULL,

	-- Replay defence: the issued_at (unix ms) of the newest accepted signed
	-- request for this ID. Every mutating request must be strictly newer.
	last_issued_at      INTEGER NOT NULL DEFAULT 0,

	-- Soft delete. Kept briefly as a tombstone so a deleted registration
	-- cannot be resurrected by replaying an older signed register payload.
	revoked_at          INTEGER,

	CHECK (length(cmd_chat_id) = 19),
	CHECK (cmd_chat_id GLOB 'cc-[A-Z2-7]*'),
	CHECK (length(public_key) = 44),
	CHECK (protocol_version > 0),
	CHECK (expires_at >= last_seen)
);

CREATE INDEX IF NOT EXISTS idx_registrations_expires_at
	ON registrations (expires_at);

-- ---------------------------------------------------------------------------
-- candidates: the ephemeral connectivity half.
--
-- These are ICE-style NAT-traversal candidates. They ARE network addresses,
-- which is why they are (a) in a separate table from identity, (b) replaced
-- wholesale on every register, and (c) cascade-deleted when the registration
-- is revoked or garbage collected. An address here is never a primary key and
-- never identifies a user.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS candidates (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,

	cmd_chat_id  TEXT    NOT NULL
		REFERENCES registrations (cmd_chat_id) ON DELETE CASCADE,

	-- 'host'                  : address on the peer's own interface (LAN)
	-- 'server_reflexive'      : peer's public address as seen by a STUN server
	-- 'server_reflexive_http' : public IP as observed by this Worker (no port)
	-- 'relay'                 : reserved; no relay exists in this architecture
	kind         TEXT    NOT NULL,

	transport    TEXT    NOT NULL,
	address      TEXT    NOT NULL,

	-- NULL for 'server_reflexive_http', where only the IP is meaningful.
	port         INTEGER,

	-- Higher is preferred. Client-supplied, clamped by the Worker.
	priority     INTEGER NOT NULL DEFAULT 0,

	created_at   INTEGER NOT NULL,

	CHECK (kind IN ('host', 'server_reflexive', 'server_reflexive_http', 'relay')),
	CHECK (transport IN ('tcp', 'udp')),
	CHECK (length(address) BETWEEN 3 AND 45),
	CHECK (port IS NULL OR (port BETWEEN 1 AND 65535)),
	CHECK (priority BETWEEN 0 AND 65535)
);

CREATE INDEX IF NOT EXISTS idx_candidates_cmd_chat_id
	ON candidates (cmd_chat_id);

-- ---------------------------------------------------------------------------
-- rate_limits: coarse fixed-window abuse counters.
--
-- Buckets are keyed by operation plus either a CMD-Chat ID or a SALTED HASH of
-- the caller IP. The raw IP is never written here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rate_limits (
	bucket       TEXT    PRIMARY KEY NOT NULL,
	window_start INTEGER NOT NULL,
	count        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start
	ON rate_limits (window_start);
