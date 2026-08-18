-- CMD-Chat phonebook schema, v2: blinded entries.
--
-- Migration number: 0002 	 2026-08-18
--
-- ---------------------------------------------------------------------------
-- WHY THIS EXISTS
--
-- The v1 schema keyed `registrations` by CMD-Chat ID and hung `candidates` off
-- it by foreign key. One JOIN produced the thing a rendezvous service should
-- never accumulate:
--
--     SELECT cmd_chat_id, address FROM registrations JOIN candidates USING (cmd_chat_id);
--
-- a live map of identity to location for every user, readable by whoever holds
-- the database. The Worker made it worse by appending the public IP it observed
-- and persisting that too, so the map filled in even for peers that published no
-- addresses of their own -- and nothing ever read that column back.
--
-- ---------------------------------------------------------------------------
-- WHAT THIS TABLE HOLDS INSTEAD
--
-- Nothing that identifies a person, and no address in readable form:
--
--   handle     HKDF(ID) truncated to 128 bits. The client derives it; this
--              Worker only ever receives the result. There is no column
--              anywhere in this schema containing a CMD-Chat ID.
--
--   write_key  An Ed25519 public key derived one-way from the identity's
--              PRIVATE seed. It authorises writes and is unlinkable to the
--              identity public key, so storing it reveals nothing about who the
--              writer is.
--
--   sealed     XChaCha20-Poly1305 over the candidate list, the session
--              fingerprint and the protocol version, keyed by HKDF(ID). This
--              Worker cannot open it. Neither can anyone with the database.
--
-- A dump of this table is a list of opaque handles and opaque blobs.
--
-- ---------------------------------------------------------------------------
-- WHAT IT DOES NOT HIDE, STATED PLAINLY
--
--   * TARGETED CONFIRMATION. The derivation is deterministic, so somebody who
--     already has a specific ID can compute its handle and entry key, and both
--     check whether it is registered and read its addresses. Preventing that
--     needs private information retrieval, which is out of all proportion to
--     this service.
--
--   * REQUEST-TIME METADATA. Cloudflare's edge sees the source IP of every call
--     by construction. What changed is that none of it is written down here.
--
-- ---------------------------------------------------------------------------
-- THE DELIBERATE TRADE
--
-- v1 authorised a write by checking that the supplied public key hashed to the
-- ID being modified, so only the identity key could touch a row. A directory
-- that does not know the ID cannot make that check. Here the FIRST writer of a
-- handle binds its write key to it, and only that key may update it afterwards.
--
-- So somebody who already knows an ID can claim its handle first and stop the
-- owner publishing. They cannot impersonate the owner -- CMDC2 authenticates the
-- peer's real identity key end to end -- and they cannot read anything. LAN
-- discovery and the relay are unaffected.
--
-- ---------------------------------------------------------------------------
-- COST
--
-- Collapsing the candidate rows into one blob is also why this is cheaper:
-- publishing writes ONE row instead of 2+N, and a lookup reads ONE row instead
-- of 1+N.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS entries (
	-- 26 RFC4648 base32 characters: HKDF(ID) truncated to 128 bits.
	handle          TEXT    PRIMARY KEY NOT NULL,

	-- Base64 (std, padded) Ed25519 public key, 32 bytes -> 44 chars.
	-- Derived from the identity's private seed; NOT the identity public key.
	write_key       TEXT    NOT NULL,

	-- Base64 of nonce(24) || XChaCha20-Poly1305 ciphertext. Opaque here.
	sealed          TEXT    NOT NULL,

	-- Unix seconds.
	created_at      INTEGER NOT NULL,
	last_seen       INTEGER NOT NULL,

	-- last_seen + TTL. Rows past this are offline and eligible for GC.
	expires_at      INTEGER NOT NULL,

	-- Replay defence: the issued_at (unix ms) of the newest accepted signed
	-- request for this handle. Every mutating request must be strictly newer.
	last_issued_at  INTEGER NOT NULL DEFAULT 0,

	-- Soft delete. Kept briefly as a tombstone so a revoked entry cannot be
	-- resurrected by replaying an older signed publish, and so the handle's
	-- write_key binding survives the revocation.
	revoked_at      INTEGER,

	CHECK (length(handle) = 26),
	CHECK (handle GLOB '[A-Z2-7]*'),
	CHECK (length(write_key) = 44),
	CHECK (length(sealed) BETWEEN 48 AND 2800),
	CHECK (expires_at >= last_seen)
);

CREATE INDEX IF NOT EXISTS idx_entries_expires_at
	ON entries (expires_at);
