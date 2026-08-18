/**
 * D1 access for blinded v2 entries.
 *
 * Every statement is prepared with bound parameters, and every one of them is
 * keyed by `handle` — a value this Worker receives and never derives, because it
 * cannot: it has no CMD-Chat ID to derive it from. See
 * migrations/0002_blinded_entries.sql.
 *
 * # Row budget
 *
 * This file exists partly to keep the cost honest, so the counts are stated:
 *
 *   publish   1 row read  (the auth state) + 1 row written
 *   touch     1 row written  (a bare UPDATE; nothing is read, nothing re-sealed)
 *   lookup    1 row read
 *   revoke    1 row written
 *
 * v1 spent 2+N writes on a publish and 1+N reads on a lookup, where N was the
 * candidate count, because addresses lived in their own table. Sealing them into
 * one blob removed the child table and with it the per-address rows.
 */

import { ENTRY_TTL_SECONDS, GC_BATCH_SIZE, TOMBSTONE_TTL_SECONDS } from './config.js';

/**
 * What a revoked entry's blob is replaced with.
 *
 * It has to satisfy the same length and base64 CHECK constraints as a real
 * sealed entry, because the tombstone stays in the same column. A short marker
 * violated them and made revocation fail with a 500 — the constraint was doing
 * its job and caught the mistake.
 *
 * It is not decryptable by anyone: it is a fixed public constant, so a client
 * that somehow read it would fail the AEAD check and treat the entry as absent.
 */
const REVOKED_PLACEHOLDER = 'cmV2b2tlZA'.padEnd(48, 'A');

/**
 * Reads only what is needed to authorise a mutating request.
 *
 * `write_key` is the important one: it is the binding that makes a handle
 * owned. A publish for a handle that already has a different write key is
 * refused, which is what stops one client overwriting another's entry.
 */
export async function getEntryAuthState(db, handle) {
	return db
		.prepare('SELECT handle, write_key, created_at, last_issued_at, revoked_at FROM entries WHERE handle = ?1')
		.bind(handle)
		.first();
}

/**
 * Creates or refreshes an entry.
 *
 * One statement, one row. There is no child table to clear and no per-address
 * insert, so this cannot leave a peer half-published and does not need a batch.
 */
export async function upsertEntry(db, { handle, writeKey, sealed, now, issuedAt }) {
	const expiresAt = now + ENTRY_TTL_SECONDS;
	await db
		.prepare(
			`INSERT INTO entries
			   (handle, write_key, sealed, created_at, last_seen, expires_at, last_issued_at, revoked_at)
			 VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, NULL)
			 ON CONFLICT(handle) DO UPDATE SET
			   sealed         = excluded.sealed,
			   last_seen      = excluded.last_seen,
			   expires_at     = excluded.expires_at,
			   last_issued_at = excluded.last_issued_at,
			   revoked_at     = NULL`,
		)
		.bind(handle, writeKey, sealed, now, expiresAt, issuedAt)
		.run();
	return { expiresAt, ttl: ENTRY_TTL_SECONDS };
}

/**
 * Extends an entry's lifetime and nothing else.
 *
 * The steady-state call. The sealed blob is not rewritten and the row is not
 * read first: the WHERE clause carries the whole authorisation decision, so a
 * heartbeat costs exactly one row.
 *
 * `write_key` is matched in the WHERE clause rather than checked beforehand,
 * which is both cheaper and safer — there is no window between the check and the
 * update.
 */
export async function touchEntry(db, { handle, writeKey, now, issuedAt }) {
	const expiresAt = now + ENTRY_TTL_SECONDS;
	const result = await db
		.prepare(
			`UPDATE entries
			    SET last_seen = ?3, expires_at = ?4, last_issued_at = ?5
			  WHERE handle = ?1
			    AND write_key = ?2
			    AND revoked_at IS NULL
			    AND last_issued_at < ?5`,
		)
		.bind(handle, writeKey, now, expiresAt, issuedAt)
		.run();
	return { changed: result.meta.changes > 0, expiresAt, ttl: ENTRY_TTL_SECONDS };
}

/**
 * Soft-deletes an entry.
 *
 * The blob is overwritten with a placeholder rather than the row being dropped:
 * the addresses stop being readable immediately, while the handle keeps its
 * write_key binding so a revoked entry cannot be claimed by somebody else, and
 * an older signed publish cannot resurrect it.
 */
export async function revokeEntry(db, { handle, writeKey, now, issuedAt }) {
	const result = await db
		.prepare(
			`UPDATE entries
			    SET revoked_at = ?3, expires_at = ?3, last_seen = ?3, last_issued_at = ?4, sealed = ?5
			  WHERE handle = ?1 AND write_key = ?2`,
		)
		.bind(handle, writeKey, now, issuedAt, REVOKED_PLACEHOLDER)
		.run();
	return { changed: result.meta.changes > 0 };
}

/**
 * Public directory read.
 *
 * Explicit column list, never SELECT *, so a future column cannot accidentally
 * become public. `write_key` is deliberately NOT returned: a reader has no use
 * for it, and withholding it means an observer cannot correlate two entries by
 * their writer.
 */
export async function lookupEntry(db, handle, now) {
	const row = await db
		.prepare('SELECT sealed, last_seen, expires_at, revoked_at FROM entries WHERE handle = ?1')
		.bind(handle)
		.first();

	if (!row) return null;
	const online = row.revoked_at === null && row.expires_at > now;
	return { row, online };
}

/** Deletes entries long past useful life. Called from cron and opportunistically. */
export async function garbageCollectEntries(db, now) {
	const cutoff = now - TOMBSTONE_TTL_SECONDS;
	const stale = await db
		.prepare('SELECT handle FROM entries WHERE expires_at < ?1 LIMIT ?2')
		.bind(cutoff, GC_BATCH_SIZE)
		.all();

	const handles = (stale.results ?? []).map((row) => row.handle);
	if (handles.length > 0) {
		await db.batch(handles.map((handle) => db.prepare('DELETE FROM entries WHERE handle = ?1').bind(handle)));
	}
	return { removed: handles.length };
}
