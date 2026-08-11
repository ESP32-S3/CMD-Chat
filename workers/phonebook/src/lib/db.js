/**
 * All D1 access lives here.
 *
 * Every statement is a prepared statement with bound parameters. No SQL is ever
 * built by concatenating request data, so there is no injection surface even
 * before validation.
 */

import { GC_BATCH_SIZE, REGISTRATION_TTL_SECONDS, TOMBSTONE_TTL_SECONDS } from './config.js';

/** Reads only the fields needed to authorise a mutating request. */
export async function getAuthState(db, id) {
	return db.prepare('SELECT cmd_chat_id, created_at, last_issued_at, revoked_at FROM registrations WHERE cmd_chat_id = ?1').bind(id).first();
}

/**
 * Creates or refreshes a registration and replaces its candidate set.
 *
 * Runs as one D1 batch (a single transaction) so a peer is never visible with a
 * half-written candidate list.
 */
export async function upsertRegistration(db, entry) {
	const { id, publicKey, sessionFingerprint, protocolVersion, clientVersion, candidates, now, issuedAt } = entry;
	const expiresAt = now + REGISTRATION_TTL_SECONDS;

	const statements = [
		db
			.prepare(
				`INSERT INTO registrations
				   (cmd_chat_id, public_key, session_fingerprint, protocol_version, client_version,
				    created_at, last_seen, expires_at, last_issued_at, revoked_at)
				 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8, NULL)
				 ON CONFLICT(cmd_chat_id) DO UPDATE SET
				   public_key          = excluded.public_key,
				   session_fingerprint = excluded.session_fingerprint,
				   protocol_version    = excluded.protocol_version,
				   client_version      = excluded.client_version,
				   last_seen           = excluded.last_seen,
				   expires_at          = excluded.expires_at,
				   last_issued_at      = excluded.last_issued_at,
				   revoked_at          = NULL`,
			)
			.bind(id, publicKey, sessionFingerprint, protocolVersion, clientVersion, now, expiresAt, issuedAt),
		// Candidates are replaced wholesale, never merged: a peer that moves
		// network must not leave its old addresses discoverable.
		db.prepare('DELETE FROM candidates WHERE cmd_chat_id = ?1').bind(id),
	];

	for (const c of candidates) {
		statements.push(
			db
				.prepare('INSERT INTO candidates (cmd_chat_id, kind, transport, address, port, priority, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)')
				.bind(id, c.kind, c.transport, c.address, c.port, c.priority, now),
		);
	}

	await db.batch(statements);
	return { expiresAt, ttl: REGISTRATION_TTL_SECONDS };
}

/** Refreshes liveness only. Never touches identity or candidates. */
export async function touchRegistration(db, id, now, issuedAt) {
	const expiresAt = now + REGISTRATION_TTL_SECONDS;
	const result = await db
		.prepare('UPDATE registrations SET last_seen = ?2, expires_at = ?3, last_issued_at = ?4 WHERE cmd_chat_id = ?1 AND revoked_at IS NULL')
		.bind(id, now, expiresAt, issuedAt)
		.run();
	return { changed: result.meta.changes > 0, expiresAt, ttl: REGISTRATION_TTL_SECONDS };
}

/**
 * Soft-deletes a registration: the peer immediately stops being discoverable
 * and every stored address is destroyed, but the row survives briefly as a
 * tombstone so an older signed `register` cannot resurrect it.
 */
export async function revokeRegistration(db, id, now, issuedAt) {
	await db.batch([
		db
			.prepare('UPDATE registrations SET revoked_at = ?2, expires_at = ?2, last_seen = ?2, last_issued_at = ?3 WHERE cmd_chat_id = ?1')
			.bind(id, now, issuedAt),
		db.prepare('DELETE FROM candidates WHERE cmd_chat_id = ?1').bind(id),
	]);
}

/**
 * Public phonebook read.
 *
 * Selects an explicit column list — never SELECT * — so a future column cannot
 * accidentally become public. Returns null for unknown IDs and a row with
 * `online: false` semantics for stale/revoked ones, which the caller turns into
 * an "offline" answer.
 */
export async function lookupRegistration(db, id, now) {
	const registration = await db
		.prepare(
			`SELECT cmd_chat_id, public_key, session_fingerprint, protocol_version, client_version,
			        last_seen, expires_at, revoked_at
			 FROM registrations WHERE cmd_chat_id = ?1`,
		)
		.bind(id)
		.first();

	if (!registration) return null;

	const online = registration.revoked_at === null && registration.expires_at > now;
	if (!online) return { registration, online: false, candidates: [] };

	const { results } = await db
		.prepare('SELECT kind, transport, address, port, priority FROM candidates WHERE cmd_chat_id = ?1 ORDER BY priority DESC, id ASC')
		.bind(id)
		.all();

	return { registration, online: true, candidates: results ?? [] };
}

/**
 * Deletes rows that are long past useful life.
 *
 * Called from the cron trigger, and opportunistically (best-effort, via
 * waitUntil) from write paths so a Worker with no cron still self-cleans.
 */
export async function garbageCollect(db, now) {
	const cutoff = now - TOMBSTONE_TTL_SECONDS;
	const stale = await db
		.prepare('SELECT cmd_chat_id FROM registrations WHERE expires_at < ?1 LIMIT ?2')
		.bind(cutoff, GC_BATCH_SIZE)
		.all();

	const ids = (stale.results ?? []).map((row) => row.cmd_chat_id);
	if (ids.length > 0) {
		const statements = [];
		for (const id of ids) {
			statements.push(db.prepare('DELETE FROM candidates WHERE cmd_chat_id = ?1').bind(id));
			statements.push(db.prepare('DELETE FROM registrations WHERE cmd_chat_id = ?1').bind(id));
		}
		await db.batch(statements);
	}

	// Rate-limit windows are worthless once the window has passed.
	await db.prepare('DELETE FROM rate_limits WHERE window_start < ?1').bind(now - 3600).run();

	return { removed: ids.length };
}
