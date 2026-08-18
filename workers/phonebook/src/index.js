/**
 * CMD-Chat phonebook Worker.
 *
 * WHAT THIS IS
 *   A public rendezvous directory. Peers that are not on the same LAN publish
 *   "here is my ID, my public key, and the addresses you can try reaching me
 *   on", and other peers look that up. That is the whole job.
 *
 * WHAT THIS IS NOT
 *   A chat server. No message ever transits this Worker or D1. After lookup the
 *   two clients talk directly to each other; the phonebook is not in the data
 *   path and holds no session state.
 *
 *   discovery (here)  ->  NAT traversal (clients)  ->  direct P2P (clients)
 *
 *   There is no relay fallback in this architecture. If NAT traversal fails,
 *   the connection fails; the phonebook deliberately does not paper over that.
 */

import { ENTRY_TTL_SECONDS, MAX_SEALED_CHARS, PROTOCOL_VERSION, REGISTRATION_TTL_SECONDS } from './lib/config.js';
import { authenticate, authenticateV2, assertHandleOwner, assertNotReplay } from './lib/auth.js';
import { garbageCollect, getAuthState, lookupRegistration, revokeRegistration, touchRegistration, upsertRegistration } from './lib/db.js';
import { garbageCollectEntries, getEntryAuthState, lookupEntry, revokeEntry, touchEntry, upsertEntry } from './lib/entries.js';
import { RequestError, fail, ok, preflight, readJsonBody } from './lib/http.js';
import { enforceRateLimit, hashClientIp } from './lib/ratelimit.js';
import {
	assertCandidates,
	assertClientVersion,
	assertCmdChatId,
	assertFingerprint,
	assertHandle,
	assertNoSecretMaterial,
	assertProtocolVersion,
	assertSealed,
	normaliseAddress,
	rejectUnknownFields,
} from './lib/validate.js';

const REGISTER_FIELDS = new Set(['id', 'public_key', 'issued_at', 'session_fingerprint', 'protocol_version', 'client_version', 'candidates']);
const HEARTBEAT_FIELDS = new Set(['id', 'public_key', 'issued_at']);
const DELETE_FIELDS = new Set(['id', 'public_key', 'issued_at']);

// The v2 request shapes. Note what is absent: there is no 'id', no 'public_key',
// and no 'candidates'. Addresses arrive sealed and the identity never arrives at
// all.
const PUBLISH_V2_FIELDS = new Set(['handle', 'write_key', 'issued_at', 'sealed']);
const TOUCH_V2_FIELDS = new Set(['handle', 'write_key', 'issued_at']);
const DELETE_V2_FIELDS = new Set(['handle', 'write_key', 'issued_at']);

export default {
	async fetch(request, env, ctx) {
		try {
			return await route(request, env, ctx);
		} catch (error) {
			if (error instanceof RequestError) return error.toResponse();
			// Never leak internals (or anything key-shaped) to the caller.
			console.error('unhandled phonebook error:', error?.message);
			return fail(500, 'internal_error', 'Unexpected server error.');
		}
	},

	/** Cron-driven expiry of stale registrations and spent rate-limit windows. */
	async scheduled(event, env, ctx) {
		const now = Math.floor(Date.now() / 1000);
		ctx.waitUntil(garbageCollect(env.cmd_chat_phonebook, now));
		ctx.waitUntil(garbageCollectEntries(env.cmd_chat_phonebook, now));
	},
};

async function route(request, env, ctx) {
	if (request.method === 'OPTIONS') return preflight();

	const url = new URL(request.url);
	const path = url.pathname.replace(/\/+$/, '') || '/';
	const db = env.cmd_chat_phonebook;
	const observedIp = request.headers.get('cf-connecting-ip');
	const ipHash = await hashClientIp(observedIp, env.IP_HASH_SALT ?? 'cmd-chat-dev-salt');

	if (path === '/' || path === '/health') {
		if (request.method !== 'GET') return methodNotAllowed('GET');
		return ok({
			service: 'cmd-chat-phonebook',
			role: 'rendezvous directory only; chat traffic never transits this service',
			protocol_version: PROTOCOL_VERSION,
			registration_ttl: REGISTRATION_TTL_SECONDS,
			// v2 is the blinded directory: no CMD-Chat ID and no address is
			// stored in readable form. Clients check this to tell a current
			// Worker from one that predates it.
			blinded_entries: true,
			entry_ttl: ENTRY_TTL_SECONDS,
		});
	}

	// STUN-lite. The Worker can only observe the source IP of an HTTPS
	// connection, so it reports the address and explicitly NOT a port: the TCP
	// source port of this request is useless for UDP hole punching.
	if (path === '/stun') {
		if (request.method !== 'GET') return methodNotAllowed('GET');
		return ok({ observed_ip: normaliseAddress(observedIp ?? '') , port_observable: false });
	}

	// ---------------------------------------------------------------------
	// v2: the blinded directory. Keyed by handle; stores no ID and no address.
	// ---------------------------------------------------------------------

	if (path === '/v2/publish') {
		if (request.method !== 'POST') return methodNotAllowed('POST');
		return handlePublishV2(request, db, ctx, { ipHash, observedIp });
	}

	if (path === '/v2/touch') {
		if (request.method !== 'POST') return methodNotAllowed('POST');
		return handleTouchV2(request, db, { ipHash });
	}

	if (path.startsWith('/v2/entry/')) {
		const handle = path.slice('/v2/entry/'.length);
		if (request.method === 'GET') return handleEntryLookupV2(handle, db, { ipHash });
		if (request.method === 'DELETE') return handleEntryDeleteV2(request, path, db, { ipHash });
		return methodNotAllowed('GET or DELETE');
	}

	// ---------------------------------------------------------------------
	// v1: the original ID-keyed directory.
	//
	// DEPRECATED. It stores a CMD-Chat ID alongside the peer's addresses, which
	// is exactly the identity-to-location map v2 exists to remove. It is kept
	// only so clients released before v2 keep working, and should be deleted
	// once they are gone.
	// ---------------------------------------------------------------------

	if (path === '/register') {
		if (request.method !== 'POST') return methodNotAllowed('POST');
		return handleRegister(request, db, ctx, { ipHash, observedIp });
	}

	if (path.startsWith('/lookup/')) {
		if (request.method !== 'GET') return methodNotAllowed('GET');
		return handleLookup(path.slice('/lookup/'.length), db, { ipHash });
	}

	if (path === '/heartbeat') {
		if (request.method !== 'POST') return methodNotAllowed('POST');
		return handleHeartbeat(request, db, { ipHash });
	}

	if (path.startsWith('/register/')) {
		if (request.method !== 'DELETE') return methodNotAllowed('DELETE');
		return handleDelete(request, path, db, { ipHash });
	}

	return fail(404, 'not_found', 'Unknown endpoint.');
}

function methodNotAllowed(allowed) {
	return fail(405, 'method_not_allowed', `This endpoint only accepts ${allowed}.`);
}

/**
 * POST /register
 *
 * Publishes (or republishes) a peer's identity and current candidate set.
 * Registering an ID that already exists updates it in place — never a duplicate.
 */
async function handleRegister(request, db, ctx, { ipHash, observedIp }) {
	const nowMs = Date.now();
	const now = Math.floor(nowMs / 1000);

	const { body, raw } = await readJsonBody(request);
	assertNoSecretMaterial(body);
	rejectUnknownFields(body, REGISTER_FIELDS, 'register request');

	const { id, publicKey, issuedAt } = await authenticate(request, '/register', body, raw, nowMs);

	const limited = await enforceRateLimit(db, 'register', { ipHash, id }, now);
	if (limited) return limited;

	const sessionFingerprint = assertFingerprint(body.session_fingerprint);
	const protocolVersion = assertProtocolVersion(body.protocol_version);
	const clientVersion = assertClientVersion(body.client_version);
	const candidates = assertCandidates(body.candidates);

	const existing = await getAuthState(db, id);
	assertNotReplay(issuedAt, existing?.last_issued_at);

	// The address this Worker actually saw is worth publishing, because a peer
	// behind NAT usually cannot discover it alone. Port is intentionally NULL.
	// The observed IP is reported back to the caller but NEVER stored.
	//
	// It used to be appended to the candidate list and written to D1, which made
	// the database hold an identity-to-public-IP mapping for every peer that
	// registered — including peers that published no addresses of their own. It
	// was also never used: the client only ever dials 'host' candidates, so
	// nothing read it back. Removing it costs no functionality.
	const observed = normaliseAddress(observedIp ?? '');
	const stored = [...candidates];


	const { expiresAt, ttl } = await upsertRegistration(db, {
		id,
		publicKey,
		sessionFingerprint,
		protocolVersion,
		clientVersion,
		candidates: stored,
		now,
		issuedAt,
	});

	ctx.waitUntil(garbageCollect(db, now).catch(() => {}));

	return ok(
		{
			id,
			created: !existing || existing.revoked_at !== null,
			expires_at: expiresAt,
			ttl,
			heartbeat_interval: Math.floor(ttl / 3),
			observed_ip: observed,
			candidates_stored: stored.length,
		},
		existing && existing.revoked_at === null ? 200 : 201,
	);
}

/**
 * GET /lookup/:id
 *
 * Public read. Returns only what a peer needs in order to try connecting.
 * Stale or revoked entries are reported as offline, never as connectable.
 */
async function handleLookup(rawId, db, { ipHash }) {
	const now = Math.floor(Date.now() / 1000);
	const id = assertCmdChatId(decodeURIComponent(rawId), 'lookup id');

	const limited = await enforceRateLimit(db, 'lookup', { ipHash, id }, now);
	if (limited) return limited;

	const found = await lookupRegistration(db, id, now);
	if (!found) return fail(404, 'not_found', 'No such CMD-Chat ID in the phonebook.', { id, online: false });

	if (!found.online) {
		// Deliberately minimal: last_seen is useful ("they were here 3 minutes
		// ago"), everything address-shaped is withheld.
		return fail(404, 'offline', 'Peer is registered but not currently online.', {
			id,
			online: false,
			last_seen: found.registration.last_seen,
		});
	}

	return ok({
		id,
		online: true,
		public_key: found.registration.public_key,
		session_fingerprint: found.registration.session_fingerprint,
		protocol_version: found.registration.protocol_version,
		client_version: found.registration.client_version,
		last_seen: found.registration.last_seen,
		expires_at: found.registration.expires_at,
		candidates: found.candidates.map((c) => ({
			kind: c.kind,
			transport: c.transport,
			address: c.address,
			port: c.port,
			priority: c.priority,
		})),
	});
}

/**
 * POST /heartbeat
 *
 * Liveness only: extends the TTL. It cannot change identity or candidates, and
 * the signature check means it can only ever extend the signer's own entry.
 */
async function handleHeartbeat(request, db, { ipHash }) {
	const nowMs = Date.now();
	const now = Math.floor(nowMs / 1000);

	const { body, raw } = await readJsonBody(request);
	assertNoSecretMaterial(body);
	rejectUnknownFields(body, HEARTBEAT_FIELDS, 'heartbeat request');

	const { id, issuedAt } = await authenticate(request, '/heartbeat', body, raw, nowMs);

	const limited = await enforceRateLimit(db, 'heartbeat', { ipHash, id }, now);
	if (limited) return limited;

	const existing = await getAuthState(db, id);
	if (!existing || existing.revoked_at !== null) {
		return fail(404, 'not_registered', 'No active registration for this ID; call /register first.');
	}
	assertNotReplay(issuedAt, existing.last_issued_at);

	const { changed, expiresAt, ttl } = await touchRegistration(db, id, now, issuedAt);
	if (!changed) return fail(404, 'not_registered', 'No active registration for this ID; call /register first.');

	return ok({ id, expires_at: expiresAt, ttl, heartbeat_interval: Math.floor(ttl / 3) });
}

/**
 * DELETE /register/:id
 *
 * Proof of ownership is the same Ed25519 signature used everywhere else, and
 * the path ID must match the signed body ID, so one peer cannot unregister
 * another. The entry is invalidated and all addresses are destroyed
 * immediately; a short tombstone remains to block replay-resurrection.
 */
async function handleDelete(request, path, db, { ipHash }) {
	const nowMs = Date.now();
	const now = Math.floor(nowMs / 1000);

	const pathId = assertCmdChatId(decodeURIComponent(path.slice('/register/'.length)), 'path id');

	const { body, raw } = await readJsonBody(request);
	assertNoSecretMaterial(body);
	rejectUnknownFields(body, DELETE_FIELDS, 'delete request');

	const { id, issuedAt } = await authenticate(request, path, body, raw, nowMs);
	if (id !== pathId) return fail(403, 'id_mismatch', 'Signed body ID does not match the ID in the path.');

	const limited = await enforceRateLimit(db, 'delete', { ipHash, id }, now);
	if (limited) return limited;

	const existing = await getAuthState(db, id);
	if (!existing) return fail(404, 'not_found', 'No such CMD-Chat ID in the phonebook.');
	assertNotReplay(issuedAt, existing.last_issued_at);

	await revokeRegistration(db, id, now, issuedAt);
	return ok({ id, revoked: true, already_revoked: existing.revoked_at !== null });
}

// ---------------------------------------------------------------------------
// v2 handlers: the blinded directory.
//
// Read these next to migrations/0002_blinded_entries.sql. The short version is
// that this Worker no longer knows who anyone is: it moves opaque handles and
// opaque blobs, and the only thing it can decide is whether the caller holds the
// key that owns a handle.
// ---------------------------------------------------------------------------

/**
 * POST /v2/publish
 *
 * Creates or refreshes a blinded entry. One row read, one row written.
 */
async function handlePublishV2(request, db, ctx, { ipHash, observedIp }) {
	const nowMs = Date.now();
	const now = Math.floor(nowMs / 1000);

	const { body, raw } = await readJsonBody(request);
	rejectUnknownFields(body, PUBLISH_V2_FIELDS, 'publish request');
	assertNoSecretMaterial(body);

	const { handle, writeKey, issuedAt } = await authenticateV2(request, '/v2/publish', body, raw, nowMs);
	const sealed = assertSealed(body.sealed, MAX_SEALED_CHARS);

	// The handle is the rate-limit subject in place of an ID. It gives the same
	// per-peer protection without the directory learning who the peer is.
	const limited = await enforceRateLimit(db, 'register', { ipHash, id: handle }, now);
	if (limited) return limited;

	const existing = await getEntryAuthState(db, handle);
	assertHandleOwner(existing, writeKey);
	assertNotReplay(issuedAt, existing?.last_issued_at);

	const { expiresAt, ttl } = await upsertEntry(db, { handle, writeKey, sealed, now, issuedAt });

	// Opportunistic cleanup so a Worker with no cron still self-cleans.
	ctx.waitUntil(garbageCollectEntries(db, now));

	return ok({
		handle,
		expires_at: expiresAt,
		ttl,
		heartbeat_interval: Math.floor(ttl / 3),
		// Reported so the caller can see its own public address, and so it can
		// choose to include it in the NEXT sealed entry. Never stored here.
		observed_ip: normaliseAddress(observedIp ?? ''),
	});
}

/**
 * POST /v2/touch
 *
 * Extends an entry's lifetime. The cheapest call in the service: one row
 * written, nothing read, no ciphertext rewritten.
 *
 * The authorisation is entirely in the UPDATE's WHERE clause — handle, write key,
 * not revoked, and strictly-newer issued_at — so there is no read-then-write
 * window, and a request that fails any of them changes nothing.
 */
async function handleTouchV2(request, db, { ipHash }) {
	const nowMs = Date.now();
	const now = Math.floor(nowMs / 1000);

	const { body, raw } = await readJsonBody(request);
	rejectUnknownFields(body, TOUCH_V2_FIELDS, 'touch request');
	assertNoSecretMaterial(body);

	const { handle, writeKey, issuedAt } = await authenticateV2(request, '/v2/touch', body, raw, nowMs);

	const limited = await enforceRateLimit(db, 'heartbeat', { ipHash, id: handle }, now);
	if (limited) return limited;

	const { changed, expiresAt, ttl } = await touchEntry(db, { handle, writeKey, now, issuedAt });
	if (!changed) {
		// Indistinguishable on purpose: an unknown handle, one owned by another
		// key, a revoked one, and a replayed request all look the same from here.
		// The client's answer to all of them is the same too — publish again.
		return fail(404, 'not_registered', 'No live entry for this handle; publish again.', { handle });
	}

	return ok({ handle, expires_at: expiresAt, ttl, heartbeat_interval: Math.floor(ttl / 3) });
}

/**
 * GET /v2/entry/{handle}
 *
 * One row read. Returns the sealed blob and nothing else that could be
 * correlated: no write key, no ID, and no address, because this Worker holds
 * none of the last two and withholds the first.
 */
async function handleEntryLookupV2(rawHandle, db, { ipHash }) {
	const now = Math.floor(Date.now() / 1000);
	const handle = assertHandle(decodeURIComponent(rawHandle), 'lookup handle');

	const limited = await enforceRateLimit(db, 'lookup', { ipHash, id: null }, now);
	if (limited) return limited;

	const found = await lookupEntry(db, handle, now);
	if (!found) return fail(404, 'not_found', 'No such entry in the directory.', { online: false });

	if (!found.online) {
		return fail(404, 'offline', 'Entry exists but is not currently online.', {
			online: false,
			last_seen: found.row.last_seen,
		});
	}

	return ok({
		online: true,
		sealed: found.row.sealed,
		last_seen: found.row.last_seen,
		expires_at: found.row.expires_at,
	});
}

/**
 * DELETE /v2/entry/{handle}
 *
 * Revokes an entry. The path handle must match the signed body handle, so a
 * captured signature for one entry cannot be aimed at another.
 */
async function handleEntryDeleteV2(request, path, db, { ipHash }) {
	const nowMs = Date.now();
	const now = Math.floor(nowMs / 1000);

	const pathHandle = assertHandle(decodeURIComponent(path.slice('/v2/entry/'.length)), 'path handle');

	const { body, raw } = await readJsonBody(request);
	rejectUnknownFields(body, DELETE_V2_FIELDS, 'delete request');
	assertNoSecretMaterial(body);

	const { handle, writeKey, issuedAt } = await authenticateV2(request, path, body, raw, nowMs);
	if (handle !== pathHandle) {
		return fail(403, 'handle_mismatch', 'Signed body handle does not match the handle in the path.');
	}

	const limited = await enforceRateLimit(db, 'delete', { ipHash, id: handle }, now);
	if (limited) return limited;

	const { changed } = await revokeEntry(db, { handle, writeKey, now, issuedAt });
	if (!changed) return fail(404, 'not_found', 'No entry for this handle and key.', { handle });

	return ok({ handle, revoked: true });
}
