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

import { PROTOCOL_VERSION, REGISTRATION_TTL_SECONDS } from './lib/config.js';
import { authenticate, assertNotReplay } from './lib/auth.js';
import { garbageCollect, getAuthState, lookupRegistration, revokeRegistration, touchRegistration, upsertRegistration } from './lib/db.js';
import { RequestError, fail, ok, preflight, readJsonBody } from './lib/http.js';
import { enforceRateLimit, hashClientIp } from './lib/ratelimit.js';
import {
	assertCandidates,
	assertClientVersion,
	assertCmdChatId,
	assertFingerprint,
	assertNoSecretMaterial,
	assertProtocolVersion,
	normaliseAddress,
	rejectUnknownFields,
} from './lib/validate.js';

const REGISTER_FIELDS = new Set(['id', 'public_key', 'issued_at', 'session_fingerprint', 'protocol_version', 'client_version', 'candidates']);
const HEARTBEAT_FIELDS = new Set(['id', 'public_key', 'issued_at']);
const DELETE_FIELDS = new Set(['id', 'public_key', 'issued_at']);

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
		ctx.waitUntil(garbageCollect(env.cmd_chat_phonebook, Math.floor(Date.now() / 1000)));
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
		});
	}

	// STUN-lite. The Worker can only observe the source IP of an HTTPS
	// connection, so it reports the address and explicitly NOT a port: the TCP
	// source port of this request is useless for UDP hole punching.
	if (path === '/stun') {
		if (request.method !== 'GET') return methodNotAllowed('GET');
		return ok({ observed_ip: normaliseAddress(observedIp ?? '') , port_observable: false });
	}

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
	const observed = normaliseAddress(observedIp ?? '');
	const stored = [...candidates];
	if (observed && !stored.some((c) => c.address === observed && c.kind === 'server_reflexive_http')) {
		stored.push({ kind: 'server_reflexive_http', transport: 'udp', address: observed, port: null, priority: 0 });
	}

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
