import { env, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import { heartbeat, lookup, makeIdentity, register, unregister } from './helpers.js';

describe('service metadata', () => {
	it('advertises itself as a directory, not a chat server', async () => {
		const res = await SELF.fetch('https://phonebook.test/health');
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.ok).toBe(true);
		expect(body.service).toBe('cmd-chat-phonebook');
		expect(body.protocol_version).toBe(1);
		expect(body.registration_ttl).toBeGreaterThan(0);
	});

	it('rejects unknown endpoints and wrong methods', async () => {
		expect((await SELF.fetch('https://phonebook.test/messages')).status).toBe(404);
		expect((await SELF.fetch('https://phonebook.test/health', { method: 'POST' })).status).toBe(405);
	});
});

describe('POST /register', () => {
	it('registers a peer and stores exactly its candidates', async () => {
		const alice = await makeIdentity();
		const res = await register(alice);

		expect(res.status).toBe(201);
		const body = await res.json();
		expect(body.ok).toBe(true);
		expect(body.id).toBe(alice.id);
		expect(body.created).toBe(true);
		expect(body.ttl).toBeGreaterThan(0);
		expect(body.heartbeat_interval).toBeGreaterThan(0);
		expect(body.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));

		const row = await env.cmd_chat_phonebook.prepare('SELECT * FROM registrations WHERE cmd_chat_id = ?1').bind(alice.id).first();
		expect(row.public_key).toBe(alice.publicKey);
		expect(row.revoked_at).toBeNull();

		const stored = await env.cmd_chat_phonebook.prepare('SELECT COUNT(*) AS n FROM candidates WHERE cmd_chat_id = ?1').bind(alice.id).first();
		expect(stored.n).toBe(2);
	});

	it('updates an existing registration in place rather than duplicating it', async () => {
		const alice = await makeIdentity();
		await register(alice);
		const second = await register(alice, {
			candidates: [{ kind: 'host', transport: 'tcp', address: '10.0.0.5', port: 4001, priority: 10 }],
		});

		expect(second.status).toBe(200);
		expect((await second.json()).created).toBe(false);

		const count = await env.cmd_chat_phonebook.prepare('SELECT COUNT(*) AS n FROM registrations WHERE cmd_chat_id = ?1').bind(alice.id).first();
		expect(count.n).toBe(1);

		// Candidates are replaced wholesale: the old address must be gone.
		const { results } = await env.cmd_chat_phonebook.prepare('SELECT address FROM candidates WHERE cmd_chat_id = ?1').bind(alice.id).all();
		expect(results.map((r) => r.address)).toEqual(['10.0.0.5']);
	});
});

describe('GET /lookup/:id', () => {
	it('returns identity and connection candidates for an online peer', async () => {
		const alice = await makeIdentity();
		await register(alice);

		const res = await lookup(alice.id);
		expect(res.status).toBe(200);
		const body = await res.json();

		expect(body.online).toBe(true);
		expect(body.public_key).toBe(alice.publicKey);
		expect(body.session_fingerprint).toHaveLength(64);
		expect(body.candidates.length).toBeGreaterThanOrEqual(2);
		expect(body.candidates[0]).toHaveProperty('address');
		expect(body.candidates[0]).toHaveProperty('port');
		expect(body.candidates[0]).toHaveProperty('transport');

		// Highest priority first, so the client can try the best path first.
		const priorities = body.candidates.map((c) => c.priority);
		expect([...priorities].sort((a, b) => b - a)).toEqual(priorities);
	});

	it('never exposes internal bookkeeping columns', async () => {
		const alice = await makeIdentity();
		await register(alice);
		const body = await lookup(alice.id).then((r) => r.json());

		for (const leaked of ['last_issued_at', 'revoked_at', 'created_at', 'observed_ip_hash']) {
			expect(body).not.toHaveProperty(leaked);
		}
	});

	it('reports an unknown ID as not found', async () => {
		const res = await lookup('cc-AAAAAAAAAAAAAAAA');
		expect(res.status).toBe(404);
		const body = await res.json();
		expect(body.error).toBe('not_found');
		expect(body.online).toBe(false);
	});

	it('reports a stale registration as offline and withholds its addresses', async () => {
		const alice = await makeIdentity();
		await register(alice);

		// Force expiry the way the passage of time would (the schema requires
		// expires_at >= last_seen, so both must move).
		await env.cmd_chat_phonebook
			.prepare('UPDATE registrations SET last_seen = 1, expires_at = 2 WHERE cmd_chat_id = ?1')
			.bind(alice.id)
			.run();

		const res = await lookup(alice.id);
		expect(res.status).toBe(404);
		const body = await res.json();
		expect(body.error).toBe('offline');
		expect(body.online).toBe(false);
		expect(body).not.toHaveProperty('candidates');
		expect(body).not.toHaveProperty('public_key');
	});
});

describe('POST /heartbeat', () => {
	it('extends the registration TTL', async () => {
		const alice = await makeIdentity();
		await register(alice);

		await env.cmd_chat_phonebook.prepare('UPDATE registrations SET expires_at = last_seen WHERE cmd_chat_id = ?1').bind(alice.id).run();
		const before = await env.cmd_chat_phonebook.prepare('SELECT expires_at FROM registrations WHERE cmd_chat_id = ?1').bind(alice.id).first();

		const res = await heartbeat(alice);
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.ok).toBe(true);
		expect(body.expires_at).toBeGreaterThan(before.expires_at);
	});

	it('does not resurrect or create a registration', async () => {
		const ghost = await makeIdentity();
		const res = await heartbeat(ghost);
		expect(res.status).toBe(404);
		expect((await res.json()).error).toBe('not_registered');

		const row = await env.cmd_chat_phonebook.prepare('SELECT COUNT(*) AS n FROM registrations WHERE cmd_chat_id = ?1').bind(ghost.id).first();
		expect(row.n).toBe(0);
	});

	it('cannot modify identity or candidates', async () => {
		const alice = await makeIdentity();
		await register(alice);
		const res = await heartbeat(alice, { candidates: [{ kind: 'host', transport: 'tcp', address: '1.2.3.4', port: 9, priority: 1 }] });
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe('unknown_field');
	});
});

describe('DELETE /register/:id', () => {
	it('removes the peer from the phonebook and destroys its addresses', async () => {
		const alice = await makeIdentity();
		await register(alice);

		const res = await unregister(alice);
		expect(res.status).toBe(200);
		expect((await res.json()).revoked).toBe(true);

		expect((await lookup(alice.id)).status).toBe(404);

		const candidates = await env.cmd_chat_phonebook.prepare('SELECT COUNT(*) AS n FROM candidates WHERE cmd_chat_id = ?1').bind(alice.id).first();
		expect(candidates.n).toBe(0);

		const row = await env.cmd_chat_phonebook.prepare('SELECT revoked_at FROM registrations WHERE cmd_chat_id = ?1').bind(alice.id).first();
		expect(row.revoked_at).not.toBeNull();
	});

	it('lets the owner re-register afterwards', async () => {
		const alice = await makeIdentity();
		await register(alice);
		await unregister(alice);

		const again = await register(alice);
		expect(again.status).toBe(201);
		expect((await lookup(alice.id)).status).toBe(200);
	});

	it('404s for an ID that was never registered', async () => {
		const ghost = await makeIdentity();
		const res = await unregister(ghost);
		expect(res.status).toBe(404);
		expect((await res.json()).error).toBe('not_found');
	});
});

describe('full discovery chain', () => {
	it('lets one peer resolve another peer into usable connection information', async () => {
		const alice = await makeIdentity();
		const bob = await makeIdentity();

		await register(alice, { candidates: [{ kind: 'host', transport: 'tcp', address: '192.168.0.7', port: 38556, priority: 120 }] });
		await register(bob, { candidates: [{ kind: 'server_reflexive', transport: 'udp', address: '198.51.100.4', port: 41234, priority: 200 }] });

		const seenByAlice = await lookup(bob.id).then((r) => r.json());
		expect(seenByAlice.online).toBe(true);
		expect(seenByAlice.public_key).toBe(bob.publicKey);
		const target = seenByAlice.candidates.find((c) => c.kind === 'server_reflexive');
		expect(target).toMatchObject({ transport: 'udp', address: '198.51.100.4', port: 41234 });

		const seenByBob = await lookup(alice.id).then((r) => r.json());
		expect(seenByBob.candidates.find((c) => c.kind === 'host')).toMatchObject({ address: '192.168.0.7', port: 38556 });

		// The phonebook stores discovery data only — no message table exists.
		const tables = await env.cmd_chat_phonebook.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all();
		const names = tables.results.map((t) => t.name);
		expect(names).not.toContain('messages');
		const appTables = names.filter((n) => !n.startsWith('_') && !n.startsWith('sqlite_') && n !== 'd1_migrations');
		expect(appTables.sort()).toEqual(['candidates', 'entries', 'rate_limits', 'registrations']);
	});
});
