import { env, SELF } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import { deleteV2, entryV2, handleFor, makeIdentity, makeV2Peer, makeWriteKey, nextIssuedAt, publishV2, register, sealedBlob, touchV2 } from './helpers.js';

/**
 * The blinded directory.
 *
 * These tests exist to hold one line: the database must not contain a map of
 * identity to location. Everything else here supports that claim or pins the
 * cost of making it.
 */

/** Every application table's full contents, for leak assertions. */
async function dumpDatabase() {
	const tables = await env.cmd_chat_phonebook.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all();
	const names = tables.results
		.map((t) => t.name)
		.filter((n) => !n.startsWith('_') && !n.startsWith('sqlite_') && n !== 'd1_migrations');

	const dump = {};
	for (const name of names) {
		const rows = await env.cmd_chat_phonebook.prepare(`SELECT * FROM ${name}`).all();
		dump[name] = rows.results ?? [];
	}
	return { names, dump, text: JSON.stringify(dump) };
}

describe('blinded directory: what the database holds', () => {
	it('stores no CMD-Chat ID and no address anywhere', async () => {
		const peer = await makeV2Peer();
		const published = await publishV2(peer);
		expect(published.status).toBe(200);

		const { text } = await dumpDatabase();

		// The identity must be absent in every form.
		expect(text).not.toContain(peer.id);
		expect(text).not.toContain(peer.id.slice(3)); // without the cc- prefix
		expect(text).not.toContain(peer.publicKey);

		// And so must every address the client would have published.
		for (const address of ['192.168.1.42', '203.0.113.9', '198.51.100.4']) {
			expect(text).not.toContain(address);
		}
	});

	it('does not persist the IP the Worker observed', async () => {
		const peer = await makeV2Peer();
		const response = await publishV2(peer, {}, { headers: { 'cf-connecting-ip': '198.51.100.77' } });
		expect(response.status).toBe(200);

		// It is reported back to the caller, so a host can see its own public
		// address and choose to seal it into the NEXT entry itself...
		expect((await response.json()).observed_ip).toBe('198.51.100.77');

		// ...and it is written nowhere. This is the row v1 accumulated for every
		// peer, mapping identity straight to public IP, and never read back.
		const { text } = await dumpDatabase();
		expect(text).not.toContain('198.51.100.77');
	});

	it('keeps the sealed blob opaque and byte-identical', async () => {
		const peer = await makeV2Peer();
		const blob = sealedBlob('a-specific-marker');
		expect((await publishV2(peer, { sealed: blob })).status).toBe(200);

		const found = await entryV2(peer.handle).then((r) => r.json());
		expect(found.online).toBe(true);
		expect(found.sealed).toBe(blob);
	});

	it('never returns the write key to a reader', async () => {
		const peer = await makeV2Peer();
		await publishV2(peer);

		const raw = await entryV2(peer.handle).then((r) => r.text());
		expect(raw).not.toContain(peer.writeKey.publicKey);
		// Nor anything else that could identify the writer.
		expect(raw).not.toContain(peer.id);
	});

	it('the v1 path no longer stores the observed IP either', async () => {
		const identity = await makeIdentity();
		const response = await register(identity, {}, { headers: { 'cf-connecting-ip': '198.51.100.88' } });
		expect(response.status).toBe(201);

		const rows = await env.cmd_chat_phonebook.prepare('SELECT * FROM candidates').all();
		const text = JSON.stringify(rows.results ?? []);
		expect(text).not.toContain('198.51.100.88');
		expect(text).not.toContain('server_reflexive_http');
	});
});

describe('blinded directory: handle ownership', () => {
	it('binds a handle to the first write key and refuses another', async () => {
		const peer = await makeV2Peer();
		expect((await publishV2(peer)).status).toBe(200);

		// A second key, same handle: refused.
		const squatter = { ...peer, writeKey: await makeWriteKey() };
		const refused = await publishV2(squatter);
		expect(refused.status).toBe(403);
		expect((await refused.json()).error).toBe('handle_claimed');

		// The original owner is unaffected.
		expect((await publishV2(peer)).status).toBe(200);
	});

	it('refuses a touch signed by a key that does not own the handle', async () => {
		const peer = await makeV2Peer();
		await publishV2(peer);

		const other = { ...peer, writeKey: await makeWriteKey() };
		const refused = await touchV2(other);
		expect(refused.status).toBe(404);
		expect((await refused.json()).error).toBe('not_registered');
	});

	it('refuses a request whose signature is by the wrong key', async () => {
		const peer = await makeV2Peer();
		const impostor = await makeWriteKey();

		const refused = await publishV2(peer, {}, { signAs: impostor });
		expect(refused.status).toBe(401);
		expect((await refused.json()).error).toBe('invalid_signature');
	});

	it('refuses a signature made over a different path', async () => {
		const peer = await makeV2Peer();
		const refused = await publishV2(peer, {}, { signPath: '/v2/touch' });
		expect(refused.status).toBe(401);
	});

	it('refuses a tampered body', async () => {
		const peer = await makeV2Peer();
		const refused = await publishV2(peer, {}, { signBody: JSON.stringify({ handle: peer.handle, sealed: 'other' }) });
		expect(refused.status).toBe(401);
	});

	it('refuses a replayed publish', async () => {
		const peer = await makeV2Peer();
		const issuedAt = nextIssuedAt();
		expect((await publishV2(peer, { issued_at: issuedAt })).status).toBe(200);

		const replayed = await publishV2(peer, { issued_at: issuedAt });
		expect(replayed.status).toBe(409);
		expect((await replayed.json()).error).toBe('replayed_request');
	});

	it('refuses a delete aimed at a different handle than the one signed', async () => {
		const peer = await makeV2Peer();
		const other = await makeV2Peer();
		await publishV2(peer);

		const refused = await deleteV2(peer, {}, { path: `/v2/entry/${other.handle}` });
		expect(refused.status).toBe(403);
		expect((await refused.json()).error).toBe('handle_mismatch');
	});

	it('a revoked handle keeps its owner, so it cannot be taken over', async () => {
		const peer = await makeV2Peer();
		await publishV2(peer);
		expect((await deleteV2(peer)).status).toBe(200);

		// Gone from the directory.
		expect((await entryV2(peer.handle)).status).toBe(404);

		// But not available to somebody else.
		const squatter = { ...peer, writeKey: await makeWriteKey() };
		expect((await publishV2(squatter)).status).toBe(403);

		// And the real owner can come back.
		expect((await publishV2(peer)).status).toBe(200);
		expect((await entryV2(peer.handle).then((r) => r.json())).online).toBe(true);
	});
});

describe('blinded directory: shape and validation', () => {
	it('derives a 26-character base32 handle', async () => {
		const identity = await makeIdentity();
		const handle = await handleFor(identity.id);
		expect(handle).toMatch(/^[A-Z2-7]{26}$/);
	});

	it('gives different IDs different handles, and the same ID the same one', async () => {
		const a = await makeIdentity();
		const b = await makeIdentity();
		expect(await handleFor(a.id)).not.toBe(await handleFor(b.id));
		expect(await handleFor(a.id)).toBe(await handleFor(a.id));
	});

	it('rejects a malformed handle', async () => {
		for (const bad of ['short', 'a'.repeat(26), '!'.repeat(26), 'A'.repeat(25), 'A'.repeat(27)]) {
			const response = await entryV2(bad);
			expect(response.status).toBe(400);
		}
	});

	it('rejects a malformed sealed blob', async () => {
		const peer = await makeV2Peer();
		for (const bad of ['', 'not base64!!', 'A'.repeat(47), 'A'.repeat(2801)]) {
			const response = await publishV2(peer, { sealed: bad });
			expect(response.status).toBe(400);
			expect((await response.json()).error).toBe('invalid_sealed');
		}
	});

	it('rejects a body large enough to be an abuse attempt before parsing it', async () => {
		const peer = await makeV2Peer();
		// The body-size guard fires ahead of field validation, which is the right
		// order: nothing oversized should reach a parser at all.
		const response = await publishV2(peer, { sealed: 'A'.repeat(9000) });
		expect(response.status).toBe(413);
	});

	it('rejects unknown fields, so a client cannot smuggle an ID in', async () => {
		const peer = await makeV2Peer();
		const response = await publishV2(peer, { id: peer.id });
		expect(response.status).toBe(400);
	});

	it('reports an unknown handle as not found, and a stale one as offline', async () => {
		const unknown = await handleFor((await makeIdentity()).id);
		const missing = await entryV2(unknown);
		expect(missing.status).toBe(404);
		expect((await missing.json()).error).toBe('not_found');

		const peer = await makeV2Peer();
		await publishV2(peer);
		await env.cmd_chat_phonebook
			.prepare('UPDATE entries SET expires_at = 1, last_seen = 1 WHERE handle = ?1')
			.bind(peer.handle)
			.run();

		const stale = await entryV2(peer.handle);
		expect(stale.status).toBe(404);
		const body = await stale.json();
		expect(body.error).toBe('offline');
		expect(body.sealed).toBeUndefined();
	});

	it('advertises the blinded protocol on /health', async () => {
		const health = await SELF.fetch('https://phonebook.test/health').then((r) => r.json());
		expect(health.blinded_entries).toBe(true);
		expect(health.entry_ttl).toBeGreaterThan(0);
	});
});

describe('blinded directory: row cost', () => {
	/**
	 * The write budget is a stated property of this design, not an accident, so
	 * it is asserted rather than assumed.
	 *
	 * v1 wrote 2+N rows for a publish, where N was the candidate count, because
	 * each address was its own row in a child table. v2 seals them into one blob
	 * and writes exactly one row however many addresses a peer has.
	 */
	it('publishing writes exactly one entry row regardless of payload size', async () => {
		const peer = await makeV2Peer();
		await publishV2(peer, { sealed: sealedBlob('x'.repeat(400)) });

		const count = await env.cmd_chat_phonebook.prepare('SELECT COUNT(*) AS n FROM entries').first();
		expect(count.n).toBe(1);

		// Republishing updates in place; it never accumulates rows.
		await publishV2(peer, { sealed: sealedBlob('different') });
		await publishV2(peer, { sealed: sealedBlob('again') });
		const after = await env.cmd_chat_phonebook.prepare('SELECT COUNT(*) AS n FROM entries').first();
		expect(after.n).toBe(1);
	});

	it('a heartbeat does not rewrite the sealed blob', async () => {
		const peer = await makeV2Peer();
		const blob = sealedBlob('unchanged-by-heartbeat');
		await publishV2(peer, { sealed: blob });

		const before = await env.cmd_chat_phonebook.prepare('SELECT sealed, expires_at FROM entries WHERE handle = ?1').bind(peer.handle).first();

		await env.cmd_chat_phonebook.prepare('UPDATE entries SET expires_at = ?2, last_seen = ?2 WHERE handle = ?1').bind(peer.handle, 1000).run();
		expect((await touchV2(peer)).status).toBe(200);

		const after = await env.cmd_chat_phonebook.prepare('SELECT sealed, expires_at FROM entries WHERE handle = ?1').bind(peer.handle).first();
		expect(after.sealed).toBe(before.sealed);
		expect(after.expires_at).toBeGreaterThan(1000);
	});

	it('the entry TTL gives a heartbeat interval that is a third of it', async () => {
		const peer = await makeV2Peer();
		const body = await publishV2(peer).then((r) => r.json());
		expect(body.heartbeat_interval).toBe(Math.floor(body.ttl / 3));
		// The TTL was raised specifically to cut write volume; hold that.
		expect(body.ttl).toBeGreaterThanOrEqual(900);
	});
});

describe('blinded directory: the full rendezvous still works', () => {
	beforeEach(async () => {
		await env.cmd_chat_phonebook.prepare('DELETE FROM entries').run();
		await env.cmd_chat_phonebook.prepare('DELETE FROM rate_limits').run();
	});

	it('one peer publishes and another resolves it by ID alone', async () => {
		// Bob publishes.
		const bob = await makeV2Peer();
		const blob = sealedBlob('bobs-sealed-candidates');
		expect((await publishV2(bob, { sealed: blob })).status).toBe(200);

		// Alice knows only Bob's ID — a human typed it. She derives the handle
		// herself; the directory is never told the ID.
		const derived = await handleFor(bob.id);
		const found = await entryV2(derived).then((r) => r.json());

		expect(found.online).toBe(true);
		expect(found.sealed).toBe(blob);

		// And the directory learned nothing along the way.
		const { text } = await dumpDatabase();
		expect(text).not.toContain(bob.id);
	});
});
