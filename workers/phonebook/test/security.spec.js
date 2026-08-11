import { env, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import { heartbeat, lookup, makeIdentity, nextIssuedAt, register, registerBody, signedFetch, unregister } from './helpers.js';

describe('request hardening', () => {
	it('rejects oversized bodies', async () => {
		const alice = await makeIdentity();
		const res = await register(alice, { client_version: 'x'.repeat(8000) });
		expect(res.status).toBe(413);
		expect((await res.json()).error).toBe('body_too_large');
	});

	it('rejects malformed JSON', async () => {
		const res = await SELF.fetch('https://phonebook.test/register', {
			method: 'POST',
			headers: { 'content-type': 'application/json', 'x-cmdchat-signature': 'AA' },
			body: '{"id": ',
		});
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe('malformed_json');
	});

	it('rejects a non-JSON content type', async () => {
		const alice = await makeIdentity();
		const res = await register(alice, {}, { contentType: 'text/plain' });
		expect(res.status).toBe(415);
	});

	it('rejects a JSON array body', async () => {
		const res = await SELF.fetch('https://phonebook.test/register', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: '[]',
		});
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe('malformed_json');
	});

	it('rejects unknown fields instead of silently ignoring them', async () => {
		const alice = await makeIdentity();
		const res = await register(alice, { is_admin: true });
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe('unknown_field');
	});

	it('refuses to accept private key material', async () => {
		const alice = await makeIdentity();
		for (const field of ['private_key', 'seed', 'password']) {
			const res = await register(alice, { [field]: 'should-never-be-sent' });
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe('secret_material_rejected');
		}
	});
});

describe('identifier validation', () => {
	it('rejects malformed IDs on lookup', async () => {
		for (const bad of ['nope', 'cc-short', 'cc-abcdefghijklmnop', 'cc-AAAAAAAAAAAAAAA!', '../../etc/passwd']) {
			const res = await lookup(encodeURIComponent(bad));
			expect(res.status, `lookup(${bad})`).toBe(400);
			expect((await res.json()).error).toBe('invalid_id');
		}
	});

	it('is not vulnerable to SQL injection through the lookup path', async () => {
		const alice = await makeIdentity();
		await register(alice);

		const res = await lookup(encodeURIComponent("cc-AAAAAAAAAAAAAAAA'; DROP TABLE registrations;--"));
		expect(res.status).toBe(400);

		// The table is still there and still holds the registration.
		const row = await env.cmd_chat_phonebook.prepare('SELECT COUNT(*) AS n FROM registrations').first();
		expect(row.n).toBeGreaterThan(0);
	});

	it('rejects a public key that does not derive the claimed ID', async () => {
		const alice = await makeIdentity();
		const mallory = await makeIdentity();

		const body = registerBody(alice, { public_key: mallory.publicKey });
		const res = await signedFetch(mallory, 'POST', '/register', body);
		expect(res.status).toBe(403);
		expect((await res.json()).error).toBe('id_key_mismatch');
	});
});

describe('candidate validation', () => {
	const cases = [
		[{ kind: 'satellite', transport: 'udp', address: '1.1.1.1', port: 1 }, 'invalid_candidate_kind'],
		[{ kind: 'host', transport: 'sctp', address: '1.1.1.1', port: 1 }, 'invalid_candidate_transport'],
		[{ kind: 'host', transport: 'udp', address: '999.1.1.1', port: 1 }, 'invalid_candidate_address'],
		[{ kind: 'host', transport: 'udp', address: 'evil.example.com', port: 1 }, 'invalid_candidate_address'],
		[{ kind: 'host', transport: 'udp', address: '0.0.0.0', port: 1 }, 'invalid_candidate_address'],
		[{ kind: 'host', transport: 'udp', address: '1.1.1.1', port: 0 }, 'invalid_candidate_port'],
		[{ kind: 'host', transport: 'udp', address: '1.1.1.1', port: 70000 }, 'invalid_candidate_port'],
		[{ kind: 'host', transport: 'udp', address: '1.1.1.1' }, 'invalid_candidate_port'],
		[{ kind: 'host', transport: 'udp', address: '1.1.1.1', port: 1, evil: 1 }, 'unknown_field'],
		[{ kind: 'relay', transport: 'udp', address: '1.1.1.1', port: 1 }, 'relay_unsupported'],
	];

	for (const [candidate, expected] of cases) {
		it(`rejects ${expected} (${JSON.stringify(candidate)})`, async () => {
			const alice = await makeIdentity();
			const res = await register(alice, { candidates: [candidate] });
			expect(res.status).toBe(400);
			expect((await res.json()).error).toBe(expected);
		});
	}

	it('accepts IPv6 candidates', async () => {
		const alice = await makeIdentity();
		const res = await register(alice, {
			candidates: [{ kind: 'host', transport: 'udp', address: '2001:db8::1', port: 5000, priority: 5 }],
		});
		expect(res.status).toBe(201);
		const body = await lookup(alice.id).then((r) => r.json());
		expect(body.candidates.some((c) => c.address === '2001:db8::1')).toBe(true);
	});

	it('rejects an empty and an over-long candidate list', async () => {
		const alice = await makeIdentity();
		expect((await register(alice, { candidates: [] })).status).toBe(400);

		const many = Array.from({ length: 20 }, (_, i) => ({ kind: 'host', transport: 'udp', address: `10.0.0.${i + 1}`, port: 1000 + i }));
		const res = await register(alice, { candidates: many });
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe('too_many_candidates');
	});
});

describe('authorisation', () => {
	it('rejects a request with no signature', async () => {
		const alice = await makeIdentity();
		const res = await SELF.fetch('https://phonebook.test/register', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(registerBody(alice)),
		});
		expect(res.status).toBe(401);
		expect((await res.json()).error).toBe('missing_signature');
	});

	it('rejects a signature from the wrong key', async () => {
		const alice = await makeIdentity();
		const mallory = await makeIdentity();
		const res = await register(alice, {}, { signAs: mallory });
		expect(res.status).toBe(401);
		expect((await res.json()).error).toBe('invalid_signature');
	});

	it('rejects a tampered body', async () => {
		const alice = await makeIdentity();
		// Sign one candidate set, send a different one.
		const res = await register(alice, {}, { signBody: JSON.stringify({ tampered: true }) });
		expect(res.status).toBe(401);
		expect((await res.json()).error).toBe('invalid_signature');
	});

	it('rejects a signature bound to a different path', async () => {
		const alice = await makeIdentity();
		await register(alice);
		const res = await heartbeat(alice, {}, { signPath: '/register' });
		expect(res.status).toBe(401);
	});

	it('stops one peer from heartbeating another peer registration', async () => {
		const alice = await makeIdentity();
		const mallory = await makeIdentity();
		await register(alice);

		// Mallory signs correctly with her own key but claims Alice's ID.
		const res = await signedFetch(mallory, 'POST', '/heartbeat', {
			id: alice.id,
			public_key: mallory.publicKey,
			issued_at: nextIssuedAt(),
		});
		expect(res.status).toBe(403);
		expect((await res.json()).error).toBe('id_key_mismatch');
	});

	it('stops one peer from deleting another peer registration', async () => {
		const alice = await makeIdentity();
		const mallory = await makeIdentity();
		await register(alice);

		const res = await signedFetch(mallory, 'DELETE', `/register/${alice.id}`, {
			id: alice.id,
			public_key: mallory.publicKey,
			issued_at: nextIssuedAt(),
		});
		expect(res.status).toBe(403);

		// Alice is still discoverable.
		expect((await lookup(alice.id)).status).toBe(200);
	});

	it('rejects a delete whose path ID differs from the signed body ID', async () => {
		const alice = await makeIdentity();
		const bob = await makeIdentity();
		await register(alice);
		await register(bob);

		const res = await unregister(alice, {}, { path: `/register/${bob.id}` });
		expect(res.status).toBe(403);
		expect((await res.json()).error).toBe('id_mismatch');
		expect((await lookup(bob.id)).status).toBe(200);
	});
});

describe('replay protection', () => {
	it('rejects a replayed heartbeat', async () => {
		const alice = await makeIdentity();
		await register(alice);

		const issuedAt = nextIssuedAt();
		const body = { id: alice.id, public_key: alice.publicKey, issued_at: issuedAt };
		expect((await signedFetch(alice, 'POST', '/heartbeat', body)).status).toBe(200);

		const replayed = await signedFetch(alice, 'POST', '/heartbeat', body);
		expect(replayed.status).toBe(409);
		expect((await replayed.json()).error).toBe('replayed_request');
	});

	it('rejects a stale timestamp outside the skew window', async () => {
		const alice = await makeIdentity();
		const res = await register(alice, { issued_at: Date.now() - 10 * 60 * 1000 });
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe('clock_skew');
	});

	it('rejects a far-future timestamp', async () => {
		const alice = await makeIdentity();
		const res = await register(alice, { issued_at: Date.now() + 10 * 60 * 1000 });
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe('clock_skew');
	});

	it('does not let a deleted registration be resurrected by an old payload', async () => {
		const alice = await makeIdentity();
		const body = registerBody(alice);
		await signedFetch(alice, 'POST', '/register', body);
		await unregister(alice);

		const replayed = await signedFetch(alice, 'POST', '/register', body);
		expect(replayed.status).toBe(409);
		expect((await lookup(alice.id)).status).toBe(404);
	});
});

describe('abuse limits', () => {
	it('rate limits repeated registration attempts for one identity', async () => {
		const alice = await makeIdentity();
		let limited = null;
		for (let i = 0; i < 15 && limited === null; i += 1) {
			const res = await register(alice);
			if (res.status === 429) limited = res;
		}
		expect(limited).not.toBeNull();
		const body = await limited.json();
		expect(body.error).toBe('rate_limited');
		expect(body.retry_after).toBeGreaterThan(0);
	});

	it('never writes a raw IP address into the rate-limit table', async () => {
		const alice = await makeIdentity();
		await register(alice);
		const { results } = await env.cmd_chat_phonebook.prepare('SELECT bucket FROM rate_limits').all();
		expect(results.length).toBeGreaterThan(0);
		for (const row of results) {
			expect(row.bucket).not.toMatch(/\d{1,3}(\.\d{1,3}){3}/);
		}
	});
});
