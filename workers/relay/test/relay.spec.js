import { SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import { collect, connect, makeIdentity, textOf } from './helpers.js';

describe('service metadata', () => {
	it('describes itself as a pipe it cannot read', async () => {
		const res = await SELF.fetch('https://relay.test/health');
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.ok).toBe(true);
		expect(body.service).toBe('cmd-chat-relay');
		expect(body.max_session_bytes).toBeGreaterThan(0);
	});

	it('requires a WebSocket upgrade on relay endpoints', async () => {
		const res = await SELF.fetch('https://relay.test/relay/cc-AAAAAAAAAAAAAAAA');
		expect(res.status).toBe(426);
		expect((await res.json()).error).toBe('expected_websocket');
	});
});

describe('authentication', () => {
	it('rejects a join with no signature', async () => {
		const host = await makeIdentity();
		const res = await SELF.fetch(`https://relay.test/relay/${host.id}`, {
			headers: { Upgrade: 'websocket', 'X-CmdChat-Role': 'host', 'X-CmdChat-Id': host.id },
		});
		expect(res.status).toBe(401);
	});

	it('rejects a signature made by a different key', async () => {
		const host = await makeIdentity();
		const mallory = await makeIdentity();
		const result = await connect(host, 'host', host.id, { signAs: mallory });
		expect(result.status).toBe(401);
		expect(result.body.error).toBe('invalid_signature');
	});

	it('rejects a public key that does not derive the claimed ID', async () => {
		const host = await makeIdentity();
		const other = await makeIdentity();
		const result = await connect(host, 'host', host.id, { publicKey: other.publicKey });
		expect(result.status).toBe(401);
		expect(result.body.error).toBe('id_key_mismatch');
	});

	it('stops a stranger claiming someone else’s host slot', async () => {
		const host = await makeIdentity();
		const mallory = await makeIdentity();
		// Mallory signs correctly, with her own valid identity, but for a
		// session that belongs to someone else.
		const result = await connect(mallory, 'host', host.id);
		expect(result.status).toBe(403);
		expect(result.body.error).toBe('not_session_owner');
	});

	it('rejects a stale timestamp', async () => {
		const host = await makeIdentity();
		const result = await connect(host, 'host', host.id, { issuedAt: Date.now() - 10 * 60 * 1000 });
		expect(result.status).toBe(401);
		expect(result.body.error).toBe('clock_skew');
	});

	it('rejects an invalid role and an invalid session', async () => {
		const host = await makeIdentity();
		expect((await connect(host, 'host', host.id, { role: 'admin' })).status).toBe(401);
		expect((await connect(host, 'guest', 'not-an-id')).status).toBe(401);
	});
});

describe('pairing', () => {
	it('tells a lone host it is waiting', async () => {
		const host = await makeIdentity();
		const { status, socket } = await connect(host, 'host', host.id);
		expect(status).toBe(101);

		const seen = collect(socket);
		expect(await seen.until(() => seen.control.length > 0)).toBe(true);
		expect(seen.control[0].type).toBe('waiting');
		socket.close();
	});

	it('refuses a guest when no host is waiting', async () => {
		const host = await makeIdentity();
		const guest = await makeIdentity();
		const result = await connect(guest, 'guest', host.id);
		expect(result.status).toBe(409);
		expect(result.body.error).toBe('no_host');
	});

	it('pairs a host and a guest and tells each who joined', async () => {
		const host = await makeIdentity();
		const guest = await makeIdentity();

		const h = await connect(host, 'host', host.id);
		const hostSeen = collect(h.socket);

		const g = await connect(guest, 'guest', host.id);
		expect(g.status).toBe(101);
		const guestSeen = collect(g.socket);

		expect(await hostSeen.until(() => hostSeen.control.some((c) => c.type === 'paired'))).toBe(true);
		expect(await guestSeen.until(() => guestSeen.control.some((c) => c.type === 'paired'))).toBe(true);

		expect(hostSeen.control.find((c) => c.type === 'paired').peer).toBe(guest.id);
		expect(guestSeen.control.find((c) => c.type === 'paired').peer).toBe(host.id);

		h.socket.close();
		g.socket.close();
	});
});

describe('forwarding', () => {
	it('relays binary frames in both directions, byte for byte', async () => {
		const host = await makeIdentity();
		const guest = await makeIdentity();

		const h = await connect(host, 'host', host.id);
		const hostSeen = collect(h.socket);
		const g = await connect(guest, 'guest', host.id);
		const guestSeen = collect(g.socket);

		await hostSeen.until(() => hostSeen.control.some((c) => c.type === 'paired'));
		await guestSeen.until(() => guestSeen.control.some((c) => c.type === 'paired'));

		g.socket.send(new TextEncoder().encode('ping').buffer);
		expect(await hostSeen.until(() => hostSeen.binary.length > 0)).toBe(true);
		expect(textOf(hostSeen.binary[0])).toBe('ping');

		h.socket.send(new TextEncoder().encode('pong').buffer);
		expect(await guestSeen.until(() => guestSeen.binary.length > 0)).toBe(true);
		expect(textOf(guestSeen.binary[0])).toBe('pong');

		h.socket.close();
		g.socket.close();
	});

	// A TLS record stream is order-sensitive and unforgiving of corruption, so
	// the pipe must preserve both exactly. (The DO pins binaryType to
	// arraybuffer for the same reason: a real client's frames arrive as Blobs
	// otherwise, which send() rejects and which would force an await — and an
	// await inside the message handler could reorder frames.)
	it('preserves frame order and contents across many frames', async () => {
		const host = await makeIdentity();
		const guest = await makeIdentity();

		const h = await connect(host, 'host', host.id);
		const hostSeen = collect(h.socket);
		const g = await connect(guest, 'guest', host.id);
		const guestSeen = collect(g.socket);
		await guestSeen.until(() => guestSeen.control.some((c) => c.type === 'paired'));

		const sent = [];
		for (let i = 0; i < 40; i += 1) {
			const payload = new Uint8Array(64).fill(i);
			sent.push(payload);
			g.socket.send(payload.buffer);
		}

		expect(await hostSeen.until(() => hostSeen.binary.length === sent.length, 5000)).toBe(true);
		for (let i = 0; i < sent.length; i += 1) {
			expect(Array.from(hostSeen.binary[i])).toEqual(Array.from(sent[i]));
		}

		h.socket.close();
		g.socket.close();
	});

	it('never forwards control text frames to the other peer', async () => {
		const host = await makeIdentity();
		const guest = await makeIdentity();

		const h = await connect(host, 'host', host.id);
		const hostSeen = collect(h.socket);
		const g = await connect(guest, 'guest', host.id);
		const guestSeen = collect(g.socket);
		await guestSeen.until(() => guestSeen.control.some((c) => c.type === 'paired'));

		const hostControlBefore = hostSeen.control.length;
		g.socket.send(JSON.stringify({ type: 'ping' }));

		// The guest gets its own pong; the host must see nothing new.
		expect(await guestSeen.until(() => guestSeen.control.some((c) => c.type === 'pong'))).toBe(true);
		expect(hostSeen.control.length).toBe(hostControlBefore);
		expect(hostSeen.binary.length).toBe(0);

		h.socket.close();
		g.socket.close();
	});

	// Regression: a host goes straight back to waiting after a guest arrives, so
	// it can serve the next one. Treating that new standby socket as a
	// replacement used to close the socket carrying the live conversation.
	it('keeps a live conversation alive when the host parks a new standby socket', async () => {
		const host = await makeIdentity();
		const guest = await makeIdentity();

		const first = await connect(host, 'host', host.id);
		const firstSeen = collect(first.socket);
		const g = await connect(guest, 'guest', host.id);
		const guestSeen = collect(g.socket);
		await guestSeen.until(() => guestSeen.control.some((c) => c.type === 'paired'));

		// Host parks a second socket for the next guest.
		const standby = await connect(host, 'host', host.id);
		expect(standby.status).toBe(101);
		const standbySeen = collect(standby.socket);
		expect(await standbySeen.until(() => standbySeen.control.some((c) => c.type === 'waiting'))).toBe(true);

		// The original conversation must still work in both directions.
		expect(firstSeen.closed.length).toBe(0);
		expect(guestSeen.closed.length).toBe(0);

		g.socket.send(new TextEncoder().encode('still here').buffer);
		expect(await firstSeen.until(() => firstSeen.binary.length > 0)).toBe(true);
		expect(textOf(firstSeen.binary[0])).toBe('still here');

		first.socket.close();
		standby.socket.close();
		g.socket.close();
	});

	it('lets a second guest reach the same host on the new standby socket', async () => {
		const host = await makeIdentity();
		const guestA = await makeIdentity();
		const guestB = await makeIdentity();

		const hostA = await connect(host, 'host', host.id);
		const a = await connect(guestA, 'guest', host.id);
		const aSeen = collect(a.socket);
		await aSeen.until(() => aSeen.control.some((c) => c.type === 'paired'));

		const hostB = await connect(host, 'host', host.id);
		const hostBSeen = collect(hostB.socket);
		const b = await connect(guestB, 'guest', host.id);
		expect(b.status).toBe(101);
		const bSeen = collect(b.socket);

		expect(await bSeen.until(() => bSeen.control.some((c) => c.type === 'paired'))).toBe(true);

		// Each conversation is independent: B's traffic must not reach A.
		b.socket.send(new TextEncoder().encode('for B').buffer);
		expect(await hostBSeen.until(() => hostBSeen.binary.length > 0)).toBe(true);
		expect(textOf(hostBSeen.binary[0])).toBe('for B');
		expect(aSeen.binary.length).toBe(0);

		hostA.socket.close();
		hostB.socket.close();
		a.socket.close();
		b.socket.close();
	});

	it('tells the guest when the host disappears', async () => {
		const host = await makeIdentity();
		const guest = await makeIdentity();

		const h = await connect(host, 'host', host.id);
		const g = await connect(guest, 'guest', host.id);
		const guestSeen = collect(g.socket);
		await guestSeen.until(() => guestSeen.control.some((c) => c.type === 'paired'));

		h.socket.close();
		expect(await guestSeen.until(() => guestSeen.closed.length > 0, 3000)).toBe(true);

		g.socket.close();
	});
});
