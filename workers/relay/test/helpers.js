import { SELF } from 'cloudflare:test';

/** Client-side reference implementation of the relay join protocol. */

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32(bytes) {
	let bits = 0;
	let value = 0;
	let out = '';
	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			out += BASE32[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
	return out;
}

function toBase64(bytes) {
	let binary = '';
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary);
}

export async function makeIdentity() {
	const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
	const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKeyBytes));
	return {
		privateKey: pair.privateKey,
		publicKey: toBase64(publicKeyBytes),
		id: `cc-${base32(digest.subarray(0, 10))}`,
	};
}

export async function joinHeaders(identity, role, session, overrides = {}) {
	const issuedAt = overrides.issuedAt ?? Date.now();
	const signer = overrides.signAs ?? identity;
	const message = new TextEncoder().encode(['cmd-chat-relay/v1', role, session, identity.id, String(issuedAt)].join('\n'));
	const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, signer.privateKey, message));

	return {
		Upgrade: 'websocket',
		'X-CmdChat-Role': overrides.role ?? role,
		'X-CmdChat-Id': overrides.id ?? identity.id,
		'X-CmdChat-PublicKey': overrides.publicKey ?? identity.publicKey,
		'X-CmdChat-IssuedAt': String(issuedAt),
		'X-CmdChat-Signature': overrides.signature ?? toBase64(signature),
	};
}

/** Opens a relay WebSocket and returns the accepted client socket. */
export async function connect(identity, role, session, overrides = {}) {
	const res = await SELF.fetch(`https://relay.test/relay/${session}`, {
		headers: await joinHeaders(identity, role, session, overrides),
	});
	if (res.status !== 101) {
		return { status: res.status, body: await res.json(), socket: null };
	}
	const socket = res.webSocket;
	socket.accept();
	return { status: res.status, socket };
}

/**
 * Collects incoming frames, keeping text (control) and binary (relayed data)
 * apart the same way the Go client does.
 */
export function collect(socket) {
	const control = [];
	const binary = [];
	const waiters = [];

	socket.addEventListener('message', (event) => {
		if (typeof event.data === 'string') control.push(JSON.parse(event.data));
		else binary.push(new Uint8Array(event.data));
		while (waiters.length) waiters.shift()();
	});

	const closed = [];
	socket.addEventListener('close', (event) => {
		closed.push({ code: event.code, reason: event.reason });
		while (waiters.length) waiters.shift()();
	});

	return {
		control,
		binary,
		closed,
		/** Waits until predicate holds or the timeout elapses. */
		async until(predicate, timeoutMs = 2000) {
			const deadline = Date.now() + timeoutMs;
			while (!predicate() && Date.now() < deadline) {
				await new Promise((resolve) => {
					waiters.push(resolve);
					setTimeout(resolve, 25);
				});
			}
			return predicate();
		},
	};
}

export function textOf(bytes) {
	return new TextDecoder().decode(bytes);
}
