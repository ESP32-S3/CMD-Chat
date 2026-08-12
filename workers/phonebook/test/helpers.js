import { SELF } from 'cloudflare:test';

/**
 * A minimal reference implementation of the client side of the phonebook
 * protocol. The Go client must produce byte-identical signing strings; if these
 * helpers and the Worker ever disagree, the tests fail.
 */

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

function toHex(bytes) {
	let out = '';
	for (const b of bytes) out += b.toString(16).padStart(2, '0');
	return out;
}

/**
 * The Worker requires `issued_at` to be strictly increasing per identity (that
 * is what makes replay impossible), so two calls inside the same millisecond
 * must not reuse a timestamp. Clients need the same guard.
 */
let lastIssuedAt = 0;
export function nextIssuedAt() {
	lastIssuedAt = Math.max(Date.now(), lastIssuedAt + 1);
	return lastIssuedAt;
}

/** Generates an Ed25519 identity and derives its CMD-Chat ID the same way the client does. */
export async function makeIdentity() {
	const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
	const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKeyBytes));
	return {
		privateKey: pair.privateKey,
		publicKeyBytes,
		publicKey: toBase64(publicKeyBytes),
		id: `cc-${base32(digest.subarray(0, 10))}`,
	};
}

async function sign(identity, method, path, issuedAt, rawBody) {
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rawBody)));
	const message = new TextEncoder().encode(['cmd-chat-phonebook/v1', method.toUpperCase(), path, String(issuedAt), toHex(digest)].join('\n'));
	const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, identity.privateKey, message));
	return toBase64(signature);
}

/**
 * Sends a signed request. `signAs` / `signPath` allow tests to deliberately
 * sign with the wrong key or over the wrong path.
 */
export async function signedFetch(identity, method, path, body, options = {}) {
	const raw = JSON.stringify(body);
	const signer = options.signAs ?? identity;
	const signature = options.signature ?? (await sign(signer, method, options.signPath ?? path, body.issued_at, options.signBody ?? raw));

	return SELF.fetch(`https://phonebook.test${path}`, {
		method,
		headers: {
			'content-type': options.contentType ?? 'application/json',
			'x-cmdchat-signature': signature,
			...(options.headers ?? {}),
		},
		body: raw,
	});
}

export function candidates(port = 38556) {
	return [
		{ kind: 'host', transport: 'tcp', address: '192.168.1.42', port, priority: 100 },
		{ kind: 'server_reflexive', transport: 'udp', address: '203.0.113.9', port: 51820, priority: 200 },
	];
}

export function registerBody(identity, overrides = {}) {
	return {
		id: identity.id,
		public_key: identity.publicKey,
		issued_at: nextIssuedAt(),
		session_fingerprint: 'a'.repeat(64),
		protocol_version: 1,
		client_version: '0.1.0',
		candidates: candidates(),
		...overrides,
	};
}

export async function register(identity, overrides = {}, options = {}) {
	return signedFetch(identity, 'POST', '/register', registerBody(identity, overrides), options);
}

export async function heartbeat(identity, overrides = {}, options = {}) {
	const body = { id: identity.id, public_key: identity.publicKey, issued_at: nextIssuedAt(), ...overrides };
	return signedFetch(identity, 'POST', '/heartbeat', body, options);
}

export async function unregister(identity, overrides = {}, options = {}) {
	const path = options.path ?? `/register/${identity.id}`;
	const body = { id: identity.id, public_key: identity.publicKey, issued_at: nextIssuedAt(), ...overrides };
	return signedFetch(identity, 'DELETE', path, body, options);
}

export async function lookup(id) {
	return SELF.fetch(`https://phonebook.test/lookup/${id}`);
}
