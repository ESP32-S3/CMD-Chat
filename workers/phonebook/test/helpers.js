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

// ---------------------------------------------------------------------------
// v2: the blinded directory.
//
// A reference implementation of the client half, mirroring internal/phonebook.
// If these and the Go client ever disagree about a derivation or a signing
// string, both test suites fail.
// ---------------------------------------------------------------------------

/** HKDF-SHA256 with a purpose label, matching internal/phonebook/handle.go. */
async function hkdf(ikm, label, length) {
	const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
	const bits = await crypto.subtle.deriveBits(
		{ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(label) },
		key,
		length * 8,
	);
	return new Uint8Array(bits);
}

/** The blinded row key for a CMD-Chat ID. */
export async function handleFor(id) {
	const raw = await hkdf(new TextEncoder().encode(id), 'cmd-chat phonebook v2 handle', 16);
	return base32(raw);
}

/**
 * The write keypair.
 *
 * The real client derives this from the identity's Ed25519 seed. WebCrypto will
 * not export a raw Ed25519 private key, so the tests generate an independent
 * keypair instead: the Worker only ever sees the public half and cannot tell the
 * difference, and unlinkability is asserted directly in the Go tests where the
 * seed is reachable.
 */
export async function makeWriteKey() {
	const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
	const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
	return { privateKey: pair.privateKey, publicKeyBytes, publicKey: toBase64(publicKeyBytes) };
}

/** A peer in the v2 directory: an ID, its handle, and a write key. */
export async function makeV2Peer() {
	const identity = await makeIdentity();
	const writeKey = await makeWriteKey();
	return { ...identity, writeKey, handle: await handleFor(identity.id) };
}

async function signV2(writeKey, method, path, issuedAt, rawBody) {
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rawBody)));
	const message = new TextEncoder().encode(
		['cmd-chat-phonebook/v2', method.toUpperCase(), path, String(issuedAt), toHex(digest)].join('\n'),
	);
	return toBase64(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, writeKey.privateKey, message)));
}

/** Sends a v2 signed request. Options mirror signedFetch. */
export async function signedFetchV2(peer, method, path, body, options = {}) {
	const raw = JSON.stringify(body);
	const signer = options.signAs ?? peer.writeKey;
	const signature = options.signature ?? (await signV2(signer, method, options.signPath ?? path, body.issued_at, options.signBody ?? raw));

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

/**
 * A stand-in sealed entry.
 *
 * The Worker must treat this as opaque, so the tests deliberately do not encrypt
 * anything real: any base64 of the right shape must be stored and returned
 * unchanged. That is the property under test.
 */
export function sealedBlob(marker = 'entry') {
	const padded = `${marker}`.padEnd(64, '.');
	return toBase64(new TextEncoder().encode(padded));
}

export async function publishV2(peer, overrides = {}, options = {}) {
	const body = {
		handle: peer.handle,
		write_key: peer.writeKey.publicKey,
		issued_at: nextIssuedAt(),
		sealed: sealedBlob(),
		...overrides,
	};
	return signedFetchV2(peer, 'POST', '/v2/publish', body, options);
}

export async function touchV2(peer, overrides = {}, options = {}) {
	const body = { handle: peer.handle, write_key: peer.writeKey.publicKey, issued_at: nextIssuedAt(), ...overrides };
	return signedFetchV2(peer, 'POST', '/v2/touch', body, options);
}

export async function deleteV2(peer, overrides = {}, options = {}) {
	const path = options.path ?? `/v2/entry/${peer.handle}`;
	const body = { handle: peer.handle, write_key: peer.writeKey.publicKey, issued_at: nextIssuedAt(), ...overrides };
	return signedFetchV2(peer, 'DELETE', path, body, options);
}

export async function entryV2(handle) {
	return SELF.fetch(`https://phonebook.test/v2/entry/${handle}`);
}
