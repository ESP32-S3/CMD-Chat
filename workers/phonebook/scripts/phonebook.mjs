#!/usr/bin/env node
/**
 * Command-line reference client for the CMD-Chat phonebook.
 *
 * This exists to exercise the real HTTP surface (local `wrangler dev` and
 * production) with genuine Ed25519 signatures, and to serve as the executable
 * spec that the Go client is ported from.
 *
 * It never transmits a private key. Signing happens locally; only the public
 * key and the signature go over the wire.
 *
 *   node scripts/phonebook.mjs health          --url <base>
 *   node scripts/phonebook.mjs identity                                   # make a throwaway identity
 *   node scripts/phonebook.mjs register        --url <base> --identity <file> [--port N]
 *   node scripts/phonebook.mjs lookup <cc-id>  --url <base>
 *   node scripts/phonebook.mjs heartbeat       --url <base> --identity <file>
 *   node scripts/phonebook.mjs delete          --url <base> --identity <file>
 */

import { createHash, generateKeyPairSync, createPrivateKey, sign as edSign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const SIGNING_PREFIX = 'cmd-chat-phonebook/v1';

// PKCS#8 prefix for a raw Ed25519 seed, so a CMD-Chat identity.json private key
// can be loaded directly by node:crypto.
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function base32(buf) {
	let bits = 0;
	let value = 0;
	let out = '';
	for (const byte of buf) {
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

function deriveId(publicKeyRaw) {
	return `cc-${base32(createHash('sha256').update(publicKeyRaw).digest().subarray(0, 10))}`;
}

function privateKeyFromSeed(seed) {
	return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: 'der', type: 'pkcs8' });
}

function newIdentity() {
	const { privateKey, publicKey } = generateKeyPairSync('ed25519');
	const spki = publicKey.export({ type: 'spki', format: 'der' });
	const raw = Buffer.from(spki.subarray(spki.length - 32));
	const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' });
	const seed = Buffer.from(pkcs8.subarray(pkcs8.length - 32));
	// Matches the CMD-Chat identity.json layout: 64-byte Ed25519 private key
	// (seed || public), 32-byte public key, derived id.
	return {
		private_key: Buffer.concat([seed, raw]).toString('base64'),
		public_key: raw.toString('base64'),
		id: deriveId(raw),
	};
}

function loadIdentity(file) {
	const parsed = JSON.parse(readFileSync(file, 'utf8'));
	const priv = Buffer.from(parsed.private_key, 'base64');
	const seed = priv.length === 64 ? priv.subarray(0, 32) : priv;
	const publicKeyRaw = Buffer.from(parsed.public_key, 'base64');
	const derived = deriveId(publicKeyRaw);
	if (parsed.id && parsed.id !== derived) throw new Error(`identity.json id ${parsed.id} does not match derived ${derived}`);
	return { key: privateKeyFromSeed(seed), publicKey: parsed.public_key, id: derived };
}

let lastIssuedAt = 0;
function nextIssuedAt() {
	lastIssuedAt = Math.max(Date.now(), lastIssuedAt + 1);
	return lastIssuedAt;
}

function signRequest(identity, method, path, issuedAt, rawBody) {
	const bodyHash = createHash('sha256').update(rawBody).digest('hex');
	const message = Buffer.from([SIGNING_PREFIX, method.toUpperCase(), path, String(issuedAt), bodyHash].join('\n'), 'utf8');
	return edSign(null, message, identity.key).toString('base64');
}

async function call(base, method, path, body, identity) {
	const headers = {};
	let raw;
	if (body !== undefined) {
		raw = JSON.stringify(body);
		headers['content-type'] = 'application/json';
		headers['x-cmdchat-signature'] = signRequest(identity, method, path, body.issued_at, raw);
	}
	const res = await fetch(new URL(path, base), { method, headers, body: raw });
	const text = await res.text();
	let parsed;
	try {
		parsed = JSON.parse(text);
	} catch {
		parsed = { raw: text };
	}
	return { status: res.status, body: parsed };
}

function arg(name, fallback) {
	const i = process.argv.indexOf(`--${name}`);
	return i === -1 ? fallback : process.argv[i + 1];
}

const command = process.argv[2];
const base = arg('url', 'http://127.0.0.1:8787');
const identityFile = arg('identity');

function report(label, result) {
	console.log(`${label}  ->  HTTP ${result.status}`);
	console.log(JSON.stringify(result.body, null, 2));
	console.log();
	return result;
}

const commands = {
	async identity() {
		const created = newIdentity();
		const out = arg('out');
		if (out) {
			writeFileSync(out, `${JSON.stringify(created, null, 2)}\n`);
			console.log(`wrote ${out}  id=${created.id}`);
		} else {
			console.log(JSON.stringify(created, null, 2));
		}
	},

	async health() {
		report('GET /health', await call(base, 'GET', '/health'));
	},

	async stun() {
		report('GET /stun', await call(base, 'GET', '/stun'));
	},

	async register() {
		const id = loadIdentity(identityFile);
		const port = Number(arg('port', '38556'));
		const body = {
			id: id.id,
			public_key: id.publicKey,
			issued_at: nextIssuedAt(),
			session_fingerprint: createHash('sha256').update(`session|${Date.now()}`).digest('hex'),
			protocol_version: 1,
			client_version: arg('client-version', '0.1.0'),
			candidates: [
				{ kind: 'host', transport: 'tcp', address: arg('host-address', '192.168.1.42'), port, priority: 100 },
				{ kind: 'server_reflexive', transport: 'udp', address: arg('reflexive-address', '203.0.113.9'), port: port + 1, priority: 200 },
			],
		};
		report(`POST /register (${id.id})`, await call(base, 'POST', '/register', body, id));
	},

	async lookup() {
		const target = process.argv[3];
		report(`GET /lookup/${target}`, await call(base, 'GET', `/lookup/${target}`));
	},

	async heartbeat() {
		const id = loadIdentity(identityFile);
		const body = { id: id.id, public_key: id.publicKey, issued_at: nextIssuedAt() };
		report(`POST /heartbeat (${id.id})`, await call(base, 'POST', '/heartbeat', body, id));
	},

	async delete() {
		const id = loadIdentity(identityFile);
		const body = { id: id.id, public_key: id.publicKey, issued_at: nextIssuedAt() };
		report(`DELETE /register/${id.id}`, await call(base, 'DELETE', `/register/${id.id}`, body, id));
	},
};

const handler = commands[command];
if (!handler) {
	console.error(`unknown command: ${command ?? '(none)'}`);
	console.error('commands: identity | health | stun | register | lookup | heartbeat | delete');
	process.exit(2);
}

await handler();
