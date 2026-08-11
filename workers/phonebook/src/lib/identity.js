/**
 * CMD-Chat identity primitives.
 *
 * These mirror the client's existing scheme exactly; nothing here is invented.
 * A CMD-Chat client stores an Ed25519 keypair and derives its public ID as:
 *
 *     cmd_chat_id = 'cc-' + base32(sha256(ed25519_public_key)[0..9])
 *
 * (RFC 4648 base32, uppercase, unpadded — 10 bytes -> exactly 16 characters.)
 *
 * Because the ID is a commitment to the public key, the Worker never needs a
 * password, API key or session token: possession of the private key IS the
 * authorisation, and the ID proves which key is allowed to speak for it.
 */

import { SIGNING_PREFIX } from './config.js';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export const CMD_CHAT_ID_RE = /^cc-[A-Z2-7]{16}$/;
export const PUBLIC_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;

/** RFC 4648 base32, uppercase, no padding. */
export function base32Encode(bytes) {
	let bits = 0;
	let value = 0;
	let out = '';
	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}
	if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
	return out;
}

export function bytesToHex(bytes) {
	let out = '';
	for (const b of bytes) out += b.toString(16).padStart(2, '0');
	return out;
}

/**
 * Strict base64 decode. Rejects anything that is not canonical standard-alphabet
 * base64 so that two different strings can never decode to the same key bytes.
 */
export function decodeBase64Strict(input, expectedBytes) {
	if (typeof input !== 'string') return null;
	let binary;
	try {
		binary = atob(input);
	} catch {
		return null;
	}
	const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
	if (expectedBytes !== undefined && bytes.byteLength !== expectedBytes) return null;
	// Re-encode and compare to reject non-canonical padding/whitespace variants.
	if (btoa(binary) !== input) return null;
	return bytes;
}

export async function sha256(bytes) {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/** Derives the canonical CMD-Chat ID for a raw 32-byte Ed25519 public key. */
export async function deriveCmdChatId(publicKeyBytes) {
	const digest = await sha256(publicKeyBytes);
	return `cc-${base32Encode(digest.subarray(0, 10))}`;
}

/**
 * Builds the string that a client signs. Kept deliberately simple and
 * line-oriented so the Go client can reproduce it byte-for-byte without a
 * canonical-JSON implementation.
 *
 *     cmd-chat-phonebook/v1\n
 *     <METHOD>\n
 *     <path>\n
 *     <issued_at_ms>\n
 *     <sha256hex(raw request body)>
 */
export function signingString(method, path, issuedAt, bodyHashHex) {
	return [SIGNING_PREFIX, method.toUpperCase(), path, String(issuedAt), bodyHashHex].join('\n');
}

/** Verifies an Ed25519 signature over `message` (both raw bytes). */
export async function verifyEd25519(publicKeyBytes, signatureBytes, message) {
	let key;
	try {
		key = await crypto.subtle.importKey('raw', publicKeyBytes, { name: 'Ed25519' }, false, ['verify']);
	} catch {
		// Malformed / off-curve key material.
		return false;
	}
	try {
		return await crypto.subtle.verify({ name: 'Ed25519' }, key, signatureBytes, message);
	} catch {
		return false;
	}
}
