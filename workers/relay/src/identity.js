/**
 * CMD-Chat identity verification for the relay.
 *
 * Identical scheme to the phonebook, deliberately: CMD-Chat already has an
 * Ed25519 identity system where the user-visible ID is a hash of the public
 * key, so the relay reuses it rather than introducing a second notion of who
 * a peer is.
 *
 *   cmd_chat_id = 'cc-' + base32(sha256(ed25519_public_key)[0..9])
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export const CMD_CHAT_ID_RE = /^cc-[A-Z2-7]{16}$/;
export const PUBLIC_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;

/** Domain separation: a relay signature can never be replayed as a phonebook one. */
export const SIGNING_PREFIX = 'cmd-chat-relay/v1';

/** Accepted clock skew for a join request, in milliseconds. */
export const MAX_CLOCK_SKEW_MS = 120_000;

function base32Encode(bytes) {
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
	if (btoa(binary) !== input) return null;
	return bytes;
}

export async function deriveCmdChatId(publicKeyBytes) {
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKeyBytes));
	return `cc-${base32Encode(digest.subarray(0, 10))}`;
}

/**
 * The string a peer signs to join a relay session.
 *
 * `session` is bound in, so a signature captured for one session cannot be used
 * to join another, and `role` is bound in so a guest signature cannot be
 * replayed to claim the host slot.
 */
export function signingString(role, session, id, issuedAt) {
	return [SIGNING_PREFIX, role, session, id, String(issuedAt)].join('\n');
}

export async function verifyEd25519(publicKeyBytes, signatureBytes, message) {
	let key;
	try {
		key = await crypto.subtle.importKey('raw', publicKeyBytes, { name: 'Ed25519' }, false, ['verify']);
	} catch {
		return false;
	}
	try {
		return await crypto.subtle.verify({ name: 'Ed25519' }, key, signatureBytes, message);
	} catch {
		return false;
	}
}

/**
 * Authenticates a relay join request.
 *
 * Returns { id, role } on success or { error, message } on failure. The caller
 * turns a failure into an HTTP response; nothing here throws.
 */
export async function authenticateJoin(headers, session, now = Date.now()) {
	const role = headers.get('x-cmdchat-role');
	if (role !== 'host' && role !== 'guest') {
		return { error: 'invalid_role', message: "Role must be 'host' or 'guest'." };
	}
	if (!CMD_CHAT_ID_RE.test(session)) {
		return { error: 'invalid_session', message: 'Session must be a CMD-Chat ID.' };
	}

	const id = headers.get('x-cmdchat-id') || '';
	if (!CMD_CHAT_ID_RE.test(id)) {
		return { error: 'invalid_id', message: 'Missing or malformed X-CmdChat-Id.' };
	}

	const publicKey = headers.get('x-cmdchat-publickey') || '';
	if (!PUBLIC_KEY_RE.test(publicKey)) {
		return { error: 'invalid_public_key', message: 'Missing or malformed X-CmdChat-PublicKey.' };
	}
	const publicKeyBytes = decodeBase64Strict(publicKey, 32);
	if (publicKeyBytes === null) {
		return { error: 'invalid_public_key', message: 'Public key is not canonical base64 of 32 bytes.' };
	}

	// The ID is a commitment to the key: this is what stops a peer claiming an
	// identity, or a host slot, that is not theirs.
	if ((await deriveCmdChatId(publicKeyBytes)) !== id) {
		return { error: 'id_key_mismatch', message: 'Public key does not derive the supplied CMD-Chat ID.' };
	}

	// A session is named after its host, so only the host's key can take the
	// host slot. Without this, anyone could squat another user's session and
	// intercept inbound guests.
	if (role === 'host' && id !== session) {
		return { error: 'not_session_owner', message: 'Only the session owner may join as host.' };
	}

	const issuedAt = Number(headers.get('x-cmdchat-issuedat'));
	if (!Number.isInteger(issuedAt) || issuedAt <= 0) {
		return { error: 'invalid_issued_at', message: 'Missing or malformed X-CmdChat-IssuedAt.' };
	}
	if (Math.abs(now - issuedAt) > MAX_CLOCK_SKEW_MS) {
		return { error: 'clock_skew', message: 'Request timestamp is too far from server time.' };
	}

	const signatureBytes = decodeBase64Strict((headers.get('x-cmdchat-signature') || '').trim(), 64);
	if (signatureBytes === null) {
		return { error: 'invalid_signature', message: 'Signature must be canonical base64 of 64 bytes.' };
	}

	const message = new TextEncoder().encode(signingString(role, session, id, issuedAt));
	if (!(await verifyEd25519(publicKeyBytes, signatureBytes, message))) {
		return { error: 'invalid_signature', message: 'Ed25519 signature verification failed.' };
	}

	return { id, role };
}
