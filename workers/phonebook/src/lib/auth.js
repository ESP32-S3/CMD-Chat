/**
 * Request authentication.
 *
 * CMD-Chat already has a cryptographic identity system (Ed25519 + an ID that is
 * a hash of the public key), so the phonebook reuses it rather than inventing
 * anything: a mutating request is authorised iff
 *
 *   1. the supplied public key hashes to the CMD-Chat ID being modified, and
 *   2. the request carries a valid Ed25519 signature by that key over
 *      prefix | METHOD | path | issued_at | sha256(body), and
 *   3. `issued_at` is within the allowed clock skew, and
 *   4. `issued_at` is strictly newer than the last request accepted for that ID.
 *
 * (1) means no one can register or mutate an ID they do not hold the key for.
 * (2) means the body cannot be tampered with in flight.
 * (3) + (4) together kill replay: an old capture is either outside the skew
 * window or not monotonically newer.
 */

import { RequestError } from './http.js';
import { bytesToHex, decodeBase64Strict, deriveCmdChatId, sha256, signingString, signingStringV2, verifyEd25519 } from './identity.js';
import { assertCmdChatId, assertHandle, assertIssuedAt, assertPublicKey } from './validate.js';

export const SIGNATURE_HEADER = 'x-cmdchat-signature';

/**
 * Verifies the signature envelope shared by /register, /heartbeat and DELETE.
 *
 * @returns {{ id: string, publicKey: string, publicKeyBytes: Uint8Array, issuedAt: number }}
 */
export async function authenticate(request, path, body, raw, now = Date.now()) {
	const id = assertCmdChatId(body.id);
	const publicKey = assertPublicKey(body.public_key);
	const issuedAt = assertIssuedAt(body.issued_at, now);

	const publicKeyBytes = decodeBase64Strict(publicKey, 32);
	if (publicKeyBytes === null) {
		throw new RequestError(400, 'invalid_public_key', 'public_key is not canonical base64 of 32 bytes.');
	}

	// The ID is a commitment to the key: this is what stops one user from
	// registering or deleting another user's entry.
	const derived = await deriveCmdChatId(publicKeyBytes);
	if (derived !== id) {
		throw new RequestError(403, 'id_key_mismatch', 'public_key does not derive the supplied CMD-Chat ID.');
	}

	const signatureHeader = request.headers.get(SIGNATURE_HEADER);
	if (!signatureHeader) {
		throw new RequestError(401, 'missing_signature', `Missing ${SIGNATURE_HEADER} header.`);
	}
	const signatureBytes = decodeBase64Strict(signatureHeader.trim(), 64);
	if (signatureBytes === null) {
		throw new RequestError(401, 'invalid_signature', 'Signature must be canonical base64 of 64 bytes.');
	}

	const bodyHashHex = bytesToHex(await sha256(raw));
	const message = new TextEncoder().encode(signingString(request.method, path, issuedAt, bodyHashHex));

	if (!(await verifyEd25519(publicKeyBytes, signatureBytes, message))) {
		throw new RequestError(401, 'invalid_signature', 'Ed25519 signature verification failed.');
	}

	return { id, publicKey, publicKeyBytes, issuedAt };
}

/**
 * Enforces strict monotonicity of `issued_at` per registration.
 *
 * `lastIssuedAt` is read from the row inside the same request, so a replayed
 * capture of a previously-accepted request is rejected even if it is still
 * inside the clock-skew window.
 */
export function assertNotReplay(issuedAt, lastIssuedAt) {
	if (lastIssuedAt !== null && lastIssuedAt !== undefined && issuedAt <= lastIssuedAt) {
		throw new RequestError(409, 'replayed_request', 'issued_at must be strictly newer than the last accepted request.');
	}
}


/**
 * Verifies the signature envelope for the blinded v2 endpoints.
 *
 * The difference from `authenticate` is what is NOT checked, and why.
 *
 * v1 verified that the supplied public key hashed to the CMD-Chat ID being
 * modified, which is what made it impossible to touch someone else's row. A
 * directory that does not know the ID cannot make that check — and not knowing
 * the ID is the whole purpose of v2.
 *
 * So authorisation here is:
 *
 *   1. the request carries a valid Ed25519 signature by `write_key` over
 *      prefix | METHOD | path | issued_at | sha256(body),
 *   2. `issued_at` is inside the clock-skew window and strictly newer than the
 *      last accepted request for this handle, and
 *   3. the handle either has no owner yet, or its stored `write_key` is exactly
 *      this one. That check lives at the call site, next to the row it read.
 *
 * (1) means a request cannot be tampered with in flight and cannot be produced
 * by anyone without the derived write key. (2) kills replay. (3) is
 * first-writer-wins, and the trade it represents is documented in
 * migrations/0002_blinded_entries.sql.
 *
 * @returns {{ handle: string, writeKey: string, writeKeyBytes: Uint8Array, issuedAt: number }}
 */
export async function authenticateV2(request, path, body, raw, now = Date.now()) {
	const handle = assertHandle(body.handle);
	const writeKey = assertPublicKey(body.write_key, 'write_key');
	const issuedAt = assertIssuedAt(body.issued_at, now);

	const writeKeyBytes = decodeBase64Strict(writeKey, 32);
	if (writeKeyBytes === null) {
		throw new RequestError(400, 'invalid_write_key', 'write_key is not canonical base64 of 32 bytes.');
	}

	const signatureHeader = request.headers.get(SIGNATURE_HEADER);
	if (!signatureHeader) {
		throw new RequestError(401, 'missing_signature', `Missing ${SIGNATURE_HEADER} header.`);
	}
	const signatureBytes = decodeBase64Strict(signatureHeader.trim(), 64);
	if (signatureBytes === null) {
		throw new RequestError(401, 'invalid_signature', 'Signature must be canonical base64 of 64 bytes.');
	}

	const bodyHashHex = bytesToHex(await sha256(raw));
	const message = new TextEncoder().encode(signingStringV2(request.method, path, issuedAt, bodyHashHex));

	if (!(await verifyEd25519(writeKeyBytes, signatureBytes, message))) {
		throw new RequestError(401, 'invalid_signature', 'Ed25519 signature verification failed.');
	}

	return { handle, writeKey, writeKeyBytes, issuedAt };
}

/**
 * Enforces that a handle is owned by exactly one write key.
 *
 * Called with the row the request already had to read to check for replay, so it
 * costs nothing extra.
 */
export function assertHandleOwner(existing, writeKey) {
	if (existing && existing.write_key !== writeKey) {
		throw new RequestError(
			403,
			'handle_claimed',
			'This directory handle is already claimed by a different key.',
		);
	}
}
