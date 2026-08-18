/**
 * Input validation.
 *
 * Every field that reaches SQL is validated here first. Unknown fields are a
 * hard error rather than being silently ignored, so a client cannot smuggle
 * extra columns ("arbitrary field injection") past the schema.
 */

import { MAX_CANDIDATES, MAX_CLOCK_SKEW_MS } from './config.js';
import { CMD_CHAT_ID_RE, PUBLIC_KEY_RE } from './identity.js';
import { badRequest } from './http.js';

const CLIENT_VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$/;
const FINGERPRINT_RE = /^[0-9a-f]{64}$/;
const CANDIDATE_KINDS = new Set(['host', 'server_reflexive', 'server_reflexive_http', 'relay']);
const TRANSPORTS = new Set(['tcp', 'udp']);

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** Rejects any property on `obj` that is not in `allowed`. */
export function rejectUnknownFields(obj, allowed, where) {
	for (const key of Object.keys(obj)) {
		if (!allowed.has(key)) throw badRequest('unknown_field', `Unexpected field '${key}' in ${where}.`);
	}
}

export function assertCmdChatId(value, field = 'id') {
	if (typeof value !== 'string' || !CMD_CHAT_ID_RE.test(value)) {
		throw badRequest('invalid_id', `'${field}' must look like cc- followed by 16 base32 characters.`);
	}
	return value;
}

export function assertPublicKey(value, field = 'public_key') {
	if (typeof value !== 'string' || !PUBLIC_KEY_RE.test(value)) {
		throw badRequest(field === 'public_key' ? 'invalid_public_key' : 'invalid_write_key', `'${field}' must be a base64-encoded 32-byte Ed25519 public key.`);
	}
	return value;
}

/**
 * Guards against a client accidentally (or a caller maliciously) posting key
 * material that must never reach this service.
 */
export function assertNoSecretMaterial(body) {
	const forbidden = ['private_key', 'privateKey', 'secret_key', 'secretKey', 'seed', 'password', 'passphrase', 'token'];
	for (const name of forbidden) {
		if (name in body) throw badRequest('secret_material_rejected', `Field '${name}' must never be sent to the phonebook.`);
	}
}

export function assertIssuedAt(value, now = Date.now()) {
	if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
		throw badRequest('invalid_issued_at', "'issued_at' must be a positive integer (unix milliseconds).");
	}
	if (Math.abs(now - value) > MAX_CLOCK_SKEW_MS) {
		throw badRequest('clock_skew', "'issued_at' is too far from server time; check the client clock.", { server_time: now });
	}
	return value;
}

export function assertProtocolVersion(value) {
	if (value === undefined) return 1;
	if (!Number.isInteger(value) || value < 1 || value > 255) {
		throw badRequest('invalid_protocol_version', "'protocol_version' must be an integer between 1 and 255.");
	}
	return value;
}

export function assertClientVersion(value) {
	if (value === undefined || value === null) return null;
	if (typeof value !== 'string' || !CLIENT_VERSION_RE.test(value)) {
		throw badRequest('invalid_client_version', "'client_version' must be <=32 chars of [A-Za-z0-9._+-].");
	}
	return value;
}

export function assertFingerprint(value) {
	if (value === undefined || value === null) return null;
	if (typeof value !== 'string' || !FINGERPRINT_RE.test(value)) {
		throw badRequest('invalid_fingerprint', "'session_fingerprint' must be 64 lowercase hex characters.");
	}
	return value;
}

/** Validates an IPv4 or IPv6 literal and returns it normalised to lower case. */
export function normaliseAddress(value) {
	if (typeof value !== 'string' || value.length < 3 || value.length > 45) return null;
	if (IPV4_RE.test(value)) {
		if (value === '0.0.0.0' || value === '255.255.255.255') return null;
		return value;
	}
	const lowered = value.toLowerCase();
	if (!isIpv6(lowered)) return null;
	if (lowered === '::' || lowered.startsWith('ff')) return null; // unspecified / multicast
	return lowered;
}

function isIpv6(value) {
	if (!/^[0-9a-f:.]+$/.test(value)) return false;
	const doubleColons = value.split('::').length - 1;
	if (doubleColons > 1) return false;

	let head = value;
	let tailIpv4Groups = 0;
	const lastColon = value.lastIndexOf(':');
	const trailer = value.slice(lastColon + 1);
	if (trailer.includes('.')) {
		if (!IPV4_RE.test(trailer)) return false;
		head = value.slice(0, lastColon + 1) + '0';
		tailIpv4Groups = 1; // the embedded IPv4 stands in for two 16-bit groups
	}

	const [left, right] = doubleColons === 1 ? head.split('::') : [head, null];
	const leftGroups = left === '' ? [] : left.split(':');
	const rightGroups = right === undefined || right === null || right === '' ? [] : right.split(':');
	for (const group of [...leftGroups, ...rightGroups]) {
		if (!/^[0-9a-f]{1,4}$/.test(group)) return false;
	}

	const total = leftGroups.length + rightGroups.length + tailIpv4Groups;
	return doubleColons === 1 ? total <= 7 : total === 8;
}

/**
 * Validates the NAT-traversal candidate list.
 *
 * Candidates are the only network addresses this service stores, and they are
 * replaced wholesale on every register, never merged.
 */
export function assertCandidates(value) {
	if (!Array.isArray(value)) throw badRequest('invalid_candidates', "'candidates' must be an array.");
	if (value.length === 0) throw badRequest('invalid_candidates', 'At least one connection candidate is required.');
	if (value.length > MAX_CANDIDATES) {
		throw badRequest('too_many_candidates', `At most ${MAX_CANDIDATES} candidates may be registered.`);
	}

	const allowed = new Set(['kind', 'transport', 'address', 'port', 'priority']);
	const seen = new Set();
	const out = [];

	for (const [index, raw] of value.entries()) {
		if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
			throw badRequest('invalid_candidates', `Candidate ${index} must be an object.`);
		}
		rejectUnknownFields(raw, allowed, `candidate ${index}`);

		if (!CANDIDATE_KINDS.has(raw.kind)) {
			throw badRequest('invalid_candidate_kind', `Candidate ${index} has an unsupported 'kind'.`);
		}
		if (raw.kind === 'relay') {
			// There is no relay in this architecture yet; accepting relay
			// candidates would imply a fallback that does not exist.
			throw badRequest('relay_unsupported', 'Relay candidates are not supported: CMD-Chat has no relay server.');
		}
		if (!TRANSPORTS.has(raw.transport)) {
			throw badRequest('invalid_candidate_transport', `Candidate ${index} must use transport 'tcp' or 'udp'.`);
		}

		const address = normaliseAddress(raw.address);
		if (address === null) throw badRequest('invalid_candidate_address', `Candidate ${index} has an invalid IP address.`);

		let port = null;
		if (raw.port !== undefined && raw.port !== null) {
			if (!Number.isInteger(raw.port) || raw.port < 1 || raw.port > 65535) {
				throw badRequest('invalid_candidate_port', `Candidate ${index} has an invalid port.`);
			}
			port = raw.port;
		}
		if (port === null && raw.kind !== 'server_reflexive_http') {
			throw badRequest('invalid_candidate_port', `Candidate ${index} requires a port.`);
		}

		let priority = 0;
		if (raw.priority !== undefined && raw.priority !== null) {
			if (!Number.isInteger(raw.priority) || raw.priority < 0 || raw.priority > 65535) {
				throw badRequest('invalid_candidate_priority', `Candidate ${index} has an invalid priority.`);
			}
			priority = raw.priority;
		}

		const dedupeKey = `${raw.kind}|${raw.transport}|${address}|${port}`;
		if (seen.has(dedupeKey)) throw badRequest('duplicate_candidate', `Candidate ${index} duplicates an earlier candidate.`);
		seen.add(dedupeKey);

		out.push({ kind: raw.kind, transport: raw.transport, address, port, priority });
	}

	return out;
}


/**
 * A v2 directory handle: exactly 26 RFC4648 base32 characters.
 *
 * This is HKDF(CMD-Chat ID) truncated to 128 bits, computed by the client. The
 * Worker cannot derive or verify it against anything — that is the entire point —
 * so all it can do is insist on the shape, which keeps the primary key
 * well-formed and bounded.
 */
export function assertHandle(value, field = 'handle') {
	if (typeof value !== 'string') throw badRequest('invalid_handle', `'${field}' must be a string.`);
	if (!/^[A-Z2-7]{26}$/.test(value)) {
		throw badRequest('invalid_handle', `'${field}' must be 26 base32 characters (A-Z, 2-7).`);
	}
	return value;
}

/**
 * A sealed entry: canonical base64, bounded.
 *
 * The Worker never opens this and must never try. It checks the encoding so a
 * malformed blob cannot be stored and served back to every reader, and the
 * length so the directory cannot be used as free storage.
 */
export function assertSealed(value, maxChars) {
	if (typeof value !== 'string') throw badRequest('invalid_sealed', "'sealed' must be a string.");
	if (value.length < 48 || value.length > maxChars) {
		throw badRequest('invalid_sealed', `'sealed' must be between 48 and ${maxChars} characters.`);
	}
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
		throw badRequest('invalid_sealed', "'sealed' must be canonical base64.");
	}
	return value;
}
