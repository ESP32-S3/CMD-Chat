/**
 * Small HTTP helpers. Every response this Worker emits is JSON.
 */

import { MAX_BODY_BYTES } from './config.js';

const CORS_HEADERS = {
	'access-control-allow-origin': '*',
	'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
	'access-control-allow-headers': 'content-type, x-cmdchat-signature',
	'access-control-max-age': '86400',
};

const BASE_HEADERS = {
	'content-type': 'application/json; charset=utf-8',
	'cache-control': 'no-store',
	'referrer-policy': 'no-referrer',
	'x-content-type-options': 'nosniff',
	...CORS_HEADERS,
};

export function json(body, status = 200, extraHeaders = {}) {
	return new Response(JSON.stringify(body), { status, headers: { ...BASE_HEADERS, ...extraHeaders } });
}

export function ok(body = {}, status = 200) {
	return json({ ok: true, ...body }, status);
}

/**
 * Error responses carry a stable machine-readable `error` code plus a human
 * `message`. Codes are what the Go client switches on.
 */
export function fail(status, code, message, extra = {}) {
	return json({ ok: false, error: code, message, ...extra }, status);
}

export function preflight() {
	return new Response(null, { status: 204, headers: CORS_HEADERS });
}

/** Raised for any request we reject before touching the database. */
export class RequestError extends Error {
	constructor(status, code, message, extra = {}) {
		super(message);
		this.status = status;
		this.code = code;
		this.extra = extra;
	}

	toResponse() {
		return fail(this.status, this.code, this.message, this.extra);
	}
}

export function badRequest(code, message, extra = {}) {
	return new RequestError(400, code, message, extra);
}

/**
 * Reads the raw request body with a hard size cap, then parses it as JSON.
 *
 * Returns both the parsed object and the exact bytes that were read: the
 * signature is computed over those bytes, so we must not re-serialise.
 */
export async function readJsonBody(request) {
	const declared = request.headers.get('content-length');
	if (declared !== null) {
		const n = Number(declared);
		if (!Number.isFinite(n) || n < 0) throw badRequest('bad_content_length', 'Malformed Content-Length header.');
		if (n > MAX_BODY_BYTES) throw new RequestError(413, 'body_too_large', `Request body exceeds ${MAX_BODY_BYTES} bytes.`);
	}

	const contentType = (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
	if (contentType !== 'application/json') {
		throw new RequestError(415, 'unsupported_media_type', 'Content-Type must be application/json.');
	}

	const raw = new Uint8Array(await request.arrayBuffer());
	// Content-Length can lie (or be absent under chunked encoding), so the
	// real enforcement is here, on the bytes we actually received.
	if (raw.byteLength > MAX_BODY_BYTES) {
		throw new RequestError(413, 'body_too_large', `Request body exceeds ${MAX_BODY_BYTES} bytes.`);
	}
	if (raw.byteLength === 0) throw badRequest('empty_body', 'Request body is required.');

	let parsed;
	try {
		parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
	} catch {
		throw badRequest('malformed_json', 'Request body is not valid UTF-8 JSON.');
	}

	if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
		throw badRequest('malformed_json', 'Request body must be a JSON object.');
	}

	return { body: parsed, raw };
}
