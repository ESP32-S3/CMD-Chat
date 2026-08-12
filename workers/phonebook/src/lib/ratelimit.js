/**
 * Coarse fixed-window rate limiting backed by D1.
 *
 * This is deliberately cheap rather than exact: the goal is to make automated
 * registration/heartbeat floods expensive, not to be a precise quota system.
 * Buckets never contain a raw IP address — only a salted hash of one.
 */

import { RATE_LIMITS } from './config.js';
import { bytesToHex, sha256 } from './identity.js';
import { fail } from './http.js';

/**
 * Salted, truncated hash of the caller IP.
 *
 * The salt is a Worker secret, so the stored value is not reversible by
 * enumerating the (small) IPv4 space with an offline dictionary.
 */
export async function hashClientIp(ip, salt) {
	if (!ip) return 'unknown';
	const digest = await sha256(new TextEncoder().encode(`${salt}|${ip}`));
	return bytesToHex(digest.subarray(0, 12));
}

async function bump(db, bucket, windowSeconds, nowSeconds) {
	const windowStart = Math.floor(nowSeconds / windowSeconds) * windowSeconds;
	const row = await db
		.prepare(
			`INSERT INTO rate_limits (bucket, window_start, count)
			 VALUES (?1, ?2, 1)
			 ON CONFLICT(bucket) DO UPDATE SET
			   count = CASE WHEN rate_limits.window_start = excluded.window_start THEN rate_limits.count + 1 ELSE 1 END,
			   window_start = excluded.window_start
			 RETURNING count, window_start`,
		)
		.bind(bucket, windowStart)
		.first();
	return { count: row?.count ?? 1, windowStart, windowSeconds };
}

/**
 * Applies the IP-scoped and (optionally) ID-scoped limits for an operation.
 *
 * @returns {Response|null} a 429 response when the caller is over the limit.
 */
export async function enforceRateLimit(db, operation, { ipHash, id }, nowSeconds = Math.floor(Date.now() / 1000)) {
	const rules = RATE_LIMITS[operation];
	if (!rules) return null;

	const checks = [];
	if (rules.ip) checks.push({ bucket: `${operation}:ip:${ipHash}`, limit: rules.ip[0], window: rules.ip[1] });
	if (rules.id && id) checks.push({ bucket: `${operation}:id:${id}`, limit: rules.id[0], window: rules.id[1] });

	for (const check of checks) {
		const { count, windowStart, windowSeconds } = await bump(db, check.bucket, check.window, nowSeconds);
		if (count > check.limit) {
			const retryAfter = Math.max(1, windowStart + windowSeconds - nowSeconds);
			return fail(429, 'rate_limited', 'Too many requests; slow down.', { retry_after: retryAfter });
		}
	}

	return null;
}
