/**
 * Tunables for the CMD-Chat phonebook.
 *
 * Nothing secret lives here. The only secret the Worker uses is IP_HASH_SALT,
 * which is supplied as a Worker secret / .dev.vars binding.
 */

/** Wire-protocol version this Worker speaks. */
export const PROTOCOL_VERSION = 1;

/** Domain-separation prefix for v1 signed requests (legacy endpoints). */
export const SIGNING_PREFIX = 'cmd-chat-phonebook/v1';

/**
 * Domain-separation prefix for v2 signed requests.
 *
 * A v1 signature can never be accepted as a v2 one, or the reverse: the prefix
 * is the first line of the signed string, and the two protocols use different
 * keys for different purposes.
 */
export const SIGNING_PREFIX_V2 = 'cmd-chat-phonebook/v2';

/** How long a v1 registration stays visible after its last heartbeat (seconds). */
export const REGISTRATION_TTL_SECONDS = 300;

/**
 * How long a v2 entry stays visible after its last heartbeat, in seconds.
 *
 * Longer than v1 on purpose. The client heartbeats every TTL/3, so this is
 * directly a divisor on how many rows the directory writes: 900 means one write
 * every five minutes per online host instead of one every hundred seconds.
 *
 * The cost is that a peer which drops off can stay listed for up to this long,
 * so a guest may try a dead address before falling back. The connection strategy
 * already handles that — every direct candidate is raced with a short timeout and
 * the relay is the backstop — so the trade is a slightly slower first attempt in
 * exchange for a third of the writes.
 */
export const ENTRY_TTL_SECONDS = 900;

/**
 * Maximum accepted sealed entry length, in base64 characters.
 *
 * Deliberately below MAX_BODY_BYTES so this check is the one that fires on an
 * oversized entry, rather than the blunt body-size guard. A real entry is around
 * 900 characters: eight candidates, a fingerprint and two version numbers.
 *
 * This is the base64 length; the Go client caps the raw sealed bytes at 2048,
 * which encodes to 2732 characters.
 */
export const MAX_SEALED_CHARS = 2800;

/**
 * How long a revoked (deleted) registration is kept as a tombstone before it is
 * garbage collected, in seconds. The tombstone exists purely so an old signed
 * `register` payload cannot be replayed to resurrect the entry.
 */
export const TOMBSTONE_TTL_SECONDS = 3600;

/** Maximum accepted request body, in bytes. */
export const MAX_BODY_BYTES = 4096;

/** Maximum NAT-traversal candidates accepted per registration. */
export const MAX_CANDIDATES = 8;

/** Accepted clock skew for a signed request's `issued_at`, in milliseconds. */
export const MAX_CLOCK_SKEW_MS = 120_000;

/** Rows deleted per opportunistic garbage-collection pass. */
export const GC_BATCH_SIZE = 200;

/** Fixed-window rate limits: [max requests, window seconds]. */
export const RATE_LIMITS = {
	register: { ip: [20, 60], id: [10, 60] },
	heartbeat: { ip: [120, 60], id: [60, 60] },
	lookup: { ip: [120, 60], id: null },
	delete: { ip: [10, 60], id: [5, 60] },
};
