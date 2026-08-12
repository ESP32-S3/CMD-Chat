/**
 * Tunables for the CMD-Chat phonebook.
 *
 * Nothing secret lives here. The only secret the Worker uses is IP_HASH_SALT,
 * which is supplied as a Worker secret / .dev.vars binding.
 */

/** Wire-protocol version this Worker speaks. */
export const PROTOCOL_VERSION = 1;

/** Domain-separation prefix for every signed request. */
export const SIGNING_PREFIX = 'cmd-chat-phonebook/v1';

/** How long a registration stays visible after its last heartbeat (seconds). */
export const REGISTRATION_TTL_SECONDS = 300;

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
