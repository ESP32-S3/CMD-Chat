/**
 * CMD-Chat relay Worker.
 *
 * WHAT THIS IS
 *   A dumb, authenticated byte pipe between exactly two CMD-Chat peers that
 *   could not reach each other directly. Each peer opens a WebSocket to the
 *   same session; the Durable Object forwards binary frames from one to the
 *   other, unchanged and unexamined.
 *
 * WHAT THIS IS NOT
 *   A chat server. The relay carries the peers' existing TLS 1.3 session as
 *   opaque ciphertext: the CMD-Chat handshake runs end-to-end *inside* this
 *   pipe, so the relay holds none of the keys needed to read a message, and
 *   the guest still pins the host's TLS certificate fingerprint. A malicious
 *   or compromised relay can drop or delay bytes; it cannot read or forge them.
 *
 *   Nothing is stored. There is no database binding on this Worker at all, and
 *   no message ever touches disk.
 *
 *   Relaying is the last resort. Peers try LAN, then direct IPv6/IPv4, and
 *   only fall back here when every direct path fails.
 */

import { authenticateJoin } from './identity.js';

/** Hard ceiling on a single relayed session. */
const MAX_SESSION_MS = 30 * 60 * 1000;

/** How long a host may sit in a session with no guest before it is closed. */
const MAX_UNPAIRED_MS = 10 * 60 * 1000;

/** Total bytes a session may relay in each direction before it is cut off. */
const MAX_SESSION_BYTES = 32 * 1024 * 1024;

/** Largest single frame accepted; CMD-Chat messages are capped at 4 KiB. */
const MAX_FRAME_BYTES = 64 * 1024;

/** Concurrent relayed conversations one host may have. Bounds abuse. */
const MAX_PAIRS = 4;

/** Application close codes (4000-4999 is the range reserved for apps). */
const CLOSE_REPLACED = 4001;
const CLOSE_NO_HOST = 4002;
const CLOSE_SESSION_FULL = 4003;
const CLOSE_PEER_LEFT = 4004;
const CLOSE_LIMIT = 4005;
const CLOSE_EXPIRED = 4006;
const CLOSE_PROTOCOL = 4007;

const JSON_HEADERS = {
	'content-type': 'application/json; charset=utf-8',
	'cache-control': 'no-store',
	'x-content-type-options': 'nosniff',
};

function json(body, status = 200) {
	return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const path = url.pathname.replace(/\/+$/, '') || '/';

		if (path === '/' || path === '/health') {
			if (request.method !== 'GET') return json({ ok: false, error: 'method_not_allowed' }, 405);
			return json({
				ok: true,
				service: 'cmd-chat-relay',
				role: 'authenticated byte pipe; carries end-to-end encrypted traffic it cannot read',
				protocol_version: 1,
				max_session_seconds: MAX_SESSION_MS / 1000,
				max_session_bytes: MAX_SESSION_BYTES,
			});
		}

		if (!path.startsWith('/relay/')) return json({ ok: false, error: 'not_found' }, 404);

		if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
			return json({ ok: false, error: 'expected_websocket', message: 'This endpoint requires a WebSocket upgrade.' }, 426);
		}

		const session = decodeURIComponent(path.slice('/relay/'.length));
		const stub = env.RELAY_SESSION.get(env.RELAY_SESSION.idFromName(session));

		// The original Request is forwarded untouched. Re-wrapping it (even just
		// to attach headers) severs the WebSocket from the real client socket:
		// the handshake still succeeds and buffered control frames arrive, but
		// the first forwarded frame afterwards fails with "Network connection
		// lost". Authentication therefore happens inside the Durable Object,
		// which is only reachable through this Worker anyway.
		return stub.fetch(request);
	},
};

/**
 * One relay session, named after the host's CMD-Chat ID.
 *
 * Holds at most two sockets and forwards binary frames between them. Text
 * frames are relay control and are never forwarded, which keeps the control
 * channel and the chat stream unambiguously separate.
 */
export class RelaySession {
	constructor(state) {
		this.state = state;

		// The host keeps one idle socket here waiting for someone to arrive.
		this.standby = null;
		this.standbyId = null;

		// Once a guest arrives the standby socket is PROMOTED into a pair and
		// the standby slot is freed, so the host can immediately park a fresh
		// socket for the next guest without disturbing the live conversation.
		// Without this promotion, a host that reconnects to wait for its next
		// guest would replace — and close — the socket currently in use.
		this.partners = new Map();
		this.peerIds = new Map();

		this.bytes = 0;
		this.startedAt = Date.now();
		this.expiryTimer = null;
		this.unpairedTimer = null;
	}

	get activePairs() {
		return this.partners.size / 2;
	}

	async fetch(request) {
		const session = decodeURIComponent(new URL(request.url).pathname.slice('/relay/'.length));

		// Refusing here is what keeps the relay from being an open proxy: you
		// need a real CMD-Chat identity, and a host slot needs its owner.
		const auth = await authenticateJoin(request.headers, session);
		if (auth.error) {
			return json({ ok: false, error: auth.error, message: auth.message }, auth.error === 'not_session_owner' ? 403 : 401);
		}
		const role = auth.role;
		const peerId = auth.id;

		if (role === 'guest' && !this.standby) {
			return json({ ok: false, error: 'no_host', message: 'That peer is not waiting on the relay.' }, 409);
		}
		if (role === 'guest' && this.activePairs >= MAX_PAIRS) {
			return json({ ok: false, error: 'session_busy', message: 'That peer already has as many relayed chats as the relay allows.' }, 409);
		}

		const pair = new WebSocketPair();
		const client = pair[0];
		const server = pair[1];
		server.accept();

		// Without this, a real (non in-isolate) client's binary frames arrive as
		// Blobs, whose byteLength is undefined and which send() will not accept.
		// Forcing arraybuffer also keeps forwarding synchronous: awaiting
		// blob.arrayBuffer() inside the message handler could reorder frames and
		// corrupt the TLS stream running through this pipe.
		server.binaryType = 'arraybuffer';

		this.wire(server);
		this.armExpiry();

		if (role === 'host') {
			// Only ever replaces an idle standby socket; sockets already serving
			// a guest live in `partners` and are untouched by this.
			if (this.standby) this.safeClose(this.standby, CLOSE_REPLACED, 'replaced by a newer standby connection');
			this.standby = server;
			this.standbyId = peerId;
			this.peerIds.set(server, peerId);
			this.armUnpairedTimeout();
			this.control(server, { type: 'waiting' });
		} else {
			const host = this.standby;
			const hostId = this.standbyId;
			this.standby = null;
			this.standbyId = null;
			this.clearUnpairedTimeout();

			this.peerIds.set(server, peerId);
			this.partners.set(host, server);
			this.partners.set(server, host);

			this.control(host, { type: 'paired', peer: peerId });
			this.control(server, { type: 'paired', peer: hostId });
		}

		return new Response(null, { status: 101, webSocket: client });
	}

	/** Attaches forwarding and teardown handlers to one side of the session. */
	wire(socket) {
		socket.addEventListener('message', (event) => {
			// Text frames are control only. Forwarding them would let a peer
			// inject into the other side's control channel.
			if (typeof event.data === 'string') {
				this.handleControl(socket, event.data);
				return;
			}

			const size = event.data.byteLength ?? event.data.size ?? 0;
			if (size > MAX_FRAME_BYTES) {
				this.shutdown(CLOSE_PROTOCOL, 'frame exceeds the relay limit');
				return;
			}

			this.bytes += size;
			if (this.bytes > MAX_SESSION_BYTES) {
				this.shutdown(CLOSE_LIMIT, 'session byte limit reached');
				return;
			}

			const other = this.partners.get(socket);
			if (!other) return;
			try {
				// Forwarded verbatim. The relay never inspects, buffers to
				// storage, or rewrites the payload.
				other.send(event.data);
			} catch {
				this.closePair(socket, CLOSE_PEER_LEFT, 'peer send failed');
			}
		});

		const teardown = () => {
			if (this.standby === socket) {
				this.standby = null;
				this.standbyId = null;
				this.clearUnpairedTimeout();
			}
			this.closePair(socket, CLOSE_PEER_LEFT, 'peer disconnected');
			this.peerIds.delete(socket);
			if (!this.standby && this.partners.size === 0) this.clearTimers();
		};

		socket.addEventListener('close', teardown);
		socket.addEventListener('error', teardown);
	}

	/** Tears down one conversation without touching any other. */
	closePair(socket, code, reason) {
		const other = this.partners.get(socket);
		this.partners.delete(socket);
		if (!other) return;
		this.partners.delete(other);
		this.peerIds.delete(other);
		this.safeClose(other, code, reason);
	}

	handleControl(socket, raw) {
		let message;
		try {
			message = JSON.parse(raw);
		} catch {
			return;
		}
		if (message?.type === 'ping') this.control(socket, { type: 'pong' });
	}

	control(socket, payload) {
		try {
			socket.send(JSON.stringify(payload));
		} catch {
			/* socket already gone */
		}
	}

	safeClose(socket, code, reason) {
		try {
			socket.close(code, reason);
		} catch {
			/* already closed */
		}
	}

	shutdown(code, reason) {
		if (this.standby) this.safeClose(this.standby, code, reason);
		for (const socket of this.partners.keys()) this.safeClose(socket, code, reason);
		this.standby = null;
		this.standbyId = null;
		this.partners.clear();
		this.peerIds.clear();
		this.clearTimers();
	}

	armExpiry() {
		if (this.expiryTimer) return;
		const remaining = Math.max(0, this.startedAt + MAX_SESSION_MS - Date.now());
		this.expiryTimer = setTimeout(() => this.shutdown(CLOSE_EXPIRED, 'session expired'), remaining);
	}

	armUnpairedTimeout() {
		this.clearUnpairedTimeout();
		this.unpairedTimer = setTimeout(() => {
			// Only drops the idle standby socket; live conversations continue.
			if (this.standby) {
				this.safeClose(this.standby, CLOSE_EXPIRED, 'no peer joined');
				this.standby = null;
				this.standbyId = null;
			}
		}, MAX_UNPAIRED_MS);
	}

	clearUnpairedTimeout() {
		if (this.unpairedTimer) {
			clearTimeout(this.unpairedTimer);
			this.unpairedTimer = null;
		}
	}

	clearTimers() {
		this.clearUnpairedTimeout();
		if (this.expiryTimer) {
			clearTimeout(this.expiryTimer);
			this.expiryTimer = null;
		}
	}
}
