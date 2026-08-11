import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
	test: {
		poolOptions: {
			workers: {
				singleWorker: true,
				// Relay sessions are long-lived Durable Object WebSockets, which
				// the per-test storage stack cannot unwind cleanly. Sessions are
				// keyed by a fresh random identity per test, so tests stay
				// independent without it.
				isolatedStorage: false,
				wrangler: { configPath: './wrangler.jsonc' },
			},
		},
	},
});
