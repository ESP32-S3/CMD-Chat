import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineWorkersConfig, readD1Migrations } from '@cloudflare/vitest-pool-workers/config';

const here = path.dirname(fileURLToPath(import.meta.url));

export default defineWorkersConfig(async () => {
	// Tests run against the same migrations that ship to production, so a
	// schema change that breaks the API fails here rather than after deploy.
	const migrations = await readD1Migrations(path.join(here, 'migrations'));

	return {
		test: {
			setupFiles: ['./test/apply-migrations.js'],
			poolOptions: {
				workers: {
					singleWorker: true,
					wrangler: { configPath: './wrangler.jsonc' },
					miniflare: {
						bindings: {
							TEST_MIGRATIONS: migrations,
							IP_HASH_SALT: 'test-only-salt',
						},
					},
				},
			},
		},
	};
});
