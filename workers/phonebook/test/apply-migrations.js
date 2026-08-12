import { applyD1Migrations, env } from 'cloudflare:test';

await applyD1Migrations(env.cmd_chat_phonebook, env.TEST_MIGRATIONS);
