import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
    resolve: {
        alias: {
            // Stub Obsidian's runtime APIs (only `normalizePath` is reached
            // from src/* code). Anything else would surface as an error,
            // which is what we want — the unit modules should not depend
            // on Obsidian internals.
            obsidian: resolve(__dirname, './tests/mocks/obsidian.ts'),
        },
    },
    test: {
        environment: 'node',
        include: ['tests/**/*.test.ts'],
    },
});
