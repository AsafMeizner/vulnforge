import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: [
      'tests/**/*.test.ts',
      'server/**/*.test.ts',
      'src/**/*.test.{ts,tsx}',
    ],
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      '**/dist-server/**',
      // Per-subdirectory vitest configs (e.g. detectors/injection) stay local.
      'server/pipeline/detectors/injection/vitest.config.ts',
    ],
    testTimeout: 15000,
    // In-memory DB for tests - override VULNFORGE_DB_PATH per-file as needed.
    env: {
      VULNFORGE_JWT_SECRET: 'test-secret-at-least-32-characters-long-for-hs256',
      VULNFORGE_MODE: 'server',
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: [
        'server/sync/**/*.ts',
        'server/auth/**/*.ts',
        'server/utils/**/*.ts',
        'server/deployment/**/*.ts',
        'server/workers/**/*.ts',
      ],
      exclude: ['**/*.test.ts'],
    },
  },
});
