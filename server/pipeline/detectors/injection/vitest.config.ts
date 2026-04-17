import { defineConfig } from 'vitest/config';

// Local vitest config for the injection detectors subsystem.
// The repo-root vitest.config.ts restricts `include` to `tests/**/*.test.ts`,
// but this subsystem co-locates tests alongside source files. Use this local
// config when running detector tests directly:
//   npx vitest run --config server/pipeline/detectors/injection/vitest.config.ts
// or
//   npx vitest run server/pipeline/detectors/injection/ --config server/pipeline/detectors/injection/vitest.config.ts
export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['server/pipeline/detectors/injection/**/*.test.ts'],
    testTimeout: 15000,
    root: process.cwd(),
  },
});
