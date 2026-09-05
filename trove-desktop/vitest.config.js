import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'happy-dom',
    globals: true,
    // A loaded CI runner needs longer than the 5s default: these tests drive a
    // full unlock-and-render through async commands. Must stay ABOVE the
    // `asyncUtilTimeout` in tests/setup.js, or waitFor is still waiting when
    // vitest gives up and the failure points at the wrong thing.
    testTimeout: 20000,
    setupFiles: ['./tests/setup.js'],
    include: ['tests/**/*.test.{js,jsx,ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.{js,jsx,ts,tsx}'],
      exclude: ['src/main.jsx', 'src/i18n/**'],
    },
  },
});
