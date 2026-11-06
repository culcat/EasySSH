import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  worker: {
    format: 'es',
  },
  server: {
    port: 3000,
    headers: {
      // Required for SharedArrayBuffer / high-precision timers in web environments if needed
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
  // @ts-expect-error vitest types inline config
  test: {
    globals: true,
    environment: 'node',
    include: ['src/__tests__/**/*.{test,spec}.ts'],
  },
});
