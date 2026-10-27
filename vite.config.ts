import react from '@vitejs/plugin-react';
import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';
import packageJson from './package.json' with { type: 'json' };

/**
 * Content Security Policy for the production build.
 *
 * GitHub Pages cannot send custom HTTP response headers, so the policy is delivered with a
 * <meta http-equiv> element. Browsers ignore `frame-ancestors`, `report-uri` and `sandbox`
 * when they are delivered this way, so those directives are deliberately not listed here;
 * see SECURITY.md for the consequences. The policy is injected only into the production
 * build because the Vite development server relies on inline scripts for hot reloading.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "worker-src 'self'",
  "connect-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "require-trusted-types-for 'script'",
  // Only a policy named "default" may exist; it approves the bundled worker URL and nothing else.
  'trusted-types default',
].join('; ');

function contentSecurityPolicy(): Plugin {
  return {
    name: 'pdf-signal-content-security-policy',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler: () => [
        {
          tag: 'meta',
          attrs: { 'http-equiv': 'Content-Security-Policy', content: CONTENT_SECURITY_POLICY },
          injectTo: 'head-prepend',
        },
      ],
    },
  };
}

export default defineConfig({
  // A relative base lets the same build run from a GitHub Pages project subpath
  // (https://<user>.github.io/<repository>/) or from a domain root without changes.
  base: './',
  plugins: [react(), contentSecurityPolicy()],
  define: {
    __APP_VERSION__: JSON.stringify(packageJson.version),
  },
  worker: {
    format: 'es',
  },
  build: {
    target: 'es2022',
    // The polyfill uses fetch(), which the `connect-src 'none'` policy forbids.
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: 'engine',
          environment: 'node',
          include: [
            'tests/unit/**/*.test.ts',
            'tests/integration/**/*.test.ts',
            'tests/parity/**/*.test.ts',
          ],
        },
      },
      {
        extends: true,
        test: {
          name: 'ui',
          environment: 'jsdom',
          include: ['tests/components/**/*.test.tsx'],
          setupFiles: ['tests/setup.ts'],
        },
      },
    ],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/main.tsx',
        'src/vite-env.d.ts',
        'src/features/pdf-analysis/worker/pdfScan.worker.ts',
      ],
      reporter: ['text', 'html', 'json-summary'],
      thresholds: {
        'src/features/pdf-analysis/engine/**': { lines: 90, branches: 85, functions: 90 },
        'src/features/pdf-analysis/assessment/**': { lines: 90, branches: 85, functions: 90 },
      },
    },
  },
});
