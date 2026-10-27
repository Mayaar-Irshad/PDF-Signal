import js from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import globals from 'globals';
import tseslint from 'typescript-eslint';

const htmlInjectionMessage =
  'Render untrusted data as React text. HTML string insertion is forbidden in PDF Signal (see SECURITY.md).';

export default defineConfig([
  globalIgnores(['dist', 'coverage', 'node_modules', '.pdfid']),
  {
    files: ['**/*.js'],
    extends: [js.configs.recommended],
    languageOptions: { globals: globals.node },
  },
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.strictTypeChecked,
      tseslint.configs.stylisticTypeChecked,
      reactHooks.configs.flat['recommended-latest'],
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      'no-restricted-syntax': [
        'error',
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: htmlInjectionMessage,
        },
        {
          selector: 'MemberExpression[property.name=/^(innerHTML|outerHTML)$/]',
          message: htmlInjectionMessage,
        },
        {
          selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
          message: htmlInjectionMessage,
        },
        {
          selector:
            "CallExpression[callee.object.name='document'][callee.property.name=/^write(ln)?$/]",
          message: htmlInjectionMessage,
        },
      ],
    },
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-globals': [
        'error',
        { name: 'localStorage', message: 'PDF Signal must not persist files or results.' },
        { name: 'sessionStorage', message: 'PDF Signal must not persist files or results.' },
        { name: 'indexedDB', message: 'PDF Signal must not persist files or results.' },
        { name: 'caches', message: 'PDF Signal must not persist files or results.' },
        { name: 'fetch', message: 'PDF Signal makes no network requests with file data.' },
        { name: 'XMLHttpRequest', message: 'PDF Signal makes no network requests with file data.' },
        { name: 'WebSocket', message: 'PDF Signal makes no network requests with file data.' },
      ],
    },
  },
  {
    files: ['tests/**/*.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      'react-refresh/only-export-components': 'off',
    },
  },
  {
    files: ['vite.config.ts'],
    languageOptions: { globals: globals.node },
  },
]);
