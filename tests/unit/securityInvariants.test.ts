import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CONTENT_SECURITY_POLICY } from '../../vite.config';
import packageJson from '../../package.json' with { type: 'json' };

/**
 * Static checks that back the security and privacy claims in SECURITY.md and PRIVACY.md.
 * ESLint enforces most of these too; this test keeps them from being silently disabled.
 */
const ROOT = resolve(import.meta.dirname, '../..');

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    return statSync(path).isDirectory()
      ? sourceFiles(path)
      : /\.(ts|tsx|css|html)$/.test(path)
        ? [path]
        : [];
  });
}

const files = [...sourceFiles(join(ROOT, 'src')), join(ROOT, 'index.html')].map((path) => ({
  path: relative(ROOT, path),
  text: readFileSync(path, 'utf8'),
}));

const FORBIDDEN: readonly [string, RegExp][] = [
  ['network: fetch', /\bfetch\s*\(/],
  ['network: XMLHttpRequest', /XMLHttpRequest/],
  ['network: sendBeacon', /sendBeacon/],
  ['network: WebSocket', /WebSocket/],
  ['network: EventSource', /EventSource/],
  ['storage: localStorage', /localStorage/],
  ['storage: sessionStorage', /sessionStorage/],
  ['storage: indexedDB', /indexedDB/],
  ['storage: Cache API', /\bcaches\./],
  ['storage: cookies', /document\.cookie/],
  ['HTML injection: dangerouslySetInnerHTML', /dangerouslySetInnerHTML/],
  ['HTML injection: innerHTML/outerHTML', /\.(inner|outer)HTML/],
  ['HTML injection: insertAdjacentHTML', /insertAdjacentHTML/],
  ['HTML injection: document.write', /document\.write/],
  ['code execution: eval', /\beval\s*\(/],
  ['code execution: Function constructor', /new\s+Function\s*\(/],
  ['code execution: string timers', /set(Timeout|Interval)\(\s*['"`]/],
  ['document rendering: iframe/object/embed', /<(iframe|object|embed)\b/i],
  ['remote resources', /https?:\/\/(?!github\.com\/DidierStevens)/],
];

describe('security invariants', () => {
  // The script-pattern file lists these constructs as detection signatures (string data, never
  // calls). ESLint's AST-based no-eval / no-new-func / no-implied-eval rules still cover it.
  const SIGNATURE_FILE = 'src/features/pdf-analysis/engine/javascriptPatterns.ts';

  it.each(FORBIDDEN)('source contains no %s', (label, pattern) => {
    const offenders = files
      .filter((file) => !(label.startsWith('code execution') && file.path === SIGNATURE_FILE))
      .filter((file) => pattern.test(file.text))
      .map((file) => file.path);
    expect(offenders).toEqual([]);
  });

  it('enforces a restrictive Content Security Policy', () => {
    const directives = Object.fromEntries(
      CONTENT_SECURITY_POLICY.split(';').map((directive) => {
        const [name = '', ...values] = directive.trim().split(/\s+/);
        return [name, values.join(' ')];
      }),
    );
    expect(directives).toMatchObject({
      'default-src': "'none'",
      'script-src': "'self'",
      'style-src': "'self'",
      'connect-src': "'none'",
      'object-src': "'none'",
      'base-uri': "'none'",
      'form-action': "'none'",
      'require-trusted-types-for': "'script'",
      'trusted-types': 'default',
    });
    expect(CONTENT_SECURITY_POLICY).not.toMatch(/unsafe-(eval|inline)|\*|data:|blob:|https?:/);
  });

  it('keeps runtime dependencies minimal', () => {
    expect(Object.keys(packageJson.dependencies).sort()).toEqual(['react', 'react-dom']);
  });

  it('contains no bidirectional or invisible characters (Trojan Source, CVE-2021-42574)', () => {
    const hidden =
      // eslint-disable-next-line no-control-regex -- detecting control characters is the purpose
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/;
    const checked = [
      ...sourceFiles(join(ROOT, 'src')),
      ...sourceFiles(join(ROOT, 'tests')),
      ...readdirSync(ROOT)
        .filter((entry) => /\.(md|json|js|ts|html|yml)$/.test(entry))
        .map((entry) => join(ROOT, entry)),
      join(ROOT, 'scripts/pdfid_reference.py'),
      join(ROOT, 'docs/pdfid-compatibility.md'),
    ];
    const offenders = checked.filter((path) => hidden.test(readFileSync(path, 'utf8')));
    expect(offenders.map((path) => relative(ROOT, path))).toEqual([]);
  });

  it('uses no inline style attributes, which the CSP would block', () => {
    const offenders = files.filter((file) => /\bstyle=\{/.test(file.text)).map((file) => file.path);
    expect(offenders).toEqual([]);
  });
});
