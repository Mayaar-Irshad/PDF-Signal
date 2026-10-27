import { describe, expect, it, vi } from 'vitest';
import {
  installTrustedTypesPolicy,
  isAllowedWorkerScriptUrl,
} from '../../src/security/trustedTypes';

const BASE = 'https://user.github.io/pdf-signal/';

describe('isAllowedWorkerScriptUrl', () => {
  it.each([
    'https://user.github.io/pdf-signal/assets/pdfScan.worker-RJCseJRa.js',
    'assets/pdfScan.worker-RJCseJRa.js',
    './assets/pdfScan.worker-a_b-C9.js',
  ])('allows the bundled worker: %s', (input) => {
    expect(isAllowedWorkerScriptUrl(input, BASE)).toBe(true);
  });

  it.each([
    ['another origin', 'https://evil.example/pdf-signal/assets/pdfScan.worker-RJCseJRa.js'],
    ['another scheme', 'http://user.github.io/pdf-signal/assets/pdfScan.worker-RJCseJRa.js'],
    ['a data URL', 'data:text/javascript,postMessage(1)'],
    ['a blob URL', 'blob:https://user.github.io/1234'],
    // eslint-disable-next-line no-script-url -- hostile input the policy must reject
    ['a javascript URL', 'javascript:alert(1)'],
    ['another script', 'assets/index-Du-peGkV.js'],
    ['a query string', 'assets/pdfScan.worker-RJCseJRa.js?x=1'],
    ['a fragment', 'assets/pdfScan.worker-RJCseJRa.js#x'],
    ['an unhashed name', 'assets/pdfScan.worker.js'],
    ['a similar name', 'assets/evil-pdfScan.worker-x.js.map'],
    ['an invalid URL', 'http://['],
  ])('rejects %s', (_, input) => {
    expect(isAllowedWorkerScriptUrl(input, BASE)).toBe(false);
  });

  it('rejects everything when the base is invalid', () => {
    expect(isAllowedWorkerScriptUrl('assets/pdfScan.worker-a.js', 'not a url')).toBe(false);
  });
});

describe('installTrustedTypesPolicy', () => {
  it('does nothing when Trusted Types are unsupported', () => {
    expect(installTrustedTypesPolicy(undefined)).toBe(false);
    expect(installTrustedTypesPolicy({})).toBe(false);
  });

  it('creates a default policy that only approves the worker bundle', () => {
    const createPolicy = vi.fn();
    expect(installTrustedTypesPolicy({ createPolicy }, () => BASE)).toBe(true);
    expect(createPolicy).toHaveBeenCalledOnce();
    const [name, rules] = createPolicy.mock.calls[0] as [
      string,
      Record<string, (input: string) => string | null>,
    ];
    expect(name).toBe('default');
    expect(Object.keys(rules)).toEqual(['createScriptURL']);
    const worker = 'https://user.github.io/pdf-signal/assets/pdfScan.worker-RJCseJRa.js';
    expect(rules.createScriptURL?.(worker)).toBe(worker);
    expect(rules.createScriptURL?.('https://evil.example/x.js')).toBeNull();
  });
});
