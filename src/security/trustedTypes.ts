/**
 * Trusted Types policy for PDF Signal.
 *
 * The production Content Security Policy sets `require-trusted-types-for 'script'`, so every
 * DOM sink that can load or run code (innerHTML, script URLs, the Worker constructor, …)
 * rejects plain strings. PDF Signal needs exactly one such sink: starting its own bundled scan
 * worker. Vite emits that call as `new Worker(new URL(...))`, which reaches the sink as a
 * string, so a `default` policy approves it. The policy defines only `createScriptURL` and only
 * accepts the same-origin, content-hashed worker bundle; HTML and script sinks stay blocked.
 */

/** Matches the worker bundle Vite emits, e.g. `/repo/assets/pdfScan.worker-RJCseJRa.js`. */
const WORKER_BUNDLE_PATH = /\/assets\/pdfScan\.worker-[A-Za-z0-9_-]+\.js$/;

export const TRUSTED_TYPES_POLICY_NAME = 'default';

/** True only for the app's own worker bundle, on the page's origin, without query or fragment. */
export function isAllowedWorkerScriptUrl(input: string, baseHref: string): boolean {
  let url: URL;
  let base: URL;
  try {
    base = new URL(baseHref);
    url = new URL(input, base);
  } catch {
    return false;
  }
  return (
    (url.protocol === 'https:' || url.protocol === 'http:') &&
    url.origin === base.origin &&
    url.search === '' &&
    url.hash === '' &&
    WORKER_BUNDLE_PATH.test(url.pathname)
  );
}

interface TrustedTypePolicyRules {
  readonly createScriptURL: (input: string) => string | null;
}

interface TrustedTypesFactory {
  createPolicy(name: string, rules: TrustedTypePolicyRules): unknown;
}

function isTrustedTypesFactory(value: unknown): value is TrustedTypesFactory {
  return (
    typeof value === 'object' &&
    value !== null &&
    'createPolicy' in value &&
    typeof value.createPolicy === 'function'
  );
}

/**
 * Installs the policy when the browser supports Trusted Types. Browsers without support do not
 * enforce the directive, so nothing is needed there. Returns whether a policy was created.
 */
export function installTrustedTypesPolicy(
  factory: unknown = Reflect.get(globalThis, 'trustedTypes'),
  baseHref: () => string = () => document.baseURI,
): boolean {
  if (!isTrustedTypesFactory(factory)) {
    return false;
  }
  factory.createPolicy(TRUSTED_TYPES_POLICY_NAME, {
    // Returning null rejects the value, so the sink throws and the browser reports a violation.
    createScriptURL: (input) => (isAllowedWorkerScriptUrl(input, baseHref()) ? input : null),
  });
  return true;
}
