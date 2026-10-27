# Security

PDF Signal analyses files that may be malicious, inside a page that may be served from a
public website. This document describes the threat model, the controls that address it, and
the limits of those controls.

## Reporting a vulnerability

Please report vulnerabilities privately through the repository's **Security → Report a
vulnerability** page (GitHub private vulnerability reporting) rather than in a public issue.
Include the affected version, the browser, and steps to reproduce. Do not attach real malicious
samples to public issues.

## Threat model

| Asset                                | Threat                                                                       |
| ------------------------------------ | ---------------------------------------------------------------------------- |
| The user's PDF (may be confidential) | Leaking it over the network, persisting it, or exposing its content          |
| The user's browser session           | Script injection through file names, PDF-derived strings or crafted messages |
| The user's device                    | A malicious PDF executing, or exhausting memory or CPU                       |
| Trust in the result                  | Over-confident wording that presents heuristics as a verdict                 |

There is no server, database, shell or SQL layer, so server-side injection classes do not
apply. The build output is static files only.

## Controls

### The PDF is data, never content

- The file is read as bytes (`Blob.arrayBuffer()`) and scanned by a byte-level state machine.
  It is never decoded as UTF-8, parsed for execution, rendered, or placed in an `iframe`,
  `object`, `embed` or PDF viewer. JavaScript inside a PDF is never executed.
- Dropping a file outside the drop zone is intercepted, so the browser does not navigate to it
  and open it in its built-in PDF viewer.
- The engine never modifies the input buffer (tested), and results never contain raw bytes,
  stream contents or document text (tested with marker strings in fixtures).

### Cross-site scripting and DOM injection

- Every value shown on screen is rendered by React as text. The code base contains no
  `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`,
  `eval`, `new Function` or string-based timers. ESLint rules (`no-restricted-syntax`,
  `no-eval`, `no-implied-eval`, `no-new-func`) and `tests/unit/securityInvariants.test.ts`
  enforce this.
- **File names** are untrusted. `sanitizeFileName` normalizes Unicode and removes control
  characters, bidirectional overrides and isolates, zero-width characters and line separators,
  which prevents spoofing such as `invoice<U+202E>fdp.exe`. Names are also length-limited.
  Markup in names stays as harmless text.
- **PDF-derived strings** (header, names, dates) are bounded in length and count. Names are
  re-encoded so that control characters, non-ASCII bytes, PDF delimiters and `#` appear as
  `#xx`; the header shows non-printable bytes as `\xNN`.
- **Messages** are fixed strings written in the code base. Validation messages never echo the
  file name, and exceptions from the worker or the report builder are mapped to fixed messages;
  their text is never displayed.
- Component tests render hostile file names and hostile PDF names and assert that no `img` or
  `script` element is created.

### Content Security Policy

The production build includes this policy as a `<meta http-equiv>` element:

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; worker-src 'self';
connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none';
require-trusted-types-for 'script'; trusted-types default
```

- No inline scripts or styles, no `unsafe-eval`, no `unsafe-inline`, no remote origins.
  `connect-src 'none'` blocks `fetch`, XHR, WebSocket, EventSource and beacons from the page.
- **Trusted Types** are enforced. The only sink the app needs is the `Worker` constructor, so
  `src/security/trustedTypes.ts` installs a `default` policy with a single `createScriptURL`
  rule that accepts only the same-origin, content-hashed worker bundle
  (`…/assets/pdfScan.worker-<hash>.js`, no query or fragment). There is no `createHTML` or
  `createScript` rule, so HTML and script sinks remain blocked.
- The policy is added only to production builds, because the Vite development server relies on
  inline scripts.
- The production build was verified in Chrome with the policy active: a full scan, forced scan,
  report download and reset produced no console errors and no CSP violations, and the only
  network requests were the app's own static files.

**GitHub Pages limitations.** GitHub Pages cannot send custom response headers. Consequently:

- `frame-ancestors`, `report-uri` and `sandbox` cannot be enforced (browsers ignore them in a
  `<meta>` policy), and `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` and
  `Permissions-Policy` headers are not sent. The page could therefore be framed by another site.
  PDF Signal has no account, session or server-side action to hijack, which limits the impact,
  but a host that supports headers (or a CDN in front of GitHub Pages) can add
  `Content-Security-Policy: frame-ancestors 'none'` and the other headers for defence in depth.
- A `<meta name="referrer" content="no-referrer">` element is included instead of a header.
- The worker script receives its policy from its own HTTP response, not from the page's
  `<meta>` element, so on GitHub Pages the worker runs without a CSP. The worker contains only
  the bundled scanning code, makes no network requests (also covered by the static checks),
  and receives only the file and a boolean option.

### Web Worker isolation and resource limits

- Scanning runs in a dedicated module worker, off the interface thread. **A worker is execution
  separation, not an operating-system sandbox**: it runs in the same browser process sandbox as
  the page and shares the browser's security boundary.
- A new worker is created for each scan and terminated when the scan ends, fails, times out or
  is cancelled. Termination frees the file bytes and stops a running scan immediately.
- Messages in both directions are validated at runtime (`worker/protocol.ts`). Unknown message
  types, mismatched request ids, out-of-range values or malformed results end the scan with a
  protocol error; malformed data never reaches the interface.
- Limits: 10 MB per file (checked on the main thread and again in the worker, before and after
  reading), a 30-second scan timeout, a bounded word buffer (256 bytes) in the tokenizer, at most
  2,000 distinct names and 200 dates retained. The keyword scanner is a single linear pass with
  no regular expressions. The deep-analysis parser applies one simple, anchored pattern to number
  tokens of at most 32 characters; script checks use plain substring search. Neither has a
  catastrophic-backtracking risk.
- The file is read once into one buffer in the worker. The main thread only reads the first
  1024 bytes for the signature check.

### Deep analysis (decompression and parsing)

The deep analysis decompresses streams and parses objects from an untrusted file, so it is
bounded throughout (`engine/deepScan.ts`, `pdfObjects.ts`, `streamFilters.ts`):

- **Decompression bombs.** FlateDecode uses the browser's `DecompressionStream`, read chunk by
  chunk and cancelled as soon as the output passes its budget: 16 MB per stream, 96 MB in total,
  at most 2,000 streams. A stream that inflates beyond its budget is truncated and reported. A
  test inflates a ~4 KB stream of 4 MB of zeros and checks that it stops at the cap.
- **Parser limits.** Nesting depth 32, 20,000 entries per array or dictionary, 2 MB per string,
  500,000 tokens per object and 20,000,000 per document (shared across all parsing, so repeated
  offsets cannot multiply the work), 100,000 objects, 2,000,000 visited values, 20,000 action
  sources, action chains followed to depth 16 with cycle detection and memoisation, and one
  15-second deadline checked during indexing, parsing, classification and decoding (inside the
  30-second scan timeout). Malformed input yields partial results, never an exception; a
  randomized hostile-input test checks this.
- **Evasion resistance.** Every definition of an object is analysed, so a decoy or an
  incremental update cannot shadow the object a reader will actually use. Encryption is read from
  the trailer or cross-reference stream, never from an `/Encrypt` token that could sit in a
  string. Objects after an unterminated or oversized object are still found. Object streams that
  could not be fully inspected (failures, decompression bombs, budget limits) are reported and
  keep the keyword-based fallback active. File-derived names never reach the result: unknown
  event keys and action types are reported as "other". These protections come from an
  independent review and are covered by `tests/unit/evasionRegression.test.ts`.
- **No execution.** Scripts are decoded to text and searched for fixed substrings. They are never
  evaluated, emulated or rendered. Script text, URLs, launch targets and attachment names are discarded after analysis; only counts, action types and pattern identifiers reach the result, the interface
  and the report (tested with marker strings).
- **Encrypted documents** are not decrypted; their streams and strings are skipped and the
  limitation is reported.

### Downloads

- Reports are built from validated data, serialized with `JSON.stringify`, and saved through a
  temporary `blob:` URL with the `application/json` type. The URL is revoked after the download
  starts, and immediately if the download fails.
- The download name is built from an allowlist (`[A-Za-z0-9._-]`), with diacritics stripped,
  path separators and reserved characters replaced, and the stem limited to 60 characters:
  `pdf-signal-report-<stem>-<UTC timestamp>.json`. Users can leave the original name out.
- Report options are validated strictly: only known keys and boolean values are accepted.

### Supply chain

- Runtime dependencies: `react` and `react-dom` (and their dependency `scheduler`). No analytics,
  telemetry, remote fonts, CDNs or third-party scripts.
- `package-lock.json` pins every package with an integrity hash; CI installs with `npm ci`.
- GitHub Actions are pinned to full commit SHAs, workflows request read-only permissions
  (Pages deployment adds `pages: write` and `id-token: write` to the deploy job only), and
  checkout does not persist credentials.
- The optional parity job downloads pdfid.py from a pinned commit and verifies its SHA-256
  before running it; it is never part of the built application.
- `npm audit` reported **0 vulnerabilities** for all dependencies on 2026-10-27; CI runs
  `npm audit --omit=dev` on every build.
- No secrets, tokens or credentials are needed or stored in the repository.
- Source files are checked for bidirectional and invisible Unicode characters ("Trojan Source",
  CVE-2021-42574).

## Wording of results

Results never state that a file is safe or malicious. The assessment uses four levels ("No
configured suspicious indicators detected", "Indicators warrant further investigation",
"Multiple potentially suspicious indicators detected", "Analysis incomplete or inconclusive")
derived from documented, deterministic rules, and every result includes the limits of a static
keyword scan. See README.md, "Triage rules".

## Out of scope

- Detection of malware that does not use the PDF features PDFiD counts, content hidden in
  compressed object streams or encrypted data, and exploits against the user's PDF reader.
- Attacks by browser extensions or a compromised device, which can read any page's data.
