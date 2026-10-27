<div align="center">

<img src="public/favicon.svg" alt="" width="72" height="72" />

# PDF Signal

**Inspect suspicious PDFs. Keep your files local.**

A browser-only PDF security triage tool: a verified TypeScript reimplementation of Didier
Stevens' [PDFiD](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py), plus a
deep analysis that finds what keyword scanners miss, all running locally in your browser.

![TypeScript strict](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)
![React 19](https://img.shields.io/badge/React-19-149eca?logo=react&logoColor=white)
![Tests](https://img.shields.io/badge/tests-650%20passing-2ea043)
![PDFiD parity](https://img.shields.io/badge/pdfid.py%200.2.10-parity%20verified-0b7a6e)
![No backend](https://img.shields.io/badge/backend-none-6e7781)
![License MIT](https://img.shields.io/badge/license-MIT-blue)

<img src="docs/screenshots/results-high-risk.png" alt="PDF Signal flagging a PDF whose auto-running JavaScript is hidden in a compressed object stream" width="900" />

</div>

---

## Contents

- [Why PDF Signal](#why-pdf-signal)
- [Features](#features)
- [Screenshots](#screenshots)
- [Using PDF Signal](#using-pdf-signal)
- [How scanning works](#how-scanning-works)
- [What it detects](#what-it-detects)
- [Privacy and security](#privacy-and-security)
- [PDFiD compatibility](#pdfid-compatibility)
- [Getting started](#getting-started)
- [Testing and quality](#testing-and-quality)
- [Technology stack](#technology-stack)
- [Project structure](#project-structure)
- [Deploying to GitHub Pages](#deploying-to-github-pages)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Credits and licence](#credits-and-licence)

## Why PDF Signal

Phishing and malware campaigns still use PDFs that run JavaScript when opened, launch programs,
carry executable attachments or leak Windows credentials through network-share links. Analysts
triage such files with PDFiD, but uploading a suspicious (and often confidential) document to an
online scanner is not always acceptable.

PDF Signal does that triage **entirely in the browser**: no upload, no server, no telemetry. It
explains what it found in plain language, separates raw measurements from interpretation, and
never claims a file is "safe".

> [!IMPORTANT]
> PDF Signal is a static triage tool, not an antivirus product. A finding is a reason to look
> closer, not proof of malware, and a clean result is not proof of safety.

## Features

|                              |                                                                                                                                                                                                                                       |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 🔍 **PDFiD-compatible scan** | All 20 PDFiD keywords plus `/Colors > 2^24`, hex-escape (obfuscation) counts, header and `%%EOF` checks, entropy, dates and names. Matches pdfid.py 0.2.10 field by field on 50 synthetic fixtures and 400 real PDFs, in two modes.   |
| 🧬 **Deep analysis**         | Decompresses object streams, where modern PDFs and evasive malware keep their dictionaries, then resolves what `/OpenAction`, `/AA` events, links and document-level scripts actually do.                                             |
| 🧪 **Script inspection**     | Checks JavaScript (including XFA forms and encoded streams) for heap-spray data, shellcode-style escapes, `eval` of decoded data and APIs from known Acrobat exploits, without ever running it.                                       |
| 📎 **Attachments and links** | Flags executable attachments (including `invoice.pdf.exe` and direction-override tricks), archives, macro-capable Office files, network-share links and `javascript:` URLs.                                                           |
| 🚨 **Clear verdicts**        | Five evidence-based levels, from "No configured suspicious indicators detected" to "High-risk indicators detected", each with a "What to do" next step, and a red warning (orange when not high risk) for anything that can run code. |
| 🎯 **Fewer false alarms**    | Keywords that PDFiD counts inside image, font or text data, but that the document never uses, are shown as context instead of raising the verdict.                                                                                    |
| 🔒 **Private by design**     | Runs in a Web Worker; strict CSP (`connect-src 'none'`, Trusted Types); no storage, analytics or third-party code.                                                                                                                    |
| 📄 **JSON report**           | Generated locally; contains counts, findings and limitations but never document text, scripts, URLs or file paths.                                                                                                                    |
| ♿ **Accessible**            | Keyboard operable, screen-reader announcements, light and dark themes, responsive down to phone widths, print-friendly results.                                                                                                       |

## Screenshots

All screenshots are taken from the production build, scanning the harmless built-in samples.

| Start page                                                                                                                    | Clean result                                                                                                                         |
| ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| <img src="docs/screenshots/landing.png" alt="Start page with drop zone, sample files and privacy notice" />                   | <img src="docs/screenshots/results-clean.png" alt="Result for a clean document: no configured suspicious indicators detected" />     |
| **Keyword counts with danger rows**                                                                                           | **Resolved actions and script patterns**                                                                                             |
| <img src="docs/screenshots/keyword-table.png" alt="Keyword table with /JS, /JavaScript and /OpenAction highlighted in red" /> | <img src="docs/screenshots/actions-and-scripts.png" alt="Actions and scripts section showing an automatic JavaScript open action" /> |

<p align="center"><img src="docs/screenshots/mobile.png" alt="Results on a phone" width="300" /></p>

## Using PDF Signal

1. **Open the app**, either a deployed copy or a local one (see [Getting started](#getting-started)).
2. **Choose a file.** Drag a PDF anywhere onto the page or press **Choose a PDF file**. No
   suspicious file at hand? Pick one of the three harmless samples (a clean document, an
   auto-running script, and the same script hidden in a compressed object stream). They are
   generated in your browser.
3. **Wait a moment.** Most files take well under a second. **Cancel scan** stops a scan at any
   time, and scans stop automatically after 30 seconds.
4. **Read the verdict.** The assessment states the overall result and a "What to do" next step.
   If the file can run code, a red or orange warning appears above it with the reasons.
5. **Dig into the evidence** with the section bar: **Assessment**, **Keyword counts** (sortable by
   risk or in PDFiD order), **Indicators**, **Actions and scripts**, **Structure**, **Names and
   dates** and **Report**.
6. **Keep a record.** **Download JSON report** saves a summary that contains no document
   content, or print the page. **Scan another file** starts again.

Files without a `%PDF` header are not scanned unless you choose **Scan anyway (forced mode)**,
the equivalent of `pdfid.py --force`.

## How scanning works

```mermaid
flowchart LR
    A["PDF file<br/>(chosen or dropped)"] --> B{"Validation<br/>main thread"}
    B -- "size limit,<br/>%PDF signature" --> C["Web Worker<br/>(new for each scan)"]
    C --> D["PDFiD-compatible<br/>keyword scan"]
    C --> E["Deep analysis<br/>object streams · actions<br/>scripts · attachments"]
    D --> F["Deterministic<br/>triage rules"]
    E --> F
    F --> G["Results<br/>(rendered as text)"]
    F --> H["JSON report<br/>(local download)"]
```

1. **Validation** checks the 10 MB size limit and looks for the `%PDF` signature in the first
   1024 bytes, treating the file name and MIME type as untrusted.
2. **The worker** reads the bytes, computes a SHA-256 hash and runs two independent analyses:
   - the **keyword scan** reproduces pdfid.py's tokenizer exactly, so its counts can be compared
     with PDFiD output;
   - the **deep analysis** parses the PDF the way a reader would: it indexes every object
     (including every redefinition), decompresses object streams and encoded streams within
     strict limits, resolves `/OpenAction`, `/AA`, link and name-tree actions, and inspects
     scripts, attachments and link targets as text.

   Every message back to the page is validated at runtime, and the worker is terminated
   afterwards, which also makes cancellation immediate.

3. **The assessment** applies [documented, deterministic rules](docs/triage-rules.md) to both
   results and explains each finding, kept separate from the raw counts. It is not a machine
   learning model and its level is not a probability.

## What it detects

| Level         | Examples                                                                                                                                                                                                                                                                                |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **High risk** | JavaScript that runs on open (`/OpenAction`, page-open events) · automatic or executable `/Launch` · exploit-style script code · executable attachments · automatic network-share access                                                                                                |
| **Priority**  | Document-level scripts · hex-obfuscated keywords (`/J#61vaScript`) · network-share or `javascript:` links · decompression bombs                                                                                                                                                         |
| **Review**    | `/JS`, `/JavaScript`, `/AA`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA`, `/JBIG2Decode` · automatic web or file actions · archives and macro documents · indicators hidden in object streams · structural anomalies (data before the header or after `%%EOF`, unbalanced objects) |
| **Context**   | Forms, object streams, encryption, open actions that only navigate, incremental updates, keywords that occur only inside stream data                                                                                                                                                    |

Every level comes with a "What to do" recommendation. Entries that can run code are highlighted
in red when the verdict is high risk and in orange otherwise, so the colours always agree with
the verdict.

The deep analysis is hardened against evasion: it analyses every definition of an object (so
decoys and incremental updates cannot hide the real one), reads encryption only from the
trailer, keeps going past malformed objects, and reports whatever it could not inspect. If it is
defeated, the PDFiD keyword heuristics still apply. Keywords are only downgraded to context when
the deep analysis completed and inspected everything.

The full rule set, the highlighting rules and the differences from PDFiD's triage plugin are in
[docs/triage-rules.md](docs/triage-rules.md).

## Privacy and security

- Files are processed in a Web Worker on your device and **never uploaded**. The production
  Content Security Policy forbids the page from opening any network connection.
- Nothing is written to browser storage. The file is held only while it is needed and released
  when the worker is terminated.
- The PDF is never rendered or executed. Scripts are decoded and pattern-matched as text, then
  discarded; their text, URLs and file names never reach the interface or the report.
- Everything from the file (names, header, dates) and the file name itself is rendered strictly
  as text. There is no `innerHTML`, `eval` or dynamic code anywhere, and Trusted Types enforce
  it in the browser.
- Decompression and parsing are bounded (16 MB per stream, 96 MB in total, 2,000 streams,
  nesting and object limits, a 15-second budget), so decompression bombs and hostile structures
  stop at a limit instead of hanging the tab.

Details: [SECURITY.md](SECURITY.md) (threat model, CSP, GitHub Pages limitations, reporting a
vulnerability) and [PRIVACY.md](PRIVACY.md).

## PDFiD compatibility

The keyword engine reproduces pdfid.py 0.2.10's tokenizer exactly, including its quirks (for
example `/JS_x` counts as `/JS`, and keywords inside streams, strings and comments count).
`scripts/pdfid_reference.py` runs the real pdfid.py on every synthetic fixture. Its output is
committed and checked on every test run, and a CI job re-runs it live against the pinned
upstream file (SHA-256 verified):

```sh
mkdir -p .pdfid && curl -fsSL -o .pdfid/pdfid.py \
  https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/104bb4fe77e24f0891a954af349449227d06f77d/pdfid.py
PDFID_PY="$PWD/.pdfid/pdfid.py" npm run test:parity
```

| Check                                 | Result                                                                                        |
| ------------------------------------- | --------------------------------------------------------------------------------------------- |
| 50 synthetic fixtures × 2 modes       | All 100 comparisons agree: 95 match exactly; in 5, pdfid.py itself crashes on malformed input |
| 400 real PDFs × 2 modes (local, once) | All 800 comparisons agree (files not included in the repository)                              |

The deep analysis never changes these counts. See
[docs/pdfid-compatibility.md](docs/pdfid-compatibility.md) for the source study, the method, the
real-world check and every known difference.

## Getting started

Requires [Node.js](https://nodejs.org/) 22.12 or later (CI uses Node.js 24).

```sh
git clone <repository-url> pdf-signal
cd pdf-signal
npm ci
npm run dev        # http://localhost:5173
```

| Command                                                       | Purpose                                                    |
| ------------------------------------------------------------- | ---------------------------------------------------------- |
| `npm run dev`                                                 | Development server with hot reload                         |
| `npm run build`                                               | Type-check and build the static site into `dist/`          |
| `npm run preview`                                             | Serve the production build locally                         |
| `npm test`                                                    | Run all tests once                                         |
| `npm run test:watch`                                          | Run tests in watch mode                                    |
| `npm run test:coverage`                                       | Tests with coverage thresholds                             |
| `npm run test:parity`                                         | Compare with the real pdfid.py (set `PDFID_PY`; see above) |
| `npm run lint` / `npm run typecheck` / `npm run format:check` | Static checks                                              |

The Content Security Policy is added only to the production build, so check security-related
changes with `npm run build && npm run preview`.

## Testing and quality

- **650 tests** (Vitest + React Testing Library) pass, plus 2 live pdfid.py tests that run only
  when `PDFID_PY` is set: unit tests for every engine module, integration tests through the real
  worker handler, component and full-flow tests in jsdom, and the recorded pdfid.py parity suite.
- Benign synthetic fixtures built byte by byte; no real malware is used or committed.
- Security tests: hostile file names and PDF names rendered as text, no network requests or
  storage during a full scan, protocol violations, cancellation, timeouts, decompression bombs,
  evasion attempts, randomized hostile input, and no document content in results or reports.
- Static invariants fail the build on network or storage APIs, HTML injection sinks, `eval`,
  embedded viewers, inline styles, remote URLs, a weakened CSP, extra runtime dependencies or
  hidden Unicode (Trojan Source) characters.
- Coverage thresholds for the engine and assessment (≥ 90 % lines, ≥ 85 % branches); currently
  about 95 % and 99.5 % of lines. Strict TypeScript (`noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`) and type-aware ESLint with zero warnings.
- The production build is checked in Chrome with the full CSP and Trusted Types enabled: no
  console errors, no CSP violations, no external requests and no horizontal scrolling on phones.
- [CI](.github/workflows/ci.yml) runs formatting, linting, type-checking, coverage, the build and
  a dependency audit on pushes to `main` and on pull requests, plus the live pdfid.py comparison.

## Technology stack

| Area           | Choice                                                                                   |
| -------------- | ---------------------------------------------------------------------------------------- |
| Interface      | React 19, TypeScript 6 (strict), plain CSS with design tokens, light and dark themes     |
| Build          | Vite 8, static output with a relative base path                                          |
| Scanning       | Web Worker; Web Crypto (SHA-256); `DecompressionStream` for Flate; no PDF libraries      |
| Testing        | Vitest 5, React Testing Library, jsdom, V8 coverage, Python 3 for the pdfid.py reference |
| Code quality   | ESLint 10 with typescript-eslint, Prettier                                               |
| CI and hosting | GitHub Actions (SHA-pinned actions), GitHub Pages or any static host                     |

The only runtime dependencies are `react` and `react-dom`.

## Project structure

```text
src/
├── app/                        App shell and styles
├── components/                 layout · upload (drop zone, samples) · scanner · results · icons
├── config/                     size and time limits
├── features/
│   ├── pdf-analysis/
│   │   ├── engine/             PDFiD-compatible scan · deep analysis (objects, filters, scripts)
│   │   ├── worker/             Web Worker, message protocol and client
│   │   ├── assessment/         triage rules and explanations
│   │   ├── validation/         file checks and name sanitizing
│   │   ├── reports/            JSON report export
│   │   ├── hooks/              upload → scan → assess workflow
│   │   └── types/              shared result types
│   └── samples/                harmless sample PDFs generated in the browser
├── security/                   Trusted Types policy
└── styles/                     design tokens, global and accessibility styles
tests/                          unit · integration · components · parity · fixtures
scripts/pdfid_reference.py      runs pdfid.py for the parity tests
docs/                           PDFiD study, triage rules, screenshots
```

## Deploying to GitHub Pages

The build is a static site with a relative base path, so `dist/` works at
`https://<user>.github.io/<repository>/`, at a domain root or in any subfolder.

1. In **Settings → Pages**, set **Source** to **GitHub Actions**. (GitHub Pages for private
   repositories requires a paid plan; public repositories are free.)
2. Run the **Deploy to GitHub Pages** workflow manually, or set the repository variable
   `PAGES_ENABLED` to `true` to deploy on every push to `main`.

No secrets are needed. GitHub Pages cannot send custom security headers, so the CSP is delivered
by a `<meta>` element; see [SECURITY.md](SECURITY.md) for the consequences. Any other static
host works too: upload the contents of `dist/`.

## Limitations

- Encrypted PDFs are not decrypted, so their compressed objects and scripts cannot be inspected.
- FlateDecode, ASCIIHex, ASCII85 and RunLength streams are decoded; LZW content is not.
- Script analysis is static pattern matching; heavily obfuscated code may show no known pattern.
- Embedded PDFs and other attachments are classified by name and type, not scanned themselves.
- Files are limited to 10 MB and scans to 30 seconds; very large documents are analysed
  partially and say so.
- Like any static scanner, it cannot see what a document fetches or does at run time, and it
  cannot detect new exploits for bugs in PDF readers' parsers (for example in fonts or images).

## Roadmap

- Decryption of documents protected only by an empty user password.
- Recursive scanning of attached PDFs.
- Batch triage of several files with a combined report.

## Credits and licence

PDF Signal is released under the [MIT licence](LICENSE). It is an independent implementation
inspired by, and verified against, [PDFiD](https://blog.didierstevens.com/programs/pdf-tools/)
by Didier Stevens, whose source code is in the public domain. No pdfid.py code is included, and
PDF Signal is not affiliated with or endorsed by its author.
