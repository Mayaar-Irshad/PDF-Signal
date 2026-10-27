# PDFiD compatibility notes

PDF Signal's scanning engine is an independent TypeScript reimplementation of the core of
[pdfid.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py) by Didier
Stevens. This document records what was learned from the upstream source, which behaviour is
reproduced, how compatibility was verified, and where PDF Signal deliberately differs.

## Reference and provenance

| Item              | Value                                                                    |
| ----------------- | ------------------------------------------------------------------------ |
| Upstream file     | `pdfid.py` in `DidierStevens/DidierStevensSuite`                         |
| Version           | 0.2.10 (`__date__ = '2025/03/05'`)                                       |
| Commit            | `104bb4fe77e24f0891a954af349449227d06f77d` (latest change to `pdfid.py`) |
| SHA-256           | `e958a01f1c2596470f27d3c308061b85d7059ff476a58d74f1957a71b4f1248f`       |
| Licence statement | "Source code put in public domain by Didier Stevens, no Copyright"       |

The licence statement is in the header of `pdfid.py` itself. The repository has no top-level
licence file (the GitHub licence API returns 404), so the per-file public-domain dedication is
the governing statement. PDF Signal contains no code copied from pdfid.py: the algorithm was
re-expressed in TypeScript, and pdfid.py is never bundled, installed or executed by the app. It
is downloaded only to run the optional compatibility tests.

## How pdfid.py scans a file

### Reading

`cBinaryFile` reads the input one byte at a time and supports "ungetting" bytes. Nothing is
decoded as text: each byte becomes the character with the same code point (`chr(byte)`,
equivalent to ISO-8859-1). PDF Signal works on a `Uint8Array` in the same way and never decodes
the file as UTF-8.

### Header (`FindPDFHeaderRelaxed`)

1. Read the first 1024 bytes and search for `%PDF` anywhere in them.
2. If it is missing, the file is "not a PDF" (`IsPDF="False"`). Without `--force`, pdfid.py
   stops here and reports no keyword counts.
3. Otherwise the header line runs from `%PDF` to the first CR or LF among the 10 bytes after the
   signature; if there is none, it is 13 bytes long.
4. The `Header` field shows the first 10 characters through Python's `repr()`.
5. Bytes up to the end of the header line are **not tokenized**; they only count towards entropy.
   Keywords before or inside the header are therefore never counted.

### Tokenizer (the main loop)

- Only `[A-Za-z0-9]` bytes are accumulated into a _word_. Every other byte ends the current word.
- A word is a _name_ when the delimiter that started it was `/`.
- Inside a name, `#` followed by two hexadecimal digits is decoded and appended to the word, and
  the word is flagged as hex-escaped. Escapes are never decoded outside names.
- A `#` in a name that is not followed by two hex digits ends the word but leaves the name state
  on, so `/A#ZZB` produces the names `/A` and `/ZZB`.
- When a word ends (`UpdateWords`), it is looked up exactly and case-sensitively: bare words
  against `obj`, `endobj`, …; names against `/Page`, `/JavaScript`, …. A match increments the
  count, and the hexcode count when the word was escaped.
- PDF strings, comments and streams are **not parsed**. Keywords inside stream data, string
  literals and comments are counted like any other occurrence.
- Because `_`, `.`, `-` and other regular characters end a word, `/JS_x` counts as `/JS`, even
  though PDF syntax treats it as a single name.

### Default keywords

| Keyword         | What it counts                               |
| --------------- | -------------------------------------------- |
| `obj`           | Start of indirect objects                    |
| `endobj`        | End of indirect objects                      |
| `stream`        | Start of stream data                         |
| `endstream`     | End of stream data                           |
| `xref`          | Cross-reference tables                       |
| `trailer`       | Trailer dictionaries                         |
| `startxref`     | Offsets of the last cross-reference section  |
| `/Page`         | Page objects (not `/Pages`)                  |
| `/Encrypt`      | Encryption dictionaries                      |
| `/ObjStm`       | Object streams, which can hide other objects |
| `/JS`           | JavaScript code entries                      |
| `/JavaScript`   | JavaScript actions and name trees            |
| `/AA`           | Additional (event-triggered) actions         |
| `/OpenAction`   | Actions run when the document opens          |
| `/AcroForm`     | Interactive forms                            |
| `/JBIG2Decode`  | JBIG2 image filter (historically exploited)  |
| `/RichMedia`    | Rich media, for example embedded Flash       |
| `/Launch`       | Launch actions                               |
| `/EmbeddedFile` | Embedded files                               |
| `/XFA`          | XML Forms Architecture forms                 |

PDF Signal reports all twenty in this order, followed by the special counter below.

### `/Colors > 2^24` (CVE-2009-3459)

Before each word is ended by an ordinary delimiter, pdfid.py checks whether the most recent
name was `/Colors` and the current word consists of digits with a value above 2^24. The final
word of the file and words ended by a malformed `#` are not checked. The counter is reported
after the keywords with a hexcode count of 0.

### Stream state

The words `stream` and `endstream` (bare words only) toggle an "inside stream" flag. It is used
only for the entropy statistics. The delimiter after `stream` counts as stream data; the
characters of `endstream` itself are removed again from the stream histogram.

### Extra data (`--extra`)

- **%%EOF** (`cPDFEOF`): a state machine counts `%%EOF` followed by LF, CR, space or tab, or at
  the very end of the data, and counts the bytes after the last marker (CR LF after a marker
  counts as zero bytes). It never re-examines the byte that breaks a partial match, so `%%%EOF`
  is not counted, and after `%%EOF ` the next byte is consumed, so in `%%EOF %%EOF` only the first
  marker counts.
- **Entropy** (`cEntropy`): Shannon entropy in bits per byte for all bytes, stream bytes and
  non-stream bytes. Stream entropy is `N/A` when there are no stream bytes.
- **Dates** (`cPDFDate`): `D:` followed by exactly 14 digits, optionally `+`, `-` or `Z` and
  `HH'mm`. A `D` restarts recognition in any state; a time zone without the full `HH'mm` drops
  the date entirely. Each date is reported with the name that preceded it.

## What PDF Signal implements

| pdfid.py feature                   | PDF Signal                                                            |
| ---------------------------------- | --------------------------------------------------------------------- |
| Default keyword counts + hexcodes  | Implemented, byte-for-byte rules                                      |
| `/Colors > 2^24`                   | Implemented                                                           |
| Relaxed header, `IsPDF`, `Header`  | Implemented; also reports the parsed version and header offset        |
| `--force`                          | "Scan anyway (forced mode)" prompt for files without a header         |
| `--extra` (EOF, entropy, dates)    | Always on                                                             |
| `--all` (all names)                | Always collected, with resource limits; shown under "Names and dates" |
| `--nozero`                         | "Only keywords that were found" filter in the table                   |
| `--disarm`                         | **Not implemented**: PDF Signal never modifies or writes PDF files    |
| `--select` expressions             | **Not implemented**: upstream evaluates them with Python `eval()`     |
| Plugins (`--plugins`), CSV, scores | **Not implemented**; replaced by PDF Signal's documented triage rules |
| `pdfid.ini` extra keywords         | Not supported; the keyword list is fixed                              |
| Directory scan, `@file`, ZIP, URL  | Not applicable in a browser app (one local file at a time)            |
| XML / JSON output                  | Replaced by PDF Signal's own JSON report schema                       |

PDF Signal additions that are not in pdfid.py: SHA-256, PDF version parsing, header offset
warning, whitespace-only trailing-data detection, counts of names with escapes and of malformed
escapes, a "file ends inside a stream" flag, and the triage assessment.

## How compatibility was verified

`tests/fixtures/fixtureDefinitions.ts` defines 49 benign synthetic fixtures covering every keyword,
hex escapes (valid, malformed, truncated, outside names, decoding to delimiters), case
variants, word boundaries, keywords in streams, strings and comments, binary and invalid UTF-8
data, header edge cases, `%%EOF` edge cases, `/Colors` values, dates, long names, truncation,
empty input, and (for the deep analysis) compressed object streams, script streams, filter
chains, document-level scripts, launch and URI actions, XFA forms, attachments and network-share and script links.

`scripts/pdfid_reference.py` loads the real pdfid.py from a path given on the command line and
runs it on each fixture in default and `--force` mode (both with `--extra` and `--all`). The
parity test compares, for every fixture and mode: `IsPDF`, whether the scan ran, the `Header`
string, every keyword count and hexcode count, the full all-names list, the `%%EOF` count, bytes
after the last `%%EOF`, all byte counts, the three entropy values (tolerance 1e-6, because
pdfid.py prints six decimals) and the dates.

Result on 2026-10-27 with pdfid.py 0.2.10 and Python 3.9.6: **all 98 comparisons (49 fixtures × 2 modes) agree**. In 93 of them pdfid.py completed and every field matched exactly. In the
remaining 5, pdfid.py raised an exception; these are the recorded differences below, and the test
asserts that pdfid.py does fail on them.

The upstream output is committed as `tests/fixtures/pdfid-reference.json` and checked on every
test run, so CI does not need Python. The `pdfid-parity` CI job additionally downloads the pinned
pdfid.py (verifying its SHA-256) and re-runs the comparison live.

To run it locally:

```sh
mkdir -p .pdfid
curl -fsSL -o .pdfid/pdfid.py \
  https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/104bb4fe77e24f0891a954af349449227d06f77d/pdfid.py
shasum -a 256 .pdfid/pdfid.py   # e958a01f…1248f
PDFID_PY="$PWD/.pdfid/pdfid.py" npm run test:parity
# Regenerate the recorded results after adding fixtures:
PDFID_PY="$PWD/.pdfid/pdfid.py" UPDATE_PDFID_REFERENCE=1 npm run test:parity
```

## Beyond PDFiD: the deep analysis

PDF Signal 1.1 adds a deep analysis that pdfid.py does not perform. It never changes the
PDFiD-compatible counts above; its results are reported separately (`ScanResult.deep`, the
"Actions and scripts" section and the "In object streams" column).

- **Object streams.** pdfid.py scans raw bytes, so keywords inside compressed object streams are
  invisible to it. The `objstm-hidden-javascript` fixture demonstrates this: the recorded
  pdfid.py output shows only `/Page` and `/ObjStm`, while PDF Signal decompresses the stream and
  finds the hidden `/JS`, `/JavaScript` and `/OpenAction`.
- **Spec-correct parsing.** The deep parser follows PDF syntax, so it sees what a PDF reader
  sees. For example it treats `/JS_x` as the name `JS_x` (pdfid.py counts it as `/JS`), and it
  decodes hex-escaped filter and action names such as `/Fl#61teDecode` before acting on them.
- **Resolved actions.** pdfid.py reports that `/OpenAction` exists; PDF Signal reports what it
  does (navigate, run JavaScript, launch a program, open a URL, …) and whether it runs without a
  click. This is what lets the assessment distinguish "open at page 1" from "run a script on
  open".

The didierstevens.com workflow reaches similar answers with pdf-parser (`-O` to decompress
object streams, `-s`/`--search`) after PDFiD; PDF Signal combines both steps for triage.

## Known differences

| Input                                                          | pdfid.py 0.2.10                                                             | PDF Signal                                                                       | Fixture                    |
| -------------------------------------------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | -------------------------- |
| Header line runs past the bytes read (e.g. a file `%PDF-1.4`)  | `IndexError` while reading the header, then an uncaught `ZeroDivisionError` | Ends the header at the end of the data; adds a compatibility note                | `header-only-short`        |
| Empty input with `--force`                                     | Uncaught `ZeroDivisionError` in the entropy calculation                     | Reports entropy as unavailable; adds a compatibility note                        | `empty`                    |
| `/Colors` followed by a word with `²`, `³` or `¹` (via `#B2`…) | `ValueError` (`isdigit()` accepts the character, `int()` rejects it)        | Does not count the value; adds a compatibility note                              | `colors-superscript-digit` |
| Non-ASCII bytes in the header                                  | `repr()` shows printable Latin-1 characters literally                       | Shows every non-ASCII byte as `\xNN`, so only ASCII reaches the interface        | unit test                  |
| Names longer than 256 bytes                                    | Kept in full                                                                | Not listed in the all-names list (counted as omitted); keyword counts unaffected | `long-names`               |
| More than 2,000 distinct other names, or more than 200 dates   | Unlimited                                                                   | Extra entries omitted and counted, to bound memory                               | unit tests                 |
| Name display                                                   | Decoded names printed raw                                                   | Non-printable, non-ASCII, delimiter and `#` characters re-escaped as `#xx`       | unit tests                 |

Not differences, but worth knowing: entropy sums may differ from pdfid.py in the last bits
because Python 3.12+ uses compensated summation in `sum()` and platforms' `log()`
implementations can differ by one ulp. Both are far below the six decimals pdfid.py prints.
