# Triage rules

The assessment (`src/features/pdf-analysis/assessment/assessIndicators.ts`, rules version
2.1.0) is a fixed, deterministic set of rules. It is not a machine-learning model, and its level
is not a probability of maliciousness. Keyword counts include occurrences that the deep analysis
found inside compressed object streams.

## Findings

| Severity  | Rule                                                                                                                                                                                               |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| High risk | JavaScript that runs automatically from `/OpenAction` or a page-open or similar `/AA` event                                                                                                        |
| High risk | A `/Launch` that runs automatically, or any launch of an executable file type (`.exe`, `.bat`, `.js`, …), a bare command or a Windows launch with parameters                                       |
| High risk | Script content matching exploit patterns: heap-spray data, `%u`-encoded shellcode, `eval` of decoded data, APIs from known Acrobat exploits (`util.printf` with a huge width, `Collab.getIcon`, …) |
| High risk | An attachment with a program or script file type (`.exe`, `.js`, `.vbs`, …), including double extensions and names disguised with direction-reversing characters                                   |
| High risk | An action that opens a network file share (`\\server\share`, `smb:`, `file://host`) without a click, which can leak Windows credentials (as in CVE-2018-4993)                                      |
| Priority  | Document-level JavaScript (`/Names /JavaScript`), which runs when the document opens                                                                                                               |
| Priority  | Any keyword written with `#xx` escapes                                                                                                                                                             |
| Priority  | A clicked link or action that points to a network share, or uses a `javascript:`, `vbscript:` or `data:` address                                                                                   |
| Priority  | A stream that expands beyond the inspection limit (a possible decompression bomb)                                                                                                                  |
| Priority  | Fallback when actions cannot be fully resolved: JavaScript or `/Launch` together with `/OpenAction` or `/AA`                                                                                       |
| Review    | `/JS`/`/JavaScript`, `/OpenAction`/`/AA`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA`, `/JBIG2Decode`, `/Colors > 2^24` (related keywords form one finding)                                   |
| Review    | Automatic actions that open web addresses, submit data or open other files                                                                                                                         |
| Review    | Script functions worth reviewing (`eval`, `unescape`, `String.fromCharCode`, network or mail access, …)                                                                                            |
| Review    | Attached archives (`.zip`, `.iso`, …) or macro-capable Office documents                                                                                                                            |
| Review    | `/JS`, `/JavaScript`, `/Launch`, `/EmbeddedFile` or `/RichMedia` found only inside compressed object streams                                                                                       |
| Review    | Object streams that could not be fully inspected (decode failure, size or count limit)                                                                                                             |
| Review    | `obj` ≠ `endobj`, `stream` ≠ `endstream`; `%PDF` not at byte 0; non-whitespace data after the last `%%EOF`                                                                                         |
| Context   | `/AcroForm`, `/ObjStm`, `/Encrypt`; `/OpenAction` or `/AA` that only navigate; several or no `%%EOF` markers; truncation; malformed escapes; unpublished header versions                           |

## When the deep analysis is trusted

Resolved actions replace the keyword-combination fallback only when the deep analysis
completed without hitting a limit, every `/OpenAction` and `/AA` the keyword scan counted was
found, every reference resolved, and every action has a known type. Otherwise the fallback stays
active, so a document that defeats the deep analysis is still judged on its keywords.

Every definition of an object is analysed. When a PDF defines the same object more than once
(incremental updates, or a decoy placed after the real object), the most dangerous
interpretation counts.

## Overall result

| Result                                              | Condition                                   |
| --------------------------------------------------- | ------------------------------------------- |
| High-risk indicators detected                       | Any high-risk finding (even in forced mode) |
| Analysis incomplete or inconclusive                 | No `%PDF` header (scan skipped, or forced)  |
| No configured suspicious indicators detected        | No priority or review findings              |
| Indicators warrant further investigation            | Exactly one priority or review finding      |
| Multiple potentially suspicious indicators detected | Two or more priority or review findings     |

Each level comes with a recommended next step ("What to do"). Context findings never raise the level. Object streams that could not be decompressed,
encryption, forced mode, truncation and deep-analysis limits are listed as "what this scan could
not see".

## Red highlighting

An entry is highlighted when it can make the document run code or start programs. It is red
("Danger") when the overall result is high risk, and orange ("Runs code") otherwise, so the
colour always agrees with the verdict:

- `/JS`, `/JavaScript` and `/Launch` whenever they are present;
- `/OpenAction` or `/AA` when the deep analysis shows that they trigger JavaScript or a launch
  (or, if it could not resolve them, when JavaScript is also present);
- `/EmbeddedFile` when an attachment has a program or script file type.

An `/OpenAction` that only opens a page is shown as context, not as a danger.

## Differences from PDFiD's triage plugin

The rules follow the spirit of the `plugin_triage.py` plugin that ships with PDFiD, with
deliberate changes:

- `/AcroForm` alone is context, because interactive forms are common in legitimate documents.
- When the deep analysis can establish what an action does, resolved actions replace keyword
  co-occurrence. An interactive form-field script, for example, is highlighted but is not
  "high risk"; a document that only opens at page 1 is not flagged at all.
- Attachments, network-share references and script content are evaluated, which a keyword
  count cannot do.
