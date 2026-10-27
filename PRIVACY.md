# Privacy

PDFs often contain personal, financial, medical or confidential business information. PDF
Signal is designed so that the file never leaves your device.

## What happens to your file

- **Processed locally.** When you choose or drop a file, your browser reads it and scans it in a
  background worker on your device. The first 1024 bytes are read on the page to check for a
  PDF signature; the full file is read only inside the worker.
- **Never uploaded.** PDF Signal has no backend, no scanning service and no external API. The
  page makes no network requests with file contents, scan results or file names. The production
  Content Security Policy blocks the page from opening network connections at all
  (`connect-src 'none'`).
- **Not stored.** The file is not written to local storage, session storage, IndexedDB, the
  Cache API or cookies, and there is no upload history. The application keeps only the scan
  results and the sanitized file name in memory while they are on screen. The worker holding the
  file bytes is terminated when the scan ends, and choosing "Scan another file" clears the
  results.
- **Not displayed.** PDF Signal never renders the document or shows its text. It shows keyword
  counts, structural facts, PDF names and date values.
- **Scripts are analysed, not kept.** To check embedded JavaScript for suspicious patterns,
  PDF Signal decompresses and reads it in memory, then discards it. Script text, web addresses, launch targets and attachment names are never displayed, stored or included in reports; only counts, action types and pattern names are.

## Reports

- Reports are generated in your browser and saved only when you click "Download JSON report".
- A report contains counts, structural findings, the assessment, the file size and SHA-256
  hash, and, by default, the file name. It never contains document text or stream contents.
- You can leave the file name out (also from the download file name). PDF date values (document
  metadata) and the list of other PDF names are left out unless you include them.
- A SHA-256 hash identifies a file. Anyone who has the same file can match the hash, so treat
  reports about confidential files as confidential.

## Analytics and third parties

PDF Signal includes no analytics, telemetry, advertising, tracking pixels, remote fonts or
third-party scripts. The only external link is to the PDFiD source code, which opens only if you
click it.

## Hosting

PDF Signal is a static website. The host that serves it (for example GitHub Pages) receives the
usual information any web server receives when you load a page, such as your IP address and
browser user agent, and may keep server logs under its own privacy policy. This happens when the
page is loaded and is unrelated to the files you scan. Self-host or run PDF Signal locally
(`npm run build && npm run preview`) if that matters for your environment.

## Your browser

Browser extensions can read the content of any page they have access to, including PDF Signal.
Use a browser profile without untrusted extensions when handling sensitive files.
