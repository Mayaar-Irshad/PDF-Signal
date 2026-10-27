import { useState } from 'react';
import type { SelectedFileInfo } from '../../features/pdf-analysis/hooks/usePdfAnalysis';
import type { ScanResult } from '../../features/pdf-analysis/types/analysis';
import { formatBytes } from '../../features/pdf-analysis/validation/validatePdfFile';

interface ScanSummaryProps {
  readonly file: SelectedFileInfo;
  readonly scan: ScanResult;
}

function headerDescription(scan: ScanResult): string {
  const { header } = scan;
  if (!header.found) {
    return 'Not found in the first 1024 bytes';
  }
  const position = header.offset === 0 ? 'at byte 0' : `at byte ${header.offset ?? '?'}`;
  return `${header.text ?? ''} (${position})`;
}

function versionDescription(scan: ScanResult): string {
  const { header } = scan;
  if (!header.found) {
    return 'Unknown';
  }
  if (header.version === null) {
    return 'Not declared in a recognizable form';
  }
  return header.versionRecognized
    ? `PDF ${header.version}`
    : `${header.version} (not a published PDF version)`;
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

/** Copies text with the Clipboard API, which browsers only provide in secure contexts. */
async function copyText(text: string): Promise<boolean> {
  const clipboard: { writeText?: (data: string) => Promise<void> } | undefined =
    typeof navigator === 'object' ? navigator.clipboard : undefined;
  if (clipboard?.writeText === undefined) {
    return false;
  }
  try {
    await clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function CopyButton({ text, label }: { readonly text: string; readonly label: string }) {
  const [status, setStatus] = useState('');
  return (
    <>
      <button
        type="button"
        className="button button--small"
        aria-label={label}
        onClick={() => {
          void copyText(text).then((copied) => {
            setStatus(copied ? 'Copied' : 'Copy unavailable: select the text instead');
          });
        }}
      >
        Copy
      </button>
      <span className="copy-status" role="status">
        {status}
      </span>
    </>
  );
}

export function ScanSummary({ file, scan }: ScanSummaryProps) {
  const eof = scan.eof;
  const bytesAfterLastEof = eof?.bytesAfterLastEof ?? null;
  return (
    <section id="section-summary" className="card scan-summary" aria-labelledby="summary-heading">
      <h2 id="summary-heading" className="section-heading">
        Scan summary
      </h2>
      <dl className="facts">
        <div className="facts__item facts__item--wide">
          <dt>File</dt>
          <dd className="breakable" data-testid="summary-file-name">
            {file.name}
          </dd>
        </div>
        <div className="facts__item">
          <dt>Size</dt>
          <dd>
            {formatBytes(scan.sizeBytes)}
            {scan.sizeBytes >= 1024 && (
              <span className="muted"> ({scan.sizeBytes.toLocaleString()} bytes)</span>
            )}
          </dd>
        </div>
        <div className="facts__item">
          <dt>Scan mode</dt>
          <dd>{scan.mode === 'forced' ? 'Forced (no PDF header)' : 'Standard'}</dd>
        </div>
        <div className="facts__item facts__item--wide">
          <dt>SHA-256</dt>
          <dd className="mono breakable hash-value">
            {scan.sha256 ?? 'Not available in this browser context'}
            {scan.sha256 !== null && <CopyButton text={scan.sha256} label="Copy SHA-256 hash" />}
          </dd>
        </div>
        <div className="facts__item">
          <dt>PDF header</dt>
          <dd className="mono breakable">{headerDescription(scan)}</dd>
        </div>
        <div className="facts__item">
          <dt>Version</dt>
          <dd>{versionDescription(scan)}</dd>
        </div>
        <div className="facts__item">
          <dt>%%EOF markers</dt>
          <dd>{eof === null ? 'Not scanned' : eof.eofCount}</dd>
        </div>
        <div className="facts__item">
          <dt>Bytes after last %%EOF</dt>
          <dd>
            {bytesAfterLastEof === null
              ? 'Not applicable'
              : `${bytesAfterLastEof}${eof?.trailingDataWhitespaceOnly === true ? ' (whitespace only)' : ''}`}
          </dd>
        </div>
        <div className="facts__item">
          <dt>Scanned</dt>
          <dd>
            {formatTimestamp(scan.scannedAt)}{' '}
            <span className="muted nowrap">
              in {Math.max(0, Math.round(scan.durationMs + (scan.deep?.durationMs ?? 0)))} ms
            </span>
          </dd>
        </div>
        <div className="facts__item">
          <dt>Engine</dt>
          <dd>
            {scan.engine.version} <span className="muted">(PDFiD-compatible)</span>
          </dd>
        </div>
      </dl>
    </section>
  );
}
