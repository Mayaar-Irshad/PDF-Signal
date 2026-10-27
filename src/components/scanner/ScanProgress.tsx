import type { ScanProgress as Progress } from '../../features/pdf-analysis/worker/pdfScanClient';
import { formatBytes } from '../../features/pdf-analysis/validation/validatePdfFile';

interface ScanProgressProps {
  readonly fileName: string;
  readonly sizeBytes: number;
  /** Null while the file is being validated, before the worker starts. */
  readonly progress: Progress | null;
  readonly forced: boolean;
  readonly onCancel?: () => void;
}

const STAGE_LABELS: Record<Progress['stage'], string> = {
  reading: 'Reading the file',
  hashing: 'Computing the SHA-256 hash',
  scanning: 'Scanning PDF keywords',
  'deep-scan': 'Inspecting actions, scripts and compressed streams',
};

/** Overall completion: reading and hashing are quick; scanning and deep analysis share the bar. */
function overallFraction(progress: Progress): number {
  switch (progress.stage) {
    case 'reading':
      return 0.05;
    case 'hashing':
      return 0.12;
    case 'scanning':
      return 0.15 + 0.45 * progress.fraction;
    case 'deep-scan':
      return 0.6 + 0.4 * progress.fraction;
  }
}

export function ScanProgress({
  fileName,
  sizeBytes,
  progress,
  forced,
  onCancel,
}: ScanProgressProps) {
  const label = progress === null ? 'Checking the file' : STAGE_LABELS[progress.stage];
  const fraction = progress === null ? null : overallFraction(progress);

  return (
    <section className="card scan-progress" aria-labelledby="progress-heading" aria-busy="true">
      <h2 id="progress-heading" className="section-heading" tabIndex={-1}>
        {progress === null ? 'Checking file…' : forced ? 'Scanning (forced mode)…' : 'Scanning…'}
      </h2>
      <p className="scan-progress__file">
        <span className="breakable">{fileName}</span>{' '}
        <span className="muted">({formatBytes(sizeBytes)})</span>
      </p>
      <p className="scan-progress__stage">{label}</p>
      {fraction === null ? (
        <progress className="progress" aria-label={label} />
      ) : (
        <progress className="progress" aria-label={label} max={1} value={fraction}>
          {Math.round(fraction * 100)}%
        </progress>
      )}
      {onCancel !== undefined && (
        <div className="button-row">
          <button type="button" className="button" onClick={onCancel}>
            Cancel scan
          </button>
        </div>
      )}
    </section>
  );
}
