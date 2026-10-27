import type { ScanFailure } from '../../features/pdf-analysis/hooks/usePdfAnalysis';

interface ScanErrorProps {
  readonly fileName: string;
  readonly error: ScanFailure;
  readonly onRetry: () => void;
  readonly onReset: () => void;
}

const GUIDANCE: Partial<Record<ScanFailure['code'], string>> = {
  cancelled: 'No result was produced. You can scan the file again or choose another one.',
  timeout: 'Very large or unusual files can take longer. Close other heavy tabs and try again.',
  'worker-unavailable':
    'Your browser blocked background workers. Try a current version of Firefox, Chrome, Edge or Safari.',
  'protocol-error': 'Try again. If this keeps happening, reload the page.',
  'read-failed': 'Check that the file still exists and is not locked by another program.',
};

export function ScanError({ fileName, error, onRetry, onReset }: ScanErrorProps) {
  const cancelled = error.code === 'cancelled';
  return (
    <section className="card scan-error" aria-labelledby="scan-error-heading">
      <h2 id="scan-error-heading" className="section-heading" tabIndex={-1}>
        {cancelled ? 'Scan cancelled' : 'The scan did not finish'}
      </h2>
      <div
        className={
          cancelled ? 'scan-error__message' : 'scan-error__message scan-error__message--error'
        }
      >
        <p>
          <span className="breakable">{fileName}</span>: {error.message}
        </p>
        <p>{GUIDANCE[error.code] ?? 'Try again, or choose another file.'}</p>
      </div>
      <div className="button-row">
        <button type="button" className="button button--primary" onClick={onRetry}>
          {cancelled ? 'Scan again' : 'Try again'}
        </button>
        <button type="button" className="button" onClick={onReset}>
          Choose another file
        </button>
      </div>
    </section>
  );
}
