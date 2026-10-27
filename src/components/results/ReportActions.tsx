import { useState } from 'react';
import type { AnalysisResult } from '../../features/pdf-analysis/hooks/usePdfAnalysis';
import {
  buildJsonReport,
  createReportFileName,
  DEFAULT_REPORT_OPTIONS,
  downloadJsonReport,
  ReportError,
  serializeReport,
  validateReportOptions,
  type DownloadOutcome,
  type ReportOptions,
} from '../../features/pdf-analysis/reports/exportJsonReport';

interface ReportActionsProps {
  readonly analysis: AnalysisResult;
  readonly onReset: () => void;
  /** Saves the serialized report; replaceable in tests. */
  readonly download?: (json: string, fileName: string) => DownloadOutcome;
  readonly now?: () => Date;
}

type Status =
  { readonly kind: 'idle' } | { readonly kind: 'success' | 'error'; readonly message: string };

export function ReportActions({
  analysis,
  onReset,
  download = downloadJsonReport,
  now = () => new Date(),
}: ReportActionsProps) {
  const [options, setOptions] = useState<ReportOptions>(DEFAULT_REPORT_OPTIONS);
  const [status, setStatus] = useState<Status>({ kind: 'idle' });
  const { scan } = analysis;

  const toggle =
    (key: keyof ReportOptions) => (event: { readonly currentTarget: HTMLInputElement }) => {
      const checked = event.currentTarget.checked;
      setOptions((previous) => ({ ...previous, [key]: checked }));
      setStatus({ kind: 'idle' });
    };

  const handleDownload = () => {
    try {
      const validOptions = validateReportOptions(options);
      const generatedAt = now();
      const report = buildJsonReport(
        { scan, assessment: analysis.assessment, fileName: analysis.file.name },
        validOptions,
        generatedAt,
      );
      const fileName = createReportFileName(
        analysis.file.name,
        generatedAt,
        validOptions.includeFileName,
      );
      const outcome = download(serializeReport(report), fileName);
      setStatus(
        outcome.ok
          ? { kind: 'success', message: `Report saved as ${fileName}.` }
          : { kind: 'error', message: outcome.message },
      );
    } catch (error) {
      setStatus({
        kind: 'error',
        message: error instanceof ReportError ? error.message : 'The report could not be created.',
      });
    }
  };

  return (
    <section id="section-report" className="card report-actions" aria-labelledby="report-heading">
      <h2 id="report-heading" className="section-heading">
        Report
      </h2>
      <p className="section-intro">
        The JSON report contains the counts, structural findings, assessment and limitations. It
        never contains document text or stream contents, and it is created on this device.
      </p>
      <fieldset className="report-options">
        <legend>Optional report contents</legend>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={options.includeFileName}
            onChange={toggle('includeFileName')}
          />
          Include the file name
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={options.includeDates} onChange={toggle('includeDates')} />
          Include PDF date values ({scan.dates.entries.length})
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={options.includeNames} onChange={toggle('includeNames')} />
          Include all other PDF names ({scan.names.entries.length})
        </label>
      </fieldset>
      <div className="button-row">
        <button type="button" className="button button--primary" onClick={handleDownload}>
          Download JSON report
        </button>
        <button type="button" className="button" onClick={onReset}>
          Scan another file
        </button>
      </div>
      <p
        className={status.kind === 'error' ? 'report-status report-status--error' : 'report-status'}
        role="status"
        data-testid="report-status"
      >
        {status.kind === 'idle' ? '' : status.message}
      </p>
    </section>
  );
}
