import type { ValidationIssue } from '../../features/pdf-analysis/validation/validatePdfFile';
import { UploadValidationMessage } from './UploadValidationMessage';

interface ForceScanPromptProps {
  readonly fileName: string;
  readonly issues: readonly ValidationIssue[];
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
}

/** Asks before scanning a file without a PDF signature (pdfid.py --force). */
export function ForceScanPrompt({ fileName, issues, onConfirm, onCancel }: ForceScanPromptProps) {
  return (
    <section className="card force-prompt" aria-labelledby="force-heading">
      <h2 id="force-heading" className="section-heading" tabIndex={-1}>
        This file may not be a PDF
      </h2>
      <p>
        <span className="breakable">{fileName}</span> does not start with a %PDF header. You can
        still scan it, but the result will be marked inconclusive unless something high-risk is
        found.
      </p>
      <UploadValidationMessage
        issues={issues.filter((issue) => issue.code !== 'signature-missing')}
        fileName={fileName}
      />
      <div className="button-row">
        <button type="button" className="button button--primary" onClick={onCancel}>
          Choose another file
        </button>
        <button type="button" className="button" onClick={onConfirm}>
          Scan anyway (forced mode)
        </button>
      </div>
    </section>
  );
}
