import type { ValidationIssue } from '../../features/pdf-analysis/validation/validatePdfFile';

interface UploadValidationMessageProps {
  readonly issues: readonly ValidationIssue[];
  /** Sanitized name of the file the issues refer to. */
  readonly fileName: string;
}

/**
 * Shows validation errors (which block the scan) and warnings (which do not). Errors are
 * announced through the status region and receive focus (see App). All text is rendered as plain text.
 */
export function UploadValidationMessage({ issues, fileName }: UploadValidationMessageProps) {
  const errors = issues.filter((issue) => issue.severity === 'error');
  const warnings = issues.filter((issue) => issue.severity === 'warning');
  if (issues.length === 0) {
    return null;
  }

  return (
    <div className="validation">
      {errors.length > 0 && (
        <div className="validation__box validation__box--error">
          <h3 id="validation-heading" className="validation__title" tabIndex={-1}>
            This file cannot be scanned: <span className="breakable">{fileName}</span>
          </h3>
          <ul>
            {errors.map((issue) => (
              <li key={issue.code}>
                <strong>{issue.message}</strong> {issue.guidance}
              </li>
            ))}
          </ul>
        </div>
      )}
      {warnings.length > 0 && (
        <div className="validation__box validation__box--warning">
          <h3 className="validation__title">File checks</h3>
          <ul>
            {warnings.map((issue) => (
              <li key={issue.code}>
                <strong>{issue.message}</strong> {issue.guidance}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
