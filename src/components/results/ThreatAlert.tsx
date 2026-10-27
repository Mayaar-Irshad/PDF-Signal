import { useState } from 'react';
import type { Assessment } from '../../features/pdf-analysis/types/analysis';
import { WarningIcon } from '../icons/WarningIcon';

interface ThreatAlertProps {
  readonly assessment: Assessment;
  /** Called after the alert is dismissed, so focus can move somewhere useful. */
  readonly onDismiss?: () => void;
}

/**
 * Warning shown above the results when the document can run code. It is red only when the
 * verdict is high risk; otherwise it uses the orange "priority" palette, so its colour always
 * matches the assessment. It is not an ARIA live region: focus moves to the results heading and
 * the status announcer already reports the verdict, which avoids reading everything twice.
 */
export function ThreatAlert({ assessment, onDismiss }: ThreatAlertProps) {
  const [dismissed, setDismissed] = useState(false);
  const dangers = assessment.interpretations.filter(
    (interpretation) => interpretation.status === 'danger',
  );
  const critical = assessment.findings.filter((finding) => finding.severity === 'critical');
  if (dismissed || (dangers.length === 0 && critical.length === 0)) {
    return null;
  }
  const highRisk = assessment.level === 'high-risk';
  const evidenceCount = critical.length + dangers.length;

  return (
    <section
      className={
        highRisk ? 'threat-alert threat-alert--critical' : 'threat-alert threat-alert--caution'
      }
      aria-labelledby="threat-alert-title"
      data-testid="threat-alert"
    >
      <WarningIcon className="threat-alert__icon" />
      <div className="threat-alert__body">
        <h2 id="threat-alert-title" className="threat-alert__title">
          {highRisk
            ? 'Warning: this PDF shows signs of malicious behaviour'
            : 'This PDF contains JavaScript'}
        </h2>
        <p className="threat-alert__advice">
          {highRisk
            ? assessment.advice
            : 'Scripts can run code in your PDF reader. Make sure you expected a document with scripts, and open it only in an up-to-date reader.'}
        </p>
        {critical.length > 0 && (
          <ul className="threat-alert__reasons">
            {critical.map((finding) => (
              <li key={finding.id}>{finding.title}</li>
            ))}
          </ul>
        )}
        <details className="threat-alert__evidence-details">
          <summary>Technical evidence ({evidenceCount})</summary>
          <ul className="threat-alert__list">
            {critical.map((finding) => (
              <li key={finding.id}>
                <strong>{finding.title}:</strong>{' '}
                <span className="threat-alert__evidence">{finding.evidence.join(' · ')}</span>
              </li>
            ))}
            {dangers.map((interpretation) => (
              <li key={interpretation.name}>
                <code className="threat-alert__keyword">{interpretation.name}</code>{' '}
                {interpretation.text}
              </li>
            ))}
          </ul>
        </details>
        <div className="threat-alert__actions">
          <a
            className={highRisk ? 'button button--danger-solid' : 'button button--priority-solid'}
            href="#section-assessment"
          >
            View assessment
          </a>
          <button
            type="button"
            className="button button--ghost"
            onClick={() => {
              setDismissed(true);
              onDismiss?.();
            }}
          >
            Dismiss warning
          </button>
        </div>
      </div>
    </section>
  );
}
