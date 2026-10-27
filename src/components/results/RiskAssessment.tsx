import { RULE_DESCRIPTIONS } from '../../features/pdf-analysis/assessment/assessIndicators';
import type {
  Assessment,
  Finding,
  FindingSeverity,
} from '../../features/pdf-analysis/types/analysis';
import { WarningIcon } from '../icons/WarningIcon';
import { LEVEL_LABELS } from './labels';

const SEVERITY_LABELS: Record<FindingSeverity, string> = {
  critical: 'High risk',
  priority: 'Priority',
  review: 'Review',
  informational: 'Context',
};

const RULE_GROUPS: readonly [string, readonly string[]][] = [
  ['High-risk findings', RULE_DESCRIPTIONS.critical],
  ['Priority findings', RULE_DESCRIPTIONS.priority],
  ['Review findings', RULE_DESCRIPTIONS.review],
  ['Context only', RULE_DESCRIPTIONS.informational],
  ['Overall result', RULE_DESCRIPTIONS.levels],
];

/**
 * Review findings that restate a more specific high-risk finding. They stay in the report but
 * are listed under that finding instead of as separate items.
 */
const COVERED_BY: Readonly<Record<string, readonly string[]>> = {
  'auto-javascript': ['javascript', 'automatic-action'],
  'auto-launch': ['launch', 'automatic-action'],
  'launch-executable': ['launch'],
  'executable-attachment': ['embedded-file'],
  'exploit-script-patterns': ['script-patterns'],
  'auto-network-share': ['automatic-action'],
  'document-level-javascript': ['javascript'],
};

interface RiskAssessmentProps {
  readonly assessment: Assessment;
}

function FindingItem({
  finding,
  related,
}: {
  readonly finding: Finding;
  readonly related: readonly Finding[];
}) {
  return (
    <li className={`finding finding--${finding.severity}`}>
      <div className="finding__header">
        <span className={`badge badge--${finding.severity}`}>
          {finding.severity === 'critical' && <WarningIcon className="badge__icon" />}
          {SEVERITY_LABELS[finding.severity]}
        </span>
        <h4 className="finding__title">{finding.title}</h4>
      </div>
      <p>{finding.detail}</p>
      <p className="finding__evidence">
        Evidence:{' '}
        {finding.evidence.map((item) => (
          <code key={item} className="evidence-chip">
            {item}
          </code>
        ))}
      </p>
      {related.length > 0 && (
        <p className="finding__related">
          Also flagged: {related.map((item) => item.title).join(', ')}.
        </p>
      )}
    </li>
  );
}

/** The interpreted triage result, kept separate from the raw keyword counts. */
export function RiskAssessment({ assessment }: RiskAssessmentProps) {
  const significant = assessment.findings.filter((finding) => finding.severity !== 'informational');
  const context = assessment.findings.filter((finding) => finding.severity === 'informational');
  const present = new Set(significant.map((finding) => finding.id));
  const coveredIds = new Set(
    [...present].flatMap((id) =>
      (COVERED_BY[id] ?? []).filter((coveredId) => present.has(coveredId)),
    ),
  );
  const shown = significant.filter((finding) => !coveredIds.has(finding.id));
  const relatedTo = (finding: Finding) =>
    significant.filter(
      (other) => coveredIds.has(other.id) && (COVERED_BY[finding.id] ?? []).includes(other.id),
    );
  const highRisk = assessment.level === 'high-risk';

  return (
    <section
      id="section-assessment"
      className={`card assessment assessment--${assessment.level}`}
      aria-labelledby="assessment-heading"
    >
      <div className="assessment__header">
        <p className="assessment__eyebrow">Triage assessment</p>
        <span className={`level-badge level-badge--${assessment.level}`}>
          {highRisk && <WarningIcon className="inline-warning" />}
          {LEVEL_LABELS[assessment.level]}
        </span>
      </div>
      <h2
        id="assessment-heading"
        className="assessment__headline"
        tabIndex={-1}
        data-testid="assessment-headline"
      >
        {assessment.headline}
      </h2>
      <p className="assessment__summary">{assessment.summary}</p>
      <p className="assessment__advice">
        <strong>What to do: </strong>
        {assessment.advice}
      </p>

      {assessment.visibilityLimits.length > 0 && (
        <div className="assessment__limits">
          <h3>What this scan could not see</h3>
          <ul>
            {assessment.visibilityLimits.map((limit) => (
              <li key={limit}>{limit}</li>
            ))}
          </ul>
        </div>
      )}

      <h3 className="assessment__subheading">
        Findings <span className="muted">({shown.length})</span>
      </h3>
      {shown.length === 0 ? (
        <p className="muted">No high-risk, priority or review findings.</p>
      ) : (
        <ol className="findings">
          {shown.map((finding) => (
            <FindingItem key={finding.id} finding={finding} related={relatedTo(finding)} />
          ))}
        </ol>
      )}

      {context.length > 0 && (
        <>
          <h3 className="assessment__subheading">
            Context <span className="muted">({context.length})</span>
          </h3>
          <ul className="findings findings--context">
            {context.map((finding) => (
              <li key={finding.id} className="finding finding--informational">
                <div className="finding__header">
                  <span className="badge badge--informational">
                    {SEVERITY_LABELS.informational}
                  </span>
                  <h4 className="finding__title">{finding.title}</h4>
                </div>
                <p>{finding.detail}</p>
              </li>
            ))}
          </ul>
        </>
      )}

      <details className="disclosure">
        <summary>How this assessment is calculated</summary>
        <div className="disclosure__body">
          <p>
            The assessment applies fixed, documented rules (version {assessment.rulesVersion}) to
            the counts and to the deep analysis. It is not a machine-learning model and not a
            probability of maliciousness.
          </p>
          {RULE_GROUPS.map(([title, rules]) => (
            <div key={title} className="rule-group">
              <p className="rule-group__title">{title}</p>
              <ul>
                {rules.map((rule) => (
                  <li key={rule}>{rule}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </details>

      <p className="assessment__disclaimer">{assessment.disclaimer}</p>
    </section>
  );
}
