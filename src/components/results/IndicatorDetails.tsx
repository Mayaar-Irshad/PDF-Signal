import { explanationFor } from '../../features/pdf-analysis/assessment/indicatorExplanations';
import type {
  KeywordCount,
  KeywordInterpretation,
} from '../../features/pdf-analysis/types/analysis';
import { WarningIcon } from '../icons/WarningIcon';

interface IndicatorDetailsProps {
  readonly keywords: readonly KeywordCount[];
  readonly interpretations: readonly KeywordInterpretation[];
  /** Code-running entries are red when the verdict is high risk, orange otherwise. */
  readonly highRisk: boolean;
}

function ExplanationList({ name }: { readonly name: string }) {
  const explanation = explanationFor(name);
  return (
    <dl className="explanation">
      <dt>What it is</dt>
      <dd>{explanation.whatItIs}</dd>
      <dt>Why analysts look closer</dt>
      <dd>{explanation.whyInvestigate}</dd>
      <dt>What it can and cannot tell you</dt>
      <dd>{explanation.limits}</dd>
    </dl>
  );
}

const STATUS_ORDER: Record<KeywordInterpretation['status'], number> = {
  danger: 0,
  review: 1,
  informational: 2,
  absent: 3,
};

/** Explains each indicator that was found (dangerous ones first), and the others on request. */
export function IndicatorDetails({ keywords, interpretations, highRisk }: IndicatorDetailsProps) {
  const interpretationOf = (name: string) =>
    interpretations.find((interpretation) => interpretation.name === name);
  const indicators = keywords.filter((keyword) => keyword.kind === 'indicator');
  const found = indicators
    .filter((keyword) => (interpretationOf(keyword.name)?.status ?? 'absent') !== 'absent')
    .sort(
      (left, right) =>
        STATUS_ORDER[interpretationOf(left.name)?.status ?? 'absent'] -
        STATUS_ORDER[interpretationOf(right.name)?.status ?? 'absent'],
    );
  const absent = indicators.filter((keyword) => !found.includes(keyword));

  return (
    <section
      id="section-indicators"
      className="card indicator-details"
      aria-labelledby="indicators-heading"
    >
      <h2 id="indicators-heading" className="section-heading">
        Indicator explanations
      </h2>
      {found.length === 0 ? (
        <p className="section-intro">
          None of the {indicators.length} indicator keywords were found. That does not show the file
          is safe: content inside encrypted data or hidden in other ways is not visible to a static
          scan.
        </p>
      ) : (
        <div className="indicator-grid">
          {found.map((keyword) => {
            const interpretation = interpretationOf(keyword.name);
            const danger = interpretation?.status === 'danger';
            const tone = danger ? (highRisk ? 'danger' : 'caution') : 'default';
            return (
              <article key={keyword.name} className={`indicator-card indicator-card--${tone}`}>
                <h3 className="indicator-card__title">
                  {danger && <WarningIcon className="inline-warning" />}
                  <code>{keyword.name}</code>
                  {danger && (
                    <span className={`badge badge--${highRisk ? 'danger' : 'caution'}`}>
                      {highRisk ? 'Danger' : 'Runs code'}
                    </span>
                  )}
                </h3>
                <p className="indicator-card__interpretation">{interpretation?.text}</p>
                <details className="indicator-card__more" open={danger}>
                  <summary>About {keyword.name}</summary>
                  <ExplanationList name={keyword.name} />
                </details>
              </article>
            );
          })}
        </div>
      )}
      {absent.length > 0 && (
        <details className="disclosure">
          <summary>About the {absent.length} indicators that were not found</summary>
          <div className="disclosure__body indicator-reference">
            {absent.map((keyword) => (
              <article key={keyword.name}>
                <h3>
                  <code>{keyword.name}</code> <span className="muted">{keyword.label}</span>
                </h3>
                <ExplanationList name={keyword.name} />
              </article>
            ))}
          </div>
        </details>
      )}
    </section>
  );
}
