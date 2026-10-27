import { useId, useState } from 'react';
import type {
  KeywordCategory,
  KeywordCount,
  KeywordInterpretation,
} from '../../features/pdf-analysis/types/analysis';
import { WarningIcon } from '../icons/WarningIcon';

const CATEGORY_LABELS: Record<KeywordCategory, string> = {
  structure: 'Structure',
  document: 'Document',
  encryption: 'Encryption',
  'object-streams': 'Object streams',
  javascript: 'JavaScript',
  'automatic-action': 'Automatic action',
  forms: 'Forms',
  'embedded-content': 'Embedded content',
  'external-action': 'External action',
  'exploit-history': 'Exploit history',
};

type Status = KeywordInterpretation['status'];

/** Sort order for "risk first": code-running entries, then review, context, then not found. */
const STATUS_ORDER: Record<Status, number> = { danger: 0, review: 1, informational: 2, absent: 3 };

const MAX_FILTER_LENGTH = 40;

interface KeywordResultsTableProps {
  readonly keywords: readonly KeywordCount[];
  readonly interpretations: readonly KeywordInterpretation[];
  /** Show the column with occurrences found in compressed object streams. */
  readonly showHidden: boolean;
  /** Code-running entries are red when the verdict is high risk, orange otherwise. */
  readonly highRisk: boolean;
}

/** Raw PDFiD counts for every configured keyword, including zero counts. */
export function KeywordResultsTable({
  keywords,
  interpretations,
  showHidden,
  highRisk,
}: KeywordResultsTableProps) {
  const [query, setQuery] = useState('');
  const [foundOnly, setFoundOnly] = useState(false);
  const [order, setOrder] = useState<'risk' | 'pdfid'>('risk');
  const filterId = useId();
  const orderId = useId();
  const interpretationOf = (name: string) =>
    interpretations.find((interpretation) => interpretation.name === name);
  const statusOf = (keyword: KeywordCount): Status =>
    interpretationOf(keyword.name)?.status ?? 'absent';

  const needle = query.trim().toLowerCase();
  const filtered = keywords.filter((keyword) => {
    if (foundOnly && statusOf(keyword) === 'absent') {
      return false;
    }
    if (needle === '') {
      return true;
    }
    return [keyword.name, keyword.label, CATEGORY_LABELS[keyword.category]].some((text) =>
      text.toLowerCase().includes(needle),
    );
  });
  const rows =
    order === 'pdfid'
      ? filtered
      : filtered
          .map((keyword, index) => ({ keyword, index }))
          .sort(
            (left, right) =>
              STATUS_ORDER[statusOf(left.keyword)] - STATUS_ORDER[statusOf(right.keyword)] ||
              Number(left.keyword.kind === 'structural') -
                Number(right.keyword.kind === 'structural') ||
              left.index - right.index,
          )
          .map(({ keyword }) => keyword);

  const statusLabel = (keyword: KeywordCount, status: Status): string => {
    if (status === 'danger') {
      return highRisk ? 'Danger' : 'Runs code';
    }
    if (status === 'review') {
      return 'Review';
    }
    return keyword.kind === 'structural' ? 'Present' : 'Context';
  };

  return (
    <section
      id="section-keywords"
      className="card keyword-table"
      aria-labelledby="keywords-heading"
    >
      <h2 id="keywords-heading" className="section-heading">
        Keyword counts
      </h2>
      <p className="section-intro">
        Raw counts measured with PDFiD rules. "Hex-escaped" counts occurrences written with #xx
        escapes
        {showHidden &&
          '; "In object streams" counts occurrences found after decompressing object streams'}
        . Entries that can make the document run code are highlighted.
      </p>
      <div className="table-controls">
        <div className="field">
          <label htmlFor={filterId}>Filter keywords</label>
          <input
            id={filterId}
            type="search"
            value={query}
            maxLength={MAX_FILTER_LENGTH}
            placeholder="e.g. JavaScript, forms"
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => {
              setQuery(event.currentTarget.value.slice(0, MAX_FILTER_LENGTH));
            }}
          />
        </div>
        <div className="field">
          <label htmlFor={orderId}>Order</label>
          <select
            id={orderId}
            value={order}
            onChange={(event) => {
              setOrder(event.currentTarget.value === 'pdfid' ? 'pdfid' : 'risk');
            }}
          >
            <option value="risk">Risk first</option>
            <option value="pdfid">PDFiD order</option>
          </select>
        </div>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={foundOnly}
            onChange={(event) => {
              setFoundOnly(event.currentTarget.checked);
            }}
          />
          Only keywords that were found
        </label>
      </div>
      <p className="table-status" role="status">
        Showing {rows.length} of {keywords.length} counters
      </p>
      <div className="table-scroll" role="region" aria-label="Keyword counts table" tabIndex={0}>
        <table>
          <caption className="visually-hidden">PDFiD keyword counts for the scanned file</caption>
          <thead>
            <tr>
              <th scope="col">Keyword</th>
              <th scope="col" className="num">
                Count
              </th>
              <th scope="col" className="num">
                Hex-escaped
              </th>
              {showHidden && (
                <th scope="col" className="num">
                  In object streams
                </th>
              )}
              <th scope="col" className="col-category">
                Category
              </th>
              <th scope="col">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((keyword) => {
              const status = statusOf(keyword);
              const hidden = interpretationOf(keyword.name)?.hiddenCount ?? 0;
              const danger = status === 'danger';
              const rowClass =
                status === 'absent'
                  ? 'is-zero'
                  : danger
                    ? highRisk
                      ? 'row--danger'
                      : 'row--caution'
                    : status === 'review'
                      ? 'row--review'
                      : undefined;
              return (
                <tr key={keyword.name} className={rowClass}>
                  <th scope="row">
                    {danger && <WarningIcon className="inline-warning" />}
                    <code className="keyword-name">{keyword.name}</code>{' '}
                    <span className="keyword-label">{keyword.label}</span>
                  </th>
                  <td className="num">{keyword.count}</td>
                  <td className={keyword.hexcodeCount > 0 ? 'num num--alert' : 'num'}>
                    {keyword.hexcodeCount}
                  </td>
                  {showHidden && (
                    <td className={hidden > 0 ? 'num num--alert' : 'num'}>{hidden}</td>
                  )}
                  <td className="col-category">{CATEGORY_LABELS[keyword.category]}</td>
                  <td>
                    {status === 'absent' ? (
                      <span className="status-absent">
                        <span aria-hidden="true">—</span>
                        <span className="visually-hidden">Not found</span>
                      </span>
                    ) : (
                      <span className={`badge badge--${danger && !highRisk ? 'caution' : status}`}>
                        {statusLabel(keyword, status)}
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {rows.length === 0 && <p className="muted">No keywords match the current filter.</p>}
    </section>
  );
}
