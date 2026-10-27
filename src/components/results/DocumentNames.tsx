import { useId, useState } from 'react';
import type { ScanResult } from '../../features/pdf-analysis/types/analysis';

interface DocumentNamesProps {
  readonly scan: ScanResult;
}

const MAX_FILTER_LENGTH = 60;
const MAX_ROWS = 500;

/**
 * Other PDF names (PDFiD --all) and PDF date values (PDFiD --extra). Both are derived from the
 * file, so they are rendered strictly as text, and names are shown with #xx re-escaping.
 */
export function DocumentNames({ scan }: DocumentNamesProps) {
  const [query, setQuery] = useState('');
  const filterId = useId();
  const { names, dates } = scan;
  const needle = query.trim().toLowerCase();
  const matching =
    needle === ''
      ? names.entries
      : names.entries.filter((entry) => entry.name.toLowerCase().includes(needle));
  const shown = matching.slice(0, MAX_ROWS);

  return (
    <section id="section-names" className="card document-names" aria-labelledby="names-heading">
      <h2 id="names-heading" className="section-heading">
        Names and dates
      </h2>
      <details className="disclosure">
        <summary>
          Date values <span className="muted">({dates.entries.length})</span>
        </summary>
        <div className="disclosure__body">
          {dates.entries.length === 0 ? (
            <p className="muted">No PDF date values (D:YYYYMMDDHHmmSS) were found.</p>
          ) : (
            <table className="stat-table">
              <caption className="visually-hidden">
                PDF date values and the name preceding each
              </caption>
              <thead>
                <tr>
                  <th scope="col">Value</th>
                  <th scope="col">Preceding name</th>
                </tr>
              </thead>
              <tbody>
                {dates.entries.map((date, index) => (
                  <tr key={`${date.value}-${index}`}>
                    <td className="mono">{date.value}</td>
                    <td className="mono breakable">{date.name === '' ? '—' : date.name}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {dates.omitted > 0 && (
            <p className="muted small">{dates.omitted} further date values were not retained.</p>
          )}
        </div>
      </details>

      <details className="disclosure">
        <summary>
          All other names <span className="muted">({names.entries.length})</span>
        </summary>
        <div className="disclosure__body">
          <div className="field">
            <label htmlFor={filterId}>Filter names</label>
            <input
              id={filterId}
              type="search"
              value={query}
              maxLength={MAX_FILTER_LENGTH}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setQuery(event.currentTarget.value.slice(0, MAX_FILTER_LENGTH));
              }}
            />
          </div>
          <p className="table-status" role="status">
            Showing {shown.length} of {names.entries.length} names
          </p>
          <div className="table-scroll" role="region" aria-label="All other names" tabIndex={0}>
            <table className="stat-table">
              <caption className="visually-hidden">PDF names other than the PDFiD keywords</caption>
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col" className="num">
                    Count
                  </th>
                  <th scope="col" className="num">
                    Hex-escaped
                  </th>
                </tr>
              </thead>
              <tbody>
                {shown.map((entry) => (
                  <tr key={entry.name}>
                    <td className="mono breakable">{entry.name}</td>
                    <td className="num">{entry.count}</td>
                    <td className="num">{entry.hexcodeCount}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {names.omitted > 0 && (
            <p className="muted small">
              {names.omitted} name occurrences were not listed because of resource limits (keyword
              counts are complete).
            </p>
          )}
        </div>
      </details>
    </section>
  );
}
