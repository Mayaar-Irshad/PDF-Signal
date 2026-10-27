import type { ScanResult } from '../../features/pdf-analysis/types/analysis';

interface StructureDetailsProps {
  readonly scan: ScanResult;
}

function formatEntropy(value: number | null): string {
  return value === null ? 'N/A' : value.toFixed(6);
}

/** Entropy, obfuscation statistics, scanner messages and PDFiD compatibility notes. */
export function StructureDetails({ scan }: StructureDetailsProps) {
  const { entropy, obfuscation } = scan;
  return (
    <section
      id="section-structure"
      className="card structure-details"
      aria-labelledby="structure-heading"
    >
      <h2 id="structure-heading" className="section-heading">
        Structure and statistics
      </h2>

      {scan.messages.length > 0 && (
        <div className="scanner-messages">
          <h3>Scanner observations</h3>
          <ul>
            {scan.messages.map((message) => (
              <li
                key={message.code}
                className={`scanner-message scanner-message--${message.severity}`}
              >
                <span className={`badge badge--${message.severity}`}>
                  {message.severity === 'warning' ? 'Warning' : 'Info'}
                </span>{' '}
                {message.text}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="stat-groups">
        {entropy !== null && (
          <div className="stat-group">
            <h3>Entropy (bits per byte)</h3>
            <table className="stat-table">
              <caption className="visually-hidden">Shannon entropy of the file bytes</caption>
              <thead>
                <tr>
                  <th scope="col">Region</th>
                  <th scope="col" className="num">
                    Entropy
                  </th>
                  <th scope="col" className="num">
                    Bytes
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row">Whole file</th>
                  <td className="num">{formatEntropy(entropy.totalEntropy)}</td>
                  <td className="num">{entropy.totalBytes.toLocaleString()}</td>
                </tr>
                <tr>
                  <th scope="row">Inside streams</th>
                  <td className="num">{formatEntropy(entropy.streamEntropy)}</td>
                  <td className="num">{entropy.streamBytes.toLocaleString()}</td>
                </tr>
                <tr>
                  <th scope="row">Outside streams</th>
                  <td className="num">{formatEntropy(entropy.nonStreamEntropy)}</td>
                  <td className="num">{entropy.nonStreamBytes.toLocaleString()}</td>
                </tr>
              </tbody>
            </table>
            <p className="muted small">
              Compressed or encrypted data is close to 8. Unusually high entropy outside streams can
              indicate hidden binary data.
            </p>
          </div>
        )}
        {obfuscation !== null && (
          <div className="stat-group">
            <h3>Name obfuscation</h3>
            <dl className="facts facts--compact">
              <div className="facts__item">
                <dt>Keyword occurrences with #xx escapes</dt>
                <dd>{obfuscation.hexEncodedKeywordOccurrences}</dd>
              </div>
              <div className="facts__item">
                <dt>Names of any kind with #xx escapes</dt>
                <dd>{obfuscation.namesWithHexEscapes}</dd>
              </div>
              <div className="facts__item">
                <dt>Malformed escapes</dt>
                <dd>{obfuscation.malformedHexEscapes}</dd>
              </div>
            </dl>
          </div>
        )}
      </div>

      {scan.compatibilityNotes.length > 0 && (
        <div className="compatibility-notes">
          <h3>Differences from pdfid.py on this file</h3>
          <ul>
            {scan.compatibilityNotes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
