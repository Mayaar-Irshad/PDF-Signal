import type { ActionRisk, DeepScanResult } from '../../features/pdf-analysis/types/analysis';
import { formatBytes } from '../../features/pdf-analysis/validation/validatePdfFile';
import { WarningIcon } from '../icons/WarningIcon';

interface DeepAnalysisProps {
  readonly deep: DeepScanResult | null;
  /** High-risk actions are red when the verdict is high risk, orange otherwise. */
  readonly highRisk: boolean;
}

const RISK_LABELS: Record<ActionRisk, string> = { high: 'High', medium: 'Medium', low: 'Low' };
const RISK_BADGES: Record<ActionRisk, string> = {
  high: 'danger',
  medium: 'review',
  low: 'informational',
};

/**
 * PDF Signal's analysis beyond PDFiD: what automatic actions do, which keywords are hidden in
 * compressed object streams, and which suspicious constructs scripts contain. Script text,
 * URLs and file names are never shown.
 */
export function DeepAnalysis({ deep, highRisk }: DeepAnalysisProps) {
  if (deep === null) {
    return null;
  }
  const highRiskActions = deep.actions.filter((action) => action.risk === 'high').length;

  return (
    <section id="section-actions" className="card deep-analysis" aria-labelledby="deep-heading">
      <h2 id="deep-heading" className="section-heading">
        Actions and scripts
      </h2>
      <p className="section-intro">
        Beyond PDFiD: PDF Signal decompressed object streams and resolved what each action does.
        Scripts are checked in memory for suspicious patterns; their text is never displayed or
        saved.
      </p>

      <dl className="facts facts--stats">
        <div className="facts__item">
          <dt>Objects analysed</dt>
          <dd>{deep.objectsIndexed.toLocaleString()}</dd>
        </div>
        <div className="facts__item">
          <dt>Object streams</dt>
          <dd>{deep.objectStreams}</dd>
        </div>
        <div className="facts__item">
          <dt>Streams decompressed</dt>
          <dd>
            {deep.streamsDecoded} <span className="muted">({formatBytes(deep.decodedBytes)})</span>
          </dd>
        </div>
        <div className="facts__item">
          <dt>Scripts analysed</dt>
          <dd>
            {deep.scripts.analyzed} of {deep.scripts.found}
            {deep.scripts.xfaScripts > 0 && (
              <span className="muted"> ({deep.scripts.xfaScripts} in XFA forms)</span>
            )}
          </dd>
        </div>
      </dl>

      {deep.hiddenKeywords.length > 0 && (
        <div className="deep-analysis__block">
          <h3>Keywords hidden in compressed object streams</h3>
          <p className="muted small">A byte-level scan such as PDFiD cannot see these.</p>
          <p>
            {deep.hiddenKeywords.map((keyword) => (
              <code key={keyword.name} className="evidence-chip">
                {keyword.name} × {keyword.count}
              </code>
            ))}
          </p>
        </div>
      )}

      <div className="deep-analysis__block">
        <h3>
          Actions <span className="muted">({deep.actions.length})</span>
        </h3>
        {deep.actions.length === 0 ? (
          <p className="muted">No actions were found.</p>
        ) : (
          <div className="table-scroll" role="region" aria-label="Actions table" tabIndex={0}>
            <table>
              <caption className="visually-hidden">
                Actions in the document, what triggers them and their risk. {highRiskActions}{' '}
                high-risk.
              </caption>
              <thead>
                <tr>
                  <th scope="col">Trigger</th>
                  <th scope="col">Runs</th>
                  <th scope="col">Action</th>
                  <th scope="col">Risk</th>
                  <th scope="col" className="num">
                    Count
                  </th>
                </tr>
              </thead>
              <tbody>
                {deep.actions.map((action) => (
                  <tr
                    key={`${action.trigger}-${action.action}`}
                    className={
                      action.risk === 'high'
                        ? highRisk
                          ? 'row--danger'
                          : 'row--caution'
                        : action.risk === 'medium'
                          ? 'row--review'
                          : undefined
                    }
                  >
                    <th scope="row">
                      <code>{action.trigger}</code>
                    </th>
                    <td>
                      {action.when}{' '}
                      {action.automatic && (
                        <span className="badge badge--review automatic-badge">Automatic</span>
                      )}
                    </td>
                    <td>
                      {action.risk === 'high' && <WarningIcon className="inline-warning" />}
                      {action.action}
                    </td>
                    <td>
                      <span
                        className={`badge badge--${action.risk === 'high' && !highRisk ? 'caution' : RISK_BADGES[action.risk]}`}
                      >
                        {RISK_LABELS[action.risk]}
                      </span>
                    </td>
                    <td className="num">
                      {action.count}
                      {action.hiddenCount > 0 && (
                        <span className="muted"> ({action.hiddenCount} hidden)</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {deep.launchTargets.executable > 0 && (
          <p className="deep-analysis__danger">
            <WarningIcon className="inline-warning" />
            {deep.launchTargets.executable} launch action(s) point to an executable file type.
          </p>
        )}
      </div>

      {(deep.attachments.total > 0 ||
        deep.targets.networkShare > 0 ||
        deep.targets.scriptUri > 0) && (
        <div className="deep-analysis__block">
          <h3>Attachments and link targets</h3>
          <ul className="target-list">
            {deep.attachments.total > 0 && (
              <li>
                {deep.attachments.total === 1
                  ? '1 attached file'
                  : `${deep.attachments.total} attached files`}
                {deep.attachments.executable > 0 && (
                  <span className="deep-analysis__danger">
                    {' '}
                    <WarningIcon className="inline-warning" />
                    {deep.attachments.executable} with a program or script file type
                  </span>
                )}
                {deep.attachments.archive > 0 && (
                  <span>, {deep.attachments.archive} archive(s)</span>
                )}
                {deep.attachments.macroDocument > 0 && (
                  <span>, {deep.attachments.macroDocument} macro-capable Office document(s)</span>
                )}
              </li>
            )}
            {deep.targets.networkShare > 0 && (
              <li className="deep-analysis__danger">
                <WarningIcon className="inline-warning" />
                {deep.targets.networkShare} action(s) point to a network file share
                {deep.targets.automaticNetworkShare > 0 &&
                  ` (${deep.targets.automaticNetworkShare} without a click)`}
                . Opening one can send Windows credentials to the remote server.
              </li>
            )}
            {deep.targets.scriptUri > 0 && (
              <li className="deep-analysis__danger">
                <WarningIcon className="inline-warning" />
                {deep.targets.scriptUri} link(s) use a javascript:, vbscript: or data: address.
              </li>
            )}
          </ul>
          <p className="muted small">
            File names and addresses are checked locally and never shown.
          </p>
        </div>
      )}

      <div className="deep-analysis__block">
        <h3>Script patterns</h3>
        {deep.scriptPatterns.length === 0 ? (
          <p className="muted">
            {deep.scripts.analyzed === 0
              ? 'No script content was available to analyse.'
              : `No suspicious patterns were found in ${deep.scripts.analyzed} analysed script(s).`}
          </p>
        ) : (
          <ul className="findings">
            {deep.scriptPatterns.map((pattern) => (
              <li
                key={pattern.id}
                className={`finding finding--${pattern.severity === 'high' ? 'critical' : pattern.severity === 'medium' ? 'review' : 'informational'}`}
              >
                <div className="finding__header">
                  <span
                    className={`badge badge--${pattern.severity === 'high' ? 'danger' : pattern.severity === 'medium' ? 'review' : 'informational'}`}
                  >
                    {pattern.severity === 'high'
                      ? 'High'
                      : pattern.severity === 'medium'
                        ? 'Medium'
                        : 'Low'}
                  </span>
                  <h4 className="finding__title">{pattern.label}</h4>
                  <span className="muted small">
                    in {pattern.scripts === 1 ? '1 script' : `${pattern.scripts} scripts`}
                  </span>
                </div>
                <p>{pattern.description}</p>
              </li>
            ))}
          </ul>
        )}
      </div>

      {deep.notes.length > 0 && (
        <ul className="deep-analysis__notes">
          {deep.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
    </section>
  );
}
