import type { Ref } from 'react';
import type { AnalysisResult } from '../../features/pdf-analysis/hooks/usePdfAnalysis';
import type { DownloadOutcome } from '../../features/pdf-analysis/reports/exportJsonReport';
import type { ValidationIssue } from '../../features/pdf-analysis/validation/validatePdfFile';
import { UploadValidationMessage } from '../upload/UploadValidationMessage';
import { DeepAnalysis } from './DeepAnalysis';
import { DocumentNames } from './DocumentNames';
import { IndicatorDetails } from './IndicatorDetails';
import { KeywordResultsTable } from './KeywordResultsTable';
import { ReportActions } from './ReportActions';
import { RiskAssessment } from './RiskAssessment';
import { ScanSummary } from './ScanSummary';
import { StructureDetails } from './StructureDetails';
import { ThreatAlert } from './ThreatAlert';

interface ScanResultsProps {
  readonly analysis: AnalysisResult;
  readonly issues: readonly ValidationIssue[];
  readonly onReset: () => void;
  readonly headingRef?: Ref<HTMLHeadingElement>;
  readonly download?: (json: string, fileName: string) => DownloadOutcome;
}

/** All result panels for a completed scan. */
export function ScanResults({ analysis, issues, onReset, headingRef, download }: ScanResultsProps) {
  const { scan, assessment, file } = analysis;
  const highRisk = assessment.level === 'high-risk';
  // The scan's own observations already report a missing signature, so it is not repeated here.
  const uploadNotes = issues.filter((issue) => issue.code !== 'signature-missing');
  const sections = [
    { id: 'section-assessment', label: 'Assessment', shown: true },
    { id: 'section-keywords', label: 'Keyword counts', shown: scan.keywordScanPerformed },
    { id: 'section-indicators', label: 'Indicators', shown: scan.keywordScanPerformed },
    { id: 'section-actions', label: 'Actions and scripts', shown: scan.deep !== null },
    { id: 'section-structure', label: 'Structure', shown: true },
    { id: 'section-names', label: 'Names and dates', shown: scan.keywordScanPerformed },
    { id: 'section-report', label: 'Report', shown: true },
  ].filter((section) => section.shown);

  return (
    <div className="results">
      <div className="results__intro">
        <div className="results__heading-row">
          <h2 ref={headingRef} tabIndex={-1} className="results__title">
            Results for <span className="results__file breakable">{file.name}</span>
          </h2>
          <button type="button" className="button button--small" onClick={onReset}>
            Scan another file
          </button>
        </div>
        <p className="muted small">
          Nothing from the document was rendered or executed. Drop another file anywhere to scan it.
        </p>
      </div>
      <nav className="section-nav" aria-label="Result sections">
        <ul>
          {sections.map((section) => (
            <li key={section.id}>
              <a href={`#${section.id}`}>{section.label}</a>
            </li>
          ))}
        </ul>
      </nav>
      <ThreatAlert
        assessment={assessment}
        onDismiss={() => {
          document.getElementById('assessment-heading')?.focus();
        }}
      />
      <UploadValidationMessage issues={uploadNotes} fileName={file.name} />
      <div className="results__grid">
        <RiskAssessment assessment={assessment} />
        <ScanSummary file={file} scan={scan} />
      </div>
      {scan.keywordScanPerformed && (
        <>
          <KeywordResultsTable
            keywords={scan.keywords}
            interpretations={assessment.interpretations}
            showHidden={scan.deep !== null && scan.deep.objectStreams > 0}
            highRisk={highRisk}
          />
          <IndicatorDetails
            keywords={scan.keywords}
            interpretations={assessment.interpretations}
            highRisk={highRisk}
          />
        </>
      )}
      <DeepAnalysis deep={scan.deep} highRisk={highRisk} />
      <StructureDetails scan={scan} />
      {scan.keywordScanPerformed && <DocumentNames scan={scan} />}
      <ReportActions
        analysis={analysis}
        onReset={onReset}
        {...(download === undefined ? {} : { download })}
      />
    </div>
  );
}
