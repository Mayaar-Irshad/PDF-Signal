import { useEffect, useRef, useState } from 'react';
import { AppFooter } from '../components/layout/AppFooter';
import { AppHeader } from '../components/layout/AppHeader';
import { PrivacyNotice } from '../components/layout/PrivacyNotice';
import { LEVEL_LABELS } from '../components/results/labels';
import { ScanResults } from '../components/results/ScanResults';
import { ScanError } from '../components/scanner/ScanError';
import { ScanProgress } from '../components/scanner/ScanProgress';
import { ForceScanPrompt } from '../components/upload/ForceScanPrompt';
import { PdfDropzone } from '../components/upload/PdfDropzone';
import { SampleFiles } from '../components/upload/SampleFiles';
import { UploadValidationMessage } from '../components/upload/UploadValidationMessage';
import { APP_CONFIG } from '../config/appConfig';
import { usePdfAnalysis, type AnalysisState } from '../features/pdf-analysis/hooks/usePdfAnalysis';
import type { DownloadOutcome } from '../features/pdf-analysis/reports/exportJsonReport';
import {
  createPdfScanClient,
  type PdfScanClient,
} from '../features/pdf-analysis/worker/pdfScanClient';
import './app.css';

export interface AppProps {
  /** Creates the scan client; tests supply one backed by an in-process worker. */
  readonly createScanClient?: () => PdfScanClient;
  readonly download?: (json: string, fileName: string) => DownloadOutcome;
}

function announcementFor(state: AnalysisState): string {
  switch (state.status) {
    case 'idle':
      return '';
    case 'validating':
      return 'Checking the selected file.';
    case 'invalid':
      return 'The file cannot be scanned.';
    case 'confirm-force':
      return 'The file has no PDF signature. Confirm to scan it anyway.';
    case 'scanning':
      return 'Scanning the file.';
    case 'complete':
      return `Scan complete: ${LEVEL_LABELS[state.analysis.assessment.level]}. ${state.analysis.assessment.advice}`;
    case 'error':
      return state.error.message;
  }
}

const BASE_TITLE = 'PDF Signal · Local PDF security triage';

function titleFor(state: AnalysisState): string {
  switch (state.status) {
    case 'idle':
      return BASE_TITLE;
    case 'validating':
    case 'scanning':
      return 'Scanning… · PDF Signal';
    case 'invalid':
      return 'File cannot be scanned · PDF Signal';
    case 'confirm-force':
      return 'Not a PDF? · PDF Signal';
    case 'error':
      return 'Scan did not finish · PDF Signal';
    case 'complete':
      return `${LEVEL_LABELS[state.analysis.assessment.level]} · ${state.analysis.file.name} · PDF Signal`;
  }
}

/** Element that should receive focus when the app enters each state. */
const FOCUS_TARGETS: Partial<Record<AnalysisState['status'], string>> = {
  invalid: 'validation-heading',
  'confirm-force': 'force-heading',
  validating: 'progress-heading',
  scanning: 'progress-heading',
  error: 'scan-error-heading',
};

function carriesFiles(event: DragEvent): boolean {
  return event.dataTransfer?.types.includes('Files') === true;
}

/**
 * Accepts a single file dropped anywhere on the page (when no scan is running) and always stops
 * the browser from navigating to a dropped PDF and opening it in its own viewer. Returns whether
 * a file is currently being dragged over the page.
 */
function useWindowFileDrop(enabled: boolean, onFile: (file: File) => void): boolean {
  const [dragging, setDragging] = useState(false);
  const latest = useRef({ enabled, onFile });
  useEffect(() => {
    latest.current = { enabled, onFile };
  });

  useEffect(() => {
    let depth = 0;
    const onEnter = (event: DragEvent) => {
      if (carriesFiles(event)) {
        depth++;
        setDragging(true);
      }
    };
    const onLeave = (event: DragEvent) => {
      if (carriesFiles(event)) {
        depth = Math.max(0, depth - 1);
        if (depth === 0) {
          setDragging(false);
        }
      }
    };
    const onOver = (event: DragEvent) => {
      if (carriesFiles(event)) {
        event.preventDefault();
      }
    };
    const onDrop = (event: DragEvent) => {
      if (!carriesFiles(event)) {
        return;
      }
      // The drop zone handles drops on itself and marks them as handled.
      const handled = event.defaultPrevented;
      event.preventDefault();
      depth = 0;
      setDragging(false);
      const files = event.dataTransfer?.files;
      const file = files?.length === 1 ? files[0] : undefined;
      if (!handled && latest.current.enabled && file !== undefined) {
        latest.current.onFile(file);
      }
    };
    window.addEventListener('dragenter', onEnter);
    window.addEventListener('dragleave', onLeave);
    window.addEventListener('dragover', onOver);
    window.addEventListener('drop', onDrop);
    return () => {
      window.removeEventListener('dragenter', onEnter);
      window.removeEventListener('dragleave', onLeave);
      window.removeEventListener('dragover', onOver);
      window.removeEventListener('drop', onDrop);
    };
  }, []);
  return dragging;
}

export function App({ createScanClient = createPdfScanClient, download }: AppProps) {
  const [client] = useState(createScanClient);
  const { state, selectFile, confirmForceScan, cancel, retry, reset } = usePdfAnalysis(client);
  const resultsHeadingRef = useRef<HTMLHeadingElement>(null);
  const pickerButtonRef = useRef<HTMLButtonElement>(null);
  const previousStatus = useRef(state.status);

  const busy = state.status === 'validating' || state.status === 'scanning';
  const dragging = useWindowFileDrop(!busy, selectFile);

  // Move focus to the heading of each new view, so keyboard and screen-reader users are never
  // left on <body> when the element they used disappears.
  useEffect(() => {
    const previous = previousStatus.current;
    previousStatus.current = state.status;
    if (state.status === previous) {
      return;
    }
    if (state.status === 'complete') {
      resultsHeadingRef.current?.focus();
    } else if (state.status === 'idle') {
      pickerButtonRef.current?.focus();
    } else {
      const target = FOCUS_TARGETS[state.status];
      if (target !== undefined) {
        document.getElementById(target)?.focus();
      }
    }
  }, [state.status]);

  useEffect(() => {
    document.title = titleFor(state);
  }, [state]);

  const showUpload = state.status === 'idle' || state.status === 'invalid';

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <AppHeader />
      <main id="main" className="app-main" tabIndex={-1}>
        <div className="visually-hidden" role="status" aria-live="polite" data-testid="announcer">
          {announcementFor(state)}
        </div>

        {showUpload && (
          <>
            <section className="hero" aria-labelledby="hero-title">
              <p className="hero__eyebrow">Static PDF triage · PDFiD-compatible keyword scan</p>
              <h2 id="hero-title" className="hero__title">
                {APP_CONFIG.tagline}
              </h2>
              <p className="hero__lead">
                PDF Signal counts the PDF keywords security analysts check first, such as
                JavaScript, automatic actions, launch actions and embedded files, and explains what
                they can and cannot tell you. The file is never opened, rendered or uploaded.
              </p>
            </section>
            <div className="upload-layout">
              <div className="upload-layout__main">
                {state.status === 'invalid' && (
                  <UploadValidationMessage issues={state.issues} fileName={state.file.name} />
                )}
                <PdfDropzone
                  onFileSelected={selectFile}
                  maxFileSizeBytes={APP_CONFIG.maxFileSizeBytes}
                  pickerButtonRef={pickerButtonRef}
                />
                <SampleFiles onFileSelected={selectFile} />
              </div>
              <PrivacyNotice />
            </div>
            <section className="card limitations" aria-labelledby="limitations-heading">
              <h2 id="limitations-heading" className="section-heading">
                What a static scan can and cannot tell you
              </h2>
              <ul>
                <li>
                  It finds the structures that let a PDF run code or act on its own: scripts,
                  automatic actions, launch actions, embedded files and similar features, including
                  ones hidden inside compressed object streams.
                </li>
                <li>
                  It checks scripts for patterns used by known exploits, but never runs them, so
                  heavily obfuscated code can go unrecognized. Encrypted content cannot be
                  inspected.
                </li>
                <li>
                  Features such as forms and scripts are common in legitimate documents. A finding
                  is a reason to look closer, not proof of malware, and a clean result is not proof
                  of safety.
                </li>
              </ul>
            </section>
          </>
        )}

        {state.status === 'validating' && (
          <ScanProgress
            fileName={state.file.name}
            sizeBytes={state.file.sizeBytes}
            progress={null}
            forced={false}
          />
        )}
        {state.status === 'confirm-force' && (
          <ForceScanPrompt
            fileName={state.file.name}
            issues={state.issues}
            onConfirm={confirmForceScan}
            onCancel={reset}
          />
        )}
        {state.status === 'scanning' && (
          <ScanProgress
            fileName={state.file.name}
            sizeBytes={state.file.sizeBytes}
            progress={state.progress}
            forced={state.force}
            onCancel={cancel}
          />
        )}
        {state.status === 'error' && (
          <ScanError
            fileName={state.file.name}
            error={state.error}
            onRetry={retry}
            onReset={reset}
          />
        )}
        {state.status === 'complete' && (
          <ScanResults
            analysis={state.analysis}
            issues={state.issues}
            onReset={reset}
            headingRef={resultsHeadingRef}
            {...(download === undefined ? {} : { download })}
          />
        )}
      </main>
      <AppFooter />
      {dragging && !showUpload && !busy && (
        <div className="drop-overlay" aria-hidden="true" data-testid="drop-overlay">
          <p className="drop-overlay__panel">Drop the file to scan it</p>
        </div>
      )}
    </>
  );
}
