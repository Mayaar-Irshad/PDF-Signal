import { useCallback, useEffect, useRef, useState } from 'react';
import { assessIndicators } from '../assessment/assessIndicators';
import type { Assessment, ScanResult } from '../types/analysis';
import {
  sanitizeFileName,
  validatePdfFile,
  type ValidationIssue,
} from '../validation/validatePdfFile';
import {
  ScanClientError,
  type PdfScanClient,
  type ScanFailureCode,
  type ScanProgress,
} from '../worker/pdfScanClient';

/** Metadata kept about the selected file. The file contents are never stored in state. */
export interface SelectedFileInfo {
  /** Sanitized for display; see `sanitizeFileName`. */
  readonly name: string;
  readonly sizeBytes: number;
}

export interface AnalysisResult {
  readonly file: SelectedFileInfo;
  readonly scan: ScanResult;
  readonly assessment: Assessment;
}

export interface ScanFailure {
  readonly code: ScanFailureCode;
  readonly message: string;
}

export type AnalysisState =
  | { readonly status: 'idle' }
  | { readonly status: 'validating'; readonly file: SelectedFileInfo }
  | {
      readonly status: 'invalid';
      readonly file: SelectedFileInfo;
      readonly issues: readonly ValidationIssue[];
    }
  | {
      readonly status: 'confirm-force';
      readonly file: SelectedFileInfo;
      readonly issues: readonly ValidationIssue[];
    }
  | {
      readonly status: 'scanning';
      readonly file: SelectedFileInfo;
      readonly issues: readonly ValidationIssue[];
      readonly force: boolean;
      readonly progress: ScanProgress;
    }
  | {
      readonly status: 'complete';
      readonly file: SelectedFileInfo;
      readonly issues: readonly ValidationIssue[];
      readonly analysis: AnalysisResult;
    }
  | {
      readonly status: 'error';
      readonly file: SelectedFileInfo;
      readonly issues: readonly ValidationIssue[];
      readonly force: boolean;
      readonly error: ScanFailure;
    };

export interface PdfAnalysisControls {
  readonly state: AnalysisState;
  readonly selectFile: (file: File) => void;
  readonly confirmForceScan: () => void;
  readonly cancel: () => void;
  readonly retry: () => void;
  readonly reset: () => void;
}

const UNEXPECTED_FAILURE: ScanFailure = {
  code: 'worker-error',
  message: 'The scanner stopped unexpectedly.',
};

/**
 * Drives the upload → validate → scan → assess workflow.
 *
 * Every asynchronous step carries a generation number; results from a superseded selection,
 * a reset or a cancelled scan are discarded, so stale results never reach the screen. The
 * File object is held in a ref only while it may still be needed (forced-scan confirmation
 * or retry) and is released when the scan completes or the state is reset.
 */
export function usePdfAnalysis(client: PdfScanClient): PdfAnalysisControls {
  const [state, setState] = useState<AnalysisState>({ status: 'idle' });
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const pendingFile = useRef<File | null>(null);

  const runScan = useCallback(
    (
      token: number,
      file: File,
      info: SelectedFileInfo,
      issues: readonly ValidationIssue[],
      force: boolean,
    ) => {
      const abort = new AbortController();
      controller.current = abort;
      setState({
        status: 'scanning',
        file: info,
        issues,
        force,
        progress: { stage: 'reading', fraction: 0 },
      });

      client
        .scan(
          file,
          { force },
          {
            signal: abort.signal,
            onProgress: (progress) => {
              if (token === generation.current) {
                setState((previous) =>
                  previous.status === 'scanning' ? { ...previous, progress } : previous,
                );
              }
            },
          },
        )
        .then((scan) => {
          if (token !== generation.current) {
            return;
          }
          pendingFile.current = null;
          const analysis: AnalysisResult = { file: info, scan, assessment: assessIndicators(scan) };
          setState({ status: 'complete', file: info, issues, analysis });
        })
        .catch((error: unknown) => {
          if (token !== generation.current) {
            return;
          }
          const failure =
            error instanceof ScanClientError
              ? { code: error.code, message: error.message }
              : UNEXPECTED_FAILURE;
          setState({ status: 'error', file: info, issues, force, error: failure });
        })
        .finally(() => {
          if (controller.current === abort) {
            controller.current = null;
          }
        });
    },
    [client],
  );

  const selectFile = useCallback(
    (file: File) => {
      generation.current += 1;
      const token = generation.current;
      controller.current?.abort();
      pendingFile.current = file;
      const info: SelectedFileInfo = { name: sanitizeFileName(file.name), sizeBytes: file.size };
      setState({ status: 'validating', file: info });

      void validatePdfFile(file).then((validation) => {
        if (token !== generation.current) {
          return;
        }
        if (!validation.canScan) {
          pendingFile.current = null;
          setState({ status: 'invalid', file: info, issues: validation.issues });
        } else if (validation.requiresForce) {
          setState({ status: 'confirm-force', file: info, issues: validation.issues });
        } else {
          runScan(token, file, info, validation.issues, false);
        }
      });
    },
    [runScan],
  );

  const confirmForceScan = useCallback(() => {
    const file = pendingFile.current;
    if (state.status !== 'confirm-force' || file === null) {
      return;
    }
    generation.current += 1;
    runScan(generation.current, file, state.file, state.issues, true);
  }, [runScan, state]);

  const retry = useCallback(() => {
    const file = pendingFile.current;
    if (state.status !== 'error' || file === null) {
      return;
    }
    generation.current += 1;
    runScan(generation.current, file, state.file, state.issues, state.force);
  }, [runScan, state]);

  const cancel = useCallback(() => {
    controller.current?.abort();
  }, []);

  const reset = useCallback(() => {
    generation.current += 1;
    controller.current?.abort();
    controller.current = null;
    pendingFile.current = null;
    setState({ status: 'idle' });
  }, []);

  useEffect(
    () => () => {
      generation.current += 1;
      controller.current?.abort();
      pendingFile.current = null;
    },
    [],
  );

  return { state, selectFile, confirmForceScan, cancel, retry, reset };
}
