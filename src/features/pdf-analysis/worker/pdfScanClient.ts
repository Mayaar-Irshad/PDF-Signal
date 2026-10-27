import { APP_CONFIG } from '../../../config/appConfig';
import type { ScanResult } from '../types/analysis';
import { isWorkerResponseMessage, type ScanRequestMessage, type ScanStage } from './protocol';

/** The part of the Worker interface the client uses; tests provide an in-process fake. */
export interface WorkerLike {
  postMessage(message: unknown): void;
  terminate(): void;
  onmessage: ((event: MessageEvent<unknown>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  onmessageerror: ((event: MessageEvent<unknown>) => void) | null;
}

export type ScanFailureCode =
  | 'cancelled'
  | 'timeout'
  | 'worker-unavailable'
  | 'worker-error'
  | 'protocol-error'
  | 'invalid-request'
  | 'file-too-large'
  | 'read-failed'
  | 'scan-failed';

const FAILURE_MESSAGES: Record<ScanFailureCode, string> = {
  cancelled: 'The scan was cancelled.',
  timeout: 'The scan took too long and was stopped.',
  'worker-unavailable': 'The scanner could not be started in this browser.',
  'worker-error': 'The scanner stopped unexpectedly.',
  'protocol-error': 'The scanner returned an unexpected response, so the result was discarded.',
  'invalid-request': 'The scanner received an invalid request.',
  'file-too-large': 'The file exceeds the size limit.',
  'read-failed': 'The file could not be read.',
  'scan-failed': 'The scanner stopped unexpectedly.',
};

/** Error with a fixed, user-presentable message chosen by PDF Signal. */
export class ScanClientError extends Error {
  readonly code: ScanFailureCode;

  constructor(code: ScanFailureCode) {
    super(FAILURE_MESSAGES[code]);
    this.name = 'ScanClientError';
    this.code = code;
  }
}

export interface ScanProgress {
  readonly stage: ScanStage;
  readonly fraction: number;
}

export interface ScanCallbacks {
  readonly onProgress?: (progress: ScanProgress) => void;
  readonly signal?: AbortSignal;
}

export interface PdfScanClient {
  scan(
    file: Blob,
    options: { readonly force: boolean },
    callbacks?: ScanCallbacks,
  ): Promise<ScanResult>;
}

export interface PdfScanClientOptions {
  readonly createWorker?: () => WorkerLike;
  readonly timeoutMs?: number;
}

function createDefaultWorker(): WorkerLike {
  return new Worker(new URL('./pdfScan.worker.ts', import.meta.url), {
    type: 'module',
    name: 'pdf-signal-scanner',
  });
}

let requestCounter = 0;

/**
 * Creates a client that runs each scan in a new dedicated worker and terminates the worker
 * as soon as the scan settles (result, error, cancellation or timeout). Terminating is what
 * makes cancellation immediate even while the synchronous scan loop is running, and it frees
 * the file bytes held by the worker.
 */
export function createPdfScanClient(options: PdfScanClientOptions = {}): PdfScanClient {
  const createWorker = options.createWorker ?? createDefaultWorker;
  const timeoutMs = options.timeoutMs ?? APP_CONFIG.scanTimeoutMs;

  return {
    scan(file, scanOptions, callbacks = {}) {
      return new Promise<ScanResult>((resolve, reject) => {
        const { signal, onProgress } = callbacks;
        if (signal?.aborted === true) {
          reject(new ScanClientError('cancelled'));
          return;
        }

        let worker: WorkerLike;
        try {
          worker = createWorker();
        } catch {
          reject(new ScanClientError('worker-unavailable'));
          return;
        }

        requestCounter += 1;
        const requestId = `scan-${requestCounter}`;
        let settled = false;

        const settle = (outcome: { result: ScanResult } | { error: ScanClientError }): void => {
          if (settled) {
            return;
          }
          settled = true;
          clearTimeout(timer);
          signal?.removeEventListener('abort', onAbort);
          worker.onmessage = null;
          worker.onerror = null;
          worker.onmessageerror = null;
          worker.terminate();
          if ('result' in outcome) {
            resolve(outcome.result);
          } else {
            reject(outcome.error);
          }
        };
        const fail = (code: ScanFailureCode): void => {
          settle({ error: new ScanClientError(code) });
        };
        const onAbort = (): void => {
          fail('cancelled');
        };

        const timer = setTimeout(() => {
          fail('timeout');
        }, timeoutMs);
        signal?.addEventListener('abort', onAbort, { once: true });

        worker.onmessage = (event) => {
          const message = event.data;
          if (!isWorkerResponseMessage(message) || message.requestId !== requestId) {
            fail('protocol-error');
            return;
          }
          switch (message.type) {
            case 'progress':
              onProgress?.({ stage: message.stage, fraction: message.fraction });
              return;
            case 'result':
              settle({ result: message.result });
              return;
            case 'error':
              fail(message.code);
              return;
          }
        };
        worker.onerror = (event) => {
          event.preventDefault();
          fail('worker-error');
        };
        worker.onmessageerror = () => {
          fail('protocol-error');
        };

        const request: ScanRequestMessage = {
          type: 'scan',
          requestId,
          file,
          options: { force: scanOptions.force },
        };
        try {
          worker.postMessage(request);
        } catch {
          fail('worker-error');
        }
      });
    },
  };
}
