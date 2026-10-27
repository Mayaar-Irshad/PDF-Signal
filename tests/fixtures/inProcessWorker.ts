import type { WorkerResponseMessage } from '../../src/features/pdf-analysis/worker/protocol';
import {
  createPdfScanClient,
  type PdfScanClient,
  type WorkerLike,
} from '../../src/features/pdf-analysis/worker/pdfScanClient';
import { handleScanRequest } from '../../src/features/pdf-analysis/worker/scanWorkerHandler';

/** Base class for worker test doubles: records messages and termination. */
export class FakeWorker implements WorkerLike {
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  onmessageerror: ((event: MessageEvent<unknown>) => void) | null = null;
  readonly received: unknown[] = [];
  terminated = false;

  postMessage(message: unknown): void {
    this.received.push(message);
  }

  terminate(): void {
    this.terminated = true;
  }

  /** Delivers a message to the client as a real worker would (asynchronously). */
  emit(data: unknown): void {
    if (!this.terminated) {
      this.onmessage?.(new MessageEvent('message', { data }));
    }
  }

  fail(): void {
    if (!this.terminated) {
      this.onerror?.(new ErrorEvent('error', { cancelable: true, message: 'simulated failure' }));
    }
  }
}

/**
 * Runs the real worker message handler (and therefore the real scanning engine) in-process.
 * Responses are structured-cloned and delivered on a later task, like postMessage.
 */
export class InProcessWorker extends FakeWorker {
  private readonly delayMs: number;

  constructor(delayMs = 0) {
    super();
    this.delayMs = delayMs;
  }

  override postMessage(message: unknown): void {
    super.postMessage(message);
    setTimeout(() => {
      void handleScanRequest(message, (response: WorkerResponseMessage) => {
        const copy = structuredClone(response);
        setTimeout(() => {
          this.emit(copy);
        }, this.delayMs);
      });
    }, 0);
  }
}

/** A worker that accepts requests and never answers (for cancellation and timeouts). */
export class SilentWorker extends FakeWorker {}

export function inProcessClient(
  options: { timeoutMs?: number; delayMs?: number } = {},
): PdfScanClient {
  return createPdfScanClient({
    createWorker: () => new InProcessWorker(options.delayMs ?? 0),
    timeoutMs: options.timeoutMs ?? 10_000,
  });
}
