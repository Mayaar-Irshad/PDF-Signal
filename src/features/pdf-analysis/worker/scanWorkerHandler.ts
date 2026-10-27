import { APP_CONFIG } from '../../../config/appConfig';
import { computeSha256Hex } from '../engine/hash';
import { analyzePdf } from '../engine/analyzePdf';
import { readBlobBytes } from '../validation/validatePdfFile';
import { isScanRequestMessage, requestIdOf, type WorkerResponseMessage } from './protocol';

export interface WorkerHandlerOptions {
  readonly maxFileSizeBytes: number;
}

const DEFAULT_OPTIONS: WorkerHandlerOptions = { maxFileSizeBytes: APP_CONFIG.maxFileSizeBytes };

/**
 * Handles one message inside the scan worker. Kept separate from the worker entry point so
 * the same code can be exercised in tests without a real Worker.
 *
 * Error replies use fixed messages written here; exception text is never forwarded, so
 * nothing derived from the file can appear in an error message.
 */
export async function handleScanRequest(
  data: unknown,
  post: (message: WorkerResponseMessage) => void,
  options: WorkerHandlerOptions = DEFAULT_OPTIONS,
): Promise<void> {
  if (!isScanRequestMessage(data)) {
    post({
      type: 'error',
      requestId: requestIdOf(data),
      code: 'invalid-request',
      message: 'The scanner received an invalid request.',
    });
    return;
  }
  const { requestId, file } = data;

  // The main thread validates the size too; the worker enforces it independently.
  if (file.size > options.maxFileSizeBytes) {
    post({
      type: 'error',
      requestId,
      code: 'file-too-large',
      message: 'The file exceeds the size limit.',
    });
    return;
  }

  post({ type: 'progress', requestId, stage: 'reading', fraction: 0 });
  let bytes: Uint8Array<ArrayBuffer>;
  try {
    bytes = await readBlobBytes(file);
  } catch {
    post({ type: 'error', requestId, code: 'read-failed', message: 'The file could not be read.' });
    return;
  }
  if (bytes.length > options.maxFileSizeBytes) {
    post({
      type: 'error',
      requestId,
      code: 'file-too-large',
      message: 'The file exceeds the size limit.',
    });
    return;
  }

  post({ type: 'progress', requestId, stage: 'hashing', fraction: 0 });
  let sha256: string | null;
  try {
    sha256 = await computeSha256Hex(bytes);
  } catch {
    sha256 = null;
  }

  post({ type: 'progress', requestId, stage: 'scanning', fraction: 0 });
  try {
    const result = await analyzePdf(bytes, {
      force: data.options.force,
      sha256,
      onProgress: (fraction) => {
        post({ type: 'progress', requestId, stage: 'scanning', fraction });
      },
      onDeepProgress: (fraction) => {
        post({ type: 'progress', requestId, stage: 'deep-scan', fraction });
      },
    });
    post({ type: 'result', requestId, result });
  } catch {
    post({
      type: 'error',
      requestId,
      code: 'scan-failed',
      message: 'The scanner stopped unexpectedly.',
    });
  }
}
