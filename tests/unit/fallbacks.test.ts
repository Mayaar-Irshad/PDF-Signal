import { afterEach, describe, expect, it, vi } from 'vitest';
import { computeSha256Hex } from '../../src/features/pdf-analysis/engine/hash';
import { readBlobBytes } from '../../src/features/pdf-analysis/validation/validatePdfFile';
import type { WorkerResponseMessage } from '../../src/features/pdf-analysis/worker/protocol';
import { handleScanRequest } from '../../src/features/pdf-analysis/worker/scanWorkerHandler';
import { BASIC_OBJECTS, bytes, createTestPdf } from '../fixtures/createTestPdf';

/** Environment fallbacks: missing Web Crypto, missing Blob.arrayBuffer, lying Blob sizes. */
describe('environment fallbacks', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns null instead of a hash when Web Crypto is unavailable', async () => {
    vi.stubGlobal('crypto', undefined);
    await expect(computeSha256Hex(bytes('abc'))).resolves.toBeNull();
    vi.stubGlobal('crypto', {});
    await expect(computeSha256Hex(bytes('abc'))).resolves.toBeNull();
  });

  it('still scans when hashing fails, and says so', async () => {
    vi.stubGlobal('crypto', {
      subtle: { digest: () => Promise.reject(new Error('OperationError')) },
    });
    const messages: WorkerResponseMessage[] = [];
    const file = new File([createTestPdf({ objects: BASIC_OBJECTS })], 'a.pdf');
    await handleScanRequest(
      { type: 'scan', requestId: 'r', file, options: { force: false } },
      (m) => messages.push(m),
    );
    const last = messages.at(-1);
    expect(last?.type).toBe('result');
    if (last?.type === 'result') {
      expect(last.result.sha256).toBeNull();
      expect(last.result.messages.map((message) => message.code)).toContain('hash-unavailable');
    }
  });

  it('re-checks the size after reading, in case the reported size was wrong', async () => {
    const file = new Blob([new Uint8Array(10)]);
    Object.defineProperty(file, 'slice', { value: () => new Blob([new Uint8Array(4096)]) });
    const messages: WorkerResponseMessage[] = [];
    await handleScanRequest(
      { type: 'scan', requestId: 'r', file, options: { force: false } },
      (m) => messages.push(m),
      {
        maxFileSizeBytes: 1024,
      },
    );
    expect(messages.at(-1)).toMatchObject({ type: 'error', code: 'file-too-large' });
  });

  it('reads blobs with FileReader when Blob.arrayBuffer is missing', async () => {
    class FakeFileReader {
      result: ArrayBuffer | string | null = null;
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      readAsArrayBuffer(blob: { data: Uint8Array<ArrayBuffer> }) {
        this.result = blob.data.buffer;
        setTimeout(() => this.onload?.(), 0);
      }
    }
    vi.stubGlobal('FileReader', FakeFileReader);
    const legacy = { slice: () => ({ data: bytes('%PDF') }), size: 4 } as unknown as Blob;
    expect(Array.from(await readBlobBytes(legacy))).toEqual([0x25, 0x50, 0x44, 0x46]);
  });

  it('rejects when FileReader fails or returns text', async () => {
    class FailingReader {
      result: string | null = null;
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      readAsArrayBuffer() {
        setTimeout(() => this.onerror?.(), 0);
      }
    }
    vi.stubGlobal('FileReader', FailingReader);
    const legacy = { slice: () => ({}), size: 1 } as unknown as Blob;
    await expect(readBlobBytes(legacy)).rejects.toThrow('could not be read');

    class TextReader extends FailingReader {
      override readAsArrayBuffer() {
        this.result = 'text';
        setTimeout(() => this.onload?.(), 0);
      }
    }
    vi.stubGlobal('FileReader', TextReader);
    await expect(readBlobBytes(legacy)).rejects.toThrow('Unexpected FileReader result');
  });
});
