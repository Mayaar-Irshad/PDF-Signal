import { describe, expect, it, vi } from 'vitest';
import { scanPdf } from '../../src/features/pdf-analysis/engine/scanPdf';
import {
  createPdfScanClient,
  ScanClientError,
  type ScanProgress,
} from '../../src/features/pdf-analysis/worker/pdfScanClient';
import {
  isScanResult,
  isWorkerResponseMessage,
  type WorkerResponseMessage,
} from '../../src/features/pdf-analysis/worker/protocol';
import { handleScanRequest } from '../../src/features/pdf-analysis/worker/scanWorkerHandler';
import { bytes } from '../fixtures/createTestPdf';
import { getFixture } from '../fixtures/fixtureDefinitions';
import {
  FakeWorker,
  InProcessWorker,
  inProcessClient,
  SilentWorker,
} from '../fixtures/inProcessWorker';

const pdfFile = (id = 'javascript-open-action') =>
  new File([getFixture(id).build()], `${id}.pdf`, { type: 'application/pdf' });

async function expectFailure(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.then(
    () => null,
    (reason: unknown) => reason,
  );
  expect(error).toBeInstanceOf(ScanClientError);
  expect((error as ScanClientError).code).toBe(code);
}

describe('scan worker handler', () => {
  async function run(data: unknown, maxFileSizeBytes = 1024 * 1024) {
    const messages: WorkerResponseMessage[] = [];
    await handleScanRequest(data, (message) => messages.push(message), { maxFileSizeBytes });
    return messages;
  }

  it('reads, hashes and scans the file, reporting progress', async () => {
    const messages = await run({
      type: 'scan',
      requestId: 'r1',
      file: pdfFile(),
      options: { force: false },
    });
    expect(messages.every(isWorkerResponseMessage)).toBe(true);
    expect(
      messages.filter((message) => message.type === 'progress').map((message) => message.stage),
    ).toEqual(expect.arrayContaining(['reading', 'hashing', 'scanning']));
    const last = messages.at(-1);
    expect(last?.type).toBe('result');
    if (last?.type === 'result') {
      expect(last.requestId).toBe('r1');
      expect(last.result.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(last.result.keywords.find((keyword) => keyword.name === '/JS')?.count).toBe(1);
    }
  });

  it.each([
    ['null', null],
    ['a string', 'scan'],
    [
      'an unknown type',
      { type: 'eval', requestId: 'r', file: new Blob([]), options: { force: false } },
    ],
    ['a missing file', { type: 'scan', requestId: 'r', options: { force: false } }],
    [
      'a non-blob file',
      { type: 'scan', requestId: 'r', file: 'C:/secret.pdf', options: { force: false } },
    ],
    [
      'a bad force flag',
      { type: 'scan', requestId: 'r', file: new Blob([]), options: { force: 'yes' } },
    ],
    [
      'an oversized id',
      { type: 'scan', requestId: 'x'.repeat(65), file: new Blob([]), options: { force: false } },
    ],
  ])('rejects %s', async (_, data) => {
    const messages = await run(data);
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatchObject({ type: 'error', code: 'invalid-request' });
  });

  it('enforces the size limit independently of the main thread', async () => {
    const messages = await run(
      {
        type: 'scan',
        requestId: 'r',
        file: new Blob([new Uint8Array(2048)]),
        options: { force: false },
      },
      1024,
    );
    expect(messages).toEqual([
      {
        type: 'error',
        requestId: 'r',
        code: 'file-too-large',
        message: 'The file exceeds the size limit.',
      },
    ]);
  });

  it('reports unreadable files with a fixed message', async () => {
    const file = new Blob([bytes('%PDF')]);
    Object.defineProperty(file, 'slice', {
      value: () => ({ arrayBuffer: () => Promise.reject(new Error('C:/private/path')) }),
    });
    const messages = await run({ type: 'scan', requestId: 'r', file, options: { force: false } });
    expect(messages.at(-1)).toEqual({
      type: 'error',
      requestId: 'r',
      code: 'read-failed',
      message: 'The file could not be read.',
    });
  });
});

describe('PDF scan client with the real handler', () => {
  it('includes the deep analysis and reports its progress', async () => {
    const stages = new Set<string>();
    const result = await inProcessClient().scan(
      pdfFile('objstm-hidden-javascript'),
      { force: false },
      {
        onProgress: (update) => stages.add(update.stage),
      },
    );
    expect(stages).toContain('deep-scan');
    expect(result.deep?.hiddenKeywords.map((keyword) => keyword.name)).toEqual([
      '/JS',
      '/JavaScript',
      '/OpenAction',
    ]);
  });

  it('returns the same result as scanning directly', async () => {
    const progress: ScanProgress[] = [];
    const result = await inProcessClient().scan(
      pdfFile(),
      { force: false },
      { onProgress: (update) => progress.push(update) },
    );
    const direct = scanPdf(getFixture('javascript-open-action').build(), { sha256: result.sha256 });
    expect(result.keywords).toEqual(direct.keywords);
    expect(result.eof).toEqual(direct.eof);
    expect(isScanResult(result)).toBe(true);
    expect(progress.length).toBeGreaterThan(0);
  });

  it('passes forced mode through', async () => {
    const file = new File([bytes('1 0 obj << /JS (x) >> endobj')], 'x.bin');
    const standard = await inProcessClient().scan(file, { force: false });
    expect(standard.keywordScanPerformed).toBe(false);
    const forced = await inProcessClient().scan(file, { force: true });
    expect(forced.mode).toBe('forced');
    expect(forced.keywords.find((keyword) => keyword.name === '/JS')?.count).toBe(1);
  });

  it('terminates the worker after every scan', async () => {
    const workers: InProcessWorker[] = [];
    const client = createPdfScanClient({
      createWorker: () => {
        const worker = new InProcessWorker();
        workers.push(worker);
        return worker;
      },
    });
    await client.scan(pdfFile(), { force: false });
    await client.scan(pdfFile('minimal'), { force: false });
    expect(workers).toHaveLength(2);
    expect(workers.every((worker) => worker.terminated)).toBe(true);
  });

  it('sends the file by reference, never its name', async () => {
    const worker = new InProcessWorker();
    await createPdfScanClient({ createWorker: () => worker }).scan(pdfFile(), { force: false });
    expect(worker.received).toHaveLength(1);
    const request = worker.received[0] as Record<string, unknown>;
    expect(Object.keys(request).sort()).toEqual(['file', 'options', 'requestId', 'type']);
    expect(request.file).toBeInstanceOf(Blob);
  });
});

describe('PDF scan client failure handling', () => {
  it('cancels a running scan and terminates the worker', async () => {
    const worker = new SilentWorker();
    const controller = new AbortController();
    const pending = createPdfScanClient({ createWorker: () => worker }).scan(
      pdfFile(),
      { force: false },
      { signal: controller.signal },
    );
    controller.abort();
    await expectFailure(pending, 'cancelled');
    expect(worker.terminated).toBe(true);
  });

  it('does not start a worker for an already-aborted signal', async () => {
    const createWorker = vi.fn(() => new SilentWorker());
    const controller = new AbortController();
    controller.abort();
    await expectFailure(
      createPdfScanClient({ createWorker }).scan(
        pdfFile(),
        { force: false },
        { signal: controller.signal },
      ),
      'cancelled',
    );
    expect(createWorker).not.toHaveBeenCalled();
  });

  it('times out and terminates the worker', async () => {
    const worker = new SilentWorker();
    await expectFailure(
      createPdfScanClient({ createWorker: () => worker, timeoutMs: 20 }).scan(pdfFile(), {
        force: false,
      }),
      'timeout',
    );
    expect(worker.terminated).toBe(true);
  });

  it('reports worker crashes', async () => {
    const worker = new SilentWorker();
    const pending = createPdfScanClient({ createWorker: () => worker }).scan(pdfFile(), {
      force: false,
    });
    worker.fail();
    await expectFailure(pending, 'worker-error');
    expect(worker.terminated).toBe(true);
  });

  it('reports a browser without worker support', async () => {
    const client = createPdfScanClient({
      createWorker: () => {
        throw new Error('Worker is not defined');
      },
    });
    await expectFailure(client.scan(pdfFile(), { force: false }), 'worker-unavailable');
  });

  it('reports a failing postMessage', async () => {
    class BrokenWorker extends FakeWorker {
      override postMessage(): void {
        throw new DOMException('DataCloneError');
      }
    }
    const worker = new BrokenWorker();
    await expectFailure(
      createPdfScanClient({ createWorker: () => worker }).scan(pdfFile(), { force: false }),
      'worker-error',
    );
  });

  it.each([
    [
      'an unknown message type',
      (id: string) => ({ type: 'html', requestId: id, body: '<img src=x onerror=alert(1)>' }),
    ],
    [
      'a mismatched request id',
      () => ({ type: 'progress', requestId: 'other', stage: 'reading', fraction: 0 }),
    ],
    [
      'an out-of-range progress value',
      (id: string) => ({ type: 'progress', requestId: id, stage: 'scanning', fraction: 7 }),
    ],
    [
      'a malformed result',
      (id: string) => ({
        type: 'result',
        requestId: id,
        result: { schemaVersion: 1, keywords: 'x' },
      }),
    ],
    [
      'an unknown error code',
      (id: string) => ({ type: 'error', requestId: id, code: 'pwned', message: 'x' }),
    ],
    ['a non-object', () => 'result'],
    [
      'a result with a malformed deep analysis',
      (id: string) => ({
        type: 'result',
        requestId: id,
        result: {
          ...scanPdf(getFixture('minimal').build()),
          deep: { status: 'complete', actions: '<b>' },
        },
      }),
    ],
  ])('discards %s as a protocol error', async (_, makeMessage) => {
    const worker = new SilentWorker();
    const pending = createPdfScanClient({ createWorker: () => worker }).scan(pdfFile(), {
      force: false,
    });
    const request = worker.received[0] as { requestId: string };
    worker.emit(makeMessage(request.requestId));
    await expectFailure(pending, 'protocol-error');
    expect(worker.terminated).toBe(true);
  });

  it('maps worker error codes to fixed messages', async () => {
    const worker = new SilentWorker();
    const pending = createPdfScanClient({ createWorker: () => worker }).scan(pdfFile(), {
      force: false,
    });
    const request = worker.received[0] as { requestId: string };
    worker.emit({
      type: 'error',
      requestId: request.requestId,
      code: 'scan-failed',
      message: '<b>file-derived text</b>',
    });
    const error = await pending.catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(ScanClientError);
    expect((error as ScanClientError).message).toBe('The scanner stopped unexpectedly.');
  });

  it('reports message deserialization errors', async () => {
    const worker = new SilentWorker();
    const pending = createPdfScanClient({ createWorker: () => worker }).scan(pdfFile(), {
      force: false,
    });
    worker.onmessageerror?.(new MessageEvent('messageerror'));
    await expectFailure(pending, 'protocol-error');
  });

  it('ignores messages after the scan settled', async () => {
    const worker = new SilentWorker();
    const controller = new AbortController();
    const pending = createPdfScanClient({ createWorker: () => worker }).scan(
      pdfFile(),
      { force: false },
      { signal: controller.signal },
    );
    controller.abort();
    await expectFailure(pending, 'cancelled');
    expect(worker.onmessage).toBeNull();
    worker.terminated = false;
    expect(() => {
      worker.emit({ type: 'result' });
    }).not.toThrow();
  });
});
