import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { scanPdf } from '../../src/features/pdf-analysis/engine/scanPdf';
import { usePdfAnalysis } from '../../src/features/pdf-analysis/hooks/usePdfAnalysis';
import type { PdfScanClient } from '../../src/features/pdf-analysis/worker/pdfScanClient';
import { BASIC_OBJECTS, createTestPdf } from '../fixtures/createTestPdf';
import { getFixture } from '../fixtures/fixtureDefinitions';

/**
 * A client that ignores cancellation and answers after a per-file delay, so that only the
 * hook's own bookkeeping can keep a slow, superseded scan off the screen.
 */
function slowClient(delays: Record<string, number>): PdfScanClient {
  return {
    scan: (file) =>
      new Promise((resolve) => {
        const name = file instanceof File ? file.name : '';
        void file.arrayBuffer().then((buffer) => {
          setTimeout(() => {
            resolve(scanPdf(new Uint8Array(buffer)));
          }, delays[name] ?? 0);
        });
      }),
  };
}

const pdf = (id: string, name: string) =>
  new File([getFixture(id).build()], name, { type: 'application/pdf' });

describe('usePdfAnalysis', () => {
  it('keeps the newest selection when an older scan finishes later', async () => {
    const client = slowClient({ 'slow.pdf': 120, 'fast.pdf': 0 });
    const { result } = renderHook(() => usePdfAnalysis(client));
    act(() => {
      result.current.selectFile(pdf('javascript-open-action', 'slow.pdf'));
    });
    await waitFor(() => {
      expect(result.current.state.status).toBe('scanning');
    });
    act(() => {
      result.current.selectFile(pdf('minimal', 'fast.pdf'));
    });
    await waitFor(() => {
      expect(result.current.state.status).toBe('complete');
    });
    await new Promise((resolve) => setTimeout(resolve, 200));
    const { state } = result.current;
    expect(state.status === 'complete' && state.analysis.file.name).toBe('fast.pdf');
    expect(state.status === 'complete' && state.analysis.assessment.level).toBe('none-detected');
  });

  it('discards a scan that finishes after a reset', async () => {
    const { result } = renderHook(() => usePdfAnalysis(slowClient({ 'a.pdf': 60 })));
    act(() => {
      result.current.selectFile(pdf('minimal', 'a.pdf'));
    });
    await waitFor(() => {
      expect(result.current.state.status).toBe('scanning');
    });
    act(() => {
      result.current.reset();
    });
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(result.current.state).toEqual({ status: 'idle' });
  });

  it('ignores retry and force confirmation when they do not apply', () => {
    const { result } = renderHook(() => usePdfAnalysis(slowClient({})));
    act(() => {
      result.current.retry();
      result.current.confirmForceScan();
      result.current.cancel();
    });
    expect(result.current.state).toEqual({ status: 'idle' });
  });

  it('does not keep the file or its contents in state', async () => {
    const secret = 'PRIVATE-DIAGNOSIS-TEXT';
    const document = createTestPdf({
      objects: [
        ...BASIC_OBJECTS,
        { body: `<< /Title (${secret}) >>` },
        { body: '<< >>', stream: secret },
      ],
    });
    const { result } = renderHook(() => usePdfAnalysis(slowClient({})));
    act(() => {
      result.current.selectFile(new File([document], 'doc.pdf'));
    });
    await waitFor(() => {
      expect(result.current.state.status).toBe('complete');
    });
    expect(JSON.stringify(result.current.state)).not.toContain(secret);
    const holdsBinary = (value: unknown): boolean =>
      value instanceof Blob ||
      value instanceof ArrayBuffer ||
      ArrayBuffer.isView(value) ||
      (typeof value === 'object' && value !== null && Object.values(value).some(holdsBinary));
    expect(holdsBinary(result.current.state)).toBe(false);
  });
});
