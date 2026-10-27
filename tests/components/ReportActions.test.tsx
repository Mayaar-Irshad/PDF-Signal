import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ReportActions } from '../../src/components/results/ReportActions';
import { assessIndicators } from '../../src/features/pdf-analysis/assessment/assessIndicators';
import { scanPdf } from '../../src/features/pdf-analysis/engine/scanPdf';
import type { AnalysisResult } from '../../src/features/pdf-analysis/hooks/usePdfAnalysis';
import type { DownloadOutcome } from '../../src/features/pdf-analysis/reports/exportJsonReport';
import { getFixture } from '../fixtures/fixtureDefinitions';

const NOW = new Date('2026-05-06T07:08:09.000Z');

function analysis(name = 'Client contract.pdf'): AnalysisResult {
  const scan = scanPdf(getFixture('dates').build(), { sha256: 'b'.repeat(64) });
  return { file: { name, sizeBytes: scan.sizeBytes }, scan, assessment: assessIndicators(scan) };
}

function setup(
  download = vi.fn<(json: string, fileName: string) => DownloadOutcome>(() => ({ ok: true })),
) {
  const onReset = vi.fn();
  render(
    <ReportActions analysis={analysis()} onReset={onReset} download={download} now={() => NOW} />,
  );
  return { download, onReset, user: userEvent.setup() };
}

const parsedReport = (download: ReturnType<typeof setup>['download']) =>
  JSON.parse(download.mock.calls.at(-1)![0]) as Record<string, unknown> & {
    file: Record<string, unknown>;
  };

describe('ReportActions', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('downloads a valid JSON report with a safe file name', async () => {
    const { download, user } = setup();
    await user.click(screen.getByRole('button', { name: 'Download JSON report' }));
    expect(download).toHaveBeenCalledOnce();
    const [, fileName] = download.mock.calls[0]!;
    expect(fileName).toBe('pdf-signal-report-Client-contract-20260506-070809.json');
    const report = parsedReport(download);
    expect(report).toMatchObject({
      application: { name: 'PDF Signal' },
      file: { name: 'Client contract.pdf' },
    });
    expect(report).not.toHaveProperty('dates');
    expect(screen.getByTestId('report-status')).toHaveTextContent(`Report saved as ${fileName}.`);
  });

  it('applies the selected report options', async () => {
    const { download, user } = setup();
    await user.click(screen.getByRole('checkbox', { name: 'Include the file name' }));
    await user.click(screen.getByRole('checkbox', { name: /Include PDF date values/ }));
    await user.click(screen.getByRole('checkbox', { name: /Include all other PDF names/ }));
    await user.click(screen.getByRole('button', { name: 'Download JSON report' }));
    const report = parsedReport(download);
    expect(report.file).not.toHaveProperty('name');
    expect(report).toHaveProperty('dates');
    expect(report).toHaveProperty('names');
    expect(download.mock.calls[0]![1]).toBe('pdf-signal-report-20260506-070809.json');
  });

  it('reports a failed download', async () => {
    const { user } = setup(
      vi.fn(() => ({ ok: false as const, message: 'The report could not be downloaded.' })),
    );
    await user.click(screen.getByRole('button', { name: 'Download JSON report' }));
    expect(screen.getByTestId('report-status')).toHaveTextContent(
      'The report could not be downloaded.',
    );
    expect(screen.getByTestId('report-status')).toHaveClass('report-status--error');
  });

  it('reports an unexpected exception without exposing its text', async () => {
    const { user } = setup(
      vi.fn(() => {
        throw new Error('<b>internal detail</b>');
      }),
    );
    await user.click(screen.getByRole('button', { name: 'Download JSON report' }));
    expect(screen.getByTestId('report-status')).toHaveTextContent(
      'The report could not be created.',
    );
    expect(screen.queryByText(/internal detail/)).not.toBeInTheDocument();
  });

  it('uses a real object URL download and revokes the URL', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const createObjectURL = vi.fn(() => 'blob:pdf-signal-test');
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);
    render(<ReportActions analysis={analysis()} onReset={vi.fn()} now={() => NOW} />);
    await userEvent
      .setup({ advanceTimers: vi.advanceTimersByTime })
      .click(screen.getByRole('button', { name: 'Download JSON report' }));
    expect(click).toHaveBeenCalledOnce();
    const blob = (createObjectURL.mock.calls[0] as unknown as [Blob])[0];
    expect(blob.type).toBe('application/json');
    expect(document.querySelector('a[download]')).toBeNull();
    vi.advanceTimersByTime(1500);
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:pdf-signal-test');
    vi.useRealTimers();
  });

  it('offers a reset action', async () => {
    const { onReset, user } = setup();
    await user.click(screen.getByRole('button', { name: 'Scan another file' }));
    expect(onReset).toHaveBeenCalledOnce();
  });
});
