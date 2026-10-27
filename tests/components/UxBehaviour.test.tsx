import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../../src/app/App';
import { ScanResults } from '../../src/components/results/ScanResults';
import { assessIndicators } from '../../src/features/pdf-analysis/assessment/assessIndicators';
import { analyzePdf } from '../../src/features/pdf-analysis/engine/analyzePdf';
import type { AnalysisResult } from '../../src/features/pdf-analysis/hooks/usePdfAnalysis';
import { bytes } from '../fixtures/createTestPdf';
import { getFixture } from '../fixtures/fixtureDefinitions';
import { inProcessClient } from '../fixtures/inProcessWorker';

async function renderResults(id: string) {
  const scan = await analyzePdf(getFixture(id).build(), { sha256: 'a'.repeat(64) });
  const analysis: AnalysisResult = {
    file: { name: `${id}.pdf`, sizeBytes: scan.sizeBytes },
    scan,
    assessment: assessIndicators(scan),
  };
  render(<ScanResults analysis={analysis} issues={[]} onReset={vi.fn()} />);
  return userEvent.setup();
}

const keywordOrder = () =>
  within(screen.getByRole('table', { name: /PDFiD keyword counts/ }))
    .getAllByRole('rowheader')
    .map((header) => header.querySelector('code')?.textContent);

describe('results presentation', () => {
  it('names the file in the results heading and gives advice for the level', async () => {
    await renderResults('javascript-open-action');
    expect(
      screen.getByRole('heading', { level: 2, name: /^Results for javascript-open-action\.pdf/ }),
    ).toBeInTheDocument();
    expect(screen.getByText('What to do:').parentElement).toHaveTextContent(
      /Do not open this file in a PDF reader/,
    );
  });

  it('lists findings that restate a high-risk finding under it', async () => {
    await renderResults('javascript-open-action');
    const assessment = document.getElementById('section-assessment')!;
    const titles = within(assessment)
      .getAllByRole('heading', { level: 4 })
      .map((heading) => heading.textContent);
    expect(titles).toContain('JavaScript runs automatically');
    expect(titles).not.toContain('JavaScript present');
    expect(
      within(assessment).getByText(/Also flagged: JavaScript present, Automatic action present\./),
    ).toBeInTheDocument();
  });

  it('orders keywords by risk by default and can switch to PDFiD order', async () => {
    const user = await renderResults('javascript-open-action');
    expect(keywordOrder().slice(0, 3)).toEqual(['/JS', '/JavaScript', '/OpenAction']);
    await user.selectOptions(screen.getByRole('combobox', { name: 'Order' }), 'pdfid');
    expect(keywordOrder().slice(0, 3)).toEqual(['obj', 'endobj', 'stream']);
    expect(keywordOrder()).toHaveLength(21);
  });

  it('shows absent keywords as a muted dash with an accessible label', async () => {
    await renderResults('minimal');
    const row = within(screen.getByRole('table', { name: /PDFiD keyword counts/ }))
      .getAllByRole('rowheader')
      .find((header) => header.querySelector('code')?.textContent === '/JavaScript')!
      .closest('tr')!;
    expect(within(row).getByText('Not found')).toHaveClass('visually-hidden');
    expect(within(row).queryByText('Context')).not.toBeInTheDocument();
  });

  it('uses a calm tone and next step for a clean file', async () => {
    await renderResults('minimal');
    expect(screen.getByText('What to do:').parentElement).toHaveTextContent(
      /Open the file with your usual care/,
    );
    expect(screen.queryByTestId('threat-alert')).not.toBeInTheDocument();
  });
});

describe('focus and page title', () => {
  it('moves focus to the forced-scan prompt and updates the page title', async () => {
    render(<App createScanClient={() => inProcessClient()} />);
    const user = userEvent.setup({ applyAccept: false });
    await user.upload(
      screen.getByTestId('file-input'),
      new File([bytes('plain text')], 'notes.pdf'),
    );
    const heading = await screen.findByRole('heading', { name: 'This file may not be a PDF' });
    await waitFor(() => {
      expect(heading).toHaveFocus();
    });
    expect(document.title).toBe('Not a PDF? · PDF Signal');
    // The safe choice is the primary action.
    expect(screen.getByRole('button', { name: 'Choose another file' })).toHaveClass(
      'button--primary',
    );
    await user.click(screen.getByRole('button', { name: 'Scan anyway (forced mode)' }));
    await screen.findByRole('heading', { name: /^Results for notes\.pdf/ });
    expect(document.title).toBe('Inconclusive · notes.pdf · PDF Signal');
    await user.click(screen.getAllByRole('button', { name: 'Scan another file' })[0]!);
    expect(document.title).toBe('PDF Signal · Local PDF security triage');
  });
});
