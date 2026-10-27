import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ScanResults } from '../../src/components/results/ScanResults';
import { assessIndicators } from '../../src/features/pdf-analysis/assessment/assessIndicators';
import { scanPdf } from '../../src/features/pdf-analysis/engine/scanPdf';
import type { AnalysisResult } from '../../src/features/pdf-analysis/hooks/usePdfAnalysis';
import { BASIC_OBJECTS, bytes, createTestPdf } from '../fixtures/createTestPdf';
import { getFixture } from '../fixtures/fixtureDefinitions';

function analysisOf(pdf: Uint8Array, name = 'sample.pdf', force = false): AnalysisResult {
  const scan = scanPdf(pdf, { sha256: 'f'.repeat(64), force });
  return { file: { name, sizeBytes: pdf.length }, scan, assessment: assessIndicators(scan) };
}

function renderResults(analysis: AnalysisResult) {
  const onReset = vi.fn();
  render(<ScanResults analysis={analysis} issues={[]} onReset={onReset} />);
  return { onReset, user: userEvent.setup() };
}

const keywordTable = () => screen.getByRole('table', { name: /PDFiD keyword counts/ });
const rowFor = (name: string) =>
  within(keywordTable())
    .getAllByRole('rowheader')
    .find((header) => header.querySelector('code')?.textContent === name)!
    .closest('tr')!;

describe('ScanResults', () => {
  it('shows every counter, including zero counts', () => {
    renderResults(analysisOf(getFixture('minimal').build()));
    const rows = within(keywordTable()).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(21);
    expect(within(rowFor('obj')).getAllByRole('cell')[0]).toHaveTextContent('3');
    expect(within(rowFor('/JavaScript')).getAllByRole('cell')[0]).toHaveTextContent('0');
    expect(rowFor('/JavaScript')).toHaveClass('is-zero');
    expect(screen.getByText('Showing 21 of 21 counters')).toBeInTheDocument();
  });

  it('keeps raw counts and the interpreted assessment in separate sections', () => {
    renderResults(analysisOf(getFixture('javascript-open-action').build()));
    const assessment = document.getElementById('section-assessment')!;
    expect(within(assessment).getByTestId('assessment-headline')).toHaveTextContent(
      'Multiple potentially suspicious indicators detected',
    );
    expect(
      within(assessment).getByRole('heading', {
        name: 'JavaScript combined with an automatic action',
      }),
    ).toBeInTheDocument();
    expect(within(assessment).queryByRole('table')).not.toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Keyword counts' })).toBeInTheDocument();
  });

  it('describes a document without indicators carefully', () => {
    renderResults(analysisOf(getFixture('minimal').build()));
    expect(screen.getByTestId('assessment-headline')).toHaveTextContent(
      'No configured suspicious indicators detected',
    );
    expect(screen.getByText(/does not show the file is safe/)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/This file is safe|file is clean/i);
  });

  it('filters keywords by name, label or category', async () => {
    const { user } = renderResults(analysisOf(getFixture('javascript-open-action').build()));
    const filter = screen.getByRole('searchbox', { name: 'Filter keywords' });
    await user.type(filter, 'javascript');
    const names = within(keywordTable())
      .getAllByRole('rowheader')
      .map((cell) => cell.querySelector('code')?.textContent);
    expect(names).toEqual(['/JS', '/JavaScript']);
    await user.clear(filter);
    await user.type(filter, 'automatic');
    expect(within(keywordTable()).getAllByRole('rowheader')).toHaveLength(2);
    await user.clear(filter);
    await user.type(filter, 'zzz');
    expect(screen.getByText('No keywords match the current filter.')).toBeInTheDocument();
  });

  it('can hide zero counts', async () => {
    const { user } = renderResults(analysisOf(getFixture('javascript-open-action').build()));
    await user.click(screen.getByRole('checkbox', { name: 'Only keywords that were found' }));
    const rows = within(keywordTable()).getAllByRole('row').slice(1);
    expect(rows.every((row) => !row.classList.contains('is-zero'))).toBe(true);
    expect(rows.length).toBeLessThan(21);
  });

  it('explains each indicator that was found and lists the rest separately', () => {
    renderResults(analysisOf(getFixture('javascript-open-action').build()));
    const details = screen.getByRole('region', { name: 'Indicator explanations' });
    const cards = within(details).getAllByRole('article');
    expect(cards.slice(0, 3).map((card) => card.querySelector('code')?.textContent)).toEqual([
      '/JS',
      '/JavaScript',
      '/OpenAction',
    ]);
    expect(within(cards[0]!).getByText('What it can and cannot tell you')).toBeInTheDocument();
    expect(
      within(details).getByText(/About the 10 indicators that were not found/),
    ).toBeInTheDocument();
  });

  it('shows hex-escaped counts and obfuscation statistics', () => {
    renderResults(analysisOf(getFixture('hex-obfuscated-names').build()));
    expect(within(rowFor('/JavaScript')).getAllByRole('cell')[1]).toHaveTextContent('2');
    expect(within(rowFor('/JavaScript')).getAllByRole('cell')[1]).toHaveClass('num--alert');
    expect(
      screen.getByRole('heading', { name: 'Keywords written with hexadecimal escapes' }),
    ).toBeInTheDocument();
  });

  it('renders file names and PDF-derived strings as text, never as markup', () => {
    const pdf = createTestPdf({
      header: '%PDF<img s',
      objects: [
        ...BASIC_OBJECTS,
        {
          body: '<< /#3Cimg#20src#3Dx#20onerror#3Dalert(1)#3E 1 /#3Cscript#3E (D:20240101000000) >>',
        },
      ],
    });
    renderResults(analysisOf(pdf, '<img src=x onerror="alert(1)"><script>alert(2)</script>.pdf'));
    expect(document.querySelector('img, script, iframe, object, embed')).toBeNull();
    expect(screen.getByTestId('summary-file-name')).toHaveTextContent(
      '<img src=x onerror="alert(1)"><script>alert(2)</script>.pdf',
    );
    expect(screen.getByText(/%PDF<img s/)).toBeInTheDocument();
    expect(screen.getByText('/#3cimg#20src=x#20onerror=alert')).toBeInTheDocument();
    expect(screen.getAllByText('/#3cscript#3e').length).toBeGreaterThan(0);
  });

  it('shows structure, scanner messages and compatibility notes', () => {
    renderResults(analysisOf(bytes('%PDF-1.4'), 'short.pdf'));
    const structure = screen.getByRole('region', { name: 'Structure and statistics' });
    expect(within(structure).getByText(/No %%EOF marker was found/)).toBeInTheDocument();
    expect(
      within(structure).getByRole('heading', { name: 'Differences from pdfid.py on this file' }),
    ).toBeInTheDocument();
    expect(within(structure).getByText(/IndexError/)).toBeInTheDocument();
  });

  it('shows an inconclusive result without a keyword table when the scan was skipped', () => {
    renderResults(analysisOf(getFixture('no-header').build()));
    expect(screen.getByTestId('assessment-headline')).toHaveTextContent(
      'Analysis incomplete or inconclusive',
    );
    expect(screen.queryByRole('table', { name: /PDFiD keyword counts/ })).not.toBeInTheDocument();
    expect(screen.getByText(/Not found in the first 1024 bytes/)).toBeInTheDocument();
  });

  it('lists names and dates on request', async () => {
    const { user } = renderResults(analysisOf(getFixture('dates').build()));
    await user.click(screen.getByText(/Date values/));
    expect(screen.getByText("D:20240101120000+01'00")).toBeVisible();
    await user.click(screen.getByText(/All other names/));
    await user.type(screen.getByRole('searchbox', { name: 'Filter names' }), 'creation');
    expect(screen.getByText('Showing 1 of', { exact: false })).toHaveTextContent(
      /Showing 1 of \d+ names/,
    );
  });
});
