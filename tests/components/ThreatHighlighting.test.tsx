import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ScanResults } from '../../src/components/results/ScanResults';
import { assessIndicators } from '../../src/features/pdf-analysis/assessment/assessIndicators';
import { analyzePdf } from '../../src/features/pdf-analysis/engine/analyzePdf';
import type { AnalysisResult } from '../../src/features/pdf-analysis/hooks/usePdfAnalysis';
import { getFixture } from '../fixtures/fixtureDefinitions';

async function renderFixture(id: string) {
  const scan = await analyzePdf(getFixture(id).build(), { sha256: 'a'.repeat(64) });
  const analysis: AnalysisResult = {
    file: { name: `${id}.pdf`, sizeBytes: scan.sizeBytes },
    scan,
    assessment: assessIndicators(scan),
  };
  render(<ScanResults analysis={analysis} issues={[]} onReset={vi.fn()} />);
  return { user: userEvent.setup(), analysis };
}

const rowFor = (name: string) =>
  within(screen.getByRole('table', { name: /PDFiD keyword counts/ }))
    .getAllByRole('rowheader')
    .find((header) => header.querySelector('code')?.textContent === name)!
    .closest('tr')!;

describe('threat highlighting', () => {
  it('pops up a red alert listing the dangerous entries of a high-risk file', async () => {
    await renderFixture('openaction-javascript-stream');
    const alert = screen.getByTestId('threat-alert');
    // Not a live region: focus and the status announcer already report the verdict.
    expect(alert).not.toHaveAttribute('role', 'alert');
    expect(alert).toHaveClass('threat-alert--critical');
    expect(within(alert).getByRole('heading')).toHaveTextContent(
      'Warning: this PDF shows signs of malicious behaviour',
    );
    expect(alert).toHaveTextContent('JavaScript runs automatically');
    expect(alert).toHaveTextContent('Script content matches exploit patterns');
    for (const keyword of ['/JS', '/JavaScript', '/OpenAction']) {
      expect(within(alert).getByText(keyword, { selector: 'code' })).toBeInTheDocument();
    }
    expect(alert).toHaveTextContent('Do not open this file in a PDF reader');
    // Advice comes before the reasons, and technical evidence is collapsed.
    const text = alert.textContent;
    expect(text.indexOf('Do not open')).toBeLessThan(text.indexOf('JavaScript runs automatically'));
    expect(within(alert).getByText(/Technical evidence/)).toBeInTheDocument();
    expect(within(alert).getByRole('link', { name: 'View assessment' })).toHaveAttribute(
      'href',
      '#section-assessment',
    );
  });

  it('moves focus to the verdict when dismissed', async () => {
    const { user } = await renderFixture('javascript-open-action');
    await user.click(screen.getByRole('button', { name: 'Dismiss warning' }));
    expect(screen.getByTestId('assessment-headline')).toHaveFocus();
  });

  it('can be dismissed', async () => {
    const { user } = await renderFixture('javascript-open-action');
    await user.click(screen.getByRole('button', { name: 'Dismiss warning' }));
    expect(screen.queryByTestId('threat-alert')).not.toBeInTheDocument();
  });

  it('warns more mildly about JavaScript that does not run automatically', async () => {
    await renderFixture('form-field-script');
    const alert = screen.getByTestId('threat-alert');
    expect(alert).not.toHaveClass('threat-alert--critical');
    expect(alert).toHaveClass('threat-alert--caution');
    expect(within(alert).getByRole('heading')).toHaveTextContent('This PDF contains JavaScript');
    // Not high risk: code-running rows use the orange caution style, labelled "Runs code".
    expect(rowFor('/JS')).toHaveClass('row--caution');
    expect(within(rowFor('/JS')).getByText('Runs code')).toBeInTheDocument();
  });

  it('shows no alert for harmless files, including a navigation-only open action', async () => {
    await renderFixture('minimal');
    expect(screen.queryByTestId('threat-alert')).not.toBeInTheDocument();
  });

  it('shows no alert when /OpenAction only opens a page', async () => {
    await renderFixture('openaction-destination');
    expect(screen.queryByTestId('threat-alert')).not.toBeInTheDocument();
    expect(rowFor('/OpenAction')).not.toHaveClass('row--danger');
    expect(within(rowFor('/OpenAction')).getByText('Context')).toBeInTheDocument();
  });

  it('marks /JS, /JavaScript and a script-running /OpenAction in red in the table', async () => {
    await renderFixture('javascript-open-action');
    for (const name of ['/JS', '/JavaScript', '/OpenAction']) {
      expect(rowFor(name)).toHaveClass('row--danger');
      expect(within(rowFor(name)).getByText('Danger')).toBeInTheDocument();
      expect(rowFor(name).querySelector('svg.inline-warning')).not.toBeNull();
    }
    expect(rowFor('/Page')).not.toHaveClass('row--danger');
  });

  it('shows red indicator cards first', async () => {
    await renderFixture('javascript-open-action');
    const cards = within(
      screen.getByRole('region', { name: 'Indicator explanations' }),
    ).getAllByRole('article');
    expect(cards[0]).toHaveClass('indicator-card--danger');
    expect(within(cards[0]!).getByText('Danger')).toBeInTheDocument();
  });

  it('shows hidden object-stream counts in their own column', async () => {
    await renderFixture('objstm-hidden-javascript');
    expect(screen.getByRole('columnheader', { name: 'In object streams' })).toBeInTheDocument();
    const cells = within(rowFor('/JavaScript')).getAllByRole('cell');
    expect(cells[0]).toHaveTextContent('0');
    expect(cells[2]).toHaveTextContent('1');
    expect(rowFor('/JavaScript')).toHaveClass('row--danger');
  });

  it('lists resolved actions and script patterns without showing script text', async () => {
    await renderFixture('openaction-javascript-stream');
    const section = screen.getByRole('region', { name: 'Actions and scripts' });
    const actionRow = within(section)
      .getByRole('rowheader', { name: '/OpenAction' })
      .closest('tr')!;
    expect(actionRow).toHaveClass('row--danger');
    expect(actionRow).toHaveTextContent('When the document is opened');
    expect(actionRow).toHaveTextContent('Automatic');
    expect(
      within(section).getByRole('heading', { name: 'Heap-spray filler data' }),
    ).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('inert text');
    expect(document.body).not.toHaveTextContent('1 + 1');
  });

  it('offers section navigation', async () => {
    await renderFixture('minimal');
    const nav = screen.getByRole('navigation', { name: 'Result sections' });
    const links = within(nav).getAllByRole('link');
    for (const link of links) {
      const target = link.getAttribute('href')!.slice(1);
      expect(document.getElementById(target), target).not.toBeNull();
    }
    expect(links.map((link) => link.textContent)).toContain('Actions and scripts');
  });

  // userEvent.setup() installs its own clipboard stub, so these stubs are installed after it.
  it('copies the SHA-256 hash', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    const { user } = await renderFixture('minimal');
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    await user.click(screen.getByRole('button', { name: 'Copy SHA-256 hash' }));
    expect(writeText).toHaveBeenCalledWith('a'.repeat(64));
    expect(await screen.findByText('Copied')).toBeInTheDocument();
  });

  it('explains when copying is unavailable', async () => {
    const { user } = await renderFixture('minimal');
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    await user.click(screen.getByRole('button', { name: 'Copy SHA-256 hash' }));
    expect(await screen.findByText(/Copy unavailable/)).toBeInTheDocument();
  });
});
