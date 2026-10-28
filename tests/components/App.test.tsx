import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../../src/app/App';
import { createPdfScanClient } from '../../src/features/pdf-analysis/worker/pdfScanClient';
import { bytes } from '../fixtures/createTestPdf';
import { getFixture } from '../fixtures/fixtureDefinitions';
import {
  FakeWorker,
  InProcessWorker,
  inProcessClient,
  SilentWorker,
} from '../fixtures/inProcessWorker';

const pdf = (id: string, name = `${id}.pdf`) =>
  new File([getFixture(id).build()], name, { type: 'application/pdf' });

function setup(createScanClient = () => inProcessClient()) {
  const download = vi.fn(() => ({ ok: true as const }));
  render(<App createScanClient={createScanClient} download={download} />);
  const user = userEvent.setup({ applyAccept: false });
  const choose = (file: File) => user.upload(screen.getByTestId('file-input'), file);
  return { user, choose, download };
}

const network = {
  fetch: vi.fn(),
  sendBeacon: vi.fn(),
  WebSocket: vi.fn(),
  EventSource: vi.fn(),
};

describe('App', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', network.fetch);
    vi.stubGlobal('WebSocket', network.WebSocket);
    vi.stubGlobal('EventSource', network.EventSource);
    Object.defineProperty(navigator, 'sendBeacon', {
      value: network.sendBeacon,
      configurable: true,
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('starts with the upload area, privacy statement and limitations', () => {
    setup();
    expect(screen.getByRole('heading', { level: 1, name: 'PDF Signal' })).toBeInTheDocument();
    expect(screen.getByText('Processed locally · no uploads')).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Inspect suspicious PDFs. Keep your files local.' }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('complementary', { name: 'Your file stays on this device' }),
    ).toHaveTextContent(/never uploaded/);
    expect(
      screen.getByRole('heading', { name: 'What a static scan can and cannot tell you' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Skip to main content' })).toHaveAttribute(
      'href',
      '#main',
    );
    expect(screen.getByRole('contentinfo')).toHaveTextContent('© 2026 Irshad');
  });

  it('scans a selected PDF with the real engine and focuses the results', async () => {
    const { choose } = setup();
    await choose(pdf('javascript-open-action'));
    const heading = await screen.findByRole('heading', { name: /^Results for / });
    await waitFor(() => {
      expect(heading).toHaveFocus();
    });
    expect(screen.getByTestId('assessment-headline')).toHaveTextContent(
      'High-risk indicators detected',
    );
    expect(
      screen.getByRole('rowheader', { name: '/JS JavaScript code entry' }),
    ).toBeInTheDocument();
    expect(screen.getByTestId('announcer')).toHaveTextContent(
      'Scan complete: High risk. Do not open this file in a PDF reader.',
    );
    expect(screen.queryByTestId('dropzone')).not.toBeInTheDocument();
  });

  it('shows validation errors for empty and oversized files and stays usable', async () => {
    const { choose } = setup();
    await choose(new File([], 'empty.pdf', { type: 'application/pdf' }));
    const emptyHeading = await screen.findByRole('heading', {
      name: /This file cannot be scanned/,
    });
    await waitFor(() => {
      expect(emptyHeading).toHaveFocus();
    });
    const box = emptyHeading.closest('.validation__box')!;
    expect(box).toHaveTextContent('The file is empty (0 bytes).');
    expect(box).toHaveTextContent('empty.pdf');

    const big = pdf('minimal', 'huge.pdf');
    Object.defineProperty(big, 'size', { value: 11 * 1024 * 1024 });
    await choose(big);
    expect(await screen.findByText(/exceeds the 10 MB limit/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Choose a PDF file' })).toBeEnabled();
  });

  it('warns about a misleading name and type but scans PDF content', async () => {
    const { choose } = setup();
    await choose(new File([getFixture('minimal').build()], 'holiday.jpg', { type: 'image/jpeg' }));
    await screen.findByRole('heading', { name: /^Results for / });
    expect(screen.getByText('The file name does not end in .pdf.')).toBeInTheDocument();
    expect(screen.getByText('Your system does not report this file as a PDF.')).toBeInTheDocument();
  });

  it('asks before a forced scan of a file without a PDF signature', async () => {
    const { choose, user } = setup();
    await choose(
      new File([bytes('1 0 obj << /JS (x) >> endobj')], 'notes.pdf', { type: 'application/pdf' }),
    );
    expect(
      await screen.findByRole('heading', { name: 'This file may not be a PDF' }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Scan anyway (forced mode)' }));
    await screen.findByRole('heading', { name: /^Results for / });
    expect(screen.getByTestId('assessment-headline')).toHaveTextContent(
      'Analysis incomplete or inconclusive',
    );
    expect(screen.getByText('Forced (no PDF header)')).toBeInTheDocument();
  });

  it('can decline a forced scan', async () => {
    const { choose, user } = setup();
    await choose(new File([bytes('plain text')], 'a.pdf'));
    await user.click(await screen.findByRole('button', { name: 'Choose another file' }));
    expect(screen.getByTestId('dropzone')).toBeInTheDocument();
  });

  it('cancels a scan, terminates the worker and can scan again', async () => {
    const workers: FakeWorker[] = [];
    const { choose, user } = setup(() =>
      createPdfScanClient({
        createWorker: () => {
          const worker = workers.length === 0 ? new SilentWorker() : new InProcessWorker();
          workers.push(worker);
          return worker;
        },
      }),
    );
    await choose(pdf('minimal'));
    await user.click(await screen.findByRole('button', { name: 'Cancel scan' }));
    expect(await screen.findByRole('heading', { name: 'Scan cancelled' })).toBeInTheDocument();
    expect(workers[0]?.terminated).toBe(true);
    await user.click(screen.getByRole('button', { name: 'Scan again' }));
    expect(await screen.findByRole('heading', { name: /^Results for / })).toBeInTheDocument();
  });

  it('reports a timeout and recovers after reset', async () => {
    const { choose, user } = setup(() =>
      createPdfScanClient({ createWorker: () => new SilentWorker(), timeoutMs: 30 }),
    );
    await choose(pdf('minimal'));
    expect(
      await screen.findByRole('heading', { name: 'The scan did not finish' }),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole('region', { name: 'The scan did not finish' })).getByText(
        /The scan took too long and was stopped\./,
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'The scan did not finish' })).toHaveFocus();
    await user.click(screen.getByRole('button', { name: 'Choose another file' }));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Choose a PDF file' })).toHaveFocus();
    });
  });

  it('reports a worker crash and retries', async () => {
    let attempt = 0;
    const { choose, user } = setup(() =>
      createPdfScanClient({
        createWorker: () => {
          attempt += 1;
          if (attempt === 1) {
            const worker = new SilentWorker();
            setTimeout(() => {
              worker.fail();
            }, 5);
            return worker;
          }
          return new InProcessWorker();
        },
      }),
    );
    await choose(pdf('minimal'));
    const crashPanel = await screen.findByRole('region', { name: 'The scan did not finish' });
    expect(within(crashPanel).getByText(/The scanner stopped unexpectedly\./)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { name: /^Results for / })).toBeInTheDocument();
  });

  it('never shows a stale result after a new file is chosen', async () => {
    let created = 0;
    const { choose, user } = setup(() =>
      createPdfScanClient({
        createWorker: () => {
          created += 1;
          return new InProcessWorker(created === 1 ? 150 : 0);
        },
      }),
    );
    await choose(pdf('javascript-open-action', 'first.pdf'));
    await user.click(await screen.findByRole('button', { name: 'Cancel scan' }));
    await user.click(await screen.findByRole('button', { name: 'Choose another file' }));
    await choose(pdf('minimal', 'second.pdf'));
    await screen.findByRole('heading', { name: /^Results for / });
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(screen.getByTestId('summary-file-name')).toHaveTextContent('second.pdf');
    expect(screen.getByTestId('assessment-headline')).toHaveTextContent(
      'No configured suspicious indicators detected',
    );
  });

  it('resets to a clean initial state after results', async () => {
    const { choose, user } = setup();
    await choose(pdf('javascript-open-action'));
    await screen.findByRole('heading', { name: /^Results for / });
    await user.click(screen.getAllByRole('button', { name: 'Scan another file' })[0]!);
    expect(screen.queryByRole('heading', { name: /^Results for / })).not.toBeInTheDocument();
    expect(screen.queryByText(/javascript-open-action/)).not.toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Choose a PDF file' })).toHaveFocus();
    });
  });

  it('handles repeated scans in a row', async () => {
    const { choose, user } = setup();
    for (const id of ['minimal', 'hex-obfuscated-names', 'trailing-data']) {
      await choose(pdf(id));
      await screen.findByRole('heading', { name: /^Results for / });
      expect(screen.getByTestId('summary-file-name')).toHaveTextContent(`${id}.pdf`);
      await user.click(screen.getAllByRole('button', { name: 'Scan another file' })[0]!);
    }
  });

  it('downloads a report from the results', async () => {
    const { choose, user, download } = setup();
    await choose(pdf('minimal'));
    await user.click(await screen.findByRole('button', { name: 'Download JSON report' }));
    expect(download).toHaveBeenCalledOnce();
    const report = JSON.parse((download.mock.calls[0] as unknown as [string])[0]) as {
      file: { name: string };
    };
    expect(report.file.name).toBe('minimal.pdf');
  });

  it('makes no network requests and stores nothing in the browser', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const xhrOpen = vi.spyOn(XMLHttpRequest.prototype, 'open');
    const { choose, user } = setup();
    await choose(pdf('javascript-open-action'));
    await screen.findByRole('heading', { name: /^Results for / });
    await user.click(screen.getByRole('button', { name: 'Download JSON report' }));
    expect(network.fetch).not.toHaveBeenCalled();
    expect(network.sendBeacon).not.toHaveBeenCalled();
    expect(network.WebSocket).not.toHaveBeenCalled();
    expect(network.EventSource).not.toHaveBeenCalled();
    expect(xhrOpen).not.toHaveBeenCalled();
    expect(setItem).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).toBe('');
  });

  it('never renders the document itself', async () => {
    const { choose } = setup();
    await choose(pdf('javascript-open-action'));
    await screen.findByRole('heading', { name: /^Results for / });
    expect(document.querySelector('iframe, object, embed, img, canvas, script')).toBeNull();
  });

  it('prevents the browser from opening files dropped outside the drop zone', () => {
    setup();
    const event = new Event('drop', { cancelable: true });
    Object.defineProperty(event, 'dataTransfer', { value: { types: ['Files'] } });
    window.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(true);
  });

  it('renders a hostile file name as text everywhere', async () => {
    const { choose } = setup();
    const name = '<img src=x onerror=alert(1)>\u202Egnp.pdf';
    await choose(new File([getFixture('minimal').build()], name, { type: 'application/pdf' }));
    await screen.findByRole('heading', { name: /^Results for / });
    expect(document.querySelector('img')).toBeNull();
    expect(screen.getByTestId('summary-file-name')).toHaveTextContent(
      '<img src=x onerror=alert(1)>gnp.pdf',
    );
    expect(within(screen.getByRole('main')).queryByText(/\u202E/)).not.toBeInTheDocument();
  });
});
