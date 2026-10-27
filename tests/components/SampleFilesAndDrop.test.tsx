import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from '../../src/app/App';
import { SampleFiles } from '../../src/components/upload/SampleFiles';
import { getFixture } from '../fixtures/fixtureDefinitions';
import { inProcessClient } from '../fixtures/inProcessWorker';

function dropOnWindow(files: File[]) {
  const event = new Event('drop', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'dataTransfer', { value: { types: ['Files'], files } });
  window.dispatchEvent(event);
  return event;
}

describe('sample files', () => {
  it('passes a generated sample file to the scanner', async () => {
    const onFileSelected = vi.fn();
    render(<SampleFiles onFileSelected={onFileSelected} />);
    await userEvent.setup().click(screen.getByRole('button', { name: /Auto-running JavaScript/ }));
    await waitFor(() => {
      expect(onFileSelected).toHaveBeenCalledOnce();
    });
    const file = onFileSelected.mock.calls[0]![0] as File;
    expect(file.name).toBe('pdf-signal-sample-auto-javascript.pdf');
  });

  it('scans a sample end to end in the app', async () => {
    render(<App createScanClient={() => inProcessClient()} />);
    await userEvent
      .setup()
      .click(screen.getByRole('button', { name: /Script hidden in an object stream/ }));
    expect(await screen.findByTestId('assessment-headline')).toHaveTextContent(
      'High-risk indicators detected',
    );
    expect(screen.getByTestId('summary-file-name')).toHaveTextContent(
      'pdf-signal-sample-hidden-javascript.pdf',
    );
  });
});

describe('dropping a file anywhere', () => {
  const pdf = (id: string) =>
    new File([getFixture(id).build()], `${id}.pdf`, { type: 'application/pdf' });

  it('starts a new scan when a file is dropped on the results page', async () => {
    render(<App createScanClient={() => inProcessClient()} />);
    dropOnWindow([pdf('minimal')]);
    expect(await screen.findByTestId('summary-file-name')).toHaveTextContent('minimal.pdf');
    dropOnWindow([pdf('javascript-open-action')]);
    await waitFor(() => {
      expect(screen.getByTestId('summary-file-name')).toHaveTextContent(
        'javascript-open-action.pdf',
      );
    });
  });

  it('shows an overlay while a file is dragged over the results page', async () => {
    render(<App createScanClient={() => inProcessClient()} />);
    dropOnWindow([pdf('minimal')]);
    await screen.findByTestId('summary-file-name');
    const enter = new Event('dragenter', { bubbles: true });
    Object.defineProperty(enter, 'dataTransfer', { value: { types: ['Files'] } });
    fireEvent(window, enter);
    expect(await screen.findByTestId('drop-overlay')).toHaveTextContent('Drop the file to scan it');
    const leave = new Event('dragleave', { bubbles: true });
    Object.defineProperty(leave, 'dataTransfer', { value: { types: ['Files'] } });
    fireEvent(window, leave);
    await waitFor(() => {
      expect(screen.queryByTestId('drop-overlay')).not.toBeInTheDocument();
    });
  });

  it('ignores drops of several files and drops already handled by the drop zone', () => {
    render(<App createScanClient={() => inProcessClient()} />);
    expect(dropOnWindow([pdf('minimal'), pdf('minimal')]).defaultPrevented).toBe(true);
    expect(screen.queryByText(/Checking file/)).not.toBeInTheDocument();
    fireEvent.drop(screen.getByTestId('dropzone'), {
      dataTransfer: { files: [pdf('minimal')], types: ['Files'] },
    });
    // Exactly one scan starts (from the drop zone), not a second one from the window handler.
    expect(screen.getAllByText('minimal.pdf')).toHaveLength(1);
  });
});
