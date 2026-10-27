import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { PdfDropzone } from '../../src/components/upload/PdfDropzone';

const MB = 1024 * 1024;

function setup() {
  const onFileSelected = vi.fn<(file: File) => void>();
  render(<PdfDropzone onFileSelected={onFileSelected} maxFileSizeBytes={10 * MB} />);
  return { onFileSelected, user: userEvent.setup({ applyAccept: false }) };
}

const pdf = () => new File(['%PDF-1.7\n'], 'doc.pdf', { type: 'application/pdf' });

function drop(files: File[]) {
  fireEvent.drop(screen.getByTestId('dropzone'), { dataTransfer: { files, types: ['Files'] } });
}

describe('PdfDropzone', () => {
  it('offers an accessible picker that states the accepted type and size limit', () => {
    setup();
    const button = screen.getByRole('button', { name: 'Choose a PDF file' });
    expect(button).toHaveAccessibleDescription(/PDF, up to 10 MB/);
    expect(screen.getByRole('heading', { name: 'Drag and drop a PDF here' })).toBeInTheDocument();
    expect(screen.getByTestId('file-input')).toHaveAttribute('accept', '.pdf,application/pdf');
  });

  it('opens the file chooser from the keyboard', async () => {
    const { user } = setup();
    const click = vi.spyOn(HTMLInputElement.prototype, 'click');
    await user.tab();
    expect(screen.getByRole('button', { name: 'Choose a PDF file' })).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(click).toHaveBeenCalledTimes(1);
    await user.keyboard(' ');
    expect(click).toHaveBeenCalledTimes(2);
    click.mockRestore();
  });

  it('passes a picked file on, regardless of its declared type', async () => {
    const { onFileSelected, user } = setup();
    const disguised = new File(['%PDF-1.7'], 'photo.jpg', { type: 'image/jpeg' });
    await user.upload(screen.getByTestId('file-input'), disguised);
    expect(onFileSelected).toHaveBeenCalledWith(disguised);
  });

  it('allows picking the same file twice', async () => {
    const { onFileSelected, user } = setup();
    const file = pdf();
    await user.upload(screen.getByTestId('file-input'), file);
    await user.upload(screen.getByTestId('file-input'), file);
    expect(onFileSelected).toHaveBeenCalledTimes(2);
  });

  it('accepts a single dropped file', () => {
    const { onFileSelected } = setup();
    const file = pdf();
    drop([file]);
    expect(onFileSelected).toHaveBeenCalledWith(file);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('rejects multiple dropped files with an explanation', () => {
    const { onFileSelected } = setup();
    drop([pdf(), pdf()]);
    expect(onFileSelected).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(
      '2 files were dropped. Drop a single PDF file at a time.',
    );
  });

  it('explains an empty drop and clears the message after a valid drop', () => {
    const { onFileSelected } = setup();
    drop([]);
    expect(screen.getByRole('alert')).toHaveTextContent(/Nothing was dropped/);
    drop([pdf()]);
    expect(onFileSelected).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows a drag state only for file drags', () => {
    setup();
    const zone = screen.getByTestId('dropzone');
    fireEvent.dragOver(zone, { dataTransfer: { types: ['text/plain'], dropEffect: 'none' } });
    expect(zone).not.toHaveClass('dropzone--active');
    fireEvent.dragEnter(zone, { dataTransfer: { types: ['Files'], dropEffect: 'none' } });
    expect(zone).toHaveClass('dropzone--active');
    expect(screen.getByRole('heading', { name: 'Drop the file to scan it' })).toBeInTheDocument();
    fireEvent.dragLeave(zone, { relatedTarget: document.body });
    expect(zone).not.toHaveClass('dropzone--active');
  });
});
