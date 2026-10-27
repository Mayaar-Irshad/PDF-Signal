import { useId, useState, type DragEvent, type Ref } from 'react';
import { formatBytes } from '../../features/pdf-analysis/validation/validatePdfFile';
import { FilePicker } from './FilePicker';

interface PdfDropzoneProps {
  readonly onFileSelected: (file: File) => void;
  readonly maxFileSizeBytes: number;
  readonly pickerButtonRef?: Ref<HTMLButtonElement>;
}

function containsFiles(event: DragEvent<HTMLElement>): boolean {
  return Array.from(event.dataTransfer.types).includes('Files');
}

/**
 * Drag-and-drop area with a file-picker button for keyboard and touch users. Exactly one
 * file is accepted per drop.
 */
export function PdfDropzone({
  onFileSelected,
  maxFileSizeBytes,
  pickerButtonRef,
}: PdfDropzoneProps) {
  const [dragging, setDragging] = useState(false);
  const [dropError, setDropError] = useState<string | null>(null);
  const hintId = useId();

  const handleDragOver = (event: DragEvent<HTMLElement>) => {
    if (!containsFiles(event)) {
      return;
    }
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
    setDragging(true);
  };

  const handleDragLeave = (event: DragEvent<HTMLElement>) => {
    const next = event.relatedTarget;
    if (!(next instanceof Node) || !event.currentTarget.contains(next)) {
      setDragging(false);
    }
  };

  const handleDrop = (event: DragEvent<HTMLElement>) => {
    event.preventDefault();
    setDragging(false);
    const files = Array.from(event.dataTransfer.files);
    if (files.length !== 1 || files[0] === undefined) {
      setDropError(
        files.length === 0
          ? 'Nothing was dropped. Drop a single PDF file, or use the button.'
          : `${files.length} files were dropped. Drop a single PDF file at a time.`,
      );
      return;
    }
    setDropError(null);
    onFileSelected(files[0]);
  };

  return (
    <section
      className={`dropzone${dragging ? ' dropzone--active' : ''}`}
      aria-labelledby={`${hintId}-title`}
      data-testid="dropzone"
      onDragEnter={handleDragOver}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <svg className="dropzone__icon" viewBox="0 0 48 48" aria-hidden="true" focusable="false">
        <path
          d="M13 6h16l9 9v27H13z M29 6v9h9 M25.5 22v13 M19.5 29l6 6 6-6"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <h2 id={`${hintId}-title`} className="dropzone__title">
        {dragging ? 'Drop the file to scan it' : 'Drag and drop a PDF here'}
      </h2>
      <p className="dropzone__or" aria-hidden="true">
        or
      </p>
      <FilePicker
        onFileSelected={onFileSelected}
        buttonRef={pickerButtonRef}
        describedBy={hintId}
      />
      <p id={hintId} className="dropzone__hint">
        PDF, up to {formatBytes(maxFileSizeBytes)}, one file at a time.
      </p>
      {dropError !== null && (
        <p className="dropzone__error" role="alert">
          {dropError}
        </p>
      )}
    </section>
  );
}
