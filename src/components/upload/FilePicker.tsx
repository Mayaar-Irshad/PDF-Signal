import { useRef, type Ref } from 'react';

interface FilePickerProps {
  readonly onFileSelected: (file: File) => void;
  readonly buttonRef?: Ref<HTMLButtonElement> | undefined;
  readonly describedBy?: string | undefined;
  readonly label?: string;
}

/**
 * A button that opens the system file chooser. The `accept` attribute only filters the
 * chooser for convenience; it is not validation, which happens in code after selection.
 */
export function FilePicker({
  onFileSelected,
  buttonRef,
  describedBy,
  label = 'Choose a PDF file',
}: FilePickerProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <>
      <input
        ref={inputRef}
        type="file"
        accept=".pdf,application/pdf"
        className="visually-hidden"
        tabIndex={-1}
        aria-hidden="true"
        data-testid="file-input"
        onChange={(event) => {
          const file = event.currentTarget.files?.[0];
          // Clear the input so choosing the same file again still triggers a new scan.
          event.currentTarget.value = '';
          if (file !== undefined) {
            onFileSelected(file);
          }
        }}
      />
      <button
        ref={buttonRef}
        type="button"
        className="button button--primary"
        aria-describedby={describedBy}
        onClick={() => inputRef.current?.click()}
      >
        {label}
      </button>
    </>
  );
}
