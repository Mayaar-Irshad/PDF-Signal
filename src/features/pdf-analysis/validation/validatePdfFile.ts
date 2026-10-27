import { findPdfSignature } from '../engine/analyzePdfHeader';
import { VALIDATION_RULES, type ValidationRules } from './validationRules';

export type ValidationIssueCode =
  | 'empty-file'
  | 'file-too-large'
  | 'invalid-size'
  | 'read-failed'
  | 'signature-missing'
  | 'signature-offset'
  | 'extension-mismatch'
  | 'mime-mismatch';

export interface ValidationIssue {
  readonly code: ValidationIssueCode;
  readonly severity: 'error' | 'warning';
  readonly message: string;
  /** How the user can resolve or interpret the issue. */
  readonly guidance: string;
}

export interface FileValidationResult {
  /** False when an error prevents scanning. */
  readonly canScan: boolean;
  /** True when the file has no `%PDF` signature and needs explicit confirmation (forced mode). */
  readonly requiresForce: boolean;
  readonly issues: readonly ValidationIssue[];
}

/** The subset of `File` that validation needs; all of it is untrusted metadata. */
export interface FileMetadata {
  readonly name: string;
  readonly size: number;
  readonly type: string;
}

// C0/C1 control characters, bidirectional overrides and isolates, zero-width characters,
// line/paragraph separators and the byte-order mark. These can disguise a name (for example
// "invoice\u202Efdp.exe") or break the layout, so they are removed before display.
const UNSAFE_NAME_CHARACTERS =
  // eslint-disable-next-line no-control-regex -- removing control characters is the purpose
  /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g;

/**
 * Makes an untrusted file name safe to show as text: Unicode-normalized, without control or
 * direction-changing characters, collapsed whitespace and a bounded length. React still
 * renders the result as text; this only prevents visual spoofing and layout abuse.
 */
export function sanitizeFileName(
  name: unknown,
  maxLength: number = VALIDATION_RULES.maxFileNameLength,
): string {
  if (typeof name !== 'string') {
    return 'Unnamed file';
  }
  const cleaned = name
    .normalize('NFC')
    .replace(/[\t\n\v\f\r ]+/g, ' ')
    .replace(UNSAFE_NAME_CHARACTERS, '')
    .replace(/ {2,}/g, ' ')
    .trim();
  if (cleaned === '') {
    return 'Unnamed file';
  }
  const characters = Array.from(cleaned);
  if (characters.length <= maxLength) {
    return cleaned;
  }
  return characters.slice(0, Math.max(1, maxLength - 1)).join('') + '…';
}

export function formatBytes(size: number): string {
  if (!Number.isFinite(size) || size < 0) {
    return 'unknown size';
  }
  if (size < 1024) {
    return `${size} ${size === 1 ? 'byte' : 'bytes'}`;
  }
  const units = ['KB', 'MB', 'GB'];
  let value = size / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit] ?? 'GB'}`;
}

/** Checks size, extension and MIME type. Only size problems prevent a scan. */
export function validateFileMetadata(
  file: FileMetadata,
  rules: Pick<
    ValidationRules,
    'maxFileSizeBytes' | 'acceptedExtensions' | 'acceptedMimeTypes'
  > = VALIDATION_RULES,
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const limit = formatBytes(rules.maxFileSizeBytes);

  if (!Number.isSafeInteger(file.size) || file.size < 0) {
    issues.push({
      severity: 'error',
      code: 'invalid-size',
      message: 'The file size could not be determined.',
      guidance: 'Select the file again from your device.',
    });
  } else if (file.size === 0) {
    issues.push({
      severity: 'error',
      code: 'empty-file',
      message: 'The file is empty (0 bytes).',
      guidance: 'Check that the download or copy finished, then select the complete file.',
    });
  } else if (file.size > rules.maxFileSizeBytes) {
    issues.push({
      severity: 'error',
      code: 'file-too-large',
      message: `The file is ${formatBytes(file.size)}, which exceeds the ${limit} limit.`,
      guidance: `PDF Signal scans files up to ${limit} to keep your browser responsive. Use the original pdfid.py for larger files.`,
    });
  }

  const name = typeof file.name === 'string' ? file.name.toLowerCase() : '';
  if (!rules.acceptedExtensions.some((extension) => name.endsWith(extension))) {
    issues.push({
      severity: 'warning',
      code: 'extension-mismatch',
      message: 'The file name does not end in .pdf.',
      guidance:
        'File names are not trusted. PDF Signal checks the file contents for a PDF signature instead.',
    });
  }

  const type = typeof file.type === 'string' ? file.type.toLowerCase() : '';
  if (type !== '' && !rules.acceptedMimeTypes.some((accepted) => accepted === type)) {
    issues.push({
      severity: 'warning',
      code: 'mime-mismatch',
      message: 'Your system does not report this file as a PDF.',
      guidance:
        'The reported file type is not trusted. PDF Signal checks the file contents instead.',
    });
  }
  return issues;
}

/** Checks the first bytes for the `%PDF` signature, using PDFiD's 1024-byte window. */
export function inspectSignature(head: Uint8Array): ValidationIssue[] {
  const offset = findPdfSignature(head);
  if (offset < 0) {
    return [
      {
        severity: 'warning',
        code: 'signature-missing',
        message: 'No %PDF signature was found in the first 1024 bytes, so this may not be a PDF.',
        guidance:
          'Like PDFiD, PDF Signal does not scan such files by default. You can scan anyway, but the result may not be meaningful.',
      },
    ];
  }
  if (offset > 0) {
    return [
      {
        severity: 'warning',
        code: 'signature-offset',
        message: `The %PDF signature starts at byte ${offset}, not at the beginning of the file.`,
        guidance:
          'PDF readers accept this, but data before the header is unusual and is reported in the results.',
      },
    ];
  }
  return [];
}

/** Reads `blob[start, end)` as bytes, with a FileReader fallback for older environments. */
export async function readBlobBytes(
  blob: Blob,
  start = 0,
  end = blob.size,
): Promise<Uint8Array<ArrayBuffer>> {
  const part = blob.slice(start, end);
  if (typeof part.arrayBuffer === 'function') {
    return new Uint8Array(await part.arrayBuffer());
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const { result } = reader;
      if (result instanceof ArrayBuffer) {
        resolve(new Uint8Array(result));
      } else {
        reject(new Error('Unexpected FileReader result'));
      }
    };
    reader.onerror = () => {
      reject(new Error('The file could not be read'));
    };
    reader.readAsArrayBuffer(part);
  });
}

/**
 * Validates a selected file before scanning. Only the first 1024 bytes are read on the main
 * thread; the full file is read inside the worker.
 */
export async function validatePdfFile(
  file: Blob & FileMetadata,
  rules: ValidationRules = VALIDATION_RULES,
): Promise<FileValidationResult> {
  const issues = validateFileMetadata(file, rules);
  if (issues.some((issue) => issue.severity === 'error')) {
    return { canScan: false, requiresForce: false, issues };
  }

  let head: Uint8Array;
  try {
    head = await readBlobBytes(file, 0, Math.min(file.size, rules.signatureWindowBytes));
  } catch {
    return {
      canScan: false,
      requiresForce: false,
      issues: [
        ...issues,
        {
          severity: 'error',
          code: 'read-failed',
          message: 'The file could not be read.',
          guidance:
            'Check that the file still exists and that your browser may access it, then try again.',
        },
      ],
    };
  }

  const signatureIssues = inspectSignature(head);
  return {
    canScan: true,
    requiresForce: signatureIssues.some((issue) => issue.code === 'signature-missing'),
    issues: [...signatureIssues, ...issues],
  };
}
