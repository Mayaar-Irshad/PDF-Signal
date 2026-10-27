import { APP_CONFIG } from '../../../config/appConfig';

/**
 * Upload validation rules. File names, extensions and MIME types are supplied by the user's
 * system and are untrusted: they only produce warnings. Size limits and content checks are
 * enforced in code.
 */
export const VALIDATION_RULES = {
  maxFileSizeBytes: APP_CONFIG.maxFileSizeBytes,
  acceptedExtensions: ['.pdf'],
  /** MIME types browsers commonly report for PDF files. An empty type is also tolerated. */
  acceptedMimeTypes: ['application/pdf', 'application/x-pdf', 'application/acrobat', 'text/pdf'],
  /** Bytes read on the main thread to check for the `%PDF` signature (PDFiD's window). */
  signatureWindowBytes: 1024,
  /** Longest file name kept for display and reports, in characters. */
  maxFileNameLength: 255,
} as const;

export type ValidationRules = typeof VALIDATION_RULES;
