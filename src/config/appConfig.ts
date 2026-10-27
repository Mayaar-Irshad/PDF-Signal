/** Application-wide settings. Every limit here is enforced in code, not only displayed. */
export const APP_CONFIG = {
  name: 'PDF Signal',
  version: __APP_VERSION__,
  tagline: 'Inspect suspicious PDFs. Keep your files local.',
  /** Largest file accepted for scanning (10 MB). */
  maxFileSizeBytes: 10 * 1024 * 1024,
  /** A scan running longer than this is stopped and reported as timed out. */
  scanTimeoutMs: 30_000,
  /** Upstream reference implementation. */
  pdfidSourceUrl: 'https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py',
} as const;
