import { APP_CONFIG } from '../../../config/appConfig';
import { PDFID_REFERENCE_VERSION } from '../engine/pdfidKeywords';
import { isScanResult } from '../worker/protocol';
import type { Assessment, ScanResult } from '../types/analysis';

export const REPORT_SCHEMA_VERSION = 2;

/** User-selectable report content. Everything not listed here is always included. */
export interface ReportOptions {
  /** Include the (sanitized) file name in the report and in the download file name. */
  readonly includeFileName: boolean;
  /** Include PDF date values found in the file (document metadata). */
  readonly includeDates: boolean;
  /** Include the list of all other PDF names. */
  readonly includeNames: boolean;
}

export const DEFAULT_REPORT_OPTIONS: ReportOptions = {
  includeFileName: true,
  includeDates: false,
  includeNames: false,
};

const REPORT_OPTION_KEYS: readonly (keyof ReportOptions)[] = [
  'includeFileName',
  'includeDates',
  'includeNames',
];

export const REPORT_LIMITATIONS =
  "This report was produced by a static analysis: a keyword scan modelled on PDFiD plus PDF Signal's deep analysis of object streams, actions, scripts and attachments. Nothing was rendered or executed. Encrypted content, unsupported stream filters and heavily obfuscated scripts may not be visible, and the deep analysis stops at fixed resource limits. This is not an antivirus verdict: findings indicate where further analysis may be needed, and the absence of findings does not mean the file is safe.";

export const REPORT_PRIVACY =
  'Generated locally in the browser. The PDF was not uploaded, and this report contains no document text or stream contents.';

export class ReportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReportError';
  }
}

/** Validates report options strictly: only known keys, and only boolean values. */
export function validateReportOptions(value: unknown): ReportOptions {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ReportError('Report options must be an object.');
  }
  const entries = Object.entries(value);
  for (const [key, option] of entries) {
    if (!REPORT_OPTION_KEYS.some((known) => known === key)) {
      throw new ReportError(`Unknown report option: ${key.slice(0, 40)}`);
    }
    if (typeof option !== 'boolean') {
      throw new ReportError(`Report option ${key} must be true or false.`);
    }
  }
  const lookup = new Map<string, unknown>(entries);
  const pick = (key: keyof ReportOptions): boolean => {
    const option = lookup.get(key);
    return typeof option === 'boolean' ? option : DEFAULT_REPORT_OPTIONS[key];
  };
  return {
    includeFileName: pick('includeFileName'),
    includeDates: pick('includeDates'),
    includeNames: pick('includeNames'),
  };
}

export interface ReportInput {
  readonly scan: ScanResult;
  readonly assessment: Assessment;
  /** Sanitized display name of the scanned file. */
  readonly fileName: string;
}

function assertAssessment(value: Assessment): void {
  const levels: readonly string[] = [
    'none-detected',
    'review',
    'multiple',
    'high-risk',
    'inconclusive',
  ];
  if (
    !levels.includes(value.level) ||
    !Array.isArray(value.findings) ||
    !Array.isArray(value.interpretations)
  ) {
    throw new ReportError('The assessment is incomplete, so no report was created.');
  }
}

/** Builds the report object. Throws ReportError when the input is not a valid analysis. */
export function buildJsonReport(input: ReportInput, options: ReportOptions, generatedAt: Date) {
  const validOptions = validateReportOptions(options);
  if (!isScanResult(input.scan)) {
    throw new ReportError('The scan result is invalid, so no report was created.');
  }
  assertAssessment(input.assessment);
  if (Number.isNaN(generatedAt.getTime())) {
    throw new ReportError('The report timestamp is invalid.');
  }
  const { scan, assessment } = input;

  return {
    reportSchemaVersion: REPORT_SCHEMA_VERSION,
    application: { name: APP_CONFIG.name, version: APP_CONFIG.version },
    generatedAt: generatedAt.toISOString(),
    scanner: {
      ...scan.engine,
      pdfidReferenceVersion: PDFID_REFERENCE_VERSION,
      resultSchemaVersion: scan.schemaVersion,
    },
    file: {
      ...(validOptions.includeFileName ? { name: input.fileName } : {}),
      sizeBytes: scan.sizeBytes,
      sha256: scan.sha256,
    },
    scan: {
      scannedAt: scan.scannedAt,
      durationMs: scan.durationMs,
      mode: scan.mode,
      isPdf: scan.isPdf,
      keywordScanPerformed: scan.keywordScanPerformed,
    },
    header: scan.header,
    keywords: scan.keywords.map(({ name, kind, category, count, hexcodeCount }) => ({
      name,
      kind,
      category,
      count,
      hexcodeCount,
    })),
    eof: scan.eof,
    entropy: scan.entropy,
    obfuscation: scan.obfuscation,
    structure: scan.structure,
    // Counts, action types and pattern identifiers only; no script text, URLs or file names.
    deepAnalysis: scan.deep,
    ...(validOptions.includeDates ? { dates: scan.dates } : {}),
    ...(validOptions.includeNames ? { names: scan.names } : {}),
    assessment: {
      rulesVersion: assessment.rulesVersion,
      level: assessment.level,
      headline: assessment.headline,
      summary: assessment.summary,
      advice: assessment.advice,
      findings: assessment.findings,
      keywordInterpretations: assessment.interpretations,
      visibilityLimits: assessment.visibilityLimits,
    },
    warnings: scan.messages,
    incompleteAnalysis:
      !scan.keywordScanPerformed || scan.mode === 'forced' || assessment.level === 'inconclusive',
    compatibilityNotes: scan.compatibilityNotes,
    limitations: REPORT_LIMITATIONS,
    privacy: REPORT_PRIVACY,
  };
}

export type PdfSignalReport = ReturnType<typeof buildJsonReport>;

function assertSerializable(value: unknown, path: string): void {
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new ReportError(`The report contains an invalid number at ${path}.`);
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      assertSerializable(item, `${path}[${index}]`);
    });
  } else if (typeof value === 'object' && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      assertSerializable(item, `${path}.${key}`);
    }
  }
}

/** Serializes the report as indented JSON, rejecting values JSON cannot represent. */
export function serializeReport(report: PdfSignalReport): string {
  assertSerializable(report, 'report');
  return `${JSON.stringify(report, null, 2)}\n`;
}

const MAX_STEM_LENGTH = 60;

/**
 * Builds a safe download name: `pdf-signal-report[-<stem>]-<UTC timestamp>.json`, where the
 * stem uses only `[A-Za-z0-9._-]`. Path separators, control characters, markup and reserved
 * names can never reach the file system through it.
 */
export function createReportFileName(
  originalName: string,
  generatedAt: Date,
  includeFileName: boolean,
): string {
  const iso = Number.isNaN(generatedAt.getTime())
    ? '1970-01-01T00:00:00'
    : generatedAt.toISOString();
  const timestamp = iso.slice(0, 19).replace(/[-:]/g, '').replace('T', '-');
  if (!includeFileName) {
    return `pdf-signal-report-${timestamp}.json`;
  }
  const stem = originalName
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/\.pdf$/i, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/[-.]{2,}/g, '-')
    .replace(/^[-._]+|[-._]+$/g, '')
    .slice(0, MAX_STEM_LENGTH)
    .replace(/[-._]+$/, '');
  return `pdf-signal-report-${stem === '' ? 'document' : stem}-${timestamp}.json`;
}

export interface DownloadEnvironment {
  readonly createObjectURL: (blob: Blob) => string;
  readonly revokeObjectURL: (url: string) => void;
  readonly document: Document;
  readonly schedule: (callback: () => void, delayMs: number) => void;
}

function browserEnvironment(): DownloadEnvironment {
  return {
    createObjectURL: (blob) => URL.createObjectURL(blob),
    revokeObjectURL: (url) => {
      URL.revokeObjectURL(url);
    },
    document,
    schedule: (callback, delayMs) => {
      window.setTimeout(callback, delayMs);
    },
  };
}

export type DownloadOutcome =
  { readonly ok: true } | { readonly ok: false; readonly message: string };

/** Delay before the object URL is revoked, giving the browser time to start the download. */
const REVOKE_DELAY_MS = 1000;

/**
 * Saves `json` through a temporary object URL and an anchor with a `download` attribute.
 * The URL is always revoked, also when the download fails.
 */
export function downloadJsonReport(
  json: string,
  fileName: string,
  environment: DownloadEnvironment = browserEnvironment(),
): DownloadOutcome {
  let url: string | null = null;
  try {
    url = environment.createObjectURL(new Blob([json], { type: 'application/json' }));
    const anchor = environment.document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    anchor.rel = 'noopener';
    anchor.hidden = true;
    environment.document.body.append(anchor);
    anchor.click();
    anchor.remove();
    const created = url;
    environment.schedule(() => {
      environment.revokeObjectURL(created);
    }, REVOKE_DELAY_MS);
    return { ok: true };
  } catch {
    if (url !== null) {
      environment.revokeObjectURL(url);
    }
    return {
      ok: false,
      message:
        'The report could not be downloaded. Check your browser download settings and try again.',
    };
  }
}
