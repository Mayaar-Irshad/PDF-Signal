import {
  SCAN_RESULT_SCHEMA_VERSION,
  type BoundedList,
  type EngineInfo,
  type HeaderAnalysis,
  type KeywordCount,
  type ScanMessage,
  type ScanResult,
} from '../types/analysis';
import { analyzeEof } from './analyzeEof';
import { analyzePdfHeader } from './analyzePdfHeader';
import { COLORS_COUNTER, PDFID_KEYWORDS, PDFID_REFERENCE_VERSION } from './pdfidKeywords';
import { scanKeywords, type KeywordScanOutput } from './scanKeywords';

export const ENGINE_VERSION = '1.2.0';

export const ENGINE_INFO: EngineInfo = {
  name: 'PDF Signal PDFiD-compatible engine',
  version: ENGINE_VERSION,
  reference: `PDFiD ${PDFID_REFERENCE_VERSION} by Didier Stevens (independent TypeScript reimplementation)`,
};

export interface ScanLimits {
  /** Distinct non-keyword names retained for the all-names list. */
  readonly maxDistinctNames: number;
  /** PDF date values retained. */
  readonly maxDates: number;
}

export const DEFAULT_SCAN_LIMITS: ScanLimits = {
  maxDistinctNames: 2000,
  maxDates: 200,
};

export interface ScanOptions {
  /** Scan even when no `%PDF` header is found (pdfid.py `--force`). */
  readonly force?: boolean;
  /** Collect every other PDF name (pdfid.py `--all`). Defaults to true. */
  readonly collectNames?: boolean;
  /** SHA-256 computed by the caller, if available. */
  readonly sha256?: string | null;
  readonly limits?: Partial<ScanLimits>;
  /** Receives scan progress as a fraction between 0 and 1. */
  readonly onProgress?: (fraction: number) => void;
  /** Clock used for timestamps; injectable for deterministic tests. */
  readonly now?: () => Date;
}

const EMPTY_LIST: BoundedList<never> = { entries: [], omitted: 0 };

function headerMessages(header: HeaderAnalysis, size: number): ScanMessage[] {
  const messages: ScanMessage[] = [];
  if (size === 0) {
    messages.push({ severity: 'warning', code: 'empty-input', text: 'The file is empty.' });
  }
  if (!header.found) {
    messages.push({
      severity: 'warning',
      code: 'header-missing',
      text: 'No %PDF header was found in the first 1024 bytes, so PDFiD would not treat this file as a PDF.',
    });
    return messages;
  }
  if (header.offset !== null && header.offset > 0) {
    messages.push({
      severity: 'warning',
      code: 'header-offset',
      text: `The %PDF header starts at byte ${header.offset} instead of byte 0. Data before the header is unusual and is sometimes used to disguise a file.`,
    });
  }
  if (!header.versionRecognized) {
    messages.push({
      severity: 'warning',
      code: 'header-version-unrecognized',
      text:
        header.version === null
          ? 'The header does not contain a version number in the form %PDF-1.7.'
          : `The header declares version ${header.version}, which is not a published PDF version.`,
    });
  }
  return messages;
}

function scanMessages(scan: KeywordScanOutput, eof: ReturnType<typeof analyzeEof>): ScanMessage[] {
  const messages: ScanMessage[] = [];
  if (eof.eofCount === 0) {
    messages.push({
      severity: 'warning',
      code: 'eof-missing',
      text: 'No %%EOF marker was found. The file may be truncated or malformed.',
    });
  } else if (eof.eofCount > 1) {
    messages.push({
      severity: 'info',
      code: 'eof-multiple',
      text: `${eof.eofCount} %%EOF markers were found. This usually means the file was updated incrementally (for example after editing or signing).`,
    });
  }
  if (eof.trailingDataPresent && eof.bytesAfterLastEof !== null) {
    messages.push({
      severity: eof.trailingDataWhitespaceOnly === true ? 'info' : 'warning',
      code: 'trailing-data',
      text:
        eof.trailingDataWhitespaceOnly === true
          ? `${eof.bytesAfterLastEof} whitespace byte(s) follow the last %%EOF marker.`
          : `${eof.bytesAfterLastEof} byte(s) of data follow the last %%EOF marker.`,
    });
  }
  if (scan.endedInsideStream) {
    messages.push({
      severity: 'warning',
      code: 'ended-inside-stream',
      text: 'The data ends inside a stream (a "stream" keyword without a later "endstream"). The file may be truncated.',
    });
  }
  if (scan.names.omitted > 0) {
    messages.push({
      severity: 'info',
      code: 'names-truncated',
      text: `${scan.names.omitted} name occurrence(s) were left out of the all-names list because of resource limits. Keyword counts are not affected.`,
    });
  }
  if (scan.dates.omitted > 0) {
    messages.push({
      severity: 'info',
      code: 'dates-truncated',
      text: `${scan.dates.omitted} date value(s) were left out because of resource limits.`,
    });
  }
  return messages;
}

function compatibilityNotes(header: HeaderAnalysis, scan: KeywordScanOutput | null): string[] {
  const notes: string[] = [];
  if (header.pdfidWouldError) {
    notes.push(
      'PDFiD 0.2.10 would stop with an IndexError on this header because the header line runs past the data it reads. PDF Signal ends the header at the end of the data.',
    );
  }
  if (scan?.pdfidColorsValueError === true) {
    notes.push(
      'PDFiD 0.2.10 would stop with a ValueError on a /Colors value containing superscript digits. PDF Signal does not count that value.',
    );
  }
  if (scan !== null && scan.entropy.totalBytes === 0) {
    notes.push(
      'PDFiD 0.2.10 would stop with a ZeroDivisionError when computing entropy for empty data. PDF Signal reports the entropy as unavailable.',
    );
  }
  return notes;
}

function buildKeywordCounts(scan: KeywordScanOutput): KeywordCount[] {
  const counts: KeywordCount[] = PDFID_KEYWORDS.map((definition, index) => ({
    ...definition,
    count: scan.counts[index] ?? 0,
    hexcodeCount: scan.hexcodeCounts[index] ?? 0,
  }));
  counts.push({ ...COLORS_COUNTER, count: scan.colorsOverThreshold, hexcodeCount: 0 });
  return counts;
}

function countOf(keywords: readonly KeywordCount[], name: string): number {
  return keywords.find((keyword) => keyword.name === name)?.count ?? 0;
}

/**
 * Scans PDF bytes with PDFiD 0.2.10 semantics, always including PDFiD's "extra data"
 * (`--extra`: %%EOF analysis, entropy and dates).
 *
 * The input is read but never modified, and the result contains no raw bytes. When no
 * header is found and `force` is not set, the keyword scan is skipped, as in PDFiD.
 */
export function scanPdf(bytes: Uint8Array, options: ScanOptions = {}): ScanResult {
  const now = options.now ?? (() => new Date());
  const startedAt = now();
  const limits: ScanLimits = { ...DEFAULT_SCAN_LIMITS, ...options.limits };
  const force = options.force ?? false;
  const header = analyzePdfHeader(bytes);
  const messages = headerMessages(header, bytes.length);
  const sha256 = options.sha256 ?? null;

  const base: Pick<
    ScanResult,
    'schemaVersion' | 'engine' | 'scannedAt' | 'sizeBytes' | 'sha256' | 'mode' | 'isPdf' | 'header'
  > = {
    schemaVersion: SCAN_RESULT_SCHEMA_VERSION,
    engine: ENGINE_INFO,
    scannedAt: startedAt.toISOString(),
    sizeBytes: bytes.length,
    sha256,
    mode: force && !header.found ? 'forced' : 'standard',
    isPdf: header.found,
    header,
  };

  if (sha256 === null) {
    messages.push({
      severity: 'info',
      code: 'hash-unavailable',
      text: 'The SHA-256 hash could not be computed because the Web Crypto API is unavailable in this context.',
    });
  }

  if (!header.found && !force) {
    messages.push({
      severity: 'warning',
      code: 'not-scanned',
      text: 'The keyword scan was not run because the file has no PDF header. Choose "Scan anyway" to force it.',
    });
    return {
      ...base,
      durationMs: now().getTime() - startedAt.getTime(),
      keywordScanPerformed: false,
      keywords: [],
      eof: null,
      entropy: null,
      obfuscation: null,
      structure: null,
      dates: EMPTY_LIST,
      names: EMPTY_LIST,
      messages,
      compatibilityNotes: compatibilityNotes(header, null),
      deep: null,
    };
  }

  if (!header.found) {
    messages.push({
      severity: 'warning',
      code: 'forced-scan',
      text: 'Forced scan: the file was scanned although it has no PDF header. Treat the counts with caution.',
    });
  }

  const scanLength = Math.max(1, bytes.length - header.scanStartOffset);
  const keywordScan = scanKeywords(bytes, {
    startOffset: header.scanStartOffset,
    collectNames: options.collectNames ?? true,
    maxDistinctNames: limits.maxDistinctNames,
    maxDates: limits.maxDates,
    ...(options.onProgress === undefined
      ? {}
      : {
          onProgress: (processed: number) => {
            options.onProgress?.(Math.min(1, (processed - header.scanStartOffset) / scanLength));
          },
        }),
  });
  const eof = analyzeEof(bytes, header.scanStartOffset);
  const keywords = buildKeywordCounts(keywordScan);
  messages.push(...scanMessages(keywordScan, eof));

  const result: ScanResult = {
    ...base,
    durationMs: now().getTime() - startedAt.getTime(),
    keywordScanPerformed: true,
    keywords,
    eof,
    entropy: keywordScan.entropy,
    obfuscation: {
      hexEncodedKeywordOccurrences: keywords.reduce((total, k) => total + k.hexcodeCount, 0),
      namesWithHexEscapes: keywordScan.namesWithHexEscapes,
      malformedHexEscapes: keywordScan.malformedHexEscapes,
    },
    structure: {
      objectKeywordsBalanced: countOf(keywords, 'obj') === countOf(keywords, 'endobj'),
      streamKeywordsBalanced: countOf(keywords, 'stream') === countOf(keywords, 'endstream'),
      headerAtFileStart: header.offset === 0,
      endedInsideStream: keywordScan.endedInsideStream,
      incrementalUpdatesLikely: eof.eofCount > 1,
    },
    dates: keywordScan.dates,
    names: keywordScan.names,
    messages,
    compatibilityNotes: compatibilityNotes(header, keywordScan),
    deep: null,
  };
  options.onProgress?.(1);
  return result;
}
