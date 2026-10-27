import type { DeepScanResult, ScanResult } from '../types/analysis';
import { deepScanPdf, type DeepScanLimits } from './deepScan';
import { scanPdf, type ScanOptions } from './scanPdf';

export interface AnalyzeOptions extends ScanOptions {
  /** Run the deep analysis after the PDFiD-compatible scan. Defaults to true. */
  readonly deep?: boolean;
  readonly deepLimits?: Partial<DeepScanLimits>;
  readonly onDeepProgress?: (fraction: number) => void;
}

const FAILED_DEEP_SCAN: DeepScanResult = {
  status: 'failed',
  durationMs: 0,
  objectsIndexed: 0,
  objectStreams: 0,
  streamsDecoded: 0,
  decodedBytes: 0,
  decodeFailures: 0,
  encrypted: false,
  objectStreamsIncomplete: 0,
  decompressionBombs: 0,
  hiddenKeywords: [],
  structuralNames: {},
  actions: [],
  unresolvedReferences: 0,
  launchTargets: { executable: 0, other: 0 },
  attachments: { total: 0, executable: 0, archive: 0, macroDocument: 0 },
  targets: { networkShare: 0, automaticNetworkShare: 0, scriptUri: 0 },
  scripts: { found: 0, analyzed: 0, undecodable: 0, bytesAnalyzed: 0, xfaScripts: 0 },
  scriptPatterns: [],
  notes: ['The deep analysis stopped unexpectedly; only the keyword scan is available.'],
};

/**
 * Full analysis: the PDFiD-compatible keyword scan (unchanged, so its counts stay comparable
 * with pdfid.py) followed by PDF Signal's deep analysis of objects, actions and scripts.
 */
export async function analyzePdf(
  bytes: Uint8Array,
  options: AnalyzeOptions = {},
): Promise<ScanResult> {
  const scan = scanPdf(bytes, options);
  if (!scan.keywordScanPerformed || options.deep === false) {
    return scan;
  }
  try {
    // Encryption is decided by the deep analysis from the trailer, not from PDFiD's /Encrypt
    // count: that token can appear anywhere (even in a string) and must not switch analysis off.
    const deep = await deepScanPdf(bytes, {
      ...(options.deepLimits === undefined ? {} : { limits: options.deepLimits }),
      ...(options.onDeepProgress === undefined ? {} : { onProgress: options.onDeepProgress }),
    });
    return { ...scan, deep };
  } catch {
    return { ...scan, deep: FAILED_DEEP_SCAN };
  }
}
