import { formatNameForDisplay } from '../../src/features/pdf-analysis/engine/decodePdfNames';
import { WORD_CAPACITY } from '../../src/features/pdf-analysis/engine/scanKeywords';
import { DEFAULT_SCAN_LIMITS } from '../../src/features/pdf-analysis/engine/scanPdf';
import type { ScanMode, ScanResult } from '../../src/features/pdf-analysis/types/analysis';
import type { FixtureDefinition } from '../fixtures/fixtureDefinitions';

/** The upstream file the reference results were produced with. */
export const PDFID_REFERENCE_SOURCE = {
  version: '0.2.10',
  repository: 'https://github.com/DidierStevens/DidierStevensSuite',
  commit: '104bb4fe77e24f0891a954af349449227d06f77d',
  sha256: 'e958a01f1c2596470f27d3c308061b85d7059ff476a58d74f1957a71b4f1248f',
} as const;

interface ReferenceCounter {
  readonly name: string;
  readonly count: number;
  readonly hexcodeCount: number;
}

export interface ReferenceModeResult {
  readonly exception?: string;
  readonly isPdf: boolean;
  readonly header?: string;
  readonly keywords?: readonly ReferenceCounter[];
  readonly names?: readonly ReferenceCounter[];
  readonly eofCount?: number | null;
  readonly bytesAfterLastEof?: number | null;
  readonly totalBytes?: number | null;
  readonly totalEntropy?: number | null;
  readonly streamBytes?: number | null;
  readonly streamEntropy?: number | null;
  readonly nonStreamBytes?: number | null;
  readonly nonStreamEntropy?: number | null;
  readonly dates?: readonly { readonly value: string; readonly name: string }[];
}

export interface ReferenceFile {
  readonly pdfidVersion: string;
  readonly python: string;
  readonly source?: typeof PDFID_REFERENCE_SOURCE;
  readonly results: Readonly<
    Record<string, { readonly standard: ReferenceModeResult; readonly forced: ReferenceModeResult }>
  >;
}

/** PDFiD prints entropy with six decimals (`%f`), so values may differ by rounding only. */
const ENTROPY_TOLERANCE = 1e-6;

function entropyMatches(ours: number | null, reference: number | null | undefined): boolean {
  if (ours === null || reference === null || reference === undefined) {
    return ours === (reference ?? null);
  }
  return Math.abs(ours - reference) <= ENTROPY_TOLERANCE;
}

/**
 * Compares one engine result with pdfid.py output for the same input and mode.
 * Returns human-readable differences; an empty array means the results agree.
 */
export function compareWithReference(
  fixture: FixtureDefinition,
  mode: ScanMode,
  reference: ReferenceModeResult,
  result: ScanResult,
): string[] {
  const differences: string[] = [];
  const expectError =
    fixture.knownPdfidError !== undefined &&
    (fixture.knownPdfidError.mode === 'both' || fixture.knownPdfidError.mode === mode);

  if (reference.exception !== undefined) {
    if (!expectError) {
      differences.push(
        `pdfid.py raised ${reference.exception}, which is not a recorded difference`,
      );
    }
    return differences;
  }
  if (expectError) {
    differences.push('fixture records a pdfid.py error, but pdfid.py completed');
  }
  if (reference.isPdf !== result.isPdf) {
    differences.push(`isPdf: pdfid=${reference.isPdf} engine=${result.isPdf}`);
  }
  if (mode === 'standard' && !reference.isPdf) {
    if (result.keywordScanPerformed) {
      differences.push('pdfid skipped the scan (no header) but the engine scanned');
    }
    return differences;
  }

  if ((reference.header ?? '') !== (result.header.text ?? '')) {
    differences.push(
      `header: pdfid=${JSON.stringify(reference.header)} engine=${JSON.stringify(result.header.text)}`,
    );
  }

  const ourKeywords = result.keywords.map(({ name, count, hexcodeCount }) => ({
    name,
    count,
    hexcodeCount,
  }));
  if (JSON.stringify(ourKeywords) !== JSON.stringify(reference.keywords ?? [])) {
    for (const expected of reference.keywords ?? []) {
      const actual = ourKeywords.find((keyword) => keyword.name === expected.name);
      if (actual?.count !== expected.count || actual.hexcodeCount !== expected.hexcodeCount) {
        differences.push(
          `${expected.name}: pdfid=${expected.count}(${expected.hexcodeCount}) engine=${actual?.count ?? '-'}(${actual?.hexcodeCount ?? '-'})`,
        );
      }
    }
    if (ourKeywords.length !== (reference.keywords ?? []).length) {
      differences.push('keyword list length differs');
    }
  }

  // Names longer than the retained word buffer, and distinct names beyond the retention cap,
  // are deliberately omitted (resource limits); every retained name must still match exactly.
  const allReference = (reference.names ?? []).map((name) => ({
    name: formatNameForDisplay(name.name),
    raw: name.name,
    count: name.count,
    hexcodeCount: name.hexcodeCount,
  }));
  const actualNames = result.names.entries.map(({ name, count, hexcodeCount }) => ({
    name,
    count,
    hexcodeCount,
  }));
  const capped = actualNames.length >= DEFAULT_SCAN_LIMITS.maxDistinctNames;
  if (capped) {
    const byName = new Map(allReference.map((entry) => [entry.name, entry]));
    for (const entry of actualNames) {
      const expected = byName.get(entry.name);
      if (expected?.count !== entry.count || expected.hexcodeCount !== entry.hexcodeCount) {
        differences.push(`retained name ${entry.name} does not match pdfid`);
      }
    }
    const retained = new Set(actualNames.map((entry) => entry.name));
    const omitted = allReference
      .filter((entry) => !retained.has(entry.name))
      .reduce((total, entry) => total + entry.count, 0);
    if (result.names.omitted !== omitted) {
      differences.push(`omitted names: expected ${omitted}, engine ${result.names.omitted}`);
    }
  } else {
    const expectedNames = allReference
      .filter((entry) => entry.raw.length <= WORD_CAPACITY + 1)
      .map(({ name, count, hexcodeCount }) => ({ name, count, hexcodeCount }));
    if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
      differences.push(
        `names differ: pdfid=${JSON.stringify(expectedNames)} engine=${JSON.stringify(actualNames)}`,
      );
    }
    const omittedOccurrences = allReference
      .filter((entry) => entry.raw.length > WORD_CAPACITY + 1)
      .reduce((total, entry) => total + entry.count, 0);
    if (result.names.omitted !== omittedOccurrences) {
      differences.push(
        `omitted long names: expected ${omittedOccurrences}, engine ${result.names.omitted}`,
      );
    }
  }

  if ((reference.eofCount ?? null) !== (result.eof?.eofCount ?? null)) {
    differences.push(`%%EOF count: pdfid=${reference.eofCount} engine=${result.eof?.eofCount}`);
  }
  if ((reference.bytesAfterLastEof ?? null) !== (result.eof?.bytesAfterLastEof ?? null)) {
    differences.push(
      `after last %%EOF: pdfid=${reference.bytesAfterLastEof} engine=${result.eof?.bytesAfterLastEof}`,
    );
  }

  const entropy = result.entropy;
  const byteCounts: [string, number | null | undefined, number | undefined][] = [
    ['total bytes', reference.totalBytes, entropy?.totalBytes],
    ['stream bytes', reference.streamBytes, entropy?.streamBytes],
    ['non-stream bytes', reference.nonStreamBytes, entropy?.nonStreamBytes],
  ];
  for (const [label, expected, actual] of byteCounts) {
    if ((expected ?? null) !== (actual ?? null)) {
      differences.push(`${label}: pdfid=${expected} engine=${actual}`);
    }
  }
  const entropies: [string, number | null | undefined, number | null][] = [
    ['total entropy', reference.totalEntropy, entropy?.totalEntropy ?? null],
    ['stream entropy', reference.streamEntropy, entropy?.streamEntropy ?? null],
    ['non-stream entropy', reference.nonStreamEntropy, entropy?.nonStreamEntropy ?? null],
  ];
  for (const [label, expected, actual] of entropies) {
    if (!entropyMatches(actual, expected)) {
      differences.push(`${label}: pdfid=${expected} engine=${actual}`);
    }
  }

  const expectedDates = (reference.dates ?? []).map((date) => ({
    value: date.value,
    name: formatNameForDisplay(date.name),
  }));
  const actualDates = result.dates.entries.map(({ value, name }) => ({ value, name }));
  if (JSON.stringify(actualDates) !== JSON.stringify(expectedDates)) {
    differences.push(
      `dates: pdfid=${JSON.stringify(expectedDates)} engine=${JSON.stringify(actualDates)}`,
    );
  }
  return differences;
}
