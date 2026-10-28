import { describe, expect, it } from 'vitest';
import { APP_CONFIG } from '../../src/config/appConfig';
import { computeSha256Hex } from '../../src/features/pdf-analysis/engine/hash';
import { ENGINE_INFO, scanPdf } from '../../src/features/pdf-analysis/engine/scanPdf';
import type { ScanResult } from '../../src/features/pdf-analysis/types/analysis';
import { bytes, createTestPdf, BASIC_OBJECTS } from '../fixtures/createTestPdf';
import { FIXTURES, getFixture } from '../fixtures/fixtureDefinitions';

const fixed = () => new Date('2026-01-02T03:04:05.000Z');

function scanFixture(id: string, force = false): ScanResult {
  return scanPdf(getFixture(id).build(), { force, sha256: 'x', now: fixed });
}

const codes = (result: ScanResult) => result.messages.map((message) => message.code);

describe('scanPdf on synthetic fixtures', () => {
  for (const fixture of FIXTURES.filter((candidate) => candidate.expectedCounts !== undefined)) {
    it(`${fixture.id}: ${fixture.description}`, () => {
      const result = scanPdf(fixture.build(), { sha256: 'x' });
      const counts = Object.fromEntries(
        result.keywords.map((keyword) => [keyword.name, keyword.count]),
      );
      expect(counts).toMatchObject(fixture.expectedCounts!);
      if (fixture.expectedHexcodeCounts !== undefined) {
        const hex = Object.fromEntries(
          result.keywords.map((keyword) => [keyword.name, keyword.hexcodeCount]),
        );
        expect(hex).toMatchObject(fixture.expectedHexcodeCounts);
      }
    });
  }
});

describe('scanPdf result', () => {
  it('describes a well-formed file completely', () => {
    const result = scanFixture('minimal');
    expect(result).toMatchObject({
      schemaVersion: 2,
      engine: ENGINE_INFO,
      scannedAt: '2026-01-02T03:04:05.000Z',
      durationMs: 0,
      mode: 'standard',
      isPdf: true,
      keywordScanPerformed: true,
      header: { found: true, offset: 0, text: '%PDF-1.7', version: '1.7', versionRecognized: true },
      eof: { eofCount: 1, bytesAfterLastEof: 0, trailingDataPresent: false },
      structure: {
        objectKeywordsBalanced: true,
        streamKeywordsBalanced: true,
        headerAtFileStart: true,
        endedInsideStream: false,
        incrementalUpdatesLikely: false,
      },
      obfuscation: {
        hexEncodedKeywordOccurrences: 0,
        namesWithHexEscapes: 0,
        malformedHexEscapes: 0,
      },
      compatibilityNotes: [],
    });
    expect(result.keywords).toHaveLength(21);
    expect(result.messages).toEqual([]);
  });

  it('attaches category, kind and label to each keyword count', () => {
    const js = scanFixture('javascript-open-action').keywords.find(
      (keyword) => keyword.name === '/JS',
    );
    expect(js).toEqual({
      name: '/JS',
      kind: 'indicator',
      category: 'javascript',
      label: 'JavaScript code entry',
      count: 1,
      hexcodeCount: 0,
    });
  });

  it('skips the keyword scan without a header unless forced, like PDFiD', () => {
    const standard = scanFixture('no-header');
    expect(standard).toMatchObject({
      isPdf: false,
      keywordScanPerformed: false,
      keywords: [],
      eof: null,
      entropy: null,
    });
    expect(codes(standard)).toEqual(['header-missing', 'not-scanned']);

    const forced = scanFixture('no-header', true);
    expect(forced).toMatchObject({ isPdf: false, keywordScanPerformed: true, mode: 'forced' });
    expect(forced.keywords.find((keyword) => keyword.name === 'obj')?.count).toBe(3);
    expect(codes(forced)).toContain('forced-scan');
  });

  it('uses standard mode when force is requested but a header exists', () => {
    expect(scanFixture('minimal', true).mode).toBe('standard');
  });

  it('reports a header after leading junk and does not tokenize the junk', () => {
    const result = scanFixture('header-after-prefix');
    expect(result.header.offset).toBeGreaterThan(0);
    expect(result.structure?.headerAtFileStart).toBe(false);
    expect(codes(result)).toContain('header-offset');
    expect(result.keywords.find((keyword) => keyword.name === '/JavaScript')?.count).toBe(0);
  });

  it('reports malformed and unpublished header versions', () => {
    expect(codes(scanFixture('header-malformed-version'))).toContain('header-version-unrecognized');
    const unpublished = scanFixture('header-unpublished-version');
    expect(unpublished.header.version).toBe('1.9');
    expect(
      unpublished.messages.find((m) => m.code === 'header-version-unrecognized')?.text,
    ).toMatch(/1\.9/);
  });

  it('reports multiple %%EOF markers as informational', () => {
    const result = scanFixture('incremental-update');
    expect(result.eof?.eofCount).toBe(2);
    expect(result.structure?.incrementalUpdatesLikely).toBe(true);
    expect(result.messages.find((message) => message.code === 'eof-multiple')?.severity).toBe(
      'info',
    );
  });

  it('distinguishes trailing data from trailing whitespace', () => {
    const data = scanFixture('trailing-data');
    expect(data.eof).toMatchObject({
      bytesAfterLastEof: 29,
      trailingDataPresent: true,
      trailingDataWhitespaceOnly: false,
    });
    expect(data.messages.find((message) => message.code === 'trailing-data')?.severity).toBe(
      'warning',
    );

    const whitespace = scanFixture('trailing-whitespace');
    expect(whitespace.eof?.trailingDataWhitespaceOnly).toBe(true);
    expect(whitespace.messages.find((message) => message.code === 'trailing-data')?.severity).toBe(
      'info',
    );
  });

  it('handles truncated files without throwing', () => {
    const result = scanFixture('truncated-in-stream');
    expect(result.eof?.eofCount).toBe(0);
    expect(codes(result)).toEqual(expect.arrayContaining(['eof-missing', 'ended-inside-stream']));
    expect(result.structure?.streamKeywordsBalanced).toBe(false);
  });

  it('handles empty input in both modes', () => {
    const standard = scanPdf(new Uint8Array(0), { sha256: 'x' });
    expect(codes(standard)).toEqual(['empty-input', 'header-missing', 'not-scanned']);
    const forced = scanPdf(new Uint8Array(0), { force: true, sha256: 'x' });
    expect(forced.entropy?.totalEntropy).toBeNull();
    expect(forced.compatibilityNotes.join(' ')).toMatch(/ZeroDivisionError/);
  });

  it('records the pdfid.py IndexError case as a compatibility note', () => {
    const result = scanFixture('header-only-short');
    expect(result.header.pdfidWouldError).toBe(true);
    expect(result.compatibilityNotes.join(' ')).toMatch(/IndexError/);
  });

  it('notes when the hash is unavailable', () => {
    const result = scanPdf(createTestPdf({ objects: BASIC_OBJECTS }));
    expect(result.sha256).toBeNull();
    expect(codes(result)).toContain('hash-unavailable');
  });

  it('reports progress ending at 1', () => {
    const fractions: number[] = [];
    scanPdf(getFixture('high-entropy-stream').build(), {
      onProgress: (fraction) => fractions.push(fraction),
    });
    expect(fractions.at(-1)).toBe(1);
    expect(fractions.every((fraction) => fraction >= 0 && fraction <= 1)).toBe(true);
  });

  it('never includes raw document content in the result', () => {
    const secret = 'CONFIDENTIAL-PATIENT-RECORD-12345';
    const pdf = createTestPdf({
      objects: [
        ...BASIC_OBJECTS,
        { body: '<< /Length 33 >>', stream: secret },
        { body: `<< /Title (${secret}) >>` },
      ],
    });
    const serialized = JSON.stringify(scanPdf(pdf, { sha256: 'x' }));
    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain('CONFIDENTIAL');
  });

  it('does not modify the input bytes', () => {
    const pdf = getFixture('hex-obfuscated-names').build();
    const copy = pdf.slice();
    scanPdf(pdf, { force: true });
    expect(pdf).toEqual(copy);
  });

  it('scans a file of the maximum size well within the scan timeout', () => {
    const large = createTestPdf({
      objects: [
        ...BASIC_OBJECTS,
        { body: '<< >>', stream: new Uint8Array(APP_CONFIG.maxFileSizeBytes).fill(0x41) },
      ],
    });
    const started = performance.now();
    const result = scanPdf(large, { sha256: 'x' });
    expect(result.keywords.find((keyword) => keyword.name === 'obj')?.count).toBe(4);
    // Shared CI machines with coverage enabled take 2–6 s for this; a laptop takes about 0.5 s.
    // A super-linear slowdown, which this test guards against, would take minutes.
    expect(performance.now() - started).toBeLessThan(APP_CONFIG.scanTimeoutMs / 3);
  });
});

describe('computeSha256Hex', () => {
  it('matches a known SHA-256 digest', async () => {
    await expect(computeSha256Hex(bytes('abc'))).resolves.toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
