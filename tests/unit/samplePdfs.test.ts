import { afterEach, describe, expect, it, vi } from 'vitest';
import { assessIndicators } from '../../src/features/pdf-analysis/assessment/assessIndicators';
import { analyzePdf } from '../../src/features/pdf-analysis/engine/analyzePdf';
import {
  buildSampleBytes,
  createSampleFile,
  isSampleAvailable,
  SAMPLES,
} from '../../src/features/samples/samplePdfs';

describe('sample PDFs', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each([
    ['clean', 'none-detected'],
    ['auto-javascript', 'high-risk'],
    ['hidden-javascript', 'high-risk'],
  ] as const)('the %s sample scans as %s with the real engine', async (id, level) => {
    const scan = await analyzePdf(await buildSampleBytes(id));
    expect(scan.header).toMatchObject({ found: true, version: '1.7' });
    expect(scan.eof?.eofCount).toBe(1);
    expect(assessIndicators(scan).level).toBe(level);
  });

  it('hides the script from the byte-level scan in the hidden sample', async () => {
    const scan = await analyzePdf(await buildSampleBytes('hidden-javascript'));
    expect(scan.keywords.find((keyword) => keyword.name === '/JavaScript')?.count).toBe(0);
    expect(scan.deep?.hiddenKeywords.map((keyword) => keyword.name)).toEqual([
      '/JS',
      '/JavaScript',
      '/OpenAction',
    ]);
  });

  it('produces a balanced, well-formed file', async () => {
    const scan = await analyzePdf(await buildSampleBytes('auto-javascript'), { sha256: 'x' });
    expect(scan.structure).toMatchObject({
      objectKeywordsBalanced: true,
      streamKeywordsBalanced: true,
    });
    expect(scan.messages).toEqual([]);
  });

  it('creates named PDF files', async () => {
    const file = await createSampleFile(SAMPLES[1]!);
    expect(file.name).toBe('pdf-signal-sample-auto-javascript.pdf');
    expect(file.type).toBe('application/pdf');
    expect(file.size).toBeGreaterThan(300);
  });

  it('hides the compressed sample when CompressionStream is unavailable', () => {
    vi.stubGlobal('CompressionStream', undefined);
    expect(SAMPLES.filter(isSampleAvailable).map((sample) => sample.id)).toEqual([
      'clean',
      'auto-javascript',
    ]);
  });
});
