import { afterEach, describe, expect, it, vi } from 'vitest';
import { analyzePdf } from '../../src/features/pdf-analysis/engine/analyzePdf';
import { deepScanPdf } from '../../src/features/pdf-analysis/engine/deepScan';
import type { DeepScanResult } from '../../src/features/pdf-analysis/types/analysis';
import {
  BASIC_OBJECTS,
  bytes,
  compress,
  createTestPdf,
  objectStream,
} from '../fixtures/createTestPdf';
import { getFixture, pseudoRandomBytes } from '../fixtures/fixtureDefinitions';

const deepOf = (id: string, options: Parameters<typeof deepScanPdf>[1] = {}) =>
  deepScanPdf(getFixture(id).build(), options);

const actions = (deep: DeepScanResult) =>
  deep.actions.map(
    (action) =>
      `${action.trigger} ${action.action} ${action.risk}${action.automatic ? ' auto' : ''}`,
  );

const patterns = (deep: DeepScanResult) => deep.scriptPatterns.map((pattern) => pattern.id).sort();

describe('deepScanPdf', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('reports nothing unusual for a plain document', async () => {
    const deep = await deepOf('minimal');
    expect(deep).toMatchObject({
      status: 'complete',
      objectsIndexed: 3,
      hiddenKeywords: [],
      actions: [],
      scriptPatterns: [],
      notes: [],
    });
  });

  it('finds keywords and actions hidden in compressed object streams', async () => {
    const deep = await deepOf('objstm-hidden-javascript');
    expect(deep.objectStreams).toBe(1);
    expect(deep.streamsDecoded).toBe(1);
    expect(deep.hiddenKeywords).toEqual([
      { name: '/JS', count: 1, hexcodeCount: 0 },
      { name: '/JavaScript', count: 1, hexcodeCount: 0 },
      { name: '/OpenAction', count: 1, hexcodeCount: 0 },
    ]);
    expect(deep.actions).toEqual([
      {
        trigger: '/OpenAction',
        when: 'When the document is opened',
        automatic: true,
        action: 'JavaScript',
        risk: 'high',
        count: 1,
        hiddenCount: 1,
      },
    ]);
    expect(deep.scripts).toMatchObject({ found: 1, analyzed: 1 });
  });

  it('recognizes an open action that only navigates', async () => {
    expect(actions(await deepOf('openaction-destination'))).toEqual([
      '/OpenAction Destination low auto',
    ]);
  });

  it('follows indirect references to compressed script streams and checks their content', async () => {
    const deep = await deepOf('openaction-javascript-stream');
    expect(actions(deep)).toEqual(['/OpenAction JavaScript high auto']);
    expect(patterns(deep)).toEqual(['eval', 'eval-decoded-code', 'heap-spray', 'unescape']);
    expect(deep.scriptPatterns[0]?.severity).toBe('high');
  });

  it('treats document-level scripts as automatic', async () => {
    expect(actions(await deepOf('document-level-javascript'))).toEqual([
      '/Names /JavaScript JavaScript high auto',
    ]);
  });

  it('treats form-field scripts as interactive', async () => {
    const deep = await deepOf('form-field-script');
    expect(deep.actions).toMatchObject([
      {
        trigger: '/AA /K',
        when: 'When a form field is typed into',
        automatic: false,
        action: 'JavaScript',
      },
    ]);
  });

  it('classifies launch targets without keeping them', async () => {
    const deep = await deepOf('launch-executable');
    expect(actions(deep)).toEqual(['/OpenAction Launch high auto']);
    expect(deep.launchTargets).toEqual({ executable: 1, other: 0 });
    expect(JSON.stringify(deep)).not.toContain('calc');
  });

  it('rates automatic web access as medium and never stores the address', async () => {
    const deep = await deepOf('openaction-uri');
    expect(actions(deep)).toEqual(['/OpenAction URI medium auto']);
    expect(JSON.stringify(deep)).not.toContain('example.com');
  });

  it('rates clicked links as low risk', async () => {
    const pdf = createTestPdf({
      objects: [
        ...BASIC_OBJECTS,
        { body: '<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://example.org) >> >>' },
      ],
    });
    expect(actions(await deepScanPdf(pdf))).toEqual(['/A URI low']);
  });

  it('finds scripts in XFA forms', async () => {
    const deep = await deepOf('xfa-script');
    expect(deep.scripts).toMatchObject({ found: 1, analyzed: 1, xfaScripts: 1 });
  });

  it('decodes hex-escaped names and filters the way PDF readers do', async () => {
    const deep = await deepOf('obfuscated-filter-and-action');
    expect(actions(deep)).toEqual(['/OpenAction JavaScript high auto']);
    expect(patterns(deep)).toEqual(['from-char-code']);
  });

  it('decodes filter chains', async () => {
    expect(patterns(await deepOf('filter-chain-script'))).toEqual(['util-printf']);
  });

  it('analyses scripts in UTF-16 hex strings', async () => {
    const utf16 = Array.from(
      'eval(unescape(x))',
      (character) => `00${character.charCodeAt(0).toString(16).padStart(2, '0')}`,
    ).join('');
    const pdf = createTestPdf({
      objects: [...BASIC_OBJECTS, { body: `<< /S /JavaScript /JS <FEFF${utf16}> >>` }],
    });
    expect(patterns(await deepScanPdf(pdf))).toEqual(['eval', 'eval-decoded-code', 'unescape']);
  });

  it('follows chained /Next actions and survives reference cycles', async () => {
    const pdf = createTestPdf({
      objects: [
        { body: '<< /Type /Catalog /OpenAction 2 0 R >>' },
        { body: '<< /S /GoTo /D [1 0 R /Fit] /Next 3 0 R >>' },
        { body: '<< /S /JavaScript /JS (x) /Next [2 0 R 3 0 R] >>' },
      ],
    });
    const deep = await deepScanPdf(pdf);
    expect(actions(deep)).toEqual([
      '/OpenAction JavaScript high auto',
      '/OpenAction GoTo low auto',
    ]);
  });

  it('counts references that cannot be resolved', async () => {
    const pdf = createTestPdf({ objects: [{ body: '<< /Type /Catalog /OpenAction 99 0 R >>' }] });
    const deep = await deepScanPdf(pdf);
    expect(actions(deep)).toEqual(['/OpenAction Unresolved medium auto']);
    expect(deep.unresolvedReferences).toBeGreaterThan(0);
  });

  it('describes /AA events by where they appear', async () => {
    const pdf = createTestPdf({
      objects: [
        { body: '<< /Type /Catalog /AA << /WC 4 0 R >> >>' },
        { body: '<< /Type /Page /AA << /O 4 0 R >> >>' },
        { body: '<< /Type /Annot /AA << /PV 4 0 R /E 4 0 R >> >>' },
        { body: '<< /S /Named /N /NextPage >>' },
      ],
    });
    const deep = await deepScanPdf(pdf);
    const byTrigger = Object.fromEntries(
      deep.actions.map((action) => [action.trigger, [action.when, action.automatic]]),
    );
    expect(byTrigger).toEqual({
      '/AA /WC': ['Before the document closes', true],
      '/AA /O': ['When a page is opened', true],
      '/AA /PV': ['When the page containing an annotation becomes visible', true],
      '/AA /E': ['When the pointer enters a field or annotation', false],
    });
  });

  it('skips decoding for encrypted documents and says so', async () => {
    const deep = await deepOf('objstm-hidden-javascript', { encrypted: true });
    expect(deep.streamsDecoded).toBe(0);
    expect(deep.status).toBe('partial');
    expect(deep.notes.join(' ')).toMatch(/encrypted/);
  });

  it('reports when the browser cannot decompress', async () => {
    vi.stubGlobal('DecompressionStream', undefined);
    const deep = await deepOf('objstm-hidden-javascript');
    expect(deep.hiddenKeywords).toEqual([]);
    expect(deep.decodeFailures).toBe(1);
    expect(deep.notes.join(' ')).toMatch(/cannot decompress/);
  });

  it('counts streams that fail to decompress', async () => {
    const pdf = createTestPdf({
      objects: [
        ...BASIC_OBJECTS,
        { body: '<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode >>', stream: 'not zlib' },
      ],
    });
    const deep = await deepScanPdf(pdf);
    expect(deep.decodeFailures).toBe(1);
    expect(deep.status).toBe('partial');
  });

  it('stops a decompression bomb at the per-stream limit', async () => {
    const bomb = compress(new Uint8Array(2 * 1024 * 1024));
    const pdf = createTestPdf({
      objects: [
        ...BASIC_OBJECTS,
        { body: '<< /Type /ObjStm /N 0 /First 0 /Filter /FlateDecode >>', stream: bomb },
      ],
    });
    const deep = await deepScanPdf(pdf, { limits: { maxDecodedBytesPerStream: 64 * 1024 } });
    expect(deep.decodedBytes).toBe(64 * 1024);
    expect(deep.notes.join(' ')).toMatch(/decompression bomb/);
  });

  it('respects the stream count, total size, object and time limits', async () => {
    const streams = Array.from({ length: 5 }, (_, index) =>
      objectStream([{ number: 100 + index, body: '<< /JS (x) >>' }]),
    );
    const pdf = createTestPdf({ objects: [...BASIC_OBJECTS, ...streams] });
    const limited = await deepScanPdf(pdf, { limits: { maxDecodedStreams: 2 } });
    expect(limited.streamsDecoded).toBe(2);
    expect(limited.notes.join(' ')).toMatch(/decompression limit/);

    let clock = 0;
    const timed = await deepScanPdf(pdf, {
      limits: { timeBudgetMs: 10 },
      now: () => (clock += 20),
    });
    expect(timed.notes.join(' ')).toMatch(/time limit/);

    const fewObjects = await deepScanPdf(pdf, { limits: { maxObjects: 2 } });
    expect(fewObjects.notes.join(' ')).toMatch(/Only the first 2 objects/);
  });

  it('reports progress up to completion', async () => {
    const progress: number[] = [];
    await deepOf('objstm-hidden-javascript', { onProgress: (fraction) => progress.push(fraction) });
    expect(progress.at(-1)).toBe(1);
  });

  it('never keeps script text, URLs or file names', async () => {
    for (const id of [
      'openaction-javascript-stream',
      'document-level-javascript',
      'launch-executable',
      'openaction-uri',
      'xfa-script',
    ]) {
      const serialized = JSON.stringify(await deepOf(id));
      // Strings that exist only inside the fixtures' scripts, links and launch targets.
      for (const content of [
        'inert text',
        '1 + 1',
        "'Hello'",
        'calc.exe',
        'example.com',
        'messageBox',
        'PDF Signal fixture',
      ]) {
        expect(serialized, `${id} leaked ${content}`).not.toContain(content);
      }
    }
  });

  it('handles random and hostile input without throwing', async () => {
    const hostile = [
      pseudoRandomBytes(200_000, 1),
      bytes('%PDF-1.7\n', '1 0 obj '.repeat(5000)),
      bytes('%PDF-1.7\n1 0 obj ', '<<'.repeat(10_000)),
      bytes('%PDF-1.7\n1 0 obj (', '\\'.repeat(10_000)),
      bytes(
        '%PDF-1.7\n1 0 obj << /Type /ObjStm /N 99999999 /First 0 >> stream\n',
        compress('1 0 2 0'),
        '\nendstream',
      ),
      bytes(
        '%PDF-1.7\n1 0 obj << /Names << /JavaScript 1 0 R >> /Kids [1 0 R] /OpenAction 1 0 R /AA 1 0 R >> endobj',
      ),
    ];
    for (const input of hostile) {
      const started = Date.now();
      const deep = await deepScanPdf(input);
      expect(['complete', 'partial']).toContain(deep.status);
      expect(Date.now() - started).toBeLessThan(5000);
    }
  });
});

describe('analyzePdf', () => {
  it('adds the deep analysis without changing the PDFiD-compatible counts', async () => {
    const pdf = getFixture('objstm-hidden-javascript').build();
    const result = await analyzePdf(pdf, { sha256: 'x' });
    expect(result.deep?.hiddenKeywords.length).toBe(3);
    expect(result.keywords.find((keyword) => keyword.name === '/JavaScript')?.count).toBe(0);
  });

  it('skips the deep analysis when the keyword scan was skipped or it is turned off', async () => {
    expect((await analyzePdf(getFixture('no-header').build())).deep).toBeNull();
    expect((await analyzePdf(getFixture('minimal').build(), { deep: false })).deep).toBeNull();
  });

  it('reports a failed deep analysis instead of throwing', async () => {
    const spy = vi.spyOn(Map.prototype, 'values').mockImplementation(() => {
      throw new Error('boom');
    });
    const result = await analyzePdf(getFixture('minimal').build());
    spy.mockRestore();
    expect(result.deep?.status).toBe('failed');
    expect(result.keywords.length).toBe(21);
  });
});
