import { describe, expect, it, vi } from 'vitest';
import { PDFID_KEYWORDS } from '../../src/features/pdf-analysis/engine/pdfidKeywords';
import { scanKeywords, WORD_CAPACITY } from '../../src/features/pdf-analysis/engine/scanKeywords';
import { scanPdf } from '../../src/features/pdf-analysis/engine/scanPdf';
import { bytes } from '../fixtures/createTestPdf';

/** Scans `%PDF-1.7\n` followed by `body` and returns a name → [count, hexcodeCount] map. */
function scan(...body: Parameters<typeof bytes>) {
  const result = scanPdf(bytes('%PDF-1.7\n', ...body), { sha256: 'test' });
  return {
    result,
    count: (name: string) => result.keywords.find((keyword) => keyword.name === name)?.count,
    hex: (name: string) => result.keywords.find((keyword) => keyword.name === name)?.hexcodeCount,
  };
}

const DEFAULTS = { startOffset: 0, collectNames: true, maxDistinctNames: 100, maxDates: 10 };

describe('keyword counting', () => {
  it('reports every PDFiD keyword plus /Colors > 2^24, in upstream order, with zero counts', () => {
    const { result } = scan('\n');
    expect(result.keywords.map((keyword) => keyword.name)).toEqual([
      'obj',
      'endobj',
      'stream',
      'endstream',
      'xref',
      'trailer',
      'startxref',
      '/Page',
      '/Encrypt',
      '/ObjStm',
      '/JS',
      '/JavaScript',
      '/AA',
      '/OpenAction',
      '/AcroForm',
      '/JBIG2Decode',
      '/RichMedia',
      '/Launch',
      '/EmbeddedFile',
      '/XFA',
      '/Colors > 2^24',
    ]);
    expect(
      result.keywords.every((keyword) => keyword.count === 0 && keyword.hexcodeCount === 0),
    ).toBe(true);
  });

  const structural = PDFID_KEYWORDS.filter((keyword) => !keyword.name.startsWith('/'));
  it.each(structural.map((keyword) => keyword.name))('counts the bare word %s', (name) => {
    const { count } = scan(` ${name} \n${name}\n`);
    expect(count(name)).toBe(2);
  });

  const names = PDFID_KEYWORDS.filter((keyword) => keyword.name.startsWith('/'));
  it.each(names.map((keyword) => keyword.name))(
    'counts the name %s and not its bare word',
    (name) => {
      const { count } = scan(`<< ${name} 1 ${name}(x) ${name.slice(1)} >>`);
      expect(count(name)).toBe(2);
    },
  );

  it('counts many occurrences', () => {
    const { count } = scan('/JS '.repeat(1000));
    expect(count('/JS')).toBe(1000);
  });

  it('does not count bare words as names or names as bare words', () => {
    const { count } = scan('/obj /endobj JavaScript OpenAction Page');
    expect(count('obj')).toBe(0);
    expect(count('endobj')).toBe(0);
    expect(count('/JavaScript')).toBe(0);
    expect(count('/OpenAction')).toBe(0);
    expect(count('/Page')).toBe(0);
  });

  it('matches whole words only', () => {
    const { count } = scan('/Pages /JSX /XJS /JavaScripts endobjx xobj startxref objstm');
    expect(count('/Page')).toBe(0);
    expect(count('/JS')).toBe(0);
    expect(count('/JavaScript')).toBe(0);
    expect(count('endobj')).toBe(0);
    expect(count('obj')).toBe(0);
    expect(count('startxref')).toBe(1);
    expect(count('xref')).toBe(0);
  });

  it('ends words at every non-alphanumeric byte, as upstream does', () => {
    // PDF syntax treats /JS_x as one name; PDFiD (and PDF Signal) count it as /JS.
    const { count } = scan('/JS_x /JS.y /JS-z /JS(a) /JS<< /JS[ /JS/JS');
    expect(count('/JS')).toBe(8);
  });

  it('is case-sensitive', () => {
    const { count } = scan('/javascript /JAVASCRIPT /Javascript /js /Js /page OBJ Obj /openaction');
    expect(count('/JavaScript')).toBe(0);
    expect(count('/JS')).toBe(0);
    expect(count('/Page')).toBe(0);
    expect(count('obj')).toBe(0);
    expect(count('/OpenAction')).toBe(0);
  });

  it('counts keywords adjacent to bytes that are not valid UTF-8', () => {
    const { count, result } = scan(
      [0xff, 0xfe],
      '/JavaScript',
      [0xc3, 0x28],
      '/JS',
      [0x80],
      'obj',
      [0xa0],
    );
    expect(count('/JavaScript')).toBe(1);
    expect(count('/JS')).toBe(1);
    expect(count('obj')).toBe(1);
    expect(result.sizeBytes).toBe(9 + 2 + 11 + 2 + 3 + 1 + 3 + 1);
  });

  it('treats high bytes as delimiters rather than letters', () => {
    // 0xC9 is 'É' in Latin-1; Python's lower() keeps it outside a-z, so it ends the word.
    const { count } = scan('/JS', [0xc9], 'x');
    expect(count('/JS')).toBe(1);
  });

  it('counts keywords in stream data, strings and comments (PDFiD does not parse them)', () => {
    const { count } = scan(
      'stream\n/JavaScript obj\nendstream\n(/Launch in a string) % /OpenAction in a comment\n',
    );
    expect(count('/JavaScript')).toBe(1);
    expect(count('obj')).toBe(1);
    expect(count('/Launch')).toBe(1);
    expect(count('/OpenAction')).toBe(1);
  });

  it('counts a keyword at the very end of the data', () => {
    expect(scan('/JavaScript').count('/JavaScript')).toBe(1);
    expect(scan('endobj').count('endobj')).toBe(1);
  });
});

describe('hexadecimal escapes in names', () => {
  it('decodes escapes and records them in the hexcode count', () => {
    const { count, hex } = scan('/Open#41ction /J#61vaScript /#4A#53 /Launch');
    expect([count('/OpenAction'), hex('/OpenAction')]).toEqual([1, 1]);
    expect([count('/JavaScript'), hex('/JavaScript')]).toEqual([1, 1]);
    expect([count('/JS'), hex('/JS')]).toEqual([1, 1]);
    expect([count('/Launch'), hex('/Launch')]).toEqual([1, 0]);
  });

  it('accepts upper- and lowercase hex digits', () => {
    const { count, hex } = scan('/#4a#53 /#4A#53 /#4a#73');
    expect(count('/JS')).toBe(2);
    expect(hex('/JS')).toBe(2);
  });

  it('counts an escaped occurrence once even with several escapes', () => {
    const { count, hex } = scan('/#4A#61#76#61#53#63#72#69#70#74');
    expect(count('/JavaScript')).toBe(1);
    expect(hex('/JavaScript')).toBe(1);
  });

  it('keeps plain and escaped occurrences separate', () => {
    const { count, hex } = scan('/OpenAction /OpenAction /Open#41ction');
    expect(count('/OpenAction')).toBe(3);
    expect(hex('/OpenAction')).toBe(1);
  });

  it('ends the word at a malformed escape but stays in name mode', () => {
    // '/JS#G1' -> '/JS' then the name '/G1'; '/Open#ZZAction' -> '/Open' and '/ZZAction'.
    const { count, result } = scan('/JS#G1 /Open#ZZAction /#4 ');
    expect(count('/JS')).toBe(1);
    expect(count('/OpenAction')).toBe(0);
    expect(result.obfuscation?.malformedHexEscapes).toBe(3);
    expect(result.names.entries.map((entry) => entry.name)).toEqual([
      '/4',
      '/G1',
      '/Open',
      '/ZZAction',
    ]);
  });

  it('handles an escape truncated by the end of the data', () => {
    expect(scan('/JS#4').count('/JS')).toBe(1);
    expect(scan('/JS#').count('/JS')).toBe(1);
    expect(scan('/J#5').count('/JS')).toBe(0);
  });

  it('never decodes # outside a name', () => {
    const { count, result } = scan('/A #4A#53 (#4A#53) <4A53> #2FJS JS#00');
    expect(count('/JS')).toBe(0);
    expect(result.obfuscation?.namesWithHexEscapes).toBe(0);
  });

  it('keeps decoded delimiters and whitespace inside the name', () => {
    const { count, result } = scan('/Java#2FScript /Java#20Script /J#00S ');
    expect(count('/JavaScript')).toBe(0);
    expect(count('/JS')).toBe(0);
    expect(result.names.entries.map((entry) => entry.name)).toEqual([
      '/J#00S',
      '/Java#20Script',
      '/Java#2fScript',
    ]);
  });

  it('counts names of any kind that contain escapes', () => {
    const { result } = scan('/Ty#70e /Pa#67e /Plain');
    expect(result.obfuscation).toEqual({
      hexEncodedKeywordOccurrences: 1,
      namesWithHexEscapes: 2,
      malformedHexEscapes: 0,
    });
  });
});

describe('/Colors > 2^24 (CVE-2009-3459)', () => {
  it.each([
    ['/Colors 16777217 ', 1],
    ['/Colors 16777216 ', 0],
    ['/Colors 0000016777217 ', 1],
    ['/Colors 99999999999999999999999999 ', 1],
    ['/Colors 3 ', 0],
    ['/Colors 1e9 ', 0],
    ['/Colors /16777300 ', 1],
    ['/Col#6Frs 20000000 ', 1],
    ['/Colors 16777217', 0], // upstream does not check the final word
    ['/Colours 16777217 ', 0],
    ['/Colors\n16777217\n/Colors 20000000 ', 2],
  ])('%j counts %i', (body, expected) => {
    expect(scan(body).count('/Colors > 2^24')).toBe(expected);
  });

  it('notes the upstream ValueError for superscript digits without counting', () => {
    const { count, result } = scan('/Colors /1', [0x23], 'B2 ');
    expect(count('/Colors > 2^24')).toBe(0);
    expect(result.compatibilityNotes.join(' ')).toMatch(/ValueError/);
  });
});

describe('stream state and entropy', () => {
  it('classifies bytes between stream and endstream as stream data', () => {
    const { result } = scan('stream\nABC\nendstream\n');
    // '\nABC\n' is stream data; the endstream keyword is removed from the stream bucket again.
    expect(result.entropy?.streamBytes).toBe(5);
    expect(result.entropy?.totalBytes).toBe(9 + 6 + 5 + 9 + 1);
    expect(result.entropy?.nonStreamBytes).toBe(9 + 6 + 9 + 1);
  });

  it('reports null stream entropy when there are no streams', () => {
    const { result } = scan('1 0 obj << >> endobj\n');
    expect(result.entropy?.streamBytes).toBe(0);
    expect(result.entropy?.streamEntropy).toBeNull();
    expect(result.entropy?.totalEntropy).toBeGreaterThan(0);
  });

  it('computes maximal entropy for uniformly distributed bytes', () => {
    const everyByte = Array.from({ length: 256 }, (_, value) => value);
    const result = scanKeywords(bytes(everyByte, everyByte), DEFAULTS);
    expect(result.entropy.totalEntropy).toBeCloseTo(8, 10);
  });

  it('computes zero entropy for a single repeated byte', () => {
    const result = scanKeywords(bytes('aaaaaaaa'), DEFAULTS);
    expect(result.entropy.totalEntropy).toBe(0);
  });

  it('flags data that ends inside a stream', () => {
    const { result } = scan('1 0 obj << >> stream\nPARTIAL');
    expect(result.structure?.endedInsideStream).toBe(true);
    expect(result.messages.map((message) => message.code)).toContain('ended-inside-stream');
  });

  it('only toggles stream state on bare words', () => {
    const { result } = scan('/stream x /endstream ');
    expect(result.entropy?.streamBytes).toBe(0);
  });

  it('adds header bytes to entropy without tokenizing them', () => {
    const result = scanKeywords(bytes('obj obj'), { ...DEFAULTS, startOffset: 4 });
    expect(result.counts[0]).toBe(1);
    expect(result.entropy.totalBytes).toBe(7);
  });
});

describe('names, dates and limits', () => {
  it('lists non-keyword names sorted by code point with counts', () => {
    const { result } = scan('/Type /type /Type /JS /Kids /K#69ds ');
    expect(result.names.entries).toEqual([
      { name: '/Kids', count: 2, hexcodeCount: 1 },
      { name: '/Type', count: 2, hexcodeCount: 0 },
      { name: '/type', count: 1, hexcodeCount: 0 },
    ]);
  });

  it('stops collecting distinct names at the limit and counts the omissions', () => {
    const body = Array.from({ length: 10 }, (_, index) => `/N${index} /N0`).join(' ');
    const result = scanKeywords(bytes(body, ' '), { ...DEFAULTS, maxDistinctNames: 3 });
    expect(result.names.entries.map((entry) => entry.name)).toEqual(['/N0', '/N1', '/N2']);
    expect(result.names.entries[0]?.count).toBe(11); // "/N0 /N0" plus one per later pair
    expect(result.names.omitted).toBe(7);
  });

  it('omits names longer than the retained buffer and never matches them as keywords', () => {
    const { result, count } = scan(
      `/JavaScript${'x'.repeat(WORD_CAPACITY)} /${'A'.repeat(WORD_CAPACITY + 5)} `,
    );
    expect(count('/JavaScript')).toBe(0);
    expect(result.names.entries).toEqual([]);
    expect(result.names.omitted).toBe(2);
  });

  it('can skip name collection entirely', () => {
    const result = scanKeywords(bytes('/A /B /C '), { ...DEFAULTS, collectNames: false });
    expect(result.names).toEqual({ entries: [], omitted: 0 });
  });

  it('records dates with the preceding name and sorts them', () => {
    const { result } = scan("/ModDate (D:20240102000000) /CreationDate (D:20240101000000+01'00')");
    expect(result.dates.entries).toEqual([
      { value: "D:20240101000000+01'00", name: '/CreationDate' },
      { value: 'D:20240102000000', name: '/ModDate' },
    ]);
  });

  it('limits the number of dates retained', () => {
    const body = Array.from({ length: 5 }, () => '(D:20240101000000)').join(' ');
    const result = scanKeywords(bytes(body), { ...DEFAULTS, maxDates: 2 });
    expect(result.dates.entries).toHaveLength(2);
    expect(result.dates.omitted).toBe(3);
  });

  it('reports progress as bytes are processed', () => {
    const onProgress = vi.fn();
    scanKeywords(bytes('x '.repeat(5000)), {
      ...DEFAULTS,
      onProgress,
      progressIntervalBytes: 1000,
    });
    expect(onProgress).toHaveBeenCalledTimes(10);
    expect(onProgress.mock.calls.map(([processed]) => processed as number).at(-1)).toBe(10000);
  });
});
