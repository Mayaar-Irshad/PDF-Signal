import { describe, expect, it } from 'vitest';
import {
  DEFAULT_PARSE_LIMITS,
  dictGet,
  findNextObjectHeader,
  indexFileObjects,
  integerOf,
  nameOf,
  parseObjectStream,
  parseValue,
  PdfLexer,
  type PdfValue,
} from '../../src/features/pdf-analysis/engine/pdfObjects';
import { bytes, compress, createTestPdf } from '../fixtures/createTestPdf';

const parse = (text: string, limits = DEFAULT_PARSE_LIMITS): PdfValue | null =>
  parseValue(new PdfLexer(bytes(text), 0, undefined, limits), limits);

const text = (value: PdfValue | null | undefined): string =>
  value?.type === 'string' ? String.fromCharCode(...value.value) : '';

describe('PDF value parser', () => {
  it('parses dictionaries, arrays, numbers, booleans, null and references', () => {
    const value = parse(
      '<< /Type /Catalog /Count 3 /Ratio -1.5 /Kids [1 0 R 2 0 R] /Open true /X null /Pages 12 0 R >>',
    );
    expect(nameOf(dictGet(value ?? undefined, 'Type'))).toBe('Catalog');
    expect(integerOf(dictGet(value ?? undefined, 'Count'))).toBe(3);
    expect(dictGet(value ?? undefined, 'Ratio')).toEqual({ type: 'number', value: -1.5 });
    expect(dictGet(value ?? undefined, 'Kids')).toEqual({
      type: 'array',
      items: [
        { type: 'ref', number: 1, generation: 0 },
        { type: 'ref', number: 2, generation: 0 },
      ],
    });
    expect(dictGet(value ?? undefined, 'Open')).toEqual({ type: 'boolean', value: true });
    expect(dictGet(value ?? undefined, 'X')).toEqual({ type: 'null' });
    expect(dictGet(value ?? undefined, 'Pages')).toEqual({
      type: 'ref',
      number: 12,
      generation: 0,
    });
  });

  it('decodes #xx escapes in names, following PDF syntax', () => {
    expect(nameOf(parse('/Java#53cript') ?? undefined)).toBe('JavaScript');
    expect(nameOf(parse('/#4A#53') ?? undefined)).toBe('JS');
    // Unlike PDFiD's tokenizer, PDF syntax keeps regular characters such as "_" in the name.
    expect(nameOf(parse('/JS_x') ?? undefined)).toBe('JS_x');
    expect(nameOf(parse('/A#ZZ') ?? undefined)).toBe('A#ZZ');
  });

  it('decodes literal string escapes and balanced parentheses', () => {
    expect(text(parse('(a\\nb\\t\\(c\\)\\\\)'))).toBe('a\nb\t(c)\\');
    expect(text(parse('(\\101\\102C\\7)'))).toBe('ABC\u0007');
    expect(text(parse('(app.alert(1);)'))).toBe('app.alert(1);');
    expect(text(parse('(line\\\ncontinued)'))).toBe('linecontinued');
    expect(text(parse('(unknown \\q escape)'))).toBe('unknown q escape');
  });

  it('decodes hex strings, ignoring whitespace and padding odd digits', () => {
    expect(text(parse('<48 65 6c 6C 6f>'))).toBe('Hello');
    expect(text(parse('<414>'))).toBe('A@');
  });

  it('skips comments', () => {
    expect(nameOf(dictGet(parse('<< % comment /Fake /Bad\n /S /URI >>') ?? undefined, 'S'))).toBe(
      'URI',
    );
  });

  it('survives malformed input without throwing', () => {
    expect(parse('<< /A (unterminated')).toMatchObject({ type: 'dict' });
    expect(parse('<< /A [1 2 /B >>')).toMatchObject({ type: 'dict' });
    expect(parse('<< 12 /Key /Value >>')).toMatchObject({ type: 'dict' });
    expect(parse('')).toBeNull();
    expect(parse('<< /A >> ')).toEqual({ type: 'dict', entries: new Map() });
    expect(parse(')')).toEqual({ type: 'keyword', value: ')' });
  });

  it('stops at object boundaries', () => {
    const lexer = new PdfLexer(bytes('<< /Length 3 >> stream\nabc'));
    expect(parseValue(lexer)).toMatchObject({ type: 'dict' });
    expect(lexer.next()).toMatchObject({ kind: 'keyword', value: 'stream' });
  });

  it('enforces depth, size and token limits', () => {
    const deep = parse('['.repeat(200) + ']'.repeat(200), { ...DEFAULT_PARSE_LIMITS, maxDepth: 8 });
    expect(deep).toMatchObject({ type: 'array' });
    const long = parse(`(${'x'.repeat(5000)})`, { ...DEFAULT_PARSE_LIMITS, maxStringBytes: 100 });
    expect(text(long)).toHaveLength(100);
    const many = parse(`[${'1 '.repeat(5000)}]`, { ...DEFAULT_PARSE_LIMITS, maxTokens: 50 });
    expect(many?.type === 'array' && many.items.length).toBeLessThan(50);
  });
});

describe('object indexing', () => {
  it('finds object headers and ignores endobj and partial words', () => {
    expect(findNextObjectHeader(bytes('12 0 obj'), 0)).toEqual({
      number: 12,
      generation: 0,
      bodyStart: 8,
    });
    expect(findNextObjectHeader(bytes('x\r\n3 2\tobj<<>>'), 0)).toMatchObject({
      number: 3,
      generation: 2,
    });
    expect(findNextObjectHeader(bytes('endobj objx 12 0objx'), 0)).toBeNull();
    // Readers reach objects by offset, so a letter right before the number does not hide one.
    expect(findNextObjectHeader(bytes('X4 0 obj'), 0)).toMatchObject({ number: 4, generation: 0 });
  });

  it('indexes objects and stream data from a real file layout', () => {
    const pdf = createTestPdf({
      objects: [
        { body: '<< /Type /Catalog >>' },
        { body: '<< /Length 11 >>', stream: 'hello world' },
      ],
    });
    const { definitions, truncated } = indexFileObjects(pdf, { maxObjects: 100 });
    expect(truncated).toBe(false);
    expect(definitions.map((object) => object.number)).toEqual([1, 2]);
    const stream = definitions[1]?.stream;
    expect(stream).not.toBeNull();
    expect(String.fromCharCode(...pdf.subarray(stream!.dataStart, stream!.dataEnd))).toBe(
      'hello world',
    );
  });

  it('falls back to searching for endstream when /Length is wrong or indirect', () => {
    for (const length of ['999', '5 0 R', '2']) {
      const pdf = createTestPdf({
        objects: [{ body: `<< /Length ${length} >>`, stream: 'abcdef' }],
      });
      const stream = indexFileObjects(pdf, { maxObjects: 10 }).definitions[0]?.stream;
      expect(String.fromCharCode(...pdf.subarray(stream!.dataStart, stream!.dataEnd))).toBe(
        'abcdef',
      );
    }
  });

  it('does not index fake object headers inside stream data', () => {
    const pdf = createTestPdf({
      objects: [{ body: '<< /Length 21 >>', stream: '\n9 0 obj << /S /JS >>' }],
    });
    expect(
      indexFileObjects(pdf, { maxObjects: 10 }).definitions.map((object) => object.number),
    ).toEqual([1]);
  });

  it('keeps every definition of an object number (incremental updates, decoys)', () => {
    const pdf = bytes('1 0 obj << /V 1 >> endobj\n1 0 obj << /V 2 >> endobj');
    const values = indexFileObjects(pdf, { maxObjects: 10 }).definitions.map((object) =>
      integerOf(dictGet(object.value, 'V')),
    );
    expect(values).toEqual([1, 2]);
  });

  it('keeps indexing after an object that never ends', () => {
    const pdf = bytes(
      '1 0 obj << /Title (unterminated >>\nendobj\n2 0 obj << /S /JavaScript >> endobj',
    );
    expect(
      indexFileObjects(pdf, { maxObjects: 10 }).definitions.map((object) => object.number),
    ).toEqual([1, 2]);
  });

  it('counts objects that hit the token limit and keeps going', () => {
    const pdf = bytes(`1 0 obj [${'1 '.repeat(500)}] endobj\n2 0 obj << /S /JavaScript >> endobj`);
    const index = indexFileObjects(pdf, {
      maxObjects: 10,
      limits: { ...DEFAULT_PARSE_LIMITS, maxTokens: 100 },
    });
    expect(index.oversized).toBe(1);
    expect(index.definitions.map((object) => object.number)).toContain(2);
  });

  it('stops when the shared token budget or the deadline runs out', () => {
    const pdf = bytes(
      Array.from({ length: 50 }, (_, index) => `${index + 1} 0 obj [1 2 3] endobj\n`).join(''),
    );
    expect(indexFileObjects(pdf, { maxObjects: 100, budget: { remaining: 20 } }).stopped).toBe(
      true,
    );
    expect(indexFileObjects(pdf, { maxObjects: 100, shouldStop: () => true }).stopped).toBe(true);
  });

  it('stops at the object limit', () => {
    const pdf = bytes(
      Array.from({ length: 20 }, (_, index) => `${index + 1} 0 obj null endobj\n`).join(''),
    );
    const index = indexFileObjects(pdf, { maxObjects: 5 });
    expect(index.truncated).toBe(true);
    expect(index.definitions).toHaveLength(5);
  });

  it('handles a truncated stream at the end of the data', () => {
    const data = bytes('1 0 obj << /Length 100 >> stream\nabc');
    const stream = indexFileObjects(data, { maxObjects: 10 }).definitions[0]?.stream;
    expect(stream).toMatchObject({ dataEnd: data.length });
    expect(String.fromCharCode(...data.subarray(stream!.dataStart, stream!.dataEnd))).toBe('abc');
  });
});

describe('object streams', () => {
  const dict = (n: number, first: number) => parse(`<< /Type /ObjStm /N ${n} /First ${first} >>`)!;

  it('parses the objects listed in the header', () => {
    const header = '10 0 11 20 ';
    const content = '<< /Type /Catalog >>' + '(stored string)';
    const objects = parseObjectStream(bytes(header, content), dict(2, header.length), 100);
    expect(objects.map((object) => object.number)).toEqual([10, 11]);
    expect(objects.every((object) => object.source === 'object-stream')).toBe(true);
    expect(text(objects[1]?.value)).toBe('stored string');
  });

  it('ignores invalid headers and out-of-range offsets', () => {
    expect(parseObjectStream(bytes('1 0 '), dict(1, 999), 10)).toEqual([]);
    expect(parseObjectStream(bytes('x'), parse('<< /N 1 >>')!, 10)).toEqual([]);
    const header = '1 500 2 0 ';
    expect(
      parseObjectStream(bytes(header, 'null'), dict(2, header.length), 10).map(
        (object) => object.number,
      ),
    ).toEqual([2]);
  });

  it('parses repeated offsets once and shares a token budget', () => {
    const entries = Array.from({ length: 200 }, (_, index) => `${index + 1} 0`).join(' ') + ' ';
    const content = `[${'1 '.repeat(1000)}]`;
    const budget = { remaining: 5000 };
    const started = Date.now();
    const objects = parseObjectStream(
      bytes(entries, content),
      dict(200, entries.length),
      1000,
      DEFAULT_PARSE_LIMITS,
      budget,
    );
    expect(objects).toHaveLength(200);
    expect(budget.remaining).toBeGreaterThan(3000);
    expect(Date.now() - started).toBeLessThan(500);
  });

  it('accepts references written without a space before R', () => {
    expect(parse('<< /OpenAction 4 0R >>')).toMatchObject({
      entries: new Map([['OpenAction', { type: 'ref', number: 4, generation: 0 }]]),
    });
  });

  it('respects the object limit', () => {
    const header = '1 0 2 2 3 4 ';
    expect(parseObjectStream(bytes(header, '1 2 3 '), dict(3, header.length), 2)).toHaveLength(2);
  });

  it('works on data produced by the fixture builder', () => {
    expect(compress('x').length).toBeGreaterThan(0);
  });
});
