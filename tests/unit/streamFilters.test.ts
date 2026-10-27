import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseValue, PdfLexer } from '../../src/features/pdf-analysis/engine/pdfObjects';
import {
  decodeAscii85,
  decodeAsciiHex,
  decodeRunLength,
  decodeStream,
  filtersOf,
  inflateBounded,
} from '../../src/features/pdf-analysis/engine/streamFilters';
import { bytes, compress } from '../fixtures/createTestPdf';

const ascii = (data: Uint8Array) => String.fromCharCode(...data);
const value = (text: string) => parseValue(new PdfLexer(bytes(text))) ?? undefined;

describe('filtersOf', () => {
  it('reads single names, arrays and abbreviations', () => {
    expect(filtersOf(value('/FlateDecode'))).toEqual(['FlateDecode']);
    expect(filtersOf(value('[/AHx /Fl]'))).toEqual(['ASCIIHexDecode', 'FlateDecode']);
    expect(filtersOf(value('/Fl#61teDecode'))).toEqual(['FlateDecode']);
    expect(filtersOf(undefined)).toEqual([]);
    expect(filtersOf(value('[/A85 1 (x) /RL]'))).toEqual(['ASCII85Decode', 'RunLengthDecode']);
  });
});

describe('inflateBounded', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('inflates zlib data', async () => {
    const result = await inflateBounded(compress('hello, compressed world'), 1024);
    expect(result).toMatchObject({ status: 'ok' });
    expect(ascii(result.bytes)).toBe('hello, compressed world');
  });

  it('stops a decompression bomb at the output cap', async () => {
    const bomb = compress(new Uint8Array(4 * 1024 * 1024));
    expect(bomb.length).toBeLessThan(10_000);
    const result = await inflateBounded(bomb, 64 * 1024);
    expect(result.status).toBe('truncated');
    expect(result.bytes.length).toBe(64 * 1024);
  });

  it('reports corrupt data as failed and keeps output decoded before trailing garbage', async () => {
    expect((await inflateBounded(bytes('not zlib data at all'), 1024)).status).toBe('failed');
    const withGarbage = await inflateBounded(bytes(compress('payload'), 'GARBAGE'), 1024);
    expect(['partial', 'ok']).toContain(withGarbage.status);
    expect(ascii(withGarbage.bytes)).toBe('payload');
    const truncated = compress('x'.repeat(10_000)).subarray(0, 20);
    expect(['partial', 'failed']).toContain((await inflateBounded(truncated, 1 << 20)).status);
  });

  it('reports unsupported when the browser lacks DecompressionStream', async () => {
    vi.stubGlobal('DecompressionStream', undefined);
    expect(await inflateBounded(compress('x'), 10)).toEqual({
      bytes: new Uint8Array(0),
      status: 'unsupported',
    });
  });
});

describe('simple filters', () => {
  it('decodes ASCIIHex', () => {
    expect(ascii(decodeAsciiHex(bytes('48 65 6C6c 6f>ignored'), 100).bytes)).toBe('Hello');
    expect(ascii(decodeAsciiHex(bytes('414'), 100).bytes)).toBe('A@');
    expect(decodeAsciiHex(bytes('41ZZ'), 100)).toMatchObject({ status: 'partial' });
    expect(decodeAsciiHex(bytes('414243'), 2)).toMatchObject({ status: 'truncated' });
  });

  it('decodes ASCII85 (vectors from Python base64.a85encode)', () => {
    expect(ascii(decodeAscii85(bytes('87cURD_*#-6q/:tBkM<lC`r~>'), 100).bytes)).toBe(
      'Hello, PDF Signal!',
    );
    expect(Array.from(decodeAscii85(bytes('z@:B~>'), 100).bytes)).toEqual([0, 0, 0, 0, 0x61, 0x62]);
    expect(decodeAscii85(bytes('87cÿURD'), 100)).toMatchObject({ status: 'partial' });
    expect(decodeAscii85(bytes('87cURD_*#-'), 3)).toMatchObject({ status: 'truncated' });
  });

  it('decodes RunLength', () => {
    expect(ascii(decodeRunLength(bytes([2], 'abc', [254], 'x', [128], 'ignored'), 100).bytes)).toBe(
      'abcxxx',
    );
    expect(decodeRunLength(bytes([129], 'z'), 10)).toMatchObject({ status: 'truncated' });
  });
});

describe('decodeStream', () => {
  it('applies filter chains in order', async () => {
    const hex = Array.from(compress('chained'), (byte) => byte.toString(16).padStart(2, '0')).join(
      '',
    );
    const result = await decodeStream(bytes(hex, '>'), ['ASCIIHexDecode', 'FlateDecode'], 1000);
    expect(result.status).toBe('ok');
    expect(ascii(result.bytes)).toBe('chained');
  });

  it('passes through data without filters', async () => {
    expect(ascii((await decodeStream(bytes('plain'), [], 100)).bytes)).toBe('plain');
    expect((await decodeStream(bytes('plain text'), [], 5)).status).toBe('truncated');
  });

  it('refuses image and unsupported filters', async () => {
    for (const filter of ['DCTDecode', 'LZWDecode', 'JBIG2Decode', 'Crypt']) {
      expect((await decodeStream(bytes('x'), [filter], 100)).status).toBe('unsupported');
    }
  });

  it('propagates a partial status through the chain', async () => {
    const result = await decodeStream(bytes('41ZZ'), ['ASCIIHexDecode', 'RunLengthDecode'], 100);
    expect(result.status).toBe('partial');
  });
});
