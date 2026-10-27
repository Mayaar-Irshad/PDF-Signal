import { describe, expect, it } from 'vitest';
import {
  analyzePdfHeader,
  findPdfSignature,
} from '../../src/features/pdf-analysis/engine/analyzePdfHeader';
import { bytes } from '../fixtures/createTestPdf';

describe('analyzePdfHeader', () => {
  it('finds a standard header and extracts the version', () => {
    expect(analyzePdfHeader(bytes('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj'))).toEqual({
      found: true,
      offset: 0,
      text: '%PDF-1.7',
      version: '1.7',
      versionRecognized: true,
      scanStartOffset: 8,
      pdfidWouldError: false,
    });
  });

  it.each(['1.0', '1.4', '1.7', '2.0'])('recognizes version %s', (version) => {
    const header = analyzePdfHeader(bytes(`%PDF-${version}\r\n`));
    expect(header.version).toBe(version);
    expect(header.versionRecognized).toBe(true);
    expect(header.scanStartOffset).toBe(8);
  });

  it('ends the header at CR as well as LF', () => {
    expect(analyzePdfHeader(bytes('%PDF-1.5\rrest')).scanStartOffset).toBe(8);
  });

  it('reports an unpublished version without inventing a valid one', () => {
    const header = analyzePdfHeader(bytes('%PDF-1.9\n'));
    expect(header.version).toBe('1.9');
    expect(header.versionRecognized).toBe(false);
  });

  it('reports a missing version as null', () => {
    const header = analyzePdfHeader(bytes('%PDF-X.Y\n'));
    expect(header.found).toBe(true);
    expect(header.version).toBeNull();
    expect(header.versionRecognized).toBe(false);
    expect(analyzePdfHeader(bytes('%PDF\n')).version).toBeNull();
  });

  it('finds a header after junk within the first 1024 bytes', () => {
    const header = analyzePdfHeader(bytes('JUNK\n%PDF-1.4\n'));
    expect(header.offset).toBe(5);
    expect(header.scanStartOffset).toBe(13);
  });

  it('accepts a signature that ends exactly at byte 1024', () => {
    const header = analyzePdfHeader(bytes('x'.repeat(1020), '%PDF-1.4\n'));
    expect(header.found).toBe(true);
    expect(header.offset).toBe(1020);
  });

  it('ignores a signature that starts within but extends beyond the first 1024 bytes', () => {
    expect(analyzePdfHeader(bytes('x'.repeat(1021), '%PDF-1.4\n')).found).toBe(false);
  });

  it('ignores a signature beyond the first 1024 bytes', () => {
    const header = analyzePdfHeader(bytes('x'.repeat(1100), '%PDF-1.4\n'));
    expect(header).toMatchObject({
      found: false,
      offset: null,
      text: null,
      version: null,
      scanStartOffset: 0,
    });
  });

  it('reports a missing header for empty and non-PDF data', () => {
    expect(analyzePdfHeader(new Uint8Array(0)).found).toBe(false);
    expect(analyzePdfHeader(bytes('PK\x03\x04 not a pdf')).found).toBe(false);
    expect(analyzePdfHeader(bytes('%pdf-1.7\n')).found).toBe(false);
  });

  it('uses 13 header bytes and shows 10 when no line break follows', () => {
    const header = analyzePdfHeader(bytes('%PDF-1.4 obj /JS endobj'));
    expect(header.text).toBe('%PDF-1.4 o');
    expect(header.scanStartOffset).toBe(13);
    expect(header.pdfidWouldError).toBe(false);
  });

  it('escapes control and non-ASCII bytes in the displayed header', () => {
    expect(analyzePdfHeader(bytes('%PDF-1.4\t', [0x00, 0xe9], '\\\n')).text).toBe(
      '%PDF-1.4\\t\\x00',
    );
    expect(analyzePdfHeader(bytes('%PDF', [0xe9], '\\\n')).text).toBe('%PDF\\xe9\\\\');
  });

  it('handles truncated headers that would make pdfid.py fail', () => {
    const header = analyzePdfHeader(bytes('%PDF-1.4'));
    expect(header).toMatchObject({
      found: true,
      text: '%PDF-1.4',
      version: '1.4',
      scanStartOffset: 8,
    });
    expect(header.pdfidWouldError).toBe(true);
    expect(analyzePdfHeader(bytes('%PDF')).scanStartOffset).toBe(4);
  });

  it('flags a header line crossing the 1024-byte window', () => {
    const header = analyzePdfHeader(bytes('x'.repeat(1016), '%PDF-1.4 more data here\n'));
    expect(header.found).toBe(true);
    expect(header.pdfidWouldError).toBe(true);
    expect(header.scanStartOffset).toBe(1016 + 13);
  });
});

describe('findPdfSignature', () => {
  it('returns the offset of the first signature', () => {
    expect(findPdfSignature(bytes('ab%PDF %PDF'))).toBe(2);
    expect(findPdfSignature(bytes('%PD'))).toBe(-1);
  });
});
