import { describe, expect, it } from 'vitest';
import {
  formatBytes,
  inspectSignature,
  readBlobBytes,
  sanitizeFileName,
  validateFileMetadata,
  validatePdfFile,
} from '../../src/features/pdf-analysis/validation/validatePdfFile';
import { VALIDATION_RULES } from '../../src/features/pdf-analysis/validation/validationRules';
import { BASIC_OBJECTS, bytes, createTestPdf } from '../fixtures/createTestPdf';

const MB = 1024 * 1024;
const codes = (issues: readonly { code: string }[]) => issues.map((issue) => issue.code);

function fileWithSize(name: string, size: number, type = 'application/pdf'): File {
  const file = new File([bytes('%PDF-1.7\n')], name, { type });
  Object.defineProperty(file, 'size', { value: size });
  return file;
}

describe('validateFileMetadata', () => {
  it('uses a 10 MB default limit', () => {
    expect(VALIDATION_RULES.maxFileSizeBytes).toBe(10 * MB);
  });

  it('accepts a normal PDF without issues', () => {
    expect(
      validateFileMetadata({ name: 'report.pdf', size: 1000, type: 'application/pdf' }),
    ).toEqual([]);
  });

  it('rejects zero-byte files', () => {
    const issues = validateFileMetadata({ name: 'empty.pdf', size: 0, type: 'application/pdf' });
    expect(codes(issues)).toEqual(['empty-file']);
    expect(issues[0]?.severity).toBe('error');
    expect(issues[0]?.guidance).not.toBe('');
  });

  it('rejects files above the limit and accepts files at the limit', () => {
    const over = validateFileMetadata({
      name: 'big.pdf',
      size: 10 * MB + 1,
      type: 'application/pdf',
    });
    expect(codes(over)).toEqual(['file-too-large']);
    expect(over[0]?.message).toContain('10 MB');
    expect(
      validateFileMetadata({ name: 'max.pdf', size: 10 * MB, type: 'application/pdf' }),
    ).toEqual([]);
  });

  it('rejects impossible sizes', () => {
    for (const size of [-1, Number.NaN, 1.5, Number.POSITIVE_INFINITY]) {
      expect(codes(validateFileMetadata({ name: 'x.pdf', size, type: '' }))).toEqual([
        'invalid-size',
      ]);
    }
  });

  it('only warns about misleading extensions', () => {
    for (const name of ['invoice.pdf.exe', 'document', 'scan.PDF.txt']) {
      const issues = validateFileMetadata({ name, size: 10, type: 'application/pdf' });
      expect(codes(issues)).toEqual(['extension-mismatch']);
      expect(issues[0]?.severity).toBe('warning');
    }
    expect(validateFileMetadata({ name: 'UPPER.PDF', size: 10, type: 'application/pdf' })).toEqual(
      [],
    );
  });

  it('only warns about unexpected MIME types and tolerates an empty type', () => {
    const issues = validateFileMetadata({
      name: 'a.pdf',
      size: 10,
      type: 'application/x-msdownload',
    });
    expect(codes(issues)).toEqual(['mime-mismatch']);
    expect(issues[0]?.severity).toBe('warning');
    expect(validateFileMetadata({ name: 'a.pdf', size: 10, type: '' })).toEqual([]);
    expect(validateFileMetadata({ name: 'a.pdf', size: 10, type: 'application/x-pdf' })).toEqual(
      [],
    );
  });

  it('never echoes the untrusted file name into messages', () => {
    const name = '<img src=x onerror=alert(1)>.exe';
    const issues = validateFileMetadata({ name, size: 0, type: 'text/html' });
    for (const issue of issues) {
      expect(issue.message + issue.guidance).not.toContain('<img');
    }
  });
});

describe('inspectSignature', () => {
  it('accepts a header at byte 0', () => {
    expect(inspectSignature(bytes('%PDF-1.7\n'))).toEqual([]);
  });

  it('warns about a header after other data', () => {
    expect(codes(inspectSignature(bytes('junk%PDF-1.7')))).toEqual(['signature-offset']);
  });

  it('flags missing signatures, including lowercase and partial ones', () => {
    for (const head of ['', 'PK\u0003\u0004', '%pdf-1.7', '%PD', 'MZ\u0090\u0000']) {
      expect(codes(inspectSignature(bytes(head)))).toEqual(['signature-missing']);
    }
  });
});

describe('sanitizeFileName', () => {
  it('keeps markup-like names as plain text for React to escape', () => {
    expect(sanitizeFileName('<script>alert(1)</script>.pdf')).toBe('<script>alert(1)</script>.pdf');
  });

  it('removes control, bidirectional and zero-width characters', () => {
    expect(sanitizeFileName('invoice\u202Efdp.exe')).toBe('invoicefdp.exe');
    expect(sanitizeFileName('a\u0000b\u0007c\u001b[31m.pdf')).toBe('abc[31m.pdf');
    expect(sanitizeFileName('zero\u200Bwidth\uFEFF.pdf')).toBe('zerowidth.pdf');
    expect(sanitizeFileName('line\u2028break.pdf')).toBe('linebreak.pdf');
  });

  it('collapses whitespace and normalizes Unicode', () => {
    expect(sanitizeFileName('  two\t\nwords  .pdf ')).toBe('two words .pdf');
    expect(sanitizeFileName('Résumé.pdf')).toBe('Résumé.pdf');
  });

  it('keeps path separators as text', () => {
    expect(sanitizeFileName('../../etc/passwd')).toBe('../../etc/passwd');
  });

  it('truncates long names without splitting surrogate pairs', () => {
    const long = `${'😀'.repeat(300)}.pdf`;
    const result = sanitizeFileName(long, 10);
    expect(Array.from(result)).toHaveLength(10);
    expect(result.endsWith('…')).toBe(true);
    expect(result).not.toMatch(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/);
    expect(Array.from(sanitizeFileName('x'.repeat(1000)))).toHaveLength(
      VALIDATION_RULES.maxFileNameLength,
    );
  });

  it('falls back for empty or invalid names', () => {
    expect(sanitizeFileName('')).toBe('Unnamed file');
    expect(sanitizeFileName('\u0000\u202E')).toBe('Unnamed file');
    expect(sanitizeFileName(undefined)).toBe('Unnamed file');
    expect(sanitizeFileName(42)).toBe('Unnamed file');
  });
});

describe('formatBytes', () => {
  it.each([
    [0, '0 bytes'],
    [1, '1 byte'],
    [1023, '1023 bytes'],
    [1024, '1.0 KB'],
    [10 * MB, '10 MB'],
    [-1, 'unknown size'],
  ])('%i → %s', (size, expected) => {
    expect(formatBytes(size)).toBe(expected);
  });
});

describe('validatePdfFile', () => {
  it('accepts a real PDF', async () => {
    const file = new File([createTestPdf({ objects: BASIC_OBJECTS })], 'ok.pdf', {
      type: 'application/pdf',
    });
    await expect(validatePdfFile(file)).resolves.toEqual({
      canScan: true,
      requiresForce: false,
      issues: [],
    });
  });

  it('accepts PDF content behind a misleading name and type, with warnings', async () => {
    const file = new File([createTestPdf({ objects: BASIC_OBJECTS })], 'photo.jpg', {
      type: 'image/jpeg',
    });
    const result = await validatePdfFile(file);
    expect(result.canScan).toBe(true);
    expect(result.requiresForce).toBe(false);
    expect(codes(result.issues)).toEqual(['extension-mismatch', 'mime-mismatch']);
  });

  it('requires confirmation for content without a PDF signature, even when named .pdf', async () => {
    const file = new File([bytes('<html><script>alert(1)</script></html>')], 'fake.pdf', {
      type: 'application/pdf',
    });
    const result = await validatePdfFile(file);
    expect(result).toMatchObject({ canScan: true, requiresForce: true });
    expect(codes(result.issues)).toContain('signature-missing');
  });

  it('rejects empty and oversized files without reading them', async () => {
    await expect(validatePdfFile(new File([], 'empty.pdf'))).resolves.toMatchObject({
      canScan: false,
    });
    const big = fileWithSize('big.pdf', 50 * MB);
    const result = await validatePdfFile(big);
    expect(result.canScan).toBe(false);
    expect(codes(result.issues)).toEqual(['file-too-large']);
  });

  it('reports unreadable files', async () => {
    const file = new File([bytes('%PDF-1.7')], 'gone.pdf');
    Object.defineProperty(file, 'slice', {
      value: () => ({ arrayBuffer: () => Promise.reject(new Error('NotReadableError')) }),
    });
    const result = await validatePdfFile(file);
    expect(result.canScan).toBe(false);
    expect(codes(result.issues)).toContain('read-failed');
  });

  it('reads only the first 1024 bytes for the signature check', async () => {
    const file = new File([bytes('%PDF-1.7\n', 'x'.repeat(5000))], 'a.pdf');
    let requestedEnd = -1;
    const originalSlice = file.slice.bind(file);
    Object.defineProperty(file, 'slice', {
      value: (start?: number, end?: number) => {
        requestedEnd = end ?? -1;
        return originalSlice(start, end);
      },
    });
    await validatePdfFile(file);
    expect(requestedEnd).toBe(1024);
  });
});

describe('readBlobBytes', () => {
  it('reads a byte range exactly, including non-UTF-8 bytes', async () => {
    const blob = new Blob([bytes([0xff, 0xfe, 0x00, 0x80, 0x41])]);
    expect(Array.from(await readBlobBytes(blob, 1, 4))).toEqual([0xfe, 0x00, 0x80]);
  });
});
