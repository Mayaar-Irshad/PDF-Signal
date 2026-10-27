import { describe, expect, it } from 'vitest';
import {
  decodeHexEscapeAt,
  formatNameForDisplay,
} from '../../src/features/pdf-analysis/engine/decodePdfNames';
import { bytes } from '../fixtures/createTestPdf';

describe('decodeHexEscapeAt', () => {
  it('decodes two hexadecimal digits after #', () => {
    expect(decodeHexEscapeAt(bytes('#41'), 0)).toBe(0x41);
    expect(decodeHexEscapeAt(bytes('/Open#41ction'), 5)).toBe(0x41);
    expect(decodeHexEscapeAt(bytes('#ff'), 0)).toBe(0xff);
    expect(decodeHexEscapeAt(bytes('#Ff'), 0)).toBe(0xff);
    expect(decodeHexEscapeAt(bytes('#00'), 0)).toBe(0);
  });

  it('rejects escapes with non-hexadecimal digits', () => {
    expect(decodeHexEscapeAt(bytes('#G1'), 0)).toBe(-1);
    expect(decodeHexEscapeAt(bytes('#1G'), 0)).toBe(-1);
    expect(decodeHexEscapeAt(bytes('# 1'), 0)).toBe(-1);
    expect(decodeHexEscapeAt(bytes('#', [0xc1], '1'), 0)).toBe(-1);
  });

  it('rejects escapes truncated by the end of the data', () => {
    expect(decodeHexEscapeAt(bytes('#'), 0)).toBe(-1);
    expect(decodeHexEscapeAt(bytes('#4'), 0)).toBe(-1);
  });

  it('only decodes at a # byte', () => {
    expect(decodeHexEscapeAt(bytes('A41'), 0)).toBe(-1);
    expect(decodeHexEscapeAt(bytes('#41'), 5)).toBe(-1);
  });
});

describe('formatNameForDisplay', () => {
  it('leaves ordinary names unchanged', () => {
    expect(formatNameForDisplay('/JavaScript')).toBe('/JavaScript');
    expect(formatNameForDisplay('/A1.b_c-d')).toBe('/A1.b_c-d');
  });

  it('re-escapes whitespace, control characters and non-ASCII bytes', () => {
    expect(formatNameForDisplay('/Java Script')).toBe('/Java#20Script');
    expect(formatNameForDisplay('/J\u0000S')).toBe('/J#00S');
    expect(formatNameForDisplay('/A\u001b[31m')).toBe('/A#1b#5b31m');
    expect(formatNameForDisplay('/café')).toBe('/caf#e9');
  });

  it('escapes # and PDF delimiters so the display is unambiguous', () => {
    expect(formatNameForDisplay('/A#B')).toBe('/A#23B');
    expect(formatNameForDisplay('/Java/Script')).toBe('/Java#2fScript');
    expect(formatNameForDisplay('/<script>')).toBe('/#3cscript#3e');
    expect(formatNameForDisplay('/a(b)c[d]{e}%')).toBe('/a#28b#29c#5bd#5d#7be#7d#25');
  });

  it('handles empty and slash-only input', () => {
    expect(formatNameForDisplay('')).toBe('');
    expect(formatNameForDisplay('/')).toBe('/');
  });
});
