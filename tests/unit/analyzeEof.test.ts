import { describe, expect, it } from 'vitest';
import { analyzeEof } from '../../src/features/pdf-analysis/engine/analyzeEof';
import { bytes } from '../fixtures/createTestPdf';

const eof = (...parts: Parameters<typeof bytes>) => analyzeEof(bytes(...parts));

describe('analyzeEof', () => {
  it('reports no marker and null trailing data for data without %%EOF', () => {
    expect(eof('%PDF-1.7\n1 0 obj')).toEqual({
      eofCount: 0,
      bytesAfterLastEof: null,
      trailingDataPresent: false,
      trailingDataWhitespaceOnly: null,
    });
  });

  it.each([
    ['%%EOF\n', 1, 0],
    ['%%EOF\r\n', 1, 0],
    ['%%EOF\r', 1, 0],
    ['%%EOF', 1, 0],
    ['%%EOF ', 1, 0],
    ['%%EOF\t', 1, 0],
    ['%%EOF \n', 1, 1],
    ['%%EOF\rX', 1, 1],
    ['%%EOF\nAPPENDED', 1, 8],
  ])('%j gives %i marker(s) and %i byte(s) after', (input, count, after) => {
    const result = eof(input);
    expect(result.eofCount).toBe(count);
    expect(result.bytesAfterLastEof).toBe(after);
  });

  it('counts multiple markers and measures after the last one', () => {
    const result = eof('a\n%%EOF\nb\n%%EOF\nTAIL');
    expect(result.eofCount).toBe(2);
    expect(result.bytesAfterLastEof).toBe(4);
    expect(result.trailingDataPresent).toBe(true);
    expect(result.trailingDataWhitespaceOnly).toBe(false);
  });

  it('distinguishes whitespace-only trailing data', () => {
    const result = eof('%%EOF\n\n \t', [0x00, 0x0c]);
    expect(result.bytesAfterLastEof).toBe(5);
    expect(result.trailingDataWhitespaceOnly).toBe(true);
  });

  it('requires a whitespace byte or the end of data after %%EOF', () => {
    expect(eof('%%EOFX\n').eofCount).toBe(0);
    expect(eof('%%EOF%%EOF\n').eofCount).toBe(0);
    expect(eof('%%eof\n').eofCount).toBe(0);
  });

  it('reproduces upstream state-machine quirks', () => {
    // A third % resets the token instead of restarting it.
    expect(eof('%%%EOF\n').eofCount).toBe(0);
    // After '%%EOF ' the next byte only resets the token, so the second marker is lost.
    expect(eof('%%EOF %%EOF\n').eofCount).toBe(1);
    expect(eof('%%EOF\r%%EOF\n').eofCount).toBe(1);
    expect(eof('%%EOF\n%%EOF\n').eofCount).toBe(2);
  });

  it('starts at the given offset', () => {
    expect(analyzeEof(bytes('%%EOF\nxx'), 1).eofCount).toBe(0);
    expect(analyzeEof(bytes('%%EOF\nxx'), 0).eofCount).toBe(1);
  });

  it('handles empty data', () => {
    expect(analyzeEof(new Uint8Array(0)).eofCount).toBe(0);
  });
});
