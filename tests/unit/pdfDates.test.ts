import { describe, expect, it } from 'vitest';
import { PdfDateParser } from '../../src/features/pdf-analysis/engine/pdfDates';

function datesIn(text: string): string[] {
  const parser = new PdfDateParser();
  const found: string[] = [];
  for (const character of text) {
    const date = parser.feed(character.charCodeAt(0));
    if (date !== null) {
      found.push(date);
    }
  }
  return found;
}

describe('PdfDateParser', () => {
  it('extracts dates with and without a time zone', () => {
    expect(datesIn("(D:20240101120000+01'00')")).toEqual(["D:20240101120000+01'00"]);
    expect(datesIn("(D:20240101120000-05'30')")).toEqual(["D:20240101120000-05'30"]);
    expect(datesIn('(D:20240101120000)')).toEqual(['D:20240101120000']);
    expect(datesIn('"D:20240101120000"')).toEqual(['D:20240101120000']);
  });

  it('requires exactly 14 digits', () => {
    expect(datesIn('(D:2024010112)')).toEqual([]);
    expect(datesIn('(D:202401011200001)')).toEqual([]);
  });

  it('drops dates whose time zone is incomplete, as upstream does', () => {
    expect(datesIn('(D:20240101120000Z)')).toEqual([]);
    expect(datesIn('(D:20240101120000+01)')).toEqual([]);
    expect(datesIn("(D:20240101120000+01'0)")).toEqual([]);
    expect(datesIn("(D:20240101120000Z00'00')")).toEqual(["D:20240101120000Z00'00"]);
  });

  it('restarts on D in any state', () => {
    expect(datesIn('D:2024DD:20240105150000)')).toEqual(['D:20240105150000']);
    expect(datesIn('D:20240101120000D')).toEqual([]);
  });

  it('requires the colon right after D', () => {
    expect(datesIn('D 20240101120000)')).toEqual([]);
    expect(datesIn('Date:20240101120000)')).toEqual([]);
  });

  it('finds several dates in sequence', () => {
    expect(datesIn('D:20240101000000 D:20250101000000 ')).toEqual([
      'D:20240101000000',
      'D:20250101000000',
    ]);
  });
});
