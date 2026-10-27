import type { BoundedList, EntropyStatistics, NameCount, PdfDateEntry } from '../types/analysis';
import { BYTE, isAlphanumericByte, latin1FromBytes } from './byteUtils';
import { decodeHexEscapeAt, formatNameForDisplay } from './decodePdfNames';
import { EntropyAccumulator } from './entropy';
import { PdfDateParser } from './pdfDates';
import { COLORS_THRESHOLD, MAX_KEYWORD_WORD_LENGTH, PDFID_KEYWORDS } from './pdfidKeywords';

/**
 * Bytes of the current word that are retained. PDFiD keeps whole words in memory; PDF Signal
 * keeps a bounded prefix, which is enough to match every keyword (at most 12 characters) and
 * prevents a hostile file from forcing unbounded string growth. The full word length is still
 * tracked, so over-long words can never be mistaken for keywords.
 */
export const WORD_CAPACITY = 256;

/** Byte values Python's `str.isdigit()` accepts besides 0–9: ², ³ and ¹ (Latin-1). */
const PYTHON_ONLY_DIGITS = new Set([0xb2, 0xb3, 0xb9]);

const COLORS_NAME = 'Colors';

export interface KeywordScanOptions {
  /** First byte to tokenize; earlier bytes (the PDF header) only contribute to entropy. */
  readonly startOffset: number;
  /** Collect every other PDF name, like `pdfid.py --all`. */
  readonly collectNames: boolean;
  readonly maxDistinctNames: number;
  readonly maxDates: number;
  /** Receives the number of bytes processed so far. */
  readonly onProgress?: (processedBytes: number) => void;
  readonly progressIntervalBytes?: number;
}

export interface KeywordScanOutput {
  /** Occurrences per keyword, aligned with `PDFID_KEYWORDS`. */
  readonly counts: readonly number[];
  /** Hex-escaped occurrences per keyword, aligned with `PDFID_KEYWORDS`. */
  readonly hexcodeCounts: readonly number[];
  /** PDFiD's `/Colors > 2^24` counter. */
  readonly colorsOverThreshold: number;
  readonly entropy: EntropyStatistics;
  readonly dates: BoundedList<PdfDateEntry>;
  readonly names: BoundedList<NameCount>;
  readonly namesWithHexEscapes: number;
  readonly malformedHexEscapes: number;
  /** True when the data ended between a `stream` keyword and its `endstream`. */
  readonly endedInsideStream: boolean;
  /** True when PDFiD 0.2.10 would raise ValueError on a `/Colors` value (see below). */
  readonly pdfidColorsValueError: boolean;
}

const plainKeywordIndex = new Map<string, number>();
const nameKeywordIndex = new Map<string, number>();
PDFID_KEYWORDS.forEach((keyword, index) => {
  if (keyword.name.startsWith('/')) {
    nameKeywordIndex.set(keyword.name.slice(1), index);
  } else {
    plainKeywordIndex.set(keyword.name, index);
  }
});

interface NameTally {
  count: number;
  hexcodeCount: number;
}

function compareCodeUnits(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  return left > right ? 1 : 0;
}

/**
 * Port of the main loop of pdfid.py `PDFiD()` (version 0.2.10).
 *
 * Tokenization rules, matching upstream exactly:
 *   - Only `[A-Za-z0-9]` bytes form words; every other byte ends the current word. A word is
 *     a *name* when the delimiter before it was `/`.
 *   - Inside a name, `#` followed by two hexadecimal digits is decoded and appended, and the
 *     occurrence is counted in the keyword's hexcode count. A `#` without two hex digits ends
 *     the word but leaves the name state on, so `/A#ZZB` yields the names `/A` and `/ZZB`.
 *   - Name keywords match only complete words, case-sensitively. Because `.`, `_` and `-` end a
 *     word, `/JS_x` counts as `/JS` (PDF syntax would treat it as one name).
 *   - Keywords are counted everywhere, including inside stream data; `stream` and `endstream`
 *     only toggle the stream state that the entropy statistics use.
 */
class PdfidTokenizer {
  readonly counts = new Array<number>(PDFID_KEYWORDS.length).fill(0);
  readonly hexcodeCounts = new Array<number>(PDFID_KEYWORDS.length).fill(0);
  readonly entropy = new EntropyAccumulator();
  colorsOverThreshold = 0;
  namesWithHexEscapes = 0;
  malformedHexEscapes = 0;
  pdfidColorsValueError = false;
  insideStream = false;

  private readonly word = new Uint8Array(WORD_CAPACITY);
  private wordLength = 0;
  private wordHasHexEscape = false;
  private wordAllDigits = true;
  private wordHasPythonOnlyDigit = false;
  private wordNumericValue = 0;
  private inName = false;
  private lastName = '';
  private lastNameIsColors = false;

  private readonly dateParser = new PdfDateParser();
  private readonly dateEntries: PdfDateEntry[] = [];
  private datesOmitted = 0;
  private readonly nameTallies = new Map<string, NameTally>();
  private namesOmitted = 0;

  private readonly options: KeywordScanOptions;

  constructor(options: KeywordScanOptions) {
    this.options = options;
  }

  run(bytes: Uint8Array): void {
    const start = Math.min(Math.max(0, this.options.startOffset), bytes.length);
    for (let index = 0; index < start; index++) {
      this.entropy.add(bytes[index] ?? 0, false);
    }

    const interval = this.options.progressIntervalBytes ?? 1 << 20;
    let nextProgress = start + interval;
    let index = start;
    while (index < bytes.length) {
      const byte = bytes[index] ?? 0;
      let consumed = 1;
      if (isAlphanumericByte(byte)) {
        this.append(byte);
      } else if (this.inName && byte === BYTE.HASH) {
        const decoded = decodeHexEscapeAt(bytes, index);
        if (decoded >= 0) {
          this.append(decoded);
          this.wordHasHexEscape = true;
          // Upstream adds the two digits to the entropy histogram but never shows them to the
          // date parser; only the '#' itself reaches it below.
          this.entropy.add(bytes[index + 1] ?? 0, this.insideStream);
          this.entropy.add(bytes[index + 2] ?? 0, this.insideStream);
          consumed = 3;
        } else {
          this.malformedHexEscapes++;
          this.flushWord();
        }
      } else {
        this.checkColorsValue();
        this.flushWord();
        this.inName = byte === BYTE.SLASH;
      }

      const date = this.dateParser.feed(byte);
      if (date !== null) {
        this.recordDate(date);
      }
      this.entropy.add(byte, this.insideStream);

      index += consumed;
      if (index >= nextProgress) {
        this.options.onProgress?.(index);
        nextProgress += interval;
      }
    }
    // Upstream flushes the final word without the /Colors check.
    this.flushWord();
  }

  dates(): BoundedList<PdfDateEntry> {
    const entries = [...this.dateEntries].sort((left, right) =>
      compareCodeUnits(left.value, right.value),
    );
    return { entries, omitted: this.datesOmitted };
  }

  names(): BoundedList<NameCount> {
    const entries = [...this.nameTallies.entries()]
      .sort(([left], [right]) => compareCodeUnits(left, right))
      .map(([name, tally]) => ({
        name: formatNameForDisplay(name),
        count: tally.count,
        hexcodeCount: tally.hexcodeCount,
      }));
    return { entries, omitted: this.namesOmitted };
  }

  private append(code: number): void {
    if (this.wordLength < WORD_CAPACITY) {
      this.word[this.wordLength] = code;
    }
    this.wordLength++;
    if (code >= BYTE.DIGIT_0 && code <= BYTE.DIGIT_9) {
      // Saturating: once the value exceeds the threshold its exact size no longer matters.
      if (this.wordNumericValue <= COLORS_THRESHOLD) {
        this.wordNumericValue = this.wordNumericValue * 10 + (code - BYTE.DIGIT_0);
      }
    } else if (PYTHON_ONLY_DIGITS.has(code)) {
      this.wordHasPythonOnlyDigit = true;
    } else {
      this.wordAllDigits = false;
    }
  }

  /** pdfid.py `cCVE_2009_3459.Check`, called before a word is ended by a delimiter. */
  private checkColorsValue(): void {
    if (!this.lastNameIsColors || this.wordLength === 0 || !this.wordAllDigits) {
      return;
    }
    if (this.wordHasPythonOnlyDigit) {
      // Python's isdigit() accepts ², ³ and ¹ but int() rejects them, so PDFiD stops with
      // ValueError. PDF Signal does not count the value and records the difference.
      this.pdfidColorsValueError = true;
    } else if (this.wordNumericValue > COLORS_THRESHOLD) {
      this.colorsOverThreshold++;
    }
  }

  /** pdfid.py `UpdateWords`. */
  private flushWord(): void {
    if (this.wordLength === 0) {
      return;
    }
    const retained = Math.min(this.wordLength, WORD_CAPACITY);
    const text = latin1FromBytes(this.word, 0, retained);

    if (this.wordLength <= MAX_KEYWORD_WORD_LENGTH) {
      const keywordIndex = this.inName ? nameKeywordIndex.get(text) : plainKeywordIndex.get(text);
      if (keywordIndex !== undefined) {
        this.counts[keywordIndex] = (this.counts[keywordIndex] ?? 0) + 1;
        if (this.wordHasHexEscape) {
          this.hexcodeCounts[keywordIndex] = (this.hexcodeCounts[keywordIndex] ?? 0) + 1;
        }
      } else if (this.inName) {
        this.tallyName(text);
      }
    } else if (this.inName) {
      this.tallyName(text);
    }

    if (this.inName) {
      this.lastName = '/' + text;
      this.lastNameIsColors = this.wordLength === COLORS_NAME.length && text === COLORS_NAME;
      if (this.wordHasHexEscape) {
        this.namesWithHexEscapes++;
      }
    } else if (text === 'stream' && this.wordLength === 6) {
      this.insideStream = true;
    } else if (text === 'endstream' && this.wordLength === 9) {
      if (this.insideStream) {
        this.entropy.removeEndstreamKeyword();
      }
      this.insideStream = false;
    }

    this.wordLength = 0;
    this.wordHasHexEscape = false;
    this.wordAllDigits = true;
    this.wordHasPythonOnlyDigit = false;
    this.wordNumericValue = 0;
  }

  private tallyName(text: string): void {
    if (!this.options.collectNames) {
      return;
    }
    const key = '/' + text;
    const existing = this.nameTallies.get(key);
    if (this.wordLength > WORD_CAPACITY) {
      this.namesOmitted++;
    } else if (existing !== undefined) {
      existing.count++;
      if (this.wordHasHexEscape) {
        existing.hexcodeCount++;
      }
    } else if (this.nameTallies.size < this.options.maxDistinctNames) {
      this.nameTallies.set(key, { count: 1, hexcodeCount: this.wordHasHexEscape ? 1 : 0 });
    } else {
      this.namesOmitted++;
    }
  }

  private recordDate(value: string): void {
    if (this.dateEntries.length < this.options.maxDates) {
      this.dateEntries.push({ value, name: formatNameForDisplay(this.lastName) });
    } else {
      this.datesOmitted++;
    }
  }
}

/**
 * Runs the PDFiD keyword scan over `bytes`, starting at `options.startOffset`.
 * Framework-independent and synchronous; call it from a Web Worker for large inputs.
 */
export function scanKeywords(bytes: Uint8Array, options: KeywordScanOptions): KeywordScanOutput {
  const tokenizer = new PdfidTokenizer(options);
  tokenizer.run(bytes);
  return {
    counts: tokenizer.counts,
    hexcodeCounts: tokenizer.hexcodeCounts,
    colorsOverThreshold: tokenizer.colorsOverThreshold,
    entropy: tokenizer.entropy.calculate(),
    dates: tokenizer.dates(),
    names: tokenizer.names(),
    namesWithHexEscapes: tokenizer.namesWithHexEscapes,
    malformedHexEscapes: tokenizer.malformedHexEscapes,
    endedInsideStream: tokenizer.insideStream,
    pdfidColorsValueError: tokenizer.pdfidColorsValueError,
  };
}
