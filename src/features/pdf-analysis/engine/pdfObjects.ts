import {
  BYTE,
  hexDigitValue,
  indexOfBytes,
  isPdfWhitespace,
  latin1FromBytes,
  latin1ToBytes,
} from './byteUtils';

/**
 * A small, defensive PDF object parser used by the deep analysis.
 *
 * Unlike the PDFiD-compatible keyword scan, this follows PDF syntax (ISO 32000): names run
 * until whitespace or a delimiter and their `#xx` escapes are decoded, strings are decoded with
 * their escapes, and `N G R` references are recognized. Every loop is bounded by the input
 * length and by explicit limits, and malformed input produces partial results, never an
 * exception.
 */

export type PdfValue =
  | { readonly type: 'null' }
  | { readonly type: 'boolean'; readonly value: boolean }
  | { readonly type: 'number'; readonly value: number }
  | { readonly type: 'name'; readonly value: string }
  | { readonly type: 'string'; readonly value: Uint8Array }
  | { readonly type: 'array'; readonly items: readonly PdfValue[] }
  | { readonly type: 'dict'; readonly entries: ReadonlyMap<string, PdfValue> }
  | { readonly type: 'ref'; readonly number: number; readonly generation: number }
  | { readonly type: 'keyword'; readonly value: string };

export type PdfDict = Extract<PdfValue, { type: 'dict' }>;

export interface ParseLimits {
  readonly maxDepth: number;
  readonly maxItems: number;
  readonly maxStringBytes: number;
  readonly maxTokens: number;
}

export const DEFAULT_PARSE_LIMITS: ParseLimits = {
  maxDepth: 32,
  maxItems: 20_000,
  maxStringBytes: 2 * 1024 * 1024,
  maxTokens: 500_000,
};

const MAX_NAME_LENGTH = 256;
const MAX_NUMBER_LENGTH = 32;

const DELIMITERS = new Uint8Array(256);
for (const character of '()<>[]{}/%') {
  DELIMITERS[character.charCodeAt(0)] = 1;
}

function isRegular(byte: number): boolean {
  return !isPdfWhitespace(byte) && DELIMITERS[byte] !== 1;
}

type TokenBody =
  | { readonly kind: 'name'; readonly value: string }
  | { readonly kind: 'number'; readonly value: number; readonly integer: boolean }
  | { readonly kind: 'string'; readonly value: Uint8Array }
  | { readonly kind: 'dict-start' | 'dict-end' | 'array-start' | 'array-end' | 'eof' }
  | { readonly kind: 'keyword'; readonly value: string };

export type Token = TokenBody & { readonly start: number; readonly end: number };

/** Growable byte buffer with a hard cap; bytes beyond the cap are dropped. */
class ByteBuilder {
  private buffer = new Uint8Array(64);
  private length = 0;
  private readonly cap: number;

  constructor(cap: number) {
    this.cap = cap;
  }

  push(byte: number): void {
    if (this.length >= this.cap) {
      return;
    }
    if (this.length === this.buffer.length) {
      const grown = new Uint8Array(Math.min(this.cap, this.buffer.length * 2));
      grown.set(this.buffer);
      this.buffer = grown;
    }
    this.buffer[this.length++] = byte;
  }

  bytes(): Uint8Array {
    return this.buffer.slice(0, this.length);
  }
}

export class PdfLexer {
  position: number;
  tokensRead = 0;
  private readonly bytes: Uint8Array;
  private readonly end: number;
  private readonly limits: ParseLimits;
  private readonly pending: Token[] = [];

  constructor(
    bytes: Uint8Array,
    start = 0,
    end: number = bytes.length,
    limits: ParseLimits = DEFAULT_PARSE_LIMITS,
  ) {
    this.bytes = bytes;
    this.position = Math.max(0, start);
    this.end = Math.min(end, bytes.length);
    this.limits = limits;
  }

  next(): Token {
    return this.pending.pop() ?? this.read();
  }

  peek(): Token {
    const token = this.next();
    this.pending.push(token);
    return token;
  }

  pushBack(token: Token): void {
    this.pending.push(token);
  }

  private byteAt(index: number): number {
    return index < this.end ? (this.bytes[index] ?? -1) : -1;
  }

  private skipWhitespaceAndComments(): void {
    while (this.position < this.end) {
      const byte = this.byteAt(this.position);
      if (isPdfWhitespace(byte)) {
        this.position++;
      } else if (byte === BYTE.PERCENT) {
        while (
          this.position < this.end &&
          this.byteAt(this.position) !== BYTE.LF &&
          this.byteAt(this.position) !== BYTE.CR
        ) {
          this.position++;
        }
      } else {
        return;
      }
    }
  }

  private read(): Token {
    this.skipWhitespaceAndComments();
    const start = this.position;
    if (start >= this.end || this.tokensRead >= this.limits.maxTokens) {
      return { kind: 'eof', start, end: start };
    }
    this.tokensRead++;
    const byte = this.byteAt(start);
    const token = this.readBody(byte);
    return { ...token, start, end: this.position };
  }

  private readBody(byte: number): TokenBody {
    switch (byte) {
      case BYTE.SLASH:
        return this.readName();
      case 0x28: // (
        return { kind: 'string', value: this.readLiteralString() };
      case 0x3c: // <
        if (this.byteAt(this.position + 1) === 0x3c) {
          this.position += 2;
          return { kind: 'dict-start' };
        }
        return { kind: 'string', value: this.readHexString() };
      case 0x3e: // >
        if (this.byteAt(this.position + 1) === 0x3e) {
          this.position += 2;
          return { kind: 'dict-end' };
        }
        this.position++;
        return { kind: 'keyword', value: '>' };
      case 0x5b: // [
        this.position++;
        return { kind: 'array-start' };
      case 0x5d: // ]
        this.position++;
        return { kind: 'array-end' };
      default:
        if (DELIMITERS[byte] === 1) {
          this.position++;
          return { kind: 'keyword', value: String.fromCharCode(byte) };
        }
        return this.readNumberOrKeyword();
    }
  }

  private readName(): TokenBody {
    this.position++; // '/'
    let name = '';
    while (this.position < this.end && isRegular(this.byteAt(this.position))) {
      let code = this.byteAt(this.position);
      if (code === BYTE.HASH) {
        const high = hexDigitValue(this.byteAt(this.position + 1));
        const low = hexDigitValue(this.byteAt(this.position + 2));
        if (high >= 0 && low >= 0) {
          code = high * 16 + low;
          this.position += 2;
        }
      }
      if (name.length < MAX_NAME_LENGTH) {
        name += String.fromCharCode(code);
      }
      this.position++;
    }
    return { kind: 'name', value: name };
  }

  private readNumberOrKeyword(): TokenBody {
    const start = this.position;
    while (this.position < this.end && isRegular(this.byteAt(this.position))) {
      this.position++;
    }
    if (this.position === start) {
      this.position++;
    }
    const text = latin1FromBytes(
      this.bytes,
      start,
      Math.min(this.position, start + MAX_NUMBER_LENGTH),
    );
    if (/^[+-]?(\d+\.?\d*|\.\d+)$/.test(text)) {
      return { kind: 'number', value: Number(text), integer: !text.includes('.') };
    }
    return { kind: 'keyword', value: text };
  }

  private readLiteralString(): Uint8Array {
    const output = new ByteBuilder(this.limits.maxStringBytes);
    this.position++; // '('
    let depth = 1;
    while (this.position < this.end) {
      const byte = this.byteAt(this.position++);
      if (byte === BYTE.BACKSLASH) {
        this.readEscape(output);
      } else if (byte === 0x28) {
        depth++;
        output.push(byte);
      } else if (byte === 0x29) {
        depth--;
        if (depth === 0) {
          break;
        }
        output.push(byte);
      } else {
        output.push(byte);
      }
    }
    return output.bytes();
  }

  private readEscape(output: ByteBuilder): void {
    const byte = this.byteAt(this.position);
    if (byte < 0) {
      return;
    }
    this.position++;
    const simple: Record<number, number> = { 0x6e: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12 };
    const mapped = simple[byte];
    if (mapped !== undefined) {
      output.push(mapped);
    } else if (byte >= 0x30 && byte <= 0x37) {
      let value = byte - 0x30;
      for (let digits = 1; digits < 3; digits++) {
        const next = this.byteAt(this.position);
        if (next < 0x30 || next > 0x37) {
          break;
        }
        value = value * 8 + (next - 0x30);
        this.position++;
      }
      output.push(value & 0xff);
    } else if (byte === BYTE.CR) {
      if (this.byteAt(this.position) === BYTE.LF) {
        this.position++;
      }
    } else if (byte !== BYTE.LF) {
      output.push(byte);
    }
  }

  private readHexString(): Uint8Array {
    const output = new ByteBuilder(this.limits.maxStringBytes);
    this.position++; // '<'
    let high = -1;
    while (this.position < this.end) {
      const byte = this.byteAt(this.position++);
      if (byte === 0x3e) {
        break;
      }
      const value = hexDigitValue(byte);
      if (value < 0) {
        continue;
      }
      if (high < 0) {
        high = value;
      } else {
        output.push(high * 16 + value);
        high = -1;
      }
    }
    if (high >= 0) {
      output.push(high * 16);
    }
    return output.bytes();
  }
}

const NULL_VALUE: PdfValue = { type: 'null' };
const OBJECT_END_KEYWORDS = new Set(['stream', 'endstream', 'obj', 'endobj']);

function isStopToken(token: Token): boolean {
  return token.kind === 'eof' || (token.kind === 'keyword' && OBJECT_END_KEYWORDS.has(token.value));
}

function skipContainer(lexer: PdfLexer): void {
  let depth = 1;
  while (depth > 0) {
    const token = lexer.next();
    if (isStopToken(token)) {
      lexer.pushBack(token);
      return;
    }
    if (token.kind === 'dict-start' || token.kind === 'array-start') {
      depth++;
    } else if (token.kind === 'dict-end' || token.kind === 'array-end') {
      depth--;
    }
  }
}

/** Parses one PDF value. Returns null at the end of the input or at an object boundary. */
export function parseValue(
  lexer: PdfLexer,
  limits: ParseLimits = DEFAULT_PARSE_LIMITS,
  depth = 0,
): PdfValue | null {
  const token = lexer.next();
  switch (token.kind) {
    case 'eof':
      return null;
    case 'name':
      return { type: 'name', value: token.value };
    case 'string':
      return { type: 'string', value: token.value };
    case 'number':
      return parseNumberOrReference(lexer, token);
    case 'dict-start':
      if (depth >= limits.maxDepth) {
        skipContainer(lexer);
        return NULL_VALUE;
      }
      return parseDictionary(lexer, limits, depth + 1);
    case 'array-start':
      if (depth >= limits.maxDepth) {
        skipContainer(lexer);
        return NULL_VALUE;
      }
      return parseArray(lexer, limits, depth + 1);
    case 'dict-end':
    case 'array-end':
      return { type: 'keyword', value: token.kind === 'dict-end' ? '>>' : ']' };
    case 'keyword':
      if (OBJECT_END_KEYWORDS.has(token.value)) {
        lexer.pushBack(token);
        return null;
      }
      if (token.value === 'true' || token.value === 'false') {
        return { type: 'boolean', value: token.value === 'true' };
      }
      return token.value === 'null' ? NULL_VALUE : { type: 'keyword', value: token.value };
  }
}

function parseNumberOrReference(
  lexer: PdfLexer,
  first: Extract<Token, { kind: 'number' }>,
): PdfValue {
  if (first.integer && first.value >= 0) {
    const second = lexer.next();
    if (second.kind === 'number' && second.integer && second.value >= 0) {
      const third = lexer.next();
      if (third.kind === 'keyword' && third.value === 'R') {
        return { type: 'ref', number: first.value, generation: second.value };
      }
      lexer.pushBack(third);
    }
    // Lenient readers such as pdf.js also accept "4 0R" without the space.
    if (second.kind === 'keyword' && /^\d{1,10}R$/.test(second.value)) {
      return { type: 'ref', number: first.value, generation: Number(second.value.slice(0, -1)) };
    }
    lexer.pushBack(second);
  }
  return { type: 'number', value: first.value };
}

function parseDictionary(lexer: PdfLexer, limits: ParseLimits, depth: number): PdfDict {
  const entries = new Map<string, PdfValue>();
  for (;;) {
    const token = lexer.next();
    if (token.kind === 'dict-end') {
      break;
    }
    if (isStopToken(token)) {
      lexer.pushBack(token);
      break;
    }
    if (token.kind !== 'name') {
      continue;
    }
    if (isStopToken(lexer.peek()) || lexer.peek().kind === 'dict-end') {
      continue;
    }
    const value = parseValue(lexer, limits, depth);
    if (value === null) {
      break;
    }
    if (entries.size < limits.maxItems || entries.has(token.value)) {
      entries.set(token.value, value);
    }
  }
  return { type: 'dict', entries };
}

function parseArray(lexer: PdfLexer, limits: ParseLimits, depth: number): PdfValue {
  const items: PdfValue[] = [];
  for (;;) {
    const token = lexer.peek();
    if (token.kind === 'array-end') {
      lexer.next();
      break;
    }
    if (isStopToken(token) || token.kind === 'dict-end') {
      if (token.kind === 'dict-end') {
        lexer.next();
      }
      break;
    }
    const value = parseValue(lexer, limits, depth);
    if (value === null) {
      break;
    }
    if (items.length < limits.maxItems) {
      items.push(value);
    }
  }
  return { type: 'array', items };
}

/** Convenience accessors. */
export function dictGet(value: PdfValue | undefined, key: string): PdfValue | undefined {
  return value?.type === 'dict' ? value.entries.get(key) : undefined;
}

export function nameOf(value: PdfValue | undefined): string | null {
  return value?.type === 'name' ? value.value : null;
}

export function integerOf(value: PdfValue | undefined): number | null {
  return value?.type === 'number' && Number.isSafeInteger(value.value) ? value.value : null;
}

export interface PdfStream {
  readonly buffer: Uint8Array;
  readonly dataStart: number;
  readonly dataEnd: number;
}

export interface PdfObject {
  readonly number: number;
  readonly generation: number;
  readonly value: PdfValue;
  readonly stream: PdfStream | null;
  readonly source: 'file' | 'object-stream';
}

const ENDSTREAM = latin1ToBytes('endstream');
const MAX_OBJECT_NUMBER = 2 ** 31 - 1;

interface ObjectHeader {
  readonly number: number;
  readonly generation: number;
  readonly bodyStart: number;
}

function readDigitsBackwards(
  bytes: Uint8Array,
  end: number,
): { value: number; start: number } | null {
  let start = end;
  while (start > 0 && start > end - 10) {
    const byte = bytes[start - 1] ?? 0;
    if (byte < BYTE.DIGIT_0 || byte > BYTE.DIGIT_9) {
      break;
    }
    start--;
  }
  if (start === end) {
    return null;
  }
  return { value: Number(latin1FromBytes(bytes, start, end)), start };
}

function skipWhitespaceBackwards(bytes: Uint8Array, end: number): number {
  let index = end;
  while (index > 0 && isPdfWhitespace(bytes[index - 1] ?? 0)) {
    index--;
  }
  return index;
}

/** Finds the next `<number> <generation> obj` header at or after `from`. */
export function findNextObjectHeader(bytes: Uint8Array, from: number): ObjectHeader | null {
  for (let index = Math.max(1, from); index + 2 < bytes.length; index++) {
    if (bytes[index] !== 0x6f || bytes[index + 1] !== 0x62 || bytes[index + 2] !== 0x6a) {
      continue;
    }
    const after = bytes[index + 3];
    if (after !== undefined && isRegular(after)) {
      continue;
    }
    const beforeKeyword = skipWhitespaceBackwards(bytes, index);
    if (beforeKeyword === index) {
      continue;
    }
    const generation = readDigitsBackwards(bytes, beforeKeyword);
    if (generation === null) {
      continue;
    }
    const beforeGeneration = skipWhitespaceBackwards(bytes, generation.start);
    if (beforeGeneration === generation.start) {
      continue;
    }
    const number = readDigitsBackwards(bytes, beforeGeneration);
    if (number === null || number.value > MAX_OBJECT_NUMBER) {
      continue;
    }
    // Readers reach objects through cross-reference offsets, so a regular character right
    // before the number (as in "X4 0 obj") does not stop them; only a longer digit run does.
    const before = number.start > 0 ? (bytes[number.start - 1] ?? 0) : BYTE.SPACE;
    if (before >= BYTE.DIGIT_0 && before <= BYTE.DIGIT_9) {
      continue;
    }
    return { number: number.value, generation: generation.value, bodyStart: index + 3 };
  }
  return null;
}

/** Locates stream data after the `stream` keyword that ends at `keywordEnd`. */
function locateStreamData(
  bytes: Uint8Array,
  keywordEnd: number,
  dict: PdfValue,
): { dataStart: number; dataEnd: number; next: number } {
  let dataStart = keywordEnd;
  if (bytes[dataStart] === BYTE.CR && bytes[dataStart + 1] === BYTE.LF) {
    dataStart += 2;
  } else if (bytes[dataStart] === BYTE.LF || bytes[dataStart] === BYTE.CR) {
    dataStart += 1;
  }

  const declared = integerOf(dictGet(dict, 'Length'));
  if (declared !== null && declared >= 0 && dataStart + declared <= bytes.length) {
    let after = dataStart + declared;
    while (after < bytes.length && isPdfWhitespace(bytes[after] ?? 0)) {
      after++;
    }
    if (indexOfBytes(bytes, ENDSTREAM, after, after + ENDSTREAM.length) === after) {
      return { dataStart, dataEnd: dataStart + declared, next: after + ENDSTREAM.length };
    }
  }

  const found = indexOfBytes(bytes, ENDSTREAM, dataStart);
  if (found < 0) {
    return { dataStart, dataEnd: bytes.length, next: bytes.length };
  }
  let dataEnd = found;
  if (dataEnd > dataStart && bytes[dataEnd - 1] === BYTE.LF) {
    dataEnd--;
  }
  if (dataEnd > dataStart && bytes[dataEnd - 1] === BYTE.CR) {
    dataEnd--;
  }
  return { dataStart, dataEnd, next: found + ENDSTREAM.length };
}

/** A token budget shared by several lexers, so repeated parsing cannot multiply the work. */
export interface TokenBudget {
  remaining: number;
}

export interface IndexOptions {
  readonly maxObjects: number;
  readonly limits?: ParseLimits;
  readonly budget?: TokenBudget;
  /** Polled while indexing; returning true stops early (time limit). */
  readonly shouldStop?: () => boolean;
}

export interface ObjectIndex {
  /** Every definition found, in file order. Later definitions of a number do not hide earlier ones. */
  readonly definitions: PdfObject[];
  readonly truncated: boolean;
  readonly stopped: boolean;
  /** Objects that hit the per-object token limit and were only partly parsed. */
  readonly oversized: number;
}

function lexerLimits(limits: ParseLimits, budget: TokenBudget): ParseLimits {
  return { ...limits, maxTokens: Math.max(0, Math.min(limits.maxTokens, budget.remaining)) };
}

/**
 * Indexes the indirect objects written directly in the file, by scanning for object headers
 * (as PDF readers do when they repair a file). Stream data is skipped, so byte sequences inside
 * streams are not mistaken for objects. Every definition is kept: an incremental update, or a
 * decoy, can define the same object number several times, and callers decide how to combine them.
 */
export function indexFileObjects(bytes: Uint8Array, options: IndexOptions): ObjectIndex {
  const limits = options.limits ?? DEFAULT_PARSE_LIMITS;
  const budget = options.budget ?? { remaining: Number.POSITIVE_INFINITY };
  const definitions: PdfObject[] = [];
  let oversized = 0;
  let position = 0;
  for (;;) {
    if (definitions.length % 256 === 0 && options.shouldStop?.() === true) {
      return { definitions, truncated: false, stopped: true, oversized };
    }
    const header = findNextObjectHeader(bytes, position);
    if (header === null) {
      return { definitions, truncated: false, stopped: false, oversized };
    }
    if (definitions.length >= options.maxObjects) {
      return { definitions, truncated: true, stopped: false, oversized };
    }
    if (budget.remaining <= 0) {
      return { definitions, truncated: false, stopped: true, oversized };
    }

    const objectLimits = lexerLimits(limits, budget);
    const lexer = new PdfLexer(bytes, header.bodyStart, bytes.length, objectLimits);
    const value = parseValue(lexer, objectLimits) ?? NULL_VALUE;
    const following = lexer.next();
    budget.remaining -= lexer.tokensRead;
    if (lexer.tokensRead >= objectLimits.maxTokens) {
      oversized++;
    }
    let stream: PdfStream | null = null;
    if (following.kind === 'keyword' && following.value === 'stream') {
      const located = locateStreamData(bytes, following.end, value);
      stream = { buffer: bytes, dataStart: located.dataStart, dataEnd: located.dataEnd };
      position = located.next;
    } else if (following.kind === 'eof') {
      // The object never ended (unterminated string, token limit, truncation). Keep looking for
      // later objects instead of giving up on the rest of the file.
      position = header.bodyStart;
    } else {
      position = Math.max(header.bodyStart, following.start);
    }
    definitions.push({
      number: header.number,
      generation: header.generation,
      value,
      stream,
      source: 'file',
    });
  }
}

/**
 * Parses the objects stored in a decoded object stream (`/Type /ObjStm`): a header of `/N`
 * pairs of object numbers and offsets, followed by the objects from offset `/First`.
 */
export function parseObjectStream(
  decoded: Uint8Array,
  dict: PdfValue,
  maxObjects: number,
  limits: ParseLimits = DEFAULT_PARSE_LIMITS,
  budget: TokenBudget = { remaining: limits.maxTokens },
): PdfObject[] {
  const count = integerOf(dictGet(dict, 'N'));
  const first = integerOf(dictGet(dict, 'First'));
  if (count === null || first === null || count < 0 || first < 0 || first > decoded.length) {
    return [];
  }
  const header = new PdfLexer(decoded, 0, first, limits);
  const objects: PdfObject[] = [];
  // Several header entries may point at the same offset; parse each offset only once.
  const parsed = new Map<number, PdfValue>();
  for (let index = 0; index < Math.min(count, maxObjects) && budget.remaining > 0; index++) {
    const numberToken = header.next();
    const offsetToken = header.next();
    if (numberToken.kind !== 'number' || offsetToken.kind !== 'number') {
      break;
    }
    const offset = first + offsetToken.value;
    if (!Number.isSafeInteger(offset) || offset < first || offset >= decoded.length) {
      continue;
    }
    let value = parsed.get(offset);
    if (value === undefined) {
      const objectLimits = lexerLimits(limits, budget);
      const lexer = new PdfLexer(decoded, offset, decoded.length, objectLimits);
      value = parseValue(lexer, objectLimits) ?? NULL_VALUE;
      budget.remaining -= lexer.tokensRead;
      parsed.set(offset, value);
    }
    objects.push({
      number: numberToken.value,
      generation: 0,
      value,
      stream: null,
      source: 'object-stream',
    });
  }
  return objects;
}
