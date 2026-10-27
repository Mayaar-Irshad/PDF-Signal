import { hexDigitValue, isPdfWhitespace } from './byteUtils';
import type { PdfValue } from './pdfObjects';

/**
 * Bounded decoders for the stream filters that can hide text: FlateDecode (zlib, decoded with
 * the browser's built-in DecompressionStream), ASCIIHexDecode, ASCII85Decode and
 * RunLengthDecode. Output is capped, so a "decompression bomb" stops at the cap instead of
 * exhausting memory. Image and font filters are not decoded.
 */

export type DecodeStatus = 'ok' | 'partial' | 'truncated' | 'failed' | 'unsupported';

export interface DecodeResult {
  readonly bytes: Uint8Array;
  /**
   * `ok`: fully decoded. `partial`: the data was corrupt or ended early; what could be decoded
   * is returned. `truncated`: the output cap was reached. `failed`: nothing could be decoded.
   * `unsupported`: a filter is not supported here (or the browser lacks DecompressionStream).
   */
  readonly status: DecodeStatus;
}

const FILTER_ALIASES: Readonly<Record<string, string>> = {
  Fl: 'FlateDecode',
  AHx: 'ASCIIHexDecode',
  A85: 'ASCII85Decode',
  RL: 'RunLengthDecode',
  LZW: 'LZWDecode',
  CCF: 'CCITTFaxDecode',
  DCT: 'DCTDecode',
};

/** Normalized filter names from a stream dictionary's /Filter entry. */
export function filtersOf(filter: PdfValue | undefined): string[] {
  if (filter === undefined) {
    return [];
  }
  const names = filter.type === 'array' ? filter.items : [filter];
  return names.flatMap((item) =>
    item.type === 'name' ? [FILTER_ALIASES[item.value] ?? item.value] : [],
  );
}

export function isDecompressionAvailable(): boolean {
  return typeof globalThis.DecompressionStream === 'function';
}

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

/** Inflates zlib data, stopping once `maxBytes` of output have been produced. */
export async function inflateBounded(data: Uint8Array, maxBytes: number): Promise<DecodeResult> {
  if (!isDecompressionAvailable()) {
    return { bytes: new Uint8Array(0), status: 'unsupported' };
  }
  const decompressor = new DecompressionStream('deflate');
  const writer = decompressor.writable.getWriter();
  // Write and read concurrently; errors surface on the reader, so writer promises are ignored.
  writer.write(new Uint8Array(data)).catch(() => undefined);
  writer.close().catch(() => undefined);

  const reader = decompressor.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        return { bytes: concat(chunks, total), status: 'ok' };
      }
      if (total + value.length > maxBytes) {
        chunks.push(value.subarray(0, maxBytes - total));
        total = maxBytes;
        await reader.cancel().catch(() => undefined);
        return { bytes: concat(chunks, total), status: 'truncated' };
      }
      chunks.push(value);
      total += value.length;
    }
  } catch {
    // Corrupt data or trailing garbage: keep whatever was decoded before the error.
    return { bytes: concat(chunks, total), status: total > 0 ? 'partial' : 'failed' };
  }
}

export function decodeAsciiHex(data: Uint8Array, maxBytes: number): DecodeResult {
  const output = new Uint8Array(Math.min(maxBytes, Math.ceil(data.length / 2)));
  let length = 0;
  let high = -1;
  for (const byte of data) {
    if (byte === 0x3e) {
      break;
    }
    const value = hexDigitValue(byte);
    if (value < 0) {
      if (!isPdfWhitespace(byte)) {
        return { bytes: output.slice(0, length), status: 'partial' };
      }
      continue;
    }
    if (high < 0) {
      high = value;
    } else {
      if (length >= output.length) {
        return { bytes: output.slice(0, length), status: 'truncated' };
      }
      output[length++] = high * 16 + value;
      high = -1;
    }
  }
  if (high >= 0 && length < output.length) {
    output[length++] = high * 16;
  }
  return { bytes: output.slice(0, length), status: 'ok' };
}

export function decodeAscii85(data: Uint8Array, maxBytes: number): DecodeResult {
  const output = new Uint8Array(Math.min(maxBytes, Math.ceil((data.length * 4) / 5) + 4));
  let length = 0;
  const group: number[] = [];
  const emit = (count: number): boolean => {
    let value = 0;
    for (let index = 0; index < 5; index++) {
      value = value * 85 + (group[index] ?? 84);
    }
    for (let index = 0; index < count; index++) {
      if (length >= output.length) {
        return false;
      }
      output[length++] = Math.floor(value / 256 ** (3 - index)) & 0xff;
    }
    return true;
  };
  for (const byte of data) {
    if (byte === 0x7e) {
      break; // '~>' end marker
    }
    if (isPdfWhitespace(byte)) {
      continue;
    }
    if (byte === 0x7a && group.length === 0) {
      group.push(0, 0, 0, 0, 0); // 'z' = four zero bytes
    } else if (byte >= 0x21 && byte <= 0x75) {
      group.push(byte - 0x21);
    } else {
      return { bytes: output.slice(0, length), status: 'partial' };
    }
    if (group.length === 5) {
      if (!emit(4)) {
        return { bytes: output.slice(0, length), status: 'truncated' };
      }
      group.length = 0;
    }
  }
  if (group.length > 1 && !emit(group.length - 1)) {
    return { bytes: output.slice(0, length), status: 'truncated' };
  }
  return { bytes: output.slice(0, length), status: 'ok' };
}

export function decodeRunLength(data: Uint8Array, maxBytes: number): DecodeResult {
  const chunks: Uint8Array[] = [];
  let total = 0;
  let index = 0;
  while (index < data.length) {
    const code = data[index++] ?? 128;
    if (code === 128) {
      break;
    }
    const chunk =
      code < 128
        ? data.subarray(index, index + code + 1)
        : new Uint8Array(257 - code).fill(data[index] ?? 0);
    index += code < 128 ? code + 1 : 1;
    if (total + chunk.length > maxBytes) {
      chunks.push(chunk.subarray(0, maxBytes - total));
      return { bytes: concat(chunks, maxBytes), status: 'truncated' };
    }
    chunks.push(chunk);
    total += chunk.length;
  }
  return { bytes: concat(chunks, total), status: 'ok' };
}

/** Applies a filter chain in order, keeping every intermediate result within `maxBytes`. */
export async function decodeStream(
  data: Uint8Array,
  filters: readonly string[],
  maxBytes: number,
): Promise<DecodeResult> {
  let current: DecodeResult = { bytes: data, status: 'ok' };
  for (const filter of filters) {
    let next: DecodeResult;
    switch (filter) {
      case 'FlateDecode':
        next = await inflateBounded(current.bytes, maxBytes);
        break;
      case 'ASCIIHexDecode':
        next = decodeAsciiHex(current.bytes, maxBytes);
        break;
      case 'ASCII85Decode':
        next = decodeAscii85(current.bytes, maxBytes);
        break;
      case 'RunLengthDecode':
        next = decodeRunLength(current.bytes, maxBytes);
        break;
      default:
        return { bytes: new Uint8Array(0), status: 'unsupported' };
    }
    if (next.status === 'failed' || next.status === 'unsupported') {
      return next;
    }
    current = { bytes: next.bytes, status: current.status === 'ok' ? next.status : current.status };
  }
  if (current.bytes.length > maxBytes) {
    return { bytes: current.bytes.subarray(0, maxBytes), status: 'truncated' };
  }
  return current;
}
