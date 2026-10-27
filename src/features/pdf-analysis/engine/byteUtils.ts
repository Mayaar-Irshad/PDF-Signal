/**
 * Byte-level helpers shared by the scanning engine.
 *
 * The engine works on raw bytes and never decodes the file as UTF-8. Where a byte sequence
 * has to become a string (for example a PDF name used as a lookup key), each byte maps to
 * the code point with the same value (ISO-8859-1), which is exactly what PDFiD's `chr(byte)`
 * does.
 */

export const BYTE = {
  TAB: 0x09,
  LF: 0x0a,
  FF: 0x0c,
  CR: 0x0d,
  SPACE: 0x20,
  QUOTE: 0x22,
  HASH: 0x23,
  PERCENT: 0x25,
  APOSTROPHE: 0x27,
  PLUS: 0x2b,
  MINUS: 0x2d,
  SLASH: 0x2f,
  DIGIT_0: 0x30,
  DIGIT_9: 0x39,
  COLON: 0x3a,
  UPPER_D: 0x44,
  UPPER_E: 0x45,
  UPPER_F: 0x46,
  UPPER_O: 0x4f,
  UPPER_Z: 0x5a,
  BACKSLASH: 0x5c,
} as const;

/** 1 for `[A-Za-z0-9]`, the only bytes PDFiD accumulates into words. */
const ALPHANUMERIC = new Uint8Array(256);
/** Value of a hexadecimal digit byte, or -1. */
const HEX_VALUE = new Int8Array(256).fill(-1);

for (let code = 0x30; code <= 0x39; code++) {
  ALPHANUMERIC[code] = 1;
  HEX_VALUE[code] = code - 0x30;
}
for (let offset = 0; offset < 26; offset++) {
  ALPHANUMERIC[0x41 + offset] = 1;
  ALPHANUMERIC[0x61 + offset] = 1;
}
for (let offset = 0; offset < 6; offset++) {
  HEX_VALUE[0x41 + offset] = 10 + offset;
  HEX_VALUE[0x61 + offset] = 10 + offset;
}

export function isAlphanumericByte(byte: number): boolean {
  return ALPHANUMERIC[byte] === 1;
}

/** Returns the value (0–15) of a hexadecimal digit byte, or -1 for any other byte. */
export function hexDigitValue(byte: number): number {
  return HEX_VALUE[byte] ?? -1;
}

export function isAsciiDigit(byte: number): boolean {
  return byte >= BYTE.DIGIT_0 && byte <= BYTE.DIGIT_9;
}

/** PDF whitespace characters (ISO 32000-2, table 1). */
export function isPdfWhitespace(byte: number): boolean {
  return (
    byte === 0x00 ||
    byte === BYTE.TAB ||
    byte === BYTE.LF ||
    byte === BYTE.FF ||
    byte === BYTE.CR ||
    byte === BYTE.SPACE
  );
}

/** Converts `bytes[start, end)` to a string, one code point per byte (ISO-8859-1). */
export function latin1FromBytes(bytes: Uint8Array, start = 0, end = bytes.length): string {
  let text = '';
  for (let index = start; index < end; index++) {
    text += String.fromCharCode(bytes[index] ?? 0);
  }
  return text;
}

/** Encodes an ASCII-only string into bytes. Throws on characters above U+00FF. */
export function latin1ToBytes(text: string): Uint8Array {
  const bytes = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code > 0xff) {
      throw new RangeError('latin1ToBytes only accepts characters in the range U+0000–U+00FF');
    }
    bytes[index] = code;
  }
  return bytes;
}

/** Finds `needle` in `haystack[from, to)`; the whole needle must fit inside the range. */
export function indexOfBytes(
  haystack: Uint8Array,
  needle: Uint8Array,
  from = 0,
  to = haystack.length,
): number {
  const limit = Math.min(to, haystack.length) - needle.length;
  outer: for (let index = Math.max(0, from); index <= limit; index++) {
    for (let offset = 0; offset < needle.length; offset++) {
      if (haystack[index + offset] !== needle[offset]) {
        continue outer;
      }
    }
    return index;
  }
  return -1;
}

const HEX_DIGITS = '0123456789abcdef';

/** Two-digit lowercase hexadecimal representation of a byte value. */
export function byteToHex(byte: number): string {
  return (HEX_DIGITS[(byte >> 4) & 0x0f] ?? '0') + (HEX_DIGITS[byte & 0x0f] ?? '0');
}

/**
 * Escapes a byte string for display, close to Python's `repr()` as used by PDFiD for the
 * `Header` field: printable ASCII is kept, `\`, tab, LF and CR are backslash-escaped and every
 * other byte becomes `\xNN`. (Python prints printable Latin-1 characters above 0x7F as-is; PDF
 * Signal escapes them so that only ASCII ever reaches the interface.)
 */
export function escapeBytesForDisplay(text: string): string {
  let escaped = '';
  for (const character of text) {
    const code = character.charCodeAt(0);
    if (code === BYTE.BACKSLASH) {
      escaped += '\\\\';
    } else if (code === BYTE.TAB) {
      escaped += '\\t';
    } else if (code === BYTE.LF) {
      escaped += '\\n';
    } else if (code === BYTE.CR) {
      escaped += '\\r';
    } else if (code >= 0x20 && code <= 0x7e) {
      escaped += character;
    } else {
      escaped += '\\x' + byteToHex(code & 0xff);
    }
  }
  return escaped;
}
