import { BYTE, byteToHex, hexDigitValue } from './byteUtils';

/**
 * PDF name hex escapes, following PDFiD 0.2.10 semantics.
 *
 * A PDF name may encode any byte as `#` followed by two hexadecimal digits, so `/Open#41ction`
 * and `/OpenAction` denote the same name. PDFiD decodes an escape only while it is reading a
 * name (the current word started right after a `/`). A `#` anywhere else, or a `#` that is
 * not followed by two hexadecimal digits, is treated as an ordinary delimiter. Escapes are
 * never decoded across the rest of the document.
 */

/**
 * Decodes the escape whose `#` is at `bytes[hashIndex]`.
 *
 * @returns the decoded byte value (0–255), or -1 when the two following bytes are missing or
 *   are not both hexadecimal digits (a malformed or truncated escape).
 */
export function decodeHexEscapeAt(bytes: Uint8Array, hashIndex: number): number {
  if (bytes[hashIndex] !== BYTE.HASH || hashIndex + 2 >= bytes.length) {
    return -1;
  }
  const high = hexDigitValue(bytes[hashIndex + 1] ?? -1);
  const low = hexDigitValue(bytes[hashIndex + 2] ?? -1);
  if (high < 0 || low < 0) {
    return -1;
  }
  return high * 16 + low;
}

/** PDF delimiter characters: ( ) < > [ ] { } / % */
const PDF_DELIMITERS = new Set([0x28, 0x29, 0x3c, 0x3e, 0x5b, 0x5d, 0x7b, 0x7d, 0x2f, 0x25]);

/** True for characters that PDF Signal shows literally inside a name. */
function isDisplaySafeNameCharacter(code: number): boolean {
  // PDF "regular characters" in printable ASCII, except '#', which is re-escaped so the
  // output stays unambiguous.
  return code > 0x20 && code < 0x7f && code !== BYTE.HASH && !PDF_DELIMITERS.has(code);
}

/**
 * Re-encodes a decoded PDF name for display. Characters outside printable ASCII, delimiters
 * and `#` become `#xx`, so control characters and non-ASCII bytes from the file never reach
 * the interface verbatim, and a decoded `/` cannot be mistaken for the start of another name.
 * For example the decoded name `/Java Script` is shown as `/Java#20Script`.
 */
export function formatNameForDisplay(decodedName: string): string {
  let display = '';
  for (let index = 0; index < decodedName.length; index++) {
    const code = decodedName.charCodeAt(index);
    if (index === 0 && code === BYTE.SLASH) {
      display += '/';
    } else if (isDisplaySafeNameCharacter(code)) {
      display += decodedName.charAt(index);
    } else {
      display += '#' + byteToHex(code & 0xff);
    }
  }
  return display;
}
