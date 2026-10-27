import type { EofAnalysis } from '../types/analysis';
import { BYTE, isPdfWhitespace } from './byteUtils';

/** Token states of pdfid.py `cPDFEOF`, named after the token text they represent. */
const State = {
  EMPTY: 0, // ''
  PERCENT: 1, // '%'
  PERCENT_PERCENT: 2, // '%%'
  E: 3, // '%%E'
  EO: 4, // '%%EO'
  EOF: 5, // '%%EOF'
  EOF_CR: 6, // '%%EOF\r'
  EOF_OTHER_WHITESPACE: 7, // '%%EOF ' or '%%EOF\t'
} as const;

type StateValue = (typeof State)[keyof typeof State];

/**
 * Byte-for-byte port of pdfid.py `cPDFEOF`.
 *
 * A marker counts only when `%%EOF` is followed by LF, CR, space or tab, or ends the data.
 * The state machine does not re-examine the byte that breaks a partial match, which yields
 * some upstream quirks that are reproduced deliberately:
 *   - `%%%EOF` is not counted, because the third `%` resets the token;
 *   - after `%%EOF ` (space or tab) the next byte only resets the token, so in
 *     `%%EOF %%EOF\n` only the first marker is counted;
 *   - CR LF after a marker leaves zero bytes "after" it, but space LF leaves one.
 */
export class EofStateMachine {
  private state: StateValue = State.EMPTY;
  private markers = 0;
  private charsAfterLastMarker = 0;

  feed(byte: number): void {
    if (this.markers > 0) {
      this.charsAfterLastMarker++;
    }
    switch (this.state) {
      case State.EMPTY:
        if (byte === BYTE.PERCENT) {
          this.state = State.PERCENT;
        }
        return;
      case State.PERCENT:
        this.state = byte === BYTE.PERCENT ? State.PERCENT_PERCENT : State.EMPTY;
        return;
      case State.PERCENT_PERCENT:
        this.state = byte === BYTE.UPPER_E ? State.E : State.EMPTY;
        return;
      case State.E:
        this.state = byte === BYTE.UPPER_O ? State.EO : State.EMPTY;
        return;
      case State.EO:
        this.state = byte === BYTE.UPPER_F ? State.EOF : State.EMPTY;
        return;
      case State.EOF:
        if (byte === BYTE.LF || byte === BYTE.CR || byte === BYTE.SPACE || byte === BYTE.TAB) {
          this.markers++;
          this.charsAfterLastMarker = 0;
          if (byte === BYTE.LF) {
            this.state = State.EMPTY;
          } else if (byte === BYTE.CR) {
            this.state = State.EOF_CR;
          } else {
            this.state = State.EOF_OTHER_WHITESPACE;
          }
        } else {
          this.state = State.EMPTY;
        }
        return;
      case State.EOF_CR:
        if (byte === BYTE.LF) {
          this.charsAfterLastMarker = 0;
        }
        this.state = State.EMPTY;
        return;
      case State.EOF_OTHER_WHITESPACE:
        this.state = State.EMPTY;
        return;
    }
  }

  /** Applies PDFiD's end-of-data rule: data ending exactly in `%%EOF` counts one marker. */
  finish(): void {
    if (this.state === State.EOF) {
      this.markers++;
      this.charsAfterLastMarker = 0;
      this.state = State.EMPTY;
    }
  }

  get eofCount(): number {
    return this.markers;
  }

  /** PDFiD's `CountCharsAfterLastEOF`; null when no marker has been seen. */
  get bytesAfterLastEof(): number | null {
    return this.markers > 0 ? this.charsAfterLastMarker : null;
  }
}

/**
 * Counts `%%EOF` markers in `bytes[startOffset, end)` and measures data after the last one.
 *
 * pdfid.py feeds the same bytes to its EOF parser from inside the keyword loop. Running it as
 * a separate pass gives identical results: the only reordering in the upstream loop (hex
 * escape digits are fed before their `#`) happens while the EOF token is necessarily empty.
 */
export function analyzeEof(bytes: Uint8Array, startOffset = 0): EofAnalysis {
  const machine = new EofStateMachine();
  for (let index = Math.max(0, startOffset); index < bytes.length; index++) {
    machine.feed(bytes[index] ?? 0);
  }
  machine.finish();

  const bytesAfterLastEof = machine.bytesAfterLastEof;
  const trailingDataPresent = bytesAfterLastEof !== null && bytesAfterLastEof > 0;
  let trailingDataWhitespaceOnly: boolean | null = null;
  if (bytesAfterLastEof !== null && trailingDataPresent) {
    trailingDataWhitespaceOnly = true;
    for (let index = bytes.length - bytesAfterLastEof; index < bytes.length; index++) {
      if (!isPdfWhitespace(bytes[index] ?? 0)) {
        trailingDataWhitespaceOnly = false;
        break;
      }
    }
  }

  return {
    eofCount: machine.eofCount,
    bytesAfterLastEof,
    trailingDataPresent,
    trailingDataWhitespaceOnly,
  };
}
