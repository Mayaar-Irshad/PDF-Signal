import { BYTE, isAsciiDigit } from './byteUtils';

const DATE_DIGITS = 14;
const TIMEZONE_LENGTH = 5;

/**
 * Port of pdfid.py `cPDFDate`, which recognizes dates of the form `D:YYYYMMDDHHmmSS` with an
 * optional `+HH'mm` / `-HH'mm` / `ZHH'mm` time zone.
 *
 * Upstream quirks reproduced deliberately:
 *   - a `D` byte restarts recognition in every state, even in the middle of a date;
 *   - exactly 14 digits are required, and a 15th digit discards the date;
 *   - after `+`, `-` or `Z` the date is reported only when the full `HH'mm` follows, so a
 *     date ending in a bare `Z` is not reported at all.
 */
export class PdfDateParser {
  private state: 0 | 1 | 2 | 3 = 0;
  private digits = '';
  private timezoneSign = '';
  private timezone = '';

  /** Feeds one byte; returns the completed date when this byte finishes one. */
  feed(byte: number): string | null {
    if (byte === BYTE.UPPER_D) {
      this.state = 1;
      return null;
    }
    switch (this.state) {
      case 0:
        return null;
      case 1:
        if (byte === BYTE.COLON) {
          this.state = 2;
          this.digits = '';
        } else {
          this.state = 0;
        }
        return null;
      case 2:
        return this.feedDateDigits(byte);
      case 3:
        return this.feedTimezone(byte);
    }
  }

  private feedDateDigits(byte: number): string | null {
    if (this.digits.length < DATE_DIGITS) {
      if (isAsciiDigit(byte)) {
        this.digits += String.fromCharCode(byte);
      } else {
        this.state = 0;
      }
      return null;
    }
    if (byte === BYTE.PLUS || byte === BYTE.MINUS || byte === BYTE.UPPER_Z) {
      this.state = 3;
      this.timezone = '';
      this.timezoneSign = String.fromCharCode(byte);
      return null;
    }
    this.state = 0;
    // Upstream returns the date for '"' and for any other non-digit; a 15th digit discards it.
    return isAsciiDigit(byte) ? null : 'D:' + this.digits;
  }

  private feedTimezone(byte: number): string | null {
    const length = this.timezone.length;
    if (length === 2) {
      if (byte === BYTE.APOSTROPHE) {
        this.timezone += "'";
      } else {
        this.state = 0;
      }
      return null;
    }
    if (!isAsciiDigit(byte)) {
      this.state = 0;
      return null;
    }
    this.timezone += String.fromCharCode(byte);
    if (this.timezone.length === TIMEZONE_LENGTH) {
      this.state = 0;
      return 'D:' + this.digits + this.timezoneSign + this.timezone;
    }
    return null;
  }
}
