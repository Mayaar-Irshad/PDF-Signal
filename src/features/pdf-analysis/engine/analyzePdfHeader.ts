import type { HeaderAnalysis } from '../types/analysis';
import {
  BYTE,
  escapeBytesForDisplay,
  indexOfBytes,
  latin1FromBytes,
  latin1ToBytes,
} from './byteUtils';

/** PDFiD reads the first 1024 bytes and looks for `%PDF` anywhere inside them. */
export const HEADER_SEARCH_WINDOW = 1024;

/** PDFiD looks for the end of the header line in the 10 bytes after `%PDF`. */
const HEADER_LINE_SCAN_LENGTH = 10;

/** PDFiD's `Header` field shows at most this many characters. */
const HEADER_DISPLAY_LENGTH = 10;

const PDF_SIGNATURE = latin1ToBytes('%PDF');

const PUBLISHED_VERSIONS = new Set(['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '2.0']);

const VERSION_PATTERN = /^%PDF-(\d{1,3}\.\d{1,3})/;

/** Byte offset of `%PDF` within the first 1024 bytes, or -1. */
export function findPdfSignature(bytes: Uint8Array): number {
  return indexOfBytes(bytes, PDF_SIGNATURE, 0, HEADER_SEARCH_WINDOW);
}

/**
 * Reproduces pdfid.py `FindPDFHeaderRelaxed`.
 *
 * The header runs from `%PDF` up to the first CR or LF among the 10 bytes after the
 * signature; when there is none it is 13 bytes long. Bytes before the end of the header are
 * not tokenized by PDFiD (they only contribute to entropy), so `scanStartOffset` tells the
 * keyword scanner where to begin.
 *
 * PDFiD indexes a list holding only the first 1024 bytes and raises IndexError when the
 * header line runs past it (for example a file that ends right after `%PDF-1.4`). PDF Signal
 * instead ends the header at the end of the data and sets `pdfidWouldError`.
 */
export function analyzePdfHeader(bytes: Uint8Array): HeaderAnalysis {
  const signatureOffset = findPdfSignature(bytes);
  if (signatureOffset < 0) {
    return {
      found: false,
      offset: null,
      text: null,
      version: null,
      versionRecognized: false,
      scanStartOffset: 0,
      pdfidWouldError: false,
    };
  }

  const windowLength = Math.min(bytes.length, HEADER_SEARCH_WINDOW);
  const firstCandidate = signatureOffset + PDF_SIGNATURE.length;
  const lastCandidate = firstCandidate + HEADER_LINE_SCAN_LENGTH - 1;
  let headerEnd = lastCandidate;
  let pdfidWouldError = false;

  for (let candidate = firstCandidate; candidate <= lastCandidate; candidate++) {
    if (candidate >= windowLength) {
      pdfidWouldError = true;
    }
    if (candidate >= bytes.length) {
      headerEnd = bytes.length;
      break;
    }
    const byte = bytes[candidate];
    if (byte === BYTE.LF || byte === BYTE.CR) {
      headerEnd = candidate;
      break;
    }
  }

  const headerLine = latin1FromBytes(bytes, signatureOffset, headerEnd);
  const version = VERSION_PATTERN.exec(headerLine)?.[1] ?? null;

  return {
    found: true,
    offset: signatureOffset,
    text: escapeBytesForDisplay(headerLine.slice(0, HEADER_DISPLAY_LENGTH)),
    version,
    versionRecognized: version !== null && PUBLISHED_VERSIONS.has(version),
    scanStartOffset: headerEnd,
    pdfidWouldError,
  };
}
