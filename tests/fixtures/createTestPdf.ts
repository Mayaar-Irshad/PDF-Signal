/**
 * Builders for benign, synthetic PDF byte sequences. Strings are converted one byte per
 * character (ISO-8859-1), never through UTF-8, so tests control every byte exactly.
 */

export type BytePart = string | Uint8Array | readonly number[];

/** Concatenates parts into bytes. String characters must be in U+0000–U+00FF. */
export function bytes(...parts: BytePart[]): Uint8Array<ArrayBuffer> {
  const chunks = parts.map((part) => {
    if (typeof part !== 'string') {
      return Uint8Array.from(part);
    }
    const chunk = new Uint8Array(part.length);
    for (let index = 0; index < part.length; index++) {
      const code = part.charCodeAt(index);
      if (code > 0xff) {
        throw new RangeError(`Fixture text must be Latin-1; found U+${code.toString(16)}`);
      }
      chunk[index] = code;
    }
    return chunk;
  });
  const output = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

export interface PdfObjectSpec {
  /** Dictionary or other object body, e.g. `<< /Type /Catalog /Pages 2 0 R >>`. */
  readonly body: string;
  /** Optional stream data written between `stream` and `endstream`. */
  readonly stream?: BytePart;
}

export interface TestPdfOptions {
  /** Header line without the line break; null omits the header. Default `%PDF-1.7`. */
  readonly header?: string | null;
  /** Bytes written before the header. */
  readonly prefix?: BytePart;
  readonly objects: readonly PdfObjectSpec[];
  /** Extra trailer dictionary entries. */
  readonly trailerEntries?: string;
  /** Final marker written after `startxref`. Default `%%EOF\n`. */
  readonly eof?: BytePart;
  /** Bytes appended after the final marker. */
  readonly suffix?: BytePart;
}

/**
 * Builds a structurally valid PDF with a correct cross-reference table. Object numbers are
 * assigned in order starting at 1; object 1 should normally be the catalog.
 */
export function createTestPdf(options: TestPdfOptions): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array[] = [];
  let length = 0;
  const push = (...items: BytePart[]): void => {
    const chunk = bytes(...items);
    parts.push(chunk);
    length += chunk.length;
  };

  if (options.prefix !== undefined) {
    push(options.prefix);
  }
  const header = options.header === undefined ? '%PDF-1.7' : options.header;
  if (header !== null) {
    // The second line is the conventional binary comment marking the file as binary.
    push(header, '\n%', [0xe2, 0xe3, 0xcf, 0xd3], '\n');
  }

  const offsets: number[] = [];
  options.objects.forEach((object, index) => {
    offsets.push(length);
    push(`${index + 1} 0 obj\n${object.body}\n`);
    if (object.stream !== undefined) {
      push('stream\n', object.stream, '\nendstream\n');
    }
    push('endobj\n');
  });

  const xrefOffset = length;
  const size = options.objects.length + 1;
  let xref = `xref\n0 ${size}\n0000000000 65535 f \n`;
  for (const offset of offsets) {
    xref += `${offset.toString().padStart(10, '0')} 00000 n \n`;
  }
  push(xref);
  push(`trailer\n<< /Size ${size} /Root 1 0 R${options.trailerEntries ?? ''} >>\n`);
  push(`startxref\n${xrefOffset}\n`);
  push(options.eof ?? '%%EOF\n');
  if (options.suffix !== undefined) {
    push(options.suffix);
  }
  return bytes(...parts);
}

/** Catalog, page tree and a single page: the smallest useful document. */
export const BASIC_OBJECTS: readonly PdfObjectSpec[] = [
  { body: '<< /Type /Catalog /Pages 2 0 R >>' },
  { body: '<< /Type /Pages /Kids [3 0 R] /Count 1 >>' },
  { body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>' },
];

/**
 * zlib-compresses data, as a FlateDecode stream stores it. This is a minimal encoder (fixed
 * Huffman codes; back-references only for runs of 258 identical bytes) instead of node:zlib,
 * whose output differs between zlib builds and Node.js versions. Fixtures must be identical on
 * every platform, because the recorded pdfid.py results describe their exact bytes.
 */
export function compress(...parts: BytePart[]): Uint8Array<ArrayBuffer> {
  const data = bytes(...parts);
  const out: number[] = [0x78, 0x01];
  let bitBuffer = 0;
  let bitCount = 0;
  const writeBits = (value: number, length: number): void => {
    bitBuffer |= value << bitCount;
    bitCount += length;
    while (bitCount >= 8) {
      out.push(bitBuffer & 0xff);
      bitBuffer >>>= 8;
      bitCount -= 8;
    }
  };
  // Huffman codes are stored most significant bit first, unlike every other field.
  const writeCode = (code: number, length: number): void => {
    let reversed = 0;
    for (let bit = 0; bit < length; bit += 1) {
      reversed = (reversed << 1) | ((code >> bit) & 1);
    }
    writeBits(reversed, length);
  };
  const writeLiteral = (byte: number): void => {
    if (byte < 144) {
      writeCode(0x30 + byte, 8);
    } else {
      writeCode(0x190 + byte - 144, 9);
    }
  };

  writeBits(1, 1); // final block
  writeBits(1, 2); // fixed Huffman codes
  let index = 0;
  while (index < data.length) {
    const byte = data[index] ?? 0;
    writeLiteral(byte);
    index += 1;
    // Repeat the previous byte 258 times: length code 285, distance code 0 (distance 1).
    while (
      index + 258 <= data.length &&
      data.subarray(index, index + 258).every((b) => b === byte)
    ) {
      writeCode(0xc5, 8);
      writeCode(0, 5);
      index += 258;
    }
  }
  writeCode(0, 7); // end of block
  if (bitCount > 0) {
    out.push(bitBuffer & 0xff);
  }

  let a = 1;
  let b = 0;
  for (const byte of data) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  out.push(b >>> 8, b & 0xff, a >>> 8, a & 0xff);
  return Uint8Array.from(out);
}

/**
 * Builds a compressed object stream (/Type /ObjStm) holding the given objects, the way PDF 1.5+
 * writers store dictionaries. Returns the object spec to place in a test PDF.
 */
export function objectStream(entries: readonly { number: number; body: string }[]): PdfObjectSpec {
  let header = '';
  let content = '';
  for (const entry of entries) {
    header += `${entry.number} ${content.length} `;
    content += `${entry.body}\n`;
  }
  const stream = compress(header, content);
  return {
    body: `<< /Type /ObjStm /N ${entries.length} /First ${header.length} /Filter /FlateDecode /Length ${stream.length} >>`,
    stream,
  };
}
