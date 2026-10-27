/**
 * Harmless sample PDFs, generated in the browser, so people can try PDF Signal without having
 * a suspicious file of their own. They are scanned exactly like an uploaded file. The only
 * script they contain shows a message box, and PDF Signal never runs it anyway.
 */

export interface SampleDefinition {
  readonly id: 'clean' | 'auto-javascript' | 'hidden-javascript';
  readonly title: string;
  readonly description: string;
  readonly fileName: string;
  /** The sample needs CompressionStream to build its compressed object stream. */
  readonly needsCompression: boolean;
}

export const SAMPLES: readonly SampleDefinition[] = [
  {
    id: 'clean',
    title: 'Clean document',
    description: 'A plain one-page PDF with no active content.',
    fileName: 'pdf-signal-sample-clean.pdf',
    needsCompression: false,
  },
  {
    id: 'auto-javascript',
    title: 'Auto-running JavaScript',
    description: 'Runs a script (a harmless message box) as soon as it is opened.',
    fileName: 'pdf-signal-sample-auto-javascript.pdf',
    needsCompression: false,
  },
  {
    id: 'hidden-javascript',
    title: 'Script hidden in an object stream',
    description:
      'The same script, compressed where byte-level scanners such as PDFiD cannot see it.',
    fileName: 'pdf-signal-sample-hidden-javascript.pdf',
    needsCompression: true,
  },
];

const SCRIPT = "app.alert('This is a harmless PDF Signal sample.');";

function encode(text: string): Uint8Array {
  const bytes = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index++) {
    bytes[index] = text.charCodeAt(index) & 0xff;
  }
  return bytes;
}

function concat(parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

async function deflate(data: Uint8Array): Promise<Uint8Array> {
  const compressor = new CompressionStream('deflate');
  const writer = compressor.writable.getWriter();
  writer.write(new Uint8Array(data)).catch(() => undefined);
  writer.close().catch(() => undefined);
  const chunks: Uint8Array[] = [];
  const reader = compressor.readable.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      return concat(chunks);
    }
    chunks.push(value);
  }
}

interface SampleObject {
  readonly body: string;
  readonly stream?: Uint8Array;
}

/** Writes a small, structurally valid PDF with a correct cross-reference table. */
function buildPdf(objects: readonly SampleObject[], rootNumber: number): Uint8Array<ArrayBuffer> {
  const parts: Uint8Array[] = [
    encode('%PDF-1.7\n%'),
    new Uint8Array([0xe2, 0xe3, 0xcf, 0xd3]),
    encode('\n'),
  ];
  let length = parts.reduce((total, part) => total + part.length, 0);
  const push = (part: Uint8Array) => {
    parts.push(part);
    length += part.length;
  };
  const offsets: number[] = [];
  objects.forEach((object, index) => {
    offsets.push(length);
    push(encode(`${index + 1} 0 obj\n${object.body}\n`));
    if (object.stream !== undefined) {
      push(encode('stream\n'));
      push(object.stream);
      push(encode('\nendstream\n'));
    }
    push(encode('endobj\n'));
  });
  const xrefOffset = length;
  let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) {
    xref += `${offset.toString().padStart(10, '0')} 00000 n \n`;
  }
  push(encode(xref));
  push(
    encode(
      `trailer\n<< /Size ${objects.length + 1} /Root ${rootNumber} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`,
    ),
  );
  return concat(parts);
}

const PAGE_TREE = '<< /Type /Pages /Kids [3 0 R] /Count 1 >>';
const PAGE = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>';

export function isSampleAvailable(sample: SampleDefinition): boolean {
  return !sample.needsCompression || typeof globalThis.CompressionStream === 'function';
}

export async function buildSampleBytes(
  id: SampleDefinition['id'],
): Promise<Uint8Array<ArrayBuffer>> {
  switch (id) {
    case 'clean':
      return buildPdf(
        [{ body: '<< /Type /Catalog /Pages 2 0 R >>' }, { body: PAGE_TREE }, { body: PAGE }],
        1,
      );
    case 'auto-javascript':
      return buildPdf(
        [
          { body: '<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>' },
          { body: PAGE_TREE },
          { body: PAGE },
          { body: `<< /Type /Action /S /JavaScript /JS (${SCRIPT}) >>` },
        ],
        1,
      );
    case 'hidden-javascript': {
      // Objects 10 (catalog) and 11 (script action) live only inside the compressed stream.
      const stored = [
        '<< /Type /Catalog /Pages 2 0 R /OpenAction 11 0 R >>',
        `<< /Type /Action /S /JavaScript /JS (${SCRIPT}) >>`,
      ];
      const header = `10 0 11 ${stored[0]?.length ?? 0} `;
      const compressed = await deflate(encode(header + stored.join('')));
      return buildPdf(
        [
          { body: '<< /Type /Metadata /Note (catalog stored in object 4) >>' },
          { body: PAGE_TREE },
          { body: PAGE },
          {
            body: `<< /Type /ObjStm /N 2 /First ${header.length} /Filter /FlateDecode /Length ${compressed.length} >>`,
            stream: compressed,
          },
        ],
        10,
      );
    }
  }
}

export async function createSampleFile(sample: SampleDefinition): Promise<File> {
  const bytes = await buildSampleBytes(sample.id);
  return new File([bytes], sample.fileName, { type: 'application/pdf' });
}
