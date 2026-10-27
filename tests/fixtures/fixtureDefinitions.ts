import {
  BASIC_OBJECTS,
  bytes,
  compress,
  createTestPdf,
  objectStream,
  type PdfObjectSpec,
} from './createTestPdf';

/**
 * Benign synthetic fixtures. Each one exercises a scanner behaviour; together they form the
 * controlled corpus that is compared against pdfid.py 0.2.10 (see tests/parity).
 *
 * None of these files is malicious. "JavaScript" fixtures contain only a comment, and every
 * suspicious keyword appears purely so that its counter can be tested.
 */
export interface FixtureDefinition {
  readonly id: string;
  readonly description: string;
  readonly build: () => Uint8Array<ArrayBuffer>;
  /** Hand-verified keyword counts (a subset), checked independently of the parity run. */
  readonly expectedCounts?: Readonly<Record<string, number>>;
  /** Hand-verified hex-escaped counts (a subset). */
  readonly expectedHexcodeCounts?: Readonly<Record<string, number>>;
  /**
   * Set when pdfid.py 0.2.10 raises an exception on this input in the given mode, so its
   * output cannot be compared. The reason is recorded as a known compatibility difference.
   */
  readonly knownPdfidError?: {
    readonly mode: 'standard' | 'forced' | 'both';
    readonly reason: string;
  };
}

const BENIGN_SCRIPT = '(// PDF Signal benign test fixture: no executable behaviour)';

/** Deterministic pseudo-random bytes (linear congruential generator). */
export function pseudoRandomBytes(length: number, seed = 0x5eed): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(length);
  let state = seed >>> 0;
  for (let index = 0; index < length; index++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    output[index] = state >>> 24;
  }
  return output;
}

const withCatalogEntries = (
  entries: string,
  extra: readonly PdfObjectSpec[] = [],
): PdfObjectSpec[] => [
  { body: `<< /Type /Catalog /Pages 2 0 R ${entries} >>` },
  ...BASIC_OBJECTS.slice(1),
  ...extra,
];

export const FIXTURES: readonly FixtureDefinition[] = [
  {
    id: 'minimal',
    description: 'Catalog, page tree and one page; no indicators',
    build: () => createTestPdf({ objects: BASIC_OBJECTS }),
    expectedCounts: {
      obj: 3,
      endobj: 3,
      stream: 0,
      endstream: 0,
      xref: 1,
      trailer: 1,
      startxref: 1,
      '/Page': 1,
      '/JS': 0,
      '/JavaScript': 0,
      '/OpenAction': 0,
    },
  },
  {
    id: 'javascript-open-action',
    description: '/OpenAction pointing at a JavaScript action',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/OpenAction 4 0 R', [
          { body: `<< /Type /Action /S /JavaScript /JS ${BENIGN_SCRIPT} >>` },
        ]),
      }),
    expectedCounts: { obj: 4, endobj: 4, '/JS': 1, '/JavaScript': 1, '/OpenAction': 1, '/AA': 0 },
  },
  {
    id: 'additional-actions-script-stream',
    description: 'Page /AA trigger whose /JS is a stream',
    build: () =>
      createTestPdf({
        objects: [
          BASIC_OBJECTS[0]!,
          BASIC_OBJECTS[1]!,
          { body: '<< /Type /Page /Parent 2 0 R /AA << /O 4 0 R >> >>' },
          { body: '<< /S /JavaScript /JS 5 0 R >>' },
          { body: '<< /Length 44 >>', stream: '// PDF Signal benign fixture, no behaviour.' },
        ],
      }),
    expectedCounts: { obj: 5, stream: 1, endstream: 1, '/AA': 1, '/JS': 1, '/JavaScript': 1 },
  },
  {
    id: 'all-indicators',
    description: 'Every PDFiD indicator keyword at least once',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries(
          '/OpenAction 4 0 R /AcroForm << /Fields [] /XFA 6 0 R >> /Names << /EmbeddedFiles 7 0 R >>',
          [
            { body: `<< /S /JavaScript /JS ${BENIGN_SCRIPT} /Next 5 0 R >>` },
            { body: '<< /S /Launch /F (placeholder.txt) >>' },
            { body: '<< /Length 7 >>', stream: '<xdp/>' },
            { body: '<< /Type /EmbeddedFile /Length 5 >>', stream: 'hello' },
            { body: '<< /Type /ObjStm /N 0 /First 0 /Length 0 >>', stream: '' },
            {
              body: '<< /Type /XObject /Subtype /Image /Filter /JBIG2Decode /Length 0 >>',
              stream: '',
            },
            { body: '<< /Type /Annot /Subtype /RichMedia /AA << >> >>' },
            { body: '<< /Predictor 2 /Colors 16777217 >>' },
          ],
        ),
        trailerEntries: ' /Encrypt 99 0 R',
      }),
    expectedCounts: {
      '/Encrypt': 1,
      '/ObjStm': 1,
      '/JS': 1,
      '/JavaScript': 1,
      '/AA': 1,
      '/OpenAction': 1,
      '/AcroForm': 1,
      '/JBIG2Decode': 1,
      '/RichMedia': 1,
      '/Launch': 1,
      '/EmbeddedFile': 1,
      '/XFA': 1,
      '/Colors > 2^24': 1,
    },
  },
  {
    id: 'hex-obfuscated-names',
    description: 'Indicator names written with #xx escapes',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/Open#41ction 4 0 R', [
          { body: `<< /S /J#61vaScript /#4A#53 ${BENIGN_SCRIPT} >>` },
          { body: '<< /S /Java#53cript /L#61unch 6 0 R >>' },
          { body: '<< /Ty#70e /Page /Parent 2 0 R >>' },
        ]),
      }),
    expectedCounts: { '/OpenAction': 1, '/JavaScript': 2, '/JS': 1, '/Launch': 1, '/Page': 2 },
    expectedHexcodeCounts: {
      '/OpenAction': 1,
      '/JavaScript': 2,
      '/JS': 1,
      '/Launch': 1,
      '/Page': 0,
    },
  },
  {
    id: 'mixed-plain-and-hex',
    description: 'The same name written plainly and with escapes, including lowercase hex',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/OpenAction 4 0 R', [
          { body: `<< /S /JavaScript /JS ${BENIGN_SCRIPT} >>` },
          { body: `<< /S /#4aava#53cript /#4a#53 ${BENIGN_SCRIPT} >>` },
        ]),
      }),
    expectedCounts: { '/JavaScript': 2, '/JS': 2, '/OpenAction': 1 },
    expectedHexcodeCounts: { '/JavaScript': 1, '/JS': 1, '/OpenAction': 0 },
  },
  {
    id: 'malformed-hex-escapes',
    description: '# not followed by two hex digits inside names',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/Open#ZZAction 4 0 R', [
          { body: '<< /JS#G1 (x) /Java#5 (y) /#4 /A#4Z >>' },
          { body: '<< /Text (#4A#53 outside a name) >>' },
        ]),
        suffix: '/JS#4',
      }),
    expectedCounts: { '/OpenAction': 0, '/JS': 2, '/JavaScript': 0 },
    expectedHexcodeCounts: { '/JS': 0 },
  },
  {
    id: 'case-sensitivity',
    description: 'Case variants that PDF readers do not treat as the keywords',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/openaction 4 0 R /OPENACTION 4 0 R', [
          { body: '<< /S /javascript /js (a) /JAVASCRIPT /Js /page /PAGE /aa /launch >>' },
          { body: 'OBJ Obj ENDOBJ Stream XREF Trailer' },
        ]),
      }),
    expectedCounts: {
      obj: 5,
      endobj: 5,
      stream: 0,
      '/OpenAction': 0,
      '/JavaScript': 0,
      '/JS': 0,
      '/Page': 1,
      '/AA': 0,
      '/Launch': 0,
    },
  },
  {
    id: 'keyword-boundaries',
    description: 'Words that contain or extend keywords',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          { body: '<< /JS_x (a) /JS.y (b) /JS-z (c) /JSX (d) /JavaScriptX /XJavaScript /Pages >>' },
          { body: '<< /Note (endobjx xobj objx startxrefs xxref) /JS(e) /Launch/Launch >>' },
        ]),
      }),
    expectedCounts: {
      '/JS': 4,
      '/JavaScript': 0,
      '/Launch': 2,
      obj: 5,
      endobj: 5,
      xref: 1,
      startxref: 1,
    },
  },
  {
    id: 'keywords-in-stream-data',
    description: 'Keywords inside stream data are still counted, as in PDFiD',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          {
            body: '<< /Length 60 >>',
            stream: 'BT /F1 12 Tf (text) Tj ET /JavaScript /OpenAction 7 0 obj endobj',
          },
        ]),
      }),
    expectedCounts: {
      '/JavaScript': 1,
      '/OpenAction': 1,
      obj: 5,
      endobj: 5,
      stream: 1,
      endstream: 1,
    },
  },
  {
    id: 'keywords-in-strings-and-comments',
    description: 'PDFiD does not parse strings or comments, so names inside them count',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/Title (/JavaScript in a string)', [
          { body: '<< /Note (call /Launch here) >>\n% /OpenAction mentioned in a comment' },
        ]),
      }),
    expectedCounts: { '/JavaScript': 1, '/Launch': 1, '/OpenAction': 1 },
  },
  {
    id: 'ordinary-text',
    description: 'Keyword-like words without a slash are not names',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          {
            body: '<< /Length 70 >>',
            stream: 'BT (Click to Launch the JavaScript OpenAction demo on this Page) Tj ET',
          },
        ]),
      }),
    expectedCounts: { '/Launch': 0, '/JavaScript': 0, '/OpenAction': 0, '/Page': 1 },
  },
  {
    id: 'binary-stream-data',
    description: 'All 256 byte values and invalid UTF-8 inside a stream',
    build: () => {
      const everyByte = Array.from({ length: 256 }, (_, value) => value);
      return createTestPdf({
        objects: withCatalogEntries('', [
          {
            body: '<< /Length 300 /Filter /FlateDecode >>',
            stream: bytes(
              everyByte,
              [0xc3, 0x28, 0xa0, 0xa1, 0xe2, 0x28, 0xa1, 0xf0, 0x28, 0x8c, 0xbc],
            ),
          },
          { body: `<< /S /JavaScript /JS ${BENIGN_SCRIPT} >>` },
        ]),
      });
    },
    expectedCounts: { '/JavaScript': 1, '/JS': 1, stream: 1, endstream: 1 },
  },
  {
    id: 'high-entropy-stream',
    description: 'Pseudo-random stream data for entropy statistics',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          { body: '<< /Length 4096 /Filter /FlateDecode >>', stream: pseudoRandomBytes(4096) },
        ]),
      }),
  },
  {
    id: 'stream-keywords-inside-stream',
    description: 'stream/endstream words appearing inside stream data change the stream state',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          { body: '<< /Length 40 >>', stream: 'data stream more endstream tail data' },
        ]),
      }),
    expectedCounts: { stream: 2, endstream: 2 },
  },
  {
    id: 'incremental-update',
    description: 'Original revision plus an appended update with its own %%EOF',
    build: () => {
      const original = createTestPdf({ objects: BASIC_OBJECTS });
      const update = bytes(
        '4 0 obj\n<< /Producer (update) >>\nendobj\n',
        'xref\n0 1\n0000000000 65535 f \n4 1\n0000000500 00000 n \n',
        'trailer\n<< /Size 5 /Root 1 0 R /Prev 9 >>\nstartxref\n600\n%%EOF\n',
      );
      return bytes(original, update);
    },
    expectedCounts: { obj: 4, endobj: 4, xref: 2, trailer: 2, startxref: 2 },
  },
  {
    id: 'trailing-data',
    description: 'Non-whitespace data appended after the last %%EOF',
    build: () =>
      createTestPdf({ objects: BASIC_OBJECTS, suffix: 'APPENDED PAYLOAD PLACEHOLDER\n' }),
  },
  {
    id: 'trailing-whitespace',
    description: 'Only whitespace after the last %%EOF',
    build: () => createTestPdf({ objects: BASIC_OBJECTS, suffix: '\n\n  \t' }),
  },
  {
    id: 'eof-crlf',
    description: '%%EOF followed by CR LF',
    build: () => createTestPdf({ objects: BASIC_OBJECTS, eof: '%%EOF\r\n' }),
  },
  {
    id: 'eof-without-newline',
    description: 'Data ends exactly with %%EOF',
    build: () => createTestPdf({ objects: BASIC_OBJECTS, eof: '%%EOF' }),
  },
  {
    id: 'eof-state-machine-quirks',
    description: 'Marker sequences that the upstream EOF state machine handles unusually',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          { body: '<< >>\n%%%EOF\n%%EOF %%EOF\n%%EOF\tX\n%%EOFX\n' },
        ]),
        eof: '%%EOF\r%%EOF\n',
      }),
  },
  {
    id: 'truncated-in-stream',
    description: 'File cut off in the middle of stream data',
    build: () => {
      const complete = createTestPdf({
        objects: withCatalogEntries('', [
          { body: '<< /Length 100 >>', stream: pseudoRandomBytes(100, 7) },
        ]),
      });
      const cut = complete.findIndex(
        (_, index) =>
          complete[index] === 0x73 &&
          String.fromCharCode(...complete.subarray(index, index + 6)) === 'stream',
      );
      return complete.slice(0, cut + 40);
    },
    expectedCounts: { stream: 1, endstream: 0, xref: 0, trailer: 0, startxref: 0 },
  },
  {
    id: 'no-header',
    description: 'PDF objects without any %PDF header',
    build: () => createTestPdf({ header: null, objects: BASIC_OBJECTS }),
  },
  {
    id: 'header-after-prefix',
    description: 'Junk bytes before the %PDF header (within the first 1024 bytes)',
    build: () =>
      createTestPdf({ prefix: 'GARBAGE BEFORE HEADER /JavaScript obj\n', objects: BASIC_OBJECTS }),
  },
  {
    id: 'header-beyond-1024-bytes',
    description: '%PDF header that starts after the first 1024 bytes',
    build: () => createTestPdf({ prefix: `${'x'.repeat(1100)}\n`, objects: BASIC_OBJECTS }),
  },
  {
    id: 'header-malformed-version',
    description: 'Header without a numeric version',
    build: () => createTestPdf({ header: '%PDF-X.Y', objects: BASIC_OBJECTS }),
  },
  {
    id: 'header-unpublished-version',
    description: 'Header declaring an unpublished version',
    build: () => createTestPdf({ header: '%PDF-1.9', objects: BASIC_OBJECTS }),
  },
  {
    id: 'header-without-line-break',
    description: 'Header followed by data without a CR or LF in the next 10 bytes',
    build: () => bytes('%PDF-1.4 obj /JS endobj /OpenAction %%EOF\n'),
  },
  {
    id: 'header-only-short',
    description: 'Eight-byte file containing only %PDF-1.4',
    build: () => bytes('%PDF-1.4'),
    knownPdfidError: {
      mode: 'both',
      reason:
        'IndexError while reading the header (caught internally), then an uncaught ZeroDivisionError computing entropy',
    },
  },
  {
    id: 'empty',
    description: 'Zero-byte input',
    build: () => new Uint8Array(0),
    knownPdfidError: {
      mode: 'forced',
      reason: 'ZeroDivisionError while computing entropy for empty data',
    },
  },
  {
    id: 'colors-cve-2009-3459',
    description: '/Colors values above, at and below 2^24',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          { body: '<< /Colors 16777217 >>' },
          { body: '<< /Colors 16777216 >>' },
          { body: '<< /Colors 0000016777217 >>' },
          { body: '<< /Colors 99999999999999999999999 >>' },
          { body: '<< /Colors /16777300 /Colors 1e9 /Colors 3 >>' },
          { body: '<< /Col#6Frs 20000000 /Col#6Fors 30000000 >>' },
        ]),
        suffix: '/Colors 16777999',
      }),
    expectedCounts: { '/Colors > 2^24': 5 },
  },
  {
    id: 'colors-superscript-digit',
    description: '/Colors followed by a name decoding to a digit and a superscript two',
    build: () =>
      createTestPdf({ objects: withCatalogEntries('', [{ body: '<< /Colors /1#B2 >>' }]) }),
    expectedCounts: { '/Colors > 2^24': 0 },
    knownPdfidError: {
      mode: 'both',
      reason: "ValueError: Python's isdigit() accepts '²' but int() rejects it",
    },
  },
  {
    id: 'dates',
    description: 'PDF date strings in several shapes',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          {
            body:
              "<< /CreationDate (D:20240101120000+01'00') /ModDate (D:20240102130000Z) " +
              "/A (D:20240103) /B (D:20240104140000) /C (D:202401041400001) /D (D:2024DD:20240105150000-05'30') >>",
          },
        ]),
      }),
  },
  {
    id: 'long-names',
    description: 'Names longer than the retained word buffer',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          {
            body: `<< /${'A'.repeat(300)} 1 /JavaScript${'B'.repeat(300)} 2 /${'7'.repeat(400)} >>`,
          },
        ]),
      }),
    expectedCounts: { '/JavaScript': 0 },
  },
  {
    id: 'hex-outside-names',
    description: 'Hex sequences that are not inside names are never decoded',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [{ body: '<< /A #4A#53 /B (#4A#53) /C <4A53> #2FJS >>' }]),
      }),
    expectedCounts: { '/JS': 0 },
  },
  {
    id: 'hex-decoded-delimiters',
    description: 'Escapes that decode to delimiters and whitespace stay inside the name',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          { body: '<< /Java#2FScript 1 /Java#20Script 2 /J#00S 3 >>' },
        ]),
      }),
    expectedCounts: { '/JavaScript': 0, '/JS': 0 },
  },
  // Deep-analysis fixtures: content hidden or resolved beyond what a keyword count shows.
  {
    id: 'objstm-hidden-javascript',
    description:
      'Catalog and a JavaScript open action stored only inside a compressed object stream',
    build: () =>
      createTestPdf({
        objects: [
          { body: '<< /Type /Pages /Kids [2 0 R] /Count 1 >>' },
          { body: '<< /Type /Page /Parent 1 0 R >>' },
          objectStream([
            { number: 10, body: '<< /Type /Catalog /Pages 1 0 R /OpenAction 11 0 R >>' },
            {
              number: 11,
              body: "<< /S /JavaScript /JS (app.alert('PDF Signal test fixture');) >>",
            },
          ]),
        ],
      }),
    expectedCounts: { '/ObjStm': 1, '/JavaScript': 0, '/JS': 0, '/OpenAction': 0, '/Page': 1 },
  },
  {
    id: 'openaction-destination',
    description: '/OpenAction that only opens page 1 at "fit page" zoom',
    build: () => createTestPdf({ objects: withCatalogEntries('/OpenAction [3 0 R /Fit]') }),
    expectedCounts: { '/OpenAction': 1, '/JavaScript': 0 },
  },
  {
    id: 'openaction-javascript-stream',
    description:
      '/OpenAction running a compressed script stream with suspicious (inert) constructs',
    build: () => {
      const script = compress(
        "/* PDF Signal benign fixture: inert text */ var filler = unescape('%u0c0c%u0c0c'); eval('1 + 1');",
      );
      return createTestPdf({
        objects: withCatalogEntries('/OpenAction 4 0 R', [
          { body: '<< /S /JavaScript /JS 5 0 R >>' },
          { body: `<< /Filter /FlateDecode /Length ${script.length} >>`, stream: script },
        ]),
      });
    },
    expectedCounts: { '/OpenAction': 1, '/JavaScript': 1, '/JS': 1 },
  },
  {
    id: 'document-level-javascript',
    description: 'Document-level script in the /Names /JavaScript tree (runs on open)',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/Names << /JavaScript << /Names [(init) 4 0 R] >> >>', [
          { body: "<< /S /JavaScript /JS (app.alert('Hello');) >>" },
        ]),
      }),
    expectedCounts: { '/JavaScript': 2, '/JS': 1, '/OpenAction': 0 },
  },
  {
    id: 'form-field-script',
    description: 'Form field keystroke script (interactive, common in legitimate forms)',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/AcroForm << /Fields [4 0 R] >>', [
          {
            body: '<< /Type /Annot /Subtype /Widget /FT /Tx /T (amount) /AA << /K << /S /JavaScript /JS (AFNumber_Keystroke(2);) >> >> >>',
          },
        ]),
      }),
    expectedCounts: { '/AA': 1, '/JS': 1, '/JavaScript': 1, '/AcroForm': 1 },
  },
  {
    id: 'launch-executable',
    description: '/OpenAction launching an executable (calc.exe)',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/OpenAction << /S /Launch /Win << /F (calc.exe) >> >>'),
      }),
    expectedCounts: { '/Launch': 1, '/OpenAction': 1 },
  },
  {
    id: 'openaction-uri',
    description: '/OpenAction that opens a web address',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/OpenAction << /S /URI /URI (https://example.com/) >>'),
      }),
    expectedCounts: { '/OpenAction': 1 },
  },
  {
    id: 'xfa-script',
    description: 'Compressed XFA form containing a script element',
    build: () => {
      const xfa = compress(
        '<xdp:xdp><template><subform><event activity="initialize"><script contentType="application/x-javascript">xfa.host.messageBox("PDF Signal fixture");</script></event></subform></template></xdp:xdp>',
      );
      return createTestPdf({
        objects: withCatalogEntries('/AcroForm << /XFA 4 0 R >>', [
          { body: `<< /Filter /FlateDecode /Length ${xfa.length} >>`, stream: xfa },
        ]),
      });
    },
    expectedCounts: { '/XFA': 1, '/AcroForm': 1, '/JavaScript': 0 },
  },
  {
    id: 'obfuscated-filter-and-action',
    description:
      'Hex-escaped action type and filter name, with a script building strings from char codes',
    build: () => {
      const script = compress('var name = String.fromCharCode(104, 105);');
      return createTestPdf({
        objects: withCatalogEntries('/OpenAction 4 0 R', [
          { body: '<< /S /Java#53cript /JS 5 0 R >>' },
          { body: `<< /Filter /Fl#61teDecode /Length ${script.length} >>`, stream: script },
        ]),
      });
    },
    expectedCounts: { '/JavaScript': 1, '/JS': 1 },
    expectedHexcodeCounts: { '/JavaScript': 1 },
  },
  {
    id: 'filter-chain-script',
    description: 'Script stream encoded with [/ASCIIHexDecode /FlateDecode]',
    build: () => {
      const compressed = compress("util.printf('%45000f', 0);");
      const hex =
        Array.from(compressed, (byte) => byte.toString(16).padStart(2, '0')).join('') + '>';
      return createTestPdf({
        objects: withCatalogEntries('', [
          { body: '<< /S /JavaScript /JS 5 0 R >>' },
          {
            body: `<< /Filter [/ASCIIHexDecode /FlateDecode] /Length ${hex.length} >>`,
            stream: hex,
          },
        ]),
      });
    },
    expectedCounts: { '/JS': 1, '/JavaScript': 1 },
  },
  {
    id: 'executable-attachment',
    description: 'Embedded file whose name ends in .exe behind a .pdf double extension',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('/Names << /EmbeddedFiles << /Names [(invoice) 4 0 R] >> >>', [
          {
            body: '<< /Type /Filespec /F (invoice.pdf.exe) /UF (invoice.pdf.exe) /EF << /F 5 0 R >> >>',
          },
          { body: '<< /Type /EmbeddedFile /Length 5 >>', stream: 'hello' },
        ]),
      }),
    expectedCounts: { '/EmbeddedFile': 1 },
  },
  {
    id: 'network-share-open-action',
    description:
      '/OpenAction opening a document on a network share (documentation address 192.0.2.1)',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries(
          '/OpenAction << /S /GoToR /F <5C5C3139322E302E322E315C73686172655C646F632E706466> /D [0 /Fit] >>',
        ),
      }),
    expectedCounts: { '/OpenAction': 1 },
  },
  {
    id: 'javascript-uri-link',
    description: 'Link annotation whose URI uses the javascript: scheme',
    build: () =>
      createTestPdf({
        objects: withCatalogEntries('', [
          {
            body: '<< /Type /Annot /Subtype /Link /A << /S /URI /URI (javascript:app.alert(1)) >> >>',
          },
        ]),
      }),
    expectedCounts: { '/JavaScript': 0 },
  },
];

export function getFixture(id: string): FixtureDefinition {
  const fixture = FIXTURES.find((candidate) => candidate.id === id);
  if (fixture === undefined) {
    throw new Error(`Unknown fixture: ${id}`);
  }
  return fixture;
}
