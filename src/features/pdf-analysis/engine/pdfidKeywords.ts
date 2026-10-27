import type { KeywordDefinition } from '../types/analysis';

/** Version of Didier Stevens' pdfid.py whose behaviour this engine reproduces. */
export const PDFID_REFERENCE_VERSION = '0.2.10';

/** Name PDFiD uses for its CVE-2009-3459 counter. */
export const COLORS_COUNTER_NAME = '/Colors > 2^24';

/** `/Colors` values strictly greater than this are counted (2^24, i.e. more than 3 bytes). */
export const COLORS_THRESHOLD = 2 ** 24;

/**
 * The default keyword list from pdfid.py 0.2.10, in upstream order. Keywords without a
 * leading slash are matched as bare words; keywords with a slash are matched as PDF names.
 * Matching is case-sensitive and exact: `/Pages` does not count as `/Page`.
 */
export const PDFID_KEYWORDS: readonly KeywordDefinition[] = [
  { name: 'obj', kind: 'structural', category: 'structure', label: 'Start of an indirect object' },
  { name: 'endobj', kind: 'structural', category: 'structure', label: 'End of an indirect object' },
  { name: 'stream', kind: 'structural', category: 'structure', label: 'Start of stream data' },
  { name: 'endstream', kind: 'structural', category: 'structure', label: 'End of stream data' },
  { name: 'xref', kind: 'structural', category: 'structure', label: 'Cross-reference table' },
  { name: 'trailer', kind: 'structural', category: 'structure', label: 'Trailer dictionary' },
  {
    name: 'startxref',
    kind: 'structural',
    category: 'structure',
    label: 'Offset of the last cross-reference section',
  },
  { name: '/Page', kind: 'structural', category: 'document', label: 'Page object' },
  { name: '/Encrypt', kind: 'indicator', category: 'encryption', label: 'Encryption dictionary' },
  {
    name: '/ObjStm',
    kind: 'indicator',
    category: 'object-streams',
    label: 'Object stream (objects stored inside a compressed stream)',
  },
  { name: '/JS', kind: 'indicator', category: 'javascript', label: 'JavaScript code entry' },
  {
    name: '/JavaScript',
    kind: 'indicator',
    category: 'javascript',
    label: 'JavaScript action or document-level script',
  },
  {
    name: '/AA',
    kind: 'indicator',
    category: 'automatic-action',
    label: 'Additional actions triggered by events',
  },
  {
    name: '/OpenAction',
    kind: 'indicator',
    category: 'automatic-action',
    label: 'Action performed when the document opens',
  },
  { name: '/AcroForm', kind: 'indicator', category: 'forms', label: 'Interactive form (AcroForm)' },
  {
    name: '/JBIG2Decode',
    kind: 'indicator',
    category: 'exploit-history',
    label: 'JBIG2 image compression filter',
  },
  {
    name: '/RichMedia',
    kind: 'indicator',
    category: 'embedded-content',
    label: 'Rich media annotation (for example Flash)',
  },
  {
    name: '/Launch',
    kind: 'indicator',
    category: 'external-action',
    label: 'Launch action (starts an application or opens a file)',
  },
  {
    name: '/EmbeddedFile',
    kind: 'indicator',
    category: 'embedded-content',
    label: 'Embedded file stream',
  },
  { name: '/XFA', kind: 'indicator', category: 'forms', label: 'XML Forms Architecture form' },
];

/**
 * PDFiD's extra counter for CVE-2009-3459: a `/Colors` name followed by an integer larger
 * than 2^24. It is not a token match, so it is defined separately from `PDFID_KEYWORDS`.
 */
export const COLORS_COUNTER: KeywordDefinition = {
  name: COLORS_COUNTER_NAME,
  kind: 'indicator',
  category: 'exploit-history',
  label: 'Oversized /Colors value associated with CVE-2009-3459',
};

/** Every counter PDFiD reports, in output order. */
export const ALL_COUNTERS: readonly KeywordDefinition[] = [...PDFID_KEYWORDS, COLORS_COUNTER];

/** Longest keyword, excluding the leading slash. Longer words can never match. */
export const MAX_KEYWORD_WORD_LENGTH = Math.max(
  ...PDFID_KEYWORDS.map((keyword) => keyword.name.replace(/^\//, '').length),
);
