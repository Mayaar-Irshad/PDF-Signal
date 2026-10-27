/**
 * Plain-language explanations for every PDFiD counter. These are static strings written for
 * PDF Signal; nothing here is derived from a scanned file.
 */
export interface IndicatorExplanation {
  /** What the PDF keyword represents. */
  readonly whatItIs: string;
  /** Why an analyst might look closer when it is present. */
  readonly whyInvestigate: string;
  /** What its presence or absence can and cannot tell you. */
  readonly limits: string;
}

const STRUCTURE_LIMITS =
  'Structural counts describe the layout of the file. On their own they say nothing about whether it is malicious.';

export const INDICATOR_EXPLANATIONS: Readonly<Record<string, IndicatorExplanation>> = {
  obj: {
    whatItIs: 'Marks the start of an indirect object, the building block of a PDF.',
    whyInvestigate:
      'A count that differs from "endobj" can point to a damaged, truncated or deliberately malformed file.',
    limits: STRUCTURE_LIMITS,
  },
  endobj: {
    whatItIs: 'Marks the end of an indirect object.',
    whyInvestigate: 'Compared with "obj" to spot incomplete or malformed objects.',
    limits: STRUCTURE_LIMITS,
  },
  stream: {
    whatItIs:
      'Starts a block of stream data such as page content, images, fonts or embedded files.',
    whyInvestigate:
      'Streams are usually compressed, so their contents (including scripts) are invisible to a keyword scan.',
    limits: STRUCTURE_LIMITS,
  },
  endstream: {
    whatItIs: 'Ends a block of stream data.',
    whyInvestigate: 'Compared with "stream" to spot truncated or malformed streams.',
    limits: STRUCTURE_LIMITS,
  },
  xref: {
    whatItIs: 'Starts a cross-reference table, the index readers use to locate objects.',
    whyInvestigate:
      'Files that were updated incrementally contain several tables. Files using cross-reference streams may contain none.',
    limits: STRUCTURE_LIMITS,
  },
  trailer: {
    whatItIs: 'Starts the trailer dictionary that points to the document catalog.',
    whyInvestigate:
      'Several trailers usually mean incremental updates; none may mean cross-reference streams are used.',
    limits: STRUCTURE_LIMITS,
  },
  startxref: {
    whatItIs: 'Gives the offset of the last cross-reference section, near the end of the file.',
    whyInvestigate: 'A missing value can indicate a truncated file.',
    limits: STRUCTURE_LIMITS,
  },
  '/Page': {
    whatItIs: 'Counts page objects (/Type /Page). /Pages tree nodes are not included.',
    whyInvestigate:
      'Many historical malicious PDFs had a single page, because the document existed only to deliver its payload.',
    limits:
      'Page count is weak evidence: most legitimate one-page documents are harmless, and pages inside object streams are not counted.',
  },
  '/Encrypt': {
    whatItIs: 'An encryption dictionary: strings and streams in the file are encrypted.',
    whyInvestigate:
      'Encryption is legitimate (for example permission restrictions), but it also hides stream contents from inspection tools.',
    limits:
      'Names in dictionaries usually stay readable, so keyword counts remain meaningful, but anything inside encrypted streams cannot be inspected.',
  },
  '/ObjStm': {
    whatItIs: 'An object stream: several objects stored together inside one compressed stream.',
    whyInvestigate:
      'Object streams are common in modern PDFs, but they can also hide keywords such as /JavaScript from a byte-level scan.',
    limits:
      'Keywords inside compressed object streams are not counted. When object streams are present, a zero count for other indicators is much weaker evidence.',
  },
  '/JS': {
    whatItIs: 'An entry holding JavaScript code (directly or in a referenced stream).',
    whyInvestigate:
      'JavaScript in PDFs has been used to exploit reader vulnerabilities and to run actions without the user noticing.',
    limits:
      'Legitimate forms use JavaScript for calculations and validation. Presence alone does not prove malicious intent; the script itself must be reviewed.',
  },
  '/JavaScript': {
    whatItIs: 'A JavaScript action type or a document-level JavaScript name tree.',
    whyInvestigate:
      'Indicates the document is designed to run scripts. Usually appears together with /JS.',
    limits:
      'Common in interactive forms. PDF Signal never executes the script, and cannot tell what it does.',
  },
  '/AA': {
    whatItIs:
      'Additional actions: actions triggered by events such as opening a page, focusing a field or closing the document.',
    whyInvestigate:
      'Automatic triggers can run scripts or other actions without an explicit click.',
    limits:
      'Form fields often use /AA for formatting and calculations. Review what the action does.',
  },
  '/OpenAction': {
    whatItIs: 'An action the reader performs when the document is opened.',
    whyInvestigate:
      'Combined with JavaScript or /Launch, it can start code as soon as the file is opened.',
    limits:
      'Often legitimate, for example to open at a specific page or zoom level. Check what the action points to.',
  },
  '/AcroForm': {
    whatItIs: 'An interactive form (AcroForm).',
    whyInvestigate: 'Forms can carry JavaScript and are part of the attack surface of PDF readers.',
    limits:
      'Interactive forms are very common in legitimate documents. PDF Signal records this as context, not as a finding on its own.',
  },
  '/JBIG2Decode': {
    whatItIs: 'A filter for JBIG2-compressed monochrome images.',
    whyInvestigate:
      'JBIG2 decoders have had serious vulnerabilities (for example CVE-2009-0658 and CVE-2021-30860), and exploits have used this filter.',
    limits:
      'Scanned documents legitimately use JBIG2. Presence alone does not indicate an exploit.',
  },
  '/RichMedia': {
    whatItIs: 'Rich media annotations, historically used to embed Flash content.',
    whyInvestigate:
      'Embedded Flash was a frequent exploitation vector; Flash is no longer supported by current readers.',
    limits:
      'Rare in modern legitimate documents, but presence alone does not show the content is harmful.',
  },
  '/Launch': {
    whatItIs: 'A launch action that asks the reader to start an application or open a file.',
    whyInvestigate: 'Launch actions have been abused to run commands or open dropped files.',
    limits: 'Modern readers usually warn before launching. Review the target of the action.',
  },
  '/EmbeddedFile': {
    whatItIs: 'A file embedded in the PDF as an attachment.',
    whyInvestigate:
      'Attachments can carry executables, scripts or documents with their own exploits.',
    limits:
      'Attachments are legitimate in many workflows (for example invoices with data files). The attachment needs separate analysis.',
  },
  '/XFA': {
    whatItIs: 'An XML Forms Architecture form, an XML-based form technology.',
    whyInvestigate: 'XFA forms can contain scripts and have been used in exploits.',
    limits:
      'XFA is deprecated in PDF 2.0 but still found in legitimate government and business forms.',
  },
  '/Colors > 2^24': {
    whatItIs: 'A /Colors value larger than 2^24 (16,777,216), counted by PDFiD.',
    whyInvestigate:
      'Such values were used to exploit CVE-2009-3459, a heap overflow in old Adobe Reader versions. Legitimate files have small /Colors values.',
    limits: 'Only detects that specific historical pattern.',
  },
};

/** Fallback for counters without a dedicated explanation. */
export const GENERIC_EXPLANATION: IndicatorExplanation = {
  whatItIs: 'A PDF keyword counted by PDFiD.',
  whyInvestigate: 'Review the keyword in context with a PDF analysis tool.',
  limits: 'Keyword counts are static signals and do not prove intent.',
};

export function explanationFor(name: string): IndicatorExplanation {
  return INDICATOR_EXPLANATIONS[name] ?? GENERIC_EXPLANATION;
}

export const TRIAGE_DISCLAIMER =
  'PDF Signal is a static triage tool, not an antivirus product. It examines the structure, actions and scripts of the file without rendering or executing anything. Findings are signals for further investigation; they do not prove that a file is malicious, and their absence does not prove that a file is safe.';
