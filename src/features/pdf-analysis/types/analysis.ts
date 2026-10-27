/**
 * Result schema for the PDF Signal scanning engine and triage assessment.
 *
 * The scanner (`ScanResult`) reports facts measured from the file bytes. The assessment
 * (`Assessment`) is a separate, deterministic interpretation of those facts. Neither
 * structure ever contains raw PDF bytes or extracted document text; the only PDF-derived
 * strings are the PDF header (at most 10 characters), PDF name tokens and PDF date values,
 * all of which are rendered as plain text.
 */

export const SCAN_RESULT_SCHEMA_VERSION = 2;

export type KeywordCategory =
  | 'structure'
  | 'document'
  | 'encryption'
  | 'object-streams'
  | 'javascript'
  | 'automatic-action'
  | 'forms'
  | 'embedded-content'
  | 'external-action'
  | 'exploit-history';

/** `structural` counters describe the file layout; `indicator` counters are triage signals. */
export type KeywordKind = 'structural' | 'indicator';

export interface KeywordDefinition {
  /** Keyword exactly as PDFiD reports it, e.g. `obj`, `/JavaScript` or `/Colors > 2^24`. */
  readonly name: string;
  readonly kind: KeywordKind;
  readonly category: KeywordCategory;
  /** One-line description of what the counter measures. */
  readonly label: string;
}

export interface KeywordCount {
  readonly name: string;
  readonly kind: KeywordKind;
  readonly category: KeywordCategory;
  readonly label: string;
  /** Number of occurrences, counted with PDFiD 0.2.10 tokenization rules. */
  readonly count: number;
  /** Occurrences that were written with at least one `#xx` hexadecimal escape. */
  readonly hexcodeCount: number;
}

export interface HeaderAnalysis {
  /** True when `%PDF` occurs within the first 1024 bytes (PDFiD's relaxed header rule). */
  readonly found: boolean;
  /** Byte offset of `%PDF`, or null when not found. */
  readonly offset: number | null;
  /** First 10 characters of the header line, escaped for display (PDFiD's `Header` field). */
  readonly text: string | null;
  /** Version number such as `1.7` when the header has the form `%PDF-<major>.<minor>`. */
  readonly version: string | null;
  /** True when `version` is one of the published PDF versions (1.0–1.7, 2.0). */
  readonly versionRecognized: boolean;
  /** First byte offset fed to the keyword scanner; header bytes before it are not tokenized. */
  readonly scanStartOffset: number;
  /** True when PDFiD 0.2.10 would raise an IndexError while reading this header. */
  readonly pdfidWouldError: boolean;
}

export interface EofAnalysis {
  /** Number of `%%EOF` markers recognized by PDFiD's EOF state machine. */
  readonly eofCount: number;
  /** PDFiD's `After last %%EOF` value; null when no marker was recognized. */
  readonly bytesAfterLastEof: number | null;
  readonly trailingDataPresent: boolean;
  /** Whether every byte after the last marker is PDF whitespace; null when not applicable. */
  readonly trailingDataWhitespaceOnly: boolean | null;
}

export interface EntropyStatistics {
  readonly totalBytes: number;
  /** Shannon entropy in bits per byte (0–8); null when there are no bytes. */
  readonly totalEntropy: number | null;
  readonly streamBytes: number;
  /** Null when no bytes were classified as stream data (PDFiD prints `N/A`). */
  readonly streamEntropy: number | null;
  readonly nonStreamBytes: number;
  readonly nonStreamEntropy: number | null;
}

export interface ObfuscationStatistics {
  /** Sum of `hexcodeCount` over every keyword. */
  readonly hexEncodedKeywordOccurrences: number;
  /** PDF names of any kind that contained at least one valid `#xx` escape. */
  readonly namesWithHexEscapes: number;
  /** `#` characters inside a name that were not followed by two hexadecimal digits. */
  readonly malformedHexEscapes: number;
}

export interface StructureSummary {
  readonly objectKeywordsBalanced: boolean;
  readonly streamKeywordsBalanced: boolean;
  readonly headerAtFileStart: boolean;
  readonly endedInsideStream: boolean;
  readonly incrementalUpdatesLikely: boolean;
}

export interface PdfDateEntry {
  /** Date value as PDFiD extracts it, e.g. `D:20240101120000+01'00`. */
  readonly value: string;
  /** Name that most recently preceded the date, e.g. `/ModDate`. */
  readonly name: string;
}

export interface NameCount {
  /** Name with non-printable or non-ASCII characters re-encoded as `#xx`. */
  readonly name: string;
  readonly count: number;
  readonly hexcodeCount: number;
}

export interface BoundedList<T> {
  readonly entries: readonly T[];
  /** Entries not retained because a resource limit was reached. */
  readonly omitted: number;
}

export type ScanMessageCode =
  | 'empty-input'
  | 'header-missing'
  | 'header-offset'
  | 'header-version-unrecognized'
  | 'forced-scan'
  | 'not-scanned'
  | 'eof-missing'
  | 'eof-multiple'
  | 'trailing-data'
  | 'ended-inside-stream'
  | 'names-truncated'
  | 'dates-truncated'
  | 'hash-unavailable';

export interface ScanMessage {
  readonly severity: 'info' | 'warning';
  readonly code: ScanMessageCode;
  readonly text: string;
}

export type ScanMode = 'standard' | 'forced';

export interface EngineInfo {
  readonly name: string;
  readonly version: string;
  readonly reference: string;
}

export interface ScanResult {
  readonly schemaVersion: typeof SCAN_RESULT_SCHEMA_VERSION;
  readonly engine: EngineInfo;
  readonly scannedAt: string;
  readonly durationMs: number;
  readonly sizeBytes: number;
  /** Lowercase hexadecimal SHA-256 of the scanned bytes, or null when unavailable. */
  readonly sha256: string | null;
  readonly mode: ScanMode;
  /** PDFiD's `IsPDF`: whether the relaxed `%PDF` header was found. */
  readonly isPdf: boolean;
  /** False when the header was missing and forced mode was not requested (PDFiD default). */
  readonly keywordScanPerformed: boolean;
  readonly header: HeaderAnalysis;
  readonly keywords: readonly KeywordCount[];
  readonly eof: EofAnalysis | null;
  readonly entropy: EntropyStatistics | null;
  readonly obfuscation: ObfuscationStatistics | null;
  readonly structure: StructureSummary | null;
  readonly dates: BoundedList<PdfDateEntry>;
  readonly names: BoundedList<NameCount>;
  readonly messages: readonly ScanMessage[];
  /** Cases where PDFiD 0.2.10 would behave differently on this input. */
  readonly compatibilityNotes: readonly string[];
  /**
   * PDF Signal's deep analysis, beyond PDFiD: decompressed object streams, resolved actions and
   * script pattern checks. Null when it was not run (no header, or not requested).
   */
  readonly deep: DeepScanResult | null;
}

export type ActionRisk = 'high' | 'medium' | 'low';

/** Aggregated actions that share a trigger and an action type. */
export interface ActionSummary {
  /** PDF key that triggers the action, e.g. `/OpenAction`, `/AA /O` or `/Names /JavaScript`. */
  readonly trigger: string;
  /** When the action runs, in plain language. */
  readonly when: string;
  /** True when the action runs without the user clicking or typing in the document. */
  readonly automatic: boolean;
  /** Action type from `/S`, or `Destination` for plain navigation, or `Unresolved`. */
  readonly action: string;
  readonly risk: ActionRisk;
  readonly count: number;
  /** Occurrences found only inside compressed object streams. */
  readonly hiddenCount: number;
}

export type ScriptPatternSeverity = 'high' | 'medium' | 'low';

/** A suspicious construct found in script content. The script text itself is never kept. */
export interface ScriptPatternHit {
  readonly id: string;
  readonly label: string;
  readonly severity: ScriptPatternSeverity;
  readonly description: string;
  /** Number of scripts in which the pattern was found. */
  readonly scripts: number;
}

export interface HiddenKeywordCount {
  readonly name: string;
  readonly count: number;
  readonly hexcodeCount: number;
}

export interface DeepScanResult {
  /** `complete`, `partial` (a limit, failure or missing browser feature) or `failed`. */
  readonly status: 'complete' | 'partial' | 'failed';
  readonly durationMs: number;
  readonly objectsIndexed: number;
  readonly objectStreams: number;
  readonly streamsDecoded: number;
  readonly decodedBytes: number;
  readonly decodeFailures: number;
  /** True when a trailer or cross-reference stream declares /Encrypt. */
  readonly encrypted: boolean;
  /** Object streams that were skipped, failed or truncated, so their content was not fully seen. */
  readonly objectStreamsIncomplete: number;
  /** Streams that decompressed past the per-stream limit (possible decompression bombs). */
  readonly decompressionBombs: number;
  /** PDFiD keywords counted inside decompressed object streams (non-zero counts only). */
  readonly hiddenKeywords: readonly HiddenKeywordCount[];
  /**
   * How often each PDFiD name keyword (without the slash) occurs in the parsed document
   * structure, as a dictionary key or name value. Keywords that PDFiD counts but that never
   * occur here only appear inside stream data (images, fonts, …), where they have no effect.
   */
  readonly structuralNames: Readonly<Record<string, number>>;
  readonly actions: readonly ActionSummary[];
  /** References to objects that could not be found while resolving actions. */
  readonly unresolvedReferences: number;
  readonly launchTargets: { readonly executable: number; readonly other: number };
  /** Embedded files (file specifications with /EF), classified by file-name extension. */
  readonly attachments: {
    readonly total: number;
    readonly executable: number;
    readonly archive: number;
    readonly macroDocument: number;
  };
  /** Action targets that point to network shares or use script URL schemes. */
  readonly targets: {
    readonly networkShare: number;
    readonly automaticNetworkShare: number;
    readonly scriptUri: number;
  };
  readonly scripts: {
    readonly found: number;
    readonly analyzed: number;
    readonly undecodable: number;
    readonly bytesAnalyzed: number;
    readonly xfaScripts: number;
  };
  readonly scriptPatterns: readonly ScriptPatternHit[];
  /** Fixed explanatory notes (limits reached, features unavailable, encryption). */
  readonly notes: readonly string[];
}

export type AssessmentLevel =
  'none-detected' | 'review' | 'multiple' | 'high-risk' | 'inconclusive';

/** `critical` findings put the overall result at `high-risk`. */
export type FindingSeverity = 'informational' | 'review' | 'priority' | 'critical';

export interface Finding {
  readonly id: string;
  readonly severity: FindingSeverity;
  readonly title: string;
  readonly detail: string;
  /** Keyword names or measurements that triggered the rule. */
  readonly evidence: readonly string[];
}

export interface KeywordInterpretation {
  readonly name: string;
  /** `danger` marks keywords that can make the document run code or launch programs. */
  readonly status: 'absent' | 'informational' | 'review' | 'danger';
  readonly text: string;
  /** Occurrences inside compressed object streams (deep analysis), not in the PDFiD count. */
  readonly hiddenCount: number;
}

export interface Assessment {
  readonly rulesVersion: string;
  readonly level: AssessmentLevel;
  readonly headline: string;
  readonly summary: string;
  /** The recommended next step for this level. */
  readonly advice: string;
  readonly findings: readonly Finding[];
  readonly interpretations: readonly KeywordInterpretation[];
  /** Conditions that limit what this scan can see (object streams, encryption, …). */
  readonly visibilityLimits: readonly string[];
  readonly disclaimer: string;
}
