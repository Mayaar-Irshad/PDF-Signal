import type {
  ActionRisk,
  ActionSummary,
  DeepScanResult,
  HiddenKeywordCount,
  ScriptPatternHit,
} from '../types/analysis';
import { latin1ToBytes, indexOfBytes } from './byteUtils';
import { findScriptPatterns, scriptBytesToText } from './javascriptPatterns';
import {
  DEFAULT_PARSE_LIMITS,
  dictGet,
  indexFileObjects,
  nameOf,
  parseObjectStream,
  parseValue,
  PdfLexer,
  type PdfObject,
  type PdfValue,
  type TokenBudget,
} from './pdfObjects';
import { COLORS_COUNTER_NAME, PDFID_KEYWORDS } from './pdfidKeywords';
import { scanKeywords } from './scanKeywords';
import { decodeStream, filtersOf, isDecompressionAvailable } from './streamFilters';

/**
 * Deep analysis: goes beyond PDFiD's byte-level keyword count to answer the questions a
 * keyword count cannot. Which keywords are hidden inside compressed object streams? What does
 * `/OpenAction` actually do: open a page, or run a script? Does script content use constructs
 * associated with exploits? Are there executable attachments or network-share links?
 *
 * Design rules:
 *   - Every definition of an object is analysed. A PDF can define the same object number more
 *     than once (incremental updates, or a decoy placed after the real object); when they
 *     disagree, the most dangerous interpretation wins.
 *   - Encryption is decided from the trailer or cross-reference stream, never from a token that
 *     could appear anywhere in the file.
 *   - Everything is bounded by one deadline and shared budgets (objects, tokens, decoded bytes,
 *     streams, scripts, action sources). Whatever is not inspected is reported, and the
 *     assessment treats incomplete coverage as a reason for caution.
 *   - Nothing derived from the document's content (script text, URLs, file names, unknown
 *     name tokens) is kept in the result; only counts, fixed labels and pattern identifiers.
 */

export interface DeepScanLimits {
  readonly maxObjects: number;
  readonly maxDecodedStreams: number;
  readonly maxDecodedBytesPerStream: number;
  readonly maxDecodedBytesTotal: number;
  readonly maxScripts: number;
  readonly maxScriptBytes: number;
  readonly maxVisitedValues: number;
  readonly maxActionSources: number;
  readonly maxActionDepth: number;
  readonly maxTokens: number;
  readonly timeBudgetMs: number;
}

export const DEFAULT_DEEP_SCAN_LIMITS: DeepScanLimits = {
  maxObjects: 100_000,
  maxDecodedStreams: 2_000,
  maxDecodedBytesPerStream: 16 * 1024 * 1024,
  maxDecodedBytesTotal: 96 * 1024 * 1024,
  maxScripts: 200,
  maxScriptBytes: 2 * 1024 * 1024,
  maxVisitedValues: 2_000_000,
  maxActionSources: 20_000,
  maxActionDepth: 16,
  maxTokens: 20_000_000,
  timeBudgetMs: 15_000,
};

export interface DeepScanOptions {
  readonly limits?: Partial<DeepScanLimits>;
  /** Overrides encryption detection (tests). By default it is read from the trailer. */
  readonly encrypted?: boolean;
  readonly onProgress?: (fraction: number) => void;
  readonly now?: () => number;
}

/** Action types defined by ISO 32000; anything else is reported as "Other". */
const ACTION_RISK: Readonly<Record<string, ActionRisk>> = {
  JavaScript: 'high',
  Launch: 'high',
  RichMediaExecute: 'high',
  ImportData: 'medium',
  SubmitForm: 'medium',
  GoToR: 'medium',
  GoToE: 'medium',
  GoToDp: 'low',
  URI: 'low',
  GoTo: 'low',
  GoTo3DView: 'low',
  Thread: 'low',
  Sound: 'low',
  Movie: 'low',
  Hide: 'low',
  Named: 'low',
  ResetForm: 'low',
  SetOCGState: 'low',
  Rendition: 'low',
  Trans: 'low',
  Destination: 'low',
  Other: 'medium',
  Unresolved: 'medium',
};

const EXECUTABLE_EXTENSIONS = [
  '.exe',
  '.com',
  '.bat',
  '.cmd',
  '.ps1',
  '.psm1',
  '.vbs',
  '.vbe',
  '.js',
  '.jse',
  '.wsf',
  '.wsh',
  '.hta',
  '.scr',
  '.pif',
  '.msi',
  '.msp',
  '.jar',
  '.lnk',
  '.cpl',
  '.dll',
  '.sh',
  '.app',
  '.command',
];

/** Containers often used to smuggle malware past mail filters. */
const ARCHIVE_EXTENSIONS = [
  '.zip',
  '.rar',
  '.7z',
  '.iso',
  '.img',
  '.vhd',
  '.vhdx',
  '.cab',
  '.tar',
  '.gz',
  '.tgz',
  '.xz',
];

/** Office formats that can carry macros. */
const MACRO_DOCUMENT_EXTENSIONS = [
  '.docm',
  '.dotm',
  '.xlsm',
  '.xltm',
  '.xlam',
  '.pptm',
  '.potm',
  '.ppam',
  '.doc',
  '.xls',
  '.ppt',
];

/** Action types whose target is a file or address. */
const TARGETED_ACTIONS = new Set(['URI', 'GoToR', 'GoToE', 'Launch', 'ImportData', 'SubmitForm']);

export type FileKind = 'executable' | 'archive' | 'macro-document' | 'other';
export type TargetKind = 'network-share' | 'script' | 'other';

const FILE_KIND_RANK: Record<FileKind, number> = {
  executable: 3,
  'macro-document': 2,
  archive: 1,
  other: 0,
};
const TARGET_RANK: Record<TargetKind, number> = { 'network-share': 2, script: 1, other: 0 };
const RISK_RANK: Record<ActionRisk, number> = { high: 2, medium: 1, low: 0 };

function hasBidiControl(text: string): boolean {
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if ((code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069)) {
      return true;
    }
  }
  return false;
}

/**
 * Classifies a file name by extension. Trailing dots and spaces (which Windows ignores) are
 * removed first, and names containing bidirectional overrides, a trick to disguise
 * "invoice<RLO>fdp.exe" as "invoiceexe.pdf", count as executables.
 */
export function classifyFileName(raw: string): FileKind {
  if (hasBidiControl(raw)) {
    return 'executable';
  }
  let end = raw.length;
  while (end > 0 && (raw[end - 1] === '.' || raw[end - 1] === ' ' || raw[end - 1] === '\u0000')) {
    end--;
  }
  const name = raw.slice(Math.max(0, end - 64), end).toLowerCase();
  const matches = (extensions: readonly string[]) =>
    extensions.some((extension) => name.endsWith(extension));
  if (matches(EXECUTABLE_EXTENSIONS)) {
    return 'executable';
  }
  if (matches(ARCHIVE_EXTENSIONS)) {
    return 'archive';
  }
  return matches(MACRO_DOCUMENT_EXTENSIONS) ? 'macro-document' : 'other';
}

/**
 * Classifies an action target. Network shares (UNC paths, smb:, file://host/) make Windows
 * send the user's credentials to the remote host when opened (for example CVE-2018-4993);
 * javascript:, vbscript: and data: URLs run code or carry content inline.
 */
export function classifyTarget(raw: string): TargetKind {
  const target = raw.trim().slice(0, 64).toLowerCase().replaceAll('\\', '/');
  if (target.startsWith('//') || target.startsWith('smb:')) {
    return 'network-share';
  }
  if (target.startsWith('file:')) {
    const rest = target.slice('file:'.length);
    return rest.startsWith('////') || (rest.startsWith('//') && !rest.startsWith('///'))
      ? 'network-share'
      : 'other';
  }
  if (
    // eslint-disable-next-line no-script-url -- a scheme prefix to detect, not a URL in use
    target.startsWith('javascript:') ||
    target.startsWith('vbscript:') ||
    target.startsWith('data:')
  ) {
    return 'script';
  }
  return 'other';
}

interface TriggerInfo {
  readonly trigger: string;
  readonly when: string;
  readonly automatic: boolean;
}

const DOCUMENT_EVENTS: Readonly<Record<string, Omit<TriggerInfo, 'trigger'>>> = {
  WC: { when: 'Before the document closes', automatic: true },
  WS: { when: 'Before the document is saved', automatic: false },
  DS: { when: 'After the document is saved', automatic: false },
  WP: { when: 'Before the document is printed', automatic: false },
  DP: { when: 'After the document is printed', automatic: false },
};

const PAGE_EVENTS: Readonly<Record<string, Omit<TriggerInfo, 'trigger'>>> = {
  O: { when: 'When a page is opened', automatic: true },
  C: { when: 'When a page is closed', automatic: true },
};

const ANNOTATION_EVENTS: Readonly<Record<string, Omit<TriggerInfo, 'trigger'>>> = {
  E: { when: 'When the pointer enters a field or annotation', automatic: false },
  X: { when: 'When the pointer leaves a field or annotation', automatic: false },
  D: { when: 'When a field or annotation is pressed', automatic: false },
  U: { when: 'When a field or annotation is released', automatic: false },
  Fo: { when: 'When a field receives focus', automatic: false },
  Bl: { when: 'When a field loses focus', automatic: false },
  PO: { when: 'When the page containing an annotation opens', automatic: true },
  PC: { when: 'When the page containing an annotation closes', automatic: true },
  PV: { when: 'When the page containing an annotation becomes visible', automatic: true },
  PI: { when: 'When the page containing an annotation is hidden', automatic: true },
  K: { when: 'When a form field is typed into', automatic: false },
  F: { when: 'When a form field value is formatted', automatic: false },
  V: { when: 'When a form field value is validated', automatic: false },
  C: { when: 'When a form field value is recalculated', automatic: false },
};

/** Maps an /AA key to a fixed description; unknown keys never reach the result verbatim. */
function describeEvent(key: string, containerType: string | null): TriggerInfo {
  const table =
    containerType === 'Catalog'
      ? DOCUMENT_EVENTS
      : containerType === 'Page'
        ? PAGE_EVENTS
        : ANNOTATION_EVENTS;
  const known = table[key] ?? (containerType === null ? DOCUMENT_EVENTS[key] : undefined);
  if (known !== undefined) {
    return { trigger: `/AA /${key}`, ...known };
  }
  return { trigger: '/AA (other event)', when: 'On another event', automatic: false };
}

interface ActionSource {
  readonly trigger: TriggerInfo;
  readonly value: PdfValue;
  readonly hidden: boolean;
}

interface ClassifiedAction {
  readonly action: string;
  readonly risk: ActionRisk;
  readonly target: TargetKind | null;
}

/** PDFiD name keywords (without the slash) tracked in the parsed structure. */
const STRUCTURAL_KEYWORDS = new Set(
  PDFID_KEYWORDS.filter((keyword) => keyword.name.startsWith('/')).map((keyword) =>
    keyword.name.slice(1),
  ),
);

const TRAILER = latin1ToBytes('trailer');
const MAX_TRAILERS = 1_000;
const MAX_ACTIONS_PER_SOURCE = 64;

type MutableAction = { -readonly [K in keyof ActionSummary]: ActionSummary[K] };
type MutablePattern = { -readonly [K in keyof ScriptPatternHit]: ScriptPatternHit[K] };
type Dict = Extract<PdfValue, { type: 'dict' }>;

class DeepScanner {
  private readonly bytes: Uint8Array;
  private readonly limits: DeepScanLimits;
  private readonly options: DeepScanOptions;
  private readonly now: () => number;
  private readonly startedAt: number;
  private readonly tokens: TokenBudget;

  /** All definitions, in file order followed by object-stream contents. */
  private readonly objects: PdfObject[] = [];
  private readonly definitions = new Map<number, PdfObject[]>();
  private readonly notes = new Set<string>();
  private readonly hiddenCounts = new Array<number>(PDFID_KEYWORDS.length + 1).fill(0);
  private readonly hiddenHexCounts = new Array<number>(PDFID_KEYWORDS.length + 1).fill(0);
  private readonly actionSources: ActionSource[] = [];
  private readonly scriptSources: { value: PdfValue; hidden: boolean }[] = [];
  private readonly xfaSources: PdfValue[] = [];
  private readonly actions = new Map<string, MutableAction>();
  private readonly patternHits = new Map<string, MutablePattern>();
  private readonly classified = new Map<number, readonly ClassifiedAction[]>();
  private readonly seenAdditionalActions = new Set<number>();
  private readonly analyzedScriptObjects = new Set<number>();

  private encrypted = false;
  private objectStreams = 0;
  private objectStreamsIncomplete = 0;
  private decompressionBombs = 0;
  private streamsDecoded = 0;
  private decodedBytes = 0;
  private decodeFailures = 0;
  private unresolved = 0;
  private visitedValues = 0;
  private executableLaunches = 0;
  private otherLaunches = 0;
  private attachmentsTotal = 0;
  private executableAttachments = 0;
  private archiveAttachments = 0;
  private macroAttachments = 0;
  private networkShareTargets = 0;
  private automaticNetworkShareTargets = 0;
  private scriptUriTargets = 0;
  private scriptsFound = 0;
  private scriptsAnalyzed = 0;
  private scriptsUndecodable = 0;
  private scriptBytesTotal = 0;
  private xfaScripts = 0;
  private readonly structuralNames = new Map<string, number>();

  constructor(bytes: Uint8Array, options: DeepScanOptions) {
    this.bytes = bytes;
    this.options = options;
    this.limits = { ...DEFAULT_DEEP_SCAN_LIMITS, ...options.limits };
    this.now = options.now ?? (() => Date.now());
    this.startedAt = this.now();
    this.tokens = { remaining: this.limits.maxTokens };
  }

  async run(): Promise<DeepScanResult> {
    const index = indexFileObjects(this.bytes, {
      maxObjects: this.limits.maxObjects,
      budget: this.tokens,
      shouldStop: () => this.timeUp(),
    });
    index.definitions.forEach((object) => {
      this.addDefinition(object);
    });
    if (index.truncated) {
      this.notes.add(
        `Only the first ${this.limits.maxObjects.toLocaleString('en')} objects were analysed.`,
      );
    }
    if (index.stopped) {
      this.notes.add('The document structure is too large to analyse completely.');
    }
    if (index.oversized > 0) {
      this.notes.add('Some objects were too large to parse completely.');
    }
    this.encrypted = this.options.encrypted ?? this.detectEncryption();
    if (this.encrypted) {
      this.notes.add(
        'The document is encrypted, so compressed objects and script contents could not be inspected.',
      );
    }
    if (!isDecompressionAvailable()) {
      this.notes.add(
        'This browser cannot decompress streams (DecompressionStream is unavailable), so compressed content was not inspected.',
      );
    }
    this.options.onProgress?.(0.2);

    await this.expandObjectStreams();
    this.options.onProgress?.(0.6);
    this.collectSources();
    this.classifyActions();
    this.options.onProgress?.(0.75);
    await this.analyzeScripts();
    await this.analyzeXfa();
    this.options.onProgress?.(1);

    if (this.decodeFailures > 0) {
      this.notes.add(
        'Some compressed streams could not be decoded (corrupt, encrypted or using unsupported filters).',
      );
    }
    return this.result();
  }

  private addDefinition(object: PdfObject): boolean {
    if (this.objects.length >= this.limits.maxObjects) {
      return false;
    }
    this.objects.push(object);
    const existing = this.definitions.get(object.number);
    if (existing === undefined) {
      this.definitions.set(object.number, [object]);
    } else {
      existing.push(object);
    }
    return true;
  }

  private timeUp(): boolean {
    if (this.now() - this.startedAt > this.limits.timeBudgetMs) {
      this.notes.add('The deep analysis time limit was reached; results are incomplete.');
      return true;
    }
    return false;
  }

  /** /Encrypt in a trailer dictionary or a cross-reference stream dictionary. */
  private detectEncryption(): boolean {
    for (const object of this.objects) {
      if (
        nameOf(dictGet(object.value, 'Type')) === 'XRef' &&
        dictGet(object.value, 'Encrypt') !== undefined
      ) {
        return true;
      }
    }
    let from = 0;
    for (let count = 0; count < MAX_TRAILERS; count++) {
      const found = indexOfBytes(this.bytes, TRAILER, from);
      if (found < 0) {
        return false;
      }
      from = found + TRAILER.length;
      const lexer = new PdfLexer(this.bytes, from, Math.min(this.bytes.length, from + 64 * 1024), {
        ...DEFAULT_PARSE_LIMITS,
        maxTokens: 10_000,
      });
      if (dictGet(parseValue(lexer) ?? undefined, 'Encrypt') !== undefined) {
        return true;
      }
    }
    return false;
  }

  /** Decodes a stream within the remaining budgets; null when skipped or undecodable. */
  private async decode(
    object: PdfObject,
  ): Promise<{ bytes: Uint8Array; truncated: boolean } | null> {
    const stream = object.stream;
    if (stream === null) {
      return null;
    }
    if (this.timeUp()) {
      return null;
    }
    if (
      this.streamsDecoded >= this.limits.maxDecodedStreams ||
      this.decodedBytes >= this.limits.maxDecodedBytesTotal
    ) {
      this.notes.add('The decompression limit was reached; some streams were not inspected.');
      return null;
    }
    const data = stream.buffer.subarray(stream.dataStart, stream.dataEnd);
    const budget = Math.min(
      this.limits.maxDecodedBytesPerStream,
      this.limits.maxDecodedBytesTotal - this.decodedBytes,
    );
    const result = await decodeStream(data, filtersOf(dictGet(object.value, 'Filter')), budget);
    this.streamsDecoded++;
    this.decodedBytes += result.bytes.length;
    if (result.status === 'failed' || result.status === 'unsupported') {
      this.decodeFailures++;
      return null;
    }
    const truncated = result.status === 'truncated';
    if (truncated) {
      this.decompressionBombs++;
      this.notes.add(
        'A stream decompressed to more data than the per-stream limit allows (a possible decompression bomb); it was truncated.',
      );
    }
    return { bytes: result.bytes, truncated };
  }

  private async expandObjectStreams(): Promise<void> {
    const containers = this.objects.filter(
      (object) => object.stream !== null && this.typeOf(object.value) === 'ObjStm',
    );
    this.objectStreams = containers.length;
    if (this.encrypted) {
      this.objectStreamsIncomplete = containers.length;
      return;
    }
    for (const container of containers) {
      const decoded = await this.decode(container);
      if (decoded === null) {
        this.objectStreamsIncomplete++;
        continue;
      }
      if (decoded.truncated) {
        this.objectStreamsIncomplete++;
      }
      const counts = scanKeywords(decoded.bytes, {
        startOffset: 0,
        collectNames: false,
        maxDistinctNames: 0,
        maxDates: 0,
      });
      counts.counts.forEach((count, index) => {
        this.hiddenCounts[index] = (this.hiddenCounts[index] ?? 0) + count;
        this.hiddenHexCounts[index] =
          (this.hiddenHexCounts[index] ?? 0) + (counts.hexcodeCounts[index] ?? 0);
      });
      this.hiddenCounts[PDFID_KEYWORDS.length] =
        (this.hiddenCounts[PDFID_KEYWORDS.length] ?? 0) + counts.colorsOverThreshold;

      const room = Math.max(0, this.limits.maxObjects - this.objects.length);
      for (const object of parseObjectStream(
        decoded.bytes,
        container.value,
        room,
        DEFAULT_PARSE_LIMITS,
        this.tokens,
      )) {
        this.addDefinition(object);
      }
      if (this.tokens.remaining <= 0) {
        this.notes.add('The document structure is too large to analyse completely.');
      }
    }
  }

  /** All values an indirect reference can resolve to (one per definition). */
  private resolveAll(value: PdfValue | undefined): PdfValue[] {
    if (value === undefined) {
      return [];
    }
    if (value.type !== 'ref') {
      return [value];
    }
    const found = this.definitions.get(value.number);
    if (found === undefined) {
      this.unresolved++;
      return [];
    }
    return found.map((object) => object.value);
  }

  private nameOfResolved(value: PdfValue | undefined): string | null {
    for (const candidate of this.resolveAll(value)) {
      const name = nameOf(candidate);
      if (name !== null) {
        return name;
      }
    }
    return null;
  }

  /** /Type, or a structural guess for catalogs and pages that omit it. */
  private typeOf(value: PdfValue): string | null {
    if (value.type !== 'dict') {
      return null;
    }
    const declared = this.nameOfResolved(value.entries.get('Type'));
    if (declared !== null) {
      return declared;
    }
    const has = (key: string) => value.entries.has(key);
    if (has('Pages') && (has('OpenAction') || has('AcroForm') || has('Names') || has('Outlines'))) {
      return 'Catalog';
    }
    if (
      !has('Subtype') &&
      has('Parent') &&
      (has('MediaBox') || has('Contents') || has('Resources'))
    ) {
      return 'Page';
    }
    return null;
  }

  /** Walks every definition's value tree, recording action triggers, scripts, forms and files. */
  private collectSources(): void {
    for (const object of this.objects) {
      const hidden = object.source === 'object-stream';
      const stack: PdfValue[] = [object.value];
      while (stack.length > 0) {
        this.visitedValues++;
        if (
          this.visitedValues > this.limits.maxVisitedValues ||
          (this.visitedValues % 4096 === 0 && this.timeUp())
        ) {
          this.notes.add('The document structure is too large to analyse completely.');
          return;
        }
        const value = stack.pop();
        if (value?.type === 'array') {
          stack.push(...value.items);
        } else if (value?.type === 'dict') {
          this.inspectDictionary(value, hidden);
          for (const key of value.entries.keys()) {
            this.countStructuralName(key);
          }
          stack.push(...value.entries.values());
        } else if (value?.type === 'name') {
          this.countStructuralName(value.value);
        }
      }
    }
  }

  private countStructuralName(name: string): void {
    if (STRUCTURAL_KEYWORDS.has(name)) {
      this.structuralNames.set(name, (this.structuralNames.get(name) ?? 0) + 1);
    }
  }

  private addActionSource(source: ActionSource): void {
    if (this.actionSources.length >= this.limits.maxActionSources) {
      this.notes.add('There are too many actions to analyse them all.');
      return;
    }
    this.actionSources.push(source);
  }

  private inspectDictionary(dict: Dict, hidden: boolean): void {
    const containerType = this.typeOf(dict);
    const openAction = dict.entries.get('OpenAction');
    if (openAction !== undefined) {
      this.addActionSource({
        trigger: { trigger: '/OpenAction', when: 'When the document is opened', automatic: true },
        value: openAction,
        hidden,
      });
    }
    const additional = dict.entries.get('AA');
    // A shared /AA dictionary (referenced by many annotations) is analysed once.
    if (
      additional !== undefined &&
      !(additional.type === 'ref' && this.seenAdditionalActions.has(additional.number))
    ) {
      if (additional.type === 'ref') {
        this.seenAdditionalActions.add(additional.number);
      }
      for (const events of this.resolveAll(additional)) {
        if (events.type !== 'dict') {
          continue;
        }
        for (const [key, value] of events.entries) {
          this.addActionSource({ trigger: describeEvent(key, containerType), value, hidden });
        }
      }
    }
    const clickAction = dict.entries.get('A');
    if (
      clickAction !== undefined &&
      this.resolveAll(clickAction).some((value) => dictGet(value, 'S') !== undefined)
    ) {
      this.addActionSource({
        trigger: {
          trigger: '/A',
          when: 'When the user clicks a link, bookmark or control',
          automatic: false,
        },
        value: clickAction,
        hidden,
      });
    }
    for (const names of this.resolveAll(dict.entries.get('Names'))) {
      const documentScripts = dictGet(names, 'JavaScript');
      if (documentScripts === undefined) {
        continue;
      }
      for (const value of this.nameTreeValues(documentScripts)) {
        this.addActionSource({
          trigger: {
            trigger: '/Names /JavaScript',
            when: 'When the document is opened (document-level script)',
            automatic: true,
          },
          value,
          hidden,
        });
      }
    }
    const script = dict.entries.get('JS');
    if (script !== undefined && this.scriptSources.length < this.limits.maxScripts * 4) {
      this.scriptSources.push({ value: script, hidden });
    }
    const xfa = dict.entries.get('XFA');
    if (xfa !== undefined) {
      this.xfaSources.push(xfa);
    }
    if (dict.entries.has('EF')) {
      this.inspectAttachment(dict);
    }
  }

  /** A file specification with /EF is an embedded file (attachment). */
  private inspectAttachment(fileSpec: Dict): void {
    this.attachmentsTotal++;
    let worst: FileKind = 'other';
    for (const key of ['UF', 'F']) {
      for (const candidate of this.resolveAll(fileSpec.entries.get(key))) {
        if (candidate.type === 'string') {
          const kind = classifyFileName(scriptBytesToText(candidate.value.subarray(0, 1024)));
          worst = FILE_KIND_RANK[kind] > FILE_KIND_RANK[worst] ? kind : worst;
        }
      }
    }
    if (worst === 'executable') {
      this.executableAttachments++;
    } else if (worst === 'archive') {
      this.archiveAttachments++;
    } else if (worst === 'macro-document') {
      this.macroAttachments++;
    }
  }

  /** Leaf values of a name tree (`/Names [key value …]` and `/Kids`). */
  private nameTreeValues(root: PdfValue): PdfValue[] {
    const values: PdfValue[] = [];
    const visited = new Set<number>();
    const queue: { node: PdfValue; depth: number }[] = [{ node: root, depth: 0 }];
    // A moving head index keeps this linear; Array.shift() would make it quadratic.
    for (let head = 0; head < queue.length && values.length < this.limits.maxScripts; head++) {
      const next = queue[head];
      if (next === undefined || next.depth > this.limits.maxActionDepth) {
        continue;
      }
      if (next.node.type === 'ref') {
        if (visited.has(next.node.number)) {
          continue;
        }
        visited.add(next.node.number);
      }
      for (const node of this.resolveAll(next.node)) {
        const pairs = dictGet(node, 'Names');
        if (pairs?.type === 'array') {
          pairs.items.forEach((item, index) => {
            if (index % 2 === 1) {
              values.push(item);
            }
          });
        }
        const kids = dictGet(node, 'Kids');
        if (kids?.type === 'array' && queue.length < this.limits.maxVisitedValues) {
          queue.push(...kids.items.map((kid) => ({ node: kid, depth: next.depth + 1 })));
        }
      }
    }
    return values;
  }

  /** Classifies an action value. Results for indirect objects are memoised per object number. */
  private classify(value: PdfValue, depth: number, path: Set<number>): readonly ClassifiedAction[] {
    if (depth > this.limits.maxActionDepth) {
      return [];
    }
    if (value.type !== 'ref') {
      return this.classifyResolved(value, depth, path);
    }
    const cached = this.classified.get(value.number);
    if (cached !== undefined) {
      return cached;
    }
    if (path.has(value.number)) {
      return [];
    }
    const definitions = this.definitions.get(value.number);
    if (definitions === undefined) {
      this.unresolved++;
      return [{ action: 'Unresolved', risk: 'medium', target: null }];
    }
    path.add(value.number);
    const results = definitions
      .flatMap((definition) => this.classifyResolved(definition.value, depth, path))
      .slice(0, MAX_ACTIONS_PER_SOURCE);
    path.delete(value.number);
    this.classified.set(value.number, results);
    return results;
  }

  private classifyResolved(
    value: PdfValue,
    depth: number,
    path: Set<number>,
  ): readonly ClassifiedAction[] {
    if (value.type === 'array' || value.type === 'name' || value.type === 'string') {
      return [{ action: 'Destination', risk: 'low', target: null }];
    }
    if (value.type !== 'dict') {
      return [{ action: 'Other', risk: 'medium', target: null }];
    }
    const subtype = this.nameOfResolved(value.entries.get('S'));
    let action: string;
    if (subtype === null) {
      action = value.entries.has('S') ? 'Other' : value.entries.has('D') ? 'Destination' : 'Other';
    } else {
      action = subtype in ACTION_RISK ? subtype : 'Other';
    }
    let risk: ActionRisk = ACTION_RISK[action] ?? 'medium';
    if (action === 'Rendition' && value.entries.has('JS')) {
      risk = 'high';
    }
    const target = TARGETED_ACTIONS.has(action) ? this.inspectTargets(value, action) : null;
    const results: ClassifiedAction[] = [{ action, risk, target }];
    const next = value.entries.get('Next');
    if (next !== undefined) {
      const chained = next.type === 'array' ? next.items : [next];
      for (const item of chained) {
        if (results.length >= MAX_ACTIONS_PER_SOURCE) {
          break;
        }
        results.push(...this.classify(item, depth + 1, path));
      }
    }
    return results;
  }

  /**
   * Classifies every file name or address an action can point to and keeps the worst. Values
   * are classified and discarded; they are never stored.
   */
  private inspectTargets(action: Dict, type: string): TargetKind {
    const strings: string[] = [];
    const collect = (value: PdfValue | undefined) => {
      for (const resolved of this.resolveAll(value)) {
        if (resolved.type === 'string') {
          strings.push(scriptBytesToText(resolved.value.subarray(0, 1024)));
        } else if (resolved.type === 'dict') {
          for (const key of ['UF', 'F', 'DOS', 'Unix', 'Mac']) {
            const entry = resolved.entries.get(key);
            if (entry?.type === 'string') {
              strings.push(scriptBytesToText(entry.value.subarray(0, 1024)));
            }
          }
        }
      }
    };
    collect(action.entries.get('URI'));
    collect(action.entries.get('F'));
    const windows = this.resolveAll(action.entries.get('Win')).find(
      (value) => value.type === 'dict',
    );
    collect(dictGet(windows, 'F'));

    let target: TargetKind = 'other';
    let file: FileKind = 'other';
    for (const text of strings) {
      const kind = classifyTarget(text);
      target = TARGET_RANK[kind] > TARGET_RANK[target] ? kind : target;
      const fileKind = classifyFileName(text);
      file = FILE_KIND_RANK[fileKind] > FILE_KIND_RANK[file] ? fileKind : file;
    }
    if (type === 'Launch') {
      // A Windows launch with parameters, or of a bare command name, starts a program.
      const windowsCommand = dictGet(windows, 'F');
      const bareCommand =
        windowsCommand?.type === 'string' &&
        !scriptBytesToText(windowsCommand.value.subarray(0, 1024)).includes('.');
      if (file === 'executable' || dictGet(windows, 'P') !== undefined || bareCommand) {
        this.executableLaunches++;
      } else {
        this.otherLaunches++;
      }
    }
    return target;
  }

  private classifyActions(): void {
    for (const [index, source] of this.actionSources.entries()) {
      if (index % 1024 === 0 && this.timeUp()) {
        return;
      }
      for (const classified of this.classify(source.value, 0, new Set())) {
        let risk: ActionRisk =
          classified.action === 'URI'
            ? source.trigger.automatic
              ? 'medium'
              : 'low'
            : classified.risk;
        if (classified.target === 'network-share') {
          this.networkShareTargets++;
          if (source.trigger.automatic) {
            this.automaticNetworkShareTargets++;
          }
          risk = 'high';
        } else if (classified.target === 'script') {
          this.scriptUriTargets++;
          risk = 'high';
        }
        const key = `${source.trigger.trigger}\u0000${classified.action}`;
        const existing = this.actions.get(key);
        if (existing === undefined) {
          this.actions.set(key, {
            trigger: source.trigger.trigger,
            when: source.trigger.when,
            automatic: source.trigger.automatic,
            action: classified.action,
            risk,
            count: 1,
            hiddenCount: source.hidden ? 1 : 0,
          });
        } else {
          existing.count++;
          existing.hiddenCount += source.hidden ? 1 : 0;
          if (RISK_RANK[risk] > RISK_RANK[existing.risk]) {
            existing.risk = risk;
          }
        }
      }
    }
  }

  /** Bytes of every definition a /JS value can resolve to. */
  private async scriptBytes(value: PdfValue): Promise<Uint8Array[]> {
    if (value.type === 'string') {
      return [value.value];
    }
    if (value.type !== 'ref') {
      return [];
    }
    if (this.analyzedScriptObjects.has(value.number)) {
      return [];
    }
    this.analyzedScriptObjects.add(value.number);
    const definitions = this.definitions.get(value.number);
    if (definitions === undefined) {
      this.unresolved++;
      return [];
    }
    const results: Uint8Array[] = [];
    for (const definition of definitions) {
      if (definition.value.type === 'string') {
        results.push(definition.value.value);
      } else if (definition.stream !== null) {
        const decoded = await this.decode(definition);
        if (decoded !== null) {
          results.push(decoded.bytes);
        }
      }
    }
    return results;
  }

  private recordPatterns(text: string): void {
    for (const pattern of findScriptPatterns(text)) {
      const existing = this.patternHits.get(pattern.id);
      if (existing === undefined) {
        this.patternHits.set(pattern.id, {
          id: pattern.id,
          label: pattern.label,
          severity: pattern.severity,
          description: pattern.description,
          scripts: 1,
        });
      } else {
        existing.scripts++;
      }
    }
  }

  private async analyzeScripts(): Promise<void> {
    for (const source of this.scriptSources) {
      if (source.value.type === 'ref' && this.analyzedScriptObjects.has(source.value.number)) {
        continue;
      }
      this.scriptsFound++;
      if (this.encrypted || this.scriptsAnalyzed >= this.limits.maxScripts || this.timeUp()) {
        this.scriptsUndecodable++;
        continue;
      }
      const versions = await this.scriptBytes(source.value);
      if (versions.length === 0) {
        this.scriptsUndecodable++;
        continue;
      }
      this.scriptsAnalyzed++;
      for (const bytes of versions) {
        const limited = bytes.subarray(0, this.limits.maxScriptBytes);
        this.scriptBytesTotal += limited.length;
        this.recordPatterns(scriptBytesToText(limited));
      }
    }
  }

  private async analyzeXfa(): Promise<void> {
    if (this.encrypted) {
      return;
    }
    const references = this.xfaSources.flatMap((source) =>
      source.type === 'array' ? source.items.filter((item) => item.type === 'ref') : [source],
    );
    for (const reference of references) {
      if (reference.type !== 'ref' || this.analyzedScriptObjects.has(reference.number)) {
        continue;
      }
      this.analyzedScriptObjects.add(reference.number);
      for (const definition of this.definitions.get(reference.number) ?? []) {
        if (definition.stream === null) {
          continue;
        }
        const decoded = await this.decode(definition);
        if (decoded === null) {
          continue;
        }
        const limited = decoded.bytes.subarray(0, this.limits.maxScriptBytes);
        const text = scriptBytesToText(limited);
        if (text.includes('<script')) {
          this.xfaScripts++;
          this.scriptsFound++;
          this.scriptsAnalyzed++;
          this.scriptBytesTotal += limited.length;
          this.recordPatterns(text);
        }
      }
    }
  }

  private result(): DeepScanResult {
    const names = [...PDFID_KEYWORDS.map((keyword) => keyword.name), COLORS_COUNTER_NAME];
    const hiddenKeywords: HiddenKeywordCount[] = names
      .map((name, index) => ({
        name,
        count: this.hiddenCounts[index] ?? 0,
        hexcodeCount: this.hiddenHexCounts[index] ?? 0,
      }))
      .filter((entry) => entry.count > 0);
    const severityRank = { high: 2, medium: 1, low: 0 } as const;
    const incomplete = this.notes.size > 0 || this.objectStreamsIncomplete > 0;
    return {
      status: incomplete ? 'partial' : 'complete',
      durationMs: Math.max(0, this.now() - this.startedAt),
      objectsIndexed: this.objects.length,
      objectStreams: this.objectStreams,
      streamsDecoded: this.streamsDecoded,
      decodedBytes: this.decodedBytes,
      decodeFailures: this.decodeFailures,
      encrypted: this.encrypted,
      objectStreamsIncomplete: this.objectStreamsIncomplete,
      decompressionBombs: this.decompressionBombs,
      hiddenKeywords,
      structuralNames: Object.fromEntries(this.structuralNames),
      actions: [...this.actions.values()].sort(
        (left, right) =>
          RISK_RANK[right.risk] - RISK_RANK[left.risk] ||
          Number(right.automatic) - Number(left.automatic) ||
          right.count - left.count,
      ),
      unresolvedReferences: this.unresolved,
      launchTargets: { executable: this.executableLaunches, other: this.otherLaunches },
      attachments: {
        total: this.attachmentsTotal,
        executable: this.executableAttachments,
        archive: this.archiveAttachments,
        macroDocument: this.macroAttachments,
      },
      targets: {
        networkShare: this.networkShareTargets,
        automaticNetworkShare: this.automaticNetworkShareTargets,
        scriptUri: this.scriptUriTargets,
      },
      scripts: {
        found: this.scriptsFound,
        analyzed: this.scriptsAnalyzed,
        undecodable: this.scriptsUndecodable,
        bytesAnalyzed: this.scriptBytesTotal,
        xfaScripts: this.xfaScripts,
      },
      scriptPatterns: [...this.patternHits.values()].sort(
        (left, right) =>
          severityRank[right.severity] - severityRank[left.severity] ||
          right.scripts - left.scripts,
      ),
      notes: [...this.notes],
    };
  }
}

/** Runs the deep analysis. Never throws for malformed input; see DeepScanResult.status. */
export async function deepScanPdf(
  bytes: Uint8Array,
  options: DeepScanOptions = {},
): Promise<DeepScanResult> {
  return new DeepScanner(bytes, options).run();
}
