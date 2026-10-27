import { SCAN_RESULT_SCHEMA_VERSION, type ScanResult } from '../types/analysis';

/**
 * Messages exchanged between the main thread and the scan worker. Both sides validate every
 * message they receive at runtime; nothing is trusted because of its TypeScript type.
 */

export interface ScanRequestMessage {
  readonly type: 'scan';
  readonly requestId: string;
  /** The selected file. Blobs are passed by reference; the worker reads the bytes itself. */
  readonly file: Blob;
  readonly options: { readonly force: boolean };
}

export type ScanStage = 'reading' | 'hashing' | 'scanning' | 'deep-scan';

export type WorkerErrorCode = 'invalid-request' | 'file-too-large' | 'read-failed' | 'scan-failed';

export type WorkerResponseMessage =
  | {
      readonly type: 'progress';
      readonly requestId: string;
      readonly stage: ScanStage;
      readonly fraction: number;
    }
  | { readonly type: 'result'; readonly requestId: string; readonly result: ScanResult }
  | {
      readonly type: 'error';
      readonly requestId: string;
      readonly code: WorkerErrorCode;
      readonly message: string;
    };

const STAGES: readonly string[] = ['reading', 'hashing', 'scanning', 'deep-scan'];
const ERROR_CODES: readonly string[] = [
  'invalid-request',
  'file-too-large',
  'read-failed',
  'scan-failed',
];
const MAX_REQUEST_ID_LENGTH = 64;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isRequestId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_REQUEST_ID_LENGTH;
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isNullableNumber(value: unknown): boolean {
  return value === null || (typeof value === 'number' && Number.isFinite(value));
}

export function isScanRequestMessage(value: unknown): value is ScanRequestMessage {
  return (
    isRecord(value) &&
    value.type === 'scan' &&
    isRequestId(value.requestId) &&
    typeof Blob !== 'undefined' &&
    value.file instanceof Blob &&
    isRecord(value.options) &&
    typeof value.options.force === 'boolean'
  );
}

function isStringList(value: unknown): boolean {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isBoundedList(
  value: unknown,
  isEntry: (entry: Record<string, unknown>) => boolean,
): boolean {
  return (
    isRecord(value) &&
    isCount(value.omitted) &&
    Array.isArray(value.entries) &&
    value.entries.every((entry) => isRecord(entry) && isEntry(entry))
  );
}

/**
 * Structural check of a scan result received from the worker. It verifies every field the
 * interface and report rely on, so a malformed message cannot reach the rendering code.
 */
export function isScanResult(value: unknown): value is ScanResult {
  if (!isRecord(value) || value.schemaVersion !== SCAN_RESULT_SCHEMA_VERSION) {
    return false;
  }
  const { header, keywords, eof, entropy, obfuscation, structure, messages } = value;
  return (
    isRecord(value.engine) &&
    typeof value.engine.name === 'string' &&
    typeof value.engine.version === 'string' &&
    typeof value.engine.reference === 'string' &&
    typeof value.scannedAt === 'string' &&
    typeof value.durationMs === 'number' &&
    isCount(value.sizeBytes) &&
    (value.sha256 === null ||
      (typeof value.sha256 === 'string' && /^[0-9a-f]{64}$/.test(value.sha256))) &&
    (value.mode === 'standard' || value.mode === 'forced') &&
    typeof value.isPdf === 'boolean' &&
    typeof value.keywordScanPerformed === 'boolean' &&
    isRecord(header) &&
    typeof header.found === 'boolean' &&
    (header.offset === null || isCount(header.offset)) &&
    (header.text === null || typeof header.text === 'string') &&
    (header.version === null || typeof header.version === 'string') &&
    typeof header.versionRecognized === 'boolean' &&
    isCount(header.scanStartOffset) &&
    typeof header.pdfidWouldError === 'boolean' &&
    Array.isArray(keywords) &&
    keywords.every(
      (keyword) =>
        isRecord(keyword) &&
        typeof keyword.name === 'string' &&
        typeof keyword.label === 'string' &&
        typeof keyword.category === 'string' &&
        (keyword.kind === 'structural' || keyword.kind === 'indicator') &&
        isCount(keyword.count) &&
        isCount(keyword.hexcodeCount),
    ) &&
    (eof === null ||
      (isRecord(eof) &&
        isCount(eof.eofCount) &&
        (eof.bytesAfterLastEof === null || isCount(eof.bytesAfterLastEof)) &&
        typeof eof.trailingDataPresent === 'boolean' &&
        (eof.trailingDataWhitespaceOnly === null ||
          typeof eof.trailingDataWhitespaceOnly === 'boolean'))) &&
    (entropy === null ||
      (isRecord(entropy) &&
        isCount(entropy.totalBytes) &&
        isCount(entropy.streamBytes) &&
        isCount(entropy.nonStreamBytes) &&
        isNullableNumber(entropy.totalEntropy) &&
        isNullableNumber(entropy.streamEntropy) &&
        isNullableNumber(entropy.nonStreamEntropy))) &&
    (obfuscation === null ||
      (isRecord(obfuscation) &&
        isCount(obfuscation.hexEncodedKeywordOccurrences) &&
        isCount(obfuscation.namesWithHexEscapes) &&
        isCount(obfuscation.malformedHexEscapes))) &&
    (structure === null ||
      (isRecord(structure) &&
        Object.values(structure).length === 5 &&
        Object.values(structure).every((flag) => typeof flag === 'boolean'))) &&
    isBoundedList(
      value.dates,
      (entry) => typeof entry.value === 'string' && typeof entry.name === 'string',
    ) &&
    isBoundedList(
      value.names,
      (entry) =>
        typeof entry.name === 'string' && isCount(entry.count) && isCount(entry.hexcodeCount),
    ) &&
    Array.isArray(messages) &&
    messages.every(
      (message) =>
        isRecord(message) &&
        (message.severity === 'info' || message.severity === 'warning') &&
        typeof message.code === 'string' &&
        typeof message.text === 'string',
    ) &&
    isStringList(value.compatibilityNotes) &&
    (value.deep === null || isDeepScanResult(value.deep))
  );
}

const RISKS: readonly unknown[] = ['high', 'medium', 'low'];

function isDeepScanResult(value: unknown): boolean {
  if (!isRecord(value)) {
    return false;
  }
  const { scripts, launchTargets } = value;
  return (
    (value.status === 'complete' || value.status === 'partial' || value.status === 'failed') &&
    typeof value.durationMs === 'number' &&
    Number.isFinite(value.durationMs) &&
    [
      value.objectsIndexed,
      value.objectStreams,
      value.streamsDecoded,
      value.decodedBytes,
      value.decodeFailures,
      value.unresolvedReferences,
      value.objectStreamsIncomplete,
      value.decompressionBombs,
    ].every(isCount) &&
    typeof value.encrypted === 'boolean' &&
    Array.isArray(value.hiddenKeywords) &&
    value.hiddenKeywords.every(
      (entry) =>
        isRecord(entry) &&
        typeof entry.name === 'string' &&
        isCount(entry.count) &&
        isCount(entry.hexcodeCount),
    ) &&
    Array.isArray(value.actions) &&
    value.actions.every(
      (action) =>
        isRecord(action) &&
        typeof action.trigger === 'string' &&
        typeof action.when === 'string' &&
        typeof action.automatic === 'boolean' &&
        typeof action.action === 'string' &&
        RISKS.includes(action.risk) &&
        isCount(action.count) &&
        isCount(action.hiddenCount),
    ) &&
    isRecord(value.attachments) &&
    [
      value.attachments.total,
      value.attachments.executable,
      value.attachments.archive,
      value.attachments.macroDocument,
    ].every(isCount) &&
    isRecord(value.targets) &&
    [
      value.targets.networkShare,
      value.targets.automaticNetworkShare,
      value.targets.scriptUri,
    ].every(isCount) &&
    isRecord(launchTargets) &&
    isCount(launchTargets.executable) &&
    isCount(launchTargets.other) &&
    isRecord(scripts) &&
    [
      scripts.found,
      scripts.analyzed,
      scripts.undecodable,
      scripts.bytesAnalyzed,
      scripts.xfaScripts,
    ].every(isCount) &&
    Array.isArray(value.scriptPatterns) &&
    value.scriptPatterns.every(
      (pattern) =>
        isRecord(pattern) &&
        typeof pattern.id === 'string' &&
        typeof pattern.label === 'string' &&
        typeof pattern.description === 'string' &&
        RISKS.includes(pattern.severity) &&
        isCount(pattern.scripts),
    ) &&
    isRecord(value.structuralNames) &&
    Object.values(value.structuralNames).every(isCount) &&
    isStringList(value.notes)
  );
}

export function isWorkerResponseMessage(value: unknown): value is WorkerResponseMessage {
  if (!isRecord(value) || !isRequestId(value.requestId)) {
    return false;
  }
  switch (value.type) {
    case 'progress':
      return (
        typeof value.stage === 'string' &&
        STAGES.includes(value.stage) &&
        typeof value.fraction === 'number' &&
        value.fraction >= 0 &&
        value.fraction <= 1
      );
    case 'result':
      return isScanResult(value.result);
    case 'error':
      return (
        typeof value.code === 'string' &&
        ERROR_CODES.includes(value.code) &&
        typeof value.message === 'string'
      );
    default:
      return false;
  }
}

/** Extracts a request id from an otherwise invalid message, for error replies. */
export function requestIdOf(value: unknown): string {
  return isRecord(value) && isRequestId(value.requestId) ? value.requestId : 'unknown';
}
