import type {
  ActionSummary,
  Assessment,
  AssessmentLevel,
  DeepScanResult,
  Finding,
  FindingSeverity,
  KeywordCount,
  KeywordInterpretation,
  ScanResult,
} from '../types/analysis';
import { explanationFor, TRIAGE_DISCLAIMER } from './indicatorExplanations';

/**
 * Deterministic triage rules. Version this whenever a rule changes; it is included in reports.
 *
 * Each rule produces a finding with a severity:
 *   - `critical`: behaviour typical of malicious documents, confirmed by the deep analysis
 *     (JavaScript or a launch action that runs automatically, a launch of an executable file,
 *     script code matching exploit patterns);
 *   - `priority`: a pattern that is uncommon in legitimate files;
 *   - `review`: an indicator that warrants a closer look;
 *   - `informational`: context that does not raise the level on its own.
 *
 * Overall level:
 *   - scan not performed, or forced on a file without a PDF header → `inconclusive`;
 *   - any critical finding → `high-risk`;
 *   - otherwise count review and priority findings: 0 → `none-detected`, 1 → `review`,
 *     2 or more → `multiple`.
 *
 * Keyword counts include occurrences found inside compressed object streams by the deep
 * analysis. The level is not a probability of maliciousness. See README.md, "Triage rules".
 */
export const RULES_VERSION = '2.1.0';

/** Human-readable summary of the rules below, shown in the interface. */
export const RULE_DESCRIPTIONS = {
  critical: [
    'JavaScript that runs automatically from /OpenAction or a page-open or similar /AA event.',
    'A /Launch action that runs automatically, or any launch of an executable file type (.exe, .bat, .js, …).',
    'Script content matching exploit patterns (heap-spray data, shellcode-style escapes, APIs from known Acrobat exploits, eval of decoded data).',
    'An attached file with a program or script file type (.exe, .js, .vbs, …) or a name disguised with direction-reversing characters.',
    'An action that opens a network file share (\\\\server\\share, smb:, file://host) without a click, which can leak Windows credentials.',
  ],
  priority: [
    'Document-level JavaScript (/Names /JavaScript), which runs when the document opens.',
    'Any keyword written with hexadecimal escapes (for example /J#61vaScript).',
    'A link or action that points to a network file share, or uses a javascript:, vbscript: or data: address.',
    'A stream that expands beyond the inspection limit (a possible decompression bomb).',
    'When actions cannot be fully resolved: JavaScript or /Launch together with /OpenAction or /AA.',
  ],
  review: [
    'Any of /JS, /JavaScript, /OpenAction, /AA, /Launch, /EmbeddedFile, /RichMedia, /XFA, /JBIG2Decode or /Colors > 2^24 (related keywords form one finding).',
    'Automatic actions that open web addresses, submit data or open other files.',
    'Script content using functions worth reviewing (eval, unescape, network or mail access, …).',
    'Attached archives (.zip, .iso, …) or macro-capable Office documents.',
    'JavaScript, launch actions, embedded files or rich media found only inside compressed object streams, and object streams that could not be fully inspected.',
    'Different counts for "obj" and "endobj", or for "stream" and "endstream"; a %PDF header not at byte 0; non-whitespace data after the last %%EOF.',
  ],
  informational: [
    '/AcroForm, /ObjStm and /Encrypt, which are common in legitimate files.',
    '/OpenAction or /AA that only navigate (for example "open at page 1").',
    'Several %%EOF markers, a missing %%EOF, data ending inside a stream, malformed escapes or an unpublished header version.',
  ],
  levels: [
    'Any high-risk finding: "High-risk indicators detected" (even for a file scanned in forced mode).',
    'No header (scan skipped or forced): "Analysis incomplete or inconclusive".',
    'Otherwise, no review or priority findings: "No configured suspicious indicators detected".',
    'One finding: "Indicators warrant further investigation"; two or more: "Multiple potentially suspicious indicators detected".',
  ],
} as const;

const REVIEW_INDICATORS: readonly {
  readonly id: string;
  readonly names: readonly string[];
  readonly title: string;
}[] = [
  { id: 'javascript', names: ['/JS', '/JavaScript'], title: 'JavaScript present' },
  { id: 'automatic-action', names: ['/OpenAction', '/AA'], title: 'Automatic action present' },
  { id: 'launch', names: ['/Launch'], title: 'Launch action present' },
  { id: 'embedded-file', names: ['/EmbeddedFile'], title: 'Embedded file present' },
  { id: 'rich-media', names: ['/RichMedia'], title: 'Rich media (Flash-era) content present' },
  { id: 'xfa', names: ['/XFA'], title: 'XFA form present' },
  { id: 'jbig2', names: ['/JBIG2Decode'], title: 'JBIG2 image filter present' },
  {
    id: 'colors-cve-2009-3459',
    names: ['/Colors > 2^24'],
    title: 'Oversized /Colors value (CVE-2009-3459 pattern)',
  },
];

/** Keywords that let a document run code or start programs; highlighted as dangers. */
const CODE_EXECUTION_KEYWORDS = new Set(['/JS', '/JavaScript', '/Launch']);
/** Hidden copies of these are a sign of concealment. */
const CONCEALMENT_KEYWORDS = ['/JS', '/JavaScript', '/Launch', '/EmbeddedFile', '/RichMedia'];
const CONTEXT_INDICATORS = new Set(['/AcroForm', '/ObjStm', '/Encrypt']);
const AUTOMATIC_TRIGGERS = ['/OpenAction', '/AA'];
const DOCUMENT_SCRIPT_TRIGGER = '/Names /JavaScript';

const HEADLINES: Record<AssessmentLevel, string> = {
  'none-detected': 'No configured suspicious indicators detected',
  review: 'Indicators warrant further investigation',
  multiple: 'Multiple potentially suspicious indicators detected',
  'high-risk': 'High-risk indicators detected',
  inconclusive: 'Analysis incomplete or inconclusive',
};

const SUMMARIES: Record<AssessmentLevel, string> = {
  'none-detected':
    'None of the keywords and patterns PDF Signal checks were found. This is not a statement that the file is safe: content can be hidden in encrypted data or in ways a static scan cannot see.',
  review:
    'One indicator was found that analysts usually examine more closely. Many legitimate documents contain such features, so review it in context before drawing conclusions.',
  multiple:
    'Several indicators were found. Combinations like these are worth investigating with a dedicated PDF analysis tool before the file is opened in a PDF reader.',
  'high-risk':
    'PDF Signal found behaviour typical of malicious documents, such as JavaScript that runs automatically, a dangerous attachment or script code associated with known exploits. Treat this file as potentially malicious.',
  inconclusive:
    'The file has no PDF header, so the keyword scan was not run and nothing can be concluded.',
};

const FORCED_SUMMARY =
  'The file has no PDF header and may not be a PDF at all. It was scanned in forced mode, so the counts below may not be meaningful.';

/** The recommended next step for each level. */
const ADVICE: Record<AssessmentLevel, string> = {
  'none-detected':
    'Nothing PDF Signal checks for was found. Open the file with your usual care, preferably in an up-to-date reader.',
  review:
    'Look at the finding below before opening the file. If you did not expect a document with this feature, do not open it.',
  multiple:
    'Do not open the file until it has been looked at more closely, ideally with a PDF analysis tool or by your security team.',
  'high-risk':
    'Do not open this file in a PDF reader. If you need its contents, have it analysed in an isolated environment first.',
  inconclusive:
    'Check that this is the file you expected. Treat it with caution and do not open it if you do not trust its source.',
};

/** Keyword counts combined with occurrences hidden in compressed object streams. */
class Counts {
  private readonly visible = new Map<string, number>();
  private readonly hidden = new Map<string, number>();

  constructor(keywords: readonly KeywordCount[], deep: DeepScanResult | null) {
    for (const keyword of keywords) {
      this.visible.set(keyword.name, keyword.count);
    }
    for (const keyword of deep?.hiddenKeywords ?? []) {
      this.hidden.set(keyword.name, keyword.count);
    }
  }

  visibleOf(name: string): number {
    return this.visible.get(name) ?? 0;
  }

  hiddenOf(name: string): number {
    return this.hidden.get(name) ?? 0;
  }

  total(name: string): number {
    return this.visibleOf(name) + this.hiddenOf(name);
  }

  evidence(names: readonly string[]): string[] {
    return names
      .filter((name) => this.total(name) > 0)
      .map((name) => {
        const hidden = this.hiddenOf(name);
        return `${name} × ${this.total(name)}${hidden > 0 ? ` (${hidden} in object streams)` : ''}`;
      });
  }
}

function times(count: number): string {
  return count === 1 ? 'once' : `${count} times`;
}

function describeAction(action: ActionSummary): string {
  return `${action.trigger} → ${action.action} × ${action.count}`;
}

/** What the deep analysis established about actions, when it ran. */
interface ActionFacts {
  /** True when actions were resolved completely, so keyword heuristics are unnecessary. */
  readonly resolved: boolean;
  /** JavaScript run by /OpenAction or an automatic /AA event. */
  readonly automaticScripts: readonly ActionSummary[];
  /** Document-level scripts (/Names /JavaScript), which also run when the document opens. */
  readonly documentScripts: readonly ActionSummary[];
  readonly automaticLaunches: readonly ActionSummary[];
  readonly automaticExternal: readonly ActionSummary[];
  /** Actions reached through /OpenAction or /AA. */
  readonly triggered: (prefix: string) => readonly ActionSummary[];
}

function actionFacts(
  deep: DeepScanResult | null,
  counts: Counts,
  streamOnly: ReadonlySet<string>,
): ActionFacts | null {
  if (deep === null || deep.status === 'failed') {
    return null;
  }
  const automatic = deep.actions.filter((action) => action.automatic);
  const triggered = (prefix: string) =>
    deep.actions.filter((action) => action.trigger.startsWith(prefix));
  // Trust the resolved actions only if every /OpenAction and /AA the keyword scan saw in the
  // document structure was found.
  const accountedFor = AUTOMATIC_TRIGGERS.every(
    (trigger) =>
      counts.total(trigger) === 0 || streamOnly.has(trigger) || triggered(trigger).length > 0,
  );
  const runsScript = (action: ActionSummary) =>
    action.action === 'JavaScript' || (action.action === 'Rendition' && action.risk === 'high');
  return {
    // Trust resolved actions only when the deep analysis completed and every action resolved
    // to a known type; otherwise the keyword heuristic stays active as a safety net.
    resolved:
      accountedFor &&
      deep.status === 'complete' &&
      deep.unresolvedReferences === 0 &&
      !deep.actions.some((action) => action.action === 'Unresolved' || action.action === 'Other'),
    automaticScripts: automatic.filter(
      (action) => runsScript(action) && action.trigger !== DOCUMENT_SCRIPT_TRIGGER,
    ),
    documentScripts: deep.actions.filter(
      (action) => runsScript(action) && action.trigger === DOCUMENT_SCRIPT_TRIGGER,
    ),
    automaticLaunches: automatic.filter(
      (action) => action.action === 'Launch' || action.action === 'RichMediaExecute',
    ),
    automaticExternal: automatic.filter(
      (action) => action.risk === 'medium' && !['Other', 'Unresolved'].includes(action.action),
    ),
    triggered,
  };
}

function deepFindings(
  deep: DeepScanResult | null,
  facts: ActionFacts | null,
  counts: Counts,
): Finding[] {
  if (deep === null || facts === null) {
    return [];
  }
  const findings: Finding[] = [];
  if (facts.automaticScripts.length > 0) {
    findings.push({
      id: 'auto-javascript',
      severity: 'critical',
      title: 'JavaScript runs automatically',
      detail:
        'The document is set up to run JavaScript without any click: when it is opened, when a page is shown, or as a document-level script. This is how most malicious PDFs start their payload.',
      evidence: facts.automaticScripts.map(describeAction),
    });
  }
  if (facts.automaticLaunches.length > 0) {
    findings.push({
      id: 'auto-launch',
      severity: 'critical',
      title: 'Launch action runs automatically',
      detail: 'The document asks the reader to start a program or open a file without any click.',
      evidence: facts.automaticLaunches.map(describeAction),
    });
  }
  if (deep.launchTargets.executable > 0) {
    findings.push({
      id: 'launch-executable',
      severity: 'critical',
      title: 'Launch action targets an executable file',
      detail:
        'A launch action points to a program or script file type (such as .exe, .bat or .js). Legitimate documents almost never do this.',
      evidence: [`${deep.launchTargets.executable} executable launch target(s)`],
    });
  }
  if (deep.attachments.executable > 0) {
    findings.push({
      id: 'executable-attachment',
      severity: 'critical',
      title: 'Executable file attached',
      detail:
        'The document carries an attached file with a program or script file type (such as .exe, .js or .vbs), or with a name disguised by direction-reversing characters. Opening the attachment could run code.',
      evidence: [`${deep.attachments.executable} executable attachment(s)`],
    });
  }
  if (deep.targets.automaticNetworkShare > 0) {
    findings.push({
      id: 'auto-network-share',
      severity: 'critical',
      title: 'Opens a network file share automatically',
      detail:
        "An action that runs without a click points to a network share (\\\\server\\share, smb: or file://host). Windows can send the user's credentials to that server, as in CVE-2018-4993.",
      evidence: [`${deep.targets.automaticNetworkShare} automatic network-share target(s)`],
    });
  } else if (deep.targets.networkShare > 0) {
    findings.push({
      id: 'network-share',
      severity: 'priority',
      title: 'Link to a network file share',
      detail:
        "A link or action points to a network share. Following it can send the user's Windows credentials to the remote server.",
      evidence: [`${deep.targets.networkShare} network-share target(s)`],
    });
  }
  if (deep.targets.scriptUri > 0) {
    findings.push({
      id: 'script-url',
      severity: 'priority',
      title: 'Link uses a script address',
      detail:
        'A link or action uses a javascript:, vbscript: or data: address, which can run code or hide content instead of opening a web page.',
      evidence: [`${deep.targets.scriptUri} script address(es)`],
    });
  }
  const riskyAttachments = deep.attachments.archive + deep.attachments.macroDocument;
  if (riskyAttachments > 0) {
    findings.push({
      id: 'risky-attachment',
      severity: 'review',
      title: 'Attachment that can hide malware',
      detail:
        'Archives and macro-capable Office documents are common ways to deliver malware past mail filters. The attachment needs separate analysis.',
      evidence: [
        ...(deep.attachments.archive > 0 ? [`${deep.attachments.archive} archive(s)`] : []),
        ...(deep.attachments.macroDocument > 0
          ? [`${deep.attachments.macroDocument} macro-capable document(s)`]
          : []),
      ],
    });
  }
  const exploitPatterns = deep.scriptPatterns.filter((pattern) => pattern.severity === 'high');
  if (exploitPatterns.length > 0) {
    findings.push({
      id: 'exploit-script-patterns',
      severity: 'critical',
      title: 'Script content matches exploit patterns',
      detail:
        'Script code in the document uses constructs associated with known PDF exploits or with hiding a payload. The script was analysed locally and was not run.',
      evidence: exploitPatterns.map((pattern) => pattern.label),
    });
  }
  const reviewPatterns = deep.scriptPatterns.filter((pattern) => pattern.severity === 'medium');
  if (reviewPatterns.length > 0) {
    findings.push({
      id: 'script-patterns',
      severity: 'review',
      title: 'Script content uses functions worth reviewing',
      detail:
        'These functions have legitimate uses, but malicious scripts rely on them to decode hidden code or to contact the outside world.',
      evidence: reviewPatterns.map((pattern) => pattern.label),
    });
  }
  if (facts.automaticExternal.length > 0) {
    findings.push({
      id: 'auto-external-action',
      severity: 'review',
      title: 'Automatic action reaches outside the document',
      detail:
        'An action that runs without a click opens a web address, submits data or opens another file. This is common in phishing documents.',
      evidence: facts.automaticExternal.map(describeAction),
    });
  }
  const concealed = CONCEALMENT_KEYWORDS.filter(
    (name) => counts.hiddenOf(name) > 0 && counts.visibleOf(name) === 0,
  );
  if (concealed.length > 0) {
    findings.push({
      id: 'hidden-indicators',
      severity: 'review',
      title: 'Indicators inside compressed object streams',
      detail:
        'These keywords appear only inside compressed object streams. Many PDF writers store objects this way, but byte-level scanners such as PDFiD cannot see them there, which is also used to evade detection.',
      evidence: concealed.map((name) => `${name} × ${counts.hiddenOf(name)}`),
    });
  }
  if (facts.documentScripts.length > 0) {
    findings.push({
      id: 'document-level-javascript',
      severity: 'priority',
      title: 'Document-level JavaScript',
      detail:
        'The document contains scripts that run when it is opened. Legitimate forms use them for helper functions; malicious documents use them to start their payload. Check what the script does.',
      evidence: facts.documentScripts.map(describeAction),
    });
  }
  if (deep.decompressionBombs > 0) {
    findings.push({
      id: 'decompression-bomb',
      severity: 'priority',
      title: 'Stream that expands enormously',
      detail:
        'A compressed stream expanded beyond the inspection limit. Such "decompression bombs" can hide content after the limit or crash analysis tools.',
      evidence: [`${deep.decompressionBombs} stream(s) over the limit`],
    });
  }
  if (deep.objectStreamsIncomplete > 0 && !deep.encrypted) {
    findings.push({
      id: 'objstm-uninspected',
      severity: 'review',
      title: 'Compressed object streams not fully inspected',
      detail:
        'Some object streams could not be decompressed or exceeded a limit, so objects inside them (which may include scripts or actions) were not checked.',
      evidence: [`${deep.objectStreamsIncomplete} of ${deep.objectStreams} object stream(s)`],
    });
  }
  return findings;
}

/**
 * Name keywords that PDFiD counted but that never occur in the parsed document structure: they
 * only appear inside stream data (compressed images, fonts, …), strings or comments, where they
 * have no effect.
 * Only trusted when the deep analysis inspected everything, so incomplete analysis can never
 * downgrade a keyword.
 */
function streamOnlyNames(deep: DeepScanResult | null, counts: Counts): ReadonlySet<string> {
  if (deep?.status !== 'complete' || deep.objectStreamsIncomplete > 0 || deep.encrypted) {
    return new Set();
  }
  return new Set(
    REVIEW_INDICATORS.flatMap((rule) => rule.names).filter(
      (name) =>
        name.startsWith('/') &&
        !name.includes(' ') &&
        counts.total(name) > 0 &&
        (deep.structuralNames[name.slice(1)] ?? 0) === 0,
    ),
  );
}

function indicatorFindings(
  counts: Counts,
  keywords: readonly KeywordCount[],
  facts: ActionFacts | null,
  streamOnly: ReadonlySet<string>,
): Finding[] {
  const findings: Finding[] = [];
  for (const rule of REVIEW_INDICATORS) {
    const evidence = counts.evidence(rule.names);
    if (evidence.length === 0) {
      continue;
    }
    const counted = rule.names.filter((name) => counts.total(name) > 0);
    if (counted.every((name) => streamOnly.has(name))) {
      findings.push({
        id: rule.id,
        severity: 'informational',
        title: `${counted.join(', ')} not used in the document structure`,
        detail:
          'PDFiD counts this keyword, but it does not occur in the document structure, only inside stream data (such as compressed images or fonts), strings or comments, where it has no effect.',
        evidence,
      });
      continue;
    }
    const primary = rule.names.find((name) => counts.total(name) > 0) ?? rule.names[0] ?? '';
    let severity: FindingSeverity = 'review';
    let title = rule.title;
    let detail = explanationFor(primary).whyInvestigate;
    if (rule.id === 'automatic-action' && facts?.resolved === true) {
      const triggered = AUTOMATIC_TRIGGERS.flatMap((trigger) => facts.triggered(trigger));
      if (triggered.length > 0 && triggered.every((action) => action.risk === 'low')) {
        severity = 'informational';
        title = 'Automatic actions only navigate';
        detail =
          'The /OpenAction and /AA entries only move to a page or change the view (for example "open at page 1"). This is common in legitimate documents.';
      }
    }
    findings.push({ id: rule.id, severity, title, detail, evidence });
  }

  const structural = (name: string) => counts.total(name) > 0 && !streamOnly.has(name);
  const hasScript = structural('/JS') || structural('/JavaScript');
  const hasAutomatic = structural('/OpenAction') || structural('/AA');
  if (facts?.resolved !== true) {
    // Without fully resolved actions, fall back to the keyword combination heuristic, unless
    // the deep analysis already confirmed the behaviour (a critical finding covers it).
    if (hasScript && hasAutomatic && (facts?.automaticScripts.length ?? 0) === 0) {
      findings.push({
        id: 'automatic-javascript',
        severity: 'priority',
        title: 'JavaScript combined with an automatic action',
        detail:
          'The file contains both JavaScript and an action that can run automatically, and PDF Signal could not confirm what the action does. This combination is typical of documents designed to run code without user interaction.',
        evidence: counts.evidence(['/JS', '/JavaScript', '/OpenAction', '/AA']),
      });
    }
    if (structural('/Launch') && hasAutomatic && (facts?.automaticLaunches.length ?? 0) === 0) {
      findings.push({
        id: 'automatic-launch',
        severity: 'priority',
        title: 'Launch action combined with an automatic action',
        detail:
          'A launch action together with an automatic trigger may try to start a program or open a file when the document is used.',
        evidence: counts.evidence(['/Launch', '/OpenAction', '/AA']),
      });
    }
  }

  const obfuscated = keywords.filter((keyword) => keyword.hexcodeCount > 0);
  if (obfuscated.length > 0) {
    findings.push({
      id: 'hex-obfuscation',
      severity: 'priority',
      title: 'Keywords written with hexadecimal escapes',
      detail:
        'Names such as /J#61vaScript are equivalent to /JavaScript but evade simple text searches. Legitimate PDF writers rarely escape these names, so this suggests deliberate obfuscation.',
      evidence: obfuscated.map((keyword) => `${keyword.name} × ${keyword.hexcodeCount} escaped`),
    });
  }

  const context: readonly [string, string, string][] = [
    ['acroform', '/AcroForm', 'Interactive form present'],
    ['object-streams', '/ObjStm', 'Object streams present'],
    ['encryption', '/Encrypt', 'Encryption dictionary present'],
  ];
  for (const [id, name, title] of context) {
    if (counts.total(name) > 0) {
      findings.push({
        id,
        severity: 'informational',
        title,
        detail: explanationFor(name).limits,
        evidence: counts.evidence([name]),
      });
    }
  }
  return findings;
}

function structuralFindings(scan: ScanResult, counts: Counts): Finding[] {
  const findings: Finding[] = [];
  const { header, eof, structure, obfuscation } = scan;

  if (structure !== null && !structure.objectKeywordsBalanced) {
    findings.push({
      id: 'object-mismatch',
      severity: 'review',
      title: '"obj" and "endobj" counts differ',
      detail:
        'Every object should open with "obj" and close with "endobj". A mismatch can mean a damaged or truncated file, or one malformed on purpose to confuse parsers.',
      evidence: [`obj × ${counts.visibleOf('obj')}`, `endobj × ${counts.visibleOf('endobj')}`],
    });
  }
  if (structure !== null && !structure.streamKeywordsBalanced) {
    findings.push({
      id: 'stream-mismatch',
      severity: 'review',
      title: '"stream" and "endstream" counts differ',
      detail:
        'A mismatch can mean a damaged or truncated file. Keywords can also occur inside stream data, which shifts these counts.',
      evidence: [
        `stream × ${counts.visibleOf('stream')}`,
        `endstream × ${counts.visibleOf('endstream')}`,
      ],
    });
  }
  if (header.found && header.offset !== null && header.offset > 0) {
    findings.push({
      id: 'header-offset',
      severity: 'review',
      title: 'Data before the PDF header',
      detail:
        'The %PDF header does not start at the beginning of the file. Readers tolerate this, but it is a known way to make a file look like another format (a polyglot) or to evade signature checks.',
      evidence: [`header at byte ${header.offset}`],
    });
  }
  if (header.found && !header.versionRecognized) {
    findings.push({
      id: 'header-version',
      severity: 'informational',
      title: 'Unusual PDF version in header',
      detail:
        'The header does not declare a published PDF version. This may indicate a damaged or hand-crafted file.',
      evidence: [header.text ?? 'no header text'],
    });
  }
  if (eof !== null && eof.trailingDataPresent && eof.trailingDataWhitespaceOnly === false) {
    findings.push({
      id: 'trailing-data',
      severity: 'review',
      title: 'Data after the last %%EOF marker',
      detail:
        'Readers ignore data after the end-of-file marker, which makes it a place to append hidden content. Some legitimate tools also append small amounts of data.',
      evidence: [`${eof.bytesAfterLastEof ?? 0} bytes after the last %%EOF`],
    });
  }
  if (eof?.eofCount === 0) {
    findings.push({
      id: 'eof-missing',
      severity: 'informational',
      title: 'No %%EOF marker',
      detail:
        'The file has no end-of-file marker and may be truncated, so parts of it may be missing from the scan.',
      evidence: ['%%EOF × 0'],
    });
  } else if (eof !== null && eof.eofCount > 1) {
    findings.push({
      id: 'incremental-updates',
      severity: 'informational',
      title: 'Several %%EOF markers',
      detail:
        'The file was probably updated incrementally (edited, annotated or signed). Earlier revisions remain in the file and are included in the counts.',
      evidence: [`%%EOF × ${eof.eofCount}`],
    });
  }
  if (structure?.endedInsideStream === true) {
    findings.push({
      id: 'ended-inside-stream',
      severity: 'informational',
      title: 'File ends inside a stream',
      detail: 'The data stops before the stream is closed, which suggests a truncated file.',
      evidence: ['stream without a later endstream'],
    });
  }
  if (obfuscation !== null && obfuscation.malformedHexEscapes > 0) {
    findings.push({
      id: 'malformed-escapes',
      severity: 'informational',
      title: 'Malformed escapes in names',
      detail:
        'Some names contain "#" without two hexadecimal digits. This is invalid PDF syntax and can confuse parsers.',
      evidence: [`${obfuscation.malformedHexEscapes} malformed escape(s)`],
    });
  }
  return findings;
}

/** Status of /OpenAction or /AA from the actions they trigger. */
function triggerStatus(
  name: string,
  facts: ActionFacts | null,
  hasScript: boolean,
): KeywordInterpretation['status'] {
  if (facts === null) {
    return hasScript ? 'danger' : 'review';
  }
  const actions = facts.triggered(name);
  if (actions.some((action) => action.risk === 'high')) {
    return 'danger';
  }
  if (actions.some((action) => action.risk === 'medium')) {
    return 'review';
  }
  return actions.length > 0 && facts.resolved ? 'informational' : 'review';
}

function triggerText(name: string, facts: ActionFacts | null): string {
  const actions = facts?.triggered(name) ?? [];
  if (actions.length === 0) {
    return 'PDF Signal could not determine what this action does.';
  }
  const types = [...new Set(actions.map((action) => action.action))].join(', ');
  return `It triggers: ${types}.`;
}

function interpret(
  keyword: KeywordCount,
  counts: Counts,
  facts: ActionFacts | null,
  reviewNames: ReadonlySet<string>,
  deep: DeepScanResult | null,
  streamOnly: ReadonlySet<string>,
): KeywordInterpretation {
  const { name, count, hexcodeCount, kind } = keyword;
  const hiddenCount = counts.hiddenOf(name);
  if (count === 0 && hiddenCount === 0) {
    return {
      name,
      status: 'absent',
      text:
        kind === 'indicator'
          ? 'Not found by this scan. Absence does not show that the file is safe.'
          : 'Not found.',
      hiddenCount,
    };
  }
  let text =
    count > 0
      ? `Found ${times(count)}.`
      : `Not visible in the file's bytes, but found ${times(hiddenCount)} inside compressed object streams.`;
  if (count > 0 && hiddenCount > 0) {
    text += ` Another ${hiddenCount} hidden inside compressed object streams.`;
  }
  if (hexcodeCount > 0) {
    text += ` ${hexcodeCount} of these used hexadecimal escapes, a common obfuscation technique.`;
  }

  const hasScript = counts.total('/JS') + counts.total('/JavaScript') > 0;
  if (streamOnly.has(name)) {
    return {
      name,
      status: 'informational',
      text: `${text} It occurs only inside stream data, strings or comments, not in the document structure, so it has no effect.`,
      hiddenCount,
    };
  }
  if (name === '/EmbeddedFile' && (deep?.attachments.executable ?? 0) > 0) {
    return {
      name,
      status: 'danger',
      text: `${text} At least one attached file is a program or script file type.`,
      hiddenCount,
    };
  }
  if (CODE_EXECUTION_KEYWORDS.has(name)) {
    const automatic = name === '/Launch' ? facts?.automaticLaunches : facts?.automaticScripts;
    const suffix =
      automatic !== undefined && automatic.length > 0
        ? ' It runs automatically, without any click.'
        : ' It can make the PDF reader run code or start programs.';
    return { name, status: 'danger', text: `${text}${suffix}`, hiddenCount };
  }
  if (name === '/OpenAction' || name === '/AA') {
    return {
      name,
      status: triggerStatus(name, facts, hasScript),
      text: `${text} ${triggerText(name, facts)}`,
      hiddenCount,
    };
  }
  if (reviewNames.has(name)) {
    return {
      name,
      status: 'review',
      text: `${text} This indicator warrants a closer look in context.`,
      hiddenCount,
    };
  }
  if (CONTEXT_INDICATORS.has(name)) {
    return { name, status: 'informational', text: `${text} Noted for context.`, hiddenCount };
  }
  return { name, status: 'informational', text, hiddenCount };
}

function visibilityLimitsFor(scan: ScanResult, counts: Counts): string[] {
  const limits: string[] = [];
  const deep = scan.deep;
  if (!scan.keywordScanPerformed) {
    limits.push('The keyword scan was not performed because the file has no PDF header.');
  }
  if (scan.mode === 'forced') {
    limits.push(
      'The file has no PDF header and was scanned in forced mode; it may not be a PDF at all.',
    );
  }
  const objectStreamsInspected =
    deep !== null && deep.status !== 'failed' && deep.decodeFailures === 0;
  if (counts.visibleOf('/ObjStm') > 0 && !objectStreamsInspected) {
    limits.push(
      'Object streams are present and could not all be decompressed, so keywords inside them may be missing.',
    );
  }
  if (
    deep !== null && deep.status !== 'failed' ? deep.encrypted : counts.visibleOf('/Encrypt') > 0
  ) {
    limits.push('The document is encrypted: encrypted strings and streams cannot be inspected.');
  }
  if (scan.eof?.eofCount === 0 || scan.structure?.endedInsideStream === true) {
    limits.push('The file appears to be truncated, so part of it may be missing.');
  }
  for (const note of deep?.notes ?? []) {
    if (!limits.includes(note)) {
      limits.push(note);
    }
  }
  return limits;
}

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 3,
  priority: 2,
  review: 1,
  informational: 0,
};

/** Assesses a scan result with the documented, deterministic rules above. */
export function assessIndicators(scan: ScanResult): Assessment {
  const counts = new Counts(scan.keywords, scan.deep);
  const streamOnly = streamOnlyNames(scan.deep, counts);
  const facts = actionFacts(scan.deep, counts, streamOnly);
  const findings = scan.keywordScanPerformed
    ? [
        ...deepFindings(scan.deep, facts, counts),
        ...indicatorFindings(counts, scan.keywords, facts, streamOnly),
        ...structuralFindings(scan, counts),
      ]
    : [];
  const significant = findings.filter((finding) => finding.severity !== 'informational').length;

  let level: AssessmentLevel;
  if (findings.some((finding) => finding.severity === 'critical')) {
    // A critical finding is shown even in forced mode, where the file may not be a PDF.
    level = 'high-risk';
  } else if (!scan.keywordScanPerformed || scan.mode === 'forced') {
    level = 'inconclusive';
  } else if (significant === 0) {
    level = 'none-detected';
  } else if (significant === 1) {
    level = 'review';
  } else {
    level = 'multiple';
  }

  const reviewNames = new Set(REVIEW_INDICATORS.flatMap((rule) => rule.names));
  return {
    rulesVersion: RULES_VERSION,
    level,
    headline: HEADLINES[level],
    summary: level === 'inconclusive' && scan.mode === 'forced' ? FORCED_SUMMARY : SUMMARIES[level],
    advice: ADVICE[level],
    findings: [...findings].sort(
      (left, right) => SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity],
    ),
    interpretations: scan.keywords.map((keyword) =>
      interpret(keyword, counts, facts, reviewNames, scan.deep, streamOnly),
    ),
    visibilityLimits: visibilityLimitsFor(scan, counts),
    disclaimer: TRIAGE_DISCLAIMER,
  };
}
