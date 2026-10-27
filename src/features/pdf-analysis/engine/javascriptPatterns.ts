import type { ScriptPatternSeverity } from '../types/analysis';

/**
 * Constructs that malicious PDF JavaScript commonly uses: dynamic code execution, payload
 * decoding, heap-spray data and Acrobat APIs with a history of exploitation. Matching is plain,
 * case-sensitive substring search (no regular expressions over file data). Scripts are analysed
 * in memory and discarded; only pattern identifiers and counts are kept.
 */
export interface ScriptPattern {
  readonly id: string;
  readonly label: string;
  readonly severity: ScriptPatternSeverity;
  readonly description: string;
  readonly needles: readonly string[];
  /** Minimum number of occurrences (across all needles) required. Defaults to 1. */
  readonly minimum?: number;
  /** Extra condition checked once a needle matched, to avoid flagging ordinary uses. */
  readonly confirm?: (script: string) => boolean;
}

/**
 * CVE-2008-2992 needs a huge field width, as in util.printf("%45000f", x). Ordinary form
 * scripts call util.printf("%.2f", value), which must not be flagged.
 */
function hasOversizedPrintfWidth(script: string): boolean {
  let from = 0;
  for (let count = 0; count < 1000; count++) {
    const found = script.indexOf('util.printf', from);
    if (found < 0) {
      return false;
    }
    from = found + 'util.printf'.length;
    const window = script.slice(from, from + 80);
    for (let index = window.indexOf('%'); index >= 0; index = window.indexOf('%', index + 1)) {
      let digits = 0;
      for (; digits < 6; digits++) {
        const code = window.charCodeAt(index + 1 + digits);
        if (code < 0x30 || code > 0x39) {
          break;
        }
      }
      if (digits >= 4) {
        return true;
      }
    }
  }
  return false;
}

export const SCRIPT_PATTERNS: readonly ScriptPattern[] = [
  {
    id: 'heap-spray',
    label: 'Heap-spray filler data',
    severity: 'high',
    description:
      'Repeated 0x0c / 0x0a filler values, characteristic of heap-spray exploits that place shellcode in memory.',
    needles: ['%u0c0c%u0c0c', '%u0a0a%u0a0a', '\\x0c\\x0c\\x0c\\x0c', '0x0c0c0c0c', '0x0a0a0a0a'],
  },
  {
    id: 'unicode-escaped-payload',
    label: '%u-encoded binary data',
    severity: 'high',
    description: 'Long runs of %uXXXX escapes, the usual way exploit scripts embed shellcode.',
    needles: ['%u'],
    minimum: 32,
  },
  {
    id: 'util-printf',
    label: 'util.printf',
    severity: 'high',
    description:
      'util.printf with a huge field width, the trigger of CVE-2008-2992 (stack overflow).',
    needles: ['util.printf'],
    confirm: hasOversizedPrintfWidth,
  },
  {
    id: 'collab-collect-email',
    label: 'Collab.collectEmailInfo',
    severity: 'high',
    description: 'Acrobat API exploited by CVE-2007-5659.',
    needles: ['collectEmailInfo'],
  },
  {
    id: 'collab-get-icon',
    label: 'Collab.getIcon',
    severity: 'high',
    description: 'Acrobat API exploited by CVE-2009-0927.',
    needles: ['Collab.getIcon'],
  },
  {
    id: 'media-new-player',
    label: 'media.newPlayer',
    severity: 'high',
    description: 'Acrobat API exploited by CVE-2009-4324.',
    needles: ['newPlayer'],
  },
  {
    id: 'custom-dictionary-open',
    label: 'spell.customDictionaryOpen',
    severity: 'high',
    description: 'Acrobat API exploited by CVE-2009-1493.',
    needles: ['customDictionaryOpen'],
  },
  {
    id: 'print-seps',
    label: 'printSeps',
    severity: 'high',
    description: 'Acrobat API exploited by CVE-2010-4091.',
    needles: ['printSeps'],
  },
  {
    id: 'export-and-launch',
    label: 'exportDataObject with nLaunch',
    severity: 'high',
    description:
      'Extracts an embedded file and asks the reader to open it, a common way to drop and run a payload.',
    needles: ['nLaunch'],
  },
  {
    id: 'eval',
    label: 'eval()',
    severity: 'medium',
    description:
      'Runs code built at run time. Malicious scripts use it to execute decoded payloads.',
    needles: ['eval(', 'eval ('],
  },
  {
    id: 'unescape',
    label: 'unescape()',
    severity: 'medium',
    description: 'Decodes escaped strings; often used to unpack hidden code or binary data.',
    needles: ['unescape('],
  },
  {
    id: 'from-char-code',
    label: 'String.fromCharCode',
    severity: 'medium',
    description: 'Builds strings from character codes, a common obfuscation technique.',
    needles: ['fromCharCode'],
  },
  {
    id: 'function-constructor',
    label: 'Function constructor / timed code',
    severity: 'medium',
    description:
      'Creates or schedules code from strings (new Function, app.setTimeOut, app.setInterval).',
    needles: ['new Function', 'setTimeOut(', 'setInterval('],
  },
  {
    id: 'get-annots',
    label: 'getAnnots',
    severity: 'medium',
    description:
      'Reads annotation data; misused to hide payloads in annotations and exploited by CVE-2009-1492.',
    needles: ['getAnnots', 'syncAnnotScan'],
  },
  {
    id: 'export-data-object',
    label: 'exportDataObject',
    severity: 'medium',
    description: 'Saves an embedded file to disk.',
    needles: ['exportDataObject'],
  },
  {
    id: 'external-communication',
    label: 'Network or mail access',
    severity: 'medium',
    description:
      'Opens web addresses, submits data or sends mail (launchURL, submitForm, SOAP, Net.HTTP, mailDoc).',
    needles: [
      'launchURL',
      'submitForm',
      'SOAP.',
      'Net.HTTP',
      'getURL(',
      'mailDoc',
      'mailMsg',
      'mailForm',
    ],
  },
  {
    id: 'hex-escaped-data',
    label: 'Many \\x escapes',
    severity: 'medium',
    description: 'Long runs of \\xNN escapes, often used to hide code or binary data.',
    needles: ['\\x'],
    minimum: 64,
  },
  {
    id: 'alert',
    label: 'app.alert',
    severity: 'low',
    description: 'Shows a dialog box; harmless on its own but used for social-engineering prompts.',
    needles: ['app.alert'],
  },
];

/** A run of this many characters without a line break suggests packed or encoded code. */
const LONG_LINE = 20_000;

export const LONG_LINE_PATTERN: ScriptPattern = {
  id: 'long-line',
  label: 'Very long single line',
  severity: 'medium',
  description:
    'More than 20,000 characters on one line, typical of packed, minified-then-obfuscated or encoded payloads.',
  needles: [],
};

export const EVAL_DECODE_PATTERN: ScriptPattern = {
  id: 'eval-decoded-code',
  label: 'eval() of decoded data',
  severity: 'high',
  description:
    'Combines eval() with unescape() or String.fromCharCode, the classic way to run a hidden payload.',
  needles: [],
};

function countOccurrences(text: string, needle: string, stopAt: number): number {
  let count = 0;
  let from = 0;
  while (count < stopAt) {
    const found = text.indexOf(needle, from);
    if (found < 0) {
      break;
    }
    count++;
    from = found + needle.length;
  }
  return count;
}

function hasLongLine(text: string): boolean {
  let lineStart = 0;
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code === 10 || code === 13) {
      lineStart = index + 1;
    } else if (index - lineStart >= LONG_LINE) {
      return true;
    }
  }
  return false;
}

/** Returns the identifiers of the patterns present in one script. */
export function findScriptPatterns(script: string): ScriptPattern[] {
  const found = SCRIPT_PATTERNS.filter((pattern) => {
    const minimum = pattern.minimum ?? 1;
    let occurrences = 0;
    for (const needle of pattern.needles) {
      occurrences += countOccurrences(script, needle, minimum - occurrences);
      if (occurrences >= minimum) {
        return pattern.confirm?.(script) ?? true;
      }
    }
    return false;
  });
  const ids = new Set(found.map((pattern) => pattern.id));
  if (ids.has('eval') && (ids.has('unescape') || ids.has('from-char-code'))) {
    found.push(EVAL_DECODE_PATTERN);
  }
  if (hasLongLine(script)) {
    found.push(LONG_LINE_PATTERN);
  }
  return found;
}

// Shared decoders. WHATWG maps the "latin1" label to windows-1252, which differs from ISO-8859-1
// only in 0x80–0x9F; that is irrelevant for the ASCII patterns and extensions matched here.
const SINGLE_BYTE = typeof TextDecoder === 'function' ? new TextDecoder('latin1') : null;
const UTF16BE = typeof TextDecoder === 'function' ? new TextDecoder('utf-16be') : null;

/** Decodes PDF string or script bytes: UTF-16BE after a byte-order mark, otherwise one byte per character. */
export function scriptBytesToText(bytes: Uint8Array): string {
  const utf16 = bytes[0] === 0xfe && bytes[1] === 0xff;
  const decoder = utf16 ? UTF16BE : SINGLE_BYTE;
  if (decoder !== null) {
    return decoder.decode(utf16 ? bytes.subarray(2) : bytes);
  }
  let text = '';
  if (utf16) {
    for (let index = 2; index + 1 < bytes.length; index += 2) {
      text += String.fromCharCode(((bytes[index] ?? 0) << 8) | (bytes[index + 1] ?? 0));
    }
    return text;
  }
  for (const byte of bytes) {
    text += String.fromCharCode(byte);
  }
  return text;
}
