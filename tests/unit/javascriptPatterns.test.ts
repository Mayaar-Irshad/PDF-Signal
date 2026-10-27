import { describe, expect, it } from 'vitest';
import {
  findScriptPatterns,
  SCRIPT_PATTERNS,
  scriptBytesToText,
} from '../../src/features/pdf-analysis/engine/javascriptPatterns';
import { bytes } from '../fixtures/createTestPdf';

const ids = (script: string) =>
  findScriptPatterns(script)
    .map((pattern) => pattern.id)
    .sort();

describe('findScriptPatterns', () => {
  it('finds nothing in an ordinary form script', () => {
    expect(
      ids('AFNumber_Format(2, 0, 0, 0, "", true); event.value = this.getField("a").value * 2;'),
    ).toEqual([]);
  });

  it.each([
    ['var s = "%u0c0c%u0c0c";', 'heap-spray'],
    ['util.printf("%45000f", 1);', 'util-printf'],
    ['Collab.collectEmailInfo({ msg: x });', 'collab-collect-email'],
    ['Collab.getIcon(n);', 'collab-get-icon'],
    ['media.newPlayer(null);', 'media-new-player'],
    ['spell.customDictionaryOpen(0, x);', 'custom-dictionary-open'],
    ['this.printSeps();', 'print-seps'],
    ['this.exportDataObject({ cName: "a", nLaunch: 2 });', 'export-and-launch'],
    ['app.setTimeOut("x()", 10);', 'function-constructor'],
    ['this.getAnnots();', 'get-annots'],
    ['app.launchURL("x");', 'external-communication'],
    ['app.alert("hi");', 'alert'],
  ])('flags %s as %s', (script, id) => {
    expect(ids(script)).toContain(id);
  });

  it('combines eval with decoding into a high-severity pattern', () => {
    expect(ids('eval(unescape("%61"))')).toEqual(['eval', 'eval-decoded-code', 'unescape']);
    expect(ids('eval (String.fromCharCode(97))')).toEqual([
      'eval',
      'eval-decoded-code',
      'from-char-code',
    ]);
    expect(ids('eval(x)')).toEqual(['eval']);
  });

  it('requires enough escapes before flagging encoded payloads', () => {
    expect(ids('%u4141'.repeat(31))).toEqual([]);
    expect(ids('%u4141'.repeat(32))).toEqual(['unicode-escaped-payload']);
    expect(ids('\\x41'.repeat(63))).toEqual([]);
    expect(ids('\\x41'.repeat(64))).toEqual(['hex-escaped-data']);
  });

  it('flags very long lines only', () => {
    expect(ids('a'.repeat(20_001))).toEqual(['long-line']);
    expect(ids(`${'a'.repeat(15_000)}\n${'a'.repeat(15_000)}`)).toEqual([]);
  });

  it('is case-sensitive like JavaScript identifiers', () => {
    expect(ids('EVAL(x); UTIL.PRINTF()')).toEqual([]);
  });

  it('defines every pattern with a label, description and needles', () => {
    for (const pattern of SCRIPT_PATTERNS) {
      expect(pattern.label.length).toBeGreaterThan(2);
      expect(pattern.description.length).toBeGreaterThan(10);
      expect(pattern.needles.length).toBeGreaterThan(0);
    }
  });
});

describe('scriptBytesToText', () => {
  it('decodes UTF-16BE with a byte-order mark', () => {
    expect(scriptBytesToText(bytes([0xfe, 0xff, 0, 0x65, 0, 0x76, 0, 0x61, 0, 0x6c]))).toBe('eval');
  });

  it('decodes other bytes one character per byte', () => {
    expect(scriptBytesToText(bytes('eval(', [0xe9], ')'))).toBe('eval(é)');
  });
});
