import { describe, expect, it } from 'vitest';
import {
  assessIndicators,
  RULES_VERSION,
} from '../../src/features/pdf-analysis/assessment/assessIndicators';
import {
  explanationFor,
  INDICATOR_EXPLANATIONS,
} from '../../src/features/pdf-analysis/assessment/indicatorExplanations';
import { ALL_COUNTERS } from '../../src/features/pdf-analysis/engine/pdfidKeywords';
import { analyzePdf } from '../../src/features/pdf-analysis/engine/analyzePdf';
import { scanPdf } from '../../src/features/pdf-analysis/engine/scanPdf';
import type { Assessment } from '../../src/features/pdf-analysis/types/analysis';
import { BASIC_OBJECTS, bytes, createTestPdf, type PdfObjectSpec } from '../fixtures/createTestPdf';
import { getFixture } from '../fixtures/fixtureDefinitions';

function assessObjects(
  extra: readonly PdfObjectSpec[],
  options: Parameters<typeof createTestPdf>[0] = { objects: [] },
) {
  const pdf = createTestPdf({ ...options, objects: [...BASIC_OBJECTS, ...extra] });
  return assessIndicators(scanPdf(pdf, { sha256: 'x' }));
}

const ids = (assessment: Assessment) => assessment.findings.map((finding) => finding.id);

describe('assessIndicators', () => {
  it('reports no configured indicators for a plain document, without calling it safe', () => {
    const assessment = assessObjects([]);
    expect(assessment).toMatchObject({
      rulesVersion: RULES_VERSION,
      level: 'none-detected',
      headline: 'No configured suspicious indicators detected',
      findings: [],
      visibilityLimits: [],
    });
    expect(assessment.summary).toMatch(/not a statement that the file is safe/);
    expect(assessment.disclaimer).toMatch(/not an antivirus product/);
    expect(assessment.headline).not.toMatch(/safe|clean|benign|malware-free/i);
    expect(assessment.summary.replace('not a statement that the file is safe', '')).not.toMatch(
      /safe|clean|benign/i,
    );
  });

  it.each([
    ['/EmbeddedFile', 'embedded-file'],
    ['/Launch', 'launch'],
    ['/RichMedia', 'rich-media'],
    ['/XFA', 'xfa'],
    ['/JBIG2Decode', 'jbig2'],
    ['/OpenAction', 'automatic-action'],
    ['/AA', 'automatic-action'],
    ['/JS', 'javascript'],
    ['/JavaScript', 'javascript'],
  ])('flags a single %s for review', (name, id) => {
    const assessment = assessObjects([{ body: `<< ${name} 1 >>` }]);
    expect(assessment.level).toBe('review');
    expect(assessment.headline).toBe('Indicators warrant further investigation');
    expect(ids(assessment)).toEqual([id]);
    expect(assessment.findings[0]?.severity).toBe('review');
    expect(assessment.findings[0]?.evidence).toEqual([`${name} × 1`]);
  });

  it('groups /JS and /JavaScript into one finding', () => {
    const assessment = assessIndicators(scanPdf(getFixture('javascript-open-action').build()));
    expect(ids(assessment).filter((id) => id === 'javascript')).toHaveLength(1);
  });

  it('flags the /Colors > 2^24 pattern', () => {
    expect(ids(assessObjects([{ body: '<< /Colors 16777217 >>' }]))).toEqual([
      'colors-cve-2009-3459',
    ]);
  });

  it('escalates JavaScript with an automatic action to a priority combination', () => {
    const assessment = assessIndicators(scanPdf(getFixture('javascript-open-action').build()));
    expect(assessment.level).toBe('multiple');
    expect(assessment.headline).toBe('Multiple potentially suspicious indicators detected');
    expect(assessment.findings[0]).toMatchObject({
      id: 'automatic-javascript',
      severity: 'priority',
    });
    expect(ids(assessment)).toEqual(['automatic-javascript', 'javascript', 'automatic-action']);
  });

  it('escalates a launch action with an automatic action', () => {
    const assessment = assessObjects([{ body: '<< /OpenAction << /S /Launch /F (x) >> >>' }]);
    expect(ids(assessment)).toContain('automatic-launch');
    expect(assessment.level).toBe('multiple');
  });

  it('treats hex-escaped keywords as priority obfuscation', () => {
    const assessment = assessObjects([{ body: '<< /Ty#70e /Pa#67e >>' }]);
    expect(ids(assessment)).toEqual(['hex-obfuscation']);
    expect(assessment.level).toBe('review');
    expect(assessment.findings[0]?.evidence).toEqual(['/Page × 1 escaped']);

    const scripted = assessIndicators(scanPdf(getFixture('hex-obfuscated-names').build()));
    expect(scripted.level).toBe('multiple');
    expect(scripted.findings.find((finding) => finding.id === 'hex-obfuscation')?.severity).toBe(
      'priority',
    );
  });

  it('records forms, object streams and encryption as context only', () => {
    const assessment = assessObjects(
      [{ body: '<< /AcroForm << >> >>' }, { body: '<< /Type /ObjStm >>', stream: '' }],
      { objects: [], trailerEntries: ' /Encrypt 9 0 R' },
    );
    expect(assessment.level).toBe('none-detected');
    expect(assessment.findings.every((finding) => finding.severity === 'informational')).toBe(true);
    expect(ids(assessment)).toEqual(['acroform', 'object-streams', 'encryption']);
    expect(assessment.visibilityLimits.join(' ')).toMatch(/Object streams/);
    expect(assessment.visibilityLimits.join(' ')).toMatch(/encrypted/);
  });

  it('flags structural inconsistencies for review', () => {
    const mismatch = assessIndicators(
      scanPdf(bytes('%PDF-1.7\n1 0 obj << >> 2 0 obj stream\nx\n%%EOF\n')),
    );
    expect(ids(mismatch)).toEqual(
      expect.arrayContaining(['object-mismatch', 'stream-mismatch', 'ended-inside-stream']),
    );
    expect(mismatch.level).toBe('multiple');
  });

  it('flags data before the header and after the last %%EOF', () => {
    expect(ids(assessIndicators(scanPdf(getFixture('header-after-prefix').build())))).toEqual([
      'header-offset',
    ]);
    expect(ids(assessIndicators(scanPdf(getFixture('trailing-data').build())))).toEqual([
      'trailing-data',
    ]);
    expect(assessIndicators(scanPdf(getFixture('trailing-whitespace').build())).findings).toEqual(
      [],
    );
  });

  it('treats incremental updates and unusual versions as context', () => {
    const updated = assessIndicators(scanPdf(getFixture('incremental-update').build()));
    expect(updated.level).toBe('none-detected');
    expect(ids(updated)).toEqual(['incremental-updates']);
    expect(
      ids(assessIndicators(scanPdf(getFixture('header-unpublished-version').build()))),
    ).toEqual(['header-version']);
  });

  it('notes truncation as a visibility limit', () => {
    const assessment = assessIndicators(scanPdf(getFixture('truncated-in-stream').build()));
    expect(assessment.visibilityLimits.join(' ')).toMatch(/truncated/);
    expect(ids(assessment)).toEqual(
      expect.arrayContaining(['eof-missing', 'ended-inside-stream', 'stream-mismatch']),
    );
  });

  it('notes malformed escapes as context', () => {
    expect(ids(assessObjects([{ body: '<< /A#ZZ 1 >>' }]))).toEqual(['malformed-escapes']);
  });

  it('is inconclusive when the scan was skipped or forced', () => {
    const skipped = assessIndicators(scanPdf(getFixture('no-header').build()));
    expect(skipped).toMatchObject({
      level: 'inconclusive',
      headline: 'Analysis incomplete or inconclusive',
      findings: [],
    });
    expect(skipped.visibilityLimits[0]).toMatch(/not performed/);

    const forced = assessIndicators(
      scanPdf(bytes('1 0 obj << /JS (x) >> endobj'), { force: true }),
    );
    expect(forced.level).toBe('inconclusive');
    expect(ids(forced)).toContain('javascript');
  });

  it('interprets every counter, including zero counts', () => {
    const scan = scanPdf(getFixture('hex-obfuscated-names').build());
    const assessment = assessIndicators(scan);
    expect(assessment.interpretations.map((interpretation) => interpretation.name)).toEqual(
      scan.keywords.map((keyword) => keyword.name),
    );
    const byName = (name: string) =>
      assessment.interpretations.find((interpretation) => interpretation.name === name);
    expect(byName('/JavaScript')).toMatchObject({ status: 'danger', hiddenCount: 0 });
    expect(byName('/JavaScript')?.text).toMatch(
      /Found 2 times.*2 of these used hexadecimal escapes/,
    );
    expect(byName('/XFA')).toEqual({
      name: '/XFA',
      status: 'absent',
      text: 'Not found by this scan. Absence does not show that the file is safe.',
      hiddenCount: 0,
    });
    expect(byName('obj')).toMatchObject({ status: 'informational', text: 'Found 6 times.' });
    expect(byName('xref')?.text).toBe('Found once.');
  });

  it('is deterministic', () => {
    const scan = scanPdf(getFixture('all-indicators').build(), { now: () => new Date(0) });
    expect(assessIndicators(scan)).toEqual(assessIndicators(scan));
    expect(new Set(ids(assessIndicators(scan))).size).toBe(ids(assessIndicators(scan)).length);
  });
});

describe('indicator explanations', () => {
  it('explain every counter with what it is, why it matters and its limits', () => {
    for (const counter of ALL_COUNTERS) {
      const explanation = INDICATOR_EXPLANATIONS[counter.name];
      expect(explanation, counter.name).toBeDefined();
      expect(explanation?.whatItIs.length).toBeGreaterThan(10);
      expect(explanation?.whyInvestigate.length).toBeGreaterThan(10);
      expect(explanation?.limits.length).toBeGreaterThan(10);
    }
  });

  it('fall back to a generic explanation for unknown names', () => {
    expect(explanationFor('/Unknown').whatItIs).toMatch(/PDF keyword/);
  });
});

describe('assessIndicators with deep analysis', () => {
  const assessDeep = async (id: string) =>
    assessIndicators(await analyzePdf(getFixture(id).build(), { sha256: 'x' }));
  const severities = (assessment: Assessment) =>
    Object.fromEntries(assessment.findings.map((finding) => [finding.id, finding.severity]));
  const statusOf = (assessment: Assessment, name: string) =>
    assessment.interpretations.find((interpretation) => interpretation.name === name)?.status;

  it('rates confirmed automatic JavaScript as high risk', async () => {
    const assessment = await assessDeep('javascript-open-action');
    expect(assessment.level).toBe('high-risk');
    expect(assessment.headline).toBe('High-risk indicators detected');
    expect(assessment.summary).toMatch(/potentially malicious/);
    expect(assessment.findings[0]).toMatchObject({ id: 'auto-javascript', severity: 'critical' });
    expect(assessment.findings[0]?.evidence).toEqual(['/OpenAction → JavaScript × 1']);
    // The confirmed finding replaces the keyword-combination heuristic.
    expect(severities(assessment)).not.toHaveProperty('automatic-javascript');
  });

  it('marks code-running entries as dangers', async () => {
    const assessment = await assessDeep('javascript-open-action');
    expect(statusOf(assessment, '/JS')).toBe('danger');
    expect(statusOf(assessment, '/JavaScript')).toBe('danger');
    expect(statusOf(assessment, '/OpenAction')).toBe('danger');
    const js = assessment.interpretations.find(
      (interpretation) => interpretation.name === '/JavaScript',
    );
    expect(js?.text).toMatch(/runs automatically/);
  });

  it('downgrades an open action that only navigates', async () => {
    const assessment = await assessDeep('openaction-destination');
    expect(assessment.level).toBe('none-detected');
    expect(severities(assessment)).toEqual({ 'automatic-action': 'informational' });
    expect(assessment.findings[0]?.title).toBe('Automatic actions only navigate');
    expect(statusOf(assessment, '/OpenAction')).toBe('informational');
  });

  it('does not treat an interactive form script as high risk', async () => {
    const assessment = await assessDeep('form-field-script');
    expect(assessment.level).toBe('multiple');
    expect(Object.values(severities(assessment))).not.toContain('critical');
    expect(statusOf(assessment, '/JS')).toBe('danger');
  });

  it('flags indicators hidden in object streams and counts them', async () => {
    const assessment = await assessDeep('objstm-hidden-javascript');
    expect(assessment.level).toBe('high-risk');
    expect(severities(assessment)).toMatchObject({
      'auto-javascript': 'critical',
      'hidden-indicators': 'review',
    });
    const js = assessment.interpretations.find(
      (interpretation) => interpretation.name === '/JavaScript',
    );
    expect(js).toMatchObject({ status: 'danger', hiddenCount: 1 });
    expect(js?.text).toMatch(
      /Not visible in the file's bytes, but found once inside compressed object streams/,
    );
    expect(assessment.visibilityLimits.join(' ')).not.toMatch(/Object streams are present/);
  });

  it('flags launches of executables and automatic launches', async () => {
    const assessment = await assessDeep('launch-executable');
    expect(severities(assessment)).toMatchObject({
      'auto-launch': 'critical',
      'launch-executable': 'critical',
    });
    expect(statusOf(assessment, '/Launch')).toBe('danger');
  });

  it('flags exploit-style script content', async () => {
    const assessment = await assessDeep('filter-chain-script');
    expect(assessment.level).toBe('high-risk');
    expect(
      assessment.findings.find((finding) => finding.id === 'exploit-script-patterns')?.evidence,
    ).toEqual(['util.printf']);
    const medium = await assessDeep('obfuscated-filter-and-action');
    expect(medium.findings.find((finding) => finding.id === 'script-patterns')).toMatchObject({
      severity: 'review',
    });
  });

  it('flags automatic actions that reach outside the document', async () => {
    const assessment = await assessDeep('openaction-uri');
    expect(assessment.level).toBe('multiple');
    expect(severities(assessment)).toMatchObject({ 'auto-external-action': 'review' });
    expect(statusOf(assessment, '/OpenAction')).toBe('review');
  });

  it('falls back to the keyword heuristic when actions cannot be resolved', async () => {
    const pdf = createTestPdf({
      objects: [{ body: '<< /Type /Catalog /OpenAction 99 0 R >>' }, { body: '<< /JS (x) >>' }],
    });
    const assessment = assessIndicators(await analyzePdf(pdf));
    expect(severities(assessment)).toMatchObject({ 'automatic-javascript': 'priority' });
    expect(assessment.level).not.toBe('high-risk');
  });

  it('lists deep-analysis limits as visibility limits', async () => {
    const pdf = createTestPdf({
      objects: [
        ...BASIC_OBJECTS,
        { body: '<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode >>', stream: 'not zlib' },
      ],
    });
    const assessment = assessIndicators(await analyzePdf(pdf));
    expect(assessment.visibilityLimits.join(' ')).toMatch(/could not all be decompressed/);
    expect(assessment.visibilityLimits.join(' ')).toMatch(/could not be decoded/);
  });
});

describe('keywords that only occur in stream data', () => {
  it('downgrades keywords that never occur in the document structure', async () => {
    const assessment = assessIndicators(
      await analyzePdf(getFixture('keywords-in-stream-data').build()),
    );
    expect(assessment.level).toBe('none-detected');
    const status = (name: string) => assessment.interpretations.find((item) => item.name === name);
    expect(status('/JavaScript')).toMatchObject({ status: 'informational' });
    expect(status('/JavaScript')?.text).toMatch(/only inside stream data, strings or comments/);
    expect(assessment.findings.find((finding) => finding.id === 'javascript')).toMatchObject({
      severity: 'informational',
    });
  });

  it('downgrades /JS bytes that happen to occur in binary image data', async () => {
    const image = bytes([0x89, 0x10], '/JS ', [0xff, 0x00, 0x7f], '/AA ', [0x01]);
    const pdf = createTestPdf({
      objects: [...BASIC_OBJECTS, { body: '<< /Type /XObject /Subtype /Image >>', stream: image }],
    });
    const scan = await analyzePdf(pdf);
    expect(scan.keywords.find((keyword) => keyword.name === '/JS')?.count).toBe(1);
    expect(assessIndicators(scan).level).toBe('none-detected');
  });

  it('never downgrades when the deep analysis was incomplete', async () => {
    const pdf = createTestPdf({
      objects: [
        ...BASIC_OBJECTS,
        { body: '<< /Length 20 >>', stream: 'BT /JavaScript ET' },
        { body: '<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode >>', stream: 'not zlib' },
      ],
    });
    const assessment = assessIndicators(await analyzePdf(pdf));
    expect(assessment.findings.find((finding) => finding.id === 'javascript')?.severity).toBe(
      'review',
    );
    expect(assessment.level).not.toBe('none-detected');
  });

  it('keeps real script keys at review or higher', async () => {
    const assessment = assessIndicators(await analyzePdf(getFixture('form-field-script').build()));
    expect(assessment.findings.find((finding) => finding.id === 'javascript')?.severity).toBe(
      'review',
    );
  });
});
