import { describe, expect, it } from 'vitest';
import { assessIndicators } from '../../src/features/pdf-analysis/assessment/assessIndicators';
import { analyzePdf } from '../../src/features/pdf-analysis/engine/analyzePdf';
import {
  classifyFileName,
  classifyTarget,
  deepScanPdf,
} from '../../src/features/pdf-analysis/engine/deepScan';
import type { Assessment } from '../../src/features/pdf-analysis/types/analysis';
import { BASIC_OBJECTS, createTestPdf } from '../fixtures/createTestPdf';
import { getFixture } from '../fixtures/fixtureDefinitions';

const severities = (assessment: Assessment) =>
  Object.fromEntries(assessment.findings.map((finding) => [finding.id, finding.severity]));

describe('classifyFileName', () => {
  it.each([
    ['setup.exe', 'executable'],
    ['invoice.pdf.exe', 'executable'],
    ['INVOICE.PDF.EXE', 'executable'],
    ['run.js', 'executable'],
    ['script.vbs', 'executable'],
    ['payload.exe. . .', 'executable'],
    ['photo.jpg', 'other'],
    ['report.pdf', 'other'],
    ['archive.zip', 'archive'],
    ['disk.iso', 'archive'],
    ['budget.xlsm', 'macro-document'],
    ['letter.doc', 'macro-document'],
    ['', 'other'],
  ])('%j is %s', (name, kind) => {
    expect(classifyFileName(name)).toBe(kind);
  });

  it('treats names disguised with direction overrides as executables', () => {
    expect(classifyFileName(`invoice${String.fromCharCode(0x202e)}fdp.exe`)).toBe('executable');
    expect(classifyFileName(`photo${String.fromCharCode(0x202e)}gpj.scr`)).toBe('executable');
  });
});

describe('classifyTarget', () => {
  it.each([
    ['\\\\192.0.2.1\\share\\doc.pdf', 'network-share'],
    ['//192.0.2.1/share', 'network-share'],
    ['smb://server/share', 'network-share'],
    ['file://server/share/doc.pdf', 'network-share'],
    ['file:////server/share', 'network-share'],
    ['file:///C:/Users/me/doc.pdf', 'other'],
    ['  JavaScript:alert(1)', 'script'],
    ['vbscript:x', 'script'],
    ['data:text/html,<b>x</b>', 'script'],
    ['https://example.com/', 'other'],
    ['mailto:someone@example.com', 'other'],
    ['other.pdf', 'other'],
  ])('%j is %s', (target, kind) => {
    expect(classifyTarget(target)).toBe(kind);
  });
});

describe('attachment and target detection', () => {
  it('flags an executable attachment as high risk and marks /EmbeddedFile in red', async () => {
    const assessment = assessIndicators(
      await analyzePdf(getFixture('executable-attachment').build()),
    );
    expect(assessment.level).toBe('high-risk');
    expect(severities(assessment)).toMatchObject({ 'executable-attachment': 'critical' });
    const embedded = assessment.interpretations.find((item) => item.name === '/EmbeddedFile');
    expect(embedded?.status).toBe('danger');
  });

  it('counts attachments by kind without keeping their names', async () => {
    const pdf = createTestPdf({
      objects: [
        ...BASIC_OBJECTS,
        { body: '<< /Type /Filespec /F (data.zip) /EF << /F 6 0 R >> >>' },
        { body: '<< /Type /Filespec /UF (sheet.xlsm) /EF << /F 6 0 R >> >>' },
        { body: '<< /Type /EmbeddedFile >>', stream: 'x' },
        { body: '<< /Type /Filespec /F (notes.txt) /EF << /F 6 0 R >> >>' },
      ],
    });
    const deep = await deepScanPdf(pdf);
    expect(deep.attachments).toEqual({ total: 3, executable: 0, archive: 1, macroDocument: 1 });
    expect(JSON.stringify(deep)).not.toMatch(/data\.zip|sheet\.xlsm|notes\.txt/);
    const assessment = assessIndicators(await analyzePdf(pdf));
    expect(severities(assessment)).toMatchObject({ 'risky-attachment': 'review' });
  });

  it('flags an automatic network-share reference as high risk', async () => {
    const scan = await analyzePdf(getFixture('network-share-open-action').build());
    expect(scan.deep?.targets).toEqual({ networkShare: 1, automaticNetworkShare: 1, scriptUri: 0 });
    expect(scan.deep?.actions[0]).toMatchObject({ action: 'GoToR', risk: 'high', automatic: true });
    expect(JSON.stringify(scan)).not.toContain('192.0.2.1');
    const assessment = assessIndicators(scan);
    expect(assessment.level).toBe('high-risk');
    expect(severities(assessment)).toMatchObject({ 'auto-network-share': 'critical' });
  });

  it('flags a clicked network-share link at priority level', async () => {
    const pdf = createTestPdf({
      objects: [
        ...BASIC_OBJECTS,
        {
          body: '<< /Type /Annot /Subtype /Link /A << /S /Launch /F (smb://192.0.2.1/share/a.pdf) >> >>',
        },
      ],
    });
    const assessment = assessIndicators(await analyzePdf(pdf));
    expect(severities(assessment)).toMatchObject({ 'network-share': 'priority' });
  });

  it('flags script addresses in links', async () => {
    const scan = await analyzePdf(getFixture('javascript-uri-link').build());
    expect(scan.deep?.targets.scriptUri).toBe(1);
    expect(severities(assessIndicators(scan))).toMatchObject({ 'script-url': 'priority' });
  });
});
