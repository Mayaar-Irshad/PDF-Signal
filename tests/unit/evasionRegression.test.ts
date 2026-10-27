import { describe, expect, it } from 'vitest';
import { assessIndicators } from '../../src/features/pdf-analysis/assessment/assessIndicators';
import { analyzePdf } from '../../src/features/pdf-analysis/engine/analyzePdf';
import { deepScanPdf, type DeepScanLimits } from '../../src/features/pdf-analysis/engine/deepScan';
import type { Assessment } from '../../src/features/pdf-analysis/types/analysis';
import {
  bytes,
  compress,
  createTestPdf,
  objectStream,
  type PdfObjectSpec,
} from '../fixtures/createTestPdf';

/**
 * Regression tests for evasions and resource problems found in an independent review of the
 * deep analysis. Each test builds the attack the way the review reproduced it.
 */

const SPRAY = "var s = unescape('%u0c0c%u0c0c'); eval(s);";
const PAGES: PdfObjectSpec = { body: '<< /Type /Pages /Kids [3 0 R] /Count 1 >>' };
const PAGE: PdfObjectSpec = { body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>' };

async function assess(pdf: Uint8Array, limits: Partial<DeepScanLimits> = {}, force = false) {
  const scan = await analyzePdf(pdf, { sha256: 'x', force, deepLimits: limits });
  return { scan, assessment: assessIndicators(scan) };
}

const ids = (assessment: Assessment) => assessment.findings.map((finding) => finding.id);
const latin1 = (data: Uint8Array) => String.fromCharCode(...data);

describe('evasion regressions', () => {
  it('ignores an /Encrypt token that is not in a trailer', async () => {
    const pdf = createTestPdf({
      objects: [
        { body: '<< /Type /Catalog /Pages 2 0 R >>' },
        PAGES,
        PAGE,
        objectStream([
          { number: 10, body: '<< /Type /Catalog /Pages 2 0 R /OpenAction 11 0 R >>' },
          { number: 11, body: `<< /S /JavaScript /JS (${SPRAY}) >>` },
        ]),
        { body: '<< /Title (/Encrypt) >>' },
      ],
      trailerEntries: ' /Info 5 0 R',
    });
    const { scan, assessment } = await assess(pdf);
    expect(scan.keywords.find((keyword) => keyword.name === '/Encrypt')?.count).toBe(1);
    expect(scan.deep?.encrypted).toBe(false);
    expect(assessment.level).toBe('high-risk');
  });

  it('detects real encryption from the trailer or a cross-reference stream', async () => {
    const trailer = createTestPdf({ objects: [PAGES], trailerEntries: ' /Encrypt 9 0 R' });
    expect((await deepScanPdf(trailer)).encrypted).toBe(true);
    const xrefStream = createTestPdf({
      objects: [PAGES, { body: '<< /Type /XRef /Encrypt 9 0 R >>', stream: 'x' }],
    });
    expect((await deepScanPdf(xrefStream)).encrypted).toBe(true);
  });

  it('analyses every definition, so a later decoy cannot hide the real object', async () => {
    const base = latin1(
      createTestPdf({
        objects: [
          { body: '<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>' },
          PAGES,
          PAGE,
          { body: `<< /S /JavaScript /JS (${SPRAY}) >>` },
        ],
      }),
    );
    const decoy = '4 0 obj\n<< /S /GoTo /D [3 0 R /Fit] >>\nendobj\n';
    const at = base.indexOf('xref\n');
    const { scan, assessment } = await assess(bytes(base.slice(0, at), decoy, base.slice(at)));
    expect(scan.deep?.actions.map((action) => action.action)).toEqual(['JavaScript', 'GoTo']);
    expect(assessment.level).toBe('high-risk');
    expect(ids(assessment)).toContain('exploit-script-patterns');
  });

  it('finds objects whose header follows a regular character', async () => {
    const pdf = bytes(
      '%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >> endobj\n',
      `X4 0 obj << /S /JavaScript /JS (${SPRAY}) >> endobj\n%%EOF\n`,
    );
    expect((await assess(pdf)).assessment.level).toBe('high-risk');
  });

  it('keeps indexing after an unterminated object and after an oversized one', async () => {
    const unterminated = bytes(
      '%PDF-1.7\n1 0 obj << /Title (never closed >> endobj\n',
      `2 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (${SPRAY}) >> >> endobj\n%%EOF\n`,
    );
    expect((await assess(unterminated)).assessment.level).toBe('high-risk');

    const oversized = bytes(
      '%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction [3 0 R /Fit] >> endobj\n',
      `5 0 obj [${'1 '.repeat(520_000)}] endobj\n`,
      `6 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (${SPRAY}) >> >> endobj\n%%EOF\n`,
    );
    const { scan, assessment } = await assess(oversized);
    expect(scan.deep?.notes.join(' ')).toMatch(/too large to parse completely/);
    expect(assessment.level).toBe('high-risk');
  });

  it('does not report a clean result when an object stream exceeded the size limit', async () => {
    const padding = ' '.repeat(100_000);
    const catalog = '<< /Type /Catalog /Pages 2 0 R /OpenAction 11 0 R >>\n';
    const header = `10 ${padding.length} 11 ${padding.length + catalog.length} `;
    const stream = compress(header, padding, catalog, `<< /S /JavaScript /JS (${SPRAY}) >>\n`);
    const pdf = createTestPdf({
      objects: [
        { body: '<< /Type /Metadata >>' },
        PAGES,
        PAGE,
        { body: `<< /Type /ObjStm /N 2 /First ${header.length} /Filter /FlateDecode >>`, stream },
      ],
    });
    const { scan, assessment } = await assess(pdf, { maxDecodedBytesPerStream: 64 * 1024 });
    expect(scan.deep).toMatchObject({
      decompressionBombs: 1,
      objectStreamsIncomplete: 1,
      status: 'partial',
    });
    expect(ids(assessment)).toEqual(
      expect.arrayContaining(['decompression-bomb', 'objstm-uninspected']),
    );
    expect(assessment.level).not.toBe('none-detected');
  });

  it('does not report a clean result when padding exhausts the stream budget', async () => {
    const padding = Array.from({ length: 3 }, (_, index) =>
      objectStream([{ number: 100 + index, body: 'null' }]),
    );
    const real = objectStream([
      { number: 10, body: '<< /Type /Catalog /OpenAction 11 0 R >>' },
      { number: 11, body: `<< /S /JavaScript /JS (${SPRAY}) >>` },
    ]);
    const pdf = createTestPdf({ objects: [PAGES, PAGE, ...padding, real] });
    const { assessment } = await assess(pdf, { maxDecodedStreams: 3 });
    expect(ids(assessment)).toContain('objstm-uninspected');
    expect(assessment.level).not.toBe('none-detected');
  });

  it('resolves "4 0R" references, indirect action types and untyped pages', async () => {
    const noSpace = createTestPdf({
      objects: [
        { body: '<< /Type /Catalog /OpenAction 2 0R >>' },
        { body: `<< /S /JavaScript /JS (${SPRAY}) >>` },
      ],
    });
    expect((await assess(noSpace)).assessment.level).toBe('high-risk');

    const indirectType = createTestPdf({
      objects: [
        { body: '<< /Type /Catalog /OpenAction 2 0 R >>' },
        { body: `<< /S 3 0 R /D [1 0 R /Fit] /JS (${SPRAY}) >>` },
        { body: '/JavaScript' },
      ],
    });
    const indirect = await assess(indirectType);
    expect(indirect.scan.deep?.actions[0]?.action).toBe('JavaScript');
    expect(indirect.assessment.level).toBe('high-risk');

    const untypedPage = createTestPdf({
      objects: [
        { body: '<< /Type /Catalog /Pages 2 0 R >>' },
        PAGES,
        {
          body: `<< /Parent 2 0 R /MediaBox [0 0 612 792] /AA << /O << /S /JavaScript /JS (x) >> >> >>`,
        },
      ],
    });
    const page = await assess(untypedPage);
    expect(page.scan.deep?.actions[0]).toMatchObject({ trigger: '/AA /O', automatic: true });
    expect(page.assessment.level).toBe('high-risk');
  });

  it('keeps the highest risk when actions are merged into one row', async () => {
    const pdf = createTestPdf({
      objects: [
        PAGES,
        { body: '<< /Type /Page /AA << /O << /S /Rendition /R 9 0 R >> >> >>' },
        { body: `<< /Type /Page /AA << /O << /S /Rendition /JS (${SPRAY}) >> >> >>` },
      ],
    });
    const { scan, assessment } = await assess(pdf);
    expect(scan.deep?.actions).toMatchObject([
      { trigger: '/AA /O', action: 'Rendition', risk: 'high', count: 2 },
    ]);
    expect(assessment.level).toBe('high-risk');
  });

  it('checks the Windows launch target and bare commands', async () => {
    const both = createTestPdf({
      objects: [
        { body: '<< /Type /Annot /A << /S /Launch /F (readme.pdf) /Win << /F (cmd.exe) >> >> >>' },
      ],
    });
    expect((await deepScanPdf(both)).launchTargets).toEqual({ executable: 1, other: 0 });
    const bare = createTestPdf({
      objects: [
        { body: '<< /Type /Annot /A << /S /Launch /Win << /F (cmd) /P (/c echo test) >> >> >>' },
      ],
    });
    expect((await deepScanPdf(bare)).launchTargets).toEqual({ executable: 1, other: 0 });
  });

  it('does not treat a forced scan with a critical finding as merely inconclusive', async () => {
    const pdf = bytes(`1 0 obj << /OpenAction << /S /JavaScript /JS (${SPRAY}) >> >> endobj`);
    const { assessment } = await assess(pdf, {}, true);
    expect(assessment.level).toBe('high-risk');
    expect(assessment.visibilityLimits.join(' ')).toMatch(/forced mode/);
  });

  it('never passes unknown names from the file into the result', async () => {
    const pdf = createTestPdf({
      objects: [
        { body: '<< /Type /Catalog /AA << /Evil#3Cscript#3E << /S /Bogus#20Action >> >> >>' },
        { body: '<< /Type /Annot /A << /S /Strange >> >>' },
      ],
    });
    const deep = await deepScanPdf(pdf);
    const serialized = JSON.stringify(deep);
    expect(serialized).not.toMatch(/Evil|<script|Bogus|Strange/);
    expect(deep.actions.map((action) => `${action.trigger} ${action.action}`).sort()).toEqual([
      '/A Other',
      '/AA (other event) Other',
    ]);
  });
});

describe('false-positive regressions', () => {
  it('does not flag ordinary util.printf formatting or button icons as exploits', async () => {
    const pdf = createTestPdf({
      objects: [
        { body: '<< /Type /Catalog /AcroForm << >> >>' },
        {
          body: `<< /Type /Annot /Subtype /Widget /AA << /F << /S /JavaScript /JS (event.value = util.printf("%.2f", v);) >> >> >>`,
        },
        {
          body: `<< /Type /Annot /Subtype /Widget /A << /S /JavaScript /JS (var icon = this.getIcon("on");) >> >>`,
        },
      ],
    });
    const { scan, assessment } = await assess(pdf);
    expect(scan.deep?.scriptPatterns).toEqual([]);
    expect(assessment.level).not.toBe('high-risk');
  });

  it('rates a form script stored in an object stream as review, not as evasion', async () => {
    const pdf = createTestPdf({
      objects: [
        PAGES,
        PAGE,
        objectStream([
          {
            number: 10,
            body: '<< /Type /Catalog /Pages 1 0 R /AcroForm << /Fields [11 0 R] >> >>',
          },
          {
            number: 11,
            body: '<< /FT /Tx /AA << /C << /S /JavaScript /JS (AFSimple_Calculate("SUM", ["a"]);) >> >> >>',
          },
        ]),
      ],
    });
    const { assessment } = await assess(pdf);
    expect(
      assessment.findings.find((finding) => finding.id === 'hidden-indicators')?.severity,
    ).toBe('review');
    expect(assessment.level).toBe('multiple');
  });

  it('rates document-level scripts as priority rather than high risk', async () => {
    const pdf = createTestPdf({
      objects: [
        { body: '<< /Type /Catalog /Names << /JavaScript << /Names [(helpers) 2 0 R] >> >> >>' },
        { body: '<< /S /JavaScript /JS (function sum(a, b) { return a + b; }) >>' },
      ],
    });
    const { assessment } = await assess(pdf);
    expect(
      assessment.findings.find((finding) => finding.id === 'document-level-javascript')?.severity,
    ).toBe('priority');
    expect(assessment.level).toBe('multiple');
  });
});

describe('resource regressions', () => {
  it('handles a shared /AA dictionary with many keys quickly', async () => {
    const keys = Array.from({ length: 2000 }, (_, index) => `/K${index} 5 0 R`).join(' ');
    const annotations = Array.from({ length: 400 }, () => ({
      body: '<< /Type /Annot /AA 4 0 R >>',
    }));
    const pdf = createTestPdf({
      objects: [
        PAGES,
        PAGE,
        ...annotations.slice(0, 1),
        { body: `<< ${keys} >>` },
        { body: '<< /S /Named /N /Next >>' },
        ...annotations.slice(1),
      ],
    });
    const started = Date.now();
    const deep = await deepScanPdf(pdf);
    expect(Date.now() - started).toBeLessThan(3000);
    expect(deep.actions).toHaveLength(1);
  });

  it('memoises chained /Next actions', async () => {
    const count = 400;
    const objects: PdfObjectSpec[] = [{ body: '<< /Type /Catalog /OpenAction 2 0 R >>' }];
    for (let index = 0; index < count; index++) {
      const next = Array.from(
        { length: 40 },
        (_, offset) => `${2 + ((index + offset + 1) % count)} 0 R`,
      ).join(' ');
      objects.push({ body: `<< /S /GoTo /D [1 0 R /Fit] /Next [${next}] >>` });
    }
    const started = Date.now();
    await deepScanPdf(createTestPdf({ objects }));
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it('stops object-stream parsing at the shared budget', async () => {
    const entries = Array.from({ length: 80 }, (_, index) => `${index + 1} 0`).join(' ') + ' ';
    const stream = compress(entries, `[${'1 '.repeat(100_000)}]`);
    const pdf = createTestPdf({
      objects: [
        { body: `<< /Type /ObjStm /N 80 /First ${entries.length} /Filter /FlateDecode >>`, stream },
      ],
    });
    const started = Date.now();
    await deepScanPdf(pdf);
    expect(Date.now() - started).toBeLessThan(3000);
  });
});
