import { describe, expect, it, vi } from 'vitest';
import { assessIndicators } from '../../src/features/pdf-analysis/assessment/assessIndicators';
import { analyzePdf } from '../../src/features/pdf-analysis/engine/analyzePdf';
import { scanPdf } from '../../src/features/pdf-analysis/engine/scanPdf';
import {
  buildJsonReport,
  createReportFileName,
  DEFAULT_REPORT_OPTIONS,
  downloadJsonReport,
  ReportError,
  serializeReport,
  validateReportOptions,
  type DownloadEnvironment,
} from '../../src/features/pdf-analysis/reports/exportJsonReport';
import type { ScanResult } from '../../src/features/pdf-analysis/types/analysis';
import { BASIC_OBJECTS, createTestPdf } from '../fixtures/createTestPdf';
import { getFixture } from '../fixtures/fixtureDefinitions';

const SECRET = 'TOP-SECRET-PATIENT-NOTE-9876';
const generatedAt = new Date('2026-03-04T05:06:07.000Z');
const SHA = 'a'.repeat(64);

function analysisWithSecret() {
  const pdf = createTestPdf({
    objects: [
      { body: `<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>` },
      ...BASIC_OBJECTS.slice(1),
      { body: `<< /S /JavaScript /JS (${SECRET}) /CreationDate (D:20240101120000) >>` },
      { body: '<< /Length 28 >>', stream: SECRET },
    ],
  });
  const scan = scanPdf(pdf, { sha256: SHA });
  return { scan, assessment: assessIndicators(scan), fileName: 'Quarterly <b>report</b>.pdf' };
}

describe('validateReportOptions', () => {
  it('fills defaults and keeps valid values', () => {
    expect(validateReportOptions({})).toEqual(DEFAULT_REPORT_OPTIONS);
    expect(validateReportOptions({ includeDates: true })).toEqual({
      ...DEFAULT_REPORT_OPTIONS,
      includeDates: true,
    });
  });

  it.each([null, undefined, 'yes', 3, [], [true]])('rejects %j', (value) => {
    expect(() => validateReportOptions(value)).toThrow(ReportError);
  });

  it('rejects unknown keys and non-boolean values', () => {
    expect(() => validateReportOptions({ includeContents: true })).toThrow(/Unknown report option/);
    expect(() => validateReportOptions({ includeDates: 'true' })).toThrow(/true or false/);
    expect(() =>
      validateReportOptions({ __proto__: { includeDates: true }, includeNames: 1 }),
    ).toThrow(ReportError);
  });
});

describe('buildJsonReport', () => {
  it('contains the documented fields and valid JSON', () => {
    const input = analysisWithSecret();
    const json = serializeReport(buildJsonReport(input, DEFAULT_REPORT_OPTIONS, generatedAt));
    const parsed = JSON.parse(json) as Record<string, unknown>;
    expect(Object.keys(parsed)).toEqual([
      'reportSchemaVersion',
      'application',
      'generatedAt',
      'scanner',
      'file',
      'scan',
      'header',
      'keywords',
      'eof',
      'entropy',
      'obfuscation',
      'structure',
      'deepAnalysis',
      'assessment',
      'warnings',
      'incompleteAnalysis',
      'compatibilityNotes',
      'limitations',
      'privacy',
    ]);
    expect(parsed).toMatchObject({
      reportSchemaVersion: 2,
      application: { name: 'PDF Signal', version: '1.2.0' },
      generatedAt: '2026-03-04T05:06:07.000Z',
      scanner: { version: '1.2.0', pdfidReferenceVersion: '0.2.10', resultSchemaVersion: 2 },
      file: { name: 'Quarterly <b>report</b>.pdf', sizeBytes: input.scan.sizeBytes, sha256: SHA },
      assessment: { level: 'multiple', rulesVersion: '2.1.0' },
      incompleteAnalysis: false,
    });
    expect(parsed.keywords).toHaveLength(21);
    expect(parsed.limitations).toMatch(/not an antivirus verdict/);
  });

  it('never contains PDF text or stream contents', () => {
    const report = buildJsonReport(
      analysisWithSecret(),
      { includeFileName: true, includeDates: true, includeNames: true },
      generatedAt,
    );
    expect(serializeReport(report)).not.toContain(SECRET);
  });

  it('includes the deep analysis without document content', async () => {
    const scan = await analyzePdf(getFixture('openaction-javascript-stream').build(), {
      sha256: SHA,
    });
    const report = buildJsonReport(
      { scan, assessment: assessIndicators(scan), fileName: 'x.pdf' },
      { includeFileName: true, includeDates: true, includeNames: true },
      generatedAt,
    );
    const json = serializeReport(report);
    expect(report.deepAnalysis?.actions[0]).toMatchObject({
      trigger: '/OpenAction',
      action: 'JavaScript',
    });
    expect(report.assessment.level).toBe('high-risk');
    expect(json).not.toContain('inert text');
    expect(json).not.toContain('%u0c0c');
  });

  it('omits the file name, dates and names unless requested', () => {
    const input = analysisWithSecret();
    const minimal = buildJsonReport(
      input,
      { includeFileName: false, includeDates: false, includeNames: false },
      generatedAt,
    );
    expect(minimal.file).not.toHaveProperty('name');
    expect(minimal).not.toHaveProperty('dates');
    expect(minimal).not.toHaveProperty('names');
    const full = buildJsonReport(
      input,
      { includeFileName: true, includeDates: true, includeNames: true },
      generatedAt,
    );
    expect(full.dates?.entries).toEqual([{ value: 'D:20240101120000', name: '/CreationDate' }]);
    expect(full.names?.entries.map((entry) => entry.name)).toContain('/Catalog');
  });

  it('marks incomplete analyses', () => {
    const scan = scanPdf(getFixture('no-header').build(), { sha256: SHA });
    const report = buildJsonReport(
      { scan, assessment: assessIndicators(scan), fileName: 'x' },
      DEFAULT_REPORT_OPTIONS,
      generatedAt,
    );
    expect(report.incompleteAnalysis).toBe(true);
    expect(report.warnings.map((warning) => warning.code)).toContain('not-scanned');
  });

  it('rejects invalid scan data, assessments, options and timestamps', () => {
    const input = analysisWithSecret();
    const broken = { ...input.scan, sizeBytes: -1 } as ScanResult;
    expect(() =>
      buildJsonReport({ ...input, scan: broken }, DEFAULT_REPORT_OPTIONS, generatedAt),
    ).toThrow(/scan result is invalid/);
    const badHash = { ...input.scan, sha256: '<script>' } as ScanResult;
    expect(() =>
      buildJsonReport({ ...input, scan: badHash }, DEFAULT_REPORT_OPTIONS, generatedAt),
    ).toThrow(ReportError);
    const badAssessment = {
      ...input.assessment,
      level: 'safe',
    } as unknown as typeof input.assessment;
    expect(() =>
      buildJsonReport({ ...input, assessment: badAssessment }, DEFAULT_REPORT_OPTIONS, generatedAt),
    ).toThrow(/assessment/);
    expect(() =>
      buildJsonReport(
        input,
        { ...DEFAULT_REPORT_OPTIONS, extra: true } as typeof DEFAULT_REPORT_OPTIONS,
        generatedAt,
      ),
    ).toThrow(ReportError);
    expect(() => buildJsonReport(input, DEFAULT_REPORT_OPTIONS, new Date(Number.NaN))).toThrow(
      /timestamp/,
    );
  });

  it('refuses to serialize values JSON cannot represent', () => {
    const report = buildJsonReport(analysisWithSecret(), DEFAULT_REPORT_OPTIONS, generatedAt);
    expect(() =>
      serializeReport({ ...report, scan: { ...report.scan, durationMs: Number.NaN } }),
    ).toThrow(/invalid number/);
    expect(() =>
      serializeReport({ ...report, scan: { ...report.scan, durationMs: Infinity } }),
    ).toThrow(ReportError);
  });
});

describe('createReportFileName', () => {
  it.each([
    ['report.pdf', 'pdf-signal-report-report-20260304-050607.json'],
    [
      'Quarterly Report (final).PDF',
      'pdf-signal-report-Quarterly-Report-final-20260304-050607.json',
    ],
    ['../../etc/passwd', 'pdf-signal-report-etc-passwd-20260304-050607.json'],
    [
      'C:\\Windows\\System32\\evil.pdf',
      'pdf-signal-report-C-Windows-System32-evil-20260304-050607.json',
    ],
    [
      '<script>alert(1)</script>.pdf',
      'pdf-signal-report-script-alert-1-script-20260304-050607.json',
    ],
    ['Résumé déjà vu.pdf', 'pdf-signal-report-Resume-deja-vu-20260304-050607.json'],
    ['invoice\u202Efdp.exe', 'pdf-signal-report-invoice-fdp.exe-20260304-050607.json'],
    ['....hidden....pdf', 'pdf-signal-report-hidden-20260304-050607.json'],
    ['日本語.pdf', 'pdf-signal-report-document-20260304-050607.json'],
    ['', 'pdf-signal-report-document-20260304-050607.json'],
  ])('%j → %s', (name, expected) => {
    expect(createReportFileName(name, generatedAt, true)).toBe(expected);
  });

  it('bounds the length and only uses safe characters', () => {
    const name = createReportFileName(`${'a-'.repeat(500)}x.pdf`, generatedAt, true);
    expect(name.length).toBeLessThanOrEqual('pdf-signal-report--20260304-050607.json'.length + 60);
    expect(name).toMatch(/^[A-Za-z0-9._-]+$/);
  });

  it('leaves the original name out when requested', () => {
    expect(createReportFileName('secret-client.pdf', generatedAt, false)).toBe(
      'pdf-signal-report-20260304-050607.json',
    );
  });

  it('falls back for an invalid date', () => {
    expect(createReportFileName('a.pdf', new Date(Number.NaN), true)).toBe(
      'pdf-signal-report-a-19700101-000000.json',
    );
  });
});

describe('downloadJsonReport', () => {
  function environment(overrides: Partial<DownloadEnvironment> = {}) {
    const anchor = {
      href: '',
      download: '',
      rel: '',
      hidden: false,
      click: vi.fn(),
      remove: vi.fn(),
    };
    const scheduled: (() => void)[] = [];
    const env = {
      createObjectURL: vi.fn((blob: Blob) =>
        blob.type === 'application/json' ? 'blob:report' : 'blob:wrong',
      ),
      revokeObjectURL: vi.fn(),
      document: {
        createElement: vi.fn(() => anchor),
        body: { append: vi.fn() },
      } as unknown as Document,
      schedule: vi.fn((callback: () => void) => {
        scheduled.push(callback);
      }),
      ...overrides,
    };
    return { env, anchor, scheduled };
  }

  it('downloads through a temporary object URL and revokes it', () => {
    const { env, anchor, scheduled } = environment();
    expect(downloadJsonReport('{}', 'pdf-signal-report.json', env)).toEqual({ ok: true });
    expect(anchor).toMatchObject({
      href: 'blob:report',
      download: 'pdf-signal-report.json',
      rel: 'noopener',
      hidden: true,
    });
    expect(anchor.click).toHaveBeenCalledOnce();
    expect(anchor.remove).toHaveBeenCalledOnce();
    expect(env.revokeObjectURL).not.toHaveBeenCalled();
    scheduled.forEach((callback) => {
      callback();
    });
    expect(env.revokeObjectURL).toHaveBeenCalledWith('blob:report');
  });

  it('reports failures and still revokes the URL', () => {
    const { env, anchor } = environment();
    anchor.click.mockImplementation(() => {
      throw new Error('blocked');
    });
    const outcome = downloadJsonReport('{}', 'r.json', env);
    expect(outcome.ok).toBe(false);
    expect(env.revokeObjectURL).toHaveBeenCalledWith('blob:report');

    const failing = environment({
      createObjectURL: () => {
        throw new Error('unsupported');
      },
    });
    expect(downloadJsonReport('{}', 'r.json', failing.env)).toMatchObject({ ok: false });
    expect(failing.env.revokeObjectURL).not.toHaveBeenCalled();
  });
});
