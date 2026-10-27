import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanPdf } from '../../src/features/pdf-analysis/engine/scanPdf';
import type { ScanMode } from '../../src/features/pdf-analysis/types/analysis';
import { FIXTURES } from '../fixtures/fixtureDefinitions';
import { compareWithReference, PDFID_REFERENCE_SOURCE, type ReferenceFile } from './pdfidReference';

/**
 * PDFiD compatibility tests.
 *
 * 1. "recorded" tests always run: they compare the engine with tests/fixtures/pdfid-reference.json,
 *    which holds real pdfid.py 0.2.10 output for every synthetic fixture.
 * 2. "live" tests run only when PDFID_PY points at a downloaded pdfid.py. They execute it on the
 *    fixtures, compare, and (with UPDATE_PDFID_REFERENCE=1) rewrite the recorded file.
 *
 *    PDFID_PY=/path/to/pdfid.py npm run test:parity
 */

const ROOT = resolve(import.meta.dirname, '../..');
const RECORDED_PATH = join(ROOT, 'tests/fixtures/pdfid-reference.json');
const OUTPUT_DIR = join(ROOT, 'tests/parity/.output');
const MODES: readonly ScanMode[] = ['standard', 'forced'];
const pdfidPath = process.env.PDFID_PY;

function engineResult(id: string, mode: ScanMode) {
  const fixture = FIXTURES.find((candidate) => candidate.id === id)!;
  return scanPdf(fixture.build(), { force: mode === 'forced', sha256: 'not-computed' });
}

function runPdfid(scriptPath: string): ReferenceFile {
  rmSync(OUTPUT_DIR, { recursive: true, force: true });
  mkdirSync(OUTPUT_DIR, { recursive: true });
  const files = FIXTURES.map((fixture) => {
    const path = join(OUTPUT_DIR, `${fixture.id}.pdf`);
    writeFileSync(path, fixture.build());
    return path;
  });
  const python = process.env.PYTHON ?? 'python3';
  const run = spawnSync(
    python,
    ['-I', join(ROOT, 'scripts/pdfid_reference.py'), scriptPath, ...files],
    {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  if (run.status !== 0) {
    throw new Error(`pdfid_reference.py failed (${run.status}): ${run.stderr}`);
  }
  return JSON.parse(run.stdout) as ReferenceFile;
}

describe.skipIf(pdfidPath === undefined)('live comparison with pdfid.py', () => {
  it('uses the pinned upstream pdfid.py', () => {
    const digest = createHash('sha256').update(readFileSync(pdfidPath!)).digest('hex');
    expect(digest, 'PDFID_PY must be pdfid.py 0.2.10 from the pinned upstream commit').toBe(
      PDFID_REFERENCE_SOURCE.sha256,
    );
  });

  it('matches pdfid.py on every fixture in both modes', () => {
    const reference = runPdfid(pdfidPath!);
    expect(reference.pdfidVersion).toBe(PDFID_REFERENCE_SOURCE.version);

    const differences: string[] = [];
    for (const fixture of FIXTURES) {
      const entry = reference.results[`${fixture.id}.pdf`];
      expect(entry, fixture.id).toBeDefined();
      for (const mode of MODES) {
        const found = compareWithReference(
          fixture,
          mode,
          entry![mode],
          engineResult(fixture.id, mode),
        );
        differences.push(...found.map((difference) => `${fixture.id} [${mode}] ${difference}`));
      }
    }
    expect(differences).toEqual([]);

    if (process.env.UPDATE_PDFID_REFERENCE === '1') {
      const recorded: ReferenceFile = { ...reference, source: PDFID_REFERENCE_SOURCE };
      writeFileSync(RECORDED_PATH, `${JSON.stringify(recorded, null, 1)}\n`);
    }
  });
});

describe('recorded pdfid.py 0.2.10 results', () => {
  const load = (): ReferenceFile => {
    if (!existsSync(RECORDED_PATH)) {
      throw new Error(
        'tests/fixtures/pdfid-reference.json is missing; see README "Compatibility testing".',
      );
    }
    return JSON.parse(readFileSync(RECORDED_PATH, 'utf8')) as ReferenceFile;
  };

  it('were produced by the pinned upstream version for every fixture', () => {
    const recorded = load();
    expect(recorded.pdfidVersion).toBe(PDFID_REFERENCE_SOURCE.version);
    expect(recorded.source).toEqual(PDFID_REFERENCE_SOURCE);
    expect(Object.keys(recorded.results).sort()).toEqual(
      FIXTURES.map((fixture) => `${fixture.id}.pdf`).sort(),
    );
  });

  for (const fixture of FIXTURES) {
    for (const mode of MODES) {
      it(`${fixture.id} (${mode})`, () => {
        const entry = load().results[`${fixture.id}.pdf`];
        expect(entry).toBeDefined();
        expect(
          compareWithReference(fixture, mode, entry![mode], engineResult(fixture.id, mode)),
        ).toEqual([]);
      });
    }
  }
});
