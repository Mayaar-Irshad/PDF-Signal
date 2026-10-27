import type { EntropyStatistics } from '../types/analysis';

const ENDSTREAM_BYTES = Array.from('endstream', (character) => character.charCodeAt(0));

/** Shannon entropy in bits per byte, summed bucket by bucket in the same order as PDFiD. */
function shannonEntropy(buckets: Float64Array, total: number): number {
  let entropy = 0;
  for (const count of buckets) {
    const probability = count / total;
    if (probability > 0) {
      // pdfid.py: -x * math.log(x, 2), where math.log(x, 2) is computed as log(x) / log(2).
      entropy += -probability * (Math.log(probability) / Math.LN2);
    }
  }
  return entropy;
}

function sum(buckets: Float64Array): number {
  let total = 0;
  for (const count of buckets) {
    total += count;
  }
  return total;
}

/**
 * Port of pdfid.py `cEntropy`: byte histograms for the whole file and for bytes PDFiD
 * classifies as stream data (between a `stream` keyword and the next `endstream`).
 */
export class EntropyAccumulator {
  private readonly all = new Float64Array(256);
  private readonly stream = new Float64Array(256);

  add(byte: number, insideStream: boolean): void {
    this.all[byte] = (this.all[byte] ?? 0) + 1;
    if (insideStream) {
      this.stream[byte] = (this.stream[byte] ?? 0) + 1;
    }
  }

  /** The `endstream` keyword itself was counted as stream data; PDFiD takes it back out. */
  removeEndstreamKeyword(): void {
    for (const byte of ENDSTREAM_BYTES) {
      const count = this.stream[byte] ?? 0;
      if (count > 0) {
        this.stream[byte] = count - 1;
      }
    }
  }

  /**
   * Computes the statistics. PDFiD raises ZeroDivisionError when there are no bytes at all;
   * PDF Signal reports null entropy instead.
   */
  calculate(): EntropyStatistics {
    const nonStream = new Float64Array(256);
    for (let byte = 0; byte < 256; byte++) {
      nonStream[byte] = (this.all[byte] ?? 0) - (this.stream[byte] ?? 0);
    }
    const totalBytes = sum(this.all);
    const streamBytes = sum(this.stream);
    const nonStreamBytes = sum(nonStream);
    return {
      totalBytes,
      totalEntropy: totalBytes > 0 ? shannonEntropy(this.all, totalBytes) : null,
      streamBytes,
      streamEntropy: streamBytes > 0 ? shannonEntropy(this.stream, streamBytes) : null,
      nonStreamBytes,
      nonStreamEntropy: nonStreamBytes > 0 ? shannonEntropy(nonStream, nonStreamBytes) : null,
    };
  }
}
