import { byteToHex } from './byteUtils';

/**
 * SHA-256 of `bytes` as lowercase hexadecimal, computed locally with the Web Crypto API.
 * Returns null when Web Crypto is unavailable (for example on a page served over plain HTTP,
 * which is not a secure context).
 */
export async function computeSha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string | null> {
  // The DOM typings declare `crypto.subtle` as always present, but browsers omit it outside
  // secure contexts, so widen the type before checking.
  const runtimeCrypto: { readonly subtle?: SubtleCrypto } | undefined =
    typeof globalThis.crypto === 'object' ? globalThis.crypto : undefined;
  const subtle = runtimeCrypto?.subtle;
  if (subtle === undefined) {
    return null;
  }
  const digest = new Uint8Array(await subtle.digest('SHA-256', bytes));
  let hex = '';
  for (const byte of digest) {
    hex += byteToHex(byte);
  }
  return hex;
}
