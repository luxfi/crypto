/**
 * ML-DSA-65 (FIPS 204) — digital signatures via libluxcrypto.
 */

import { getFFI } from './ffi.js';

let _pkSize: number | null = null;
let _skSize: number | null = null;
let _sigSize: number | null = null;

function sizes(): { pk: number; sk: number; sig: number } {
  if (_pkSize === null) {
    const ffi = getFFI();
    _pkSize = ffi.mldsa65_pk_size();
    _skSize = ffi.mldsa65_sk_size();
    _sigSize = ffi.mldsa65_sig_size();
  }
  return { pk: _pkSize!, sk: _skSize!, sig: _sigSize! };
}

/**
 * Generate an ML-DSA-65 key pair.
 * @returns [publicKey, secretKey]
 */
export function keypair(): [Uint8Array, Uint8Array] {
  const { pk: pkSize, sk: skSize } = sizes();
  const ffi = getFFI();

  const pkBuf = Buffer.alloc(pkSize);
  const skBuf = Buffer.alloc(skSize);
  const pkLen = Buffer.alloc(4);
  const skLen = Buffer.alloc(4);

  const rc = ffi.mldsa65_keypair(pkBuf, pkLen, skBuf, skLen);
  if (rc !== 0) throw new Error(`mldsa65_keypair failed: ${rc}`);

  const actualPkLen = pkLen.readInt32LE(0);
  const actualSkLen = skLen.readInt32LE(0);

  return [
    new Uint8Array(pkBuf.buffer, pkBuf.byteOffset, actualPkLen),
    new Uint8Array(skBuf.buffer, skBuf.byteOffset, actualSkLen),
  ];
}

/**
 * Sign a message with ML-DSA-65.
 * @returns signature
 */
export function sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  const { sig: sigSize } = sizes();
  const ffi = getFFI();

  const skBuf = Buffer.from(secretKey);
  const msgBuf = Buffer.from(message);
  const sigBuf = Buffer.alloc(sigSize);
  const sigLen = Buffer.alloc(4);

  const rc = ffi.mldsa65_sign(skBuf, skBuf.length, msgBuf, msgBuf.length, sigBuf, sigLen);
  if (rc !== 0) throw new Error(`mldsa65_sign failed: ${rc}`);

  const actualSigLen = sigLen.readInt32LE(0);
  return new Uint8Array(sigBuf.buffer, sigBuf.byteOffset, actualSigLen);
}

/**
 * Verify an ML-DSA-65 signature.
 * @returns true if valid, false otherwise
 */
export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const ffi = getFFI();

  const pkBuf = Buffer.from(publicKey);
  const msgBuf = Buffer.from(message);
  const sigBuf = Buffer.from(signature);

  const rc = ffi.mldsa65_verify(pkBuf, pkBuf.length, msgBuf, msgBuf.length, sigBuf, sigBuf.length);
  return rc === 0;
}
