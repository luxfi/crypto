/**
 * ML-KEM-768 (FIPS 203) — key encapsulation via libluxcrypto.
 */

import { getFFI } from './ffi.js';

let _pkSize: number | null = null;
let _skSize: number | null = null;
let _ctSize: number | null = null;
const SS_SIZE = 32;

function sizes(): { pk: number; sk: number; ct: number } {
  if (_pkSize === null) {
    const ffi = getFFI();
    _pkSize = ffi.lux_mlkem768_pk_size();
    _skSize = ffi.lux_mlkem768_sk_size();
    _ctSize = ffi.lux_mlkem768_ct_size();
  }
  return { pk: _pkSize!, sk: _skSize!, ct: _ctSize! };
}

/**
 * Generate an ML-KEM-768 key pair.
 * @returns [publicKey, secretKey]
 */
export function keypair(): [Uint8Array, Uint8Array] {
  const { pk: pkSize, sk: skSize } = sizes();
  const ffi = getFFI();

  const pkBuf = Buffer.alloc(pkSize);
  const skBuf = Buffer.alloc(skSize);
  const pkLen = Buffer.alloc(4); // int*
  const skLen = Buffer.alloc(4);

  const rc = ffi.lux_mlkem768_keypair(pkBuf, pkLen, skBuf, skLen);
  if (rc !== 0) throw new Error(`lux_mlkem768_keypair failed: ${rc}`);

  const actualPkLen = pkLen.readInt32LE(0);
  const actualSkLen = skLen.readInt32LE(0);

  return [
    new Uint8Array(pkBuf.buffer, pkBuf.byteOffset, actualPkLen),
    new Uint8Array(skBuf.buffer, skBuf.byteOffset, actualSkLen),
  ];
}

/**
 * Encapsulate a shared secret for the given public key.
 * @returns [ciphertext, sharedSecret]
 */
export function encapsulate(publicKey: Uint8Array): [Uint8Array, Uint8Array] {
  const { ct: ctSize } = sizes();
  const ffi = getFFI();

  const pkBuf = Buffer.from(publicKey);
  const ctBuf = Buffer.alloc(ctSize);
  const ssBuf = Buffer.alloc(SS_SIZE);
  const ctLen = Buffer.alloc(4);
  const ssLen = Buffer.alloc(4);

  const rc = ffi.lux_mlkem768_encapsulate(pkBuf, pkBuf.length, ctBuf, ctLen, ssBuf, ssLen);
  if (rc !== 0) throw new Error(`lux_mlkem768_encapsulate failed: ${rc}`);

  const actualCtLen = ctLen.readInt32LE(0);
  const actualSsLen = ssLen.readInt32LE(0);

  return [
    new Uint8Array(ctBuf.buffer, ctBuf.byteOffset, actualCtLen),
    new Uint8Array(ssBuf.buffer, ssBuf.byteOffset, actualSsLen),
  ];
}

/**
 * Decapsulate a shared secret from ciphertext.
 * @returns sharedSecret
 */
export function decapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const ffi = getFFI();

  const skBuf = Buffer.from(secretKey);
  const ctBuf = Buffer.from(ciphertext);
  const ssBuf = Buffer.alloc(SS_SIZE);
  const ssLen = Buffer.alloc(4);

  const rc = ffi.lux_mlkem768_decapsulate(skBuf, skBuf.length, ctBuf, ctBuf.length, ssBuf, ssLen);
  if (rc !== 0) throw new Error(`lux_mlkem768_decapsulate failed: ${rc}`);

  const actualSsLen = ssLen.readInt32LE(0);
  return new Uint8Array(ssBuf.buffer, ssBuf.byteOffset, actualSsLen);
}
