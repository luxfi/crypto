/**
 * FFI layer — loads libluxcrypto shared library.
 *
 * Search order:
 *   1. LUX_CRYPTO_LIB env var (explicit path)
 *   2. Adjacent to this package (wheel/npm ships the lib)
 *   3. ~/work/lux/crypto/dist/ (development build)
 *   4. System library path
 */

import koffi from 'koffi';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir, platform } from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

function libName(): string {
  switch (platform()) {
    case 'darwin': return 'libluxcrypto.dylib';
    case 'win32': return 'libluxcrypto.dll';
    default: return 'libluxcrypto.so';
  }
}

function findLib(): string | null {
  const env = process.env.LUX_CRYPTO_LIB;
  if (env && existsSync(env)) return env;

  const name = libName();

  for (const dir of [__dirname, join(__dirname, '..'), join(__dirname, '..', '..')]) {
    const p = join(dir, name);
    if (existsSync(p)) return p;
  }

  const dist = join(homedir(), 'work', 'lux', 'crypto', 'dist', name);
  if (existsSync(dist)) return dist;

  return null;
}

const libPath = findLib();
export const LUX_CRYPTO_AVAILABLE = libPath !== null;

interface LuxCryptoFFI {
  lux_mlkem768_keypair(pk: Buffer, pkLen: Buffer, sk: Buffer, skLen: Buffer): number;
  lux_mlkem768_encapsulate(pk: Buffer, pkLen: number, ct: Buffer, ctLen: Buffer, ss: Buffer, ssLen: Buffer): number;
  lux_mlkem768_decapsulate(sk: Buffer, skLen: number, ct: Buffer, ctLen: number, ss: Buffer, ssLen: Buffer): number;
  lux_mlkem768_pk_size(): number;
  lux_mlkem768_sk_size(): number;
  lux_mlkem768_ct_size(): number;
  lux_mldsa65_keypair(pk: Buffer, pkLen: Buffer, sk: Buffer, skLen: Buffer): number;
  lux_mldsa65_sign(sk: Buffer, skLen: number, msg: Buffer, msgLen: number, sig: Buffer, sigLen: Buffer): number;
  lux_mldsa65_verify(pk: Buffer, pkLen: number, msg: Buffer, msgLen: number, sig: Buffer, sigLen: number): number;
  lux_mldsa65_pk_size(): number;
  lux_mldsa65_sk_size(): number;
  lux_mldsa65_sig_size(): number;
}

let _ffi: LuxCryptoFFI | null = null;

export function getFFI(): LuxCryptoFFI {
  if (_ffi) return _ffi;
  if (!libPath) {
    throw new Error(
      'libluxcrypto not found. Build it with: cd ~/work/lux/crypto && make lib'
    );
  }
  const lib = koffi.load(libPath);

  _ffi = {
    lux_mlkem768_keypair: lib.func('int lux_mlkem768_keypair(void *pk, int *pkLen, void *sk, int *skLen)'),
    lux_mlkem768_encapsulate: lib.func('int lux_mlkem768_encapsulate(const void *pk, int pkLen, void *ct, int *ctLen, void *ss, int *ssLen)'),
    lux_mlkem768_decapsulate: lib.func('int lux_mlkem768_decapsulate(const void *sk, int skLen, const void *ct, int ctLen, void *ss, int *ssLen)'),
    lux_mlkem768_pk_size: lib.func('int lux_mlkem768_pk_size()'),
    lux_mlkem768_sk_size: lib.func('int lux_mlkem768_sk_size()'),
    lux_mlkem768_ct_size: lib.func('int lux_mlkem768_ct_size()'),
    lux_mldsa65_keypair: lib.func('int lux_mldsa65_keypair(void *pk, int *pkLen, void *sk, int *skLen)'),
    lux_mldsa65_sign: lib.func('int lux_mldsa65_sign(const void *sk, int skLen, const void *msg, int msgLen, void *sig, int *sigLen)'),
    lux_mldsa65_verify: lib.func('int lux_mldsa65_verify(const void *pk, int pkLen, const void *msg, int msgLen, const void *sig, int sigLen)'),
    lux_mldsa65_pk_size: lib.func('int lux_mldsa65_pk_size()'),
    lux_mldsa65_sk_size: lib.func('int lux_mldsa65_sk_size()'),
    lux_mldsa65_sig_size: lib.func('int lux_mldsa65_sig_size()'),
  };
  return _ffi;
}
