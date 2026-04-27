/**
 * FFI layer — loads libluxcrypto shared library.
 *
 * Search order:
 *   1. CRYPTO_LIB env var (explicit path; deprecated alias: LUX_CRYPTO_LIB)
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

function envLib(): string | undefined {
  if (process.env.CRYPTO_LIB) return process.env.CRYPTO_LIB;
  if (process.env.LUX_CRYPTO_LIB) {
    console.warn('LUX_CRYPTO_LIB is deprecated; use CRYPTO_LIB');
    return process.env.LUX_CRYPTO_LIB;
  }
  return undefined;
}

function findLib(): string | null {
  const env = envLib();
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
export const cryptoAvailable = libPath !== null;

interface CryptoFFI {
  mlkem768_keypair(pk: Buffer, pkLen: Buffer, sk: Buffer, skLen: Buffer): number;
  mlkem768_encapsulate(pk: Buffer, pkLen: number, ct: Buffer, ctLen: Buffer, ss: Buffer, ssLen: Buffer): number;
  mlkem768_decapsulate(sk: Buffer, skLen: number, ct: Buffer, ctLen: number, ss: Buffer, ssLen: Buffer): number;
  mlkem768_pk_size(): number;
  mlkem768_sk_size(): number;
  mlkem768_ct_size(): number;
  mldsa65_keypair(pk: Buffer, pkLen: Buffer, sk: Buffer, skLen: Buffer): number;
  mldsa65_sign(sk: Buffer, skLen: number, msg: Buffer, msgLen: number, sig: Buffer, sigLen: Buffer): number;
  mldsa65_verify(pk: Buffer, pkLen: number, msg: Buffer, msgLen: number, sig: Buffer, sigLen: number): number;
  mldsa65_pk_size(): number;
  mldsa65_sk_size(): number;
  mldsa65_sig_size(): number;
}

let _ffi: CryptoFFI | null = null;

export function getFFI(): CryptoFFI {
  if (_ffi) return _ffi;
  if (!libPath) {
    throw new Error(
      'libluxcrypto not found. Build it with: cd ~/work/lux/crypto && make lib'
    );
  }
  const lib = koffi.load(libPath);

  _ffi = {
    mlkem768_keypair: lib.func('int mlkem768_keypair(void *pk, int *pkLen, void *sk, int *skLen)'),
    mlkem768_encapsulate: lib.func('int mlkem768_encapsulate(const void *pk, int pkLen, void *ct, int *ctLen, void *ss, int *ssLen)'),
    mlkem768_decapsulate: lib.func('int mlkem768_decapsulate(const void *sk, int skLen, const void *ct, int ctLen, void *ss, int *ssLen)'),
    mlkem768_pk_size: lib.func('int mlkem768_pk_size()'),
    mlkem768_sk_size: lib.func('int mlkem768_sk_size()'),
    mlkem768_ct_size: lib.func('int mlkem768_ct_size()'),
    mldsa65_keypair: lib.func('int mldsa65_keypair(void *pk, int *pkLen, void *sk, int *skLen)'),
    mldsa65_sign: lib.func('int mldsa65_sign(const void *sk, int skLen, const void *msg, int msgLen, void *sig, int *sigLen)'),
    mldsa65_verify: lib.func('int mldsa65_verify(const void *pk, int pkLen, const void *msg, int msgLen, const void *sig, int sigLen)'),
    mldsa65_pk_size: lib.func('int mldsa65_pk_size()'),
    mldsa65_sk_size: lib.func('int mldsa65_sk_size()'),
    mldsa65_sig_size: lib.func('int mldsa65_sig_size()'),
  };
  return _ffi;
}
