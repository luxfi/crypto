/**
 * Quick smoke test for luxcrypto TypeScript bindings.
 */
import { LUX_CRYPTO_AVAILABLE, mlkem768, mldsa65 } from './index.js';

console.log(`luxcrypto available: ${LUX_CRYPTO_AVAILABLE}`);

if (!LUX_CRYPTO_AVAILABLE) {
  console.error('libluxcrypto not found — build with: cd ~/work/lux/crypto && make lib');
  process.exit(1);
}

// ML-KEM-768 roundtrip
console.log('\n=== ML-KEM-768 (FIPS 203) ===');
const [kemPk, kemSk] = mlkem768.keypair();
console.log(`  pk: ${kemPk.length} bytes`);
console.log(`  sk: ${kemSk.length} bytes`);

const [ct, ssEnc] = mlkem768.encapsulate(kemPk);
console.log(`  ct: ${ct.length} bytes`);
console.log(`  ss: ${ssEnc.length} bytes`);

const ssDec = mlkem768.decapsulate(kemSk, ct);
console.log(`  ss_dec: ${ssDec.length} bytes`);

const match = Buffer.from(ssEnc).equals(Buffer.from(ssDec));
console.log(`  roundtrip: ${match ? 'PASS' : 'FAIL'}`);

// ML-DSA-65 sign/verify
console.log('\n=== ML-DSA-65 (FIPS 204) ===');
const [dsaPk, dsaSk] = mldsa65.keypair();
console.log(`  pk: ${dsaPk.length} bytes`);
console.log(`  sk: ${dsaSk.length} bytes`);

const message = new TextEncoder().encode('Hello, post-quantum world!');
const sig = mldsa65.sign(dsaSk, message);
console.log(`  sig: ${sig.length} bytes`);

const valid = mldsa65.verify(dsaPk, message, sig);
console.log(`  verify: ${valid ? 'PASS' : 'FAIL'}`);

const wrongMsg = new TextEncoder().encode('tampered');
const invalid = mldsa65.verify(dsaPk, wrongMsg, sig);
console.log(`  reject tampered: ${!invalid ? 'PASS' : 'FAIL'}`);

if (match && valid && !invalid) {
  console.log('\nAll tests passed!');
} else {
  console.error('\nSome tests failed!');
  process.exit(1);
}
