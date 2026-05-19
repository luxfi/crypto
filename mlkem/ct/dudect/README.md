# Lux ML-KEM-768 -- constant-time analysis harness (dudect)

Empirical constant-time verification of the Lux ML-KEM-768 hot path
(Keygen / Encaps / Decaps) using dudect
(https://github.com/oreparaz/dudect).

## CT population

Both dudect classes are **valid** invocations of the routine under
test, differing only in the random or secret input:

- **Keygen**: class A = `keygen(zero-tape)`, class B = `keygen(random-tape)`.
- **Encaps**: class A = `encaps(pk, zero-tape)`, class B = `encaps(pk, random-tape)`.
- **Decaps**: class A = `decaps(sk, pool[0])`, class B = `decaps(sk, pool[rand])`.
  Both inputs are VALID ciphertexts under the matching public key;
  any timing difference is a real ciphertext-content-dependent
  signal in Decaps (i.e., a FO-K timing attack surface).

## Quick start

```bash
./fetch.sh             # one-time: pulls dudect.h
make                   # builds all three harnesses
./dudect_keygen        # smoke test (~30s)
./dudect_encaps        # smoke test (~30s)
./dudect_decaps        # smoke test (~30s)
```

## Full submission run

```bash
DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_decaps
```

Pin a CPU (`taskset -c 0` on Linux), disable turbo boost, close
background services. Each full run takes ~6 hours.

## Exit codes

- `0`: VERDICT no leakage detected within budget.
- `2`: VERDICT leakage detected (t-test > 4.5).
- Other: harness setup error.

## Status

Expected verdict for all three routines is "no leakage detected"
because Lux wraps Cloudflare circl's mlkem768 implementation, which
is documented as CT and routinely tested against the NIST KAT
vectors. The harness is the empirical regression guard.

## Citations

- Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?",
  DATE 2017.
- Cloudflare circl ML-KEM:
  https://github.com/cloudflare/circl/tree/main/kem/mlkem
