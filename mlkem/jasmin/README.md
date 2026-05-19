# Lux ML-KEM-768 -- Jasmin high-assurance track

This directory holds the Jasmin sources for the Lux ML-KEM-768
high-assurance implementation track. The Lux Jasmin entrypoints are
thin wrappers around libjade's already-verified ML-KEM-768 kernel.

## File layout

| File | Purpose |
|------|---------|
| `lib/mlkem_params.jinc` | Lux-side parameter constants. |
| `keygen.jazz` | ML-KEM-768 keygen wrapper. |
| `encaps.jazz` | ML-KEM-768 + X-Wing encaps wrappers. |
| `decaps.jazz` | ML-KEM-768 + X-Wing decaps wrappers. |

## libjade integration

The single-party ML-KEM-768 kernel is fetched from libjade
(https://github.com/formosa-crypto/libjade) at a pinned commit. The
libjade tree is **not** committed to this repository; the fetch is
explicit and reproducible:

```bash
cd jasmin
./fetch.sh                 # clones libjade at the pinned commit
```

(Per the same protocol as `~/work/lux/pulsar/jasmin/ml-dsa-65/`.)

The libjade ML-KEM-768 kernel is:

- Functional-spec verified against FIPS 203 (Barbosa et al.,
  Eurocrypt 2021).
- Constant-time verified against the BGL leakage model
  (Almeida-Barbosa et al., IEEE S&P 2020).

## Why a wrapper?

The Lux ML-KEM-768 Tier A track is intentionally narrow: we do not
re-implement what libjade already verifies. Instead, the wrapper
gives the artifact pack:

1. A single visible Lux-side entrypoint matching the Go ABI in
   `~/work/lux/crypto/mlkem/mlkem.go`.
2. A canonical citation surface for the Pulsar identity-stage
   `sealEnvelope` (which is the same `lux_mlkem768_encaps` plus an
   HKDF + AEAD wrapping layer) and the Quasar handshake.
3. A drop-in slot for the X-Wing hybrid (which combines ML-KEM-768
   with X25519 per draft-connolly-cfrg-xwing-kem).

## How to build

```bash
./fetch.sh                              # one-time libjade fetch
jasminc -checkCT keygen.jazz            # CT check
jasminc -checkCT encaps.jazz            # CT check
jasminc -checkCT decaps.jazz            # CT check
```

Each invocation should succeed with no constant-time violations
reported.

## Citations

- Almeida, Barbosa, Barthe, Blot, Gregoire, Laporte, Oliveira,
  Pacheco, Schwabe, Strub, "The last mile: High-assurance and
  high-speed cryptographic implementations", IEEE S&P 2020.
- Barbosa, Barthe, Doczkal, Don, Fehr, Gregoire, Huang, Hulsing, Lee,
  Wu, "Fixing and Mechanizing the Security Proof of Fiat-Shamir with
  Aborts and Dilithium", CRYPTO 2023.
- Hofheinz, Hovelmanns, Kiltz, "A Modular Analysis of the
  Fujisaki-Okamoto Transformation", TCC 2017.
- Bos et al., "CRYSTALS-Kyber: A CCA-secure module-lattice-based
  KEM", EuroS&P 2018.
- Connolly, Schwabe, Westerbaan, "X-Wing: The Hybrid KEM You've Been
  Looking For", draft-connolly-cfrg-xwing-kem.
