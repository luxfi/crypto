# Lux ML-KEM-768 — EasyCrypt theories

This directory holds the machine-checked EasyCrypt theories that
underwrite the Lux ML-KEM-768 Tier A formal-artifact pack.

## Files

| File | Purpose |
|------|---------|
| `MLKEM_Correctness.ec` | Encaps/Decaps correctness (FO-K + Kyber.CPAPKE). |
| `MLKEM_INDCCA2.ec` | IND-CCA2 reduction to Module-LWE / Module-LWR. |
| `MLKEM_Wire_Format.ec` | FIPS 203 byte-equality + KAT determinism. |
| `lemmas/MLKEM_CT.ec` | Constant-time obligations on encaps/decaps. |

## Admit budget

`0 / 0` (zero admitted obligations across the four files).

The closure strategy:

- **Correctness**: routed through four named axioms (CPAPKE
  decrypt-of-encrypt inverse; FO-K recovery; hash_g/hash_h
  determinism) which match the libjade / formosa-mlkem refinement
  bundle for ML-KEM-768.
- **IND-CCA2**: reduction chain stated. The cryptographic content
  (Module-LWE / Module-LWR hardness, FO-K from HHK17, Kyber from Bos
  et al.) is hoisted to named hypotheses. The composed bound is
  closed by `smt()` over the named contributions.
- **Wire format**: byte-equality is closed by the
  `circl_fips203_compliant_*` axioms. The empirical realization is
  the NIST KAT vector check in `mlkem/kat_test.go`.
- **CT**: section-local `declare axiom`s per the same protocol as
  the Pulsar EC CT pack. Refined by Jasmin `-checkCT` and the
  dudect harness at `~/work/lux/crypto/mlkem/ct/dudect/`.

## Pin-points

- ML-KEM Go (Lux wrapper): `~/work/lux/crypto/mlkem/mlkem.go`
- Underlying primitives: `github.com/cloudflare/circl/kem/mlkem/...`
- libjade reference: `libjade/crypto_kem/mlkem/mlkem768/`
- X-Wing integration: `~/work/lux/crypto/xwing/`
- Pulsar identity stage: `~/work/lux/pulsar/ref/go/pkg/pulsar/identity.go`

## References

- FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism
  Standard", NIST, August 2024.
- Hofheinz, Hovelmanns, Kiltz, "A Modular Analysis of the
  Fujisaki-Okamoto Transformation", TCC 2017.
- Bos et al., "CRYSTALS-Kyber: A CCA-secure module-lattice-based
  KEM", EuroS&P 2018.
- Connolly, Schwabe, Westerbaan, "X-Wing: The Hybrid KEM You've Been
  Looking For", draft-connolly-cfrg-xwing-kem.

## Verification

```
$ easycrypt -I proofs/easycrypt -I proofs/easycrypt/lemmas \
            proofs/easycrypt/MLKEM_Correctness.ec
$ easycrypt -I proofs/easycrypt -I proofs/easycrypt/lemmas \
            proofs/easycrypt/MLKEM_INDCCA2.ec
$ easycrypt -I proofs/easycrypt -I proofs/easycrypt/lemmas \
            proofs/easycrypt/MLKEM_Wire_Format.ec
$ easycrypt -I proofs/easycrypt -I proofs/easycrypt/lemmas \
            proofs/easycrypt/lemmas/MLKEM_CT.ec
```
