# attestation

Remote-attestation quote verification for TEEs (Intel SGX DCAP v3, Intel TDX
DCAP v4, AMD SEV-SNP). Given a raw hardware quote and a pinned trust policy,
this package cryptographically checks the claim: "I am running the expected
code inside a genuine enclave, and my confidentiality key is bound to that
enclave." A quote either passes all four soundness checks or is rejected with
a specific error — nothing is skipped.

## Scope

**Does:**

- Parse Intel SGX (DCAP v3), Intel TDX (DCAP v4), and AMD SEV-SNP quote wire
  formats into a canonical `Quote` shape (`vendor.go`).
- Verify the attestation-key certificate chain to a **pinned** vendor root
  (`attestation.go:74-89`, `vendor.go:49-68`).
- Verify the ECDSA signature over the exact signed region of the quote
  (SGX/TDX: header ‖ report body under P-256/SHA-256; SNP: `report[0:0x2A0]`
  under P-384/SHA-384) (`vendor.go:136-139`, `vendor.go:207-209`,
  `vendor.go:257-259`).
- Enforce a caller-supplied enclave measurement allow-list (`MRENCLAVE` for
  SGX, `MRTD` for TDX/SNP) (`attestation.go:99-102`).
- Enforce the operator-key binding: `report_data[0:32] == sha256(operatorPub)`
  (`attestation.go:57-60`, `vendor.go:273-277`).

**Does not:**

- Fetch PCK / VCEK certificates from Intel PCS or AMD KDS. Callers supply the
  cert chain in the quote or as a separate parameter (`VerifySNP` takes
  `vcekDER` + `askDER` explicitly, `vendor.go:237`).
- Manage the pinned root store or measurement allow-list. Callers construct
  `*x509.CertPool` and `map[[32]byte]bool` / `map[[48]byte]bool` themselves
  (`attestation.go:35-38`).
- Rotate or revoke roots. Pin lifecycle is upstream policy.

## Public API

Verified against HEAD.

| Symbol                          | Location                    | Purpose                                                                |
|---------------------------------|-----------------------------|------------------------------------------------------------------------|
| `Quote`                         | `attestation.go:26-32`      | Canonical parsed quote (measurement, report data, leaf, chain, sig).   |
| `Policy`                        | `attestation.go:35-38`      | Trust policy: pinned roots + allowed 32-byte measurements.             |
| `BindKey(operatorPub) [32]byte` | `attestation.go:58-60`      | The value an enclave must place in `ReportData` to bind a pub key.     |
| `Verify(q, policy, boundKey)`   | `attestation.go:66-109`     | Verify a canonical `Quote` against policy + operator key binding.      |
| `VerifySGX(...)`                | `vendor.go:90-150`          | Parse + verify an Intel SGX DCAP v3 quote; returns MRENCLAVE (32B).    |
| `VerifyTDX(...)`                | `vendor.go:166-220`         | Parse + verify an Intel TDX DCAP v4 quote; returns MRTD (48B).         |
| `VerifySNP(...)`                | `vendor.go:237-269`         | Parse + verify an AMD SEV-SNP report; returns measurement (48B).       |
| `VendorSGX / VendorTDX / VendorSNP` | `vendor.go:29-33`       | String vendor tags.                                                    |
| `ErrChain / ErrSignature / ErrMeasurement / ErrBinding / ErrFormat` | `attestation.go:40-46` | Distinguishable verification failures. |
| `ErrQuoteLayout`                | `vendor.go:35`              | Wire-format-level parse failure (short buffer, bad r‖s width).         |

## Vendor integrations

`vendor.go` implements the three production TEE quote formats directly (no
third-party dependency, no CGO). Offsets follow the Intel SGX/TDX DCAP quote
spec and the AMD SEV-SNP firmware ABI (`vendor.go:11-13`):

- **Intel SGX DCAP v3** — `Header(48) ‖ ReportBody(384) ‖ sigDataLen(4) ‖
  sigData`. MRENCLAVE at absolute offset 112; report_data at 368. ECDSA-P256
  over SHA-256. The QE report binds the attestation key via
  `report_data = sha256(attestPub ‖ authData)` (`vendor.go:70-150`).
- **Intel TDX DCAP v4** — `Header(48) ‖ TDReport(584) ‖ sigDataLen(4) ‖
  sigData`. MRTD at 184; report_data at 568. Same sigData shape as SGX;
  ECDSA-P256/SHA-256 (`vendor.go:152-220`).
- **AMD SEV-SNP** — 1184-byte attestation report. report_data at `0x50`;
  measurement at `0x90`; signature at `0x2A0` as raw little-endian r‖s (72
  bytes each). ECDSA-P384 over SHA-384. VCEK leaf must be supplied by the
  caller and chain to a pinned AMD root (ARK/ASK) (`vendor.go:222-269`).

Signature scalars for SGX/TDX ship as raw big-endian r‖s; SNP ships them
little-endian. Both are re-encoded to ASN.1 for `crypto/ecdsa`
(`vendor.go:37-46`, `vendor.go:245-251`, `vendor.go:290-297`).

## Security model

Trust root is a **pinned** `*x509.CertPool` supplied by the caller — typically
the Intel SGX/TDX root and/or AMD ARK/ASK. Verification is all-or-nothing: a
quote with a valid measurement but a bad signature, or a valid signature
under an unpinned chain, is rejected (`attestation.go:63-65`).

The four checks (`attestation.go:66-109`) are:

1. **Chain** — attestation-key certificate chains to a pinned root
   (`ErrChain`).
2. **Signature** — ECDSA signature over the exact signed preimage verifies
   under the attestation key (`ErrSignature`). Preimage is
   `domain ‖ Measurement ‖ ReportData` where `domain = "hanzo/poi/tee-quote/v1"`
   for the canonical shape (`attestation.go:22-23`, `attestation.go:49-55`);
   for vendor-native quotes, the signed region is the header + report body
   verbatim (`vendor.go:99`, `vendor.go:175`, `vendor.go:243`).
3. **Measurement** — `MRENCLAVE` / `MRTD` on the caller's allow-list
   (`ErrMeasurement`).
4. **Binding** — `report_data[0:32] == sha256(boundKey)` (`ErrBinding`).
   This is the load-bearing link to `promptseal`: it proves the sealed prompt
   can only be opened inside the attested enclave (`attestation.go:1-9`).

**Replay guards** are out of scope. `Verify` is stateless; nonce / freshness
handling belongs to the caller (typically a challenge in `boundKey` derivation
or an outer transcript).

Off-curve points are rejected before use (`vendor.go:341-352`), and byte
comparisons for the key-binding check use `equalFixed` — a constant-time
XOR reduction (`vendor.go:279-288`).

## Production status

**Real implementation.** Not a scaffolding stub.

- `attestation.go` (109 lines) — canonical `Verify` performs all four checks
  with no bypass; each has a specific error and a dedicated code path
  (`attestation.go:74-107`).
- `vendor.go` (369 lines) — three production TEE quote parsers with real
  spec-derived byte offsets (`vendor.go:82-87`, `vendor.go:158-163`,
  `vendor.go:227-233`), raw-r‖s → ASN.1 re-encoding for `crypto/ecdsa`
  (`vendor.go:37-46`), and P-256 / P-384 dispatch by vendor
  (`vendor.go:137`, `vendor.go:257`).
- `attestation_test.go` (196 lines) + `vendor_test.go` (252 lines) — tests
  cover chain failure, bad signature, disallowed measurement, and wrong
  binding for each vendor path.

Verified at commit HEAD on the `docs/attestation-readme` branch base.

## References

- Adjacent to **LP-5300 / LP-5301** (Proof-of-Thought / Proof-of-Inference
  receipts) insofar as PoT is a form of computation attestation: an enclave
  attestation is the hardware-rooted variant of the same "I ran this code"
  claim that PoT expresses at the LP layer.
- The `domain = "hanzo/poi/tee-quote/v1"` tag (`attestation.go:23`) and the
  package doc's promptseal reference point to the Hanzo Proof-of-Inference
  pipeline: attested-TEE decryption is how PoI achieves non-custodial
  delegated operation.
- Intel SGX / TDX DCAP quote spec (Intel).
- AMD SEV-SNP firmware ABI (AMD).
