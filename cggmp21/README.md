# cggmp21

Threshold-ECDSA protocol scaffolding for the CGGMP21 construction
(Canetti, Gennaro, Goldfeder, Makriyannis, Peled, 2021 — *"UC
Non-Interactive, Proactive, Threshold ECDSA with Identifiable
Aborts"*, [eprint 2021/060](https://eprint.iacr.org/2021/060)).

CGGMP21 is Lux's canonical native-MPC construction for production
signing paths (see the bridge policy in
[luxfi/bridge#405](https://github.com/luxfi/bridge/pull/405): *"Production
stays pure native MPC (CGGMP21 / FROST via luxfi/mpc)"*). This
package holds the in-tree types + protocol-round skeleton used by
higher-level threshold code; the fully-verified production signer
lives at [`github.com/luxfi/threshold`](../threshold) and consumes
the same primitives.

## Scope

This package provides:

- Party / session state machines for the four-round CGGMP21 flow
  (Commit → Reveal → Multiply → Open).
- A Paillier keypair + additively-homomorphic encryption used by the
  MtA (multiplicative-to-additive) share-conversion step, including
  a Schnorr-style ZK-proof-of-plaintext-knowledge skeleton.
- ECDSA signature and identifiable-abort record types.
- A `VerifySignature` helper for the final aggregated signature.

This package does **not** provide:

- A production-ready `Finalize` — the current `Finalize` intentionally
  returns an error and delegates to `github.com/luxfi/threshold` for
  the full MtA reconciliation, consistency checks, and
  identifiable-abort proofs. Do not call this package's
  `Finalize` from signing paths.
- The full CGGMP21 ZK proof suite. `ProveKnowledge` /
  `VerifyKnowledge` here are a simplified Schnorr-style sketch (with
  a non-Fiat-Shamir placeholder challenge) intended to illustrate
  shape; production code MUST use the proofs specified in the CGGMP21
  paper (Πenc, Πlog*, Πaff-g, Πmul, Πdec, etc.).
- Distributed key-generation networking. `Party.KeyGen` populates
  local share state only; a transport layer supplies peer shares.
- Dispute resolution or on-chain glue — those live above this package
  in the bridge / threshold layers.

## Public API

Verified against `cggmp21.go` and `paillier.go` at file time.

### Core types

| Symbol | Purpose |
| --- | --- |
| `Signature` | ECDSA `(R, S)` output. |
| `Config` | Threshold `t`, total parties `n`, curve, round timeout. |
| `Party` | Per-node state (secret share, Paillier keys, sessions). |
| `SigningSession` | Per-session state across all four rounds. |
| `ECPoint` | `(X, Y)` on the configured curve. |
| `Round2Message`, `Round3Message`, `Round4Message` | Wire messages between rounds. |
| `IdentifiableAbort` | Blame record for a misbehaving party. |

### Party lifecycle

| Symbol | Purpose |
| --- | --- |
| `NewParty(id, index, cfg, log)` | Constructor. Generates a 2048-bit Paillier keypair. |
| `(*Party).KeyGen(parties)` | Local DKG step — samples `x_i`, computes `[x_i]G`. |
| `(*Party).InitiateSign(sessionID, message)` | Opens a signing session; hashes message with SHA-256. |
| `(*Party).Round1_Commitment(sessionID)` | Samples `k_i`, `γ_i`; returns `H(i, [γ_i]G)`. |
| `(*Party).Round2_Reveal(sessionID, commitments)` | Reveals `[γ_i]G` after receiving peer commitments. |
| `(*Party).Round3_Multiply(sessionID, reveals)` | Verifies commitments, computes `δ_i = k_i·γ_i` and `χ_i = x_i·k_i`. |
| `(*Party).Round4_Open(sessionID, round3msgs)` | Broadcasts `δ_i` and collects peer `[δ_j]G`. |
| `(*Party).Finalize(sessionID, round4msgs)` | **Stub** — returns an error; use `luxfi/threshold`. |

### Helpers

| Symbol | Purpose |
| --- | --- |
| `VerifySignature(pubKey, message, sig)` | Verifies a completed threshold signature against a public key. |
| `ScalarBaseMult(curve, k)` | Convenience wrapper returning an `*ECPoint`. |

### Paillier (in `paillier.go`)

| Symbol | Purpose |
| --- | --- |
| `PaillierPublicKey`, `PaillierPrivateKey` | Keypair types. |
| `GeneratePaillierKeyPair(bits)` | Samples two primes, returns keypair. |
| `(*PaillierPublicKey).Encrypt(m)` | Standard Paillier encryption. |
| `(*PaillierPrivateKey).Decrypt(c)` | Standard Paillier decryption. |
| `(*PaillierPublicKey).Add(c1, c2)` | Homomorphic addition (`c1·c2 mod n²`). |
| `(*PaillierPublicKey).Multiply(c, k)` | Homomorphic constant-multiplication (`c^k mod n²`). |
| `L(x, n)` | Standard Paillier `L(x) = (x−1)/n`. |
| `ZKProof`, `ProveKnowledge`, `VerifyKnowledge` | Schnorr-style plaintext-knowledge proof **sketch** — see caveat above. |

## Paillier usage

CGGMP21 uses Paillier as the additively-homomorphic backbone of the
MtA conversion — every `Party` holds a private Paillier key and the
peers' public keys, so a share `k_i` can be multiplied against a
peer's `γ_j` under encryption and the result reshared additively.
The keypair is generated eagerly inside `NewParty` at 2048 bits; the
current tree does not gate that on a config option.

## Security notes

- **Threshold model.** `t`-of-`n` with the identifiable-abort variant
  from CGGMP21: any party deviating from the protocol can be
  cryptographically blamed via `IdentifiableAbort`; the honest
  majority does not lose their key material on abort.
- **No key extraction on abort.** Aborts surface at message-level
  proof failure, not by revealing secret shares.
- **Curve.** Configured through `Config.Curve` — production callers
  should pass `secp256k1` (or the equivalent `luxfi/crypto/secp256k1`)
  and never mix curves across a session.
- **Randomness.** All sampling uses `crypto/rand`; do not substitute
  a deterministic source for testing outside of dedicated test
  builds.

## Operational constraints

Per the bridge signing policy
([luxfi/bridge#405](https://github.com/luxfi/bridge/pull/405)):

- **Non-custodial by default.** Production signing paths must remain
  pure native MPC — CGGMP21 (this package + `luxfi/threshold`) for
  ECDSA and FROST (via `luxfi/mpc`) for Schnorr / Ed25519.
- **No cosigner path.** Cosigner / MPC-provider fallback is
  explicitly opt-in and must not be reachable from the default bridge
  configuration.
- **`Finalize` is not wired.** Any caller reaching this package's
  `Finalize` is a bug — route through `luxfi/threshold`.

## References

- Canetti, Gennaro, Goldfeder, Makriyannis, Peled. *UC
  Non-Interactive, Proactive, Threshold ECDSA with Identifiable
  Aborts.* CCS 2020 / eprint 2021/060.
  <https://eprint.iacr.org/2021/060>
- Sibling packages in this repo:
  - [`../threshold`](../threshold) — production threshold-signing
    entrypoint that this package feeds.
  - [`../bls`](../bls) — BLS threshold (separate construction, not
    ECDSA).
- Ecosystem:
  - [`luxfi/mpc`](https://github.com/luxfi/mpc) — hosts the FROST
    Schnorr/Ed25519 side of the native-MPC stack.
  - [`luxfi/bridge`](https://github.com/luxfi/bridge) — canonical
    consumer; PR #405 sets the production-signing policy this
    package supports.
