# Publishing the lux-crypto Rust crates to crates.io

This runbook covers publishing the 23 Rust binding crates that
live under `rust/lux-crypto-*` (22 algorithm crates plus the `lux-crypto`
umbrella).

The crates are all FFI bindings to static archives produced by
`luxcpp/crypto`. Because of that, **`cargo publish` cannot run the verify
step** in isolation -- the verify step does an isolated rebuild that does
not have access to the C archives. Use `--no-verify` for the actual upload.
Dry-run packaging (`cargo publish --dry-run --no-verify`) succeeds for all
23 crates in this workspace.

## 1. License decision (BLOCKER -- humans must answer first)

The repository-level `LICENSE` file is the **Lux Ecosystem License v1.2**,
which restricts commercial use to the Lux Primary Network and descending
chains. The per-crate `Cargo.toml` declares
`license = "BSD-3-Clause"` (a valid SPDX identifier), and per-file SPDX
headers in `src/*.rs` declare `BSD-3-Clause-Eco` (an internal marker).

Before publishing, decide one of:

1. Change every crate to `license-file = "LICENSE"` and bundle the
   Lux Ecosystem License with each published crate. Publishing a non-OSI
   license to crates.io is permitted but will surface a yellow banner on
   crates.io.
2. Keep `license = "BSD-3-Clause"` and ensure the Rust source code in
   `rust/` is genuinely BSD-3-Clause (independent of the umbrella project
   license). This is the current state; verify with legal that this is
   intended.
3. Adopt a dual license (e.g. `Apache-2.0 OR MIT`) and re-stamp every
   `Cargo.toml` and source-file SPDX header.

**Until this is resolved, do not publish.** The dry-runs are clean; the
remaining work is a license sign-off, then the upload itself.

## 2. crates.io account + token

```bash
# One-time per publisher account
cargo login <token>            # token from https://crates.io/me
```

The publisher account must be a member of the
[`luxfi` GitHub org](https://github.com/luxfi) and have crates.io publish
permission. To grant publish access for an existing crate:

```bash
cargo owner --add github:luxfi:rust-publishers lux-crypto-<alg>
```

## 3. Name reservation order

Name reservation on crates.io is "first push wins". Reserve all 20 names in
one session to avoid squatters. Recommended order (umbrella last so it can
pin the others as deps in a future release):

```text
lux-crypto-aead
lux-crypto-banderwagon
lux-crypto-blake2b
lux-crypto-blake3
lux-crypto-bls
lux-crypto-ed25519
lux-crypto-evm256
lux-crypto-ipa
lux-crypto-keccak
lux-crypto-kzg
lux-crypto-lamport
lux-crypto-mldsa
lux-crypto-mlkem
lux-crypto-ntt
lux-crypto-pedersen
lux-crypto-poly_mul
lux-crypto-poseidon
lux-crypto-ripemd160
lux-crypto-secp256k1
lux-crypto-sha256
lux-crypto-slhdsa
lux-crypto-verkle
lux-crypto              # umbrella, last
```

## 4. Per-crate dry-run (already verified, included for reproduction)

Run from `rust/`:

```bash
for c in lux-crypto-aead lux-crypto-banderwagon lux-crypto-blake2b \
         lux-crypto-blake3 lux-crypto-bls lux-crypto-ed25519 \
         lux-crypto-evm256 lux-crypto-ipa lux-crypto-keccak \
         lux-crypto-kzg lux-crypto-lamport lux-crypto-mldsa \
         lux-crypto-mlkem lux-crypto-ntt lux-crypto-pedersen \
         lux-crypto-poly_mul lux-crypto-poseidon lux-crypto-ripemd160 \
         lux-crypto-secp256k1 lux-crypto-sha256 lux-crypto-slhdsa \
         lux-crypto-verkle lux-crypto; do
  cargo publish --dry-run -p "$c" --no-verify --allow-dirty || break
done
```

Every crate must report `aborting upload due to dry run`. As of
2026-04-27 all 22 crates pass this check.

## 5. Upload (ordered)

```bash
# Repeat for every crate name in step 3
cargo publish -p lux-crypto-aead --no-verify
sleep 30  # let crates.io index update before publishing dependents

# ... and so on for each crate
```

`--no-verify` is required because the verify step rebuilds in isolation
without the `luxcpp/crypto` archives. End-users will hit the same isolation
when they consume the published crate; the build script documents the
required `CRYPTO_DIR` / `CRYPTO_BUILD_DIR` environment variables in every
crate's README.

## 6. Native-archive dependency (Option C, documented)

These crates link against static archives produced by the C++ project at
`https://github.com/luxfi/crypto`. Downstream consumers must build those
archives once and point the build script at them via:

```bash
export CRYPTO_DIR=$HOME/.local        # install prefix
# or
export CRYPTO_BUILD_DIR=$(pwd)/build  # cmake build dir
cargo build -p lux-crypto-<alg>
```

Each per-crate `README.md` documents this. We deliberately did not bundle
the C source (option B): the C codebase is large, has its own build
toolchain, and bundling would force `cmake + clang` to be available at
`cargo build` time for every consumer.

If a future release wants in-source builds, the path is:

1. Add a `[features]` section per crate with a default feature `linked`
   (current behaviour) and an opt-in feature `vendored` that vendors a
   tagged snapshot of `luxcpp/crypto` and runs cmake from `build.rs`.
2. Add `cmake = "0.1"` and `cc = "1.0"` to `[build-dependencies]` only on
   the vendored feature path.
3. Document the feature flag in each README.

This is deferred until there is demand from external consumers.

## 7. Post-publish verification

For each published crate, confirm:

- `https://crates.io/crates/lux-crypto-<alg>` renders
- `https://docs.rs/lux-crypto-<alg>` renders (docs.rs builds without
  CRYPTO_DIR; the build will fail there until we either add a `docs.rs`
  metadata block that skips link, or wire a vendored build path; see #8)

## 8. docs.rs build (known follow-up)

docs.rs builds in a sandbox without `CRYPTO_DIR`. To make documentation
build there, add to each per-crate `Cargo.toml`:

```toml
[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs"]
```

and gate the `extern "C"` blocks behind `#[cfg(not(docsrs))]` so docs.rs
only compiles signatures, not the link step. This is a follow-up; not
required for the initial publish.

## 9. Yanking

If a release contains a wire-format incompatibility, yank with:

```bash
cargo yank --vers 0.1.0 -p lux-crypto-<alg>
```

Yanked versions stay published but are no longer selected by Cargo's
resolver.

## 10. Versioning policy

- Stay on `0.1.x` until the C-ABI surface stabilises.
- A breaking change to the C-ABI bumps the **minor** version
  (`0.1.x -> 0.2.0`) for every crate in lockstep.
- Never bump to `1.0.0` until the FFI surface is frozen and audit-stable.

## 11. Workspace package fields

The workspace at `rust/Cargo.toml` provides:

```toml
[workspace.package]
edition = "2021"
license = "BSD-3-Clause"
rust-version = "1.74"
authors = ["Lux Industries Inc. <opensource@lux.network>"]
homepage = "https://lux.network"
repository = "https://github.com/luxfi/crypto"
documentation = "https://docs.lux.network/crypto"
readme = "README.md"
```

Per-crate `Cargo.toml` files inherit via `field.workspace = true`. Add
crate-specific `keywords`, `categories`, and `description` per crate.

## 12. Source attribution checklist

| Crate | Vendored / derived | Upstream license |
|-------|--------------------|------------------|
| `lux-crypto-blake3` | BLAKE3 ref v1.5.0 | CC0 / Apache-2.0 |
| `lux-crypto-ed25519` | ed25519-donna | Public domain |
| `lux-crypto-mldsa`, `lux-crypto-mlkem`, `lux-crypto-slhdsa` | PQClean | CC0 / public domain |
| `lux-crypto-kzg` | c-kzg-4844 | Apache-2.0 |
| `lux-crypto-evm256` | intx + evmmax | Apache-2.0 |
| `lux-crypto-poseidon` | gnark-crypto v0.20.1 round constants | Apache-2.0 |
| `lux-crypto-banderwagon`, `lux-crypto-verkle` | Public Banderwagon SRS | CC0 |

Every crate's README declares the vendored source. The Cargo metadata
license field describes the **Rust binding** license, not the upstream
algorithm authors' license; both are compatible.
