# Publishing the Lux Crypto Rust crates

Runbook for publishing the workspace to crates.io.

## Prerequisites

1. A crates.io API token in `~/.cargo/credentials.toml` (`cargo login`).
2. The luxcpp/crypto static archives built locally (`CRYPTO_BUILD_DIR`
   pointed at the cmake build directory).
3. A clean working tree on the release tag.

## Order of operations

The umbrella crate (`lux-crypto`) depends on every per-algorithm crate.
Per-algorithm crates have no inter-dependencies, so they can be published
in any order; the umbrella **must** be published last.

```bash
cd /Users/z/work/lux/crypto/rust
export CRYPTO_BUILD_DIR=/Users/z/work/luxcpp/crypto/build-cto

# Step 1: per-algorithm crates (any order, twenty calls).
for c in \
    lux-crypto-aead lux-crypto-blake2b lux-crypto-blake3 lux-crypto-bls \
    lux-crypto-bn254 lux-crypto-ed25519 lux-crypto-evm256 lux-crypto-ipa \
    lux-crypto-keccak lux-crypto-kzg lux-crypto-lamport lux-crypto-mldsa \
    lux-crypto-mlkem lux-crypto-ntt lux-crypto-pedersen lux-crypto-poly-mul \
    lux-crypto-ripemd160 lux-crypto-secp256k1 lux-crypto-sha256 \
    lux-crypto-slhdsa
do
    cargo publish -p "$c"
    # crates.io needs a few seconds to index each upload.
    sleep 10
done

# Step 2: umbrella crate.
cargo publish -p lux-crypto
```

## Tagging

Tag the workspace repo immediately after the publish completes:

```bash
git tag -a v0.1.0-rust -m "lux-crypto Rust crates 0.1.0"
git push origin v0.1.0-rust
```

## Post-publish verification

```bash
# From a clean, separate machine:
cargo install --no-default-features --features "keccak,secp256k1" lux-crypto

# Or pin a specific version:
cargo add lux-crypto-keccak@0.1.0
```

## Dry-run before each release

```bash
cd /Users/z/work/lux/crypto/rust
export CRYPTO_BUILD_DIR=/Users/z/work/luxcpp/crypto/build-cto

for c in lux-crypto-aead lux-crypto-blake2b lux-crypto-blake3 lux-crypto-bls \
         lux-crypto-bn254 lux-crypto-ed25519 lux-crypto-evm256 lux-crypto-ipa \
         lux-crypto-keccak lux-crypto-kzg lux-crypto-lamport lux-crypto-mldsa \
         lux-crypto-mlkem lux-crypto-ntt lux-crypto-pedersen \
         lux-crypto-poly-mul lux-crypto-ripemd160 lux-crypto-secp256k1 \
         lux-crypto-sha256 lux-crypto-slhdsa
do
    cargo publish --dry-run --no-verify -p "$c" --allow-dirty
done
```

Every dry-run must pass before any real publish.

## License notes

Workspace defaults to `BSD-3-Clause`. crates.io accepts SPDX expressions; if
the org legal review pushes the per-crate license to `Apache-2.0 OR MIT`,
update the workspace `[workspace.package]` `license` field and re-run dry-run
before publishing.

## Currently blocked

This workspace has not been published to crates.io. The first publish should
happen on a CI machine with a token issued for the `luxfi-org` namespace,
not from a developer laptop. No `cargo login` token is currently present in
the development environment.
