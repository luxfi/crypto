# lux-crypto

Umbrella crate over the per-algorithm Lux crypto bindings.

Re-exports each `lux-crypto-<alg>` crate behind a Cargo feature so a single
dependency line can pull in exactly the surface a consumer needs.

## Use

```toml
[dependencies]
# Default set: keccak, secp256k1, sha256, ripemd160
lux-crypto = "0.1"

# Or pick specific algorithms:
lux-crypto = { version = "0.1", default-features = false, features = ["keccak", "secp256k1"] }

# Or include every working algorithm (default + blake2b):
lux-crypto = { version = "0.1", default-features = false, features = ["working"] }

# Or pull in every per-algorithm crate (including NOTIMPL stubs):
lux-crypto = { version = "0.1", default-features = false, features = ["all"] }
```

```rust
use lux_crypto::keccak;

let digest = keccak::hash(b"abc");
```

## Algorithm status

| Crate                 | Feature      | Status                                |
|-----------------------|--------------|---------------------------------------|
| `lux-crypto-keccak`   | `keccak`     | wired, vectors verified               |
| `lux-crypto-secp256k1`| `secp256k1`  | wired, vectors verified               |
| `lux-crypto-sha256`   | `sha256`     | wired, vectors verified               |
| `lux-crypto-ripemd160`| `ripemd160`  | wired, vectors verified               |
| `lux-crypto-blake2b`  | `blake2b`    | wired, vectors verified               |
| `lux-crypto-blake3`   | `blake3`     | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-ed25519`  | `ed25519`    | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-slhdsa`   | `slhdsa`     | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-mldsa`    | `mldsa`      | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-mlkem`    | `mlkem`      | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-bls`      | `bls`        | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-kzg`      | `kzg`        | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-bn254`    | `bn254`      | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-aead`     | `aead`       | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-ipa`      | `ipa`        | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-pedersen` | `pedersen`   | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-lamport`  | `lamport`    | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-ntt`      | `ntt`        | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-poly-mul` | `poly-mul`   | binding shipped, C-ABI NOTIMPL        |
| `lux-crypto-evm256`   | `evm256`     | binding shipped, C-ABI NOTIMPL        |

## Build environment

Each per-algorithm crate links statically against `libcrypto/<alg>.a` (and
the corresponding `<alg>_cpu.a` body). The build script discovers the static
archives in this order:

1. `CRYPTO_DIR` — install prefix; archives at `$CRYPTO_DIR/lib/<alg>/`.
2. `CRYPTO_BUILD_DIR` — cmake build dir; archives at `$CRYPTO_BUILD_DIR/<alg>/`.
3. Default fallback to `../../../../luxcpp/crypto/build-cto/`.

```bash
CRYPTO_BUILD_DIR=/path/to/luxcpp/crypto/build-cto cargo build --release
```

## License

Apache-2.0 OR MIT (workspace inherits BSD-3-Clause; see workspace Cargo.toml).

## Source

C-ABI canonical: `luxcpp/crypto/c-abi/lux_crypto.h`.
