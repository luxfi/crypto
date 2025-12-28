# lux-crypto (Rust) benchmarks

## Status

No criterion benches yet. The Rust crate is a thin FFI binding —
performance is bounded by the C library. Benchmarks for the underlying
implementations live where the work happens:

| Subject | Where the bench lives |
|---|---|
| secp256k1 ecrecover (CPU + Metal) | `luxcpp/crypto/secp256k1/test/` |
| mldsa keygen/sign/verify          | `luxcpp/crypto/mldsa/test/` |
| mlkem keygen/encaps/decaps        | `luxcpp/crypto/mlkem/test/` |
| slhdsa keygen/sign/verify         | `luxcpp/crypto/slhdsa/test/` |
| ed25519 keygen/sign/verify        | `luxcpp/crypto/ed25519/test/` |
| keccak256 hashing (CPU + GPU)     | `luxcpp/crypto/keccak/test/` |

The Rust crate adds no measurable overhead to the FFI call (one
`unsafe extern "C"` jump per primitive), so a Rust-side bench would
duplicate the C-side numbers within sampling noise. Adding criterion
benches solely to publish a Rust-flavored number would be vanity work.

## When Rust benches are warranted

If the Rust crate ever grows non-trivial Rust-side code (e.g. a
thread-pool batch dispatcher, a streaming API, async wrapper), criterion
benches under `benches/` will be added at that point.

Until then: see `luxcpp/crypto/<alg>/test/` for per-algorithm
benchmark numbers, and `luxcpp/fhe/BENCHMARKS_*.txt` for FHE numbers.
