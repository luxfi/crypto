# lux-crypto-evm256

Canonical Rust binding for Lux EVM 256-bit big-int math primitives:
- `modexp` (EIP-198 / 0x05 precompile)
- `evm256_mulmod` (EVM `MULMOD` opcode)
- `evm256_addmod` (EVM `ADDMOD` opcode)

**Status: stub — `c_modexp.cpp` returns `CRYPTO_ERR_NOTIMPL`.** Tests gated
`#[ignore]`. Tracked at `#modexp-c-abi-impl`.

The implementations live in `luxcpp/crypto/modexp/`; the empty
`luxcpp/crypto/evm256/` directory is a placeholder for future kernel-side
dispatch.

## Source

C-ABI body: `luxcpp/crypto/modexp/c-abi/c_modexp.cpp`.
