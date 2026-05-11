// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package ethdilithium_compat is an EVM-friendly ML-DSA variant
// reimplemented from the public description of the ZKNoxHQ
// EthDilithium scheme. NOT FIPS 204; for benchmark and Ethereum-
// fallback ONLY.
//
// # WHAT THIS IS
//
// The strict luxfi PQ profile lives in crypto/pq/mldsa/mldsa65 and
// follows FIPS 204 verbatim, including SHAKE-256 at every Algorithm
// 30 / 31 / 32 / 33 call site. Verifying a FIPS 204 signature on an
// EVM smart contract or in a precompile is expensive primarily
// because the EVM has no native SHAKE-256 instruction — every
// absorb/squeeze must be unrolled in solidity at ~20k gas per
// permutation.
//
// EthDilithium addresses this by routing the message-bind hash
// through Keccak-256 instead of SHAKE-256: an EVM verifier already
// has a native Keccak instruction, and our off-chain signer can do
// the same Keccak compression. The signature itself is then a
// standard FIPS 204 signature, but on the Keccak-derived "effective
// message", not on the caller-provided raw bytes.
//
// API
//
//	Sign(skBytes, msg, ctx []byte) ([]byte, error)
//	Verify(pkBytes, msg, ctx, sig []byte) bool
//
// Both wrap crypto/pq/mldsa/mldsa65 under the hood. The wire format
// of the public key, private key, and signature is identical to
// FIPS 204 ML-DSA-65 — only the message preprocessing differs. The
// effective message passed to ML-DSA is:
//
//	effMsg = Keccak256("LUX/EthDilithium/v1" ‖ uint8(len(ctx)) ‖ ctx ‖ msg)
//
// where the length-prefix on ctx prevents a (ctx=A, msg=B) signature
// from re-binding against (ctx=A‖B, msg=""). This is the same
// length-prefix discipline FIPS 204 §5.2 uses for its own context-
// binding, but it is performed in Keccak-256 rather than SHAKE-256.
//
// # NOT INTEROPERABLE
//
// Signatures produced by this package will NOT verify under
// mldsa65.Verify with the same (msg, ctx) — they will verify under
// mldsa65.Verify with the Keccak-derived effMsg. The pk and sig
// byte layouts are identical to FIPS 204 (so an EVM verifier
// expecting ML-DSA-65 wire bytes accepts the same input), but the
// signed payload semantics differ.
//
// Verify will REFUSE pk/sk bytes that do not match the FIPS 204
// ML-DSA-65 wire size; we deliberately do not silently accept
// other parameter sets so an EVM contract written for ML-DSA-65
// cannot be tricked into routing through a different verifier.
//
// # NOT FIPS 204 COMPLIANT
//
// This package is for benchmarking and Ethereum-fallback ONLY.
// NOT acceptable under any LUX_STRICT_E2E_PQ profile.
// The strict path is crypto/pq/mldsa/mldsa{44,65,87}.{Sign,Verify}.
//
// The Keccak substitution and message preprocessing here are based
// on the publicly documented EthDilithium variant; the code is
// re-implemented in this package and shares no source with the
// LGPL-3.0 ZKNoxHQ/ETHDILITHIUM reference repository.
package ethdilithium_compat
