// Package polymul is the canonical entry point for polynomial multiplication
// in the lattice-cryptography ring Z_q[X] / (X^N + 1).
//
// The CPU implementation is a schoolbook O(N^2) multiplication that handles
// arbitrary moduli. For production lattice crypto callers should use the
// algorithm-specific NTT-based multiplication in mldsa/ or mlkem/, or
// route through the GPU via github.com/luxfi/accel which has fused
// NTT+pointwise+INTT kernels.
//
// Naming follows the luxcpp/crypto/poly_mul/ directory; both polymul (Go
// idiomatic) and the underscore form are accepted as identifiers.
package polymul
