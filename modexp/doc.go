// Package modexp is the canonical alias for github.com/luxfi/crypto/bigmodexp.
//
// modexp matches the EVM precompile name (EIP-198) and the luxcpp/crypto
// directory layout. The two import paths return identical types.
package modexp

import "github.com/luxfi/crypto/bigmodexp"

// Int is the patched big.Int with the fixed Exp implementation.
type Int = bigmodexp.Int
