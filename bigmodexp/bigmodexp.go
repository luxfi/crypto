// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
//
// Package bigmodexp re-exports the patched math/big from go-bigmodexpfix
// under the luxfi/crypto namespace so that downstream packages never
// import ethereum/* directly.
//
// The upstream package provides a patched big.Int.Exp that fixes a
// consensus-critical modular exponentiation edge case.

package bigmodexp

import (
	upstream "github.com/ethereum/go-bigmodexpfix/src/math/big"
)

// Int is the patched big.Int with the fixed Exp implementation.
type Int = upstream.Int
