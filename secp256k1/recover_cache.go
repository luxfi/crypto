// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1

import (
	"github.com/luxfi/crypto/cache"
)

// RecoverCacheType provides a cache for public key recovery with methods
type RecoverCacheType struct {
	cache *cache.LRU[string, *PublicKey]
}

// NewRecoverCache creates a new recover cache
func NewRecoverCache(size int) RecoverCacheType {
	return RecoverCacheType{
		cache: cache.NewLRU[string, *PublicKey](size),
	}
}

// RecoverPublicKey recovers a public key from a message and signature
func (r RecoverCacheType) RecoverPublicKey(msg, sig []byte) (*PublicKey, error) {
	return RecoverPublicKey(msg, sig)
}

// RecoverPublicKeyFromHash recovers a public key from a hash and signature
func (r RecoverCacheType) RecoverPublicKeyFromHash(hash, sig []byte) (*PublicKey, error) {
	return RecoverPublicKeyFromHash(hash, sig)
}