// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package hashing is an alias for hash package for backwards compatibility.
// New code should use github.com/luxfi/crypto/hash directly.
package hashing

import "github.com/luxfi/crypto/hash"

const (
	HashLen = hash.HashLen
	AddrLen = hash.AddrLen
)

// Type aliases
type Hash256 = hash.Hash256
type Hash160 = hash.Hash160

// Error aliases
var ErrInvalidHashLen = hash.ErrInvalidHashLen

// Function aliases - SHA256 (256-bit)
var ComputeHash256Array = hash.ComputeHash256Array
var ComputeHash256 = hash.ComputeHash256
var ToHash256 = hash.ToHash256

// Function aliases - RIPEMD160 (160-bit)
var ComputeHash160Array = hash.ComputeHash160Array
var ComputeHash160 = hash.ComputeHash160
var ToHash160 = hash.ToHash160

// Utility functions
var Checksum = hash.Checksum
var PubkeyBytesToAddress = hash.PubkeyBytesToAddress
