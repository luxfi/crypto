// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package kats

// Vector is one Known-Answer-Test record. Every field is the
// canonical FIPS 204 wire encoding of the value (Seed = 32-byte ξ;
// PublicKey, PrivateKey, Signature = mldsaXX wire bytes; Msg, Ctx
// = arbitrary byte slices).
type Vector struct {
	// Count is the vector index within its parameter-set slice;
	// surfaced in test failure messages so a diff is easy to pin.
	Count int
	// Seed is the 32-byte ξ fed to NewKeyFromSeed.
	Seed []byte
	// Msg is the message bytes passed to Sign / Verify.
	Msg []byte
	// Ctx is the domain-separation context. May be empty.
	Ctx []byte
	// PublicKey is the expected mldsaXX.PublicKey.Bytes() output.
	PublicKey []byte
	// PrivateKey is the expected mldsaXX.PrivateKey.Bytes() output.
	PrivateKey []byte
	// Signature is the expected deterministic
	// mldsaXX.Sign(sk, Msg, Ctx, false) output.
	Signature []byte
}
