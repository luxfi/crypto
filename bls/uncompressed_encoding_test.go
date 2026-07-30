// Copyright (C) 2019-2026, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"bytes"
	"testing"
)

// A G1 public key has two wire widths: PublicKeyLen compressed (x plus a sign bit) and
// 2*PublicKeyLen uncompressed (x‖y). Both must round-trip, and the two builds of this package
// — cgo and pure-Go — must agree on them, because they serialize keys that go on the wire and
// into validator registrations.
//
// The pure-Go build's PublicKeyToUncompressedBytes used to return the COMPRESSED bytes. It hid
// because both widths parse: circl's G1.SetBytes reads the compression bit and accepts either,
// so a narrowed key still verified and nothing failed until a validator set registered with
// uncompressed keys met a verifier that had narrowed them — the Hanzo 36963 halt, where no vote
// could be counted and the chain sat at one height with every other signal healthy.
func TestPublicKeyUncompressedIsActuallyUncompressed(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub := sk.PublicKey()

	compressed := PublicKeyToCompressedBytes(pub)
	uncompressed := PublicKeyToUncompressedBytes(pub)

	if len(compressed) != PublicKeyLen {
		t.Fatalf("compressed len = %d, want %d", len(compressed), PublicKeyLen)
	}
	if len(uncompressed) != 2*PublicKeyLen {
		t.Fatalf("uncompressed len = %d, want %d — a serializer must not silently return the "+
			"other width; both parse, so this is invisible until a fleet registers uncompressed keys",
			len(uncompressed), 2*PublicKeyLen)
	}
	if bytes.Equal(compressed, uncompressed) {
		t.Fatal("uncompressed bytes are identical to compressed — the function is aliasing the other encoding")
	}

	// Both widths must recover the SAME key. Parsing alone is not enough: a mis-parsed key
	// still fails Verify and strands a chain the same way a rejected one does.
	msg := []byte("canonical vote message")
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	roundTrip, err := PublicKeyFromCompressedBytes(compressed)
	if err != nil || roundTrip == nil {
		t.Fatalf("compressed: parse failed: %v", err)
	}
	if !Verify(roundTrip, sig, msg) {
		t.Error("compressed: parsed but did not verify a valid signature")
	}

	// The uncompressed form must survive the valid-bytes path, which is what a validator
	// registration carrying uncompressed keys actually goes through.
	fromUncompressed := PublicKeyFromValidUncompressedBytes(uncompressed)
	if fromUncompressed == nil {
		t.Fatal("PublicKeyFromValidUncompressedBytes rejected our own uncompressed output — " +
			"the serializer and the parser disagree about the encoding")
	}
	if !Verify(fromUncompressed, sig, msg) {
		t.Error("uncompressed: parsed but did not verify a valid signature")
	}
	if !bytes.Equal(PublicKeyToCompressedBytes(fromUncompressed), compressed) {
		t.Error("uncompressed round-trip produced a different key")
	}
}
