package verkle

import (
	"bytes"
	"testing"

	"github.com/luxfi/crypto/ipa/banderwagon"
)

func TestParseNodeEmptyPayload(t *testing.T) {
	t.Parallel()

	_, err := ParseNode([]byte{}, 0)
	if err != errSerializedPayloadTooShort {
		t.Fatalf("invalid error, got %v, expected %v", err, "unexpected EOF")
	}
}

func TestLeafStemLength(t *testing.T) {
	t.Parallel()

	// Serialize a leaf with no values, but whose stem is 32 bytes. The
	// serialization should trim the extra byte.
	toolong := make([]byte, 32)
	leaf, err := NewLeafNode(toolong, make([][]byte, NodeWidth))
	if err != nil {
		t.Fatal(err)
	}
	ser, err := leaf.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(ser) != nodeTypeSize+StemSize+bitlistSize+3*banderwagon.UncompressedSize {
		t.Fatalf("invalid serialization when the stem is longer than 31 bytes: %x (%d bytes != %d)", ser, len(ser), nodeTypeSize+StemSize+bitlistSize+2*banderwagon.UncompressedSize)
	}
}

func TestInvalidNodeEncoding(t *testing.T) {
	t.Parallel()

	// Test a short payload.
	if _, err := ParseNode([]byte{leafType}, 0); err != errSerializedPayloadTooShort {
		t.Fatalf("invalid error, got %v, expected %v", err, errSerializedPayloadTooShort)
	}

	// Test an invalid node type.
	values := make([][]byte, NodeWidth)
	values[42] = testValue
	ln, err := NewLeafNode(ffx32KeyTest, values)
	if err != nil {
		t.Fatal(err)
	}
	lnbytes, err := ln.Serialize()
	if err != nil {
		t.Fatalf("serializing leaf node: %v", err)
	}
	lnbytes[0] = 0xc0 // Change the type of the node to something invalid.
	if _, err := ParseNode(lnbytes, 0); err != ErrInvalidNodeEncoding {
		t.Fatalf("invalid error, got %v, expected %v", err, ErrInvalidNodeEncoding)
	}
}

func TestParseNodeEoA(t *testing.T) {
	// EIP-6800 EoA leaf layout (post-pack model):
	//   values[0] = basic data (version + balance + nonce + codesize packed)
	//   values[1] = code hash (must equal EmptyCodeHash for an EoA)
	//   values[2..255] = nil
	// The on-wire encoding stores only basic-data + the c1/root
	// commitments + the stem; the parser reconstructs values[1] =
	// EmptyCodeHash deterministically (see parseEoAccountNode in
	// encoding.go). values[2..255] stay nil after round-trip.
	values := make([][]byte, 256)
	values[0] = zero32[:]          // basic data (packed: version+balance+nonce+codesize)
	values[1] = EmptyCodeHash[:]   // code hash — required = EmptyCodeHash for EoA
	ln, err := NewLeafNode(ffx32KeyTest[:31], values)
	if err != nil {
		t.Fatalf("error creating leaf node: %v", err)
	}

	serialized, err := ln.Serialize()
	if err != nil {
		t.Fatalf("error serializing leaf node: %v", err)
	}

	if serialized[0] != eoAccountType {
		t.Fatalf("invalid encoding type, got %d, expected %d", serialized[0], eoAccountType)
	}

	deserialized, err := ParseNode(serialized, 5)
	if err != nil {
		t.Fatalf("error deserializing leaf node: %v", err)
	}

	lnd, ok := deserialized.(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", deserialized)
	}

	if lnd.depth != 5 {
		t.Fatalf("invalid depth, got %d, expected %d", lnd.depth, 5)
	}

	if !bytes.Equal(lnd.stem, ffx32KeyTest[:31]) {
		t.Fatalf("invalid stem, got %x, expected %x", lnd.stem, ffx32KeyTest[:31])
	}

	if !bytes.Equal(lnd.values[0], zero32[:]) {
		t.Fatalf("invalid basic data, got %x, expected %x", lnd.values[0], zero32[:])
	}

	if !bytes.Equal(lnd.values[1], EmptyCodeHash[:]) {
		t.Fatalf("invalid code hash, got %x, expected %x", lnd.values[1], EmptyCodeHash[:])
	}

	// EoA layout has values[2..255] = nil (no per-slot storage for EoA).
	for i := 2; i < 256; i++ {
		if lnd.values[i] != nil {
			t.Fatalf("value %d should be nil for EoA, got %x", i, lnd.values[i])
		}
	}

	if !lnd.c2.Equal(&banderwagon.Identity) {
		t.Fatalf("invalid c2, got %x, expected %x", lnd.c2, banderwagon.Identity)
	}

	if !lnd.c1.Equal(ln.c1) {
		t.Fatalf("invalid c1, got %x, expected %x", lnd.c1, ln.c1)
	}

	if !lnd.commitment.Equal(ln.commitment) {
		t.Fatalf("invalid commitment, got %x, expected %x", lnd.commitment, ln.commitment)
	}
}
func TestParseNodeSingleSlot(t *testing.T) {
	// Single-slot leaf: exactly one of the 256 value slots is non-nil.
	// We pick slot index 100 (< 128) so the c1 branch of parseSingleSlot
	// fires — meaning c1 is loaded from the serialized payload and
	// c2 is set to banderwagon.Identity. (For idx >= 128 the
	// branches swap; see parseSingleSlotNode in encoding.go.)
	values := make([][]byte, 256)
	values[100] = EmptyCodeHash
	ln, err := NewLeafNode(ffx32KeyTest[:31], values)
	if err != nil {
		t.Fatalf("error creating leaf node: %v", err)
	}

	serialized, err := ln.Serialize()
	if err != nil {
		t.Fatalf("error serializing leaf node: %v", err)
	}

	if serialized[0] != singleSlotType {
		t.Fatalf("invalid encoding type, got %d, expected %d", serialized[0], singleSlotType)
	}

	deserialized, err := ParseNode(serialized, 5)
	if err != nil {
		t.Fatalf("error deserializing leaf node: %v", err)
	}

	lnd, ok := deserialized.(*LeafNode)
	if !ok {
		t.Fatalf("expected leaf node, got %T", deserialized)
	}

	if lnd.depth != 5 {
		t.Fatalf("invalid depth, got %d, expected %d", lnd.depth, 5)
	}

	if !bytes.Equal(lnd.stem, ffx32KeyTest[:31]) {
		t.Fatalf("invalid stem, got %x, expected %x", lnd.stem, ffx32KeyTest[:31])
	}

	for i := range values {
		if i != 100 {
			if lnd.values[i] != nil {
				t.Fatalf("value %d, got %x, expected empty slot", i, lnd.values[i])
			}
		} else {
			if !bytes.Equal(lnd.values[i], EmptyCodeHash[:]) {
				t.Fatalf("got %x, expected empty slot", lnd.values[i])
			}
		}
	}

	if !lnd.c2.Equal(&banderwagon.Identity) {
		t.Fatalf("invalid c2, got %x, expected %x", lnd.c2, banderwagon.Identity)
	}

	if !lnd.c1.Equal(ln.c1) {
		t.Fatalf("invalid c1, got %x, expected %x", lnd.c1, ln.c1)
	}

	if !lnd.commitment.Equal(ln.commitment) {
		t.Fatalf("invalid commitment, got %x, expected %x", lnd.commitment, ln.commitment)
	}
}
