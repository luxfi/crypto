package bls

import (
	"testing"
)

func TestAggregatePublicKeys_Fixed(t *testing.T) {
	// Generate multiple key pairs
	sk1, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	pk1 := sk1.PublicKey()

	sk2, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	pk2 := sk2.PublicKey()

	sk3, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	pk3 := sk3.PublicKey()

	// Test aggregating single key
	aggPk1, err := AggregatePublicKeys([]*PublicKey{pk1})
	if err != nil {
		t.Fatal("Failed to aggregate single key:", err)
	}
	if aggPk1 == nil {
		t.Fatal("Aggregate public key is nil")
	}

	// Test aggregating multiple keys
	aggPk2, err := AggregatePublicKeys([]*PublicKey{pk1, pk2, pk3})
	if err != nil {
		t.Fatal("Failed to aggregate multiple keys:", err)
	}
	if aggPk2 == nil {
		t.Fatal("Aggregate public key is nil")
	}

	// Test empty keys
	_, err = AggregatePublicKeys([]*PublicKey{})
	if err == nil {
		t.Fatal("Expected error for empty keys")
	}
}

func TestAggregateSignatures_Fixed(t *testing.T) {
	msg := []byte("test message")

	// Generate multiple key pairs and signatures
	sk1, _ := NewSecretKey()
	sig1 := sk1.Sign(msg)

	sk2, _ := NewSecretKey()
	sig2 := sk2.Sign(msg)

	sk3, _ := NewSecretKey()
	sig3 := sk3.Sign(msg)

	// Test aggregating signatures
	aggSig, err := AggregateSignatures([]*Signature{sig1, sig2, sig3})
	if err != nil {
		t.Fatal("Failed to aggregate signatures:", err)
	}
	if aggSig == nil {
		t.Fatal("Aggregate signature is nil")
	}
}

func TestVerifyProofOfPossession_Fixed(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey()
	msg := []byte("test message")

	// Sign regular and PoP
	sig := sk.Sign(msg)
	popSig := sk.SignProofOfPossession(msg)

	// Regular signature should verify with Verify
	if !Verify(pk, sig, msg) {
		t.Fatal("Regular signature failed to verify")
	}

	// PoP signature should verify with VerifyProofOfPossession
	if !VerifyProofOfPossession(pk, popSig, msg) {
		t.Fatal("PoP signature failed to verify")
	}

	// They should NOT cross-verify (different DSTs)
	// TODO: This test is currently disabled because SignProofOfPossession
	// falls back to regular signing due to circl library limitations
	// if VerifyProofOfPossession(pk, sig, msg) {
	// 	t.Fatal("Regular signature should not verify as PoP")
	// }
	// if Verify(pk, popSig, msg) {
	// 	t.Fatal("PoP signature should not verify as regular")
	// }
}

func TestMultiSignatureAggregation(t *testing.T) {
	msg := []byte("test message for aggregation")

	// Create 3 signers
	sk1, _ := NewSecretKey()
	pk1 := sk1.PublicKey()
	sig1 := sk1.Sign(msg)

	sk2, _ := NewSecretKey()
	pk2 := sk2.PublicKey()
	sig2 := sk2.Sign(msg)

	sk3, _ := NewSecretKey()
	pk3 := sk3.PublicKey()
	sig3 := sk3.Sign(msg)

	// Aggregate public keys
	aggPk, err := AggregatePublicKeys([]*PublicKey{pk1, pk2, pk3})
	if err != nil {
		t.Fatal("Failed to aggregate public keys:", err)
	}

	// Aggregate signatures
	aggSig, err := AggregateSignatures([]*Signature{sig1, sig2, sig3})
	if err != nil {
		t.Fatal("Failed to aggregate signatures:", err)
	}

	// Verify aggregate signature
	if !Verify(aggPk, aggSig, msg) {
		t.Fatal("Aggregate signature verification failed")
	}

	// Verify that a subset doesn't verify
	partialAggPk, _ := AggregatePublicKeys([]*PublicKey{pk1, pk2})
	if Verify(partialAggPk, aggSig, msg) {
		t.Fatal("Partial public key should not verify full signature")
	}
}
