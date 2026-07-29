package lamport

import (
	"bytes"
	"crypto/sha3"
	"testing"
)

func TestLamportHashFuncConstants(t *testing.T) {
	if SHA256 != HashFunc(0) {
		t.Error("SHA256 hash function constant mismatch")
	}
	if SHA512 != HashFunc(1) {
		t.Error("SHA512 hash function constant mismatch")
	}
	if SHA3_256 != HashFunc(2) {
		t.Error("SHA3_256 hash function constant mismatch")
	}
	if SHA3_512 != HashFunc(3) {
		t.Error("SHA3_512 hash function constant mismatch")
	}
}

func TestLamportSignVerifySHA256(t *testing.T) {
	priv, err := GenerateKey(nil, SHA256)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pub := priv.Public()
	msg := []byte("test message for lamport signature")

	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !pub.Verify(msg, sig) {
		t.Error("valid signature failed verification")
	}

	// Verify with wrong message should fail
	if pub.Verify([]byte("wrong message"), sig) {
		t.Error("signature verified with wrong message")
	}
}

func TestLamportSignVerifySHA512(t *testing.T) {
	priv, err := GenerateKey(nil, SHA512)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pub := priv.Public()
	msg := []byte("test message for SHA512 lamport")

	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !pub.Verify(msg, sig) {
		t.Error("valid SHA512 signature failed verification")
	}
}

func TestLamportSerialization(t *testing.T) {
	priv, err := GenerateKey(nil, SHA256)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pub := priv.Public()

	// Serialize and deserialize public key
	pubBytes := pub.Bytes()
	pub2, err := PublicKeyFromBytes(pubBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}

	msg := []byte("serialization test")
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Deserialized public key should verify
	if !pub2.Verify(msg, sig) {
		t.Error("deserialized public key failed to verify signature")
	}

	// Serialize and deserialize signature
	sigBytes := sig.Bytes()
	sig2, err := SignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatalf("SignatureFromBytes failed: %v", err)
	}

	if !pub.Verify(msg, sig2) {
		t.Error("deserialized signature failed verification")
	}
}

func TestLamportOneTimeProperty(t *testing.T) {
	priv, err := GenerateKey(nil, SHA256)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	pub := priv.Public()

	// First sign should work
	sig, err := priv.Sign([]byte("first message"))
	if err != nil {
		t.Fatalf("First Sign failed: %v", err)
	}

	if !pub.Verify([]byte("first message"), sig) {
		t.Error("first signature failed verification")
	}

	// Second sign should produce invalid signature (key was zeroed)
	sig2, err := priv.Sign([]byte("second message"))
	if err != nil {
		t.Fatalf("Second Sign failed: %v", err)
	}

	// The second signature should NOT verify against the original public key
	// because the private key was zeroed after first use
	if pub.Verify([]byte("second message"), sig2) {
		t.Error("signature after key destruction should not verify")
	}
}

func BenchmarkLamportSignSHA256(b *testing.B) {
	msg := []byte("benchmark message")
	for i := 0; i < b.N; i++ {
		priv, _ := GenerateKey(nil, SHA256)
		priv.Sign(msg)
	}
}

func BenchmarkLamportVerifySHA256(b *testing.B) {
	priv, _ := GenerateKey(nil, SHA256)
	pub := priv.Public()
	msg := []byte("benchmark message")
	sig, _ := priv.Sign(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub.Verify(msg, sig)
	}
}

// TestSHA3ModesAreActuallySHA3 pins the fix for a defect that was invisible from
// outside: the SHA3_256 and SHA3_512 modes returned sha256.New() and
// sha512.New(), with a comment saying a real import would come later. Keys and
// signatures produced under those modes were SHA-2, so a verifier reading the
// mode field and using real SHA-3 would reject every one of them — and two
// implementations that agreed on the label disagreed on the bytes.
//
// The test compares against the standard library directly rather than against
// a captured vector: a captured vector would have frozen whatever the code did.
func TestSHA3ModesAreActuallySHA3(t *testing.T) {
	msg := []byte("lamport sha3 mode must be sha3")

	for _, tc := range []struct {
		name string
		mode HashFunc
		want func([]byte) []byte
	}{
		{"SHA3_256", SHA3_256, func(b []byte) []byte { h := sha3.New256(); h.Write(b); return h.Sum(nil) }},
		{"SHA3_512", SHA3_512, func(b []byte) []byte { h := sha3.New512(); h.Write(b); return h.Sum(nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := getHasher(tc.mode)
			h.Write(msg)
			got := h.Sum(nil)
			if !bytes.Equal(got, tc.want(msg)) {
				t.Fatalf("%s does not hash with SHA-3", tc.name)
			}
			// And it must differ from the SHA-2 it used to silently return.
			s2 := getHasher(map[HashFunc]HashFunc{SHA3_256: SHA256, SHA3_512: SHA512}[tc.mode])
			s2.Write(msg)
			if bytes.Equal(got, s2.Sum(nil)) {
				t.Fatalf("%s produced the SHA-2 digest — the silent fallback is back", tc.name)
			}
		})
	}
}
