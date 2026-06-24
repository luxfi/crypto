package promptseal

import (
	"bytes"
	"testing"
)

func TestSealRoundTrip(t *testing.T) {
	pub, priv, err := GenerateOperatorKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	prompt := []byte("what is the airspeed velocity of an unladen swallow?")
	aad := []byte("intent:0xabc123")
	sealed, err := SealPrompt(pub, prompt, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := OpenPrompt(priv, sealed, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, prompt) {
		t.Fatal("round-trip mismatch")
	}
}

// ADVERSARIAL: a different operator (or any third party) cannot open a prompt sealed to someone else.
func TestWrongKeyCannotOpen(t *testing.T) {
	pubA, _, _ := GenerateOperatorKey()
	_, privB, _ := GenerateOperatorKey() // a DIFFERENT operator
	sealed, err := SealPrompt(pubA, []byte("secret prompt"), []byte("ctx"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := OpenPrompt(privB, sealed, []byte("ctx")); err == nil {
		t.Fatal("a non-recipient operator must NOT be able to open the prompt")
	}
}

// ADVERSARIAL: flipping any ciphertext byte makes Open fail (AEAD integrity).
func TestTamperedCiphertextRejected(t *testing.T) {
	pub, priv, _ := GenerateOperatorKey()
	sealed, _ := SealPrompt(pub, []byte("integrity matters"), []byte("ctx"))
	for _, i := range []int{0, len(sealed) / 2, len(sealed) - 1} {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0x01
		if _, err := OpenPrompt(priv, bad, []byte("ctx")); err == nil {
			t.Fatalf("a tampered byte at %d must be rejected", i)
		}
	}
}

// ADVERSARIAL: the aad binds context — opening under a different aad (a replay to another request)
// fails authentication.
func TestWrongAADRejected(t *testing.T) {
	pub, priv, _ := GenerateOperatorKey()
	sealed, _ := SealPrompt(pub, []byte("bound to intent A"), []byte("intent:A"))
	if _, err := OpenPrompt(priv, sealed, []byte("intent:B")); err == nil {
		t.Fatal("a sealed prompt must not open under a different aad (no cross-request replay)")
	}
}

// ADVERSARIAL: a passive observer learns nothing. The sealed blob does not contain the plaintext,
// and two seals of the SAME prompt differ (semantic security / fresh ephemeral key each time).
func TestObserverLearnsNothing(t *testing.T) {
	pub, _, _ := GenerateOperatorKey()
	prompt := []byte("a very distinctive plaintext marker XYZZY")
	s1, _ := SealPrompt(pub, prompt, []byte("ctx"))
	s2, _ := SealPrompt(pub, prompt, []byte("ctx"))
	if bytes.Contains(s1, prompt) {
		t.Fatal("the sealed blob must not contain the plaintext")
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("two seals of the same prompt must differ (semantic security)")
	}
}

func TestMalformedKeyRejected(t *testing.T) {
	pub, _, _ := GenerateOperatorKey()
	if _, err := SealPrompt([]byte{1, 2, 3}, []byte("x"), nil); err == nil {
		t.Fatal("a malformed operator public key must be rejected")
	}
	sealed, _ := SealPrompt(pub, []byte("x"), nil)
	if _, err := OpenPrompt([]byte{1, 2, 3}, sealed, nil); err == nil {
		t.Fatal("a malformed operator private key must be rejected")
	}
}
