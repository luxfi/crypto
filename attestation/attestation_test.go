package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// genCA makes a self-signed ECDSA-P256 root CA.
func genCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

// genLeaf makes an attestation-key leaf cert signed by the root.
func genLeaf(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "attestation-key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func makeQuote(attestKey *ecdsa.PrivateKey, leafDER []byte, m [32]byte, operatorPub []byte) *Quote {
	rd := BindKey(operatorPub)
	digest := sha256.Sum256(signedBody(m, rd))
	sig, _ := ecdsa.SignASN1(rand.Reader, attestKey, digest[:])
	return &Quote{Measurement: m, ReportData: rd, LeafDER: leafDER, Signature: sig}
}

// the happy path: a genuine quote from an enclave running allow-listed code, bound to the operator's
// confidentiality key, verifies.
func TestVerify_GenuineQuote(t *testing.T) {
	root, rootKey := genCA(t, "vendor-root")
	attestKey, leafDER := genLeaf(t, root, rootKey)
	measurement := sha256.Sum256([]byte("the expected enclave image"))
	operatorPub := []byte("operator-confidentiality-pubkey")

	roots := x509.NewCertPool()
	roots.AddCert(root)
	policy := &Policy{Roots: roots, AllowedMeasure: map[[32]byte]bool{measurement: true}}

	q := makeQuote(attestKey, leafDER, measurement, operatorPub)
	if err := Verify(q, policy, operatorPub); err != nil {
		t.Fatalf("a genuine quote must verify, got %v", err)
	}
}

// ADVERSARIAL: a forged signature is rejected (the prior stub didn't check this at all).
func TestVerify_BadSignatureRejected(t *testing.T) {
	root, rootKey := genCA(t, "vendor-root")
	attestKey, leafDER := genLeaf(t, root, rootKey)
	m := sha256.Sum256([]byte("img"))
	op := []byte("opkey")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	policy := &Policy{Roots: roots, AllowedMeasure: map[[32]byte]bool{m: true}}

	q := makeQuote(attestKey, leafDER, m, op)
	q.Signature[len(q.Signature)-1] ^= 0x01 // flip a signature byte
	if err := Verify(q, policy, op); err != ErrSignature {
		t.Fatalf("a tampered signature must be ErrSignature, got %v", err)
	}
}

// ADVERSARIAL — THE KEY ONE: an attacker mints a perfectly-formed quote (own root, valid sig,
// correct measurement, correct binding), but its root is NOT the pinned vendor root → rejected.
func TestVerify_UnpinnedRootRejected(t *testing.T) {
	pinnedRoot, _ := genCA(t, "vendor-root")
	attackerRoot, attackerKey := genCA(t, "attacker-root")
	attestKey, leafDER := genLeaf(t, attackerRoot, attackerKey) // chains to the ATTACKER root
	m := sha256.Sum256([]byte("img"))
	op := []byte("opkey")

	roots := x509.NewCertPool()
	roots.AddCert(pinnedRoot) // only the genuine vendor root is pinned
	policy := &Policy{Roots: roots, AllowedMeasure: map[[32]byte]bool{m: true}}

	q := makeQuote(attestKey, leafDER, m, op)
	if err := Verify(q, policy, op); err != ErrChain {
		t.Fatalf("a quote not chaining to a pinned root must be ErrChain, got %v", err)
	}
}

// ADVERSARIAL: a genuine quote for a DIFFERENT (not allow-listed) enclave image is rejected — the
// operator cannot swap in unattested code.
func TestVerify_WrongMeasurementRejected(t *testing.T) {
	root, rootKey := genCA(t, "vendor-root")
	attestKey, leafDER := genLeaf(t, root, rootKey)
	expected := sha256.Sum256([]byte("expected"))
	actual := sha256.Sum256([]byte("some other code")) // validly signed, but not allow-listed
	op := []byte("opkey")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	policy := &Policy{Roots: roots, AllowedMeasure: map[[32]byte]bool{expected: true}}

	q := makeQuote(attestKey, leafDER, actual, op)
	if err := Verify(q, policy, op); err != ErrMeasurement {
		t.Fatalf("a non-allow-listed measurement must be ErrMeasurement, got %v", err)
	}
}

// ADVERSARIAL: a genuine quote that binds operator A's key cannot vouch for operator B — so a sealed
// prompt for A cannot be opened by an enclave attested for B.
func TestVerify_UnboundKeyRejected(t *testing.T) {
	root, rootKey := genCA(t, "vendor-root")
	attestKey, leafDER := genLeaf(t, root, rootKey)
	m := sha256.Sum256([]byte("img"))
	roots := x509.NewCertPool()
	roots.AddCert(root)
	policy := &Policy{Roots: roots, AllowedMeasure: map[[32]byte]bool{m: true}}

	q := makeQuote(attestKey, leafDER, m, []byte("operator-A-key"))
	if err := Verify(q, policy, []byte("operator-B-key")); err != ErrBinding {
		t.Fatalf("a quote bound to a different key must be ErrBinding, got %v", err)
	}
}

// ADVERSARIAL: tampering the measurement after signing breaks the signature (you cannot keep a valid
// sig while changing what was attested).
func TestVerify_TamperedMeasurementBreaksSignature(t *testing.T) {
	root, rootKey := genCA(t, "vendor-root")
	attestKey, leafDER := genLeaf(t, root, rootKey)
	m := sha256.Sum256([]byte("img"))
	op := []byte("opkey")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	policy := &Policy{Roots: roots, AllowedMeasure: map[[32]byte]bool{m: true, {}: true}}

	q := makeQuote(attestKey, leafDER, m, op)
	q.Measurement = [32]byte{} // change the attested code after signing
	if err := Verify(q, policy, op); err != ErrSignature {
		t.Fatalf("changing the measurement after signing must be ErrSignature, got %v", err)
	}
}
