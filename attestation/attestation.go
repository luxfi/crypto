// Package attestation verifies a TEE remote-attestation quote so an operator's claim — "I run the
// expected code inside a genuine enclave that decrypts only in-boundary" — is CRYPTOGRAPHICALLY
// checkable. It closes the audit's TEE finding (the prior verifier checked only a buffer length and
// a measurement byte-compare): here a quote verifies iff (1) the attestation key's certificate
// chains to a pinned vendor root, (2) the ECDSA signature over the report is valid under that key,
// (3) the enclave measurement is on the allow-list, and (4) the report binds the operator's
// confidentiality public key. (4) is the load-bearing link to promptseal: it proves the sealed
// prompt can be opened ONLY inside the attested enclave, making delegated operation non-custodial
// end to end.
//
// The byte layout of a real Intel SGX/TDX DCAP or AMD SEV-SNP quote maps into the canonical Quote
// below (platform-specific parsers are a thin shim); this package owns the SOUNDNESS.
package attestation

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
)

// domain separates the report-signing preimage from any other signature in the stack.
var domain = []byte("hanzo/poi/tee-quote/v1")

// Quote is a canonical TEE attestation quote.
type Quote struct {
	Measurement [32]byte // MRENCLAVE / MRTD — identifies the code running in the enclave
	ReportData  [32]byte // application binding: sha256(operator confidentiality public key)
	LeafDER     []byte   // the attestation key certificate (DER); its ECDSA key signs the report
	Chain       [][]byte // intermediate certificates (DER), leaf → … → a root in the policy
	Signature   []byte   // ASN.1 ECDSA-P256 signature over signedBody(Measurement‖ReportData)
}

// Policy is what a verifier trusts: the pinned vendor root(s) and the accepted enclave measurements.
type Policy struct {
	Roots          *x509.CertPool
	AllowedMeasure map[[32]byte]bool
}

var (
	ErrChain       = errors.New("attestation: certificate chain does not verify to a pinned root")
	ErrSignature   = errors.New("attestation: report signature invalid")
	ErrMeasurement = errors.New("attestation: enclave measurement not on the allow-list")
	ErrBinding     = errors.New("attestation: report does not bind the operator's confidentiality key")
	ErrFormat      = errors.New("attestation: malformed quote")
)

// signedBody is the exact preimage the attestation key signs.
func signedBody(m, rd [32]byte) []byte {
	b := make([]byte, 0, len(domain)+64)
	b = append(b, domain...)
	b = append(b, m[:]...)
	b = append(b, rd[:]...)
	return b
}

// BindKey is the value an enclave must place in ReportData to bind a confidentiality key.
func BindKey(operatorPub []byte) [32]byte {
	return sha256.Sum256(operatorPub)
}

// Verify checks `q` against `policy` and binds it to `boundKey` (the operator's confidentiality
// public key, e.g. its promptseal key). Returns nil iff all four checks pass; a specific error
// otherwise. NO check is skipped: a quote with a valid measurement but a bad signature or an
// unpinned chain is rejected.
func Verify(q *Quote, policy *Policy, boundKey []byte) error {
	if q == nil || policy == nil || policy.Roots == nil {
		return ErrFormat
	}
	leaf, err := x509.ParseCertificate(q.LeafDER)
	if err != nil {
		return ErrFormat
	}
	// (1) the attestation key cert chains to a PINNED root.
	inter := x509.NewCertPool()
	for _, d := range q.Chain {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return ErrFormat
		}
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         policy.Roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return ErrChain
	}
	// (2) the report SIGNATURE verifies under the attestation key.
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrFormat
	}
	digest := sha256.Sum256(signedBody(q.Measurement, q.ReportData))
	if !ecdsa.VerifyASN1(pub, digest[:], q.Signature) {
		return ErrSignature
	}
	// (3) the enclave MEASUREMENT is accepted (the enclave runs the expected code).
	if !policy.AllowedMeasure[q.Measurement] {
		return ErrMeasurement
	}
	// (4) the report BINDS the operator's confidentiality key — so only this attested enclave can
	//     open prompts sealed to that key.
	if q.ReportData != BindKey(boundKey) {
		return ErrBinding
	}
	return nil
}
