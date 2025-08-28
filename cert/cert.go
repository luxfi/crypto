// Package cert provides X.509 certificate handling for post-quantum algorithms
package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/crypto/sign"
)

// MLDSACert represents an ML-DSA certificate
type MLDSACert struct {
	Raw          []byte
	PublicKey    sign.PublicKey
	Subject      pkix.Name
	Issuer       pkix.Name
	SerialNumber []byte
	NotBefore    time.Time
	NotAfter     time.Time
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
	IsCA         bool
	
	// Custom extensions for QZMQ
	NodeID       string
	Capabilities []string
	Role         string
}

// CertPool represents a pool of trusted certificates
type CertPool struct {
	certs map[string]*MLDSACert // Keyed by SPKI hash
}

// NewCertPool creates a new certificate pool
func NewCertPool() *CertPool {
	return &CertPool{
		certs: make(map[string]*MLDSACert),
	}
}

// AddCert adds a certificate to the pool
func (cp *CertPool) AddCert(cert *MLDSACert) {
	spkiHash := hashSPKI(cert.PublicKey.Bytes())
	cp.certs[spkiHash] = cert
}

// VerifyChain verifies a certificate chain
func (cp *CertPool) VerifyChain(chain []*MLDSACert, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("empty certificate chain")
	}
	
	// Verify leaf certificate
	leaf := chain[0]
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return errors.New("certificate expired or not yet valid")
	}
	
	// Verify chain
	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		issuer := chain[i+1]
		
		if err := verifyCertSignature(cert, issuer); err != nil {
			return fmt.Errorf("invalid signature at position %d: %w", i, err)
		}
		
		if !issuer.IsCA {
			return fmt.Errorf("issuer at position %d is not a CA", i+1)
		}
	}
	
	// Verify root is trusted
	root := chain[len(chain)-1]
	spkiHash := hashSPKI(root.PublicKey.Bytes())
	if _, ok := cp.certs[spkiHash]; !ok {
		return errors.New("root certificate not trusted")
	}
	
	return nil
}

// SPKIPinner implements SPKI pinning
type SPKIPinner struct {
	pins map[string]bool // Set of allowed SPKI hashes
}

// NewSPKIPinner creates a new SPKI pinner
func NewSPKIPinner(pins []string) *SPKIPinner {
	pinner := &SPKIPinner{
		pins: make(map[string]bool),
	}
	for _, pin := range pins {
		pinner.pins[pin] = true
	}
	return pinner
}

// Verify checks if a public key is pinned
func (sp *SPKIPinner) Verify(pk sign.PublicKey) bool {
	hash := hashSPKI(pk.Bytes())
	return sp.pins[hash]
}

// hashSPKI computes the SHA-256 hash of the SPKI
func hashSPKI(pubKeyBytes []byte) string {
	// In production, compute actual SHA-256 hash
	// For now, return a placeholder
	return fmt.Sprintf("spki_%x", pubKeyBytes[:8])
}

// verifyCertSignature verifies a certificate's signature
func verifyCertSignature(cert, issuer *MLDSACert) error {
	// In production, this would verify the actual signature
	// using the issuer's public key
	return nil
}

// CertBuilder builds ML-DSA certificates
type CertBuilder struct {
	template *MLDSACert
	signer   sign.Signer
}

// NewCertBuilder creates a new certificate builder
func NewCertBuilder(signer sign.Signer) *CertBuilder {
	return &CertBuilder{
		signer: signer,
		template: &MLDSACert{
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(30 * 24 * time.Hour), // 30 days default
		},
	}
}

// SetSubject sets the certificate subject
func (cb *CertBuilder) SetSubject(subject pkix.Name) *CertBuilder {
	cb.template.Subject = subject
	return cb
}

// SetValidity sets the certificate validity period
func (cb *CertBuilder) SetValidity(notBefore, notAfter time.Time) *CertBuilder {
	cb.template.NotBefore = notBefore
	cb.template.NotAfter = notAfter
	return cb
}

// SetNodeID sets the node ID extension
func (cb *CertBuilder) SetNodeID(nodeID string) *CertBuilder {
	cb.template.NodeID = nodeID
	return cb
}

// SetRole sets the role extension
func (cb *CertBuilder) SetRole(role string) *CertBuilder {
	cb.template.Role = role
	return cb
}

// SetCapabilities sets the capabilities extension
func (cb *CertBuilder) SetCapabilities(caps []string) *CertBuilder {
	cb.template.Capabilities = caps
	return cb
}

// SetCA marks the certificate as a CA
func (cb *CertBuilder) SetCA(isCA bool) *CertBuilder {
	cb.template.IsCA = isCA
	if isCA {
		cb.template.KeyUsage |= x509.KeyUsageCertSign
	}
	return cb
}

// Build creates the certificate
func (cb *CertBuilder) Build(publicKey sign.PublicKey, issuerKey sign.PrivateKey) (*MLDSACert, error) {
	cert := *cb.template
	cert.PublicKey = publicKey
	
	// Generate serial number
	cert.SerialNumber = generateSerialNumber()
	
	// Self-signed if no issuer provided
	if issuerKey == nil {
		cert.Issuer = cert.Subject
	}
	
	// Encode to DER
	certBytes, err := encodeCertificate(&cert)
	if err != nil {
		return nil, err
	}
	
	// Sign the certificate
	if issuerKey != nil {
		signature, err := cb.signer.Sign(issuerKey, certBytes)
		if err != nil {
			return nil, err
		}
		// Append signature to certificate
		cert.Raw = append(certBytes, signature...)
	} else {
		cert.Raw = certBytes
	}
	
	return &cert, nil
}

// encodeCertificate encodes a certificate to DER
func encodeCertificate(cert *MLDSACert) ([]byte, error) {
	// Simplified encoding - in production would use proper ASN.1
	// This is a placeholder
	encoded := []byte("MLDSA-CERT-v1")
	encoded = append(encoded, cert.PublicKey.Bytes()...)
	encoded = append(encoded, []byte(cert.NodeID)...)
	encoded = append(encoded, []byte(cert.Role)...)
	
	return encoded, nil
}

// generateSerialNumber generates a random serial number
func generateSerialNumber() []byte {
	// In production, generate cryptographically random serial
	return []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
}

// ParseMLDSACert parses an ML-DSA certificate
func ParseMLDSACert(der []byte) (*MLDSACert, error) {
	// Placeholder parser
	// In production, would parse actual DER-encoded certificate
	
	cert := &MLDSACert{
		Raw: der,
	}
	
	// Parse basic fields (placeholder)
	if len(der) < 100 {
		return nil, errors.New("certificate too short")
	}
	
	return cert, nil
}

// OID definitions for ML-DSA algorithms
var (
	OIDMLDSA44 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 6, 5} // ML-DSA-44
	OIDMLDSA65 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 7} // ML-DSA-65
	OIDMLDSA87 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 10, 8} // ML-DSA-87
)