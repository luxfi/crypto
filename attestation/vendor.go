package attestation

// vendor.go — byte-layout parsers for the three production TEE quote formats: Intel SGX (DCAP v3),
// Intel TDX (DCAP v4), and AMD SEV-SNP. Each parser decodes the documented binary structure into the
// canonical fields (measurement, report data, the signed region, the attestation signature, and the
// embedded certificate chain) and verifies them: the attestation signature over the exact signed
// bytes, the certificate chain to a PINNED vendor root, the measurement allow-list, and the binding
// of the operator's confidentiality key in the report data. This is the real wire format the audit's
// stub never parsed.
//
// Offsets are from the Intel SGX/TDX DCAP quote spec and the AMD SEV-SNP firmware ABI. Signature
// scalars in these quotes are raw big-endian r‖s; we re-encode to ASN.1 for crypto/ecdsa. SGX/TDX
// use ECDSA-P256 over SHA-256; SEV-SNP uses ECDSA-P384 over SHA-384.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"hash"
	"math/big"
)

const (
	VendorSGX = "sgx"
	VendorTDX = "tdx"
	VendorSNP = "sev-snp"
)

var ErrQuoteLayout = errors.New("attestation: quote shorter than its declared layout")

// rawSigToASN1 re-encodes a fixed-width big-endian r‖s pair into the ASN.1 SEQUENCE crypto/ecdsa wants.
func rawSigToASN1(rs []byte) ([]byte, error) {
	if len(rs)%2 != 0 || len(rs) == 0 {
		return nil, ErrQuoteLayout
	}
	half := len(rs) / 2
	r := new(big.Int).SetBytes(rs[:half])
	s := new(big.Int).SetBytes(rs[half:])
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// chainTo verifies a leaf DER cert chains through `inter` DERs to a root in `roots`.
func chainTo(leafDER []byte, interDER [][]byte, roots *x509.CertPool) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, ErrFormat
	}
	inter := x509.NewCertPool()
	for _, d := range interDER {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, ErrFormat
		}
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, ErrChain
	}
	return leaf, nil
}

// --- Intel SGX DCAP v3 ----------------------------------------------------------------------------
//
// Layout: Header(48) ‖ ReportBody(384) ‖ sigDataLen(4) ‖ sigData.
//
//	Header:      version u16le @0; tee_type u32le @4 (0 = SGX).
//	ReportBody:  mr_enclave[32] @ +64; report_data[64] @ +320.   (absolute @112 and @368)
//	sigData:     quoteSig[64] (r‖s) ‖ attestPub[64] (raw P256 point) ‖ qeReport[384] ‖
//	             qeReportSig[64] ‖ authDataLen u16 ‖ authData ‖ certDataType u16 ‖ certDataLen u32 ‖
//	             certData(PEM PCK chain).
//
// Trust: attestPub signs Header‖ReportBody (the quote); attestPub is bound in qeReport.report_data
//
//	= sha256(attestPub ‖ authData); the PCK leaf (from certData) signs qeReport and chains to the
//	pinned Intel SGX root.
const (
	sgxHeaderLen = 48
	sgxBodyLen   = 384
	sgxMREnclave = sgxHeaderLen + 64             // 112
	sgxReportDat = sgxHeaderLen + 320            // 368
	sgxSigOff    = sgxHeaderLen + sgxBodyLen + 4 // 436
)

// VerifySGX parses and verifies an Intel SGX DCAP quote, returning the verified MRENCLAVE.
func VerifySGX(raw []byte, roots *x509.CertPool, allowed map[[32]byte]bool, boundKey []byte) ([]byte, error) {
	if len(raw) < sgxSigOff+64+64+sgxBodyLen+64+2 {
		return nil, ErrQuoteLayout
	}
	if binary.LittleEndian.Uint16(raw[0:2]) != 3 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		return nil, errors.New("attestation: not an SGX v3 quote")
	}
	mr := raw[sgxMREnclave : sgxMREnclave+32]
	reportData := raw[sgxReportDat : sgxReportDat+64]
	signedRegion := raw[:sgxHeaderLen+sgxBodyLen] // header ‖ report body

	p := sgxSigOff
	quoteSig := raw[p : p+64]
	attestPub := raw[p+64 : p+128]
	qeReport := raw[p+128 : p+128+sgxBodyLen]
	rest := raw[p+128+sgxBodyLen:]
	qeReportSig := rest[:64]
	authLen := int(binary.LittleEndian.Uint16(rest[64:66]))
	if len(rest) < 66+authLen+6 {
		return nil, ErrQuoteLayout
	}
	authData := rest[66 : 66+authLen]
	cd := rest[66+authLen:]
	// certData: type u16 ‖ len u32 ‖ data
	certLen := int(binary.LittleEndian.Uint32(cd[2:6]))
	if len(cd) < 6+certLen {
		return nil, ErrQuoteLayout
	}
	pckChain := splitPEMChain(cd[6 : 6+certLen])
	if len(pckChain) == 0 {
		return nil, ErrFormat
	}

	// (a) PCK leaf chains to the pinned Intel root, and signs the QE report.
	pckLeaf, err := chainTo(pckChain[0], pckChain[1:], roots)
	if err != nil {
		return nil, err
	}
	if err := ecdsaVerifyRaw(pckLeaf, sha256.New, qeReport, qeReportSig); err != nil {
		return nil, ErrSignature
	}
	// (b) the attestation key is bound in the QE report: report_data = sha256(attestPub ‖ authData).
	want := sha256.Sum256(append(append([]byte(nil), attestPub...), authData...))
	if !equalFixed(qeReport[320:352], want[:]) {
		return nil, errors.New("attestation: attestation key not bound in QE report")
	}
	// (c) the attestation key signs the quote (header ‖ report body).
	if err := ecdsaVerifyRawKey(attestPub, sha256.New, signedRegion, quoteSig); err != nil {
		return nil, ErrSignature
	}
	// (d) policy: measurement allow-list + operator-key binding (report_data[0:32]).
	var m32 [32]byte
	copy(m32[:], mr)
	if !allowed[m32] {
		return nil, ErrMeasurement
	}
	if !bindsKey(reportData, boundKey) {
		return nil, ErrBinding
	}
	return mr, nil
}

// --- Intel TDX DCAP v4 ----------------------------------------------------------------------------
//
// Layout: Header(48) ‖ TDReport(584) ‖ sigDataLen(4) ‖ sigData (same sigData shape as SGX).
//
//	Header:    version u16le @0 (=4); tee_type u32le @4 (=0x81 for TDX).
//	TDReport:  mr_td[48] @ +136; report_data[64] @ +520.   (absolute @184 and @568)
const (
	tdxHeaderLen = 48
	tdxBodyLen   = 584
	tdxMRTD      = tdxHeaderLen + 136 // 184
	tdxReportDat = tdxHeaderLen + 520 // 568
	tdxSigOff    = tdxHeaderLen + tdxBodyLen + 4
)

// VerifyTDX parses and verifies an Intel TDX DCAP quote, returning the verified MRTD.
func VerifyTDX(raw []byte, roots *x509.CertPool, allowed map[[48]byte]bool, boundKey []byte) ([]byte, error) {
	if len(raw) < tdxSigOff+64+64+sgxBodyLen+64+2 {
		return nil, ErrQuoteLayout
	}
	if binary.LittleEndian.Uint16(raw[0:2]) != 4 || binary.LittleEndian.Uint32(raw[4:8]) != 0x81 {
		return nil, errors.New("attestation: not a TDX v4 quote")
	}
	mr := raw[tdxMRTD : tdxMRTD+48]
	reportData := raw[tdxReportDat : tdxReportDat+64]
	signedRegion := raw[:tdxHeaderLen+tdxBodyLen]

	p := tdxSigOff
	quoteSig := raw[p : p+64]
	attestPub := raw[p+64 : p+128]
	qeReport := raw[p+128 : p+128+sgxBodyLen]
	rest := raw[p+128+sgxBodyLen:]
	qeReportSig := rest[:64]
	authLen := int(binary.LittleEndian.Uint16(rest[64:66]))
	if len(rest) < 66+authLen+6 {
		return nil, ErrQuoteLayout
	}
	authData := rest[66 : 66+authLen]
	cd := rest[66+authLen:]
	certLen := int(binary.LittleEndian.Uint32(cd[2:6]))
	if len(cd) < 6+certLen {
		return nil, ErrQuoteLayout
	}
	pckChain := splitPEMChain(cd[6 : 6+certLen])
	if len(pckChain) == 0 {
		return nil, ErrFormat
	}
	pckLeaf, err := chainTo(pckChain[0], pckChain[1:], roots)
	if err != nil {
		return nil, err
	}
	if err := ecdsaVerifyRaw(pckLeaf, sha256.New, qeReport, qeReportSig); err != nil {
		return nil, ErrSignature
	}
	want := sha256.Sum256(append(append([]byte(nil), attestPub...), authData...))
	if !equalFixed(qeReport[320:352], want[:]) {
		return nil, errors.New("attestation: attestation key not bound in QE report")
	}
	if err := ecdsaVerifyRawKey(attestPub, sha256.New, signedRegion, quoteSig); err != nil {
		return nil, ErrSignature
	}
	var m48 [48]byte
	copy(m48[:], mr)
	if !allowed[m48] {
		return nil, ErrMeasurement
	}
	if !bindsKey(reportData, boundKey) {
		return nil, ErrBinding
	}
	return mr, nil
}

// --- AMD SEV-SNP ----------------------------------------------------------------------------------
//
// Layout: attestation_report (1184 bytes). report_data[64] @0x50; measurement[48] @0x90;
//
//	signature @0x2A0 (ECDSA-P384: r[72]‖s[72], little-endian, zero-padded). The VCEK (P-384) signs
//	report[0:0x2A0]; the VCEK cert chains to the pinned AMD ARK/ASK (supplied out of band).
const (
	snpReportLen  = 1184
	snpReportData = 0x50  // 80
	snpMeasure    = 0x90  // 144
	snpSigOff     = 0x2A0 // 672
	snpSigComp    = 72    // r and s are each 72 bytes, little-endian
)

// VerifySNP parses and verifies an AMD SEV-SNP attestation report. `vcekDER` is the VCEK leaf cert
// (fetched from the AMD KDS); it must chain to a pinned AMD root in `roots`. Returns the measurement.
func VerifySNP(raw, vcekDER []byte, askDER [][]byte, roots *x509.CertPool, allowed map[[48]byte]bool, boundKey []byte) ([]byte, error) {
	if len(raw) < snpReportLen {
		return nil, ErrQuoteLayout
	}
	mr := raw[snpMeasure : snpMeasure+48]
	reportData := raw[snpReportData : snpReportData+64]
	signedRegion := raw[:snpSigOff]

	// SNP stores r,s little-endian; convert to big-endian for ASN.1.
	rLE := raw[snpSigOff : snpSigOff+snpSigComp]
	sLE := raw[snpSigOff+snpSigComp : snpSigOff+2*snpSigComp]
	sigASN1, err := asn1.Marshal(struct{ R, S *big.Int }{leUint(rLE), leUint(sLE)})
	if err != nil {
		return nil, ErrFormat
	}

	vcek, err := chainTo(vcekDER, askDER, roots)
	if err != nil {
		return nil, err
	}
	if err := ecdsaVerifyASN1(vcek, sha512.New384, signedRegion, sigASN1); err != nil {
		return nil, ErrSignature
	}
	var m48 [48]byte
	copy(m48[:], mr)
	if !allowed[m48] {
		return nil, ErrMeasurement
	}
	if !bindsKey(reportData, boundKey) {
		return nil, ErrBinding
	}
	return mr, nil
}

// --- shared helpers -------------------------------------------------------------------------------

// bindsKey reports whether the report data's first 32 bytes are sha256(key) — the operator binding.
func bindsKey(reportData, key []byte) bool {
	bk := BindKey(key)
	return equalFixed(reportData[:32], bk[:])
}

func equalFixed(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

// leUint reads a little-endian byte slice as a big.Int (SNP scalar encoding).
func leUint(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return new(big.Int).SetBytes(be)
}

// ecdsaVerifyRaw verifies a raw (r‖s) signature over hash(msg) by a certificate's key.
func ecdsaVerifyRaw(cert *x509.Certificate, newH func() hash.Hash, msg, rawSig []byte) error {
	sig, err := rawSigToASN1(rawSig)
	if err != nil {
		return err
	}
	return ecdsaVerifyASN1(cert, newH, msg, sig)
}

// ecdsaVerifyASN1 verifies an ASN.1 signature over hash(msg) by a certificate's ECDSA key.
func ecdsaVerifyASN1(cert *x509.Certificate, newH func() hash.Hash, msg, sig []byte) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrFormat
	}
	hh := newH()
	hh.Write(msg)
	if !ecdsa.VerifyASN1(pub, hh.Sum(nil), sig) {
		return ErrSignature
	}
	return nil
}

// ecdsaVerifyRawKey verifies a raw (r‖s) signature by a raw uncompressed P-256 point (the DCAP
// attestation key, which travels in the quote as 64 bytes X‖Y rather than as a certificate).
func ecdsaVerifyRawKey(rawPoint []byte, newH func() hash.Hash, msg, rawSig []byte) error {
	pub, err := uncompressedP256(rawPoint)
	if err != nil {
		return err
	}
	sig, err := rawSigToASN1(rawSig)
	if err != nil {
		return err
	}
	hh := newH()
	hh.Write(msg)
	if !ecdsa.VerifyASN1(pub, hh.Sum(nil), sig) {
		return ErrSignature
	}
	return nil
}

// uncompressedP256 builds a P-256 public key from a 64-byte X‖Y point, rejecting off-curve points.
func uncompressedP256(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != 64 {
		return nil, ErrFormat
	}
	x := new(big.Int).SetBytes(raw[:32])
	y := new(big.Int).SetBytes(raw[32:])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, ErrFormat
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// splitPEMChain decodes a PEM bundle (the DCAP cert-data field) into a DER list, leaf first.
func splitPEMChain(pemBytes []byte) [][]byte {
	var out [][]byte
	rest := pemBytes
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, b.Bytes)
		}
	}
	return out
}
