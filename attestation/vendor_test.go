package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"testing"
)

// --- helpers to build layout-accurate quotes (a test CA stands in for the pinned vendor root) ----

func pad(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

func pad2(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// signP256Raw returns a 64-byte r‖s big-endian signature over hash(msg).
func signP256Raw(t *testing.T, key *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	d := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return append(pad2(r.Bytes(), 32), pad2(s.Bytes(), 32)...)
}

// signP384RawLE returns r‖s as 72-byte little-endian scalars over sha384(msg) (SNP encoding).
func signP384RawLE(t *testing.T, key *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	d := sha512.Sum384(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	toLE := func(x []byte) []byte {
		be := pad2(x, 72)
		le := make([]byte, 72)
		for i := range be {
			le[71-i] = be[i]
		}
		return le
	}
	return append(toLE(r.Bytes()), toLE(s.Bytes())...)
}

// attestPubBytes is the 64-byte X‖Y form the DCAP attestation key travels as.
func attestPubBytes(key *ecdsa.PrivateKey) []byte {
	return append(pad2(key.PublicKey.X.Bytes(), 32), pad2(key.PublicKey.Y.Bytes(), 32)...)
}

func pemOf(ders ...[]byte) []byte {
	var out []byte
	for _, d := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return out
}

// buildSGXQuote assembles a layout-accurate SGX DCAP v3 quote signed by attestKey, with the QE
// report signed by pckLeaf (chaining to root via pckDER‖rootDER).
func buildSGXQuote(t *testing.T, attestKey, pckKey *ecdsa.PrivateKey, pckDER, rootDER []byte, mr [32]byte, boundKey []byte) []byte {
	header := make([]byte, sgxHeaderLen)
	binary.LittleEndian.PutUint16(header[0:2], 3) // version 3
	binary.LittleEndian.PutUint32(header[4:8], 0) // tee_type SGX

	body := make([]byte, sgxBodyLen)
	copy(body[64:96], mr[:]) // mr_enclave
	{
		bk := BindKey(boundKey)
		copy(body[320:352], bk[:])
	} // report_data binds the operator key

	attestPub := attestPubBytes(attestKey)
	authData := []byte("qe-auth")
	quoteSig := signP256Raw(t, attestKey, append(append([]byte(nil), header...), body...))

	qe := make([]byte, sgxBodyLen)
	bind := sha256.Sum256(append(append([]byte(nil), attestPub...), authData...))
	copy(qe[320:352], bind[:]) // qe_report.report_data binds the attestation key
	qeSig := signP256Raw(t, pckKey, qe)

	certData := pemOf(pckDER, rootDER)
	var q []byte
	q = append(q, header...)
	q = append(q, body...)
	q = append(q, pad(nil, 4)...) // sigDataLen (unused by the parser)
	q = append(q, quoteSig...)
	q = append(q, attestPub...)
	q = append(q, qe...)
	q = append(q, qeSig...)
	q = append(q, byte(len(authData)), 0) // authLen u16 LE
	q = append(q, authData...)
	q = append(q, 0, 0) // certDataType u16
	cl := make([]byte, 4)
	binary.LittleEndian.PutUint32(cl, uint32(len(certData)))
	q = append(q, cl...)
	q = append(q, certData...)
	return q
}

func TestVerifySGX_Genuine(t *testing.T) {
	root, rootKey := genCA(t, "intel-sgx-root")
	pckKey, pckDER := genLeaf(t, root, rootKey)
	attestKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mr := sha256.Sum256([]byte("enclave-image"))
	op := []byte("operator-key")
	rootDER := root.Raw

	q := buildSGXQuote(t, attestKey, pckKey, pckDER, rootDER, mr, op)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	got, err := VerifySGX(q, roots, map[[32]byte]bool{mr: true}, op)
	if err != nil {
		t.Fatalf("genuine SGX quote must verify: %v", err)
	}
	if [32]byte(got) != mr {
		t.Fatal("returned the wrong MRENCLAVE")
	}

	// ADVERSARIAL: flip a measurement byte → the quote signature no longer covers it.
	bad := append([]byte(nil), q...)
	bad[sgxMREnclave] ^= 0x01
	if _, err := VerifySGX(bad, roots, map[[32]byte]bool{mr: true}, op); err == nil {
		t.Fatal("a tampered MRENCLAVE must be rejected")
	}
	// ADVERSARIAL: a different pinned root → chain fails.
	other, _ := genCA(t, "not-intel")
	op2 := x509.NewCertPool()
	op2.AddCert(other)
	if _, err := VerifySGX(q, op2, map[[32]byte]bool{mr: true}, op); err != ErrChain {
		t.Fatalf("a quote not chaining to the pinned root must be ErrChain, got %v", err)
	}
	// ADVERSARIAL: unbound key.
	if _, err := VerifySGX(q, roots, map[[32]byte]bool{mr: true}, []byte("other-op")); err != ErrBinding {
		t.Fatalf("a quote bound to a different key must be ErrBinding, got %v", err)
	}
}

// buildTDXQuote assembles a layout-accurate Intel TDX DCAP v4 quote (SGX sigData shape, TDX dims).
func buildTDXQuote(t *testing.T, attestKey, pckKey *ecdsa.PrivateKey, pckDER, rootDER []byte, mr [48]byte, boundKey []byte) []byte {
	header := make([]byte, tdxHeaderLen)
	binary.LittleEndian.PutUint16(header[0:2], 4)    // version 4
	binary.LittleEndian.PutUint32(header[4:8], 0x81) // tee_type TDX
	body := make([]byte, tdxBodyLen)
	copy(body[136:184], mr[:]) // mr_td
	bk := BindKey(boundKey)
	copy(body[520:552], bk[:]) // report_data binds the operator key
	attestPub := attestPubBytes(attestKey)
	authData := []byte("qe-auth")
	quoteSig := signP256Raw(t, attestKey, append(append([]byte(nil), header...), body...))
	qe := make([]byte, sgxBodyLen)
	bind := sha256.Sum256(append(append([]byte(nil), attestPub...), authData...))
	copy(qe[320:352], bind[:])
	qeSig := signP256Raw(t, pckKey, qe)
	certData := pemOf(pckDER, rootDER)
	var q []byte
	q = append(q, header...)
	q = append(q, body...)
	q = append(q, pad(nil, 4)...)
	q = append(q, quoteSig...)
	q = append(q, attestPub...)
	q = append(q, qe...)
	q = append(q, qeSig...)
	q = append(q, byte(len(authData)), 0)
	q = append(q, authData...)
	q = append(q, 0, 0)
	cl := make([]byte, 4)
	binary.LittleEndian.PutUint32(cl, uint32(len(certData)))
	q = append(q, cl...)
	q = append(q, certData...)
	return q
}

func TestVerifyTDX_Genuine(t *testing.T) {
	root, rootKey := genCA(t, "intel-tdx-root")
	pckKey, pckDER := genLeaf(t, root, rootKey)
	attestKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var mr [48]byte
	tdImg := sha256.Sum256([]byte("td-image"))
	copy(mr[:], pad2(tdImg[:], 48))
	op := []byte("operator-key")
	q := buildTDXQuote(t, attestKey, pckKey, pckDER, root.Raw, mr, op)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := VerifyTDX(q, roots, map[[48]byte]bool{mr: true}, op); err != nil {
		t.Fatalf("genuine TDX quote must verify: %v", err)
	}
	bad := append([]byte(nil), q...)
	bad[tdxMRTD] ^= 0x01
	if _, err := VerifyTDX(bad, roots, map[[48]byte]bool{mr: true}, op); err == nil {
		t.Fatal("a tampered MRTD must be rejected")
	}
}

// buildSNPReport assembles a layout-accurate SEV-SNP report signed by vcekKey (P-384).
func buildSNPReport(t *testing.T, vcekKey *ecdsa.PrivateKey, mr []byte, boundKey []byte) []byte {
	r := make([]byte, snpReportLen)
	{
		bk := BindKey(boundKey)
		copy(r[snpReportData:snpReportData+32], bk[:])
	}
	copy(r[snpMeasure:snpMeasure+48], mr)
	sig := signP384RawLE(t, vcekKey, r[:snpSigOff])
	copy(r[snpSigOff:snpSigOff+144], sig)
	return r
}

func TestVerifySNP_Genuine(t *testing.T) {
	// AMD root → VCEK leaf (P-384).
	rootKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootCert, rootDER := genCAWithKey(t, "amd-ark", rootKey)
	vcekKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	vcekDER := genLeafWithKey(t, rootCert, rootKey, vcekKey)
	_ = rootDER

	snpImg := sha256.Sum256([]byte("snp-image"))
	mr := pad2(snpImg[:], 48)
	op := []byte("operator-key")
	report := buildSNPReport(t, vcekKey, mr, op)

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	got, err := VerifySNP(report, vcekDER, nil, roots, map[[48]byte]bool{[48]byte(mr): true}, op)
	if err != nil {
		t.Fatalf("genuine SNP report must verify: %v", err)
	}
	if string(got) != string(mr) {
		t.Fatal("returned the wrong measurement")
	}
	// ADVERSARIAL: tamper the measurement → P-384 signature fails.
	bad := append([]byte(nil), report...)
	bad[snpMeasure] ^= 0x01
	if _, err := VerifySNP(bad, vcekDER, nil, roots, map[[48]byte]bool{[48]byte(mr): true}, op); err == nil {
		t.Fatal("a tampered SNP measurement must be rejected")
	}
}
