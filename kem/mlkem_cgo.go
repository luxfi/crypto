//go:build cgo && liboqs
// +build cgo,liboqs

package kem

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -loqs

#include <oqs/oqs.h>
#include <stdlib.h>
#include <string.h>

#define OQS_SUCCESS_VAL OQS_SUCCESS

// ML-KEM-768 wrapper functions
void* mlkem768_new() {
    return OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
}

void mlkem768_free(void* kem) {
    if (kem != NULL) {
        OQS_KEM_free((OQS_KEM*)kem);
    }
}

int mlkem768_keypair(void* kem, uint8_t* public_key, uint8_t* secret_key) {
    if (kem == NULL) return -1;
    return OQS_KEM_keypair((OQS_KEM*)kem, public_key, secret_key);
}

int mlkem768_encaps(void* kem, uint8_t* ciphertext, uint8_t* shared_secret, const uint8_t* public_key) {
    if (kem == NULL) return -1;
    return OQS_KEM_encaps((OQS_KEM*)kem, ciphertext, shared_secret, public_key);
}

int mlkem768_decaps(void* kem, uint8_t* shared_secret, const uint8_t* ciphertext, const uint8_t* secret_key) {
    if (kem == NULL) return -1;
    return OQS_KEM_decaps((OQS_KEM*)kem, shared_secret, ciphertext, secret_key);
}

// ML-KEM-1024 wrapper functions
void* mlkem1024_new() {
    return OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
}

void mlkem1024_free(void* kem) {
    if (kem != NULL) {
        OQS_KEM_free((OQS_KEM*)kem);
    }
}

int mlkem1024_keypair(void* kem, uint8_t* public_key, uint8_t* secret_key) {
    if (kem == NULL) return -1;
    return OQS_KEM_keypair((OQS_KEM*)kem, public_key, secret_key);
}

int mlkem1024_encaps(void* kem, uint8_t* ciphertext, uint8_t* shared_secret, const uint8_t* public_key) {
    if (kem == NULL) return -1;
    return OQS_KEM_encaps((OQS_KEM*)kem, ciphertext, shared_secret, public_key);
}

int mlkem1024_decaps(void* kem, uint8_t* shared_secret, const uint8_t* ciphertext, const uint8_t* secret_key) {
    if (kem == NULL) return -1;
    return OQS_KEM_decaps((OQS_KEM*)kem, shared_secret, ciphertext, secret_key);
}
*/
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

// MLKEM768CGO implements ML-KEM-768 using liboqs via CGO
type MLKEM768CGO struct {
	kem unsafe.Pointer
}

// NewMLKEM768CGO creates a new ML-KEM-768 instance using liboqs
func NewMLKEM768CGO() (*MLKEM768CGO, error) {
	kem := C.mlkem768_new()
	if kem == nil {
		return nil, errors.New("failed to create ML-KEM-768 instance")
	}
	
	m := &MLKEM768CGO{kem: kem}
	runtime.SetFinalizer(m, (*MLKEM768CGO).cleanup)
	return m, nil
}

// cleanup frees the C resources
func (m *MLKEM768CGO) cleanup() {
	if m.kem != nil {
		C.mlkem768_free(m.kem)
		m.kem = nil
	}
}

// GenerateKeyPair generates a new ML-KEM-768 key pair using liboqs
func (m *MLKEM768CGO) GenerateKeyPair() (PublicKey, PrivateKey, error) {
	if m.kem == nil {
		return nil, nil, errors.New("KEM instance not initialized")
	}
	
	pk := &MLKEM768PublicKey{
		data: make([]byte, mlkem768PublicKeySize),
	}
	sk := &MLKEM768PrivateKey{
		data: make([]byte, mlkem768PrivateKeySize),
		pk:   pk,
	}
	
	ret := C.mlkem768_keypair(
		m.kem,
		(*C.uint8_t)(unsafe.Pointer(&pk.data[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk.data[0])),
	)
	
	if ret != C.OQS_SUCCESS_VAL {
		return nil, nil, errors.New("ML-KEM-768 key generation failed")
	}
	
	return pk, sk, nil
}

// Encapsulate generates a shared secret and ciphertext using liboqs
func (m *MLKEM768CGO) Encapsulate(pk PublicKey) ([]byte, []byte, error) {
	if m.kem == nil {
		return nil, nil, errors.New("KEM instance not initialized")
	}
	
	mlkemPK, ok := pk.(*MLKEM768PublicKey)
	if !ok {
		return nil, nil, errors.New("invalid public key type")
	}
	
	ciphertext := make([]byte, mlkem768CiphertextSize)
	sharedSecret := make([]byte, mlkem768SharedSecretSize)
	
	ret := C.mlkem768_encaps(
		m.kem,
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])),
		(*C.uint8_t)(unsafe.Pointer(&mlkemPK.data[0])),
	)
	
	if ret != C.OQS_SUCCESS_VAL {
		return nil, nil, errors.New("ML-KEM-768 encapsulation failed")
	}
	
	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext using liboqs
func (m *MLKEM768CGO) Decapsulate(sk PrivateKey, ciphertext []byte) ([]byte, error) {
	if m.kem == nil {
		return nil, errors.New("KEM instance not initialized")
	}
	
	mlkemSK, ok := sk.(*MLKEM768PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}
	
	if len(ciphertext) != mlkem768CiphertextSize {
		return nil, errors.New("invalid ciphertext size")
	}
	
	sharedSecret := make([]byte, mlkem768SharedSecretSize)
	
	ret := C.mlkem768_decaps(
		m.kem,
		(*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&mlkemSK.data[0])),
	)
	
	if ret != C.OQS_SUCCESS_VAL {
		return nil, errors.New("ML-KEM-768 decapsulation failed")
	}
	
	return sharedSecret, nil
}

// PublicKeySize returns the size of public keys
func (m *MLKEM768CGO) PublicKeySize() int {
	return mlkem768PublicKeySize
}

// PrivateKeySize returns the size of private keys
func (m *MLKEM768CGO) PrivateKeySize() int {
	return mlkem768PrivateKeySize
}

// CiphertextSize returns the size of ciphertexts
func (m *MLKEM768CGO) CiphertextSize() int {
	return mlkem768CiphertextSize
}

// SharedSecretSize returns the size of shared secrets
func (m *MLKEM768CGO) SharedSecretSize() int {
	return mlkem768SharedSecretSize
}

// MLKEM1024CGO implements ML-KEM-1024 using liboqs via CGO
type MLKEM1024CGO struct {
	kem unsafe.Pointer
}

// NewMLKEM1024CGO creates a new ML-KEM-1024 instance using liboqs
func NewMLKEM1024CGO() (*MLKEM1024CGO, error) {
	kem := C.mlkem1024_new()
	if kem == nil {
		return nil, errors.New("failed to create ML-KEM-1024 instance")
	}
	
	m := &MLKEM1024CGO{kem: kem}
	runtime.SetFinalizer(m, (*MLKEM1024CGO).cleanup)
	return m, nil
}

// cleanup frees the C resources
func (m *MLKEM1024CGO) cleanup() {
	if m.kem != nil {
		C.mlkem1024_free(m.kem)
		m.kem = nil
	}
}

// GenerateKeyPair generates a new ML-KEM-1024 key pair using liboqs
func (m *MLKEM1024CGO) GenerateKeyPair() (PublicKey, PrivateKey, error) {
	if m.kem == nil {
		return nil, nil, errors.New("KEM instance not initialized")
	}
	
	pk := &MLKEM1024PublicKey{
		data: make([]byte, mlkem1024PublicKeySize),
	}
	sk := &MLKEM1024PrivateKey{
		data: make([]byte, mlkem1024PrivateKeySize),
		pk:   pk,
	}
	
	ret := C.mlkem1024_keypair(
		m.kem,
		(*C.uint8_t)(unsafe.Pointer(&pk.data[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk.data[0])),
	)
	
	if ret != C.OQS_SUCCESS_VAL {
		return nil, nil, errors.New("ML-KEM-1024 key generation failed")
	}
	
	return pk, sk, nil
}

// Encapsulate generates a shared secret and ciphertext using liboqs
func (m *MLKEM1024CGO) Encapsulate(pk PublicKey) ([]byte, []byte, error) {
	if m.kem == nil {
		return nil, nil, errors.New("KEM instance not initialized")
	}
	
	mlkemPK, ok := pk.(*MLKEM1024PublicKey)
	if !ok {
		return nil, nil, errors.New("invalid public key type")
	}
	
	ciphertext := make([]byte, mlkem1024CiphertextSize)
	sharedSecret := make([]byte, mlkem1024SharedSecretSize)
	
	ret := C.mlkem1024_encaps(
		m.kem,
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])),
		(*C.uint8_t)(unsafe.Pointer(&mlkemPK.data[0])),
	)
	
	if ret != C.OQS_SUCCESS_VAL {
		return nil, nil, errors.New("ML-KEM-1024 encapsulation failed")
	}
	
	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext using liboqs
func (m *MLKEM1024CGO) Decapsulate(sk PrivateKey, ciphertext []byte) ([]byte, error) {
	if m.kem == nil {
		return nil, errors.New("KEM instance not initialized")
	}
	
	mlkemSK, ok := sk.(*MLKEM1024PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}
	
	if len(ciphertext) != mlkem1024CiphertextSize {
		return nil, errors.New("invalid ciphertext size")
	}
	
	sharedSecret := make([]byte, mlkem1024SharedSecretSize)
	
	ret := C.mlkem1024_decaps(
		m.kem,
		(*C.uint8_t)(unsafe.Pointer(&sharedSecret[0])),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		(*C.uint8_t)(unsafe.Pointer(&mlkemSK.data[0])),
	)
	
	if ret != C.OQS_SUCCESS_VAL {
		return nil, errors.New("ML-KEM-1024 decapsulation failed")
	}
	
	return sharedSecret, nil
}

// PublicKeySize returns the size of public keys
func (m *MLKEM1024CGO) PublicKeySize() int {
	return mlkem1024PublicKeySize
}

// PrivateKeySize returns the size of private keys
func (m *MLKEM1024CGO) PrivateKeySize() int {
	return mlkem1024PrivateKeySize
}

// CiphertextSize returns the size of ciphertexts
func (m *MLKEM1024CGO) CiphertextSize() int {
	return mlkem1024CiphertextSize
}

// SharedSecretSize returns the size of shared secrets
func (m *MLKEM1024CGO) SharedSecretSize() int {
	return mlkem1024SharedSecretSize
}

// cgoAvailable returns true when CGO is available  
func cgoAvailable() bool {
	return true
}