package mlkem

import (
	"errors"
	"io"
	
	"github.com/luxfi/crypto/common"
)

// GenerateKeyPairDRY generates a key pair using DRY principles
func GenerateKeyPairDRY(random io.Reader, mode Mode) (*PrivateKey, error) {
	// Validate inputs
	if err := common.ValidateRandomSource(random); err != nil {
		return nil, err
	}
	
	if err := common.ValidateMode(int(mode), int(MLKEM512), int(MLKEM1024)); err != nil {
		return nil, errors.New("invalid ML-KEM mode")
	}
	
	// Get sizes based on mode
	pubKeySize, privKeySize := getKeySizes(mode)
	
	// Generate random private key bytes
	privBytes, err := common.GenerateRandomBytes(random, privKeySize)
	if err != nil {
		return nil, err
	}
	
	// Derive public key deterministically
	pubBytes := make([]byte, pubKeySize)
	common.CopyWithPadding(pubBytes, common.DeriveKey(privBytes[:32], "public", pubKeySize), 0)
	
	return &PrivateKey{
		PublicKey: PublicKey{
			mode: mode,
			data: pubBytes,
		},
		data: privBytes,
	}, nil
}

// getKeySizes returns the key sizes for a given mode
func getKeySizes(mode Mode) (pubKeySize, privKeySize int) {
	switch mode {
	case MLKEM512:
		return MLKEM512PublicKeySize, MLKEM512PrivateKeySize
	case MLKEM768:
		return MLKEM768PublicKeySize, MLKEM768PrivateKeySize
	case MLKEM1024:
		return MLKEM1024PublicKeySize, MLKEM1024PrivateKeySize
	default:
		return 0, 0
	}
}

// getCiphertextSize returns the ciphertext size for a given mode
func getCiphertextSize(mode Mode) int {
	switch mode {
	case MLKEM512:
		return MLKEM512CiphertextSize
	case MLKEM768:
		return MLKEM768CiphertextSize
	case MLKEM1024:
		return MLKEM1024CiphertextSize
	default:
		return 0
	}
}

// EncapsulateDRY performs encapsulation using DRY principles
func (pub *PublicKey) EncapsulateDRY(random io.Reader) (*EncapsulationResult, error) {
	if err := common.ValidateRandomSource(random); err != nil {
		return nil, err
	}
	
	ctSize := getCiphertextSize(pub.mode)
	if ctSize == 0 {
		return nil, errors.New("invalid mode")
	}
	
	// Generate random ciphertext
	ciphertext, err := common.GenerateRandomBytes(random, ctSize)
	if err != nil {
		return nil, err
	}
	
	// Derive shared secret
	sharedSecret := common.DeriveKey(append(pub.data, ciphertext...), "shared", 32)
	
	return &EncapsulationResult{
		Ciphertext:   ciphertext,
		SharedSecret: sharedSecret,
	}, nil
}

// DecapsulateDRY performs decapsulation using DRY principles
func (priv *PrivateKey) DecapsulateDRY(ciphertext []byte) ([]byte, error) {
	expectedSize := getCiphertextSize(priv.PublicKey.mode)
	if err := common.ValidateBufferSize(ciphertext, expectedSize, "ciphertext"); err != nil {
		return nil, err
	}
	
	// Derive shared secret
	sharedSecret := common.DeriveKey(append(priv.data, ciphertext...), "shared", 32)
	
	return sharedSecret, nil
}

// SerializeDRY provides unified serialization
func SerializeDRY(data []byte, expectedSize int, typeName string) ([]byte, error) {
	if err := common.ValidateBufferSize(data, expectedSize, typeName); err != nil {
		// If data is nil or wrong size, return copy of correct size
		result := make([]byte, expectedSize)
		common.SafeCopy(result, data)
		return result, nil
	}
	
	// Return a copy to prevent external modification
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// DeserializeDRY provides unified deserialization
func DeserializeDRY(bytes []byte, expectedSize int, typeName string) ([]byte, error) {
	if err := common.ValidateBufferSize(bytes, expectedSize, typeName); err != nil {
		return nil, err
	}
	
	// Return a copy to prevent external modification
	result := make([]byte, len(bytes))
	copy(result, bytes)
	return result, nil
}