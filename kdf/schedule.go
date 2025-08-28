// Package kdf provides key derivation functions and schedules
package kdf

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HashID identifies a hash algorithm
type HashID string

const (
	SHA256 HashID = "sha256"
	SHA384 HashID = "sha384"
)

// Suite defines the cryptographic suite
type Suite struct {
	Kem  string
	Sig  string
	Aead string
	Hash HashID
}

// HandshakeKeys contains derived keys for handshake
type HandshakeKeys struct {
	ClientKey      []byte
	ServerKey      []byte
	ClientIV       []byte
	ServerIV       []byte
	ExporterSecret []byte
	KeyID          uint32
}

// KeySchedule manages key derivation for QZMQ
type KeySchedule struct {
	suite         Suite
	hash          func() hash.Hash
	handshakeKeys *HandshakeKeys
	updateCounter uint32
}

// NewKeySchedule creates a new key schedule
func NewKeySchedule(suite Suite) *KeySchedule {
	var hashFunc func() hash.Hash
	
	switch suite.Hash {
	case SHA256:
		hashFunc = sha256.New
	case SHA384:
		hashFunc = sha512.New384
	default:
		hashFunc = sha256.New
	}
	
	return &KeySchedule{
		suite: suite,
		hash:  hashFunc,
	}
}

// DeriveHandshakeKeys derives keys from KEM and ECDHE secrets
func (ks *KeySchedule) DeriveHandshakeKeys(kemSecret, ecdheSecret []byte, transcript []byte) (*HandshakeKeys, error) {
	// Concatenate secrets
	combined := append(kemSecret, ecdheSecret...)
	
	// HKDF-Extract
	salt := []byte("QZMQ-v1-Handshake")
	prk := hkdf.Extract(ks.hash, combined, salt)
	
	// Derive various keys using HKDF-Expand
	keys := &HandshakeKeys{}
	
	// Client traffic secret
	clientInfo := append([]byte("client traffic secret"), transcript...)
	clientSecret := ks.expand(prk, clientInfo, 32)
	
	// Server traffic secret
	serverInfo := append([]byte("server traffic secret"), transcript...)
	serverSecret := ks.expand(prk, serverInfo, 32)
	
	// Derive actual keys and IVs from traffic secrets
	keys.ClientKey = ks.expand(clientSecret, []byte("key"), 32)
	keys.ClientIV = ks.expand(clientSecret, []byte("iv"), 12)
	keys.ServerKey = ks.expand(serverSecret, []byte("key"), 32)
	keys.ServerIV = ks.expand(serverSecret, []byte("iv"), 12)
	
	// Exporter secret
	exporterInfo := append([]byte("exporter secret"), transcript...)
	keys.ExporterSecret = ks.expand(prk, exporterInfo, 32)
	
	// Generate key ID
	keyIDBytes := ks.expand(prk, []byte("key id"), 4)
	keys.KeyID = binary.BigEndian.Uint32(keyIDBytes)
	
	ks.handshakeKeys = keys
	ks.updateCounter = 0
	
	return keys, nil
}

// KeyUpdate performs key ratcheting
func (ks *KeySchedule) KeyUpdate() (*HandshakeKeys, error) {
	if ks.handshakeKeys == nil {
		return nil, ErrNoHandshakeKeys
	}
	
	ks.updateCounter++
	
	// Create update info with counter
	updateInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(updateInfo, ks.updateCounter)
	
	// Ratchet client key
	newClientSecret := ks.expand(
		ks.handshakeKeys.ClientKey,
		append([]byte("key update"), updateInfo...),
		32,
	)
	
	// Ratchet server key
	newServerSecret := ks.expand(
		ks.handshakeKeys.ServerKey,
		append([]byte("key update"), updateInfo...),
		32,
	)
	
	// Derive new keys
	newKeys := &HandshakeKeys{
		ClientKey: ks.expand(newClientSecret, []byte("key"), 32),
		ClientIV:  ks.expand(newClientSecret, []byte("iv"), 12),
		ServerKey: ks.expand(newServerSecret, []byte("key"), 32),
		ServerIV:  ks.expand(newServerSecret, []byte("iv"), 12),
		ExporterSecret: ks.handshakeKeys.ExporterSecret, // Exporter doesn't change
		KeyID: ks.handshakeKeys.KeyID + ks.updateCounter,
	}
	
	ks.handshakeKeys = newKeys
	
	return newKeys, nil
}

// Export derives an exported value for channel binding
func (ks *KeySchedule) Export(context []byte, length int) ([]byte, error) {
	if ks.handshakeKeys == nil {
		return nil, ErrNoHandshakeKeys
	}
	
	info := append([]byte("QZMQ exporter"), context...)
	return ks.expand(ks.handshakeKeys.ExporterSecret, info, length), nil
}

// expand performs HKDF-Expand
func (ks *KeySchedule) expand(prk, info []byte, length int) []byte {
	r := hkdf.Expand(ks.hash, prk, info)
	output := make([]byte, length)
	
	if _, err := io.ReadFull(r, output); err != nil {
		panic(err) // Should never happen with correct parameters
	}
	
	return output
}

// EarlyData derives keys for 0-RTT data
func (ks *KeySchedule) DeriveEarlyDataKeys(psk []byte, transcript []byte) (*HandshakeKeys, error) {
	// HKDF-Extract with PSK
	salt := []byte("QZMQ-v1-EarlyData")
	prk := hkdf.Extract(ks.hash, psk, salt)
	
	// Derive early traffic secret
	earlyInfo := append([]byte("early traffic secret"), transcript...)
	earlySecret := ks.expand(prk, earlyInfo, 32)
	
	// Derive keys for early data
	keys := &HandshakeKeys{
		ClientKey: ks.expand(earlySecret, []byte("key"), 32),
		ClientIV:  ks.expand(earlySecret, []byte("iv"), 12),
		// Server doesn't send early data, so no server keys
		ServerKey: nil,
		ServerIV:  nil,
		ExporterSecret: ks.expand(prk, []byte("early exporter secret"), 32),
		KeyID: 0, // Special ID for early data
	}
	
	return keys, nil
}

// ResumptionSecret derives a resumption PSK
func (ks *KeySchedule) ResumptionSecret(transcript []byte) ([]byte, error) {
	if ks.handshakeKeys == nil {
		return nil, ErrNoHandshakeKeys
	}
	
	info := append([]byte("resumption secret"), transcript...)
	return ks.expand(ks.handshakeKeys.ExporterSecret, info, 32), nil
}

// Error types
var (
	ErrNoHandshakeKeys = &keyScheduleError{"no handshake keys derived"}
)

type keyScheduleError struct {
	msg string
}

func (e *keyScheduleError) Error() string {
	return e.msg
}

// Budgets tracks key usage limits
type Budgets struct {
	MaxMessages uint32
	MaxBytes    uint64
	MaxAge      int // seconds
	
	currentMessages uint32
	currentBytes    uint64
	keyBirth        int64 // unix timestamp
}

// NewBudgets creates new key usage budgets
func NewBudgets(maxMsgs uint32, maxBytes uint64, maxAge int) *Budgets {
	return &Budgets{
		MaxMessages: maxMsgs,
		MaxBytes:    maxBytes,
		MaxAge:      maxAge,
	}
}

// CheckAndUpdate checks if key update is needed
func (b *Budgets) CheckAndUpdate(msgSize int, now int64) bool {
	b.currentMessages++
	b.currentBytes += uint64(msgSize)
	
	if b.currentMessages >= b.MaxMessages {
		return true
	}
	
	if b.currentBytes >= b.MaxBytes {
		return true
	}
	
	if b.keyBirth > 0 && now-b.keyBirth >= int64(b.MaxAge) {
		return true
	}
	
	return false
}

// Reset resets the budgets after key update
func (b *Budgets) Reset(now int64) {
	b.currentMessages = 0
	b.currentBytes = 0
	b.keyBirth = now
}