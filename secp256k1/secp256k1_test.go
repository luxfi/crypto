// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecover(t *testing.T) {
	require := require.New(t)

	key, err := NewPrivateKey()
	require.NoError(err)

	msg := []byte{1, 2, 3}
	sig, err := key.Sign(msg)
	require.NoError(err)

	pub := key.PublicKey()
	pubRec, err := RecoverPublicKey(msg, sig[:])
	require.NoError(err)

	require.Equal(pub.Bytes(), pubRec.Bytes())
	require.True(pub.Verify(msg, sig[:]))
}

func TestPrivateKeySECP256K1Uncompressed(t *testing.T) {
	require := require.New(t)

	key, err := NewPrivateKey()
	require.NoError(err)

	pubUncompressed := key.PublicKey()
	require.NotNil(pubUncompressed)
}

func TestPrivateKeyMarshalText(t *testing.T) {
	require := require.New(t)

	key, err := NewPrivateKey()
	require.NoError(err)

	text, err := key.MarshalText()
	require.NoError(err)

	key2 := &PrivateKey{}
	err = key2.UnmarshalText(text)
	require.NoError(err)

	require.Equal(key.Bytes(), key2.Bytes())
}

func TestPrivateKeyUnmarshalTextDirect(t *testing.T) {
	require := require.New(t)

	// Create a key and marshal it
	key, err := NewPrivateKey()
	require.NoError(err)

	text, err := key.MarshalText()
	require.NoError(err)

	// Test direct UnmarshalText (no quotes)
	key2 := &PrivateKey{}
	err = key2.UnmarshalText(text)
	require.NoError(err)
	require.Equal(key.Bytes(), key2.Bytes())
}

func TestPrivateKeyUnmarshalJSON(t *testing.T) {
	require := require.New(t)

	// Create a key and marshal it
	key, err := NewPrivateKey()
	require.NoError(err)

	keyString := key.String()

	// Test UnmarshalJSON with quoted string (as JSON would provide)
	quotedJSON := []byte(`"` + keyString + `"`)
	key2 := &PrivateKey{}
	err = key2.UnmarshalJSON(quotedJSON)
	require.NoError(err)
	require.Equal(key.Bytes(), key2.Bytes())

	// Test UnmarshalJSON with unquoted string (should still work)
	key3 := &PrivateKey{}
	err = key3.UnmarshalJSON([]byte(keyString))
	require.NoError(err)
	require.Equal(key.Bytes(), key3.Bytes())
}

func TestPrivateKeyMarshalUnmarshalJSON(t *testing.T) {
	require := require.New(t)

	key, err := NewPrivateKey()
	require.NoError(err)

	// Marshal to JSON
	jsonBytes := []byte(`"` + key.String() + `"`)

	// Unmarshal from JSON
	key2 := &PrivateKey{}
	err = key2.UnmarshalJSON(jsonBytes)
	require.NoError(err)

	require.Equal(key.Bytes(), key2.Bytes())
}

func TestPrivateKeyUnmarshalInvalidPrefix(t *testing.T) {
	require := require.New(t)

	key := &PrivateKey{}

	// Test with missing prefix
	err := key.UnmarshalText([]byte("invalidprefix123"))
	require.Error(err)
	require.Contains(err.Error(), "missing PrivateKey- prefix")
}

func TestPrivateKeyUnmarshalNull(t *testing.T) {
	require := require.New(t)

	key := &PrivateKey{}

	// Test with "null" string
	err := key.UnmarshalText([]byte("null"))
	require.NoError(err)
}

func TestPublicKeyVerify(t *testing.T) {
	require := require.New(t)

	key, err := NewPrivateKey()
	require.NoError(err)

	msg := []byte("hello world")
	sig, err := key.Sign(msg)
	require.NoError(err)

	pub := key.PublicKey()
	require.True(pub.Verify(msg, sig[:]))

	// Wrong message should fail
	require.False(pub.Verify([]byte("wrong message"), sig[:]))
}

func TestInvalidSignatureLength(t *testing.T) {
	require := require.New(t)

	key, err := NewPrivateKey()
	require.NoError(err)

	msg := []byte("test")
	pub := key.PublicKey()

	// Too short signature
	shortSig := make([]byte, SignatureLen-1)
	require.False(pub.Verify(msg, shortSig))

	// Too long signature
	longSig := make([]byte, SignatureLen+1)
	require.False(pub.Verify(msg, longSig))
}
