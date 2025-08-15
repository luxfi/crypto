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
