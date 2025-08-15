// Copyright (C) 2020-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignVerify(t *testing.T) {
	require := require.New(t)

	sk, err := NewSecretKey()
	require.NoError(err)

	pk := sk.PublicKey()
	require.NotNil(pk)

	msg := make([]byte, 32)
	_, err = rand.Read(msg)
	require.NoError(err)

	sig := sk.Sign(msg)
	require.NotNil(sig)

	valid := Verify(pk, sig, msg)
	require.True(valid)

	// Wrong message should fail
	msg[0]++
	valid = Verify(pk, sig, msg)
	require.False(valid)
}

func TestProofOfPossession(t *testing.T) {
	require := require.New(t)

	sk, err := NewSecretKey()
	require.NoError(err)

	pk := sk.PublicKey()
	require.NotNil(pk)

	msg := make([]byte, 32)
	_, err = rand.Read(msg)
	require.NoError(err)

	sig := sk.SignProofOfPossession(msg)
	require.NotNil(sig)

	valid := VerifyProofOfPossession(pk, sig, msg)
	require.True(valid)
}

func TestSecretKeyFromBytes(t *testing.T) {
	require := require.New(t)

	sk1, err := NewSecretKey()
	require.NoError(err)

	bytes := SecretKeyToBytes(sk1)
	require.Len(bytes, SecretKeyLen)

	sk2, err := SecretKeyFromBytes(bytes)
	require.NoError(err)

	require.Equal(SecretKeyToBytes(sk1), SecretKeyToBytes(sk2))
}

func TestPublicKeyFromBytes(t *testing.T) {
	require := require.New(t)

	sk, err := NewSecretKey()
	require.NoError(err)

	pk1 := sk.PublicKey()
	bytes := PublicKeyToCompressedBytes(pk1)
	require.Len(bytes, PublicKeyLen)

	pk2, err := PublicKeyFromCompressedBytes(bytes)
	require.NoError(err)

	require.Equal(PublicKeyToCompressedBytes(pk1), PublicKeyToCompressedBytes(pk2))
}

func TestSignatureFromBytes(t *testing.T) {
	require := require.New(t)

	sk, err := NewSecretKey()
	require.NoError(err)

	msg := []byte("test message")
	sig1 := sk.Sign(msg)

	bytes := SignatureToBytes(sig1)
	require.Len(bytes, SignatureLen)

	sig2, err := SignatureFromBytes(bytes)
	require.NoError(err)

	require.Equal(SignatureToBytes(sig1), SignatureToBytes(sig2))
}
