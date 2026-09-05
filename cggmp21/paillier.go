// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// PaillierPublicKey represents a Paillier public key
type PaillierPublicKey struct {
	N   *big.Int // n = p*q
	NSq *big.Int // n^2
	G   *big.Int // generator (typically n+1)
}

// PaillierPrivateKey represents a Paillier private key
type PaillierPrivateKey struct {
	PublicKey *PaillierPublicKey
	// The trapdoor, unexported. Any one of these recovers the factorisation, and
	// an exported field is emitted by whatever walks the value.
	lambda *big.Int // lcm(p-1, q-1)
	mu     *big.Int // modular multiplicative inverse
	primeP *big.Int // prime p
	primeQ *big.Int // prime q
}

// GeneratePaillierKeyPair generates a new Paillier keypair
func GeneratePaillierKeyPair(bits int) (*PaillierPrivateKey, *PaillierPublicKey, error) {
	// Generate two large primes p and q
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, err
	}

	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, err
	}

	// Compute n = p*q
	n := new(big.Int).Mul(p, q)
	nSq := new(big.Int).Mul(n, n)

	// Compute lambda = lcm(p-1, q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))

	gcd := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
	lambda := new(big.Int).Mul(pMinus1, qMinus1)
	lambda.Div(lambda, gcd)

	// Set g = n+1 (standard choice)
	g := new(big.Int).Add(n, big.NewInt(1))

	// Compute mu = (L(g^lambda mod n^2))^(-1) mod n
	// where L(x) = (x-1)/n
	gLambda := new(big.Int).Exp(g, lambda, nSq)
	l := L(gLambda, n)
	mu := new(big.Int).ModInverse(l, n)

	if mu == nil {
		return nil, nil, errors.New("failed to compute modular inverse")
	}

	pubKey := &PaillierPublicKey{
		N:   n,
		NSq: nSq,
		G:   g,
	}

	privKey := &PaillierPrivateKey{
		PublicKey: pubKey,
		lambda:    lambda,
		mu:        mu,
		primeP:    p,
		primeQ:    q,
	}

	return privKey, pubKey, nil
}

// Encrypt encrypts a plaintext using Paillier encryption
func (pub *PaillierPublicKey) Encrypt(plaintext *big.Int) (*big.Int, error) {
	// Check plaintext is in valid range
	if plaintext.Cmp(pub.N) >= 0 || plaintext.Sign() < 0 {
		return nil, errors.New("plaintext out of range")
	}

	// Generate random r where gcd(r, n) = 1
	var r *big.Int
	for {
		r, _ = rand.Int(rand.Reader, pub.N)
		if new(big.Int).GCD(nil, nil, r, pub.N).Cmp(big.NewInt(1)) == 0 {
			break
		}
	}

	// Compute ciphertext = g^m * r^n mod n^2
	gm := new(big.Int).Exp(pub.G, plaintext, pub.NSq)
	rn := new(big.Int).Exp(r, pub.N, pub.NSq)

	ciphertext := new(big.Int).Mul(gm, rn)
	ciphertext.Mod(ciphertext, pub.NSq)

	return ciphertext, nil
}

// Decrypt decrypts a ciphertext using Paillier decryption
func (priv *PaillierPrivateKey) Decrypt(ciphertext *big.Int) (*big.Int, error) {
	// Check ciphertext is in valid range
	if ciphertext.Cmp(priv.PublicKey.NSq) >= 0 || ciphertext.Sign() <= 0 {
		return nil, errors.New("ciphertext out of range")
	}

	// Compute plaintext = L(c^lambda mod n^2) * mu mod n
	cLambda := new(big.Int).Exp(ciphertext, priv.lambda, priv.PublicKey.NSq)
	l := L(cLambda, priv.PublicKey.N)

	plaintext := new(big.Int).Mul(l, priv.mu)
	plaintext.Mod(plaintext, priv.PublicKey.N)

	return plaintext, nil
}

// Add performs homomorphic addition of two ciphertexts
func (pub *PaillierPublicKey) Add(c1, c2 *big.Int) *big.Int {
	// E(m1) * E(m2) = E(m1 + m2)
	result := new(big.Int).Mul(c1, c2)
	result.Mod(result, pub.NSq)
	return result
}

// Multiply performs homomorphic multiplication by a constant
func (pub *PaillierPublicKey) Multiply(ciphertext, constant *big.Int) *big.Int {
	// E(m)^k = E(k*m)
	result := new(big.Int).Exp(ciphertext, constant, pub.NSq)
	return result
}

// L computes L(x) = (x-1)/n
func L(x, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, big.NewInt(1)), n)
}
