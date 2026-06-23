// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package bls

import (
	"testing"

	"github.com/cloudflare/circl/ecc/bls12381"
	blssign "github.com/cloudflare/circl/sign/bls"
)

// negatePublicKey returns -pk as a *PublicKey by negating the underlying G1 point
// (white-box: the test is package bls). For BLS12-381, -P = (x, -y); CIRCL's
// bls12381.G1.Neg() negates y. The negated key is a VALID non-identity subgroup
// point (it is the public key of -sk), so it passes every input check — yet
// aggregating it with pk yields the identity, the case under test.
func negatePublicKey(t *testing.T, pk *PublicKey) *PublicKey {
	t.Helper()
	b, err := pk.pk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal pk: %v", err)
	}
	var g bls12381.G1
	if err := g.SetBytes(b); err != nil {
		t.Fatalf("decode pk point: %v", err)
	}
	g.Neg()
	neg := new(blssign.PublicKey[blssign.KeyG1SigG2])
	if err := neg.UnmarshalBinary(g.BytesCompressed()); err != nil {
		t.Fatalf("re-encode negated point: %v", err)
	}
	// Sanity: -pk is itself a valid (non-identity, on-curve, in-subgroup) key.
	if !neg.Validate() {
		t.Fatal("negated key must itself be a valid non-identity G1 point")
	}
	return &PublicKey{pk: neg}
}

// TestAggregatePublicKeys_RejectsIdentityAggregate is the defense-in-depth
// regression: AggregatePublicKeys must REFUSE an aggregate that is the identity
// (point at infinity), even when every input is a valid non-identity subgroup key.
//
// Construction: pk and -pk. Both are valid keys (each is the public key of a real
// secret, -sk for the second), so they pass every per-input check; their sum is
// the identity O. WITHOUT the result.Validate() guard, AggregatePublicKeys would
// return a usable *PublicKey wrapping O — and Verify against the identity key
// trivially accepts the identity signature, a forgery enabler. WITH the guard, it
// returns a clean error.
//
// purego (CIRCL, //go:build !cgo) is the canonical node image (CGO_ENABLED=0); the
// cgo path enforces the SAME guard via blst KeyValidate().
func TestAggregatePublicKeys_RejectsIdentityAggregate(t *testing.T) {
	sk, err := NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey: %v", err)
	}
	pk := sk.PublicKey()
	negPk := negatePublicKey(t, pk)

	// Both inputs are valid keys (precondition for the test to be meaningful: the
	// reject must come from the AGGREGATE being identity, not from a bad input).
	if !pk.pk.Validate() || !negPk.pk.Validate() {
		t.Fatal("both inputs must be valid non-identity keys")
	}

	agg, err := AggregatePublicKeys([]*PublicKey{pk, negPk})
	if err == nil {
		t.Fatalf("AggregatePublicKeys accepted an IDENTITY aggregate (pk + -pk = O) — "+
			"it must fail closed; got key=%v", agg)
	}
	if agg != nil {
		t.Fatal("AggregatePublicKeys must return a nil key alongside the error for an identity aggregate")
	}

	// Control: a normal two-key aggregate (pk + pk' with independent keys) is NOT
	// the identity and MUST still succeed — the guard rejects only the degenerate
	// identity, never a legitimate aggregate.
	sk2, err := NewSecretKey()
	if err != nil {
		t.Fatalf("NewSecretKey 2: %v", err)
	}
	if _, err := AggregatePublicKeys([]*PublicKey{pk, sk2.PublicKey()}); err != nil {
		t.Fatalf("a legitimate (non-identity) aggregate must succeed, got: %v", err)
	}
}
