// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package crypto_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/luxfi/crypto/encryption"
	"github.com/luxfi/crypto/secp256k1"
)

// A type that prints its own secret is reached by every sink at once: fmt on a
// struct that holds one, an error built with one in scope, a text logger walking
// a value, json.Marshal on anything containing it. None of those call sites says
// "write out a key", and what came out round-tripped to the identical key.
func TestASecretDoesNotPrintItself(t *testing.T) {
	k, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("new key: %v", err)
	}
	secret := k.Reveal()
	if !strings.HasPrefix(secret, secp256k1.PrivateKeyPrefix) || len(secret) < 20 {
		t.Fatalf("Reveal did not produce a key: %q", secret)
	}

	holder := struct {
		Key *secp256k1.PrivateKey `json:"key"`
	}{Key: k}

	for name, got := range map[string]string{
		"String":         k.String(),
		"%v":             fmt.Sprintf("%v", k),
		"%s on a holder": fmt.Sprintf("%s", holder),
		"error":          fmt.Errorf("signing with %v failed", k).Error(),
	} {
		if strings.Contains(got, secret) {
			t.Errorf("%s printed the key: %s", name, got)
		}
	}

	// json reaches MarshalText; it must refuse rather than emit.
	if b, err := json.Marshal(holder); err == nil && strings.Contains(string(b), secret) {
		t.Errorf("json.Marshal emitted the key: %s", b)
	}
}

// The identity for every blob it can open, printed by any %v that reaches it.
func TestAnIdentityDoesNotPrintItself(t *testing.T) {
	id, err := encryption.GenerateXWingIdentity()
	if err != nil {
		t.Skipf("identity unavailable: %v", err)
	}
	secret := id.Reveal()
	if !strings.Contains(secret, "AGE-SECRET-KEY-PQ-1") {
		t.Fatalf("Reveal did not produce an identity: %q", secret)
	}
	for name, got := range map[string]string{
		"String": id.String(),
		"%v":     fmt.Sprintf("%v", id),
		"error":  fmt.Errorf("decrypting with %v failed", id).Error(),
	} {
		if strings.Contains(got, secret) {
			t.Errorf("%s printed the identity: %s", name, got)
		}
	}
}
